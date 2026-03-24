import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { PrismaService } from '../../prisma/prisma.service';
import { AiService } from '../ai/ai.service';
import { NotificationService } from '../notification/notification.service';
import { dump as yamlDump, load as yamlLoad } from 'js-yaml';
import { matchesSubscription, getMatchedProducts, normalizeName } from '../../shared/vendor-normalization';

type RiskLevel = 'critical' | 'high' | 'medium';

type CandidateItem = {
    id: number;
    cveId: string;
    cvssV31Score: number | null;
    cvssV31Severity: string | null;
    epssScore: number | null;
    hasPublicExploit: boolean;
    isKnownExploited: boolean;
    publishedAt: Date;
    riskLevel: RiskLevel;
    smartReason: string;
    lastNotifiedAt: Date | null;
    shouldNotifyNow: boolean;
};

type SmartDatasetVulnerability = {
    id: number;
    cveId: string;
    description: string;
    publishedAt: Date;
    cvssV31Score: number | null;
    cvssV31Severity: string | null;
    cvssV31Vector: string | null;
    attackVector: 'Network' | 'Adjacent' | 'Local' | 'Physical' | 'Unknown';
    epssScore: number | null;
    hasPublicExploit: boolean;
    isKnownExploited: boolean;
    affectedProducts: Array<{ vendor: string; product: string; version?: string; versionRange?: string }>;
    exploitReferences: string[];
    references: string[];
    sources: Array<'notified' | 'matched'>;
    realRiskScore: number;
};

type SmartAnalysisResult = {
    executiveSummary: string;
    top3RealRisk: Array<{
        cveId: string;
        reason: string;
        priority: 'immediate' | 'high' | 'medium';
        evidence: string[];
    }>;
    detectedCorrelations: Array<{
        title: string;
        description: string;
        involvedCves: string[];
        attackPath: string;
        riskLevel: 'critical' | 'high' | 'medium';
    }>;
    mitigationRoadmap: Array<{
        order: number;
        action: string;
        why: string;
        cves: string[];
    }>;
};

type SubscriberDataset = {
    subscriber: {
        id: number;
        name: string;
        email: string;
    };
    periodStart: Date;
    periodEnd: Date;
    vulnerabilities: SmartDatasetVulnerability[];
    groupedAssets: Array<{
        vendor: string;
        product: string;
        cveIds: string[];
    }>;
    ownedSystems: Array<{
        externalId: string;
        hostname: string;
        platform: string | null;
        riskLevel: string | null;
        source: string;
        isSelected: boolean;
    }>;
    stats: {
        total: number;
        notifiedCount: number;
        matchedCount: number;
        withExploit: number;
        knownExploited: number;
        highOrCritical: number;
    };
};

type WeeklyRunResult = {
    subscriberId: number;
    reportId?: number;
    status: 'sent' | 'skipped' | 'failed';
    reason?: string;
    totalVulnerabilities?: number;
    periodStart?: Date;
    periodEnd?: Date;
};

type SmartNotificationConfig = {
    lookbackDays: number;
    maxCandidateVulnerabilities: number;
    minCvssForCandidates: number;
    minEpssForCandidates: number;
    epssHighThreshold: number;
    epssMediumThreshold: number;
    knownExploitedBoost: number;
    publicExploitBoost: number;
    epssHighBoost: number;
    epssMediumBoost: number;
    topRiskCount: number;
    promptTemplate: string;
    promptPersona: string;
    promptLanguage: 'es' | 'en';
    promptExtraInstructions: string;
    aiModelOverride: string;
    subjectPrefix: string;
    emailTitle: string;
    introText: string;
    footerText: string;
    sectionExecutiveTitle: string;
    sectionTopRiskTitle: string;
    sectionCorrelationsTitle: string;
    sectionRoadmapTitle: string;
    sectionTechnicalTitle: string;
    showExecutiveSection: boolean;
    showStatsSection: boolean;
    showTopRiskSection: boolean;
    showCorrelationsSection: boolean;
    showRoadmapSection: boolean;
    showTechnicalSection: boolean;
    technicalTableLimit: number;
    includeTechnicalTable: boolean;
};

type OwnedSystemInput = {
    externalId: string;
    source?: 'manual' | 'defender';
    hostname: string;
    fqdn?: string;
    platform?: string;
    osVersion?: string;
    riskLevel?: string;
    healthStatus?: string;
    onboardingStatus?: string;
    lastSeenAt?: string | Date | null;
    isSelected?: boolean;
    tags?: string[];
    rawData?: any;
};

type DefenderActionCatalogItem = {
    actionId: string;
    name: string;
    description: string;
    requiresApproval: boolean;
};

@Injectable()
export class SmartNotificationsService {
    private readonly logger = new Logger(SmartNotificationsService.name);
    private static readonly CONFIG_SLUG = 'smart-notifications-config';
    private static readonly DEFAULT_CONFIG: SmartNotificationConfig = {
        lookbackDays: 180,
        maxCandidateVulnerabilities: 150,
        minCvssForCandidates: 7,
        minEpssForCandidates: 0.2,
        epssHighThreshold: 0.7,
        epssMediumThreshold: 0.3,
        knownExploitedBoost: 3,
        publicExploitBoost: 2,
        epssHighBoost: 2,
        epssMediumBoost: 1,
        topRiskCount: 3,
        promptTemplate: '',
        promptPersona: 'Analista Senior de Ciberseguridad',
        promptLanguage: 'es',
        promptExtraInstructions: '',
        aiModelOverride: '',
        subjectPrefix: '[OCC] Hallazgo inteligente de vulnerabilidades',
        emailTitle: '🧠 Hallazgo Inteligente OCC',
        introText: 'Este informe resume hallazgos inteligentes y correlaciones relevantes detectadas en tus activos durante la ventana analizada.',
        footerText: 'Servicios OCC — Informe inteligente generado automáticamente',
        sectionExecutiveTitle: 'Resumen Ejecutivo',
        sectionTopRiskTitle: 'Top Riesgo Real',
        sectionCorrelationsTitle: 'Correlaciones Detectadas',
        sectionRoadmapTitle: 'Hoja de Ruta de Mitigación',
        sectionTechnicalTitle: 'Base Técnica Analizada',
        showExecutiveSection: true,
        showStatsSection: true,
        showTopRiskSection: true,
        showCorrelationsSection: true,
        showRoadmapSection: true,
        showTechnicalSection: true,
        technicalTableLimit: 20,
        includeTechnicalTable: true,
    };

    constructor(
        private readonly prisma: PrismaService,
        private readonly aiService: AiService,
        private readonly notificationService: NotificationService,
    ) { }

    async getSubscriberOwnedSystems(subscriberId: number) {
        await this.ensureSubscriberExists(subscriberId);

        const items = await (this.prisma as any).subscriberOwnedSystem.findMany({
            where: {
                subscriberUserId: subscriberId,
                isActive: true,
            },
            orderBy: [{ isSelected: 'desc' }, { hostname: 'asc' }],
        });

        return {
            subscriberId,
            total: items.length,
            selected: items.filter((item) => item.isSelected).length,
            items: items.map((item) => ({
                ...item,
                tags: this.safeJsonArray(item.tags),
                rawData: this.safeJsonObject(item.rawData),
            })),
        };
    }

    async saveSubscriberOwnedSystemsSelection(
        subscriberId: number,
        systems: OwnedSystemInput[],
    ) {
        await this.ensureSubscriberExists(subscriberId);

        const normalized = (Array.isArray(systems) ? systems : [])
            .map((system) => this.normalizeOwnedSystemInput(system))
            .filter((system) => !!system.externalId && !!system.hostname);

        if (normalized.length === 0) {
            return {
                subscriberId,
                saved: 0,
                message: 'No valid systems provided',
            };
        }

        for (const system of normalized) {
            await (this.prisma as any).subscriberOwnedSystem.upsert({
                where: {
                    subscriberUserId_externalId: {
                        subscriberUserId: subscriberId,
                        externalId: system.externalId,
                    },
                },
                update: {
                    source: system.source,
                    hostname: system.hostname,
                    fqdn: system.fqdn,
                    platform: system.platform,
                    osVersion: system.osVersion,
                    riskLevel: system.riskLevel,
                    healthStatus: system.healthStatus,
                    onboardingStatus: system.onboardingStatus,
                    lastSeenAt: system.lastSeenAt,
                    isSelected: system.isSelected,
                    isActive: true,
                    tags: JSON.stringify(system.tags || []),
                    rawData: system.rawData ? JSON.stringify(system.rawData) : null,
                },
                create: {
                    subscriberUserId: subscriberId,
                    externalId: system.externalId,
                    source: system.source,
                    hostname: system.hostname,
                    fqdn: system.fqdn,
                    platform: system.platform,
                    osVersion: system.osVersion,
                    riskLevel: system.riskLevel,
                    healthStatus: system.healthStatus,
                    onboardingStatus: system.onboardingStatus,
                    lastSeenAt: system.lastSeenAt,
                    isSelected: system.isSelected,
                    tags: JSON.stringify(system.tags || []),
                    rawData: system.rawData ? JSON.stringify(system.rawData) : null,
                },
            });
        }

        return {
            subscriberId,
            saved: normalized.length,
        };
    }

    async syncSubscriberSystemsFromDefender(
        subscriberId: number,
        payload?: {
            systems?: OwnedSystemInput[];
            markMissingAsInactive?: boolean;
        },
    ) {
        const systems = payload?.systems || [];
        const markMissingAsInactive = payload?.markMissingAsInactive !== false;

        const saveResult = await this.saveSubscriberOwnedSystemsSelection(subscriberId, systems);

        if (markMissingAsInactive) {
            const currentIds = new Set(
                (Array.isArray(systems) ? systems : [])
                    .map((system) => String(system?.externalId || '').trim())
                    .filter(Boolean),
            );

            if (currentIds.size > 0) {
                await (this.prisma as any).subscriberOwnedSystem.updateMany({
                    where: {
                        subscriberUserId: subscriberId,
                        externalId: { notIn: [...currentIds] },
                    },
                    data: {
                        isActive: false,
                        isSelected: false,
                    },
                });
            }
        }

        return {
            subscriberId,
            synced: saveResult.saved,
            source: 'defender',
            note: 'Sync endpoint prepared for Microsoft Defender connector integration',
        };
    }

    getDefenderActionCatalog(): DefenderActionCatalogItem[] {
        return [
            {
                actionId: 'isolate-device',
                name: 'Aislar dispositivo',
                description: 'Aísla el endpoint de la red para contención rápida.',
                requiresApproval: true,
            },
            {
                actionId: 'run-antivirus-scan',
                name: 'Ejecutar escaneo AV',
                description: 'Lanza escaneo antimalware completo en el sistema.',
                requiresApproval: false,
            },
            {
                actionId: 'collect-investigation-package',
                name: 'Recolectar paquete forense',
                description: 'Solicita paquete de investigación para análisis SOC.',
                requiresApproval: false,
            },
            {
                actionId: 'restrict-app-execution',
                name: 'Restringir ejecución de aplicaciones',
                description: 'Aplica política temporal de contención de ejecución.',
                requiresApproval: true,
            },
        ];
    }

    async planDefenderAction(
        subscriberId: number,
        actionId: string,
        systemExternalIds: string[],
        notes?: string,
        requestedBy?: string,
    ) {
        await this.ensureSubscriberExists(subscriberId);

        const catalog = this.getDefenderActionCatalog();
        const selectedAction = catalog.find((item) => item.actionId === actionId);
        if (!selectedAction) {
            throw new Error('Invalid actionId');
        }

        const uniqueSystemIds = [...new Set((systemExternalIds || []).map((id) => String(id || '').trim()).filter(Boolean))];
        if (uniqueSystemIds.length === 0) {
            throw new Error('At least one systemExternalId is required');
        }

        const existingSystems = await (this.prisma as any).subscriberOwnedSystem.findMany({
            where: {
                subscriberUserId: subscriberId,
                externalId: { in: uniqueSystemIds },
                isActive: true,
            },
            select: {
                externalId: true,
                hostname: true,
                source: true,
            },
        });

        const existingIds = new Set(existingSystems.map((item) => item.externalId));
        const missingIds = uniqueSystemIds.filter((id) => !existingIds.has(id));

        const request = await (this.prisma as any).defenderActionRequest.create({
            data: {
                subscriberUserId: subscriberId,
                actionId: selectedAction.actionId,
                actionName: selectedAction.name,
                systemExternalIds: JSON.stringify(uniqueSystemIds),
                status: selectedAction.requiresApproval ? 'pending-approval' : 'planned',
                notes: notes ? String(notes) : null,
                requestedBy: requestedBy ? String(requestedBy) : null,
            },
        });

        return {
            requestId: request.id,
            subscriberId,
            action: selectedAction,
            systemsResolved: existingSystems,
            systemsMissing: missingIds,
            status: request.status,
            note: 'Action was planned only. Connector execution will be added in future Defender integration.',
        };
    }

    async getSmartConfig() {
        return this.loadSmartConfig();
    }

    async saveSmartConfig(input: Partial<SmartNotificationConfig>) {
        const current = await this.loadSmartConfig();
        const merged = this.sanitizeConfig({ ...current, ...(input || {}) });

        await this.prisma.apiConfiguration.upsert({
            where: { slug: SmartNotificationsService.CONFIG_SLUG },
            update: {
                name: 'Smart Notifications Config',
                provider: 'smart_notifications',
                isActive: true,
                settings: JSON.stringify(merged),
            },
            create: {
                name: 'Smart Notifications Config',
                slug: SmartNotificationsService.CONFIG_SLUG,
                provider: 'smart_notifications',
                isActive: true,
                settings: JSON.stringify(merged),
            },
        });

        return merged;
    }

    async importSmartConfigProfile(input: {
        content?: string;
        profile?: any;
        format?: 'yaml' | 'json';
    }) {
        const parsed = this.parseProfileInput(input || {});
        const extracted = this.extractConfigFromDetailedProfile(parsed);
        const applied = await this.saveSmartConfig(extracted);

        return {
            imported: true,
            format: (input?.format || (typeof input?.content === 'string' ? 'yaml' : 'json')),
            applied,
        };
    }

    async exportSmartConfigProfile(format: 'yaml' | 'json' = 'yaml') {
        const cfg = await this.loadSmartConfig();
        const profile = this.buildDetailedProfileFromConfig(cfg);

        if (format === 'json') {
            return {
                format: 'json',
                profile,
            };
        }

        return {
            format: 'yaml',
            content: yamlDump(profile, {
                noRefs: true,
                lineWidth: 140,
            }),
            profile,
        };
    }

    @Cron('0 0 * * * *')
    async runScheduledWeeklyReports() {
        const centerSettings = await this.notificationService.getNotificationCenterSettings().catch(() => null);
        if (centerSettings?.general?.processEnabled === false || centerSettings?.intelligent?.enabled === false) {
            return;
        }

        const scheduledHour = Number(centerSettings?.intelligent?.evaluationHour ?? 8);
        if (new Date().getHours() !== scheduledHour) {
            return;
        }

        this.logger.log('Starting scheduled intelligent notifications');
        await this.runWeeklyForAllSubscribers('cron');
    }

    async checkAccumulatedRiskThreshold(): Promise<void> {
        const subscribers = await this.prisma.user.findMany({
            where: { isActive: true, isSubscriber: true },
            select: { id: true, name: true },
        });

        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

        for (const subscriber of subscribers) {
            try {
                // Count recent critical+exploitable vulns matching this subscriber's subscriptions
                const subscriptions = await this.prisma.userSubscription.findMany({
                    where: { userId: subscriber.id, isActive: true },
                    select: { vendor: true, product: true },
                });

                if (subscriptions.length === 0) continue;

                const recentCriticalVulns = await this.prisma.vulnerability.findMany({
                    where: {
                        publishedAt: { gte: sevenDaysAgo },
                        OR: [
                            { isKnownExploited: true },
                            { AND: [{ hasPublicExploit: true }, { cvssV31Score: { gte: 9 } }] },
                        ],
                    },
                    select: {
                        id: true,
                        cveId: true,
                        affectedProducts: true,
                    },
                });

                // Filter to only those matching subscriber's subscriptions
                const normalizedSubs = subscriptions.map((s) => ({
                    vendor: String(s.vendor || '').trim().toLowerCase(),
                    product: String(s.product || '').trim().toLowerCase(),
                }));

                let matchCount = 0;
                for (const vuln of recentCriticalVulns) {
                    const products = this.parseAffectedProducts(vuln.affectedProducts);
                    const matches = products.some((p) =>
                        normalizedSubs.some((s) => {
                            const pVendor = String(p.vendor || '').trim().toLowerCase();
                            const pProduct = String(p.product || '').trim().toLowerCase();
                            return (!s.vendor || s.vendor === pVendor) && (!s.product || s.product === pProduct);
                        }),
                    );
                    if (matches) matchCount++;
                }

                if (matchCount < 3) continue;

                // Check last smart report date
                const lastReport = await (this.prisma as any).smartNotificationReport.findFirst({
                    where: { subscriberUserId: subscriber.id, status: 'sent' },
                    orderBy: { sentAt: 'desc' },
                    select: { sentAt: true },
                });

                const daysSinceLastReport = lastReport?.sentAt
                    ? (Date.now() - lastReport.sentAt.getTime()) / (24 * 60 * 60 * 1000)
                    : Infinity;

                // Trigger if >= 3 critical+exploitable CVEs AND no report in last 3 days
                if (daysSinceLastReport > 3) {
                    this.logger.warn(
                        `Accumulated risk threshold crossed for subscriber=${subscriber.id} (${subscriber.name}): ${matchCount} critical CVEs, ${daysSinceLastReport === Infinity ? 'never reported' : daysSinceLastReport.toFixed(1) + ' days since last report'}. Triggering event-driven smart report.`,
                    );
                    await this.runWeeklyForSubscriber(subscriber.id, { trigger: 'manual' });
                }
            } catch (error) {
                this.logger.error(
                    `Risk threshold check failed for subscriber=${subscriber.id}: ${error instanceof Error ? error.message : 'Unknown'}`,
                );
            }
        }
    }

    private async loadSmartConfig(): Promise<SmartNotificationConfig> {
        const row = await this.prisma.apiConfiguration.findFirst({
            where: {
                slug: SmartNotificationsService.CONFIG_SLUG,
                isActive: true,
            },
        });

        if (!row?.settings) return SmartNotificationsService.DEFAULT_CONFIG;

        try {
            const parsed = JSON.parse(row.settings || '{}');
            return this.sanitizeConfig({ ...SmartNotificationsService.DEFAULT_CONFIG, ...parsed });
        } catch {
            return SmartNotificationsService.DEFAULT_CONFIG;
        }
    }

    private sanitizeConfig(input: Partial<SmartNotificationConfig>): SmartNotificationConfig {
        const n = (value: any, fallback: number, min: number, max: number) => {
            const num = Number(value);
            if (!Number.isFinite(num)) return fallback;
            return Math.max(min, Math.min(max, num));
        };

        const lookbackDays = Math.floor(n(input.lookbackDays, 180, 7, 365));
        const maxCandidateVulnerabilities = Math.floor(n(input.maxCandidateVulnerabilities, 150, 20, 500));
        const minCvssForCandidates = n(input.minCvssForCandidates, 7, 0, 10);
        const minEpssForCandidates = n(input.minEpssForCandidates, 0.2, 0, 1);
        const epssHighThreshold = n(input.epssHighThreshold, 0.7, 0, 1);
        const epssMediumThresholdRaw = n(input.epssMediumThreshold, 0.3, 0, 1);
        const epssMediumThreshold = Math.min(epssMediumThresholdRaw, epssHighThreshold);

        return {
            lookbackDays,
            maxCandidateVulnerabilities,
            minCvssForCandidates,
            minEpssForCandidates,
            epssHighThreshold,
            epssMediumThreshold,
            knownExploitedBoost: n(input.knownExploitedBoost, 3, 0, 10),
            publicExploitBoost: n(input.publicExploitBoost, 2, 0, 10),
            epssHighBoost: n(input.epssHighBoost, 2, 0, 10),
            epssMediumBoost: n(input.epssMediumBoost, 1, 0, 10),
            topRiskCount: Math.floor(n(input.topRiskCount, 3, 1, 10)),
            promptTemplate: String(input.promptTemplate || '').trim(),
            promptPersona: String(input.promptPersona || SmartNotificationsService.DEFAULT_CONFIG.promptPersona).trim(),
            promptLanguage: input.promptLanguage === 'en' ? 'en' : 'es',
            promptExtraInstructions: String(input.promptExtraInstructions || '').trim(),
            aiModelOverride: String(input.aiModelOverride || '').trim(),
            subjectPrefix: String(input.subjectPrefix || SmartNotificationsService.DEFAULT_CONFIG.subjectPrefix).trim(),
            emailTitle: String(input.emailTitle || SmartNotificationsService.DEFAULT_CONFIG.emailTitle).trim(),
            introText: String(input.introText || SmartNotificationsService.DEFAULT_CONFIG.introText).trim(),
            footerText: String(input.footerText || SmartNotificationsService.DEFAULT_CONFIG.footerText).trim(),
            sectionExecutiveTitle: String(input.sectionExecutiveTitle || SmartNotificationsService.DEFAULT_CONFIG.sectionExecutiveTitle).trim(),
            sectionTopRiskTitle: String(input.sectionTopRiskTitle || SmartNotificationsService.DEFAULT_CONFIG.sectionTopRiskTitle).trim(),
            sectionCorrelationsTitle: String(input.sectionCorrelationsTitle || SmartNotificationsService.DEFAULT_CONFIG.sectionCorrelationsTitle).trim(),
            sectionRoadmapTitle: String(input.sectionRoadmapTitle || SmartNotificationsService.DEFAULT_CONFIG.sectionRoadmapTitle).trim(),
            sectionTechnicalTitle: String(input.sectionTechnicalTitle || SmartNotificationsService.DEFAULT_CONFIG.sectionTechnicalTitle).trim(),
            showExecutiveSection: input.showExecutiveSection ?? SmartNotificationsService.DEFAULT_CONFIG.showExecutiveSection,
            showStatsSection: input.showStatsSection ?? SmartNotificationsService.DEFAULT_CONFIG.showStatsSection,
            showTopRiskSection: input.showTopRiskSection ?? SmartNotificationsService.DEFAULT_CONFIG.showTopRiskSection,
            showCorrelationsSection: input.showCorrelationsSection ?? SmartNotificationsService.DEFAULT_CONFIG.showCorrelationsSection,
            showRoadmapSection: input.showRoadmapSection ?? SmartNotificationsService.DEFAULT_CONFIG.showRoadmapSection,
            showTechnicalSection: input.showTechnicalSection ?? SmartNotificationsService.DEFAULT_CONFIG.showTechnicalSection,
            technicalTableLimit: Math.floor(n(input.technicalTableLimit, 20, 5, 100)),
            includeTechnicalTable: input.includeTechnicalTable ?? SmartNotificationsService.DEFAULT_CONFIG.includeTechnicalTable,
        };
    }

    private parseProfileInput(input: { content?: string; profile?: any; format?: 'yaml' | 'json' }) {
        if (input?.profile && typeof input.profile === 'object') return input.profile;

        const raw = String(input?.content || '').trim();
        if (!raw) throw new Error('Profile content is required');

        if (input?.format === 'json') {
            return JSON.parse(raw);
        }

        if (input?.format === 'yaml' || !input?.format) {
            const parsed = yamlLoad(raw);
            if (!parsed || typeof parsed !== 'object') {
                throw new Error('Invalid YAML profile');
            }
            return parsed;
        }

        throw new Error('Unsupported profile format');
    }

    private extractConfigFromDetailedProfile(profile: any): Partial<SmartNotificationConfig> {
        const get = (path: string, fallback?: any) => {
            const value = path.split('.').reduce((acc: any, key: string) => {
                if (acc && typeof acc === 'object' && key in acc) return acc[key];
                return undefined;
            }, profile);
            return value === undefined ? fallback : value;
        };

        return {
            lookbackDays: get('dataLayer.lookbackDays'),
            maxCandidateVulnerabilities: get('dataLayer.maxCandidateVulnerabilities'),
            minCvssForCandidates: get('dataLayer.candidateFilters.minCvssForCandidates'),
            minEpssForCandidates: get('dataLayer.candidateFilters.minEpssForCandidates'),
            knownExploitedBoost: get('riskScoring.boosts.knownExploitedBoost'),
            publicExploitBoost: get('riskScoring.boosts.publicExploitBoost'),
            epssHighBoost: get('riskScoring.boosts.epssHighBoost'),
            epssMediumBoost: get('riskScoring.boosts.epssMediumBoost'),
            epssHighThreshold: get('riskScoring.thresholds.epssHighThreshold'),
            epssMediumThreshold: get('riskScoring.thresholds.epssMediumThreshold'),
            topRiskCount: get('riskScoring.ordering.topRiskCount'),
            promptTemplate: get('aiLayer.promptProfile.template'),
            promptPersona: get('aiLayer.promptProfile.persona'),
            promptLanguage: get('aiLayer.promptProfile.language'),
            promptExtraInstructions: get('aiLayer.promptProfile.extraInstructions'),
            aiModelOverride: get('aiLayer.model'),
            subjectPrefix: get('notificationOutput.subjectPrefix'),
            emailTitle: get('notificationOutput.contentCustomization.emailTitle'),
            introText: get('notificationOutput.contentCustomization.introText'),
            footerText: get('notificationOutput.contentCustomization.footerText'),
            sectionExecutiveTitle: get('notificationOutput.sectionTitles.executive'),
            sectionTopRiskTitle: get('notificationOutput.sectionTitles.topRisk'),
            sectionCorrelationsTitle: get('notificationOutput.sectionTitles.correlations'),
            sectionRoadmapTitle: get('notificationOutput.sectionTitles.roadmap'),
            sectionTechnicalTitle: get('notificationOutput.sectionTitles.technical'),
            showExecutiveSection: get('notificationOutput.sectionVisibility.showExecutiveSection'),
            showStatsSection: get('notificationOutput.sectionVisibility.showStatsSection'),
            showTopRiskSection: get('notificationOutput.sectionVisibility.showTopRiskSection'),
            showCorrelationsSection: get('notificationOutput.sectionVisibility.showCorrelationsSection'),
            showRoadmapSection: get('notificationOutput.sectionVisibility.showRoadmapSection'),
            showTechnicalSection: get('notificationOutput.sectionVisibility.showTechnicalSection'),
            includeTechnicalTable: get('notificationOutput.technicalTable.includeTechnicalTable'),
            technicalTableLimit: get('notificationOutput.technicalTable.technicalTableLimit'),
        };
    }

    private buildDetailedProfileFromConfig(cfg: SmartNotificationConfig) {
        return {
            version: 1,
            name: 'smart-notifications',
            profile: 'runtime-export',
            dataLayer: {
                lookbackDays: cfg.lookbackDays,
                maxCandidateVulnerabilities: cfg.maxCandidateVulnerabilities,
                candidateFilters: {
                    minCvssForCandidates: cfg.minCvssForCandidates,
                    minEpssForCandidates: cfg.minEpssForCandidates,
                },
            },
            riskScoring: {
                boosts: {
                    knownExploitedBoost: cfg.knownExploitedBoost,
                    publicExploitBoost: cfg.publicExploitBoost,
                    epssHighBoost: cfg.epssHighBoost,
                    epssMediumBoost: cfg.epssMediumBoost,
                },
                thresholds: {
                    epssHighThreshold: cfg.epssHighThreshold,
                    epssMediumThreshold: cfg.epssMediumThreshold,
                },
                ordering: {
                    topRiskCount: cfg.topRiskCount,
                },
            },
            aiLayer: {
                model: cfg.aiModelOverride || null,
                promptProfile: {
                    template: cfg.promptTemplate,
                    persona: cfg.promptPersona,
                    language: cfg.promptLanguage,
                    extraInstructions: cfg.promptExtraInstructions,
                },
            },
            notificationOutput: {
                subjectPrefix: cfg.subjectPrefix,
                contentCustomization: {
                    emailTitle: cfg.emailTitle,
                    introText: cfg.introText,
                    footerText: cfg.footerText,
                },
                sectionTitles: {
                    executive: cfg.sectionExecutiveTitle,
                    topRisk: cfg.sectionTopRiskTitle,
                    correlations: cfg.sectionCorrelationsTitle,
                    roadmap: cfg.sectionRoadmapTitle,
                    technical: cfg.sectionTechnicalTitle,
                },
                sectionVisibility: {
                    showExecutiveSection: cfg.showExecutiveSection,
                    showStatsSection: cfg.showStatsSection,
                    showTopRiskSection: cfg.showTopRiskSection,
                    showCorrelationsSection: cfg.showCorrelationsSection,
                    showRoadmapSection: cfg.showRoadmapSection,
                    showTechnicalSection: cfg.showTechnicalSection,
                },
                technicalTable: {
                    includeTechnicalTable: cfg.includeTechnicalTable,
                    technicalTableLimit: cfg.technicalTableLimit,
                },
            },
        };
    }

    async runWeeklyForAllSubscribers(trigger: 'manual' | 'cron' = 'manual') {
        const centerSettings = await this.notificationService.getNotificationCenterSettings().catch(() => null);
        if (centerSettings?.general?.processEnabled === false || centerSettings?.intelligent?.enabled === false) {
            return {
                trigger,
                processed: 0,
                sent: 0,
                skipped: 0,
                failed: 0,
                skippedByPolicy: true,
                reason: 'intelligent_notifications_disabled',
                results: [],
            };
        }

        let jobRunId: number | null = null;
        try {
            const job = await this.notificationService.startNotificationJobRun('intelligent_notification_job', trigger === 'cron' ? 'cron' : 'manual', {
                source: 'smart-notifications',
            });
            jobRunId = Number(job?.id || 0) || null;
        } catch (error) {
            this.logger.warn(`Intelligent notification job already running or unavailable: ${error instanceof Error ? error.message : error}`);
        }

        try {
            const subscribers = await this.prisma.user.findMany({
                where: {
                    isActive: true,
                    isSubscriber: true,
                    canReceiveNotifications: true,
                    notificationsPaused: false,
                },
                select: {
                    id: true,
                    notificationsPausedUntil: true,
                },
                orderBy: { id: 'asc' },
            });

            const results: WeeklyRunResult[] = [];
            for (const subscriber of subscribers) {
                if (subscriber.notificationsPausedUntil && new Date(subscriber.notificationsPausedUntil).getTime() > Date.now()) {
                    results.push({
                        subscriberId: subscriber.id,
                        status: 'skipped',
                        reason: 'Notifications paused until future date',
                    });
                    continue;
                }
                try {
                    const result = await this.runWeeklyForSubscriber(subscriber.id, { trigger });
                    results.push(result);
                } catch (error) {
                    const message = error instanceof Error ? error.message : 'Unknown error';
                    this.logger.error(`Smart weekly report failed for subscriber=${subscriber.id}: ${message}`);
                    results.push({
                        subscriberId: subscriber.id,
                        status: 'failed',
                        reason: message,
                    } as WeeklyRunResult);
                }
            }

            const response = {
                trigger,
                processed: results.length,
                sent: results.filter((r) => r.status === 'sent').length,
                skipped: results.filter((r) => r.status === 'skipped').length,
                failed: results.filter((r) => r.status === 'failed').length,
                results,
            };
            if (jobRunId) {
                const watermarkStarts = results
                    .map((item) => item.periodStart)
                    .filter((item): item is Date => item instanceof Date && !Number.isNaN(item.getTime()))
                    .sort((a, b) => a.getTime() - b.getTime());
                const watermarkEnds = results
                    .map((item) => item.periodEnd)
                    .filter((item): item is Date => item instanceof Date && !Number.isNaN(item.getTime()))
                    .sort((a, b) => a.getTime() - b.getTime());
                await this.notificationService.completeNotificationJobRun(jobRunId, {
                    notificationsSent: response.sent,
                    notificationsFailed: response.failed,
                    vulnerabilitiesConsidered: results.reduce((sum, item) => sum + Number(item.totalVulnerabilities || 0), 0),
                    queuePending: 0,
                    watermarkFrom: watermarkStarts[0] || null,
                    watermarkTo: watermarkEnds[watermarkEnds.length - 1] || null,
                    details: response,
                }).catch(() => undefined);
            }
            return response;
        } catch (error) {
            if (jobRunId) {
                await this.notificationService.failNotificationJobRun(jobRunId, error, {
                    details: {
                        source: 'smart-notifications',
                        trigger,
                    },
                }).catch(() => undefined);
            }
            throw error;
        }
    }

    async runWeeklyForSubscriber(subscriberId: number, options?: { trigger?: 'manual' | 'cron' }) {
        try {
            const trigger = options?.trigger || 'manual';
            const smartConfig = await this.loadSmartConfig();
            const { periodStart, periodEnd } = this.getLookbackWindow(smartConfig.lookbackDays);

            const dataset = await this.buildSubscriberDataset(subscriberId, periodStart, periodEnd, smartConfig);
            if (!dataset) {
                return {
                    subscriberId,
                    status: 'failed',
                    reason: 'Subscriber not found or inactive',
                } as WeeklyRunResult;
            }

            if (dataset.vulnerabilities.length === 0) {
                return {
                    subscriberId,
                    status: 'skipped',
                    reason: `No matching vulnerabilities in ${smartConfig.lookbackDays}-day window`,
                    periodStart,
                    periodEnd,
                } as WeeklyRunResult;
            }

            const effectiveAi = await this.getEffectiveAiSettings(smartConfig);
            const { promptSystem, promptUser } = this.buildCorrelationPrompt(dataset, smartConfig);

            const report = await (this.prisma as any).smartNotificationReport.create({
                data: {
                    subscriberUserId: dataset.subscriber.id,
                    periodStart,
                    periodEnd,
                    recipientEmail: dataset.subscriber.email,
                    status: 'generated',
                    aiProvider: effectiveAi.provider,
                    aiModel: effectiveAi.model,
                    inputSnapshot: JSON.stringify({
                        trigger,
                        configProfile: smartConfig,
                        stats: dataset.stats,
                        ownedSystems: dataset.ownedSystems,
                        groupedAssets: dataset.groupedAssets,
                        vulnerabilities: dataset.vulnerabilities.map((v) => ({
                            cveId: v.cveId,
                            attackVector: v.attackVector,
                            cvssV31Score: v.cvssV31Score,
                            cvssV31Severity: v.cvssV31Severity,
                            epssScore: v.epssScore,
                            hasPublicExploit: v.hasPublicExploit,
                            isKnownExploited: v.isKnownExploited,
                            sources: v.sources,
                            affectedProducts: v.affectedProducts,
                        })),
                    }),
                },
            });

            try {
                const aiResponse = await this.aiService.chatStructuredJson([
                    { role: 'system', content: promptSystem },
                    { role: 'user', content: promptUser },
                ], { model: effectiveAi.model });

                const aiContent = this.extractAiContent(aiResponse);
                const analysis = this.parseAnalysisJson(aiContent, dataset, smartConfig);

                const subject = `${smartConfig.subjectPrefix} — ${dataset.subscriber.name} (${dataset.stats.total} CVEs)`;
                const context = this.buildWeeklyEmailContext(dataset, analysis, smartConfig);

                const sent = await this.notificationService.sendEmail(
                    dataset.subscriber.email,
                    subject,
                    'smart-weekly-report',
                    context,
                );

                await (this.prisma as any).smartNotificationReport.update({
                    where: { id: report.id },
                    data: {
                        subject,
                        status: sent ? 'sent' : 'failed',
                        sentAt: sent ? new Date() : null,
                        analysisJson: JSON.stringify(analysis),
                        errorMessage: sent ? null : 'SMTP send failed',
                    },
                });

                return {
                    subscriberId,
                    reportId: report.id,
                    status: sent ? 'sent' : 'failed',
                    reason: sent ? undefined : 'SMTP send failed',
                    totalVulnerabilities: dataset.vulnerabilities.length,
                    periodStart,
                    periodEnd,
                    emailSent: !!sent,
                } as WeeklyRunResult;
            } catch (error) {
                const message = error instanceof Error ? error.message : 'Unknown error';
                this.logger.error(`Smart weekly report failed for subscriber=${subscriberId}: ${message}`);

                await (this.prisma as any).smartNotificationReport.update({
                    where: { id: report.id },
                    data: {
                        status: 'failed',
                        errorMessage: message,
                    },
                });

                return {
                    subscriberId,
                    reportId: report.id,
                    status: 'failed',
                    reason: message,
                    periodStart,
                    periodEnd,
                } as WeeklyRunResult;
            }
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Unknown error';
            this.logger.error(`runWeeklyForSubscriber failed for subscriber=${subscriberId}: ${message}`, error instanceof Error ? error.stack : '');
            return {
                subscriberId,
                status: 'failed',
                reason: `Error: ${message}`,
            } as WeeklyRunResult;
        }
    }

    async previewWeeklyForSubscriber(subscriberId: number) {
        try {
            const smartConfig = await this.loadSmartConfig();
            const { periodStart, periodEnd } = this.getLookbackWindow(smartConfig.lookbackDays);
            const dataset = await this.buildSubscriberDataset(subscriberId, periodStart, periodEnd, smartConfig);

            if (!dataset) {
                return {
                    subscriberId,
                    status: 'failed',
                    reason: 'Subscriber not found or inactive',
                };
            }

            if (dataset.vulnerabilities.length === 0) {
                return {
                    subscriberId,
                    status: 'skipped',
                    reason: `No matching vulnerabilities in ${smartConfig.lookbackDays}-day window`,
                    datasetStats: dataset.stats,
                };
            }

            const effectiveAi = await this.getEffectiveAiSettings(smartConfig);
            const { promptSystem, promptUser } = this.buildCorrelationPrompt(dataset, smartConfig);

            let analysis: SmartAnalysisResult;
            let usedFallback = false;

            try {
                const aiResponse = await this.aiService.chatStructuredJson([
                    { role: 'system', content: promptSystem },
                    { role: 'user', content: promptUser },
                ], { model: effectiveAi.model });
                const aiContent = this.extractAiContent(aiResponse);
                analysis = this.parseAnalysisJson(aiContent, dataset, smartConfig);
            } catch (aiError) {
                this.logger.error(`AI analysis failed for preview subscriber=${subscriberId}: ${aiError instanceof Error ? aiError.message : 'Unknown'}`);
                analysis = this.buildFallbackAnalysis(dataset, smartConfig);
                usedFallback = true;
            }

            const subject = `${smartConfig.subjectPrefix} — ${dataset.subscriber.name} (${dataset.stats.total} CVEs)`;
            const context = this.buildWeeklyEmailContext(dataset, analysis, smartConfig);
            const html = await this.notificationService.renderTemplate('smart-weekly-report', context);

            return {
                subscriberId,
                status: 'preview',
                subject,
                usedFallback,
                aiProvider: effectiveAi.provider,
                aiModel: effectiveAi.model,
                configProfile: smartConfig,
                datasetStats: dataset.stats,
                analysis,
                html,
            };
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Unknown error';
            this.logger.error(`Preview failed for subscriber=${subscriberId}: ${message}`, error instanceof Error ? error.stack : '');
            return {
                subscriberId,
                status: 'failed',
                reason: `Error generating preview: ${message}`,
            };
        }
    }

    async testWeeklyForSubscriber(subscriberId: number) {
        try {
            const smartConfig = await this.loadSmartConfig();
            const { periodStart, periodEnd } = this.getLookbackWindow(smartConfig.lookbackDays);
            const dataset = await this.buildSubscriberDataset(subscriberId, periodStart, periodEnd, smartConfig);

            if (!dataset) {
                return {
                    subscriberId,
                    status: 'failed',
                    reason: 'Subscriber not found or inactive',
                };
            }

            if (dataset.vulnerabilities.length === 0) {
                return {
                    subscriberId,
                    status: 'skipped',
                    reason: `No matching vulnerabilities in ${smartConfig.lookbackDays}-day window`,
                    datasetStats: dataset.stats,
                };
            }

            const effectiveAi = await this.getEffectiveAiSettings(smartConfig);
            const { promptSystem, promptUser } = this.buildCorrelationPrompt(dataset, smartConfig);

            let analysis: SmartAnalysisResult;
            let usedFallback = false;

            try {
                const aiResponse = await this.aiService.chatStructuredJson([
                    { role: 'system', content: promptSystem },
                    { role: 'user', content: promptUser },
                ], { model: effectiveAi.model });
                const aiContent = this.extractAiContent(aiResponse);
                analysis = this.parseAnalysisJson(aiContent, dataset, smartConfig);
            } catch (aiError) {
                this.logger.error(`AI analysis failed for test subscriber=${subscriberId}: ${aiError instanceof Error ? aiError.message : 'Unknown'}`);
                analysis = this.buildFallbackAnalysis(dataset, smartConfig);
                usedFallback = true;
            }

            const subject = `${smartConfig.subjectPrefix} [TEST] — ${dataset.subscriber.name} (${dataset.stats.total} CVEs)`;
            const context = this.buildWeeklyEmailContext(dataset, analysis, smartConfig);
            const html = await this.notificationService.renderTemplate('smart-weekly-report', context);
            const sent = await this.notificationService.sendEmail(
                dataset.subscriber.email,
                subject,
                'smart-weekly-report',
                context,
            );

            return {
                subscriberId,
                status: sent ? 'sent' : 'failed',
                reason: sent ? undefined : 'SMTP send failed',
                isTest: true,
                usedFallback,
                aiProvider: effectiveAi.provider,
                aiModel: effectiveAi.model,
                recipientEmail: dataset.subscriber.email,
                subject,
                configProfile: smartConfig,
                datasetStats: dataset.stats,
                analysis,
                html,
            };
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Unknown error';
            this.logger.error(`Test failed for subscriber=${subscriberId}: ${message}`, error instanceof Error ? error.stack : '');
            return {
                subscriberId,
                status: 'failed',
                reason: `Error generating test: ${message}`,
            };
        }
    }

    async getWeeklyHistory(page = 1, limit = 20, subscriberId?: number) {
        const safePage = Number.isFinite(page) && page > 0 ? Math.floor(page) : 1;
        const safeLimit = Number.isFinite(limit) && limit > 0 ? Math.min(Math.floor(limit), 100) : 20;
        const skip = (safePage - 1) * safeLimit;

        const where = subscriberId
            ? { subscriberUserId: subscriberId }
            : undefined;

        const [items, total] = await Promise.all([
            (this.prisma as any).smartNotificationReport.findMany({
                where,
                include: {
                    subscriber: {
                        select: { id: true, name: true, email: true },
                    },
                },
                orderBy: { periodEnd: 'desc' },
                take: safeLimit,
                skip,
            }),
            (this.prisma as any).smartNotificationReport.count({ where }),
        ]);

        return {
            page: safePage,
            limit: safeLimit,
            total,
            items,
        };
    }

    async getCandidates(
        page = 1,
        limit = 20,
        minScore = 7,
        daysWithoutNotify = 7,
    ) {
        const safePage = Number.isFinite(page) && page > 0 ? Math.floor(page) : 1;
        const safeLimit = Number.isFinite(limit) && limit > 0 ? Math.min(Math.floor(limit), 100) : 20;
        const safeMinScore = Number.isFinite(minScore) ? minScore : 7;
        const safeDays = Number.isFinite(daysWithoutNotify) && daysWithoutNotify >= 0
            ? Math.floor(daysWithoutNotify)
            : 7;

        const vulnerabilities = await this.prisma.vulnerability.findMany({
            where: {
                OR: [
                    { cvssV31Score: { gte: safeMinScore } },
                    { hasPublicExploit: true },
                    { isKnownExploited: true },
                ],
            },
            select: {
                id: true,
                cveId: true,
                cvssV31Score: true,
                cvssV31Severity: true,
                epssScore: true,
                hasPublicExploit: true,
                isKnownExploited: true,
                publishedAt: true,
                notifications: {
                    select: { sentAt: true },
                    orderBy: { sentAt: 'desc' },
                    take: 1,
                },
            },
            orderBy: [
                { publishedAt: 'desc' },
                { id: 'desc' },
            ],
        });

        const now = Date.now();
        const thresholdMs = safeDays * 24 * 60 * 60 * 1000;

        const mapped: CandidateItem[] = vulnerabilities.map((vulnerability) => {
            const riskLevel = this.computeRiskLevel(vulnerability);
            const smartReason = this.computeSmartReason(vulnerability);
            const lastNotifiedAt = vulnerability.notifications[0]?.sentAt || null;
            const shouldNotifyNow = !lastNotifiedAt || (now - lastNotifiedAt.getTime()) > thresholdMs;

            return {
                id: vulnerability.id,
                cveId: vulnerability.cveId,
                cvssV31Score: vulnerability.cvssV31Score,
                cvssV31Severity: vulnerability.cvssV31Severity,
                epssScore: vulnerability.epssScore,
                hasPublicExploit: vulnerability.hasPublicExploit,
                isKnownExploited: vulnerability.isKnownExploited,
                publishedAt: vulnerability.publishedAt,
                riskLevel,
                smartReason,
                lastNotifiedAt,
                shouldNotifyNow,
            };
        });

        const riskWeight: Record<RiskLevel, number> = {
            critical: 3,
            high: 2,
            medium: 1,
        };

        mapped.sort((a, b) => {
            const byRisk = riskWeight[b.riskLevel] - riskWeight[a.riskLevel];
            if (byRisk !== 0) return byRisk;

            const byPublishedAt = b.publishedAt.getTime() - a.publishedAt.getTime();
            if (byPublishedAt !== 0) return byPublishedAt;

            return b.id - a.id;
        });

        const total = mapped.length;
        const start = (safePage - 1) * safeLimit;
        const items = mapped.slice(start, start + safeLimit);

        return {
            page: safePage,
            limit: safeLimit,
            total,
            items,
        };
    }

    async buildSummary(vulnerabilityIds: number[]) {
        const uniqueIds = Array.from(new Set((vulnerabilityIds || []).filter(id => Number.isInteger(id) && id > 0)));

        if (uniqueIds.length === 0) {
            return {
                total: 0,
                critical: 0,
                high: 0,
                medium: 0,
                recommendedSubject: '[OCC] Alerta inteligente: 0 vulnerabilidades priorizadas',
                recommendationText: 'No se seleccionaron vulnerabilidades para notificar.\nSeleccione CVEs críticas o altas para iniciar una alerta priorizada.',
            };
        }

        const vulnerabilities = await this.prisma.vulnerability.findMany({
            where: { id: { in: uniqueIds } },
            select: {
                id: true,
                cvssV31Score: true,
                epssScore: true,
                hasPublicExploit: true,
                isKnownExploited: true,
            },
        });

        let critical = 0;
        let high = 0;
        let medium = 0;

        for (const vulnerability of vulnerabilities) {
            const riskLevel = this.computeRiskLevel(vulnerability);
            if (riskLevel === 'critical') critical += 1;
            else if (riskLevel === 'high') high += 1;
            else medium += 1;
        }

        const total = vulnerabilities.length;

        return {
            total,
            critical,
            high,
            medium,
            recommendedSubject: `[OCC] Alerta inteligente: ${total} vulnerabilidades priorizadas`,
            recommendationText: `Se priorizaron ${total} vulnerabilidades: ${critical} críticas, ${high} altas y ${medium} medias.\nRecomendación: notificar primero las críticas y altas para reducir exposición inmediata.\nMantenga las medias en cola para comunicación programada y seguimiento.`,
        };
    }

    private computeRiskLevel(vulnerability: {
        cvssV31Score?: number | null;
        epssScore?: number | null;
        hasPublicExploit: boolean;
        isKnownExploited: boolean;
    }): RiskLevel {
        const cvss = vulnerability.cvssV31Score || 0;
        const epss = vulnerability.epssScore || 0;

        if (
            vulnerability.isKnownExploited ||
            vulnerability.hasPublicExploit ||
            cvss >= 9 ||
            epss >= 0.7
        ) {
            return 'critical';
        }

        if (cvss >= 7 || epss >= 0.3) {
            return 'high';
        }

        return 'medium';
    }

    private computeSmartReason(vulnerability: {
        cvssV31Score?: number | null;
        epssScore?: number | null;
        hasPublicExploit: boolean;
        isKnownExploited: boolean;
    }): string {
        const cvss = vulnerability.cvssV31Score || 0;
        const epss = vulnerability.epssScore || 0;

        if (vulnerability.isKnownExploited) {
            return 'Explotación conocida (KEV)';
        }

        if (vulnerability.hasPublicExploit) {
            return 'Exploit público disponible';
        }

        if (cvss >= 9 && epss >= 0.3) {
            return 'CVSS alto y probabilidad EPSS relevante';
        }

        if (cvss >= 9) {
            return 'Severidad CVSS crítica';
        }

        if (epss >= 0.7) {
            return 'Alta probabilidad de explotación (EPSS)';
        }

        if (cvss >= 7 && epss >= 0.3) {
            return 'CVSS alto y probabilidad EPSS relevante';
        }

        if (cvss >= 7) {
            return 'CVSS alto';
        }

        if (epss >= 0.3) {
            return 'Probabilidad EPSS relevante';
        }

        return 'Priorización preventiva por riesgo observado';
    }

    private getLookbackWindow(lookbackDays = 180) {
        const periodEnd = new Date();
        const periodStart = new Date(periodEnd.getTime() - lookbackDays * 24 * 60 * 60 * 1000);
        return { periodStart, periodEnd };
    }

    private async buildSubscriberDataset(
        subscriberId: number,
        periodStart: Date,
        periodEnd: Date,
        smartConfig: SmartNotificationConfig,
    ): Promise<SubscriberDataset | null> {
        const subscriber = await this.prisma.user.findFirst({
            where: {
                id: subscriberId,
                isActive: true,
                isSubscriber: true,
            },
            select: {
                id: true,
                name: true,
                email: true,
                notificationEmail: true,
            },
        });

        if (!subscriber) return null;

        // Separately fetch subscriptions to ensure proper retrieval
        const userSubscriptions = await this.prisma.userSubscription.findMany({
            where: {
                userId: subscriber.id,
                isActive: true,
            },
            select: {
                id: true,
                vendor: true,
                product: true,
                versions: true,
            },
        });

        this.logger.debug(
            `Subscriber ${subscriber.id} (${subscriber.name}) has ${userSubscriptions.length} active subscriptions`
        );

        const ownedSystems = await (this.prisma as any).subscriberOwnedSystem.findMany({
            where: {
                subscriberUserId: subscriber.id,
                isActive: true,
            },
            select: {
                externalId: true,
                hostname: true,
                platform: true,
                riskLevel: true,
                source: true,
                isSelected: true,
            },
            orderBy: [{ isSelected: 'desc' }, { hostname: 'asc' }],
        });

        const normalizedSubscriptions = (userSubscriptions || []).map((subscription) => ({
            vendor: normalizeName(subscription.vendor),
            product: normalizeName(subscription.product),
            versions: this.parseJsonArray(subscription.versions || '[]').map((version) => version.toLowerCase()),
        }));

        const sentNotifications = await this.prisma.vulnerabilityNotification.findMany({
            where: {
                subscriberUserId: subscriber.id,
                status: 'sent',
                sentAt: {
                    gte: periodStart,
                    lte: periodEnd,
                },
            },
            select: { vulnerabilityId: true },
        });

        const notifiedIds = [...new Set(sentNotifications.map((notification) => notification.vulnerabilityId))];
        const notifiedVulnerabilities = notifiedIds.length
            ? await this.prisma.vulnerability.findMany({
                where: { id: { in: notifiedIds } },
                select: {
                    id: true,
                    cveId: true,
                    description: true,
                    publishedAt: true,
                    cvssV31Score: true,
                    cvssV31Severity: true,
                    cvssV31Vector: true,
                    epssScore: true,
                    hasPublicExploit: true,
                    isKnownExploited: true,
                    affectedProducts: true,
                    exploitReferences: true,
                    references: true,
                },
            })
            : [];

        const candidateNewMatches = await this.prisma.vulnerability.findMany({
            where: {
                publishedAt: { gte: periodStart, lte: periodEnd },
                OR: [
                    { cvssV31Score: { gte: smartConfig.minCvssForCandidates } },
                    { epssScore: { gte: smartConfig.minEpssForCandidates } },
                    { hasPublicExploit: true },
                    { isKnownExploited: true },
                ],
            },
            select: {
                id: true,
                cveId: true,
                description: true,
                publishedAt: true,
                cvssV31Score: true,
                cvssV31Severity: true,
                cvssV31Vector: true,
                epssScore: true,
                hasPublicExploit: true,
                isKnownExploited: true,
                affectedProducts: true,
                exploitReferences: true,
                references: true,
            },
            orderBy: [{ isKnownExploited: 'desc' }, { cvssV31Score: 'desc' }],
            take: Math.max(100, smartConfig.maxCandidateVulnerabilities * 3),
        });

        const vulnerabilityMap = new Map<number, SmartDatasetVulnerability>();
        for (const vulnerability of notifiedVulnerabilities) {
            vulnerabilityMap.set(
                vulnerability.id,
                this.toSmartDatasetVulnerability(vulnerability, ['notified'], smartConfig),
            );
        }

        for (const vulnerability of candidateNewMatches) {
            const matchedProducts = getMatchedProducts(
                normalizedSubscriptions,
                this.parseAffectedProducts(vulnerability.affectedProducts),
            );

            if (matchedProducts.length === 0) continue;

            if (vulnerabilityMap.has(vulnerability.id)) {
                const existing = vulnerabilityMap.get(vulnerability.id)!;
                if (!existing.sources.includes('matched')) {
                    existing.sources.push('matched');
                }
                continue;
            }

            vulnerabilityMap.set(
                vulnerability.id,
                this.toSmartDatasetVulnerability(vulnerability, ['matched'], smartConfig),
            );
        }

        // Filter out CVEs the subscriber has already marked as patched
        const patchedCves = await (this.prisma as any).subscriberPatchedCve.findMany({
            where: { userId: subscriber.id },
            select: { cveId: true },
        });
        const patchedCveIds = new Set<string>(patchedCves.map((p: any) => p.cveId));

        const vulnerabilities = [...vulnerabilityMap.values()]
            .filter((v) => !patchedCveIds.has(v.cveId))
            .sort((a, b) => b.realRiskScore - a.realRiskScore)
            .slice(0, smartConfig.maxCandidateVulnerabilities);

        if (patchedCveIds.size > 0) {
            this.logger.debug(
                `Subscriber ${subscriber.id}: excluded ${patchedCveIds.size} patched CVEs from dataset`,
            );
        }

        const groupedAssetsMap = new Map<string, { vendor: string; product: string; cveIds: Set<string> }>();
        for (const vulnerability of vulnerabilities) {
            const matchedProducts = getMatchedProducts(normalizedSubscriptions, vulnerability.affectedProducts);
            const productsToUse = matchedProducts.length > 0 ? matchedProducts : vulnerability.affectedProducts;

            for (const product of productsToUse) {
                const vendor = String(product.vendor || 'unknown').trim();
                const productName = String(product.product || 'unknown').trim();
                const key = `${vendor.toLowerCase()}:${productName.toLowerCase()}`;

                if (!groupedAssetsMap.has(key)) {
                    groupedAssetsMap.set(key, {
                        vendor,
                        product: productName,
                        cveIds: new Set<string>(),
                    });
                }

                groupedAssetsMap.get(key)!.cveIds.add(vulnerability.cveId);
            }
        }

        const groupedAssets = [...groupedAssetsMap.values()]
            .map((asset) => ({
                vendor: asset.vendor,
                product: asset.product,
                cveIds: [...asset.cveIds],
            }))
            .sort((a, b) => b.cveIds.length - a.cveIds.length);

        return {
            subscriber: {
                id: subscriber.id,
                name: subscriber.name,
                email: subscriber.notificationEmail || subscriber.email,
            },
            periodStart,
            periodEnd,
            vulnerabilities,
            groupedAssets,
            ownedSystems,
            stats: {
                total: vulnerabilities.length,
                notifiedCount: vulnerabilities.filter((v) => v.sources.includes('notified')).length,
                matchedCount: vulnerabilities.filter((v) => v.sources.includes('matched')).length,
                withExploit: vulnerabilities.filter((v) => v.hasPublicExploit).length,
                knownExploited: vulnerabilities.filter((v) => v.isKnownExploited).length,
                highOrCritical: vulnerabilities.filter((v) => (v.cvssV31Score || 0) >= 7.5).length,
            },
        };
    }

    private toSmartDatasetVulnerability(
        vulnerability: any,
        sources: Array<'notified' | 'matched'>,
        smartConfig: SmartNotificationConfig,
    ): SmartDatasetVulnerability {
        const affectedProducts = this.parseAffectedProducts(vulnerability.affectedProducts);
        const cvssScore = vulnerability.cvssV31Score || 0;
        const epssScore = vulnerability.epssScore || 0;

        let risk = cvssScore;
        if (vulnerability.isKnownExploited) risk += smartConfig.knownExploitedBoost;
        if (vulnerability.hasPublicExploit) risk += smartConfig.publicExploitBoost;
        if (epssScore >= smartConfig.epssHighThreshold) risk += smartConfig.epssHighBoost;
        else if (epssScore >= smartConfig.epssMediumThreshold) risk += smartConfig.epssMediumBoost;

        return {
            id: vulnerability.id,
            cveId: vulnerability.cveId,
            description: String(vulnerability.description || 'Sin descripción disponible'),
            publishedAt: vulnerability.publishedAt,
            cvssV31Score: vulnerability.cvssV31Score,
            cvssV31Severity: vulnerability.cvssV31Severity,
            cvssV31Vector: vulnerability.cvssV31Vector,
            attackVector: this.resolveAttackVector(vulnerability.cvssV31Vector),
            epssScore: vulnerability.epssScore,
            hasPublicExploit: !!vulnerability.hasPublicExploit,
            isKnownExploited: !!vulnerability.isKnownExploited,
            affectedProducts,
            exploitReferences: this.parseJsonArray(vulnerability.exploitReferences || '[]'),
            references: this.parseJsonArray(vulnerability.references || '[]'),
            sources,
            realRiskScore: Number(risk.toFixed(2)),
        };
    }

    private async getEffectiveAiSettings(smartConfig: SmartNotificationConfig) {
        const aiConfig = await this.aiService.getConfig();
        const overrideModel = String(smartConfig.aiModelOverride || '').trim();

        return {
            provider: aiConfig.provider,
            model: overrideModel || aiConfig.model,
        };
    }

    private renderSmartPromptTemplate(
        template: string,
        dataset: SubscriberDataset,
        smartConfig: SmartNotificationConfig,
    ) {
        const values: Record<string, string> = {
            lookbackDays: String(smartConfig.lookbackDays),
            topRiskCount: String(smartConfig.topRiskCount),
            promptLanguage: smartConfig.promptLanguage,
            promptPersona: smartConfig.promptPersona,
            subscriberName: dataset.subscriber.name,
            subscriberId: String(dataset.subscriber.id),
        };

        return String(template || '').replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_, key: string) => {
            return key in values ? values[key] : '';
        });
    }

    private buildCorrelationPrompt(dataset: SubscriberDataset, smartConfig: SmartNotificationConfig) {
        const vulnerabilityLines = dataset.vulnerabilities.map((vulnerability) => {
            const products = vulnerability.affectedProducts
                .slice(0, 6)
                .map((product) => `${product.vendor}/${product.product}`)
                .join(', ') || 'N/D';

            return [
                `${vulnerability.cveId}`,
                `desc=${vulnerability.description.slice(0, 220)}`,
                `cvss=${vulnerability.cvssV31Score ?? 'n/a'}(${vulnerability.cvssV31Severity || 'UNKNOWN'})`,
                `attackVector=${vulnerability.attackVector}`,
                `kev=${vulnerability.isKnownExploited ? 'yes' : 'no'}`,
                `poc=${vulnerability.hasPublicExploit ? 'yes' : 'no'}`,
                `epss=${vulnerability.epssScore ?? 'n/a'}`,
                `products=${products}`,
                `sources=${vulnerability.sources.join('+')}`,
            ].join(' | ');
        });

        const assetLines = dataset.groupedAssets
            .slice(0, 100)
            .map((asset) => `${asset.vendor}/${asset.product} => ${asset.cveIds.join(', ')}`);

        const ownerSystemLines = dataset.ownedSystems
            .filter((system) => system.isSelected)
            .slice(0, 100)
            .map((system) => `${system.hostname} (${system.platform || 'unknown'}) | risk=${system.riskLevel || 'n/a'} | source=${system.source}`);

        const promptTemplate = String(smartConfig.promptTemplate || '').trim();
        const promptSystem = promptTemplate
            ? this.renderSmartPromptTemplate(promptTemplate, dataset, smartConfig)
            : [
                `Actúa como ${smartConfig.promptPersona} especializado en exploit chaining y análisis de riesgo acumulado.`,
                'Responde EXCLUSIVAMENTE con JSON válido. No incluyas markdown, no incluyas texto fuera del JSON.',
                '',
                'TU TAREA PRINCIPAL es detectar CADENAS DE EXPLOTACIÓN (exploit chains):',
                '- Busca CVEs que afectan al MISMO sistema/producto y podrían combinarse en un ataque secuencial.',
                '- Identifica patrones: acceso inicial (ej: Network+RCE) → escalada de privilegios (ej: Local+EoP) → movimiento lateral o exfiltración.',
                '- Valora si un atacante con acceso a un exploit público (PoC/KEV) podría encadenar con otro CVE del mismo fabricante/producto.',
                '- Prioriza cadenas donde al menos un eslabón tiene KEV=yes o PoC=yes.',
                '- Analiza los vectores de ataque (attackVector) para determinar accesibilidad: Network > Adjacent > Local > Physical.',
                '',
                'TAREAS SECUNDARIAS:',
                '- Evalúa riesgo acumulado: si un fabricante/producto tiene >3 CVEs de alto riesgo en la ventana, es señal de alerta sistémica.',
                '- Detecta patrones recurrentes: si un vendor tiene CVEs del mismo tipo (ej: múltiples RCE, múltiples SQLi), indica tendencia.',
                '',
                'CRITERIOS DE PRIORIZACIÓN:',
                '- Criticidad real = CVSS × explotabilidad (KEV > PoC > EPSS alto > sin exploit conocido).',
                '- Una CVE CVSS 7.5 con KEV=yes es MÁS urgente que una CVE CVSS 10.0 sin exploit conocido.',
                '- Vector de ataque Network siempre más accesible que Local.',
                '- EPSS >= 0.7 indica alta probabilidad de explotación inminente.',
                '',
                'Si faltan datos para confirmar una cadena, indícalo como hipótesis con el nivel de confianza.',
                `Idioma de respuesta: ${smartConfig.promptLanguage === 'en' ? 'English' : 'Español'}.`,
                smartConfig.promptExtraInstructions ? `Instrucciones extra: ${smartConfig.promptExtraInstructions}` : '',
                '',
                'Esquema JSON de salida obligatorio:',
                '{',
                '  "executiveSummary": "string (2-4 frases, lenguaje ejecutivo, menciona las cadenas detectadas y el riesgo principal)",',
                '  "top3RealRisk": [',
                '    {',
                '      "cveId": "string",',
                '      "reason": "string (incluye evidencia de explotabilidad: KEV, PoC, EPSS)",',
                '      "priority": "immediate|high|medium",',
                '      "evidence": ["string (datos concretos que sustentan la prioridad)"]',
                '    }',
                '  ],',
                '  "detectedCorrelations": [',
                '    {',
                '      "title": "string (nombre descriptivo de la cadena o correlación)",',
                '      "description": "string (paso a paso: cómo un atacante encadenaría estos CVEs)",',
                '      "involvedCves": ["string"],',
                '      "attackPath": "string (ej: Initial Access via CVE-X (Network/RCE) → Privilege Escalation via CVE-Y (Local/EoP) → Data Exfiltration)",',
                '      "riskLevel": "critical|high|medium"',
                '    }',
                '  ],',
                '  "mitigationRoadmap": [',
                '    {',
                '      "order": 1,',
                '      "action": "string (acción concreta y específica: parchear, aislar, monitorizar...)",',
                '      "why": "string (justificación técnica de por qué esta acción primero)",',
                '      "cves": ["string"]',
                '    }',
                '  ]',
                '}',
            ].join('\n');

        const promptUser = [
            `Suscriptor: ${dataset.subscriber.name} (id=${dataset.subscriber.id})`,
            `Ventana: ${dataset.periodStart.toISOString()} a ${dataset.periodEnd.toISOString()}`,
            `Totales: ${JSON.stringify(dataset.stats)}`,
            'Sistemas owner seleccionados del suscriptor:',
            ...(ownerSystemLines.length ? ownerSystemLines : ['Sin sistemas owner seleccionados']),
            '',
            'Activos agrupados por fabricante/producto:',
            ...assetLines,
            '',
            `Vulnerabilidades detectadas (últimos ${smartConfig.lookbackDays} días, notificadas + nuevas coincidentes):`,
            ...vulnerabilityLines,
            '',
            'Tareas de análisis:',
            '1) Identifica cadenas de ataque plausibles (exploit chaining) entre CVEs y/o activos.',
            '2) Evalúa criticidad agregada por fabricante/producto cuando hay múltiples fallos.',
            `3) Prioriza top ${smartConfig.topRiskCount} por probabilidad real de explotación y daño operativo hoy.`,
            '4) Propón una hoja de ruta de mitigación con pasos accionables y ordenados.',
        ].join('\n');

        return { promptSystem, promptUser };
    }

    private parseAnalysisJson(
        aiContent: string,
        dataset: SubscriberDataset,
        smartConfig: SmartNotificationConfig,
    ): SmartAnalysisResult {
        const fallback = this.buildFallbackAnalysis(dataset, smartConfig);
        if (!aiContent || !aiContent.trim()) {
            this.logger.warn('AI returned empty content, using fallback analysis');
            return fallback;
        }

        const attempts: string[] = [aiContent];
        const objectMatch = aiContent.match(/\{[\s\S]*\}/);
        if (objectMatch?.[0]) attempts.push(objectMatch[0]);

        for (const attempt of attempts) {
            try {
                const parsed = JSON.parse(attempt);
                if (
                    typeof parsed?.executiveSummary === 'string' &&
                    Array.isArray(parsed?.top3RealRisk) &&
                    Array.isArray(parsed?.detectedCorrelations) &&
                    Array.isArray(parsed?.mitigationRoadmap)
                ) {
                    return {
                        executiveSummary: parsed.executiveSummary,
                        top3RealRisk: parsed.top3RealRisk.slice(0, smartConfig.topRiskCount),
                        detectedCorrelations: parsed.detectedCorrelations.slice(0, 8),
                        mitigationRoadmap: parsed.mitigationRoadmap.slice(0, 10),
                    };
                }
            } catch (parseError) {
                this.logger.warn(
                    `AI JSON parse attempt failed: ${parseError instanceof Error ? parseError.message : 'Unknown'}. Content length=${attempt.length}`,
                );
            }
        }

        this.logger.warn('All AI JSON parse attempts failed, using fallback analysis');
        return fallback;
    }

    private buildFallbackAnalysis(dataset: SubscriberDataset, smartConfig: SmartNotificationConfig): SmartAnalysisResult {
        const top = [...dataset.vulnerabilities]
            .sort((a, b) => b.realRiskScore - a.realRiskScore)
            .slice(0, smartConfig.topRiskCount);

        return {
            executiveSummary: `Se detectaron ${dataset.stats.total} vulnerabilidades relevantes en los últimos ${smartConfig.lookbackDays} días; ${dataset.stats.knownExploited} aparecen en KEV y ${dataset.stats.withExploit} tienen PoC público, lo que incrementa la urgencia de mitigación.`,
            top3RealRisk: top.map((vulnerability, index) => ({
                cveId: vulnerability.cveId,
                reason: `Prioridad por combinación de CVSS ${vulnerability.cvssV31Score ?? 'n/a'}, EPSS ${vulnerability.epssScore ?? 'n/a'}, KEV=${vulnerability.isKnownExploited ? 'sí' : 'no'} y PoC=${vulnerability.hasPublicExploit ? 'sí' : 'no'}.`,
                priority: index === 0 ? 'immediate' : (index === 1 ? 'high' : 'medium'),
                evidence: [
                    vulnerability.isKnownExploited ? 'Incluida en CISA KEV' : 'Sin KEV confirmado',
                    vulnerability.hasPublicExploit ? 'Exploit público disponible' : 'Sin PoC público confirmado',
                    `Vector de ataque: ${vulnerability.attackVector}`,
                ],
            })),
            detectedCorrelations: [],
            mitigationRoadmap: [
                {
                    order: 1,
                    action: 'Aplicar parches y mitigaciones temporales a CVEs con KEV o PoC público.',
                    why: 'Reducen primero el riesgo de explotación activa.',
                    cves: top.map((vulnerability) => vulnerability.cveId),
                },
                {
                    order: 2,
                    action: 'Priorizar hardening y segmentación en activos con múltiples CVEs por fabricante/producto.',
                    why: 'Disminuye la posibilidad de encadenamiento entre fallos.',
                    cves: dataset.vulnerabilities.slice(0, 8).map((vulnerability) => vulnerability.cveId),
                },
            ],
        };
    }

    private buildWeeklyEmailContext(
        dataset: SubscriberDataset,
        analysis: SmartAnalysisResult,
        smartConfig: SmartNotificationConfig,
    ) {
        const top3Html = analysis.top3RealRisk.length
            ? analysis.top3RealRisk
                .map((item, index) => {
                    const evidence = Array.isArray(item.evidence)
                        ? item.evidence.map((value) => `<li>${this.escapeHtml(String(value))}</li>`).join('')
                        : '';
                    return `
<div style="border:1px solid #E5E7EB;border-radius:8px;padding:12px;margin-bottom:10px;">
  <strong>#${index + 1} ${this.escapeHtml(item.cveId || 'N/A')}</strong>
  <div style="color:#4B5563;font-size:13px;margin-top:6px;">${this.escapeHtml(item.reason || '')}</div>
  ${evidence ? `<ul style="margin:8px 0 0 18px;padding:0;">${evidence}</ul>` : ''}
</div>`;
                })
                .join('')
            : '<p>No se identificaron riesgos priorizados.</p>';

        const buildCorrelationCard = (correlation: SmartAnalysisResult['detectedCorrelations'][0]): string => {
            const riskLevel = correlation.riskLevel || 'medium';
            const attackPath = correlation.attackPath || '';
            const steps = attackPath.split(/\s*→\s*/).filter(s => s.trim());

            const headerColors: Record<string, { bg: string; badge: string; bText: string; border: string; icon: string }> = {
                critical: { bg: '#7F1D1D', badge: '#FCA5A5', bText: '#7F1D1D', border: '#FCA5A5', icon: '🔴' },
                high:     { bg: '#7C2D12', badge: '#FDBA74', bText: '#7C2D12', border: '#FDBA74', icon: '🟠' },
                medium:   { bg: '#78350F', badge: '#FDE68A', bText: '#78350F', border: '#FDE68A', icon: '🟡' },
            };
            const hc = headerColors[riskLevel] || headerColors['medium'];

            const getStepStyle = (step: string): { bg: string; color: string; icon: string } => {
                const s = step.toLowerCase();
                if (s.includes('initial access') || s.includes('network') || s.includes('reconnaissance'))
                    return { bg: '#DBEAFE', color: '#1D4ED8', icon: '🌐' };
                if (s.includes('rce') || s.includes('remote code') || s.includes('exploit') || s.includes('injection'))
                    return { bg: '#FEE2E2', color: '#B91C1C', icon: '💥' };
                if (s.includes('privilege') || s.includes('escalation') || s.includes('eop') || s.includes('lpe'))
                    return { bg: '#FEF3C7', color: '#B45309', icon: '⬆️' };
                if (s.includes('lateral') || s.includes('movement') || s.includes('pivot'))
                    return { bg: '#EDE9FE', color: '#6D28D9', icon: '↔️' };
                if (s.includes('persistence') || s.includes('backdoor'))
                    return { bg: '#F3F4F6', color: '#374151', icon: '🔒' };
                if (s.includes('exfil') || s.includes('data') || s.includes('extract') || s.includes('collection'))
                    return { bg: '#D1FAE5', color: '#065F46', icon: '📤' };
                if (s.includes('dos') || s.includes('denial') || s.includes('disrupt'))
                    return { bg: '#FFE4E6', color: '#9F1239', icon: '⛔' };
                return { bg: '#F1F5F9', color: '#475569', icon: '⚡' };
            };

            const chainNodesHtml = steps.length > 0
                ? steps.map((step, i) => {
                    const st = getStepStyle(step);
                    const isLast = i === steps.length - 1;
                    return `<span style="display:inline-flex;align-items:center;gap:3px;background:${st.bg};color:${st.color};border-radius:6px;padding:5px 10px;font-size:11px;font-weight:700;white-space:nowrap;">${st.icon} ${this.escapeHtml(step.trim())}</span>${!isLast ? '<span style="color:#F59E0B;font-weight:900;font-size:18px;line-height:1;padding:0 4px;">→</span>' : ''}`;
                }).join('')
                : `<span style="font-size:12px;color:#6B7280;">${this.escapeHtml(attackPath)}</span>`;

            const cveBadgesHtml = (correlation.involvedCves || [])
                .map(cve => `<span style="display:inline-block;background:#EFF6FF;color:#1D4ED8;border:1px solid #BFDBFE;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700;margin:2px;">${this.escapeHtml(cve)}</span>`)
                .join('');

            return `
<div style="border:1px solid ${hc.badge};border-radius:10px;margin-bottom:18px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.07);">
  <!-- Header -->
  <div style="background:${hc.bg};padding:10px 14px;display:flex;align-items:center;gap:8px;">
    <span style="font-size:15px;">${hc.icon}</span>
    <strong style="color:#fff;font-size:13px;flex:1;">${this.escapeHtml(correlation.title || 'Cadena de Ataque')}</strong>
    <span style="background:${hc.badge};color:${hc.bText};border-radius:4px;padding:2px 8px;font-size:10px;font-weight:700;text-transform:uppercase;">${this.escapeHtml(riskLevel)}</span>
  </div>
  <!-- Attack Chain Diagram -->
  <div style="padding:14px 14px 10px;background:#FAFAFA;border-bottom:1px solid #E5E7EB;">
    <div style="font-size:10px;font-weight:700;color:#6B7280;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;">🔗 Ruta de Ataque</div>
    <div style="display:flex;flex-wrap:wrap;align-items:center;gap:4px;line-height:2.2;">
      ${chainNodesHtml}
    </div>
  </div>
  <!-- CVEs involucrados -->
  <div style="padding:10px 14px;border-bottom:1px solid #E5E7EB;background:#fff;">
    <div style="font-size:10px;font-weight:700;color:#6B7280;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;">📋 CVEs Involucrados</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;">${cveBadgesHtml || '<span style="font-size:12px;color:#9CA3AF;">N/D</span>'}</div>
  </div>
  <!-- Descripción -->
  <div style="padding:10px 14px;background:#fff;">
    <div style="font-size:10px;font-weight:700;color:#6B7280;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;">📝 Descripción Técnica</div>
    <p style="margin:0;font-size:12px;color:#374151;line-height:1.6;">${this.escapeHtml(correlation.description || '')}</p>
  </div>
</div>`;
        };

        const correlationsHtml = analysis.detectedCorrelations.length
            ? analysis.detectedCorrelations.map(c => buildCorrelationCard(c)).join('')
            : '<p style="color:#6B7280;font-size:13px;">No se detectaron cadenas de ataque en esta ventana.</p>';

        const roadmapHtml = analysis.mitigationRoadmap.length
            ? analysis.mitigationRoadmap
                .sort((a, b) => (a.order || 0) - (b.order || 0))
                .map((step) => `
<div style="margin-bottom:12px;">
  <strong>Paso ${Number(step.order) || '-'}</strong>: ${this.escapeHtml(step.action || '')}
  <div style="font-size:12px;color:#6B7280;">${this.escapeHtml(step.why || '')}</div>
  <div style="font-size:12px;color:#4B5563;">CVEs: ${this.escapeHtml((step.cves || []).join(', ') || 'N/D')}</div>
</div>`)
                .join('')
            : '<p>Sin hoja de ruta específica.</p>';

        const vulnerabilityRows = dataset.vulnerabilities
            .slice(0, smartConfig.technicalTableLimit)
            .map((vulnerability) => `
<tr>
  <td style="padding:8px;border-bottom:1px solid #E5E7EB;">${this.escapeHtml(vulnerability.cveId)}</td>
  <td style="padding:8px;border-bottom:1px solid #E5E7EB;">${this.escapeHtml(String(vulnerability.cvssV31Score ?? 'n/a'))}</td>
  <td style="padding:8px;border-bottom:1px solid #E5E7EB;">${this.escapeHtml(vulnerability.attackVector)}</td>
  <td style="padding:8px;border-bottom:1px solid #E5E7EB;">${vulnerability.isKnownExploited ? 'Sí' : 'No'}</td>
  <td style="padding:8px;border-bottom:1px solid #E5E7EB;">${vulnerability.hasPublicExploit ? 'Sí' : 'No'}</td>
</tr>`)
            .join('');

    const vulnerabilitiesHtml = smartConfig.includeTechnicalTable ? `
<table style="width:100%;border-collapse:collapse;font-size:12px;">
  <thead>
    <tr style="background:#F3F4F6;">
      <th style="padding:8px;text-align:left;">CVE</th>
      <th style="padding:8px;text-align:left;">CVSS</th>
      <th style="padding:8px;text-align:left;">Vector</th>
      <th style="padding:8px;text-align:left;">KEV</th>
      <th style="padding:8px;text-align:left;">PoC</th>
    </tr>
  </thead>
  <tbody>
    ${vulnerabilityRows}
  </tbody>
</table>` : '<p>Tabla técnica desactivada por configuración.</p>';

                const introText = this.escapeHtml(
                        String(smartConfig.introText || '')
                                .replaceAll('{{lookbackDays}}', String(smartConfig.lookbackDays))
                                .replaceAll('{{subscriberName}}', dataset.subscriber.name),
                );

                const sectionTitleStyle = 'margin: 0 0 10px; font-size: 14px; color: #1B2A4A; text-transform: uppercase; letter-spacing: .5px;';
                const executiveSectionHtml = smartConfig.showExecutiveSection
                        ? `<h2 style="${sectionTitleStyle}">${this.escapeHtml(smartConfig.sectionExecutiveTitle)}</h2>
<div style="background: #F8FAFC; border: 1px solid #E5E7EB; border-radius: 8px; padding: 12px 14px; margin-bottom: 20px;">
    <p style="margin: 0; color: #111827; font-size: 14px; line-height: 1.5;">${this.escapeHtml(analysis.executiveSummary)}</p>
</div>`
                        : '';

                const statsSectionHtml = smartConfig.showStatsSection
                        ? `<div style="display: flex; gap: 10px; margin-bottom: 22px;">
    <div style="flex: 1; background: #EFF6FF; border: 1px solid #BFDBFE; border-radius: 8px; padding: 12px; text-align: center;">
        <div style="font-size: 10px; color: #2563EB; font-weight: 700; text-transform: uppercase;">Total CVE</div>
        <div style="font-size: 28px; font-weight: 800; color: #1E3A8A; font-family: monospace;">${dataset.stats.total}</div>
    </div>
</div>`
                        : '';

                const topRiskSectionHtml = smartConfig.showTopRiskSection
                        ? `<h2 style="${sectionTitleStyle}">${this.escapeHtml(smartConfig.sectionTopRiskTitle)}</h2>
${top3Html}`
                        : '';

                const correlationsSectionHtml = smartConfig.showCorrelationsSection
                        ? `<h2 style="margin: 20px 0 10px; font-size: 14px; color: #1B2A4A; text-transform: uppercase; letter-spacing: .5px;">${this.escapeHtml(smartConfig.sectionCorrelationsTitle)}</h2>
${correlationsHtml}`
                        : '';

                const roadmapSectionHtml = smartConfig.showRoadmapSection
                        ? `<h2 style="margin: 20px 0 10px; font-size: 14px; color: #1B2A4A; text-transform: uppercase; letter-spacing: .5px;">${this.escapeHtml(smartConfig.sectionRoadmapTitle)}</h2>
${roadmapHtml}`
                        : '';

                const technicalSectionHtml = smartConfig.showTechnicalSection
                        ? `<h2 style="margin: 20px 0 10px; font-size: 14px; color: #1B2A4A; text-transform: uppercase; letter-spacing: .5px;">${this.escapeHtml(smartConfig.sectionTechnicalTitle)}</h2>
<div style="border: 1px solid #E5E7EB; border-radius: 8px; overflow: hidden;">${vulnerabilitiesHtml}</div>`
                        : '';

        return {
            subscriberName: dataset.subscriber.name,
            periodStart: dataset.periodStart.toISOString().slice(0, 10),
            periodEnd: dataset.periodEnd.toISOString().slice(0, 10),
            generatedAt: new Date().toISOString(),
            totalVulnerabilities: dataset.stats.total,
                        emailTitle: this.escapeHtml(smartConfig.emailTitle),
                        introText,
                        footerText: this.escapeHtml(smartConfig.footerText),
                        executiveSectionHtml,
                        statsSectionHtml,
                        topRiskSectionHtml,
                        correlationsSectionHtml,
                        roadmapSectionHtml,
                        technicalSectionHtml,
        };
    }

    private extractAiContent(aiResponse: any): string {
        if (!aiResponse) return '';
        if (typeof aiResponse === 'string') return aiResponse;
        if (typeof aiResponse.content === 'string') return aiResponse.content;
        if (Array.isArray(aiResponse.content)) {
            return aiResponse.content
                .map((chunk: any) => (typeof chunk === 'string' ? chunk : chunk?.text || ''))
                .join('\n');
        }
        return '';
    }

    private resolveAttackVector(cvssVector: string | null): 'Network' | 'Adjacent' | 'Local' | 'Physical' | 'Unknown' {
        if (!cvssVector) return 'Unknown';
        const vector = String(cvssVector).toUpperCase();
        if (vector.includes('AV:N')) return 'Network';
        if (vector.includes('AV:A')) return 'Adjacent';
        if (vector.includes('AV:L')) return 'Local';
        if (vector.includes('AV:P')) return 'Physical';
        return 'Unknown';
    }

    private parseAffectedProducts(raw: string | null | undefined): Array<{ vendor: string; product: string; version?: string; versionRange?: string }> {
        if (!raw) return [];

        try {
            const parsed = JSON.parse(raw);
            if (!Array.isArray(parsed)) return [];

            return parsed
                .map((item: any) => ({
                    vendor: String(item?.vendor || '').trim(),
                    product: String(item?.product || '').trim(),
                    version: item?.version ? String(item.version).trim() : undefined,
                    versionRange: item?.versionRange ? String(item.versionRange).trim() : undefined,
                }))
                .filter((item: { vendor: string; product: string }) => !!item.vendor || !!item.product);
        } catch {
            return [];
        }
    }

    private parseJsonArray(raw: string | null | undefined): string[] {
        if (!raw) return [];
        try {
            const parsed = JSON.parse(raw);
            if (!Array.isArray(parsed)) return [];
            return parsed.map((item) => String(item)).filter(Boolean);
        } catch {
            return [];
        }
    }

    // getMatchedProducts and matchesSubscription imported from shared/vendor-normalization

    private async ensureSubscriberExists(subscriberId: number) {
        const exists = await this.prisma.user.findFirst({
            where: {
                id: subscriberId,
                isSubscriber: true,
                isActive: true,
            },
            select: { id: true },
        });

        if (!exists) {
            throw new Error('Subscriber not found or inactive');
        }
    }

    private normalizeOwnedSystemInput(input: OwnedSystemInput) {
        const source = input?.source === 'defender' ? 'defender' : 'manual';
        const externalId = String(input?.externalId || '').trim();
        const hostname = String(input?.hostname || '').trim();
        const tags = Array.isArray(input?.tags)
            ? input.tags.map((tag) => String(tag || '').trim()).filter(Boolean)
            : [];

        let parsedLastSeenAt: Date | null = null;
        if (input?.lastSeenAt) {
            const maybeDate = new Date(input.lastSeenAt as any);
            parsedLastSeenAt = Number.isNaN(maybeDate.getTime()) ? null : maybeDate;
        }

        return {
            source,
            externalId,
            hostname,
            fqdn: input?.fqdn ? String(input.fqdn).trim() : null,
            platform: input?.platform ? String(input.platform).trim() : null,
            osVersion: input?.osVersion ? String(input.osVersion).trim() : null,
            riskLevel: input?.riskLevel ? String(input.riskLevel).trim() : null,
            healthStatus: input?.healthStatus ? String(input.healthStatus).trim() : null,
            onboardingStatus: input?.onboardingStatus ? String(input.onboardingStatus).trim() : null,
            lastSeenAt: parsedLastSeenAt,
            isSelected: input?.isSelected !== false,
            tags,
            rawData: input?.rawData || null,
        };
    }

    private safeJsonArray(raw: string | null | undefined): string[] {
        if (!raw) return [];
        try {
            const parsed = JSON.parse(raw);
            if (!Array.isArray(parsed)) return [];
            return parsed.map((item) => String(item)).filter(Boolean);
        } catch {
            return [];
        }
    }

    private safeJsonObject(raw: string | null | undefined): Record<string, any> {
        if (!raw) return {};
        try {
            const parsed = JSON.parse(raw);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
            return parsed;
        } catch {
            return {};
        }
    }

    private escapeHtml(value: string): string {
        return String(value)
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#039;');
    }
}
