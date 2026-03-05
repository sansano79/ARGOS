import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { PrismaService } from '../../prisma/prisma.service';
import { AiService } from '../ai/ai.service';
import { NotificationService } from '../notification/notification.service';
import { dump as yamlDump, load as yamlLoad } from 'js-yaml';

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
        subjectPrefix: '[OCC] Informe inteligente semanal',
        emailTitle: '🧠 Informe Inteligente Semanal',
        introText: 'Este informe resume el análisis inteligente de las vulnerabilidades detectadas en tus activos durante los últimos {{lookbackDays}} días.',
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

        const items = await this.prisma.subscriberOwnedSystem.findMany({
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
            await this.prisma.subscriberOwnedSystem.upsert({
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
                await this.prisma.subscriberOwnedSystem.updateMany({
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

        const existingSystems = await this.prisma.subscriberOwnedSystem.findMany({
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

        const request = await this.prisma.defenderActionRequest.create({
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

    @Cron('0 0 8 * * 1')
    async runScheduledWeeklyReports() {
        this.logger.log('Starting scheduled smart weekly notifications');
        await this.runWeeklyForAllSubscribers('cron');
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
        const subscribers = await this.prisma.user.findMany({
            where: {
                isActive: true,
                isSubscriber: true,
            },
            select: {
                id: true,
            },
            orderBy: { id: 'asc' },
        });

        const results: WeeklyRunResult[] = [];
        for (const subscriber of subscribers) {
            const result = await this.runWeeklyForSubscriber(subscriber.id, { trigger });
            results.push(result);
        }

        return {
            trigger,
            processed: results.length,
            sent: results.filter((r) => r.status === 'sent').length,
            skipped: results.filter((r) => r.status === 'skipped').length,
            failed: results.filter((r) => r.status === 'failed').length,
            results,
        };
    }

    async runWeeklyForSubscriber(subscriberId: number, options?: { trigger?: 'manual' | 'cron' }) {
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
            } as WeeklyRunResult;
        }

        const effectiveAi = await this.getEffectiveAiSettings(smartConfig);
        const { promptSystem, promptUser } = this.buildCorrelationPrompt(dataset, smartConfig);

        const report = await this.prisma.smartNotificationReport.create({
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

            await this.prisma.smartNotificationReport.update({
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
            } as WeeklyRunResult;
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Unknown error';
            this.logger.error(`Smart weekly report failed for subscriber=${subscriberId}: ${message}`);

            await this.prisma.smartNotificationReport.update({
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
            } as WeeklyRunResult;
        }
    }

    async previewWeeklyForSubscriber(subscriberId: number) {
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
        } catch {
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
    }

    async testWeeklyForSubscriber(subscriberId: number) {
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
        } catch {
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
    }

    async getWeeklyHistory(page = 1, limit = 20, subscriberId?: number) {
        const safePage = Number.isFinite(page) && page > 0 ? Math.floor(page) : 1;
        const safeLimit = Number.isFinite(limit) && limit > 0 ? Math.min(Math.floor(limit), 100) : 20;
        const skip = (safePage - 1) * safeLimit;

        const where = subscriberId
            ? { subscriberUserId: subscriberId }
            : undefined;

        const [items, total] = await Promise.all([
            this.prisma.smartNotificationReport.findMany({
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
            this.prisma.smartNotificationReport.count({ where }),
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
                subscriptions: {
                    where: { isActive: true },
                    select: { vendor: true, product: true, versions: true },
                },
            },
        });

        if (!subscriber) return null;

        const ownedSystems = await this.prisma.subscriberOwnedSystem.findMany({
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

        const normalizedSubscriptions = (subscriber.subscriptions || []).map((subscription) => ({
            vendor: String(subscription.vendor || '').trim().toLowerCase(),
            product: String(subscription.product || '').trim().toLowerCase(),
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
            const matchedProducts = this.getMatchedProducts(
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

        const vulnerabilities = [...vulnerabilityMap.values()]
            .sort((a, b) => b.realRiskScore - a.realRiskScore)
            .slice(0, smartConfig.maxCandidateVulnerabilities);

        const groupedAssetsMap = new Map<string, { vendor: string; product: string; cveIds: Set<string> }>();
        for (const vulnerability of vulnerabilities) {
            const matchedProducts = this.getMatchedProducts(normalizedSubscriptions, vulnerability.affectedProducts);
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
                `Actúa como ${smartConfig.promptPersona} especializado en exploit chaining.`,
                'Responde EXCLUSIVAMENTE con JSON válido.',
                'No incluyas markdown, no incluyas texto fuera del JSON.',
                'Evalúa criticidad real por combinación de impacto (CVSS) y explotabilidad (KEV/PoC/EPSS).',
                'Si faltan datos, indícalo con supuestos breves sin inventar hechos.',
                `Idioma de respuesta: ${smartConfig.promptLanguage === 'en' ? 'English' : 'Español'}.`,
                smartConfig.promptExtraInstructions ? `Instrucciones extra: ${smartConfig.promptExtraInstructions}` : '',
                'Esquema JSON de salida obligatorio:',
                '{',
                '  "executiveSummary": "string",',
                '  "top3RealRisk": [',
                '    {"cveId":"string","reason":"string","priority":"immediate|high|medium","evidence":["string"]}',
                '  ],',
                '  "detectedCorrelations": [',
                '    {"title":"string","description":"string","involvedCves":["string"],"attackPath":"string","riskLevel":"critical|high|medium"}',
                '  ],',
                '  "mitigationRoadmap": [',
                '    {"order":1,"action":"string","why":"string","cves":["string"]}',
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
        if (!aiContent || !aiContent.trim()) return fallback;

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
            } catch {
                // keep trying with extracted object / fallback
            }
        }

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

        const correlationsHtml = analysis.detectedCorrelations.length
            ? analysis.detectedCorrelations
                .map((correlation) => `
<div style="border-left:4px solid #F59E0B;background:#FFFBEB;padding:10px 12px;margin-bottom:10px;">
  <strong>${this.escapeHtml(correlation.title || 'Correlación')}</strong>
  <p style="margin:6px 0;color:#374151;">${this.escapeHtml(correlation.description || '')}</p>
  <p style="margin:0;font-size:12px;color:#6B7280;">CVEs: ${this.escapeHtml((correlation.involvedCves || []).join(', ') || 'N/D')}</p>
</div>`)
                .join('')
            : '<p>No se detectaron correlaciones fuertes en esta ventana.</p>';

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

    private getMatchedProducts(
        subscriptions: Array<{ vendor: string; product: string; versions: string[] }>,
        affectedProducts: Array<{ vendor: string; product: string; version?: string; versionRange?: string }>,
    ) {
        const matches: Array<{ vendor: string; product: string; version?: string; versionRange?: string }> = [];

        for (const affectedProduct of affectedProducts) {
            if (
                subscriptions.some((subscription) => this.matchesSubscription(subscription, affectedProduct))
            ) {
                matches.push(affectedProduct);
            }
        }

        return matches;
    }

    private matchesSubscription(
        subscription: { vendor: string; product: string; versions: string[] },
        affectedProduct: { vendor: string; product: string; version?: string; versionRange?: string },
    ): boolean {
        const subscriptionVendor = String(subscription.vendor || '').trim().toLowerCase();
        const subscriptionProduct = String(subscription.product || '').trim().toLowerCase();
        const affectedVendor = String(affectedProduct.vendor || '').trim().toLowerCase();
        const affectedProductName = String(affectedProduct.product || '').trim().toLowerCase();

        if (subscriptionVendor && subscriptionVendor !== affectedVendor) return false;
        if (subscriptionProduct && subscriptionProduct !== affectedProductName) return false;
        if (!affectedVendor && !affectedProductName) return false;

        if (!subscription.versions || subscription.versions.length === 0) return true;

        const affectedVersion = String(affectedProduct.version || '').trim().toLowerCase();
        const affectedRange = String(affectedProduct.versionRange || '').trim().toLowerCase();
        if (!affectedVersion && !affectedRange) return true;

        return subscription.versions.some((version) => {
            const normalizedVersion = String(version || '').trim().toLowerCase();
            return normalizedVersion && (affectedVersion === normalizedVersion || affectedRange.includes(normalizedVersion));
        });
    }

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
