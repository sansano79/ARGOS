import { Injectable, Logger, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import * as nodemailer from 'nodemailer';
import * as fs from 'fs';
import * as path from 'path';

interface SmtpConfig {
    host: string;
    port: number;
    user: string;
    pass: string;
    secure: boolean;
    from: string;
}

interface NotificationTemplateConfig {
    headerImageUrl: string;
    name?: string;
    introMessage: string;
    showExploitProbability: boolean;
    showExploitExists: boolean;
    showAffectedSoftware: boolean;
    showDescription: boolean;
    showReferences: boolean;
    showPatchLink: boolean;
}

type NotificationCenterConfig = {
    general: {
        processEnabled: boolean;
        defaultChannel: 'email';
        dedupeWindowHours: number;
        retryBackoffMinutes: number[];
        activeTemplateKey: 'legacy' | 'normal_v2' | 'intelligent';
    };
    immediate: {
        enabled: boolean;
        minSeverity: string;
        minCvss: number;
        minEpss: number;
        minEpssPercentile: number;
        kevOnly: boolean;
        publicExploitOnly: boolean;
        activeExploitationOnly: boolean;
        patchUnconfirmedOnly: boolean;
        newVulnerabilityOnly: boolean;
        onSeverityChange: boolean;
        onExploitChange: boolean;
        onPatchChange: boolean;
        onlySubscribedSystems: boolean;
        minConfidence: number;
        minSources: number;
        vendorFilters: string[];
        productFilters: string[];
        categoryFilters: string[];
        exclusions: string[];
    };
    digest: {
        enabled: boolean;
        intervalHours: number;
        minSeverity: string;
        minCvss: number;
        minEpss: number;
        onlySubscribedSystems: boolean;
        minConfidence: number;
        minSources: number;
        vendorFilters: string[];
        productFilters: string[];
        categoryFilters: string[];
        exclusions: string[];
        groupingMode: string;
    };
    intelligent: {
        enabled: boolean;
        evaluationHour: number;
        analysisFrequencyHours: number;
        primaryWindowHours: number;
        recentContextDays: number;
        historicalContextDays: number;
        onlyWhenFinding: boolean;
        minConfidence: number;
        minRelevanceScore: number;
        cooldownHours: number;
        maxNotificationsPerSubscriberPerDay: number;
        scenarioFlags: {
            attackPath: boolean;
            campaignCluster: boolean;
            compoundRisk: boolean;
            postureChange: boolean;
        };
    };
    templates: {
        available: Array<{
            key: 'legacy' | 'normal_v2' | 'intelligent';
            name: string;
            description: string;
            category: 'legacy' | 'standard' | 'intelligent';
        }>;
    };
};

type NotificationProcessHealth = {
    enabled: boolean;
    smtpConfigured: boolean;
    queuePending: number;
    retries: number;
    lastSent: any;
    lastFailed: any;
    jobs: Record<string, any>;
    recentLogs: any[];
};

@Injectable()
export class NotificationService {
    private readonly logger = new Logger(NotificationService.name);
    private static readonly CENTER_SETTINGS_SLUG = 'notification-center-settings';
    private transporter: nodemailer.Transporter | null = null;
    private smtpConfig: SmtpConfig | null = null;

    constructor(
        private prisma: PrismaService,
        private configService: ConfigService,
    ) { }

    async onModuleInit() {
        await this.loadConfig();
    }

    async loadConfig() {
        try {
            const config = await this.prisma.apiConfiguration.findFirst({
                where: { provider: 'smtp', isActive: true },
            });

            if (config && config.settings) {
                const settings = JSON.parse(config.settings || '{}');
                this.smtpConfig = {
                    host: settings.host,
                    port: parseInt(settings.port, 10),
                    user: settings.user,
                    pass: config.apiKeyEncrypted || '',
                    secure: settings.secure === true || settings.secure === 'true',
                    from: settings.from,
                };
                this.createTransporter();
            }
        } catch (error) {
            this.logger.warn('Failed to load SMTP configuration: ' + error.message);
        }
    }

    private getDefaultNotificationCenterConfig(): NotificationCenterConfig {
        return {
            general: {
                processEnabled: true,
                defaultChannel: 'email',
                dedupeWindowHours: 24,
                retryBackoffMinutes: [5, 15, 30],
                activeTemplateKey: 'normal_v2',
            },
            immediate: {
                enabled: true,
                minSeverity: 'HIGH',
                minCvss: 8.5,
                minEpss: 0.2,
                minEpssPercentile: 0.8,
                kevOnly: false,
                publicExploitOnly: false,
                activeExploitationOnly: false,
                patchUnconfirmedOnly: false,
                newVulnerabilityOnly: true,
                onSeverityChange: true,
                onExploitChange: true,
                onPatchChange: true,
                onlySubscribedSystems: true,
                minConfidence: 0.6,
                minSources: 1,
                vendorFilters: [],
                productFilters: [],
                categoryFilters: [],
                exclusions: [],
            },
            digest: {
                enabled: true,
                intervalHours: 12,
                minSeverity: 'MEDIUM',
                minCvss: 7,
                minEpss: 0,
                onlySubscribedSystems: true,
                minConfidence: 0.5,
                minSources: 1,
                vendorFilters: [],
                productFilters: [],
                categoryFilters: [],
                exclusions: [],
                groupingMode: 'priority',
            },
            intelligent: {
                enabled: true,
                evaluationHour: 8,
                analysisFrequencyHours: 24,
                primaryWindowHours: 24,
                recentContextDays: 7,
                historicalContextDays: 60,
                onlyWhenFinding: true,
                minConfidence: 0.65,
                minRelevanceScore: 0.6,
                cooldownHours: 24,
                maxNotificationsPerSubscriberPerDay: 2,
                scenarioFlags: {
                    attackPath: true,
                    campaignCluster: true,
                    compoundRisk: true,
                    postureChange: true,
                },
            },
            templates: {
                available: [
                    {
                        key: 'legacy',
                        name: 'Plantilla actual',
                        description: 'Compatibilidad con la plantilla histórica de CVE.',
                        category: 'legacy',
                    },
                    {
                        key: 'normal_v2',
                        name: 'Plantilla normal v2',
                        description: 'Resumen ejecutivo elegante para alertas inmediatas y digest.',
                        category: 'standard',
                    },
                    {
                        key: 'intelligent',
                        name: 'Plantilla inteligente',
                        description: 'Marco premium para hallazgos de inteligencia y correlaciones.',
                        category: 'intelligent',
                    },
                ],
            },
        };
    }

    private normalizeStringArray(value: any): string[] {
        if (Array.isArray(value)) {
            return value.map((item) => String(item || '').trim()).filter(Boolean);
        }
        if (typeof value === 'string') {
            const trimmed = value.trim();
            if (!trimmed) return [];
            try {
                const parsed = JSON.parse(trimmed);
                return this.normalizeStringArray(parsed);
            } catch {
                return trimmed
                    .split(',')
                    .map((item) => item.trim())
                    .filter(Boolean);
            }
        }
        return [];
    }

    private mergeNotificationCenterConfig(input: any): NotificationCenterConfig {
        const defaults = this.getDefaultNotificationCenterConfig();
        const source = input && typeof input === 'object' ? input : {};
        return {
            general: {
                ...defaults.general,
                ...(source.general || {}),
                retryBackoffMinutes: this.normalizeNumericArray(source?.general?.retryBackoffMinutes, defaults.general.retryBackoffMinutes),
            },
            immediate: {
                ...defaults.immediate,
                ...(source.immediate || {}),
                vendorFilters: this.normalizeStringArray(source?.immediate?.vendorFilters ?? defaults.immediate.vendorFilters),
                productFilters: this.normalizeStringArray(source?.immediate?.productFilters ?? defaults.immediate.productFilters),
                categoryFilters: this.normalizeStringArray(source?.immediate?.categoryFilters ?? defaults.immediate.categoryFilters),
                exclusions: this.normalizeStringArray(source?.immediate?.exclusions ?? defaults.immediate.exclusions),
            },
            digest: {
                ...defaults.digest,
                ...(source.digest || {}),
                vendorFilters: this.normalizeStringArray(source?.digest?.vendorFilters ?? defaults.digest.vendorFilters),
                productFilters: this.normalizeStringArray(source?.digest?.productFilters ?? defaults.digest.productFilters),
                categoryFilters: this.normalizeStringArray(source?.digest?.categoryFilters ?? defaults.digest.categoryFilters),
                exclusions: this.normalizeStringArray(source?.digest?.exclusions ?? defaults.digest.exclusions),
            },
            intelligent: {
                ...defaults.intelligent,
                ...(source.intelligent || {}),
                analysisFrequencyHours: Math.max(1, Number(source?.intelligent?.analysisFrequencyHours ?? defaults.intelligent.analysisFrequencyHours)),
                primaryWindowHours: Math.max(1, Number(source?.intelligent?.primaryWindowHours ?? source?.intelligent?.recentWindowHours ?? defaults.intelligent.primaryWindowHours)),
                recentContextDays: Math.max(1, Number(source?.intelligent?.recentContextDays ?? source?.intelligent?.contextWindowDays ?? defaults.intelligent.recentContextDays)),
                historicalContextDays: Math.max(
                    Math.max(7, Number(source?.intelligent?.recentContextDays ?? source?.intelligent?.contextWindowDays ?? defaults.intelligent.recentContextDays)),
                    Number(source?.intelligent?.historicalContextDays ?? defaults.intelligent.historicalContextDays),
                ),
                minConfidence: Math.max(0, Math.min(1, Number(source?.intelligent?.minConfidence ?? defaults.intelligent.minConfidence))),
                minRelevanceScore: Math.max(0, Math.min(1, Number(source?.intelligent?.minRelevanceScore ?? defaults.intelligent.minRelevanceScore))),
                cooldownHours: Math.max(1, Number(source?.intelligent?.cooldownHours ?? defaults.intelligent.cooldownHours)),
                maxNotificationsPerSubscriberPerDay: Math.max(1, Number(source?.intelligent?.maxNotificationsPerSubscriberPerDay ?? defaults.intelligent.maxNotificationsPerSubscriberPerDay)),
                scenarioFlags: {
                    ...defaults.intelligent.scenarioFlags,
                    ...((source.intelligent || {}).scenarioFlags || {}),
                },
            },
            templates: defaults.templates,
        };
    }

    private normalizeNumericArray(value: any, fallback: number[]): number[] {
        const items = Array.isArray(value) ? value : fallback;
        return items
            .map((item) => Number(item))
            .filter((item) => Number.isFinite(item) && item > 0)
            .map((item) => Math.round(item));
    }

    async getNotificationCenterSettings() {
        const [row, templateConfigs, recipientStats, processHealth] = await Promise.all([
            this.prisma.apiConfiguration.findFirst({
                where: { slug: NotificationService.CENTER_SETTINGS_SLUG, provider: 'notification-center' },
            }),
            this.listTemplateConfigs(),
            this.getNotificationRecipientSummary(),
            this.getNotificationProcessHealth(),
        ]);

        const rawSettings = this.parseJson(row?.settings || '{}');
        const config = this.mergeNotificationCenterConfig(rawSettings);

        return {
            ...config,
            general: {
                ...config.general,
                smtpConfigured: !!this.smtpConfig,
            },
            templates: {
                ...config.templates,
                activeLegacyTemplateId: templateConfigs.find((row) => row.isActive)?.id || null,
                legacyTemplateConfigs: templateConfigs,
            },
            recipients: recipientStats,
            processHealth,
        };
    }

    async saveNotificationCenterSettings(data: any) {
        const merged = this.mergeNotificationCenterConfig(data);
        const existing = await this.prisma.apiConfiguration.findFirst({
            where: { slug: NotificationService.CENTER_SETTINGS_SLUG, provider: 'notification-center' },
        });

        const payload = {
            name: 'Notification Center Settings',
            slug: NotificationService.CENTER_SETTINGS_SLUG,
            provider: 'notification-center',
            settings: JSON.stringify(merged),
            isActive: true,
        };

        if (existing) {
            await this.prisma.apiConfiguration.update({
                where: { id: existing.id },
                data: payload,
            });
        } else {
            await this.prisma.apiConfiguration.create({ data: payload });
        }

        // Recalculate isNotificable asynchronously after config change
        this.recalculateAllNotificable().catch((err) =>
            this.logger.error(`Failed to recalculate isNotificable: ${err.message}`),
        );

        return this.getNotificationCenterSettings();
    }

    private async getNotificationRecipientSummary() {
        const users = await this.prisma.user.findMany({
            where: { isActive: true },
            select: {
                id: true,
                role: true,
                isSubscriber: true,
                canReceiveNotifications: true,
                notificationsPaused: true,
            },
        });

        const normalized = Array.isArray(users) ? users : [];
        return {
            totalUsers: normalized.length,
            enabledRecipients: normalized.filter((user) => user.canReceiveNotifications).length,
            pausedRecipients: normalized.filter((user) => user.notificationsPaused).length,
            admins: normalized.filter((user) => String(user.role || '').toUpperCase() === 'ADMIN').length,
            viewers: normalized.filter((user) => String(user.role || '').toUpperCase() === 'VIEWER').length,
            subscribers: normalized.filter((user) => user.isSubscriber).length,
        };
    }

    private createTransporter() {
        if (!this.smtpConfig) return;

        this.transporter = nodemailer.createTransport({
            host: this.smtpConfig.host,
            port: this.smtpConfig.port,
            secure: this.smtpConfig.secure,
            auth: {
                user: this.smtpConfig.user,
                pass: this.smtpConfig.pass,
            },
            tls: {
                rejectUnauthorized: false
            }
        });
    }

    async saveConfig(config: SmtpConfig) {
        const existingConfig = await this.prisma.apiConfiguration.findFirst({
            where: { provider: 'smtp' },
        });

        const parsedPort = Number(config.port);
        if (!config.host || !parsedPort || !config.user || !config.from) {
            throw new InternalServerErrorException('Invalid SMTP configuration');
        }

        const settings = JSON.stringify({
            host: config.host,
            port: parsedPort,
            user: config.user,
            secure: config.secure,
            from: config.from,
        });

        const passwordToStore = (config.pass && String(config.pass).trim().length > 0)
            ? config.pass
            : (existingConfig?.apiKeyEncrypted || '');

        if (existingConfig) {
            await this.prisma.apiConfiguration.update({
                where: { id: existingConfig.id },
                data: {
                    settings,
                    apiKeyEncrypted: passwordToStore,
                    isActive: true,
                    name: 'SMTP Configuration',
                },
            });
        } else {
            if (!passwordToStore) {
                throw new InternalServerErrorException('SMTP password is required');
            }
            await this.prisma.apiConfiguration.create({
                data: {
                    name: 'SMTP Configuration',
                    slug: 'smtp-config',
                    provider: 'smtp',
                    settings,
                    apiKeyEncrypted: passwordToStore,
                    isActive: true,
                },
            });
        }

        await this.loadConfig();
        return { success: true };
    }

    async getConfig() {
        const config = await this.prisma.apiConfiguration.findFirst({
            where: { provider: 'smtp' },
        });

        if (!config) return null;

        const settings = JSON.parse(config.settings || '{}');
        return {
            host: settings.host,
            port: settings.port,
            user: settings.user,
            secure: settings.secure,
            from: settings.from,
        };
    }

    async getTemplateConfig(): Promise<NotificationTemplateConfig> {
        let config = await this.prisma.apiConfiguration.findFirst({
            where: { provider: 'notification-template', isActive: true },
            orderBy: { updatedAt: 'desc' },
        });

        if (!config) {
            config = await this.prisma.apiConfiguration.findFirst({
                where: { provider: 'notification-template' },
                orderBy: { updatedAt: 'desc' },
            });
        }

        if (!config?.settings) {
            return this.getDefaultTemplateConfig();
        }

        try {
            const settings = JSON.parse(config.settings);
            return {
                ...this.getDefaultTemplateConfig(),
                ...settings,
            };
        } catch {
            return this.getDefaultTemplateConfig();
        }
    }

    async saveTemplateConfig(config: Partial<NotificationTemplateConfig> & { templateId?: number; name?: string }) {
        const mergedConfig: NotificationTemplateConfig = {
            ...this.getDefaultTemplateConfig(),
            ...config,
        };

        const settings = JSON.stringify(mergedConfig);
        const templateId = Number(config.templateId || 0);
        const name = (config.name || '').trim() || 'Plantilla CVE';

        if (templateId > 0) {
            await this.prisma.apiConfiguration.update({
                where: { id: templateId },
                data: {
                    name,
                    isActive: true,
                    settings,
                },
            });
        } else {
            await this.prisma.apiConfiguration.updateMany({
                where: { provider: 'notification-template', isActive: true },
                data: { isActive: false },
            });

            const slug = `notification-template-${Date.now()}`;
            await this.prisma.apiConfiguration.create({
                data: {
                    name,
                    slug,
                    provider: 'notification-template',
                    settings,
                    isActive: true,
                },
            });
        }

        return { success: true };
    }

    async listTemplateConfigs() {
        const rows = await this.prisma.apiConfiguration.findMany({
            where: { provider: 'notification-template' },
            select: { id: true, name: true, slug: true, isActive: true, updatedAt: true },
            orderBy: [{ isActive: 'desc' }, { updatedAt: 'desc' }],
        });
        return rows;
    }

    async getTemplateConfigById(id: number): Promise<NotificationTemplateConfig> {
        const row = await this.prisma.apiConfiguration.findUnique({ where: { id } });
        if (!row || row.provider !== 'notification-template') {
            throw new NotFoundException('Template not found');
        }
        try {
            const parsed = JSON.parse(row.settings || '{}');
            return { ...this.getDefaultTemplateConfig(), ...parsed, name: row.name || 'Plantilla CVE' };
        } catch {
            return { ...this.getDefaultTemplateConfig(), name: row.name || 'Plantilla CVE' };
        }
    }

    async activateTemplateConfig(id: number) {
        const row = await this.prisma.apiConfiguration.findUnique({ where: { id } });
        if (!row || row.provider !== 'notification-template') {
            throw new NotFoundException('Template not found');
        }
        await this.prisma.apiConfiguration.updateMany({
            where: { provider: 'notification-template', isActive: true },
            data: { isActive: false },
        });
        await this.prisma.apiConfiguration.update({
            where: { id },
            data: { isActive: true },
        });
        return { success: true };
    }

    async getTemplatePreview(
        vulnerabilityId: number,
        overrideConfig?: Partial<NotificationTemplateConfig>,
    ): Promise<{ html: string; cveId: string; manufacturer: string }> {
        const vuln = await this.prisma.vulnerability.findUnique({
            where: { id: vulnerabilityId },
            select: {
                cveId: true,
                cvssV31Severity: true,
                cvssV31Score: true,
                publishedAt: true,
                epssScore: true,
                hasPublicExploit: true,
                affectedProducts: true,
                description: true,
                references: true,
                remediationInfo: true,
            },
        });

        if (!vuln) {
            throw new NotFoundException('Vulnerability not found');
        }

        const normalizedVuln = this.normalizeVulnerabilityData(vuln);
        const cfg = { ...(await this.getTemplateConfig()), ...(overrideConfig || {}) };
        const manufacturer = this.resolveManufacturer(normalizedVuln);
        const html = this.renderConfiguredCveTemplate(
            {
                cveId: normalizedVuln.cveId,
                vulnerability: normalizedVuln,
            },
            cfg,
        );

        const previewHtml = cfg.headerImageUrl?.startsWith('data:image/')
            ? html.replace('cid:occ-header-banner', cfg.headerImageUrl)
            : html;

        return { html: previewHtml, cveId: normalizedVuln.cveId, manufacturer };
    }

    async sendTestEmail(to: string) {
        if (!this.transporter) {
            await this.loadConfig();
            if (!this.transporter) {
                throw new NotFoundException('SMTP Configuration not found or invalid');
            }
        }

        try {
            const html = '<div style="font-family: Inter, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">' +
                '<div style="background: linear-gradient(135deg, #1B2A4A 0%, #3B6CB5 100%); color: #fff; padding: 24px; border-radius: 8px 8px 0 0;">' +
                '<h1 style="margin: 0; font-size: 20px;">🛡️ OCC-TVM</h1>' +
                '<p style="margin: 4px 0 0; opacity: 0.8; font-size: 12px;">Oficina de Ciberseguridad Corporativa</p>' +
                '</div>' +
                '<div style="background: #fff; padding: 24px; border: 1px solid #E5E7EB; border-top: none; border-radius: 0 0 8px 8px;">' +
                '<h2 style="color: #1B2A4A; font-size: 16px;">✅ Email de prueba</h2>' +
                '<p style="color: #4A5568; font-size: 14px; line-height: 1.6;">Este es un email de prueba para verificar que la configuración SMTP funciona correctamente.</p>' +
                '<div style="background: #F0FDF4; border-left: 4px solid #16A34A; padding: 12px 16px; border-radius: 4px; margin-top: 16px;">' +
                '<strong style="color: #16A34A;">Configuración verificada</strong>' +
                '<p style="color: #4A5568; font-size: 12px; margin: 4px 0 0;">Las notificaciones por correo están listas para enviarse.</p>' +
                '</div>' +
                '</div>' +
                '</div>';

            const info = await this.transporter.sendMail({
                from: this.smtpConfig?.from || 'noreply@occ.local',
                to,
                subject: '✅ Test Email — OCC-TVM',
                html,
            });

            // Log the test email
            await this.logNotification(to, 'Test', '✅ Test Email — OCC-TVM', html);

            this.logger.log(`Test email sent: ${info.messageId}`);
            return { success: true, messageId: info.messageId };
        } catch (error) {
            this.logger.error('Failed to send test email', error);
            throw new InternalServerErrorException('Failed to send email: ' + error.message);
        }
    }

    async sendEmail(
        to: string,
        subject: string,
        templateName: string,
        context: any,
        options: {
            notificationType?: string;
            templateKey?: string;
            channel?: string;
            triggerReason?: string;
            metadata?: Record<string, any>;
            recipientUserId?: number;
            cveIds?: string[];
        } = {},
    ) {
        if (!this.transporter) {
            await this.loadConfig();
            if (!this.transporter) {
                this.logger.warn('Email sending skipped: SMTP not configured');
                return false;
            }
        }

        try {
            const html = await this.loadTemplate(templateName, context);
            const attachments = await this.getInlineTemplateAttachments(templateName);
            const info = await this.transporter.sendMail({
                from: this.smtpConfig?.from || 'noreply@occ.local',
                to,
                subject,
                html,
                attachments,
            });

            // Log notification
            await this.logNotification(
                to,
                context.recipientName || to,
                subject,
                html,
                options.cveIds || context.cveIds || [],
                {
                    notificationType: options.notificationType,
                    templateKey: options.templateKey || templateName,
                    channel: options.channel || 'email',
                    triggerReason: options.triggerReason,
                    metadata: options.metadata,
                    recipientUserId: options.recipientUserId,
                },
            );

            this.logger.log(`Email sent to ${to}: ${info.messageId}`);
            return true;
        } catch (error) {
            this.logger.error(`Failed to send email to ${to}`, error);
            await this.logNotification(
                to,
                context.recipientName || to,
                subject,
                '',
                options.cveIds || context.cveIds || [],
                {
                    notificationType: options.notificationType,
                    templateKey: options.templateKey || templateName,
                    channel: options.channel || 'email',
                    triggerReason: options.triggerReason,
                    metadata: {
                        ...(options.metadata || {}),
                        failedAt: new Date().toISOString(),
                    },
                    recipientUserId: options.recipientUserId,
                    errorMessage: error instanceof Error ? error.message : String(error || 'Unknown error'),
                },
            );
            return false;
        }
    }

    /**
     * Sends a single consolidated email containing multiple CVEs for a given vendor.
     * Used by automatic notifications to group alerts per subscriber + vendor.
     */
    async sendGroupedCveEmail(
        to: string,
        recipientName: string,
        vendor: string,
        vulnerabilities: Array<{
            cveId: string;
            severity: string;
            cvssScore: any;
            epssScore: any;
            hasPublicExploit: boolean;
            description: string;
            affectedProducts: any[];
            references: any[];
            remediationInfo: any;
            publishedAt: any;
        }>,
        options: {
            recipientUserId?: number;
            templateKey?: string;
            triggerReason?: string;
        } = {},
    ): Promise<boolean> {
        if (!this.transporter) {
            await this.loadConfig();
            if (!this.transporter) {
                this.logger.warn('Email sending skipped: SMTP not configured');
                return false;
            }
        }

        try {
            const cfg = await this.getTemplateConfig();
            const headerSrc = cfg.headerImageUrl
                ? (cfg.headerImageUrl.startsWith('data:image/') ? 'cid:occ-header-banner' : this.escapeHtml(cfg.headerImageUrl))
                : '';

            const intro = (cfg.introMessage || '')
                .replace(/\{\{\s*fabricante\s*\}\}/gi, vendor)
                .split('\n')
                .filter(Boolean)
                .map((line: string) => `<p style="margin:8px 0;color:#111827;font-size:16px;line-height:1.45;">${this.escapeHtml(line)}</p>`)
                .join('');

            // Render each CVE block
            const cveBlocks = vulnerabilities.map((vuln) => {
                const publishedAt = vuln.publishedAt ? new Date(vuln.publishedAt).toLocaleString('es-ES') : 'N/D';
                const exploitProbability = vuln.epssScore != null ? `${(Number(vuln.epssScore) * 100).toFixed(2)}%` : 'N/D';
                const affectedProducts = Array.isArray(vuln.affectedProducts) ? vuln.affectedProducts : [];
                const references = this.getNotificationReferences(vuln);
                const remediation = vuln.remediationInfo || {};
                const patchLink = (remediation as any)?.patchUrls?.[0] || '';

                const affectedHtml = affectedProducts.length > 0
                    ? `<ul style="margin:8px 0 0 22px;padding:0;">${affectedProducts.slice(0, 10)
                        .map((p: any) => `<li style="margin:2px 0;">${this.escapeHtml(`${p.vendor || ''}/${p.product || ''}`)}</li>`)
                        .join('')}</ul>`
                    : '<p style="margin:8px 0;color:#6B7280;">Sin productos identificados.</p>';

                const referencesHtml = references.length > 0
                    ? `<ul style="margin:8px 0 0 22px;padding:0;">${references.slice(0, 5)
                        .map((r: any) => `<li style="margin:2px 0;"><a href="${this.escapeHtml(r.url || '#')}" style="color:#2563EB;">${this.escapeHtml(r.url || 'Referencia')}</a></li>`)
                        .join('')}</ul>`
                    : '';

                const sevColor = ({ CRITICAL: 'DC2626', HIGH: 'EA580C', MEDIUM: 'CA8A04', LOW: '16A34A' } as Record<string, string>)[vuln.severity?.toUpperCase()] || '6B7280';

                return `
          <div style="border:1px solid #D1D5DB;background:#fff;margin-bottom:16px;">
            <div style="background:#${sevColor};color:#fff;padding:8px 12px;font-size:22px;font-weight:700;">${this.escapeHtml(vuln.cveId)}</div>
            <table style="width:100%;border-collapse:collapse;">
              <tr>
                <td style="padding:10px 12px;border:1px solid #E5E7EB;font-weight:700;">CVSS: ${this.escapeHtml(String(vuln.cvssScore ?? 'N/D'))}</td>
                <td style="padding:10px 12px;border:1px solid #E5E7EB;font-weight:700;">Severidad: ${this.escapeHtml(vuln.severity || 'N/D')}</td>
                <td style="padding:10px 12px;border:1px solid #E5E7EB;font-weight:700;">Publicado: ${this.escapeHtml(publishedAt)}</td>
              </tr>
            </table>
            ${cfg.showExploitProbability ? `<div style="padding:10px 12px;border:1px solid #E5E7EB;text-align:right;"><span style="background:#D9E16B;padding:6px 10px;border-radius:6px;font-weight:700;">Prob. Explotación: ${this.escapeHtml(exploitProbability)}</span></div>` : ''}
            ${cfg.showExploitExists ? `<div style="padding:10px 12px;border:1px solid #E5E7EB;"><strong>Exploit conocido:</strong> ${vuln.hasPublicExploit ? 'Sí' : 'No'}</div>` : ''}
            ${cfg.showDescription ? `<div style="padding:12px;border:1px solid #E5E7EB;"><strong>Descripción:</strong><p style="margin:8px 0 0;">${this.escapeHtml(vuln.description || 'Sin descripción disponible')}</p></div>` : ''}
            ${cfg.showAffectedSoftware ? `<div style="padding:12px;border:1px solid #E5E7EB;"><strong>Productos Afectados:</strong>${affectedHtml}</div>` : ''}
            ${cfg.showReferences && references.length > 0 ? `<div style="padding:12px;border:1px solid #E5E7EB;"><strong>Referencias:</strong>${referencesHtml}</div>` : ''}
            ${cfg.showPatchLink && patchLink ? `<div style="padding:12px;border:1px solid #E5E7EB;"><strong>Parche:</strong> <a href="${this.escapeHtml(patchLink)}" style="color:#2563EB;">${this.escapeHtml(patchLink)}</a></div>` : ''}
          </div>`;
            }).join('');

            const html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#F3F4F6;font-family:Arial,sans-serif;color:#111827;">
  <div style="max-width:920px;margin:0 auto;padding:16px;">
    <div style="background:#fff;border:1px solid #D1D5DB;">
      ${headerSrc ? `<img src="${headerSrc}" alt="Cabecera" style="width:100%;display:block;" />` : ''}
      <div style="padding:18px 24px;">
        <h2 style="text-align:center;margin:4px 0 14px;font-size:36px;">Productos ${this.escapeHtml(vendor)}</h2>
        <p style="margin:8px 0;color:#111827;font-size:16px;">Hola <strong>${this.escapeHtml(recipientName)}</strong>,</p>
        <p style="margin:8px 0;color:#4A5568;font-size:14px;line-height:1.6;">
          Se han identificado <strong>${vulnerabilities.length}</strong> vulnerabilidad${vulnerabilities.length > 1 ? 'es' : ''}
          relacionada${vulnerabilities.length > 1 ? 's' : ''} con <strong>${this.escapeHtml(vendor)}</strong>
          que requiere${vulnerabilities.length > 1 ? 'n' : ''} tu atención.
        </p>
        ${intro}
      </div>
      <div style="padding:0 20px 20px;">
        ${cveBlocks}
      </div>
    </div>
    <p style="color:#9CA3AF;font-size:11px;text-align:center;margin:16px 0 0;">
      Este mensaje ha sido generado automáticamente por el sistema de Gestión de Vulnerabilidades OCC.<br>
      No respondas a este correo.
    </p>
  </div>
</body>
</html>`;

            const attachments = await this.getInlineTemplateAttachments('cve-alert');
            const subject = vulnerabilities.length === 1
                ? `🛡️ Alerta CVE: ${vulnerabilities[0].cveId} — ${vulnerabilities[0].severity || 'INFO'}`
                : `🛡️ ${vulnerabilities.length} vulnerabilidades — ${vendor}`;

            const info = await this.transporter.sendMail({
                from: this.smtpConfig?.from || 'noreply@occ.local',
                to,
                subject,
                html,
                attachments,
            });

            await this.logNotification(
                to,
                recipientName,
                subject,
                html,
                vulnerabilities.map((v) => v.cveId),
                {
                    notificationType: 'digest',
                    templateKey: options.templateKey || 'legacy',
                    triggerReason: options.triggerReason || `vendor_group:${vendor}`,
                    recipientUserId: options.recipientUserId,
                },
            );

            this.logger.log(`Grouped email sent to ${to} (${vendor}, ${vulnerabilities.length} CVEs): ${info.messageId}`);
            return true;
        } catch (error) {
            this.logger.error(`Failed to send grouped email to ${to}`, error);
            return false;
        }
    }

    /**
     * Sends a single consolidated email per subscriber with ALL their CVEs grouped by vendor.
     * Used instead of sendGroupedCveEmail when we want ONE email per subscriber (not per vendor).
     */
    async sendConsolidatedSubscriberEmail(
        to: string,
        recipientName: string,
        vendorGroups: Map<string, Array<{
            cveId: string;
            severity: string;
            cvssScore: any;
            epssScore: any;
            hasPublicExploit: boolean;
            isKnownExploited: boolean;
            description: string;
            affectedProducts: any[];
            references: any[];
            remediationInfo: any;
            publishedAt: any;
        }>>,
        emailType: 'immediate' | 'digest' = 'immediate',
        options: {
            recipientUserId?: number;
            templateKey?: string;
            triggerReason?: string;
        } = {},
    ): Promise<boolean> {
        if (!this.transporter) {
            await this.loadConfig();
            if (!this.transporter) {
                this.logger.warn('Email sending skipped: SMTP not configured');
                return false;
            }
        }

        try {
            const cfg = await this.getTemplateConfig();
            const headerSrc = cfg.headerImageUrl
                ? (cfg.headerImageUrl.startsWith('data:image/') ? 'cid:occ-header-banner' : this.escapeHtml(cfg.headerImageUrl))
                : '';

            // Count totals
            let totalCves = 0;
            let criticalCount = 0;
            let highCount = 0;
            const vendorNames: string[] = [];

            for (const [vendor, vulns] of vendorGroups) {
                totalCves += vulns.length;
                vendorNames.push(vendor);
                for (const v of vulns) {
                    const sev = (v.severity || '').toUpperCase();
                    if (sev === 'CRITICAL') criticalCount++;
                    else if (sev === 'HIGH') highCount++;
                }
            }

            // Build vendor sections
            const vendorSections: string[] = [];
            for (const [vendor, vulns] of vendorGroups) {
                const sortedVulns = [...vulns].sort((a, b) => {
                    const scoreA = Number(a.cvssScore) || 0;
                    const scoreB = Number(b.cvssScore) || 0;
                    return scoreB - scoreA;
                });

                const cveBlocks = sortedVulns.map((vuln) => {
                    const publishedAt = vuln.publishedAt ? new Date(vuln.publishedAt).toLocaleString('es-ES') : 'N/D';
                    const exploitProbability = vuln.epssScore != null ? `${(Number(vuln.epssScore) * 100).toFixed(2)}%` : 'N/D';
                    const affectedProducts = Array.isArray(vuln.affectedProducts) ? vuln.affectedProducts : [];
                    const references = this.getNotificationReferences(vuln);
                    const remediation = vuln.remediationInfo || {};
                    const patchLink = (remediation as any)?.patchUrls?.[0] || '';

                    const affectedHtml = affectedProducts.length > 0
                        ? `<ul style="margin:8px 0 0 22px;padding:0;">${affectedProducts.slice(0, 10)
                            .map((p: any) => `<li style="margin:2px 0;">${this.escapeHtml(`${p.vendor || ''}/${p.product || ''}`)}</li>`)
                            .join('')}</ul>`
                        : '<p style="margin:8px 0;color:#6B7280;">Sin productos identificados.</p>';

                    const referencesHtml = references.length > 0
                        ? `<ul style="margin:8px 0 0 22px;padding:0;">${references.slice(0, 5)
                            .map((r: any) => `<li style="margin:2px 0;"><a href="${this.escapeHtml(r.url || '#')}" style="color:#2563EB;">${this.escapeHtml(r.url || 'Referencia')}</a></li>`)
                            .join('')}</ul>`
                        : '';

                    const sevColor = ({ CRITICAL: 'DC2626', HIGH: 'EA580C', MEDIUM: 'CA8A04', LOW: '16A34A' } as Record<string, string>)[(vuln.severity || '').toUpperCase()] || '6B7280';
                    const exploitBadge = vuln.isKnownExploited
                        ? '<span style="background:#DC2626;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;margin-left:8px;">KEV</span>'
                        : vuln.hasPublicExploit
                            ? '<span style="background:#EA580C;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;margin-left:8px;">Exploit público</span>'
                            : '';

                    return `
              <div style="border:1px solid #D1D5DB;background:#fff;margin-bottom:12px;">
                <div style="background:#${sevColor};color:#fff;padding:8px 12px;font-size:20px;font-weight:700;">${this.escapeHtml(vuln.cveId)}${exploitBadge}</div>
                <table style="width:100%;border-collapse:collapse;">
                  <tr>
                    <td style="padding:8px 12px;border:1px solid #E5E7EB;font-weight:700;">CVSS: ${this.escapeHtml(String(vuln.cvssScore ?? 'N/D'))}</td>
                    <td style="padding:8px 12px;border:1px solid #E5E7EB;font-weight:700;">Severidad: ${this.escapeHtml(vuln.severity || 'N/D')}</td>
                    <td style="padding:8px 12px;border:1px solid #E5E7EB;font-weight:700;">Publicado: ${this.escapeHtml(publishedAt)}</td>
                  </tr>
                </table>
                ${cfg.showExploitProbability ? `<div style="padding:8px 12px;border:1px solid #E5E7EB;text-align:right;"><span style="background:#D9E16B;padding:4px 8px;border-radius:6px;font-weight:700;font-size:13px;">Prob. Explotación: ${this.escapeHtml(exploitProbability)}</span></div>` : ''}
                ${cfg.showDescription ? `<div style="padding:10px 12px;border:1px solid #E5E7EB;"><strong>Descripción:</strong><p style="margin:6px 0 0;font-size:14px;">${this.escapeHtml(vuln.description || 'Sin descripción disponible')}</p></div>` : ''}
                ${cfg.showAffectedSoftware ? `<div style="padding:10px 12px;border:1px solid #E5E7EB;"><strong>Productos Afectados:</strong>${affectedHtml}</div>` : ''}
                ${cfg.showReferences && references.length > 0 ? `<div style="padding:10px 12px;border:1px solid #E5E7EB;"><strong>Referencias:</strong>${referencesHtml}</div>` : ''}
                ${cfg.showPatchLink && patchLink ? `<div style="padding:10px 12px;border:1px solid #E5E7EB;"><strong>Parche:</strong> <a href="${this.escapeHtml(patchLink)}" style="color:#2563EB;">${this.escapeHtml(patchLink)}</a></div>` : ''}
              </div>`;
                }).join('');

                vendorSections.push(`
            <div style="margin-bottom:24px;">
              <h3 style="margin:0 0 12px;font-size:24px;color:#1F2937;border-bottom:2px solid #2563EB;padding-bottom:8px;">${this.escapeHtml(vendor)} (${vulns.length})</h3>
              ${cveBlocks}
            </div>`);
            }

            const typeLabel = emailType === 'digest' ? 'Resumen' : 'Alerta';
            const severitySummary = [
                criticalCount > 0 ? `${criticalCount} crítica${criticalCount > 1 ? 's' : ''}` : '',
                highCount > 0 ? `${highCount} alta${highCount > 1 ? 's' : ''}` : '',
            ].filter(Boolean).join(' + ') || `${totalCves} vulnerabilidad${totalCves > 1 ? 'es' : ''}`;

            const html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#F3F4F6;font-family:Arial,sans-serif;color:#111827;">
  <div style="max-width:920px;margin:0 auto;padding:16px;">
    <div style="background:#fff;border:1px solid #D1D5DB;">
      ${headerSrc ? `<img src="${headerSrc}" alt="Cabecera" style="width:100%;display:block;" />` : ''}
      <div style="padding:18px 24px;">
        <h2 style="text-align:center;margin:4px 0 14px;font-size:32px;">${typeLabel} de Vulnerabilidades</h2>
        <p style="margin:8px 0;color:#111827;font-size:16px;">Hola <strong>${this.escapeHtml(recipientName)}</strong>,</p>
        <p style="margin:8px 0;color:#4A5568;font-size:14px;line-height:1.6;">
          Se han identificado <strong>${totalCves}</strong> vulnerabilidad${totalCves > 1 ? 'es' : ''}
          (${severitySummary}) en ${vendorNames.length} fabricante${vendorNames.length > 1 ? 's' : ''}
          que requiere${totalCves > 1 ? 'n' : ''} tu atención.
        </p>
      </div>
      <div style="padding:0 20px 20px;">
        ${vendorSections.join('')}
      </div>
    </div>
    <p style="color:#9CA3AF;font-size:11px;text-align:center;margin:16px 0 0;">
      Este mensaje ha sido generado automáticamente por el sistema de Gestión de Vulnerabilidades OCC.<br>
      No respondas a este correo.
    </p>
  </div>
</body>
</html>`;

            const attachments = await this.getInlineTemplateAttachments('cve-alert');
            const vendorList = vendorNames.slice(0, 3).join(', ') + (vendorNames.length > 3 ? '...' : '');
            const subject = emailType === 'digest'
                ? `📋 Resumen CVE: ${severitySummary} (${vendorList})`
                : `🛡️ ${severitySummary} — ${vendorList}`;

            const info = await this.transporter.sendMail({
                from: this.smtpConfig?.from || 'noreply@occ.local',
                to,
                subject,
                html,
                attachments,
            });

            const allCveIds = Array.from(vendorGroups.values()).flat().map((v) => v.cveId);
            await this.logNotification(to, recipientName, subject, html, allCveIds, {
                notificationType: emailType,
                templateKey: options.templateKey || 'normal_v2',
                triggerReason: options.triggerReason || `${emailType}_notification`,
                recipientUserId: options.recipientUserId,
                metadata: {
                    vendorCount: vendorGroups.size,
                    vendorNames,
                },
            });

            this.logger.log(`Consolidated ${emailType} email sent to ${to} (${totalCves} CVEs, ${vendorNames.length} vendors): ${info.messageId}`);
            return true;
        } catch (error) {
            this.logger.error(`Failed to send consolidated email to ${to}`, error);
            return false;
        }
    }

    /**
     * Cron: Send digest emails daily at 08:00.
     * Processes PendingDigestNotification entries for subscribers with matching digestFrequency.
     */
    @Cron('0 0 */2 * * *')
    async sendScheduledDigests() {
        return this.runDigestNotificationJob('cron');
    }

    async runDigestNotificationJob(triggerMode: 'manual' | 'cron' = 'manual') {
        this.logger.log('Digest cron: starting daily digest processing');
        const centerSettings = await this.getNotificationCenterSettingsRaw();
        const intervalHours = Number(centerSettings.digest.intervalHours || 12);
        const latestCompleted = await (this.prisma as any).notificationJobRun.findFirst({
            where: {
                jobType: 'digest_notification_job',
                status: 'completed',
            },
            orderBy: { finishedAt: 'desc' },
        });
        if (!centerSettings.general.processEnabled || !centerSettings.digest.enabled) {
            this.logger.log('Digest cron: process disabled by notification center settings');
            return {
                success: true,
                skipped: true,
                reason: 'process_disabled',
            };
        }

        if (triggerMode === 'cron') {
            if (latestCompleted?.finishedAt) {
                const elapsedMs = Date.now() - new Date(latestCompleted.finishedAt).getTime();
                if (elapsedMs < intervalHours * 3600000) {
                    this.logger.log(`Digest cron: waiting interval ${intervalHours}h before next cycle`);
                    return {
                        success: true,
                        skipped: true,
                        reason: 'interval_not_reached',
                    };
                }
            }
        }

        const watermarkTo = new Date();
        const watermarkFrom = latestCompleted?.watermarkTo
            ? new Date(latestCompleted.watermarkTo)
            : latestCompleted?.finishedAt
                ? new Date(latestCompleted.finishedAt)
                : new Date(watermarkTo.getTime() - intervalHours * 3600000);

        const job = await this.startNotificationJobRun('digest_notification_job', triggerMode, {
            source: 'notification-service',
        });
        let emailsSent = 0;
        let totalProcessed = 0;
        let queuePending = 0;

        try {
            // Find subscribers with pending digest notifications
            const pendingGrouped = await this.prisma.pendingDigestNotification.findMany({
                include: {
                    user: {
                        select: {
                            id: true,
                            name: true,
                            email: true,
                            notificationEmail: true,
                            notificationPolicy: true,
                        },
                    },
                    vulnerability: {
                        select: {
                            id: true,
                            cveId: true,
                            cvssV31Severity: true,
                            cvssV31Score: true,
                            publishedAt: true,
                            epssScore: true,
                            hasPublicExploit: true,
                            isKnownExploited: true,
                            affectedProducts: true,
                            description: true,
                            references: true,
                            remediationInfo: true,
                        },
                    },
                },
                orderBy: { createdAt: 'asc' },
            });

            queuePending = pendingGrouped.length;
            if (pendingGrouped.length === 0) {
                this.logger.log('Digest cron: no pending digest notifications');
                await this.completeNotificationJobRun(job.id, {
                    notificationsSent: 0,
                    notificationsFailed: 0,
                    vulnerabilitiesConsidered: 0,
                    queuePending: 0,
                    watermarkFrom,
                    watermarkTo,
                    details: { message: 'No pending digest notifications' },
                });
                return { success: true, emailsSent: 0, totalProcessed: 0 };
            }

            // Group by subscriber
            const bySubscriber = new Map<number, {
                user: typeof pendingGrouped[0]['user'];
                entries: typeof pendingGrouped;
            }>();

            for (const entry of pendingGrouped) {
                if (!bySubscriber.has(entry.userId)) {
                    bySubscriber.set(entry.userId, { user: entry.user, entries: [] });
                }
                bySubscriber.get(entry.userId)!.entries.push(entry);
            }

            const processedIds: number[] = [];

            for (const [, { user, entries }] of bySubscriber) {
                // Check digest frequency: for now, daily is always eligible at 08:00
                const policy = user.notificationPolicy;
                const frequency = policy?.digestFrequency || 'daily';

                // Skip if frequency doesn't match today's schedule
                const now = new Date();
                if (frequency === 'weekly') {
                    const dayOfWeek = now.getDay(); // 0=Sun, 1=Mon...
                    const targetDay = policy?.digestDayOfWeek ?? 1; // default Monday
                    if (dayOfWeek !== targetDay) continue;
                }
                // '4h' and '8h' frequencies are handled via separate cron entries or skipped here

                const recipientEmail = user.notificationEmail || user.email;
                if (!recipientEmail) continue;

                // Group entries by vendor
                const vendorMap = new Map<string, Array<{
                    cveId: string; severity: string; cvssScore: any; epssScore: any;
                    hasPublicExploit: boolean; isKnownExploited: boolean; description: string;
                    affectedProducts: any[]; references: any[]; remediationInfo: any; publishedAt: any;
                }>>();

                for (const entry of entries) {
                    const v = entry.vulnerability;
                    const vendor = entry.vendor || 'unknown';

                    if (!vendorMap.has(vendor)) vendorMap.set(vendor, []);
                    const list = vendorMap.get(vendor)!;

                    // Avoid duplicate CVEs
                    if (list.some((x) => x.cveId === v.cveId)) continue;

                    list.push({
                        cveId: v.cveId,
                        severity: v.cvssV31Severity || 'N/A',
                        cvssScore: v.cvssV31Score ?? 'N/A',
                        epssScore: v.epssScore,
                        hasPublicExploit: !!v.hasPublicExploit,
                        isKnownExploited: !!v.isKnownExploited,
                        description: v.description || 'Sin descripción disponible',
                        affectedProducts: this.parseJson(v.affectedProducts) || [],
                        references: this.parseJson(v.references) || [],
                        remediationInfo: this.parseJson(v.remediationInfo) || {},
                        publishedAt: v.publishedAt,
                    });
                }

                const sent = await this.sendConsolidatedSubscriberEmail(
                    recipientEmail,
                    user.name,
                    vendorMap,
                    'digest',
                    {
                        recipientUserId: user.id,
                        templateKey: 'normal_v2',
                        triggerReason: `digest_notification_job:${triggerMode}`,
                    },
                );

                // Record VulnerabilityNotification for deduplication
                for (const entry of entries) {
                    await this.prisma.vulnerabilityNotification.create({
                        data: {
                            vulnerabilityId: entry.vulnerabilityId,
                            subscriberUserId: user.id,
                            recipientEmail,
                            recipientName: user.name,
                            status: sent ? 'sent' : 'failed',
                        },
                    });
                    processedIds.push(entry.id);
                    totalProcessed++;
                }

                if (sent) emailsSent++;
            }

            // Remove processed pending entries
            if (processedIds.length > 0) {
                await this.prisma.pendingDigestNotification.deleteMany({
                    where: { id: { in: processedIds } },
                });
            }

            this.logger.log(
                `Digest cron complete: ${emailsSent} digest emails sent, ${totalProcessed} CVEs processed`,
            );
            await this.completeNotificationJobRun(job.id, {
                notificationsSent: emailsSent,
                notificationsFailed: Math.max(bySubscriber.size - emailsSent, 0),
                vulnerabilitiesConsidered: totalProcessed,
                queuePending: Math.max(queuePending - processedIds.length, 0),
                watermarkFrom,
                watermarkTo,
                details: {
                    subscriberCount: bySubscriber.size,
                    processedIds,
                },
            });
            return { success: true, emailsSent, totalProcessed };
        } catch (error) {
            this.logger.error('Digest cron failed', error);
            await this.failNotificationJobRun(job.id, error, {
                notificationsSent: emailsSent,
                notificationsFailed: 1,
                vulnerabilitiesConsidered: totalProcessed,
                queuePending,
                details: {
                    watermarkFrom,
                    watermarkTo,
                },
            });
            throw error;
        }
    }

    private async logNotification(
        recipientEmail: string,
        recipientName: string,
        subject: string,
        htmlContent: string,
        cveIds: string[] = [],
        options: {
            notificationType?: string;
            templateKey?: string;
            channel?: string;
            triggerReason?: string;
            errorMessage?: string | null;
            metadata?: Record<string, any>;
            recipientUserId?: number;
        } = {},
    ) {
        try {
            await this.prisma.notificationLog.create({
                data: {
                    recipientEmail,
                    recipientName,
                    subject,
                    notificationType: options.notificationType || 'normal',
                    templateKey: options.templateKey || null,
                    channel: options.channel || 'email',
                    vulnerabilityCount: Array.isArray(cveIds) ? cveIds.length : 0,
                    triggerReason: options.triggerReason || null,
                    htmlContent,
                    cveIds: JSON.stringify(cveIds),
                    status: options.errorMessage ? 'failed' : 'sent',
                    errorMessage: options.errorMessage || null,
                    metadataJson: options.metadata ? JSON.stringify(options.metadata) : null,
                },
            });
            if (options.recipientUserId) {
                await this.prisma.user.update({
                    where: { id: options.recipientUserId },
                    data: { lastNotificationSentAt: new Date() },
                }).catch(() => undefined);
            }
        } catch (error) {
            this.logger.error('Failed to log notification', error);
        }
    }

    async startNotificationJobRun(jobType: string, triggerMode: 'manual' | 'cron' | 'hook' = 'manual', details?: Record<string, any>) {
        const existing = await (this.prisma as any).notificationJobRun.findFirst({
            where: {
                jobType,
                status: 'running',
            },
            orderBy: { startedAt: 'desc' },
        });
        if (existing) {
            throw new InternalServerErrorException(`Job already running: ${jobType}`);
        }

        return (this.prisma as any).notificationJobRun.create({
            data: {
                jobType,
                triggerMode,
                status: 'running',
                details: details ? JSON.stringify(details) : null,
            },
        });
    }

    async completeNotificationJobRun(id: number, data: {
        notificationsSent?: number;
        notificationsFailed?: number;
        vulnerabilitiesConsidered?: number;
        queuePending?: number;
        watermarkFrom?: Date | null;
        watermarkTo?: Date | null;
        details?: Record<string, any>;
    } = {}) {
        return (this.prisma as any).notificationJobRun.update({
            where: { id },
            data: {
                status: 'completed',
                finishedAt: new Date(),
                notificationsSent: Number(data.notificationsSent || 0),
                notificationsFailed: Number(data.notificationsFailed || 0),
                vulnerabilitiesConsidered: Number(data.vulnerabilitiesConsidered || 0),
                queuePending: Number(data.queuePending || 0),
                watermarkFrom: data.watermarkFrom || null,
                watermarkTo: data.watermarkTo || null,
                details: data.details ? JSON.stringify(data.details) : undefined,
            },
        });
    }

    async failNotificationJobRun(id: number, error: any, data: {
        notificationsSent?: number;
        notificationsFailed?: number;
        vulnerabilitiesConsidered?: number;
        queuePending?: number;
        details?: Record<string, any>;
    } = {}) {
        return (this.prisma as any).notificationJobRun.update({
            where: { id },
            data: {
                status: 'failed',
                finishedAt: new Date(),
                notificationsSent: Number(data.notificationsSent || 0),
                notificationsFailed: Number(data.notificationsFailed || 0),
                vulnerabilitiesConsidered: Number(data.vulnerabilitiesConsidered || 0),
                queuePending: Number(data.queuePending || 0),
                errorMessage: String(error?.message || error || 'Unknown error'),
                retryCount: { increment: 1 },
                details: data.details ? JSON.stringify(data.details) : undefined,
            },
        });
    }

    async getHistory(page: number = 1, limit: number = 20) {
        const take = Math.min(limit, 100);
        const skip = (page - 1) * take;

        const [data, total] = await Promise.all([
            this.prisma.notificationLog.findMany({
                orderBy: { sentAt: 'desc' },
                take,
                skip,
                select: {
                    id: true,
                    recipientEmail: true,
                    recipientName: true,
                    subject: true,
                    notificationType: true,
                    templateKey: true,
                    channel: true,
                    vulnerabilityCount: true,
                    triggerReason: true,
                    cveIds: true,
                    status: true,
                    errorMessage: true,
                    metadataJson: true,
                    sentAt: true,
                },
            }),
            this.prisma.notificationLog.count(),
        ]);

        return {
            data: data.map(d => ({
                ...d,
                to: d.recipientEmail,
                template: d.templateKey,
                type: d.notificationType,
                cveIds: this.parseJson(d.cveIds),
                metadata: this.parseJson(d.metadataJson || '{}'),
            })),
            total,
            page,
            limit: take,
        };
    }

    async getNotificationById(id: number) {
        const notification = await this.prisma.notificationLog.findUnique({
            where: { id },
        });
        if (!notification) throw new NotFoundException('Notification not found');
        return {
            ...notification,
            to: notification.recipientEmail,
            template: notification.templateKey,
            type: notification.notificationType,
            cveIds: this.parseJson(notification.cveIds),
            metadata: this.parseJson(notification.metadataJson || '{}'),
        };
    }

    async resendNotification(id: number) {
        if (!this.transporter) {
            await this.loadConfig();
            if (!this.transporter) {
                throw new NotFoundException('SMTP Configuration not found or invalid');
            }
        }

        const notification = await this.prisma.notificationLog.findUnique({
            where: { id },
        });
        if (!notification) {
            throw new NotFoundException('Notification not found');
        }

        try {
            const info = await this.transporter.sendMail({
                from: this.smtpConfig?.from || 'noreply@occ.local',
                to: notification.recipientEmail,
                subject: notification.subject,
                html: notification.htmlContent,
            });

            await this.logNotification(
                notification.recipientEmail,
                notification.recipientName || notification.recipientEmail,
                notification.subject,
                notification.htmlContent,
                this.parseJson(notification.cveIds) || [],
                {
                    notificationType: notification.notificationType || 'normal',
                    templateKey: notification.templateKey || undefined,
                    channel: notification.channel || 'email',
                    triggerReason: `manual_resend:${notification.id}`,
                    metadata: {
                        resentFromId: notification.id,
                        messageId: info.messageId,
                    },
                },
            );

            return { success: true, messageId: info.messageId };
        } catch (error) {
            this.logger.error(`Failed to resend notification ${id}`, error);
            throw new InternalServerErrorException('Failed to resend notification');
        }
    }

    async getNotificationProcessHealth(): Promise<NotificationProcessHealth> {
        const [settings, queuePending, recentLogs, latestRuns, lastSent, lastFailed, latestSmartSent, latestSmartFailed] = await Promise.all([
            this.getNotificationCenterSettingsRaw(),
            this.prisma.pendingDigestNotification.count(),
            this.prisma.notificationLog.findMany({
                orderBy: { sentAt: 'desc' },
                take: 12,
                select: {
                    id: true,
                    recipientEmail: true,
                    subject: true,
                    notificationType: true,
                    status: true,
                    sentAt: true,
                    vulnerabilityCount: true,
                    triggerReason: true,
                    errorMessage: true,
                },
            }),
            (this.prisma as any).notificationJobRun.findMany({
                orderBy: { startedAt: 'desc' },
                take: 20,
            }),
            this.prisma.notificationLog.findFirst({
                where: { status: 'sent' },
                orderBy: { sentAt: 'desc' },
                select: {
                    id: true,
                    subject: true,
                    notificationType: true,
                    sentAt: true,
                    recipientEmail: true,
                },
            }),
            this.prisma.notificationLog.findFirst({
                where: { status: { not: 'sent' } },
                orderBy: { sentAt: 'desc' },
                select: {
                    id: true,
                    subject: true,
                    notificationType: true,
                    sentAt: true,
                    recipientEmail: true,
                    errorMessage: true,
                },
            }),
            (this.prisma as any).smartNotificationReport.findFirst({
                where: { status: 'sent' },
                orderBy: { sentAt: 'desc' },
            }),
            (this.prisma as any).smartNotificationReport.findFirst({
                where: { status: 'failed' },
                orderBy: { updatedAt: 'desc' },
            }),
        ]);

        const groupedRuns = new Map<string, any>();
        const latestCompletedByJob = new Map<string, any>();
        const latestFailedByJob = new Map<string, any>();
        for (const run of latestRuns || []) {
            if (!groupedRuns.has(run.jobType)) {
                groupedRuns.set(run.jobType, run);
            }
            if (run.status === 'completed' && !latestCompletedByJob.has(run.jobType)) {
                latestCompletedByJob.set(run.jobType, run);
            }
            if (run.status === 'failed' && !latestFailedByJob.has(run.jobType)) {
                latestFailedByJob.set(run.jobType, run);
            }
        }

        const digestRun = groupedRuns.get('digest_notification_job');
        const immediateRun = groupedRuns.get('immediate_notification_job');
        const intelligentRun = groupedRuns.get('intelligent_notification_job') || (latestSmartSent || latestSmartFailed ? {
            jobType: 'intelligent_notification_job',
            status: latestSmartSent ? 'completed' : 'failed',
            startedAt: latestSmartSent?.createdAt || latestSmartFailed?.createdAt || null,
            finishedAt: latestSmartSent?.sentAt || latestSmartFailed?.updatedAt || null,
            notificationsSent: latestSmartSent ? 1 : 0,
            notificationsFailed: latestSmartFailed ? 1 : 0,
            queuePending: 0,
            errorMessage: latestSmartFailed?.errorMessage || null,
        } : null);

        const retries = Number((latestRuns || []).reduce((sum: number, run: any) => sum + Number(run.retryCount || 0), 0));
        const nextDigestExecution = this.calculateNextDigestExecution(settings.digest, digestRun);
        const nextIntelligentExecution = this.calculateNextIntelligentExecution(settings.intelligent, intelligentRun);

        return {
            enabled: settings.general.processEnabled,
            smtpConfigured: !!this.smtpConfig,
            queuePending,
            retries,
            lastSent,
            lastFailed,
            jobs: {
                immediate: this.mapJobHealth('immediate_notification_job', immediateRun, {
                    nextExecution: 'Tras la siguiente recolección con hallazgos relevantes',
                    mode: 'hook',
                    lastSuccessfulAt: latestCompletedByJob.get('immediate_notification_job')?.finishedAt || latestCompletedByJob.get('immediate_notification_job')?.startedAt || null,
                    lastFailedAt: latestFailedByJob.get('immediate_notification_job')?.finishedAt || latestFailedByJob.get('immediate_notification_job')?.startedAt || null,
                }),
                digest: this.mapJobHealth('digest_notification_job', digestRun, {
                    nextExecution: nextDigestExecution,
                    mode: 'scheduled',
                    lastSuccessfulAt: latestCompletedByJob.get('digest_notification_job')?.finishedAt || latestCompletedByJob.get('digest_notification_job')?.startedAt || null,
                    lastFailedAt: latestFailedByJob.get('digest_notification_job')?.finishedAt || latestFailedByJob.get('digest_notification_job')?.startedAt || null,
                }),
                intelligent: this.mapJobHealth('intelligent_notification_job', intelligentRun, {
                    nextExecution: nextIntelligentExecution,
                    mode: 'scheduled',
                    lastSuccessfulAt: latestCompletedByJob.get('intelligent_notification_job')?.finishedAt || latestCompletedByJob.get('intelligent_notification_job')?.startedAt || latestSmartSent?.sentAt || null,
                    lastFailedAt: latestFailedByJob.get('intelligent_notification_job')?.finishedAt || latestFailedByJob.get('intelligent_notification_job')?.startedAt || latestSmartFailed?.updatedAt || null,
                }),
            },
            recentLogs,
        };
    }

    private mapJobHealth(jobType: string, run: any, extras: { nextExecution: string; mode: string; lastSuccessfulAt?: string | Date | null; lastFailedAt?: string | Date | null }) {
        const details = this.parseJson(run?.details || '{}') || {};
        return {
            jobType,
            mode: extras.mode,
            status: run?.status || 'idle',
            startedAt: run?.startedAt || null,
            finishedAt: run?.finishedAt || null,
            watermarkFrom: run?.watermarkFrom || null,
            watermarkTo: run?.watermarkTo || null,
            notificationsSent: Number(run?.notificationsSent || 0),
            notificationsFailed: Number(run?.notificationsFailed || 0),
            vulnerabilitiesConsidered: Number(run?.vulnerabilitiesConsidered || 0),
            queuePending: Number(run?.queuePending || 0),
            errorMessage: run?.errorMessage || null,
            nextExecution: extras.nextExecution,
            durationMs: run?.startedAt && run?.finishedAt
                ? Math.max(0, new Date(run.finishedAt).getTime() - new Date(run.startedAt).getTime())
                : Number(details?.durationMs || 0),
            lastSuccessfulAt: extras.lastSuccessfulAt || (run?.status === 'completed' ? (run?.finishedAt || run?.startedAt || null) : null),
            lastFailedAt: extras.lastFailedAt || (run?.status === 'failed' ? (run?.finishedAt || run?.startedAt || null) : null),
            findingsDetected: Number(details?.findingsDetected || 0),
            impactedSubscribers: Number(details?.impactedSubscribers || 0),
            notificationsSuppressed: Number(details?.notificationsSuppressed || 0),
            schedulerStatus: details?.schedulerStatus || (extras.mode === 'scheduled' ? 'active' : 'manual'),
        };
    }

    private calculateNextDigestExecution(digestConfig: NotificationCenterConfig['digest'], run: any): string {
        const interval = Number(digestConfig?.intervalHours || 12);
        const lastBase = run?.finishedAt ? new Date(run.finishedAt) : new Date();
        if (!digestConfig?.enabled) return 'Deshabilitado';
        lastBase.setHours(lastBase.getHours() + interval);
        return lastBase.toISOString();
    }

    private calculateNextIntelligentExecution(intelligentConfig: NotificationCenterConfig['intelligent'], run?: any): string {
        if (!intelligentConfig?.enabled) return 'Deshabilitado';
        const intervalHours = Number(intelligentConfig.analysisFrequencyHours || 24);
        const next = run?.finishedAt ? new Date(run.finishedAt) : new Date();
        if (intervalHours >= 24) {
            next.setHours(Number(intelligentConfig.evaluationHour || 8), 0, 0, 0);
            if (next.getTime() <= Date.now()) next.setDate(next.getDate() + 1);
            return next.toISOString();
        }
        next.setHours(next.getHours() + intervalHours);
        return next.toISOString();
    }

    private async getNotificationCenterSettingsRaw(): Promise<NotificationCenterConfig> {
        const row = await this.prisma.apiConfiguration.findFirst({
            where: { slug: NotificationService.CENTER_SETTINGS_SLUG, provider: 'notification-center' },
        });
        return this.mergeNotificationCenterConfig(this.parseJson(row?.settings || '{}'));
    }

    // ── Notification Policy CRUD ────────────────────────────────────

    async getNotificationPolicy(userId: number) {
        const policy = await this.prisma.notificationPolicy.findUnique({
            where: { userId },
        });

        if (!policy) {
            // Return defaults
            return {
                userId,
                immediateEnabled: true,
                immediateMinSeverity: 'HIGH',
                immediateMinCvss: 8.5,
                immediateMinEpss: 0.2,
                immediateMinEpssPercentile: 0.8,
                immediateKevOnly: false,
                immediatePublicExploitOnly: false,
                immediateActiveExploitationOnly: false,
                immediatePatchUnconfirmedOnly: false,
                immediateOnlyNewVulnerabilities: true,
                immediateOnSeverityChange: true,
                immediateOnExploitChange: true,
                immediateOnPatchChange: true,
                immediateOnlySubscribedSystems: true,
                immediateMinConfidence: 0.6,
                immediateMinSources: 1,
                immediateVendorFilters: '[]',
                immediateProductFilters: '[]',
                immediateCategoryFilters: '[]',
                immediateExclusions: '[]',
                immediateForCritical: true,
                immediateForExploitable: true,
                digestEnabled: true,
                digestMinSeverity: 'MEDIUM',
                digestMinCvss: 7.0,
                digestMinEpss: 0,
                digestOnlySubscribedSystems: true,
                digestMinConfidence: 0.5,
                digestMinSources: 1,
                digestVendorFilters: '[]',
                digestProductFilters: '[]',
                digestCategoryFilters: '[]',
                digestExclusions: '[]',
                digestFrequency: 'daily',
                digestHour: 8,
                digestDayOfWeek: null,
                intelligentEnabled: true,
                intelligentDailyHour: 8,
                intelligentLookbackHours: 24,
                intelligentContextDays: 7,
                intelligentMinConfidence: 0.65,
                intelligentMinRelevanceScore: 0.6,
                intelligentCooldownHours: 24,
                intelligentMaxNotificationsPerDay: 2,
                intelligentExclusions: '[]',
                intelligentOnlyWhenFinding: true,
                intelligentScenarioFlags: JSON.stringify({
                    attackPath: true,
                    campaignCluster: true,
                    compoundRisk: true,
                    postureChange: true,
                }),
                minCvssForImmediate: 9.0,
                isActive: true,
                isDefault: true,
            };
        }

        return { ...policy, isDefault: false };
    }

    async upsertNotificationPolicy(userId: number, data: {
        immediateEnabled?: boolean;
        immediateMinSeverity?: string;
        immediateMinCvss?: number;
        immediateMinEpss?: number;
        immediateMinEpssPercentile?: number;
        immediateKevOnly?: boolean;
        immediatePublicExploitOnly?: boolean;
        immediateActiveExploitationOnly?: boolean;
        immediatePatchUnconfirmedOnly?: boolean;
        immediateOnlyNewVulnerabilities?: boolean;
        immediateOnSeverityChange?: boolean;
        immediateOnExploitChange?: boolean;
        immediateOnPatchChange?: boolean;
        immediateOnlySubscribedSystems?: boolean;
        immediateMinConfidence?: number;
        immediateMinSources?: number;
        immediateVendorFilters?: string;
        immediateProductFilters?: string;
        immediateCategoryFilters?: string;
        immediateExclusions?: string;
        immediateForCritical?: boolean;
        immediateForExploitable?: boolean;
        minCvssForImmediate?: number;
        digestEnabled?: boolean;
        digestMinSeverity?: string;
        digestMinCvss?: number;
        digestMinEpss?: number;
        digestOnlySubscribedSystems?: boolean;
        digestMinConfidence?: number;
        digestMinSources?: number;
        digestVendorFilters?: string;
        digestProductFilters?: string;
        digestCategoryFilters?: string;
        digestExclusions?: string;
        periodicEnabled?: boolean;
        periodicThresholdCvss?: number;
        periodicIntervalHours?: number;
        intelligentEnabled?: boolean;
        intelligentDailyHour?: number;
        intelligentLookbackHours?: number;
        intelligentContextDays?: number;
        intelligentMinConfidence?: number;
        intelligentMinRelevanceScore?: number;
        intelligentCooldownHours?: number;
        intelligentMaxNotificationsPerDay?: number;
        intelligentExclusions?: string;
        intelligentOnlyWhenFinding?: boolean;
        intelligentScenarioFlags?: string;
        smartEnabled?: boolean;
        smartFrequency?: string;
        smartDayOfWeek?: number;
        smartHour?: number;
        digestFrequency?: string;
        digestHour?: number;
        digestDayOfWeek?: number;
        isActive?: boolean;
    }) {
        // Validate user exists and is subscriber
        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        if (!user) throw new NotFoundException(`User with id ${userId} not found`);

        const updateData: any = {};
        const fields = [
            'immediateEnabled', 'immediateMinSeverity', 'immediateMinCvss', 'immediateMinEpss', 'immediateMinEpssPercentile',
            'immediateKevOnly', 'immediatePublicExploitOnly', 'immediateActiveExploitationOnly', 'immediatePatchUnconfirmedOnly',
            'immediateOnlyNewVulnerabilities', 'immediateOnSeverityChange', 'immediateOnExploitChange', 'immediateOnPatchChange',
            'immediateOnlySubscribedSystems', 'immediateMinConfidence', 'immediateMinSources', 'immediateVendorFilters',
            'immediateProductFilters', 'immediateCategoryFilters', 'immediateExclusions',
            'immediateForCritical', 'immediateForExploitable', 'minCvssForImmediate',
            'digestEnabled', 'digestMinSeverity', 'digestMinCvss', 'digestMinEpss', 'digestOnlySubscribedSystems',
            'digestMinConfidence', 'digestMinSources', 'digestVendorFilters', 'digestProductFilters', 'digestCategoryFilters',
            'digestExclusions',
            'periodicEnabled', 'periodicThresholdCvss', 'periodicIntervalHours',
            'intelligentEnabled', 'intelligentDailyHour', 'intelligentLookbackHours', 'intelligentContextDays',
            'intelligentMinConfidence', 'intelligentMinRelevanceScore', 'intelligentCooldownHours', 'intelligentMaxNotificationsPerDay', 'intelligentExclusions',
            'intelligentOnlyWhenFinding', 'intelligentScenarioFlags',
            'smartEnabled', 'smartFrequency', 'smartDayOfWeek', 'smartHour',
            'digestFrequency', 'digestHour', 'digestDayOfWeek', 'isActive',
        ];
        for (const f of fields) {
            if (data[f] !== undefined) updateData[f] = data[f];
        }

        const policy = await this.prisma.notificationPolicy.upsert({
            where: { userId },
            create: {
                userId,
                immediateEnabled: data.immediateEnabled ?? true,
                immediateMinSeverity: data.immediateMinSeverity ?? 'HIGH',
                immediateMinCvss: data.immediateMinCvss ?? 8.5,
                immediateMinEpss: data.immediateMinEpss ?? 0.2,
                immediateMinEpssPercentile: data.immediateMinEpssPercentile ?? 0.8,
                immediateKevOnly: data.immediateKevOnly ?? false,
                immediatePublicExploitOnly: data.immediatePublicExploitOnly ?? false,
                immediateActiveExploitationOnly: data.immediateActiveExploitationOnly ?? false,
                immediatePatchUnconfirmedOnly: data.immediatePatchUnconfirmedOnly ?? false,
                immediateOnlyNewVulnerabilities: data.immediateOnlyNewVulnerabilities ?? true,
                immediateOnSeverityChange: data.immediateOnSeverityChange ?? true,
                immediateOnExploitChange: data.immediateOnExploitChange ?? true,
                immediateOnPatchChange: data.immediateOnPatchChange ?? true,
                immediateOnlySubscribedSystems: data.immediateOnlySubscribedSystems ?? true,
                immediateMinConfidence: data.immediateMinConfidence ?? 0.6,
                immediateMinSources: data.immediateMinSources ?? 1,
                immediateVendorFilters: data.immediateVendorFilters ?? '[]',
                immediateProductFilters: data.immediateProductFilters ?? '[]',
                immediateCategoryFilters: data.immediateCategoryFilters ?? '[]',
                immediateExclusions: data.immediateExclusions ?? '[]',
                immediateForCritical: data.immediateForCritical ?? true,
                immediateForExploitable: data.immediateForExploitable ?? true,
                minCvssForImmediate: data.minCvssForImmediate ?? 9.0,
                digestEnabled: data.digestEnabled ?? true,
                digestMinSeverity: data.digestMinSeverity ?? 'MEDIUM',
                digestMinCvss: data.digestMinCvss ?? 7.0,
                digestMinEpss: data.digestMinEpss ?? 0,
                digestOnlySubscribedSystems: data.digestOnlySubscribedSystems ?? true,
                digestMinConfidence: data.digestMinConfidence ?? 0.5,
                digestMinSources: data.digestMinSources ?? 1,
                digestVendorFilters: data.digestVendorFilters ?? '[]',
                digestProductFilters: data.digestProductFilters ?? '[]',
                digestCategoryFilters: data.digestCategoryFilters ?? '[]',
                digestExclusions: data.digestExclusions ?? '[]',
                periodicEnabled: data.periodicEnabled ?? true,
                periodicThresholdCvss: data.periodicThresholdCvss ?? 7.0,
                periodicIntervalHours: data.periodicIntervalHours ?? 12,
                intelligentEnabled: data.intelligentEnabled ?? true,
                intelligentDailyHour: data.intelligentDailyHour ?? 8,
                intelligentLookbackHours: data.intelligentLookbackHours ?? 24,
                intelligentContextDays: data.intelligentContextDays ?? 7,
                intelligentMinConfidence: data.intelligentMinConfidence ?? 0.65,
                intelligentMinRelevanceScore: data.intelligentMinRelevanceScore ?? 0.6,
                intelligentCooldownHours: data.intelligentCooldownHours ?? 24,
                intelligentMaxNotificationsPerDay: data.intelligentMaxNotificationsPerDay ?? 2,
                intelligentExclusions: data.intelligentExclusions ?? '[]',
                intelligentOnlyWhenFinding: data.intelligentOnlyWhenFinding ?? true,
                intelligentScenarioFlags: data.intelligentScenarioFlags ?? JSON.stringify({
                    attackPath: true,
                    campaignCluster: true,
                    compoundRisk: true,
                    postureChange: true,
                }),
                smartEnabled: data.smartEnabled ?? true,
                smartFrequency: data.smartFrequency ?? 'weekly',
                smartDayOfWeek: data.smartDayOfWeek ?? 1,
                smartHour: data.smartHour ?? 8,
                digestFrequency: data.digestFrequency ?? 'daily',
                digestHour: data.digestHour ?? 8,
                digestDayOfWeek: data.digestDayOfWeek ?? null,
                isActive: data.isActive ?? true,
            },
            update: updateData,
        });

        return policy;
    }

    async getAllNotificationPolicies() {
        const policies = await this.prisma.notificationPolicy.findMany({
            include: {
                user: {
                    select: { id: true, name: true, email: true, isSubscriber: true },
                },
            },
            orderBy: { userId: 'asc' },
        });

        return policies;
    }

    async getAvailableTemplates() {
        const templatesDir = this.getTemplatesDir();
        try {
            const files = fs.readdirSync(templatesDir)
                .filter(f => f.endsWith('.html'))
                .map(f => ({
                    name: f.replace('.html', ''),
                    filename: f,
                }));
            return files;
        } catch {
            return [];
        }
    }

    private getTemplatesDir(): string {
        // In production (dist/), templates are copied to dist/src/templates
        const distPath = path.join(process.cwd(), 'dist', 'src', 'templates');
        if (fs.existsSync(distPath)) return distPath;
        // In development, use src/templates
        return path.join(process.cwd(), 'src', 'templates');
    }

    async renderTemplate(templateName: string, context: any): Promise<string> {
        return this.loadTemplate(templateName, context);
    }

    private async loadTemplate(templateName: string, context: any): Promise<string> {
        if (templateName === 'cve-alert') {
            const templateConfig = await this.getTemplateConfig();
            return this.renderConfiguredCveTemplate(context, templateConfig);
        }

        const templatePath = path.join(this.getTemplatesDir(), `${templateName}.html`);

        try {
            let content = fs.readFileSync(templatePath, 'utf-8');
            for (const key in context) {
                const regex = new RegExp(`{{ ${key} }}`, 'g');
                content = content.replace(regex, String(context[key]));
                const regexNoSpace = new RegExp(`{{${key}}}`, 'g');
                content = content.replace(regexNoSpace, String(context[key]));
            }
            return content;
        } catch (error) {
            this.logger.error(`Template not found or error reading: ${templateName}`, error);
            return `
            <div style="font-family: Inter, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
              <h1>${context.title || 'Notification'}</h1>
              <p>${context.body || JSON.stringify(context)}</p>
            </div>
          `;
        }
    }

    private parseJson(value: any): any {
        if (typeof value === 'string') {
            try { return JSON.parse(value); } catch { return value; }
        }
        return value;
    }

    private getDefaultTemplateConfig(): NotificationTemplateConfig {
        return {
            headerImageUrl: '',
            introMessage: 'La Oficina de Ciberseguridad Corporativa informa de la publicación de nuevas Vulnerabilidades del Fabricante {{fabricante}} en los siguientes CVE con una estimación de Impacto CVSS superior a 7.5 sobre 10.\n\nSe recomienda proceder a la identificación de los activos afectados y ejecutar las correspondientes tareas de mitigación y actuación recomendadas por el fabricante.\n\nImportante: La lista de versiones afectadas que aparecen en este comunicado ha sido simplificada, por favor, consulte la lista Oficial del fabricante en los enlaces que aparecen en el apartado de referencias.',
            showExploitProbability: true,
            showExploitExists: true,
            showAffectedSoftware: true,
            showDescription: true,
            showReferences: true,
            showPatchLink: true,
        };
    }

    private renderConfiguredCveTemplate(context: any, cfg: NotificationTemplateConfig): string {
        const vuln = context?.vulnerability || {};
        const references = this.getNotificationReferences(vuln);
        const remediation = vuln.remediationInfo || {};
        const affectedProducts = Array.isArray(vuln.affectedProducts) ? vuln.affectedProducts : [];

        const fabricante = this.resolveManufacturer(vuln);
        const intro = (cfg.introMessage || '')
            .replace(/{{\s*fabricante\s*}}/gi, fabricante)
            .split('\n')
            .filter(Boolean)
            .map((line: string) => `<p style="margin:8px 0;color:#111827;font-size:16px;line-height:1.45;">${this.escapeHtml(line)}</p>`)
            .join('');

        const referencesHtml = references.length > 0
            ? `<ul style="margin:8px 0 0 22px;padding:0;">${references
                .slice(0, 8)
                .map((r: any) => `<li style="margin:2px 0;"><a href="${this.escapeHtml(r.url || '#')}" style="color:#2563EB;">${this.escapeHtml(r.url || 'Referencia')}</a></li>`)
                .join('')}</ul>`
            : '<p style="margin:8px 0;color:#6B7280;">Sin referencias.</p>';

        const affectedHtml = affectedProducts.length > 0
            ? `<ul style="margin:8px 0 0 22px;padding:0;">${affectedProducts
                .slice(0, 20)
                .map((p: any) => `<li style="margin:2px 0;">${this.escapeHtml(`${p.vendor || ''}/${p.product || ''}`)}</li>`)
                .join('')}</ul>`
            : '<p style="margin:8px 0;color:#6B7280;">Sin productos identificados.</p>';

        const patchLink = remediation?.patchUrls?.[0] || '';
        const publishedAt = vuln.publishedAt ? new Date(vuln.publishedAt).toLocaleString('es-ES') : 'N/D';
        const exploitProbability = vuln.epssScore != null ? `${(Number(vuln.epssScore) * 100).toFixed(2)}%` : 'N/D';
        const headerSrc = cfg.headerImageUrl
            ? (cfg.headerImageUrl.startsWith('data:image/') ? 'cid:occ-header-banner' : this.escapeHtml(cfg.headerImageUrl))
            : '';

        return `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#F3F4F6;font-family:Arial,sans-serif;color:#111827;">
  <div style="max-width:920px;margin:0 auto;padding:16px;">
    <div style="background:#fff;border:1px solid #D1D5DB;">
      ${headerSrc ? `<img src="${headerSrc}" alt="Cabecera" style="width:100%;display:block;" />` : ''}
      <div style="padding:18px 24px;">
        <h2 style="text-align:center;margin:4px 0 14px;font-size:40px;">Productos ${this.escapeHtml(fabricante)}</h2>
        ${intro}
      </div>

      <div style="padding:0 20px 20px;">
        <div style="border:1px solid #D1D5DB;background:#fff;">
          <div style="background:#6B7280;color:#fff;padding:8px 12px;font-size:28px;font-weight:700;">${this.escapeHtml(vuln.cveId || context.cveId || 'CVE')}</div>
          <table style="width:100%;border-collapse:collapse;">
            <tr>
              <td style="padding:10px 12px;border:1px solid #E5E7EB;font-weight:700;">CVSS: ${this.escapeHtml(String(vuln.cvssScore ?? context.cvssScore ?? 'N/D'))}</td>
              <td style="padding:10px 12px;border:1px solid #E5E7EB;background:#DC2626;color:#fff;font-weight:700;">Severidad: ${this.escapeHtml(String(vuln.severity ?? context.severity ?? 'N/D')).toLowerCase()}</td>
              <td style="padding:10px 12px;border:1px solid #E5E7EB;font-weight:700;">Publicado en: ${this.escapeHtml(publishedAt)}</td>
            </tr>
          </table>
          ${cfg.showExploitProbability ? `<div style="padding:10px 12px;border:1px solid #E5E7EB;text-align:right;"><span style="background:#D9E16B;padding:6px 10px;border-radius:6px;font-weight:700;">Probabilidad de Explotación: ${this.escapeHtml(exploitProbability)}</span></div>` : ''}
          ${cfg.showExploitExists ? `<div style="padding:10px 12px;border:1px solid #E5E7EB;"><strong>Existencia de exploit:</strong> ${vuln.hasPublicExploit ? 'Sí' : 'No'}</div>` : ''}
          ${cfg.showDescription ? `<div style="padding:12px;border:1px solid #E5E7EB;"><strong>Descripción:</strong><p style="margin:8px 0 0;">${this.escapeHtml(vuln.description || context.description || 'Sin descripción disponible')}</p></div>` : ''}
          ${cfg.showAffectedSoftware ? `<div style="padding:12px;border:1px solid #E5E7EB;"><strong>Productos Afectados:</strong>${affectedHtml}</div>` : ''}
          ${cfg.showReferences ? `<div style="padding:12px;border:1px solid #E5E7EB;"><strong>Referencias:</strong>${referencesHtml}</div>` : ''}
          ${cfg.showPatchLink ? `<div style="padding:12px;border:1px solid #E5E7EB;"><strong>Enlace del parche:</strong> ${patchLink ? `<a href="${this.escapeHtml(patchLink)}" style="color:#2563EB;">${this.escapeHtml(patchLink)}</a>` : 'No disponible'}</div>` : ''}
        </div>
      </div>
    </div>
  </div>
</body>
</html>`;
    }

    private async getInlineTemplateAttachments(templateName: string): Promise<any[]> {
        if (templateName !== 'cve-alert') return [];

        const cfg = await this.getTemplateConfig();
        const dataUrl = cfg.headerImageUrl || '';
        if (!dataUrl.startsWith('data:image/')) return [];

        const parsed = this.parseDataUrlImage(dataUrl);
        if (!parsed) return [];

        return [{
            filename: `occ-header.${parsed.ext}`,
            content: parsed.buffer,
            cid: 'occ-header-banner',
            contentType: parsed.mime,
        }];
    }

    private parseDataUrlImage(dataUrl: string): { mime: string; ext: string; buffer: Buffer } | null {
        const match = dataUrl.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/);
        if (!match) return null;

        const mime = match[1];
        const base64 = match[2];
        const ext = mime.split('/')[1]?.split('+')[0] || 'png';

        try {
            const buffer = Buffer.from(base64, 'base64');
            return { mime, ext, buffer };
        } catch {
            return null;
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

    private resolveManufacturer(vuln: any): string {
        const products = Array.isArray(vuln?.affectedProducts) ? vuln.affectedProducts : [];
        const vendors = [...new Set(
            products
                .map((p: any) => String(p?.vendor || '').trim())
                .filter((v: string) => v.length > 0),
        )];
        if (vendors.length === 0) return 'N/D';
        return vendors.slice(0, 3).join(', ');
    }

    private normalizeVulnerabilityData(vuln: any): any {
        const remediationInfo = this.parseJson(vuln.remediationInfo) || {};
        return {
            cveId: vuln.cveId,
            severity: vuln.cvssV31Severity || 'N/A',
            cvssScore: vuln.cvssV31Score ?? 'N/A',
            publishedAt: vuln.publishedAt,
            epssScore: vuln.epssScore,
            hasPublicExploit: !!vuln.hasPublicExploit,
            affectedProducts: this.parseJson(vuln.affectedProducts) || [],
            description: vuln.description || 'Sin descripción disponible',
            references: this.parseJson(vuln.references) || [],
            remediationInfo,
        };
    }

    private getNotificationReferences(vuln: any): Array<{ url: string; tags?: string[] }> {
        const parsedRefs = Array.isArray(vuln?.references) ? vuln.references : [];
        const remediation = vuln?.remediationInfo || {};
        const remediationRefs = Array.isArray(remediation?.allReferences) ? remediation.allReferences : [];

        const merged = [...parsedRefs, ...remediationRefs]
            .map((r: any) => ({
                url: String(r?.url || '').trim(),
                tags: Array.isArray(r?.tags) ? r.tags : [],
            }))
            .filter((r: any) => !!r.url);

        if (!merged.some((r) => r.url.includes('nvd.nist.gov')) && vuln?.cveId) {
            merged.push({ url: `https://nvd.nist.gov/vuln/detail/${vuln.cveId}`, tags: ['NVD'] });
        }

        const seen = new Set<string>();
        return merged.filter((r) => {
            if (seen.has(r.url)) return false;
            seen.add(r.url);
            return true;
        });
    }

    // ── Test methods for each notification level ──────────────────────

    /**
     * Level 1 test: Sends an instant notification with a recent CRITICAL/exploitable CVE.
     */
    async testInstantNotification(to: string, userId?: number) {
        if (!this.transporter) {
            await this.loadConfig();
            if (!this.transporter) throw new NotFoundException('SMTP not configured');
        }

        // Find a real critical CVE to use as sample
        const sample = await this.prisma.vulnerability.findFirst({
            where: {
                OR: [
                    { cvssV31Severity: 'CRITICAL' },
                    { isKnownExploited: true },
                ],
            },
            orderBy: { publishedAt: 'desc' },
        });

        if (!sample) throw new NotFoundException('No critical CVE found for test');

        const cfg = await this.getTemplateConfig();
        const html = await this.renderConfiguredCveTemplate(sample, cfg);

        const subject = `[TEST] Alerta Instantanea: ${sample.cveId} — ${sample.cvssV31Severity || 'CRITICAL'}`;
        const info = await this.transporter.sendMail({
            from: this.smtpConfig?.from || 'noreply@occ.local',
            to,
            subject,
            html,
        });

        await this.logNotification(to, 'Test Instant', subject, html, [sample.cveId]);
        return { success: true, messageId: info.messageId, cveId: sample.cveId, level: 'instant' };
    }

    /**
     * Level 2 test: Sends a periodic grouped notification with recent CVEs above threshold.
     */
    async testPeriodicNotification(to: string, userId?: number) {
        if (!this.transporter) {
            await this.loadConfig();
            if (!this.transporter) throw new NotFoundException('SMTP not configured');
        }

        const policy = userId
            ? await this.prisma.notificationPolicy.findUnique({ where: { userId } })
            : null;
        const threshold = policy?.periodicThresholdCvss ?? 7.0;

        // Get recent CVEs above threshold, grouped by vendor
        const samples = await this.prisma.vulnerability.findMany({
            where: {
                cvssV31Score: { gte: threshold },
                publishedAt: { gte: new Date(Date.now() - 7 * 86400000) },
            },
            orderBy: { cvssV31Score: 'desc' },
            take: 10,
        });

        if (samples.length === 0) throw new NotFoundException(`No CVEs with CVSS >= ${threshold} found in last 7 days`);

        // Group by vendor
        const byVendor: Record<string, any[]> = {};
        for (const v of samples) {
            const vendor = v.primaryVendor || 'Unknown';
            if (!byVendor[vendor]) byVendor[vendor] = [];
            byVendor[vendor].push(v);
        }

        // Use the first vendor group to send a sample grouped email
        const [vendor, vulns] = Object.entries(byVendor)[0];
        const mapped = vulns.map((v) => ({
            cveId: v.cveId,
            severity: v.cvssV31Severity || 'MEDIUM',
            cvssScore: v.cvssV31Score,
            epssScore: v.epssScore,
            hasPublicExploit: v.hasPublicExploit || false,
            description: v.description || '',
            affectedProducts: this.parseJsonField(v.affectedProducts),
            references: this.parseJsonField(v.references),
            remediationInfo: this.parseJsonField(v.remediationInfo),
            publishedAt: v.publishedAt,
        }));

        await this.sendGroupedCveEmail(to, 'Test User', vendor, mapped);
        return {
            success: true,
            level: 'periodic',
            vendor,
            cveCount: mapped.length,
            threshold,
        };
    }

    /**
     * Level 3 test: Sends a smart/AI notification wrapped with ordinary branding.
     */
    async testSmartNotification(to: string, userId?: number) {
        if (!this.transporter) {
            await this.loadConfig();
            if (!this.transporter) throw new NotFoundException('SMTP not configured');
        }

        // Build a sample smart notification HTML
        const cfg = await this.getTemplateConfig();
        const headerSrc = cfg.headerImageUrl
            ? (cfg.headerImageUrl.startsWith('data:image/') ? 'cid:occ-header-banner' : this.escapeHtml(cfg.headerImageUrl))
            : '';

        const smartBody = `
            <div style="padding:16px 24px;">
                <h2 style="color:#1B2A4A;font-size:18px;margin:0 0 12px;">Informe Inteligente Semanal (TEST)</h2>
                <p style="color:#4A5568;font-size:14px;line-height:1.6;">
                    Este es un email de prueba del nivel 3 — Notificaciones Inteligentes.
                    En produccion, este contenido sera generado por IA con analisis de correlacion,
                    cadenas de explotacion y recomendaciones priorizadas.
                </p>
                <div style="background:#EFF6FF;border-left:4px solid #3B82F6;padding:12px 16px;border-radius:4px;margin:16px 0;">
                    <strong style="color:#1E40AF;">Resumen ejecutivo</strong>
                    <p style="color:#4A5568;font-size:13px;margin:6px 0 0;">
                        Se han detectado vulnerabilidades con potencial de encadenamiento
                        en los productos suscritos. Se recomienda priorizar la mitigacion
                        segun el plan detallado en el informe completo.
                    </p>
                </div>
                <div style="background:#FEF3C7;border-left:4px solid #D97706;padding:12px 16px;border-radius:4px;margin:16px 0;">
                    <strong style="color:#92400E;">Top 3 Riesgos</strong>
                    <ol style="color:#4A5568;font-size:13px;margin:8px 0 0;padding-left:20px;">
                        <li>Cadena de explotacion RCE + escalada de privilegios en software critico</li>
                        <li>Vulnerabilidad activamente explotada sin parche disponible</li>
                        <li>Multiples CVEs en el mismo componente con exploit publico</li>
                    </ol>
                </div>
            </div>`;

        const html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#F3F4F6;font-family:Arial,sans-serif;color:#111827;">
  <div style="max-width:920px;margin:0 auto;padding:16px;">
    <div style="background:#fff;border:1px solid #D1D5DB;">
      ${headerSrc ? `<img src="${headerSrc}" alt="Cabecera" style="width:100%;display:block;" />` : ''}
      ${smartBody}
    </div>
    <p style="color:#9CA3AF;font-size:11px;text-align:center;margin:16px 0 0;">
      Este mensaje ha sido generado automaticamente por el sistema de Gestion de Vulnerabilidades OCC.<br>
      No respondas a este correo.
    </p>
  </div>
</body>
</html>`;

        const attachments = await this.getInlineTemplateAttachments('cve-alert');
        const subject = '[TEST] Informe Inteligente Semanal — OCC-TVM';
        const info = await this.transporter.sendMail({
            from: this.smtpConfig?.from || 'noreply@occ.local',
            to,
            subject,
            html,
            attachments,
        });

        await this.logNotification(to, 'Test Smart', subject, html);
        return { success: true, messageId: info.messageId, level: 'smart' };
    }

    private parseJsonField(value: any): any {
        if (!value) return [];
        if (typeof value === 'object') return value;
        try { return JSON.parse(value); } catch { return []; }
    }

    // ── Notificable evaluation ─────────────────────────────────────

    private static readonly SEVERITY_ORDER: Record<string, number> = {
        NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4,
    };

    private vulnMeetsLevelCriteria(
        vuln: { cvssV31Score?: number | null; cvssV31Severity?: string | null; epssScore?: number | null; epssPercentile?: number | null; isKnownExploited?: boolean; hasPublicExploit?: boolean; exploitStatus?: string | null; patchAvailable?: boolean | null; dataConfidence?: number | null; sourceCount?: number; primaryVendor?: string | null; primaryProduct?: string | null; weaknessCategory?: string | null },
        level: { enabled: boolean; minSeverity: string; minCvss: number; minEpss: number; minConfidence: number; minSources: number; kevOnly?: boolean; publicExploitOnly?: boolean; activeExploitationOnly?: boolean; patchUnconfirmedOnly?: boolean; vendorFilters: string[]; productFilters: string[]; categoryFilters: string[]; exclusions: string[] },
    ): boolean {
        if (!level.enabled) return false;

        const vulnSev = String(vuln.cvssV31Severity || 'NONE').toUpperCase();
        const minSev = String(level.minSeverity || 'NONE').toUpperCase();
        if ((NotificationService.SEVERITY_ORDER[vulnSev] ?? 0) < (NotificationService.SEVERITY_ORDER[minSev] ?? 0)) return false;

        if (level.minCvss > 0 && (vuln.cvssV31Score ?? 0) < level.minCvss) return false;
        if (level.minEpss > 0 && (vuln.epssScore ?? 0) < level.minEpss) return false;
        if (level.minConfidence > 0 && (vuln.dataConfidence ?? 0) < level.minConfidence) return false;
        if (level.minSources > 1 && (vuln.sourceCount ?? 1) < level.minSources) return false;

        if (level.kevOnly && !vuln.isKnownExploited) return false;
        if (level.publicExploitOnly && !vuln.hasPublicExploit) return false;
        if (level.activeExploitationOnly && vuln.exploitStatus !== 'active') return false;
        if (level.patchUnconfirmedOnly && vuln.patchAvailable === true) return false;

        const vendor = String(vuln.primaryVendor || '').toLowerCase();
        const product = String(vuln.primaryProduct || '').toLowerCase();
        const category = String(vuln.weaknessCategory || '').toLowerCase();

        if (level.vendorFilters.length > 0 && vendor && !level.vendorFilters.some((f) => vendor.includes(f.toLowerCase()))) return false;
        if (level.productFilters.length > 0 && product && !level.productFilters.some((f) => product.includes(f.toLowerCase()))) return false;
        if (level.categoryFilters.length > 0 && category && !level.categoryFilters.some((f) => category.includes(f.toLowerCase()))) return false;
        if (level.exclusions.length > 0) {
            const combined = `${vendor} ${product} ${vuln.cvssV31Severity || ''}`.toLowerCase();
            if (level.exclusions.some((ex) => combined.includes(ex.toLowerCase()))) return false;
        }

        return true;
    }

    /**
     * Evaluate whether a vulnerability meets the notification criteria
     * from the notification center config (immediate OR digest levels).
     */
    async evaluateIsNotificable(vuln: {
        cvssV31Score?: number | null; cvssV31Severity?: string | null;
        epssScore?: number | null; epssPercentile?: number | null;
        isKnownExploited?: boolean; hasPublicExploit?: boolean;
        exploitStatus?: string | null; patchAvailable?: boolean | null;
        dataConfidence?: number | null; sourceCount?: number;
        primaryVendor?: string | null; primaryProduct?: string | null;
        weaknessCategory?: string | null;
    }): Promise<boolean> {
        const config = await this.getNotificationCenterSettingsRaw();
        if (!config.general.processEnabled) return false;

        return this.vulnMeetsLevelCriteria(vuln, config.immediate) ||
               this.vulnMeetsLevelCriteria(vuln, config.digest);
    }

    /**
     * Recalculate isNotificable for all vulnerabilities based on current config.
     * Uses two-pass updateMany for efficiency.
     */
    async recalculateAllNotificable(): Promise<{ markedTrue: number; markedFalse: number }> {
        const config = await this.getNotificationCenterSettingsRaw();

        if (!config.general.processEnabled) {
            const result = await this.prisma.vulnerability.updateMany({
                where: { isNotificable: true },
                data: { isNotificable: false },
            });
            return { markedTrue: 0, markedFalse: result.count };
        }

        // Build OR conditions for immediate and digest levels
        const buildWhereForLevel = (level: typeof config.immediate | typeof config.digest): any | null => {
            if (!level.enabled) return null;
            const where: any = {};

            const minSev = String(level.minSeverity || 'NONE').toUpperCase();
            const sevOrder = NotificationService.SEVERITY_ORDER[minSev] ?? 0;
            if (sevOrder > 0) {
                const allowedSevs = Object.entries(NotificationService.SEVERITY_ORDER)
                    .filter(([, v]) => v >= sevOrder)
                    .map(([k]) => k);
                where.cvssV31Severity = { in: allowedSevs };
            }

            if (level.minCvss > 0) where.cvssV31Score = { gte: level.minCvss };
            if (level.minEpss > 0) where.epssScore = { gte: level.minEpss };
            if (level.minConfidence > 0) where.dataConfidence = { gte: level.minConfidence };
            if (level.minSources > 1) where.sourceCount = { gte: level.minSources };

            if ('kevOnly' in level && level.kevOnly) where.isKnownExploited = true;
            if ('publicExploitOnly' in level && level.publicExploitOnly) where.hasPublicExploit = true;
            if ('activeExploitationOnly' in level && level.activeExploitationOnly) where.exploitStatus = 'active';
            if ('patchUnconfirmedOnly' in level && level.patchUnconfirmedOnly) where.patchAvailable = { not: true };

            if (level.vendorFilters.length > 0) {
                where.OR = [
                    ...(where.OR || []),
                    ...level.vendorFilters.map((v) => ({ primaryVendor: { contains: v.toLowerCase() } })),
                ];
            }

            return where;
        };

        const immediateWhere = buildWhereForLevel(config.immediate);
        const digestWhere = buildWhereForLevel(config.digest);

        const orConditions: any[] = [];
        if (immediateWhere) orConditions.push(immediateWhere);
        if (digestWhere) orConditions.push(digestWhere);

        if (orConditions.length === 0) {
            const result = await this.prisma.vulnerability.updateMany({
                where: { isNotificable: true },
                data: { isNotificable: false },
            });
            return { markedTrue: 0, markedFalse: result.count };
        }

        const matchWhere = orConditions.length === 1 ? orConditions[0] : { OR: orConditions };

        // Pass 1: mark matching as true
        const trueResult = await this.prisma.vulnerability.updateMany({
            where: { ...matchWhere, isNotificable: false },
            data: { isNotificable: true },
        });

        // Pass 2: mark non-matching as false
        const falseResult = await this.prisma.vulnerability.updateMany({
            where: { NOT: matchWhere, isNotificable: true },
            data: { isNotificable: false },
        });

        this.logger.log(`Recalculated isNotificable: ${trueResult.count} marked true, ${falseResult.count} marked false`);
        return { markedTrue: trueResult.count, markedFalse: falseResult.count };
    }
}
