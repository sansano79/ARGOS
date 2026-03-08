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

@Injectable()
export class NotificationService {
    private readonly logger = new Logger(NotificationService.name);
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
                '<h1 style="margin: 0; font-size: 20px;">🛡️ Servicios OCC</h1>' +
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
                subject: '✅ Test Email — Servicios OCC',
                html,
            });

            // Log the test email
            await this.logNotification(to, 'Test', '✅ Test Email — Servicios OCC', html);

            this.logger.log(`Test email sent: ${info.messageId}`);
            return { success: true, messageId: info.messageId };
        } catch (error) {
            this.logger.error('Failed to send test email', error);
            throw new InternalServerErrorException('Failed to send email: ' + error.message);
        }
    }

    async sendEmail(to: string, subject: string, templateName: string, context: any) {
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
                context.cveIds || [],
            );

            this.logger.log(`Email sent to ${to}: ${info.messageId}`);
            return true;
        } catch (error) {
            this.logger.error(`Failed to send email to ${to}`, error);
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
            await this.logNotification(to, recipientName, subject, html, allCveIds);

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
    @Cron('0 0 8 * * *')
    async sendScheduledDigests() {
        this.logger.log('Digest cron: starting daily digest processing');

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

            if (pendingGrouped.length === 0) {
                this.logger.log('Digest cron: no pending digest notifications');
                return;
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

            let emailsSent = 0;
            let totalProcessed = 0;
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
        } catch (error) {
            this.logger.error('Digest cron failed', error);
        }
    }

    private async logNotification(
        recipientEmail: string,
        recipientName: string,
        subject: string,
        htmlContent: string,
        cveIds: string[] = [],
    ) {
        try {
            await this.prisma.notificationLog.create({
                data: {
                    recipientEmail,
                    recipientName,
                    subject,
                    htmlContent,
                    cveIds: JSON.stringify(cveIds),
                },
            });
        } catch (error) {
            this.logger.error('Failed to log notification', error);
        }
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
                    cveIds: true,
                    status: true,
                    sentAt: true,
                },
            }),
            this.prisma.notificationLog.count(),
        ]);

        return {
            data: data.map(d => ({
                ...d,
                cveIds: this.parseJson(d.cveIds),
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
            cveIds: this.parseJson(notification.cveIds),
        };
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
}
