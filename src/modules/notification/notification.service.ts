import { Injectable, Logger, InternalServerErrorException, NotFoundException } from '@nestjs/common';
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
                const settings = JSON.parse(config.settings);
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

        const settings = JSON.stringify({
            host: config.host,
            port: config.port,
            user: config.user,
            secure: config.secure,
            from: config.from,
        });

        if (existingConfig) {
            await this.prisma.apiConfiguration.update({
                where: { id: existingConfig.id },
                data: {
                    settings,
                    apiKeyEncrypted: config.pass,
                    isActive: true,
                    name: 'SMTP Configuration',
                },
            });
        } else {
            await this.prisma.apiConfiguration.create({
                data: {
                    name: 'SMTP Configuration',
                    slug: 'smtp-config',
                    provider: 'smtp',
                    settings,
                    apiKeyEncrypted: config.pass,
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

        const settings = JSON.parse(config.settings);
        return {
            host: settings.host,
            port: settings.port,
            user: settings.user,
            secure: settings.secure,
            from: settings.from,
        };
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
            const info = await this.transporter.sendMail({
                from: this.smtpConfig?.from,
                to,
                subject,
                html,
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

    private async loadTemplate(templateName: string, context: any): Promise<string> {
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
}
