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
                    pass: config.apiKeyEncrypted || '', // We use this field for password
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
                    apiKeyEncrypted: config.pass, // Storing password here for simplicity as encrypted field
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
            // Do not return password
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
            const info = await this.transporter.sendMail({
                from: this.smtpConfig?.from || 'noreply@occ.local',
                to,
                subject: 'Test Email from OCC Vulnerability Collector',
                text: 'This is a test email to verify your SMTP settings.',
                html: '<b>This is a test email</b> to verify your SMTP settings.',
            });
            this.logger.log(`Test email sent: ${info.messageId}`);
            return { success: true, messageId: info.messageId };
        } catch (error) {
            this.logger.error('Failed to send test email', error);
            throw new InternalServerErrorException('Failed to send email: ' + error.message);
        }
    }

    async sendEmail(to: string, subject: string, templateName: string, context: any) {
        if (!this.transporter) {
            // Try to reload config just in case
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
            this.logger.log(`Email sent to ${to}: ${info.messageId}`);
            return true;
        } catch (error) {
            this.logger.error(`Failed to send email to ${to}`, error);
            return false;
        }
    }

    private async loadTemplate(templateName: string, context: any): Promise<string> {
        const templatePath = path.join(process.cwd(), 'src', 'templates', `${templateName}.html`);

        try {
            let content = fs.readFileSync(templatePath, 'utf-8');
            // Simple template engine: replace {{ key }} with value
            for (const key in context) {
                const regex = new RegExp(`{{ ${key} }}`, 'g');
                content = content.replace(regex, context[key]);
                // Also try without spaces
                const regexNoSpace = new RegExp(`{{${key}}}`, 'g');
                content = content.replace(regexNoSpace, context[key]);
            }
            return content;
        } catch (error) {
            this.logger.error(`Template not found or error reading: ${templateName}`, error);
            // Fallback to basic HTML if template fails
            return `
            <h1>${context.title || 'Notification'}</h1>
            <p>${JSON.stringify(context)}</p>
          `;
        }
    }
}
