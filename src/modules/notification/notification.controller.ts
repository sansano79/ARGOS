import { Controller, Get, Post, Put, Body, Query, Param, UseGuards, ParseIntPipe } from '@nestjs/common';
import { NotificationService } from './notification.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../auth/decorators/roles.decorator';

@Controller('notifications')
@UseGuards(JwtAuthGuard, RolesGuard)
export class NotificationController {
    constructor(private readonly notificationService: NotificationService) { }

    @Get('config')
    @Roles('ADMIN')
    async getConfig() {
        return await this.notificationService.getConfig();
    }

    @Post('config')
    @Roles('ADMIN')
    async saveConfig(@Body() config: any) {
        return await this.notificationService.saveConfig(config);
    }

    @Post('test')
    @Roles('ADMIN')
    async sendTestEmail(@Body('email') email: string) {
        return await this.notificationService.sendTestEmail(email);
    }

    @Get('history')
    @Roles('ADMIN')
    async getHistory(
        @Query('page') page?: string,
        @Query('limit') limit?: string,
    ) {
        return await this.notificationService.getHistory(
            parseInt(page || '1'),
            parseInt(limit || '20'),
        );
    }

    @Get('history/:id')
    @Roles('ADMIN')
    async getNotificationDetail(@Param('id', ParseIntPipe) id: number) {
        return await this.notificationService.getNotificationById(id);
    }

    @Post('history/:id/resend')
    @Roles('ADMIN')
    async resendNotification(@Param('id', ParseIntPipe) id: number) {
        return await this.notificationService.resendNotification(id);
    }

    @Get('settings-center')
    @Roles('ADMIN')
    async getNotificationCenterSettings() {
        return await this.notificationService.getNotificationCenterSettings();
    }

    @Post('settings-center')
    @Roles('ADMIN')
    async saveNotificationCenterSettings(@Body() body: any) {
        return await this.notificationService.saveNotificationCenterSettings(body || {});
    }

    @Get('process-health')
    @Roles('ADMIN')
    async getProcessHealth() {
        return await this.notificationService.getNotificationProcessHealth();
    }

    @Post('process/run-now')
    @Roles('ADMIN')
    async runProcessNow(@Body() body: { jobType?: string }) {
        const jobType = String(body?.jobType || '').trim();
        if (jobType === 'digest_notification_job') {
            return await this.notificationService.runDigestNotificationJob('manual');
        }
        if (jobType === 'immediate_notification_job') {
            return {
                success: true,
                mode: 'hook',
                message: 'La notificación inmediata se ejecuta tras la recolección; usa "Probar" para validar la plantilla y el canal.',
            };
        }
        return {
            success: false,
            message: 'Usa el proceso inteligente desde sus endpoints dedicados.',
        };
    }

    @Get('templates')
    @Roles('ADMIN')
    async getTemplates() {
        return await this.notificationService.getAvailableTemplates();
    }

    @Get('template-config')
    @Roles('ADMIN')
    async getTemplateConfig(): Promise<any> {
        return await this.notificationService.getTemplateConfig();
    }

    @Get('template-configs')
    @Roles('ADMIN')
    async listTemplateConfigs(): Promise<any> {
        return await this.notificationService.listTemplateConfigs();
    }

    @Get('template-config/:id')
    @Roles('ADMIN')
    async getTemplateConfigById(@Param('id', ParseIntPipe) id: number): Promise<any> {
        return await this.notificationService.getTemplateConfigById(id);
    }

    @Post('template-config')
    @Roles('ADMIN')
    async saveTemplateConfig(@Body() config: any): Promise<any> {
        return await this.notificationService.saveTemplateConfig(config);
    }

    @Post('template-config/:id/activate')
    @Roles('ADMIN')
    async activateTemplateConfig(@Param('id', ParseIntPipe) id: number): Promise<any> {
        return await this.notificationService.activateTemplateConfig(id);
    }

    @Post('template-preview')
    @Roles('ADMIN')
    async getTemplatePreview(
        @Body() body: { vulnerabilityId: number; config?: any },
    ): Promise<any> {
        return await this.notificationService.getTemplatePreview(
            Number(body?.vulnerabilityId),
            body?.config || {},
        );
    }

    // ── Notification Policy endpoints ────────────────────────────────

    @Get('policy/:userId')
    @Roles('ADMIN')
    async getNotificationPolicy(@Param('userId', ParseIntPipe) userId: number) {
        return await this.notificationService.getNotificationPolicy(userId);
    }

    @Put('policy/:userId')
    @Roles('ADMIN')
    async upsertNotificationPolicy(
        @Param('userId', ParseIntPipe) userId: number,
        @Body() body: {
            immediateForCritical?: boolean;
            immediateForExploitable?: boolean;
            minCvssForImmediate?: number;
            periodicEnabled?: boolean;
            periodicThresholdCvss?: number;
            periodicIntervalHours?: number;
            smartEnabled?: boolean;
            smartFrequency?: string;
            smartDayOfWeek?: number;
            smartHour?: number;
            digestFrequency?: string;
            digestHour?: number;
            digestDayOfWeek?: number;
            isActive?: boolean;
        },
    ) {
        return await this.notificationService.upsertNotificationPolicy(userId, body);
    }

    @Get('policies')
    @Roles('ADMIN')
    async getAllNotificationPolicies() {
        return await this.notificationService.getAllNotificationPolicies();
    }

    // ── Test endpoints for each notification level ─────────────────

    @Post('test-instant')
    @Roles('ADMIN')
    async testInstantNotification(@Body() body: { email: string; userId?: number }) {
        return await this.notificationService.testInstantNotification(body.email, body.userId);
    }

    @Post('test-periodic')
    @Roles('ADMIN')
    async testPeriodicNotification(@Body() body: { email: string; userId?: number }) {
        return await this.notificationService.testPeriodicNotification(body.email, body.userId);
    }

    @Post('test-smart')
    @Roles('ADMIN')
    async testSmartNotification(@Body() body: { email: string; userId?: number }) {
        return await this.notificationService.testSmartNotification(body.email, body.userId);
    }

    @Post('recalculate-notificable')
    @Roles('ADMIN')
    async recalculateNotificable() {
        return await this.notificationService.recalculateAllNotificable();
    }
}
