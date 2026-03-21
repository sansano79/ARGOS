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
            digestFrequency?: string;
            digestHour?: number;
            digestDayOfWeek?: number;
            minCvssForImmediate?: number;
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
}
