import { Controller, Get, Post, Body, UseGuards, Param } from '@nestjs/common';
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
}
