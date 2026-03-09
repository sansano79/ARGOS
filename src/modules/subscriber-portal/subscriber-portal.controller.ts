import {
    Controller, Get, Put, Post, Delete,
    Body, Param, Request, UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../auth/decorators/roles.decorator';
import { SubscriberPortalService } from './subscriber-portal.service';

@Controller('subscriber-portal')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('SUBSCRIBER', 'ADMIN')
export class SubscriberPortalController {
    constructor(private readonly service: SubscriberPortalService) {}

    @Get('profile')
    async getProfile(@Request() req: any) {
        return this.service.getProfile(req.user.id);
    }

    @Put('subscriptions')
    async updateSubscriptions(
        @Request() req: any,
        @Body() body: { subscriptions: Array<{ vendor: string; product: string; versions?: string[] }> },
    ) {
        return this.service.updateSubscriptions(req.user.id, body?.subscriptions || []);
    }

    @Get('subscription-catalog')
    async getSubscriptionCatalog() {
        return this.service.getSubscriptionCatalog();
    }

    @Get('notifications')
    async getNotifications(@Request() req: any) {
        return this.service.getNotifications(req.user.id);
    }

    @Get('vulnerabilities')
    async getVulnerabilities(@Request() req: any) {
        return this.service.getVulnerabilities(req.user.id);
    }

    @Post('vulnerabilities/:cveId/patched')
    async markAsPatched(
        @Request() req: any,
        @Param('cveId') cveId: string,
        @Body() body: { notes?: string },
    ) {
        return this.service.markAsPatched(req.user.id, cveId, body?.notes);
    }

    @Delete('vulnerabilities/:cveId/patched')
    async unmarkAsPatched(
        @Request() req: any,
        @Param('cveId') cveId: string,
    ) {
        return this.service.unmarkAsPatched(req.user.id, cveId);
    }
}
