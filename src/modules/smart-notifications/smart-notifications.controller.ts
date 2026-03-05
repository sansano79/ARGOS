import { Body, Controller, Get, Param, ParseIntPipe, Post, Query, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../auth/decorators/roles.decorator';
import { SmartNotificationsService } from './smart-notifications.service';

@Controller('smart-notifications')
@UseGuards(JwtAuthGuard, RolesGuard)
export class SmartNotificationsController {
    constructor(private readonly smartNotificationsService: SmartNotificationsService) { }

    @Get('candidates')
    @Roles('ADMIN')
    async getCandidates(
        @Query('page') page?: string,
        @Query('limit') limit?: string,
        @Query('minScore') minScore?: string,
        @Query('daysWithoutNotify') daysWithoutNotify?: string,
    ) {
        return this.smartNotificationsService.getCandidates(
            parseInt(page || '1', 10),
            parseInt(limit || '20', 10),
            parseFloat(minScore || '7'),
            parseInt(daysWithoutNotify || '7', 10),
        );
    }

    @Post('summary')
    @Roles('ADMIN')
    async getSummary(@Body() body: { vulnerabilityIds: number[] }) {
        return this.smartNotificationsService.buildSummary(body?.vulnerabilityIds || []);
    }

    @Post('weekly/run-all')
    @Roles('ADMIN')
    async runWeeklyAll() {
        return this.smartNotificationsService.runWeeklyForAllSubscribers('manual');
    }

    @Post('weekly/run/:subscriberId')
    @Roles('ADMIN')
    async runWeeklySubscriber(
        @Param('subscriberId', ParseIntPipe) subscriberId: number,
    ) {
        return this.smartNotificationsService.runWeeklyForSubscriber(subscriberId, { trigger: 'manual' });
    }

    @Post('weekly/preview/:subscriberId')
    @Roles('ADMIN')
    async previewWeeklySubscriber(
        @Param('subscriberId', ParseIntPipe) subscriberId: number,
    ) {
        return this.smartNotificationsService.previewWeeklyForSubscriber(subscriberId);
    }

    @Post('weekly/test/:subscriberId')
    @Roles('ADMIN')
    async testWeeklySubscriber(
        @Param('subscriberId', ParseIntPipe) subscriberId: number,
    ) {
        return this.smartNotificationsService.testWeeklyForSubscriber(subscriberId);
    }

    @Get('weekly/history')
    @Roles('ADMIN')
    async getWeeklyHistory(
        @Query('page') page?: string,
        @Query('limit') limit?: string,
        @Query('subscriberId') subscriberId?: string,
    ) {
        const parsedSubscriberId = subscriberId ? parseInt(subscriberId, 10) : undefined;
        return this.smartNotificationsService.getWeeklyHistory(
            parseInt(page || '1', 10),
            parseInt(limit || '20', 10),
            Number.isInteger(parsedSubscriberId) ? parsedSubscriberId : undefined,
        );
    }

    @Get('config')
    @Roles('ADMIN')
    async getConfig() {
        return this.smartNotificationsService.getSmartConfig();
    }

    @Post('config')
    @Roles('ADMIN')
    async saveConfig(@Body() body: any) {
        return this.smartNotificationsService.saveSmartConfig(body || {});
    }

    @Post('config/import')
    @Roles('ADMIN')
    async importConfigProfile(
        @Body() body: { content?: string; profile?: any; format?: 'yaml' | 'json' },
    ) {
        return this.smartNotificationsService.importSmartConfigProfile(body || {});
    }

    @Get('config/export')
    @Roles('ADMIN')
    async exportConfigProfile(
        @Query('format') format?: string,
    ) {
        const normalized = format === 'json' ? 'json' : 'yaml';
        return this.smartNotificationsService.exportSmartConfigProfile(normalized);
    }

    @Get('defender/actions/catalog')
    @Roles('ADMIN')
    async getDefenderActionCatalog() {
        return {
            items: this.smartNotificationsService.getDefenderActionCatalog(),
        };
    }

    @Post('defender/actions/plan')
    @Roles('ADMIN')
    async planDefenderAction(
        @Body() body: {
            subscriberId: number;
            actionId: string;
            systemExternalIds: string[];
            notes?: string;
            requestedBy?: string;
        },
    ) {
        return this.smartNotificationsService.planDefenderAction(
            Number(body?.subscriberId),
            String(body?.actionId || ''),
            Array.isArray(body?.systemExternalIds) ? body.systemExternalIds : [],
            body?.notes,
            body?.requestedBy,
        );
    }

    @Get('subscribers/:subscriberId/systems')
    @Roles('ADMIN')
    async getSubscriberOwnedSystems(
        @Param('subscriberId', ParseIntPipe) subscriberId: number,
    ) {
        return this.smartNotificationsService.getSubscriberOwnedSystems(subscriberId);
    }

    @Post('subscribers/:subscriberId/systems/select')
    @Roles('ADMIN')
    async saveSubscriberOwnedSystemsSelection(
        @Param('subscriberId', ParseIntPipe) subscriberId: number,
        @Body() body: { systems: any[] },
    ) {
        return this.smartNotificationsService.saveSubscriberOwnedSystemsSelection(
            subscriberId,
            Array.isArray(body?.systems) ? body.systems : [],
        );
    }

    @Post('subscribers/:subscriberId/systems/sync-defender')
    @Roles('ADMIN')
    async syncSubscriberSystemsFromDefender(
        @Param('subscriberId', ParseIntPipe) subscriberId: number,
        @Body() body: { systems?: any[]; markMissingAsInactive?: boolean },
    ) {
        return this.smartNotificationsService.syncSubscriberSystemsFromDefender(subscriberId, {
            systems: Array.isArray(body?.systems) ? body.systems : [],
            markMissingAsInactive: body?.markMissingAsInactive,
        });
    }
}
