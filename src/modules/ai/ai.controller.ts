import { Controller, Post, Body, UseGuards, Get, Query } from '@nestjs/common';
import { AiService } from './ai.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../auth/decorators/roles.decorator';

@Controller('ai')
@UseGuards(JwtAuthGuard)
export class AiController {
    constructor(private readonly aiService: AiService) { }

    @Post('chat')
    async chat(@Body('messages') messages: any[]) {
        return await this.aiService.chat(messages);
    }

    @Get('config')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('ADMIN')
    async getConfig() {
        return this.aiService.getConfig();
    }

    @Post('config')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('ADMIN')
    async saveConfig(@Body() body: any) {
        return this.aiService.saveConfig(body || {});
    }

    @Get('models')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('ADMIN')
    async listModels() {
        return this.aiService.listOllamaModels();
    }

    @Post('test')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('ADMIN')
    async testConnection(@Body() body: any) {
        return this.aiService.testConnection(body || {});
    }

    @Get('context')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('ADMIN')
    async getContextAudit(@Query('q') q?: string) {
        return this.aiService.getVulnerabilityContextAudit(String(q || ''));
    }
}
