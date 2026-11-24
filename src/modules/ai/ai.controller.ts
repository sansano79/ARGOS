import { BadRequestException, Controller, Post, Body, UseGuards, Get, Query } from '@nestjs/common';
import { UserThrottlerGuard } from '../../common/guards/user-throttler.guard';
import { AiService } from './ai.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../auth/decorators/roles.decorator';

@Controller('ai')
@UseGuards(JwtAuthGuard)
export class AiController {
    constructor(private readonly aiService: AiService) { }

    @Post('chat')
    @UseGuards(JwtAuthGuard, UserThrottlerGuard)
    async chat(@Body('messages') messages: any[]) {
        return await this.aiService.chat(sanitizeChatMessages(messages));
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

const MAX_CHAT_MESSAGES = 100;
const MAX_CHAT_MESSAGE_LENGTH = 8000;
const ALLOWED_CHAT_ROLES = new Set(['user', 'assistant']);

/**
 * Turnos de texto user/assistant; se admite un único mensaje `system` en la
 * primera posición (contexto de pantalla que envía el frontend).
 */
export function sanitizeChatMessages(messages: unknown): Array<{ role: string; content: string }> {
    if (!Array.isArray(messages) || messages.length === 0 || messages.length > MAX_CHAT_MESSAGES) {
        throw new BadRequestException(`messages must be an array of 1-${MAX_CHAT_MESSAGES} items`);
    }
    return messages.map((m: any, index: number) => {
        const role = String(m?.role || '');
        const content = m?.content;
        const roleAllowed = ALLOWED_CHAT_ROLES.has(role) || (role === 'system' && index === 0);
        if (!roleAllowed || typeof content !== 'string' || content.length > MAX_CHAT_MESSAGE_LENGTH) {
            throw new BadRequestException('Invalid chat message');
        }
        return { role, content };
    });
}
