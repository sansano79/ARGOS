import { Injectable, Logger, InternalServerErrorException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import { lastValueFrom } from 'rxjs';

interface AiConfig {
    provider: 'openai' | 'ollama';
    apiKey?: string;
    baseUrl?: string;
    model: string;
}

@Injectable()
export class AiService {
    private readonly logger = new Logger(AiService.name);
    private config: AiConfig | null = null;

    constructor(
        private prisma: PrismaService,
        private configService: ConfigService,
        private httpService: HttpService,
    ) { }

    async onModuleInit() {
        await this.loadConfig();
    }

    async loadConfig() {
        const dbConfig = await this.prisma.apiConfiguration.findFirst({
            where: { provider: 'ai_provider', isActive: true },
        });

        if (dbConfig) {
            const settings = JSON.parse(dbConfig.settings);
            this.config = {
                provider: settings.provider,
                baseUrl: settings.baseUrl,
                model: settings.model,
                apiKey: dbConfig.apiKeyEncrypted || undefined,
            };
        } else {
            // Default to env if no DB config
            const ollamaUrl = this.configService.get('OLLAMA_BASE_URL');
            if (ollamaUrl) {
                this.config = {
                    provider: 'ollama',
                    baseUrl: ollamaUrl,
                    model: this.configService.get('OLLAMA_MODEL') || 'llama3',
                };
            }
        }
    }

    async chat(messages: any[]) {
        if (!this.config) {
            await this.loadConfig();
            if (!this.config) throw new InternalServerErrorException('AI settings not configured');
        }

        const config = this.config; // Local variable for type safety

        try {
            if (config.provider === 'openai') {
                return await this.chatOpenAI(messages, config);
            } else {
                return await this.chatOllama(messages, config);
            }
        } catch (error) {
            this.logger.error('Error in AI chat', error);
            throw new InternalServerErrorException('AI request failed: ' + error.message);
        }
    }

    private async chatOpenAI(messages: any[], config: AiConfig) {
        const url = 'https://api.openai.com/v1/chat/completions';
        const payload = {
            model: config.model,
            messages,
        };
        const headers = {
            Authorization: `Bearer ${config.apiKey}`,
            'Content-Type': 'application/json',
        };

        const response = await lastValueFrom(this.httpService.post(url, payload, { headers }));
        return response.data.choices[0].message;
    }

    private async chatOllama(messages: any[], config: AiConfig) {
        const baseUrl = config.baseUrl || 'http://localhost:11434';
        const url = `${baseUrl}/api/chat`;
        const payload = {
            model: config.model,
            messages,
            stream: false
        };

        const response = await lastValueFrom(this.httpService.post(url, payload));
        return response.data.message;
    }
}
