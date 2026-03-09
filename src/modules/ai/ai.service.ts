import { Injectable, Logger, InternalServerErrorException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import { lastValueFrom, timeout, catchError } from 'rxjs';
import { TimeoutError } from 'rxjs';

interface AiConfig {
    provider: 'openai' | 'ollama';
    apiKey?: string;
    baseUrl?: string;
    model: string;
}

export interface AiConfigResponse {
    provider: 'openai' | 'ollama';
    baseUrl?: string;
    model: string;
    source: 'db' | 'env';
}

@Injectable()
export class AiService {
    private readonly logger = new Logger(AiService.name);
    private config: AiConfig | null = null;
    private static readonly DEFAULT_OLLAMA_MODEL = 'krith/qwen2.5-32b-instruct:IQ1_M';
    private static readonly AI_TIMEOUT_MS = 30_000; // 30 seconds

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
            where: { slug: 'ai-provider', isActive: true },
        });

        if (dbConfig) {
            const settings = JSON.parse(dbConfig.settings || '{}');
            const provider = (settings.provider || 'ollama') as 'openai' | 'ollama';
            this.config = {
                provider,
                baseUrl: settings.baseUrl || this.configService.get<string>('OLLAMA_BASE_URL') || undefined,
                model: settings.model || this.configService.get<string>('OLLAMA_MODEL') || AiService.DEFAULT_OLLAMA_MODEL,
                apiKey: dbConfig.apiKeyEncrypted || undefined,
            };
            return;
        }

        const ollamaUrlFromEnv = this.configService.get<string>('OLLAMA_BASE_URL');
        if (ollamaUrlFromEnv || this.configService.get<string>('OLLAMA_MODEL')) {
            this.config = {
                provider: 'ollama',
                baseUrl: ollamaUrlFromEnv,
                model: this.configService.get<string>('OLLAMA_MODEL') || AiService.DEFAULT_OLLAMA_MODEL,
            };
            return;
        }
        this.config = null;
    }

    async getConfig(): Promise<AiConfigResponse> {
        const dbConfig = await this.prisma.apiConfiguration.findFirst({
            where: { slug: 'ai-provider', isActive: true },
        });

        if (dbConfig) {
            const settings = JSON.parse(dbConfig.settings || '{}');
            return {
                provider: (settings.provider || 'ollama') as 'openai' | 'ollama',
                baseUrl: settings.baseUrl || '',
                model: settings.model || AiService.DEFAULT_OLLAMA_MODEL,
                source: 'db',
            };
        }

        return {
            provider: 'ollama',
            baseUrl: this.configService.get<string>('OLLAMA_BASE_URL') || '',
            model: this.configService.get<string>('OLLAMA_MODEL') || AiService.DEFAULT_OLLAMA_MODEL,
            source: 'env',
        };
    }

    async saveConfig(input: { provider?: 'openai' | 'ollama'; baseUrl?: string; model?: string }) {
        const provider = (input.provider || 'ollama') as 'openai' | 'ollama';
        const baseUrl = String(input.baseUrl || '').trim();
        const model = String(input.model || '').trim();

        if (provider === 'ollama') {
            if (!baseUrl) {
                throw new InternalServerErrorException('Base URL de Ollama es obligatoria');
            }
            if (!model) {
                throw new InternalServerErrorException('Modelo de Ollama es obligatorio');
            }
        }

        const settings = {
            provider,
            baseUrl,
            model,
        };

        await this.prisma.apiConfiguration.upsert({
            where: { slug: 'ai-provider' },
            update: {
                provider: 'ai_provider',
                isActive: true,
                endpointUrl: baseUrl || null,
                settings: JSON.stringify(settings),
            },
            create: {
                name: 'AI Provider',
                slug: 'ai-provider',
                provider: 'ai_provider',
                endpointUrl: baseUrl || null,
                settings: JSON.stringify(settings),
                isActive: true,
            },
        });

        await this.loadConfig();
        return this.getConfig();
    }

    async listOllamaModels(): Promise<string[]> {
        const cfg = await this.getConfig();
        const baseUrl = cfg.baseUrl || this.configService.get<string>('OLLAMA_BASE_URL') || '';
        if (!baseUrl) return [];

        const tagsUrl = `${baseUrl}/api/tags`;
        try {
            const response = await lastValueFrom(this.httpService.get(tagsUrl));
            const models = Array.isArray(response?.data?.models) ? response.data.models : [];
            return models
                .map((m: any) => m?.name || m?.model)
                .filter((m: any) => !!m)
                .map((m: any) => String(m));
        } catch {
            return [];
        }
    }

    async getVulnerabilityContextAudit(prompt = '') {
        const context = await this.buildVulnerabilityContext(String(prompt || ''));
        return {
            generatedAt: new Date().toISOString(),
            prompt: String(prompt || ''),
            context,
        };
    }

    async chat(messages: any[]) {
        if (!this.config) {
            await this.loadConfig();
            if (!this.config) throw new InternalServerErrorException('AI settings not configured');
        }

        const config = this.config; // Local variable for type safety
        const safeMessages = Array.isArray(messages) ? messages : [];
        const contextualizedMessages = await this.injectVulnerabilityContext(safeMessages);

        try {
            if (config.provider === 'openai') {
                return await this.chatOpenAI(contextualizedMessages, config);
            } else {
                return await this.chatOllama(contextualizedMessages, config);
            }
        } catch (error) {
            this.logger.error('Error in AI chat', error);
            throw new InternalServerErrorException('AI request failed: ' + error.message);
        }
    }

    async chatStructuredJson(
        messages: any[],
        options?: { model?: string },
    ) {
        if (!this.config) {
            await this.loadConfig();
            if (!this.config) throw new InternalServerErrorException('AI settings not configured');
        }

        const config = { ...this.config };
        if (options?.model) {
            config.model = options.model;
        }

        const safeMessages = Array.isArray(messages) ? messages : [];

        const jsonSystemMsg = {
            role: 'system',
            content: 'IMPORTANT: Respond ONLY with valid JSON. No markdown, no code fences, no text outside the JSON object.',
        };

        const finalMessages = [jsonSystemMsg, ...safeMessages];

        try {
            if (config.provider === 'openai') {
                return await this.chatOpenAI(finalMessages, config);
            } else {
                return await this.chatOllama(finalMessages, config);
            }
        } catch (error) {
            this.logger.error('Error in AI chatStructuredJson', error);
            throw new InternalServerErrorException('AI structured JSON request failed: ' + error.message);
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

        const response = await lastValueFrom(
            this.httpService.post(url, payload, { headers, timeout: AiService.AI_TIMEOUT_MS }).pipe(
                timeout(AiService.AI_TIMEOUT_MS),
            ),
        );
        return response.data.choices[0].message;
    }

    private async chatOllama(messages: any[], config: AiConfig) {
        const baseUrl = config.baseUrl || 'http://localhost:11434';
        const url = `${baseUrl}/api/chat`;
        let model = (config.model || '').trim();

        // Quick connectivity check (2s timeout) before attempting a long chat
        try {
            await lastValueFrom(
                this.httpService.get(`${baseUrl}/api/tags`, { timeout: 2000 }).pipe(timeout(2500)),
            );
        } catch {
            throw new InternalServerErrorException(
                `Ollama no disponible en ${baseUrl}. Verifique que el servicio está corriendo.`,
            );
        }

        if (!model) {
            model = await this.getFirstOllamaModel(baseUrl);
            this.logger.warn(`OLLAMA_MODEL vacío; usando modelo detectado: ${model}`);
        }

        const runChat = async (modelName: string) => {
            const payload = {
                model: modelName,
                messages,
                stream: false,
            };
            return lastValueFrom(
                this.httpService.post(url, payload, { timeout: AiService.AI_TIMEOUT_MS }).pipe(
                    timeout(AiService.AI_TIMEOUT_MS + 5000),
                ),
            );
        };

        try {
            const response = await runChat(model);
            return response.data.message;
        } catch (error: any) {
            // Si el modelo no existe, intenta con el primer modelo disponible.
            if (error?.response?.status === 404) {
                const fallbackModel = await this.getFirstOllamaModel(baseUrl);
                if (fallbackModel && fallbackModel !== model) {
                    this.logger.warn(`Modelo Ollama "${model}" no encontrado. Reintentando con "${fallbackModel}"`);
                    const response = await runChat(fallbackModel);
                    return response.data.message;
                }
            }
            throw error;
        }
    }

    private async getFirstOllamaModel(baseUrl: string): Promise<string> {
        const tagsUrl = `${baseUrl}/api/tags`;
        const response = await lastValueFrom(
            this.httpService.get(tagsUrl, { timeout: 5000 }).pipe(timeout(5000)),
        );
        const models = Array.isArray(response?.data?.models) ? response.data.models : [];
        const first = models[0]?.name || models[0]?.model;
        if (!first) {
            throw new InternalServerErrorException('No hay modelos disponibles en Ollama (/api/tags)');
        }
        return String(first);
    }

    private async injectVulnerabilityContext(messages: any[]): Promise<any[]> {
        const lastUserPrompt = this.getLastUserPrompt(messages);
        const vulnerabilityContext = await this.buildVulnerabilityContext(lastUserPrompt);

        const guardrailMessage = {
            role: 'system',
            content:
                'Puedes consultar y usar exclusivamente datos técnicos de vulnerabilidades. ' +
                'No uses ni inventes datos de usuarios, cuentas, correos o credenciales.',
        };

        const contextMessage = {
            role: 'system',
            content: vulnerabilityContext,
        };

        return [guardrailMessage, contextMessage, ...messages];
    }

    private getLastUserPrompt(messages: any[]): string {
        for (let i = messages.length - 1; i >= 0; i -= 1) {
            const m = messages[i];
            if (m?.role === 'user' && typeof m?.content === 'string' && m.content.trim()) {
                return m.content.trim();
            }
        }
        return '';
    }

    private parseCveIds(text: string): string[] {
        if (!text) return [];
        const matches = text.match(/CVE-\d{4}-\d{4,7}/gi) || [];
        return [...new Set(matches.map((m) => m.toUpperCase()))];
    }

    private parseJsonArray(raw: string | null | undefined): string[] {
        if (!raw) return [];
        try {
            const parsed = JSON.parse(raw);
            if (!Array.isArray(parsed)) return [];
            return parsed.map((x) => String(x)).filter(Boolean);
        } catch {
            return [];
        }
    }

    private parseAffectedProducts(raw: string | null | undefined): string[] {
        if (!raw) return [];
        try {
            const parsed = JSON.parse(raw);
            if (!Array.isArray(parsed)) return [];
            return parsed
                .map((p: any) => {
                    if (p && typeof p === 'object') {
                        const vendor = p.vendor || p.name || '';
                        const product = p.product || '';
                        const value = `${vendor}${vendor && product ? '/' : ''}${product}`.trim();
                        return value || null;
                    }
                    return String(p || '').trim() || null;
                })
                .filter((value): value is string => typeof value === 'string' && value.length > 0);
        } catch {
            return [];
        }
    }

    private formatVulnerabilityLine(v: any): string {
        const score = v.cvssV31Score != null ? Number(v.cvssV31Score).toFixed(1) : 'n/a';
        const severity = v.cvssV31Severity || 'UNKNOWN';
        const exploited = v.isKnownExploited ? 'KEV' : (v.hasPublicExploit ? 'PoC' : 'No');
        const epss = v.epssScore != null ? `${(Number(v.epssScore) * 100).toFixed(2)}%` : 'n/a';
        const products = this.parseAffectedProducts(v.affectedProducts).slice(0, 3).join(', ') || 'n/d';
        const refs = this.parseJsonArray(v.references).slice(0, 2).join(' | ') || 'n/d';
        const published = v.publishedAt ? new Date(v.publishedAt).toISOString().slice(0, 10) : 'n/d';

        return `${v.cveId} | CVSS ${score} (${severity}) | EPSS ${epss} | Exploit: ${exploited} | Publicado: ${published} | Productos: ${products} | Referencias: ${refs}`;
    }

    private async buildVulnerabilityContext(lastUserPrompt: string): Promise<string> {
        const cveIds = this.parseCveIds(lastUserPrompt);

        const [total, critical, kev, recent, topRisk, byCve] = await Promise.all([
            this.prisma.vulnerability.count(),
            this.prisma.vulnerability.count({ where: { cvssV31Severity: 'CRITICAL' } }),
            this.prisma.vulnerability.count({ where: { isKnownExploited: true } }),
            this.prisma.vulnerability.findMany({
                take: 8,
                orderBy: { publishedAt: 'desc' },
                select: {
                    cveId: true,
                    cvssV31Score: true,
                    cvssV31Severity: true,
                    epssScore: true,
                    isKnownExploited: true,
                    hasPublicExploit: true,
                    publishedAt: true,
                    affectedProducts: true,
                    references: true,
                },
            }),
            this.prisma.vulnerability.findMany({
                take: 8,
                where: { cvssV31Score: { gte: 7.5 } },
                orderBy: [{ isKnownExploited: 'desc' }, { cvssV31Score: 'desc' }],
                select: {
                    cveId: true,
                    cvssV31Score: true,
                    cvssV31Severity: true,
                    epssScore: true,
                    isKnownExploited: true,
                    hasPublicExploit: true,
                    publishedAt: true,
                    affectedProducts: true,
                    references: true,
                },
            }),
            cveIds.length
                ? this.prisma.vulnerability.findMany({
                    where: { cveId: { in: cveIds } },
                    select: {
                        cveId: true,
                        description: true,
                        cvssV31Score: true,
                        cvssV31Severity: true,
                        epssScore: true,
                        isKnownExploited: true,
                        hasPublicExploit: true,
                        publishedAt: true,
                        affectedProducts: true,
                        references: true,
                    },
                })
                : Promise.resolve([] as any[]),
        ]);

        const exactSection = byCve.length
            ? `Coincidencias exactas por CVE solicitada:\n${byCve.map((v) => this.formatVulnerabilityLine(v)).join('\n')}\n`
            : '';

        const topRiskSection = topRisk.map((v) => this.formatVulnerabilityLine(v)).join('\n');
        const recentSection = recent.map((v) => this.formatVulnerabilityLine(v)).join('\n');

        return [
            'Contexto interno de BD (solo vulnerabilities):',
            `Total CVE: ${total}`,
            `Critical: ${critical}`,
            `KEV (explotación activa): ${kev}`,
            exactSection ? `\n${exactSection}` : '',
            '\nTop CVE riesgo (CVSS >= 7.5):',
            topRiskSection || 'Sin datos',
            '\nCVE recientes:',
            recentSection || 'Sin datos',
            '\nInstrucción: Responde solo con estos datos de vulnerabilidades + razonamiento técnico. Nunca incluyas datos de usuarios.',
        ]
            .filter(Boolean)
            .join('\n');
    }
}
