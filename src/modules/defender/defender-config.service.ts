import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import {
  decryptSecret,
  encryptSecret,
  isEncryptedSecret,
  resolveSecretKey,
} from '../../common/secret-crypto.util';
import {
  DEFAULT_DEFENDER_SETTINGS,
  DEFENDER_CONFIG_SLUG,
  DefenderConfigView,
  DefenderSettings,
  ResolvedDefenderConfig,
} from './defender.types';

// Solo nube comercial (el token se pide a login.microsoftonline.com). Evita SSRF con una baseUrl arbitraria.
const ALLOWED_HOST = /^([a-z0-9-]+\.)?api\.security\.microsoft\.com$|^([a-z0-9-]+\.)?api\.securitycenter\.microsoft\.com$/i;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type DefenderConfigInput = Partial<DefenderSettings> & {
  isActive?: boolean;
  /** Si se envía, sustituye al secreto guardado. Cadena vacía lo borra. */
  clientSecret?: string;
};

const clampInt = (value: unknown, min: number, max: number, fallback: number) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
};

const cleanList = (value: unknown): string[] => {
  const raw = Array.isArray(value) ? value : String(value ?? '').split(',');
  return [...new Set(raw.map((v) => String(v ?? '').trim()).filter(Boolean))].slice(0, 20);
};

export function normalizeDefenderSettings(input: Partial<DefenderSettings> | null | undefined): DefenderSettings {
  const d = DEFAULT_DEFENDER_SETTINGS;
  const src = input || {};
  const teamId = Number(src.teamId);
  return {
    tenantId: String(src.tenantId ?? d.tenantId).trim(),
    clientId: String(src.clientId ?? d.clientId).trim(),
    baseUrl: String(src.baseUrl || d.baseUrl).trim().replace(/\/+$/, ''),
    serverTags: src.serverTags === undefined ? [...d.serverTags] : cleanList(src.serverTags),
    serverOsPlatforms: src.serverOsPlatforms === undefined ? [] : cleanList(src.serverOsPlatforms),
    teamId: Number.isInteger(teamId) && teamId > 0 ? teamId : null,
    autoSyncEnabled: src.autoSyncEnabled === undefined ? d.autoSyncEnabled : Boolean(src.autoSyncEnabled),
    fullSyncIntervalHours: clampInt(src.fullSyncIntervalHours, 24, 24 * 30, d.fullSyncIntervalHours),
    deltaSyncIntervalHours: clampInt(src.deltaSyncIntervalHours, 6, 24 * 7, d.deltaSyncIntervalHours),
    requestsPerMinute: clampInt(src.requestsPerMinute, 1, 45, d.requestsPerMinute),
    maxDevicesPerRun: clampInt(src.maxDevicesPerRun, 1, 5000, d.maxDevicesPerRun),
    staleDeviceDays: clampInt(src.staleDeviceDays, 1, 180, d.staleDeviceDays),
  };
}

export function validateDefenderSettings(s: DefenderSettings): string[] {
  const errors: string[] = [];
  if (s.tenantId && !GUID.test(s.tenantId)) errors.push('tenantId debe ser un GUID');
  if (s.clientId && !GUID.test(s.clientId)) errors.push('clientId debe ser un GUID');
  try {
    const url = new URL(s.baseUrl);
    if (url.protocol !== 'https:' || !ALLOWED_HOST.test(url.hostname)) {
      errors.push('baseUrl debe ser un endpoint HTTPS oficial de la API de Defender');
    }
  } catch {
    errors.push('baseUrl no es una URL válida');
  }
  if (s.serverTags.length === 0 && s.serverOsPlatforms.length === 0) {
    errors.push('Indica al menos un tag o una plataforma de SO para seleccionar servidores');
  }
  return errors;
}

@Injectable()
export class DefenderConfigService {
  private readonly logger = new Logger(DefenderConfigService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
  ) {}

  private get secretKey() {
    return resolveSecretKey(this.configService.get<string>('DEFENDER_SECRET_KEY'));
  }

  private get envSecret() {
    return String(this.configService.get<string>('DEFENDER_CLIENT_SECRET') || '').trim() || null;
  }

  private async loadRow() {
    return this.prisma.apiConfiguration.findUnique({ where: { slug: DEFENDER_CONFIG_SLUG } });
  }

  private parseSettings(raw: string | null | undefined): DefenderSettings {
    try {
      return normalizeDefenderSettings(raw ? JSON.parse(raw) : {});
    } catch {
      return normalizeDefenderSettings({});
    }
  }

  async getResolved(): Promise<ResolvedDefenderConfig> {
    const row = await this.loadRow();
    const settings = this.parseSettings(row?.settings);
    let clientSecret: string | null = null;
    let secretSource: ResolvedDefenderConfig['secretSource'] = null;

    if (this.envSecret) {
      clientSecret = this.envSecret;
      secretSource = 'env';
    } else if (row?.apiKeyEncrypted && isEncryptedSecret(row.apiKeyEncrypted)) {
      const key = this.secretKey;
      if (key) {
        try {
          clientSecret = decryptSecret(row.apiKeyEncrypted, key);
          secretSource = 'db';
        } catch {
          this.logger.error('No se pudo descifrar el secreto de Defender (¿cambió DEFENDER_SECRET_KEY?)');
        }
      } else {
        this.logger.warn('Hay secreto de Defender en BD pero falta DEFENDER_SECRET_KEY');
      }
    }

    return { ...settings, isActive: row?.isActive ?? false, clientSecret, secretSource };
  }

  async getView(): Promise<DefenderConfigView> {
    const row = await this.loadRow();
    const settings = this.parseSettings(row?.settings);
    const hasDbSecret = Boolean(row?.apiKeyEncrypted && isEncryptedSecret(row.apiKeyEncrypted));
    return {
      ...settings,
      isActive: row?.isActive ?? false,
      hasClientSecret: Boolean(this.envSecret) || hasDbSecret,
      secretSource: this.envSecret ? 'env' : hasDbSecret ? 'db' : null,
      secretStorageAvailable: Boolean(this.secretKey),
    };
  }

  async save(input: DefenderConfigInput, userId?: number): Promise<DefenderConfigView> {
    const row = await this.loadRow();
    const current = this.parseSettings(row?.settings);
    const merged = normalizeDefenderSettings({ ...current, ...input });
    const errors = validateDefenderSettings(merged);
    if (errors.length) throw new BadRequestException(errors);

    if (merged.teamId) {
      const team = await this.prisma.subscriberTeam.findUnique({ where: { id: merged.teamId } });
      if (!team) throw new BadRequestException('teamId no corresponde a ningún equipo de ARGOS');
    }

    let apiKeyEncrypted = row?.apiKeyEncrypted ?? null;
    if (input.clientSecret !== undefined) {
      const secret = String(input.clientSecret || '').trim();
      if (!secret) {
        apiKeyEncrypted = null;
      } else {
        const key = this.secretKey;
        if (!key) {
          throw new BadRequestException(
            'Define DEFENDER_SECRET_KEY en el entorno para guardar el secreto cifrado, o usa DEFENDER_CLIENT_SECRET',
          );
        }
        apiKeyEncrypted = encryptSecret(secret, key);
      }
    }

    const data = {
      name: 'Microsoft Defender for Endpoint',
      provider: 'microsoft_defender',
      endpointUrl: merged.baseUrl,
      settings: JSON.stringify(merged),
      apiKeyEncrypted,
      isActive: input.isActive ?? row?.isActive ?? true,
    };

    await this.prisma.apiConfiguration.upsert({
      where: { slug: DEFENDER_CONFIG_SLUG },
      update: data,
      create: { ...data, slug: DEFENDER_CONFIG_SLUG, createdBy: userId ?? null },
    });

    return this.getView();
  }

  /** Errores que impiden sincronizar; vacío si la configuración es utilizable. */
  readinessErrors(cfg: ResolvedDefenderConfig): string[] {
    const errors = validateDefenderSettings(cfg);
    if (!cfg.isActive) errors.push('La integración con Defender está desactivada');
    if (!cfg.tenantId) errors.push('Falta tenantId');
    if (!cfg.clientId) errors.push('Falta clientId');
    if (!cfg.clientSecret) errors.push('Falta el secreto de cliente (o no se puede descifrar)');
    if (!cfg.teamId) errors.push('Falta el equipo de ARGOS donde guardar los servidores (teamId)');
    return errors;
  }
}
