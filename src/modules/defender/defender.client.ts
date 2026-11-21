import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { lastValueFrom } from 'rxjs';
import { SlidingWindowRateLimiter } from './rate-limiter';
import {
  DefenderMachine,
  DefenderMachineVulnerability,
  DefenderVulnerabilityChange,
  ResolvedDefenderConfig,
} from './defender.types';

/** Audiencia legacy: algunas APIs devuelven 403 con otra audiencia (doc. Microsoft). */
export const DEFENDER_TOKEN_SCOPE = 'https://api.securitycenter.microsoft.com/.default';
const TOKEN_HOST = 'https://login.microsoftonline.com';
const REQUEST_TIMEOUT_MS = 60_000;
const MAX_RETRIES = 3;
const MAX_PAGES = 500;

/** Límites por endpoint, por debajo de los publicados por Microsoft. */
const LIMITS = {
  machines: 90, // 100/min
  changes: 25, // 30/min
};

export class DefenderApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

type Bucket = 'machines' | 'vulnerabilities' | 'changes';

const odataString = (value: string) => `'${String(value).replace(/'/g, "''")}'`;

/** Construye los filtros OData (unidos con OR por el llamante) para seleccionar servidores. */
export function buildServerFilters(cfg: Pick<ResolvedDefenderConfig, 'serverTags' | 'serverOsPlatforms'>): string[] {
  return [
    ...cfg.serverTags.map((tag) => `machineTags/any(t: t eq ${odataString(tag)})`),
    ...cfg.serverOsPlatforms.map((os) => `osPlatform eq ${odataString(os)}`),
  ];
}

@Injectable()
export class DefenderClient {
  private readonly logger = new Logger(DefenderClient.name);
  private token: { value: string; expiresAt: number; cacheKey: string } | null = null;
  private limiter = new SlidingWindowRateLimiter();
  private sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms));

  constructor(private readonly http: HttpService) {}

  /** Solo para tests. */
  setTimingForTests(limiter: SlidingWindowRateLimiter, sleep: (ms: number) => Promise<void>) {
    this.limiter = limiter;
    this.sleep = sleep;
  }

  invalidateToken() {
    this.token = null;
  }

  async getToken(cfg: ResolvedDefenderConfig): Promise<string> {
    const cacheKey = `${cfg.tenantId}|${cfg.clientId}`;
    if (this.token && this.token.cacheKey === cacheKey && this.token.expiresAt - Date.now() > 5 * 60_000) {
      return this.token.value;
    }
    if (!cfg.tenantId || !cfg.clientId || !cfg.clientSecret) {
      throw new DefenderApiError('Credenciales de Defender incompletas');
    }
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      scope: DEFENDER_TOKEN_SCOPE,
    }).toString();

    try {
      const res = await lastValueFrom(
        this.http.post(`${TOKEN_HOST}/${encodeURIComponent(cfg.tenantId)}/oauth2/v2.0/token`, body, {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 20_000,
        }),
      );
      const value = String(res?.data?.access_token || '');
      if (!value) throw new DefenderApiError('Respuesta de token sin access_token');
      const expiresIn = Number(res?.data?.expires_in) || 3599;
      this.token = { value, expiresAt: Date.now() + expiresIn * 1000, cacheKey };
      return value;
    } catch (error: any) {
      if (error instanceof DefenderApiError) throw error;
      const status = error?.response?.status;
      // El cuerpo de error de Entra ID no contiene el secreto; solo se expone el código AADSTS.
      const aad = String(error?.response?.data?.error_description || '').match(/AADSTS\d+/)?.[0];
      throw new DefenderApiError(
        `No se pudo obtener el token de Entra ID${status ? ` (HTTP ${status})` : ''}${aad ? ` ${aad}` : ''}`,
        status,
      );
    }
  }

  private assertSameOrigin(cfg: ResolvedDefenderConfig, url: string) {
    const base = new URL(cfg.baseUrl);
    const target = new URL(url);
    if (target.protocol !== 'https:' || target.host !== base.host) {
      throw new DefenderApiError(`URL de paginación fuera del dominio configurado: ${target.host}`);
    }
  }

  private async get<T = any>(cfg: ResolvedDefenderConfig, bucket: Bucket, url: string): Promise<T> {
    this.assertSameOrigin(cfg, url);
    const limit = bucket === 'vulnerabilities' ? cfg.requestsPerMinute : LIMITS[bucket];
    let refreshedToken = false;

    for (let attempt = 0; ; attempt++) {
      await this.limiter.acquire(bucket, limit);
      const token = await this.getToken(cfg);
      try {
        const res = await lastValueFrom(
          this.http.get(url, {
            headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
            timeout: REQUEST_TIMEOUT_MS,
          }),
        );
        return res.data as T;
      } catch (error: any) {
        const status: number | undefined = error?.response?.status;
        if (status === 401 && !refreshedToken) {
          refreshedToken = true;
          this.invalidateToken();
          continue;
        }
        const retryable = status === 429 || status === undefined || status >= 500;
        if (!retryable || attempt >= MAX_RETRIES) {
          const detail = error?.response?.data?.error?.message || error?.message || 'error desconocido';
          throw new DefenderApiError(
            `Defender API ${status ? `HTTP ${status}` : 'sin respuesta'} en ${new URL(url).pathname}: ${String(detail).slice(0, 300)}`,
            status,
          );
        }
        const retryAfter = Number(error?.response?.headers?.['retry-after']);
        const waitMs =
          status === 429 && Number.isFinite(retryAfter) && retryAfter > 0
            ? Math.min(retryAfter, 300) * 1000
            : 2 ** attempt * 2000;
        this.logger.warn(`Defender ${status ?? 'red'} en ${new URL(url).pathname}; reintento ${attempt + 1} en ${waitMs} ms`);
        await this.sleep(waitMs);
      }
    }
  }

  /** Recorre una colección OData siguiendo @odata.nextLink o $skip. */
  private async collect<T>(
    cfg: ResolvedDefenderConfig,
    bucket: Bucket,
    firstUrl: string,
    pageSize: number | null,
  ): Promise<T[]> {
    const items: T[] = [];
    let url: string | null = firstUrl;
    let skip = 0;
    for (let page = 0; url && page < MAX_PAGES; page++) {
      const data: any = await this.get(cfg, bucket, url);
      const value: T[] = Array.isArray(data?.value) ? data.value : [];
      items.push(...value);
      const next = data?.['@odata.nextLink'];
      if (next) {
        url = String(next);
      } else if (pageSize && value.length >= pageSize) {
        skip += pageSize;
        const u = new URL(firstUrl);
        u.searchParams.set('$skip', String(skip));
        url = u.toString();
      } else {
        url = null;
      }
    }
    if (url) throw new DefenderApiError(`Paginación detenida tras ${MAX_PAGES} páginas en ${new URL(firstUrl).pathname}`);
    return items;
  }

  private buildUrl(cfg: ResolvedDefenderConfig, path: string, params: Record<string, string | number>) {
    const u = new URL(path, `${cfg.baseUrl}/`);
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, String(v));
    return u.toString();
  }

  /** Equipos que cumplen alguno de los filtros de servidor, sin duplicados. */
  async listServers(cfg: ResolvedDefenderConfig): Promise<DefenderMachine[]> {
    const byId = new Map<string, DefenderMachine>();
    const pageSize = 10_000;
    for (const filter of buildServerFilters(cfg)) {
      const url = this.buildUrl(cfg, '/api/machines', { $filter: filter, $top: pageSize });
      const machines = await this.collect<DefenderMachine>(cfg, 'machines', url, pageSize);
      for (const m of machines) if (m?.id) byId.set(m.id, m);
    }
    return [...byId.values()];
  }

  async listMachineVulnerabilities(cfg: ResolvedDefenderConfig, machineId: string): Promise<DefenderMachineVulnerability[]> {
    const pageSize = 10_000;
    const url = this.buildUrl(cfg, '/api/vulnerabilities/machinesVulnerabilities', {
      $filter: `machineId eq ${odataString(machineId)}`,
      $top: pageSize,
    });
    return this.collect<DefenderMachineVulnerability>(cfg, 'vulnerabilities', url, pageSize);
  }

  async listVulnerabilityChanges(cfg: ResolvedDefenderConfig, since: Date): Promise<DefenderVulnerabilityChange[]> {
    const url = this.buildUrl(cfg, '/api/machines/SoftwareVulnerabilityChangesByMachine', {
      pageSize: 50_000,
      sinceTime: since.toISOString(),
    });
    return this.collect<DefenderVulnerabilityChange>(cfg, 'changes', url, null);
  }

  /** Comprueba token y lectura de equipos; cuenta servidores del primer filtro. */
  async testConnection(cfg: ResolvedDefenderConfig) {
    await this.getToken(cfg);
    const filters = buildServerFilters(cfg);
    const url = this.buildUrl(cfg, '/api/machines', { $top: 100, ...(filters[0] ? { $filter: filters[0] } : {}) });
    const data: any = await this.get(cfg, 'machines', url);
    const value: DefenderMachine[] = Array.isArray(data?.value) ? data.value : [];
    return {
      sampleFilter: filters[0] || null,
      sampleCount: value.length,
      sampleTruncated: value.length >= 100,
      sample: value.slice(0, 5).map((m) => ({ id: m.id, computerDnsName: m.computerDnsName, osPlatform: m.osPlatform })),
    };
  }
}
