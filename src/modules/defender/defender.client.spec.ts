import { of, throwError } from 'rxjs';
import { DefenderApiError, DefenderClient, DEFENDER_TOKEN_SCOPE } from './defender.client';
import { SlidingWindowRateLimiter } from './rate-limiter';
import { ResolvedDefenderConfig } from './defender.types';

const cfg: ResolvedDefenderConfig = {
  tenantId: '11111111-1111-1111-1111-111111111111',
  clientId: '22222222-2222-2222-2222-222222222222',
  clientSecret: 'super-secret-value',
  secretSource: 'db',
  baseUrl: 'https://eu.api.security.microsoft.com',
  serverTags: ['server'],
  serverOsPlatforms: [],
  teamId: 1,
  isActive: true,
  autoSyncEnabled: false,
  fullSyncIntervalHours: 168,
  deltaSyncIntervalHours: 6,
  requestsPerMinute: 40,
  maxDevicesPerRun: 500,
  staleDeviceDays: 30,
};

const httpError = (status: number, headers: Record<string, string> = {}) =>
  throwError(() => ({ response: { status, headers, data: { error: { message: `boom ${status}` } } } }));

function setup() {
  const http: any = {
    post: jest.fn().mockReturnValue(of({ data: { access_token: 'tok-1', expires_in: 3600 } })),
    get: jest.fn(),
  };
  const client = new DefenderClient(http);
  const sleep = jest.fn().mockResolvedValue(undefined);
  client.setTimingForTests(new SlidingWindowRateLimiter(() => 0, sleep), sleep);
  return { http, client, sleep };
}

describe('DefenderClient', () => {
  it('pide el token con client credentials y la audiencia legacy, y lo cachea', async () => {
    const { http, client } = setup();
    expect(await client.getToken(cfg)).toBe('tok-1');
    expect(await client.getToken(cfg)).toBe('tok-1');
    expect(http.post).toHaveBeenCalledTimes(1);
    const [url, body] = http.post.mock.calls[0];
    expect(url).toBe(`https://login.microsoftonline.com/${cfg.tenantId}/oauth2/v2.0/token`);
    expect(new URLSearchParams(body).get('scope')).toBe(DEFENDER_TOKEN_SCOPE);
    expect(new URLSearchParams(body).get('grant_type')).toBe('client_credentials');
  });

  it('no incluye el secreto en el error de token', async () => {
    const { http, client } = setup();
    http.post.mockReturnValue(
      throwError(() => ({
        response: { status: 401, data: { error_description: 'AADSTS7000215: Invalid client secret provided.' } },
      })),
    );
    const error = await client.getToken(cfg).catch((e) => e);
    expect(error).toBeInstanceOf(DefenderApiError);
    expect(error.message).toContain('AADSTS7000215');
    expect(error.message).not.toContain(cfg.clientSecret);
  });

  it('filtra servidores por tag en la API y une resultados sin duplicados', async () => {
    const { http, client } = setup();
    http.get
      .mockReturnValueOnce(of({ data: { value: [{ id: 'a' }, { id: 'b' }] } }))
      .mockReturnValueOnce(of({ data: { value: [{ id: 'b' }, { id: 'c' }] } }));
    const out = await client.listServers({ ...cfg, serverTags: ['server', 'srv'] });
    expect(out.map((m) => m.id)).toEqual(['a', 'b', 'c']);
    const firstUrl = new URL(http.get.mock.calls[0][0]);
    expect(firstUrl.pathname).toBe('/api/machines');
    expect(firstUrl.searchParams.get('$filter')).toBe("machineTags/any(t: t eq 'server')");
    expect(http.get.mock.calls[0][1].headers.Authorization).toBe('Bearer tok-1');
  });

  it('pide vulnerabilidades por equipo y sigue @odata.nextLink', async () => {
    const { http, client } = setup();
    http.get
      .mockReturnValueOnce(
        of({
          data: {
            value: [{ cveId: 'CVE-2024-0001', machineId: 'm1' }],
            '@odata.nextLink': 'https://eu.api.security.microsoft.com/api/vulnerabilities/machinesVulnerabilities?$skiptoken=x',
          },
        }),
      )
      .mockReturnValueOnce(of({ data: { value: [{ cveId: 'CVE-2024-0002', machineId: 'm1' }] } }));
    const out = await client.listMachineVulnerabilities(cfg, 'm1');
    expect(out).toHaveLength(2);
    expect(new URL(http.get.mock.calls[0][0]).searchParams.get('$filter')).toBe("machineId eq 'm1'");
  });

  it('rechaza un nextLink a otro dominio (no filtra el token)', async () => {
    const { http, client } = setup();
    http.get.mockReturnValueOnce(
      of({ data: { value: [], '@odata.nextLink': 'https://evil.example.com/steal' } }),
    );
    await expect(client.listMachineVulnerabilities(cfg, 'm1')).rejects.toThrow('fuera del dominio');
    expect(http.get).toHaveBeenCalledTimes(1);
  });

  it('respeta Retry-After en 429 y reintenta', async () => {
    const { http, client, sleep } = setup();
    http.get
      .mockReturnValueOnce(httpError(429, { 'retry-after': '7' }))
      .mockReturnValueOnce(of({ data: { value: [{ id: 'a' }] } }));
    const out = await client.listServers(cfg);
    expect(out).toHaveLength(1);
    expect(sleep).toHaveBeenCalledWith(7000);
  });

  it('renueva el token una vez ante 401', async () => {
    const { http, client } = setup();
    http.post
      .mockReturnValueOnce(of({ data: { access_token: 'tok-1', expires_in: 3600 } }))
      .mockReturnValueOnce(of({ data: { access_token: 'tok-2', expires_in: 3600 } }));
    http.get.mockReturnValueOnce(httpError(401)).mockReturnValueOnce(of({ data: { value: [] } }));
    await client.listServers(cfg);
    expect(http.get.mock.calls[1][1].headers.Authorization).toBe('Bearer tok-2');
  });

  it('no reintenta errores 4xx no transitorios', async () => {
    const { http, client } = setup();
    http.get.mockReturnValue(httpError(403));
    await expect(client.listServers(cfg)).rejects.toThrow('HTTP 403');
    expect(http.get).toHaveBeenCalledTimes(1);
  });

  it('abandona tras 3 reintentos en 5xx', async () => {
    const { http, client } = setup();
    http.get.mockReturnValue(httpError(503));
    await expect(client.listServers(cfg)).rejects.toThrow('HTTP 503');
    expect(http.get).toHaveBeenCalledTimes(4);
  });
});

describe('SlidingWindowRateLimiter', () => {
  it('espera cuando se supera el límite en la ventana', async () => {
    let t = 0;
    const sleep = jest.fn(async (ms: number) => {
      t += ms;
    });
    const limiter = new SlidingWindowRateLimiter(() => t, sleep);
    for (let i = 0; i < 3; i++) await limiter.acquire('k', 3);
    expect(sleep).not.toHaveBeenCalled();
    await limiter.acquire('k', 3);
    expect(sleep).toHaveBeenCalledTimes(1);
    expect(t).toBeGreaterThanOrEqual(60_000);
  });
});
