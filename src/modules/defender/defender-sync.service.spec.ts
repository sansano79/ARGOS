import { ConfigService } from '@nestjs/config';
import { DefenderSyncService } from './defender-sync.service';
import { DefenderConfigService } from './defender-config.service';
import { NormalizedFinding } from './defender.types';
import { encryptSecret, isEncryptedSecret, resolveSecretKey, decryptSecret } from '../../common/secret-crypto.util';

const finding = (cveId: string, extra: Partial<NormalizedFinding> = {}): NormalizedFinding => ({
  cveId,
  productVendor: 'microsoft',
  productName: 'windows_server_2019',
  productVersion: '10.0',
  defenderSeverity: 'High',
  defenderCvss: null,
  exploitabilityLevel: null,
  fixingKbId: 'KB1',
  recommendedUpdate: null,
  diskPaths: null,
  registryPaths: null,
  firstSeenAt: null,
  ...extra,
});

function prismaMock() {
  const p: any = {
    vulnerability: { findMany: jest.fn().mockResolvedValue([{ id: 10, cveId: 'CVE-2024-0001' }]) },
    deviceVulnerabilityFinding: {
      findMany: jest.fn().mockResolvedValue([]),
      createMany: jest.fn((a) => ({ op: 'createMany', a })),
      update: jest.fn((a) => ({ op: 'update', a })),
      updateMany: jest.fn((a) => ({ op: 'updateMany', a })),
    },
    teamSystem: {
      findFirst: jest.fn().mockResolvedValue(null),
      create: jest.fn(async ({ data }) => ({ id: data.externalId === 'm1' ? 1 : 2, name: data.name })),
      update: jest.fn(),
      updateMany: jest.fn().mockResolvedValue({ count: 0 }),
    },
    defenderSyncRun: {
      findFirst: jest.fn().mockResolvedValue(null),
      create: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
    },
    collectorSourceHealth: { create: jest.fn().mockResolvedValue({}) },
    $transaction: jest.fn().mockResolvedValue([]),
  };
  return p;
}

describe('DefenderSyncService.applySnapshot', () => {
  it('crea nuevos, refresca existentes y marca como corregidos los ausentes', async () => {
    const prisma = prismaMock();
    prisma.deviceVulnerabilityFinding.findMany.mockResolvedValue([
      // sigue presente y sin cambios → solo lastSeenAt
      { id: 1, cveId: 'CVE-2024-0001', productVendor: 'microsoft', productName: 'windows_server_2019', productVersion: '10.0', status: 'open', defenderSeverity: 'High', fixingKbId: 'KB1', vulnerabilityId: 10 },
      // ya no aparece → fixed
      { id: 2, cveId: 'CVE-2023-9999', productVendor: 'microsoft', productName: 'windows_server_2019', productVersion: '10.0', status: 'open', defenderSeverity: 'High', fixingKbId: 'KB0', vulnerabilityId: null },
      // estaba corregido y reaparece → reabrir
      { id: 3, cveId: 'CVE-2024-0003', productVendor: 'microsoft', productName: 'windows_server_2019', productVersion: '10.0', status: 'fixed', defenderSeverity: 'High', fixingKbId: 'KB1', vulnerabilityId: null },
    ]);
    const service = new DefenderSyncService(prisma, {} as any, {} as any);

    const res = await service.applySnapshot(5, 'm1', [
      finding('CVE-2024-0001'),
      finding('CVE-2024-0002'),
      finding('CVE-2024-0003'),
    ]);

    expect(res.fixed).toBe(1);
    expect([...res.unknownCves].sort()).toEqual(['CVE-2024-0002', 'CVE-2024-0003']);
    const created = prisma.deviceVulnerabilityFinding.createMany.mock.calls[0][0].data;
    expect(created.map((c: any) => c.cveId)).toEqual(['CVE-2024-0002']);
    expect(prisma.deviceVulnerabilityFinding.update).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: 3 }, data: expect.objectContaining({ status: 'open', fixedAt: null }) }),
    );
    const updateManyCalls = prisma.deviceVulnerabilityFinding.updateMany.mock.calls.map((c: any) => c[0]);
    expect(updateManyCalls).toContainEqual(expect.objectContaining({ where: { id: { in: [1] } } }));
    expect(updateManyCalls).toContainEqual(
      expect.objectContaining({ where: { id: { in: [2] } }, data: expect.objectContaining({ status: 'fixed' }) }),
    );
  });
});

describe('DefenderSyncService full sync', () => {
  const cfg: any = {
    isActive: true,
    tenantId: 't',
    clientId: 'c',
    clientSecret: 's',
    teamId: 7,
    staleDeviceDays: 30,
    maxDevicesPerRun: 500,
  };

  it('un servidor que falla no marca sus hallazgos como corregidos y el run queda partial', async () => {
    const prisma = prismaMock();
    prisma.deviceVulnerabilityFinding.findMany.mockResolvedValue([]);
    prisma.defenderSyncRun.findFirst.mockResolvedValue({ id: 1, mode: 'full', status: 'queued' });
    prisma.defenderSyncRun.findFirst.mockResolvedValueOnce({ id: 1, mode: 'full', status: 'queued' }).mockResolvedValueOnce(null);
    const client: any = {
      listServers: jest.fn().mockResolvedValue([
        { id: 'm1', computerDnsName: 'srv1', onboardingStatus: 'Onboarded' },
        { id: 'm2', computerDnsName: 'srv2', onboardingStatus: 'Onboarded' },
      ]),
      listMachineVulnerabilities: jest.fn(async (_c: any, id: string) => {
        if (id === 'm2') throw new Error('HTTP 503');
        return [{ cveId: 'CVE-2024-0001', machineId: 'm1', productName: 'x' }];
      }),
    };
    const config: any = { getResolved: jest.fn().mockResolvedValue(cfg), readinessErrors: jest.fn().mockReturnValue([]) };
    const service = new DefenderSyncService(prisma, client, config);
    const snapshot = jest.spyOn(service, 'applySnapshot');

    await service.processQueue();

    expect(snapshot).toHaveBeenCalledTimes(1);
    expect(snapshot.mock.calls[0][1]).toBe('m1');
    const update = prisma.defenderSyncRun.update.mock.calls[0][0].data;
    expect(update).toMatchObject({ status: 'partial', devicesSeen: 2, devicesFailed: 1, mode: 'full' });
    expect(JSON.parse(update.failures)[0]).toMatchObject({ deviceId: 'm2' });
    // Los equipos ausentes del listado sí se desactivan (el listado fue completo).
    expect(prisma.teamSystem.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: expect.objectContaining({ externalId: { notIn: ['m1', 'm2'] } }) }),
    );
  });

  it('un listado vacío no desactiva ningún servidor', async () => {
    const prisma = prismaMock();
    prisma.defenderSyncRun.findFirst.mockResolvedValueOnce({ id: 1, mode: 'full', status: 'queued' }).mockResolvedValueOnce(null);
    const client: any = { listServers: jest.fn().mockResolvedValue([]), listMachineVulnerabilities: jest.fn() };
    const config: any = { getResolved: jest.fn().mockResolvedValue(cfg), readinessErrors: jest.fn().mockReturnValue([]) };
    await new DefenderSyncService(prisma, client, config).processQueue();
    expect(prisma.teamSystem.updateMany).not.toHaveBeenCalled();
    expect(prisma.defenderSyncRun.update.mock.calls[0][0].data.status).toBe('success');
  });

  it('un delta sin sync previo reciente se ejecuta como completo', async () => {
    const prisma = prismaMock();
    prisma.defenderSyncRun.findFirst
      .mockResolvedValueOnce({ id: 1, mode: 'delta', status: 'queued' }) // cola
      .mockResolvedValueOnce(null) // último sync correcto
      .mockResolvedValueOnce(null); // cola vacía
    const client: any = { listServers: jest.fn().mockResolvedValue([]), listVulnerabilityChanges: jest.fn() };
    const config: any = { getResolved: jest.fn().mockResolvedValue(cfg), readinessErrors: jest.fn().mockReturnValue([]) };
    await new DefenderSyncService(prisma, client, config).processQueue();
    expect(client.listVulnerabilityChanges).not.toHaveBeenCalled();
    expect(prisma.defenderSyncRun.update.mock.calls[0][0].data).toMatchObject({ mode: 'full', status: 'success' });
  });
});

describe('DefenderConfigService secretos', () => {
  const key = 'a'.repeat(64);

  function service(row: any, env: Record<string, string> = { DEFENDER_SECRET_KEY: key }) {
    const prisma: any = {
      apiConfiguration: { findUnique: jest.fn().mockResolvedValue(row), upsert: jest.fn() },
      subscriberTeam: { findUnique: jest.fn().mockResolvedValue({ id: 1 }) },
    };
    return { prisma, svc: new DefenderConfigService(prisma, new ConfigService(env)) };
  }

  it('cifra el secreto al guardarlo y nunca lo devuelve en la vista', async () => {
    const { prisma, svc } = service(null);
    prisma.apiConfiguration.upsert.mockImplementation(async ({ create }: any) => {
      prisma.apiConfiguration.findUnique.mockResolvedValue(create);
    });
    const view = await svc.save({ clientSecret: 'my-secret', serverTags: ['server'] });
    const stored = prisma.apiConfiguration.upsert.mock.calls[0][0].create.apiKeyEncrypted;
    expect(isEncryptedSecret(stored)).toBe(true);
    expect(stored).not.toContain('my-secret');
    expect(decryptSecret(stored, resolveSecretKey(key)!)).toBe('my-secret');
    expect(JSON.stringify(view)).not.toContain('my-secret');
    expect(view.hasClientSecret).toBe(true);
  });

  it('rechaza guardar el secreto sin clave de cifrado', async () => {
    const { svc } = service(null, {});
    await expect(svc.save({ clientSecret: 'x' })).rejects.toThrow('DEFENDER_SECRET_KEY');
  });

  it('rechaza una baseUrl que no es de Microsoft', async () => {
    const { svc } = service(null);
    await expect(svc.save({ baseUrl: 'https://attacker.example.com' })).rejects.toThrow();
  });

  it('DEFENDER_CLIENT_SECRET tiene prioridad sobre el de BD', async () => {
    const row = { isActive: true, settings: '{}', apiKeyEncrypted: encryptSecret('db-secret', resolveSecretKey(key)!) };
    const { svc } = service(row, { DEFENDER_SECRET_KEY: key, DEFENDER_CLIENT_SECRET: 'env-secret' });
    const resolved = await svc.getResolved();
    expect(resolved).toMatchObject({ clientSecret: 'env-secret', secretSource: 'env' });
  });
});
