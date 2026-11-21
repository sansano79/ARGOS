import {
  dedupeFindings,
  enrichmentUpdate,
  machineToSystemData,
  normalizeMachineVulnerability,
  normalizeVulnerabilityChange,
  reduceChanges,
  selectActiveServers,
} from './defender-sync.logic';
import { buildServerFilters } from './defender.client';

describe('defender sync logic', () => {
  it('normaliza hallazgos de machinesVulnerabilities y descarta CVEs no válidas', () => {
    const f = normalizeMachineVulnerability({
      cveId: 'cve-2024-21412',
      machineId: 'm1',
      productVendor: 'Microsoft',
      productName: 'Windows_Server_2019',
      productVersion: '10.0.17763.5329',
      severity: 'High',
      fixingKbId: '5034127',
    });
    expect(f).toMatchObject({
      cveId: 'CVE-2024-21412',
      productVendor: 'microsoft',
      productName: 'windows_server_2019',
      fixingKbId: 'KB5034127',
      defenderSeverity: 'High',
    });
    expect(normalizeMachineVulnerability({ cveId: 'TVM-2020-0002', machineId: 'm1' })).toBeNull();
  });

  it('deduplica por CVE + software + versión', () => {
    const base = { machineId: 'm1', productVendor: 'google', productName: 'chrome', productVersion: '120' };
    const out = dedupeFindings([
      normalizeMachineVulnerability({ ...base, cveId: 'CVE-2024-0001' }),
      normalizeMachineVulnerability({ ...base, cveId: 'CVE-2024-0001' }),
      normalizeMachineVulnerability({ ...base, cveId: 'CVE-2024-0001', productVersion: '121' }),
    ]);
    expect(out).toHaveLength(2);
  });

  it('no sobrescribe con null los campos que el endpoint no trae', () => {
    const f = normalizeMachineVulnerability({ cveId: 'CVE-2024-0001', machineId: 'm1', productName: 'x', severity: 'Low' })!;
    expect(enrichmentUpdate(f)).toEqual({ defenderSeverity: 'Low' });
  });

  it('reduce el delta: gana el evento más reciente y, ante empate RBAC, el abierto', () => {
    const row = {
      DeviceId: 'm1',
      CveId: 'CVE-2024-0001',
      SoftwareVendor: 'v',
      SoftwareName: 'n',
      SoftwareVersion: '1',
      EventTimestamp: '2026-11-20T06:00:00Z',
    };
    const rbacMove = reduceChanges([
      { ...row, Status: 'Fixed' },
      { ...row, Status: 'New' },
    ]);
    expect(rbacMove).toHaveLength(1);
    expect(rbacMove[0].status).toBe('open');

    const laterFix = reduceChanges([
      { ...row, Status: 'New' },
      { ...row, Status: 'Fixed', EventTimestamp: '2026-11-20T12:00:00Z' },
    ]);
    expect(laterFix[0].status).toBe('fixed');
  });

  it('una actualización de versión genera hallazgos distintos (fixed en la antigua, abierto en la nueva)', () => {
    const row = { DeviceId: 'm1', CveId: 'CVE-2024-0001', SoftwareName: 'n', EventTimestamp: '2026-11-20T06:00:00Z' };
    const out = reduceChanges([
      { ...row, SoftwareVersion: '1.0', Status: 'Fixed' },
      { ...row, SoftwareVersion: '2.0', Status: 'New' },
    ]);
    expect(out.map((e) => [e.finding.productVersion, e.status]).sort()).toEqual([
      ['1.0', 'fixed'],
      ['2.0', 'open'],
    ]);
  });

  it('el delta conserva CVSS, explotabilidad, KB y rutas', () => {
    const f = normalizeVulnerabilityChange({
      DeviceId: 'm1',
      CveId: 'CVE-2024-0001',
      SoftwareName: 'n',
      CvssScore: '8.8',
      ExploitabilityLevel: 'ExploitIsVerified',
      RecommendedSecurityUpdateId: 'KB5034441',
      DiskPaths: ['C:\\a.exe'],
      Status: 'New',
    })!;
    expect(f).toMatchObject({ defenderCvss: 8.8, exploitabilityLevel: 'ExploitIsVerified', fixingKbId: 'KB5034441' });
    expect(JSON.parse(f.diskPaths!)).toEqual(['C:\\a.exe']);
  });

  it('selecciona servidores incorporados y con contacto reciente', () => {
    const now = new Date('2026-11-21T00:00:00Z');
    const out = selectActiveServers(
      [
        { id: 'a', onboardingStatus: 'Onboarded', lastSeen: '2026-11-20T00:00:00Z' },
        { id: 'b', onboardingStatus: 'CanBeOnboarded', lastSeen: '2026-11-20T00:00:00Z' },
        { id: 'c', onboardingStatus: 'Onboarded', lastSeen: '2026-09-01T00:00:00Z' },
        { id: 'd', onboardingStatus: 'Onboarded', lastSeen: '2026-11-20T12:00:00Z' },
      ],
      30,
      now,
    );
    expect(out.map((m) => m.id)).toEqual(['d', 'a']);
  });

  it('proyecta Machine sobre TeamSystem sin perder el contexto de exposición', () => {
    const data = machineToSystemData({
      id: 'abc',
      computerDnsName: 'srv-sql01.corp.local',
      osPlatform: 'WindowsServer2019',
      machineTags: ['server', 'prod'],
      exposureLevel: 'High',
      riskScore: 'Medium',
    });
    expect(data).toMatchObject({ name: 'srv-sql01.corp.local', hostname: 'srv-sql01', tags: 'server, prod', riskLevel: 'Medium' });
    expect(JSON.parse(data.rawData)).toMatchObject({ exposureLevel: 'High' });
  });

  it('construye filtros OData por tag y SO escapando comillas', () => {
    expect(buildServerFilters({ serverTags: ["o'brien"], serverOsPlatforms: ['WindowsServer2022'] })).toEqual([
      "machineTags/any(t: t eq 'o''brien')",
      "osPlatform eq 'WindowsServer2022'",
    ]);
  });
});
