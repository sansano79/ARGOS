import {
  DefenderMachine,
  DefenderMachineVulnerability,
  DefenderVulnerabilityChange,
  NormalizedFinding,
} from './defender.types';

const MAX_VARCHAR = 191;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

const str = (value: unknown, max = MAX_VARCHAR) => {
  const s = String(value ?? '').trim();
  return s.length > max ? s.slice(0, max) : s;
};
const optStr = (value: unknown, max = MAX_VARCHAR) => str(value, max) || null;
const lower = (value: unknown) => str(value).toLowerCase();

const jsonList = (value: unknown): string | null => {
  if (!Array.isArray(value)) return null;
  const list = value.map((v) => String(v ?? '').trim()).filter(Boolean);
  return list.length ? JSON.stringify(list.slice(0, 50)) : null;
};

const toDate = (value: unknown): Date | null => {
  if (!value) return null;
  const d = new Date(String(value));
  return Number.isNaN(d.getTime()) ? null : d;
};

const toNumber = (value: unknown): number | null => {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
};

/** El KB llega como "5034441" o "KB5034441": se guarda normalizado como KB<n>. */
const normalizeKb = (value: unknown): string | null => {
  const s = str(value, 64);
  if (!s) return null;
  return /^\d+$/.test(s) ? `KB${s}` : s.toUpperCase().startsWith('KB') ? s.toUpperCase() : s;
};

/** Clave de identidad de un hallazgo dentro de un equipo. */
export const findingKey = (f: Pick<NormalizedFinding, 'cveId' | 'productVendor' | 'productName' | 'productVersion'>) =>
  [f.cveId, f.productVendor, f.productName, f.productVersion].join('|');

export function isValidCve(cveId: unknown): boolean {
  return CVE_RE.test(String(cveId ?? '').trim());
}

export function normalizeMachineVulnerability(v: DefenderMachineVulnerability): NormalizedFinding | null {
  if (!isValidCve(v?.cveId)) return null;
  return {
    cveId: str(v.cveId, 32).toUpperCase(),
    productVendor: lower(v.productVendor),
    productName: lower(v.productName) || 'unknown',
    productVersion: lower(v.productVersion),
    defenderSeverity: optStr(v.severity, 20),
    defenderCvss: null,
    exploitabilityLevel: null,
    fixingKbId: normalizeKb(v.fixingKbId),
    recommendedUpdate: null,
    diskPaths: null,
    registryPaths: null,
    firstSeenAt: null,
  };
}

export function normalizeVulnerabilityChange(c: DefenderVulnerabilityChange): NormalizedFinding | null {
  if (!isValidCve(c?.CveId)) return null;
  return {
    cveId: str(c.CveId, 32).toUpperCase(),
    productVendor: lower(c.SoftwareVendor),
    productName: lower(c.SoftwareName) || 'unknown',
    productVersion: lower(c.SoftwareVersion),
    defenderSeverity: optStr(c.VulnerabilitySeverityLevel, 20),
    defenderCvss: toNumber(c.CvssScore),
    exploitabilityLevel: optStr(c.ExploitabilityLevel, 40),
    fixingKbId: normalizeKb(c.RecommendedSecurityUpdateId),
    recommendedUpdate: optStr(c.RecommendedSecurityUpdate, 2000),
    diskPaths: jsonList(c.DiskPaths),
    registryPaths: jsonList(c.RegistryPaths),
    firstSeenAt: toDate(c.FirstSeenTimestamp),
  };
}

/** Elimina duplicados por clave. Si se repite, conserva el último. */
export function dedupeFindings(findings: Array<NormalizedFinding | null>): NormalizedFinding[] {
  const map = new Map<string, NormalizedFinding>();
  for (const f of findings) if (f) map.set(findingKey(f), f);
  return [...map.values()];
}

/**
 * Datos que se pueden actualizar sin perder información: los campos que el
 * endpoint de origen no trae (null) no sobrescriben lo ya guardado.
 */
export function enrichmentUpdate(f: NormalizedFinding) {
  const out: Record<string, unknown> = {};
  const fields: Array<keyof NormalizedFinding> = [
    'defenderSeverity',
    'defenderCvss',
    'exploitabilityLevel',
    'fixingKbId',
    'recommendedUpdate',
    'diskPaths',
    'registryPaths',
  ];
  for (const k of fields) if (f[k] !== null && f[k] !== undefined) out[k] = f[k];
  return out;
}

export interface ChangeEvent {
  deviceId: string;
  status: 'open' | 'fixed';
  finding: NormalizedFinding;
  eventAt: number;
}

/**
 * Agrupa el delta en el estado final por equipo + hallazgo. Si un equipo cambia
 * de grupo RBAC, Microsoft emite "Fixed" (grupo antiguo) y "New" (grupo nuevo)
 * para el mismo registro: ante empate de fecha gana el estado abierto.
 */
export function reduceChanges(changes: DefenderVulnerabilityChange[]): ChangeEvent[] {
  const byKey = new Map<string, ChangeEvent>();
  for (const c of changes) {
    const finding = normalizeVulnerabilityChange(c);
    const deviceId = str(c?.DeviceId, 64);
    if (!finding || !deviceId) continue;
    const status: ChangeEvent['status'] = String(c.Status).toLowerCase() === 'fixed' ? 'fixed' : 'open';
    const eventAt = toDate(c.EventTimestamp)?.getTime() ?? 0;
    const key = `${deviceId}|${findingKey(finding)}`;
    const prev = byKey.get(key);
    if (!prev || eventAt > prev.eventAt || (eventAt === prev.eventAt && status === 'open')) {
      byKey.set(key, { deviceId, status, finding, eventAt });
    }
  }
  return [...byKey.values()];
}

/** Descarta equipos no incorporados o sin contacto reciente con Defender. */
export function selectActiveServers(machines: DefenderMachine[], staleDays: number, now = new Date()): DefenderMachine[] {
  const threshold = now.getTime() - staleDays * 24 * 3600 * 1000;
  return machines
    .filter((m) => m?.id)
    .filter((m) => !m.onboardingStatus || m.onboardingStatus === 'Onboarded')
    .filter((m) => {
      const seen = toDate(m.lastSeen);
      return !seen || seen.getTime() >= threshold;
    })
    .sort((a, b) => (toDate(b.lastSeen)?.getTime() ?? 0) - (toDate(a.lastSeen)?.getTime() ?? 0));
}

/** Proyección de un Machine de Defender sobre TeamSystem. */
export function machineToSystemData(m: DefenderMachine) {
  const fqdn = str(m.computerDnsName) || m.id;
  const tags = (m.machineTags || []).map((t) => String(t).trim()).filter(Boolean);
  return {
    name: fqdn,
    hostname: fqdn.split('.')[0] || fqdn,
    fqdn: optStr(m.computerDnsName),
    platform: optStr(m.osPlatform),
    osVersion: optStr(m.osVersion || m.version || (m.osBuild ? String(m.osBuild) : null)),
    riskLevel: optStr(m.riskScore),
    healthStatus: optStr(m.healthStatus),
    tags: tags.length ? tags.join(', ') : null,
    rawData: JSON.stringify({
      id: m.id,
      computerDnsName: m.computerDnsName ?? null,
      osPlatform: m.osPlatform ?? null,
      osVersion: m.osVersion ?? m.version ?? null,
      machineTags: tags,
      rbacGroupName: m.rbacGroupName ?? null,
      exposureLevel: m.exposureLevel ?? null,
      riskScore: m.riskScore ?? null,
      deviceValue: m.deviceValue ?? null,
      lastIpAddress: m.lastIpAddress ?? null,
      lastExternalIpAddress: m.lastExternalIpAddress ?? null,
      healthStatus: m.healthStatus ?? null,
      onboardingStatus: m.onboardingStatus ?? null,
      lastSeen: m.lastSeen ?? null,
      aadDeviceId: m.aadDeviceId ?? null,
    }),
  };
}
