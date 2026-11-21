export const DEFENDER_CONFIG_SLUG = 'defender';
export const DEFENDER_SOURCE = 'defender';

export interface DefenderSettings {
  tenantId: string;
  clientId: string;
  baseUrl: string;
  /** Tags de Defender que identifican servidores (OR). */
  serverTags: string[];
  /** Alternativa/complemento: plataformas de SO (p. ej. WindowsServer2019). */
  serverOsPlatforms: string[];
  /** Equipo de ARGOS donde se crean los servidores nuevos. */
  teamId: number | null;
  autoSyncEnabled: boolean;
  fullSyncIntervalHours: number;
  deltaSyncIntervalHours: number;
  /** Ritmo para el endpoint de vulnerabilidades por equipo (límite Microsoft: 50/min). */
  requestsPerMinute: number;
  maxDevicesPerRun: number;
  /** Equipos sin contacto con Defender en más días que estos se ignoran. */
  staleDeviceDays: number;
}

export const DEFAULT_DEFENDER_SETTINGS: DefenderSettings = {
  tenantId: '',
  clientId: '',
  baseUrl: 'https://eu.api.security.microsoft.com',
  serverTags: ['server'],
  serverOsPlatforms: [],
  teamId: null,
  autoSyncEnabled: false,
  fullSyncIntervalHours: 168,
  deltaSyncIntervalHours: 6,
  requestsPerMinute: 40,
  maxDevicesPerRun: 500,
  staleDeviceDays: 30,
};

export interface ResolvedDefenderConfig extends DefenderSettings {
  isActive: boolean;
  clientSecret: string | null;
  secretSource: 'env' | 'db' | null;
}

/** Vista pública de la configuración: nunca incluye el secreto. */
export interface DefenderConfigView extends DefenderSettings {
  isActive: boolean;
  hasClientSecret: boolean;
  secretSource: 'env' | 'db' | null;
  secretStorageAvailable: boolean;
}

/** Subconjunto documentado del recurso Machine de Defender for Endpoint. */
export interface DefenderMachine {
  id: string;
  computerDnsName?: string | null;
  osPlatform?: string | null;
  osVersion?: string | null;
  version?: string | null;
  osBuild?: number | null;
  machineTags?: string[] | null;
  rbacGroupName?: string | null;
  exposureLevel?: string | null;
  riskScore?: string | null;
  deviceValue?: string | null;
  lastIpAddress?: string | null;
  lastExternalIpAddress?: string | null;
  healthStatus?: string | null;
  onboardingStatus?: string | null;
  lastSeen?: string | null;
  aadDeviceId?: string | null;
}

/** Registro de /api/vulnerabilities/machinesVulnerabilities. */
export interface DefenderMachineVulnerability {
  id?: string;
  cveId: string;
  machineId: string;
  fixingKbId?: string | null;
  productName?: string | null;
  productVendor?: string | null;
  productVersion?: string | null;
  severity?: string | null;
}

/** Registro de /api/machines/SoftwareVulnerabilityChangesByMachine. */
export interface DefenderVulnerabilityChange {
  Id?: string;
  DeviceId: string;
  DeviceName?: string;
  CveId: string;
  SoftwareVendor?: string | null;
  SoftwareName?: string | null;
  SoftwareVersion?: string | null;
  VulnerabilitySeverityLevel?: string | null;
  CvssScore?: string | number | null;
  ExploitabilityLevel?: string | null;
  RecommendedSecurityUpdate?: string | null;
  RecommendedSecurityUpdateId?: string | null;
  DiskPaths?: string[] | null;
  RegistryPaths?: string[] | null;
  Status: 'New' | 'Fixed' | 'Updated' | string;
  EventTimestamp?: string;
  FirstSeenTimestamp?: string;
}

/** Hallazgo normalizado, independiente del endpoint de origen. */
export interface NormalizedFinding {
  cveId: string;
  productVendor: string;
  productName: string;
  productVersion: string;
  defenderSeverity: string | null;
  defenderCvss: number | null;
  exploitabilityLevel: string | null;
  fixingKbId: string | null;
  recommendedUpdate: string | null;
  diskPaths: string | null;
  registryPaths: string | null;
  firstSeenAt: Date | null;
}

export type SyncMode = 'full' | 'delta';
export type SyncRunStatus = 'queued' | 'running' | 'success' | 'partial' | 'error';
