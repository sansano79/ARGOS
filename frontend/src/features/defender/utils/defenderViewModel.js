export const splitList = (value) =>
  [...new Set(String(value || "").split(",").map((v) => v.trim()).filter(Boolean))];

export const joinList = (list) => (Array.isArray(list) ? list.join(", ") : "");

/** Configuración del API → valores del formulario (el secreto nunca viene del API). */
export const configToForm = (config) => ({
  isActive: config?.isActive !== false,
  tenantId: config?.tenantId || "",
  clientId: config?.clientId || "",
  clientSecret: "",
  baseUrl: config?.baseUrl || "https://eu.api.security.microsoft.com",
  serverTags: joinList(config?.serverTags ?? ["server"]),
  serverOsPlatforms: joinList(config?.serverOsPlatforms),
  teamId: config?.teamId ? String(config.teamId) : "",
  autoSyncEnabled: Boolean(config?.autoSyncEnabled),
  fullSyncIntervalHours: String(config?.fullSyncIntervalHours ?? 168),
  deltaSyncIntervalHours: String(config?.deltaSyncIntervalHours ?? 6),
  requestsPerMinute: String(config?.requestsPerMinute ?? 40),
  maxDevicesPerRun: String(config?.maxDevicesPerRun ?? 500),
  staleDeviceDays: String(config?.staleDeviceDays ?? 30),
});

/** Formulario → payload. El secreto solo se envía si se ha escrito uno nuevo. */
export const formToPayload = (form) => {
  const payload = {
    isActive: Boolean(form.isActive),
    tenantId: form.tenantId.trim(),
    clientId: form.clientId.trim(),
    baseUrl: form.baseUrl.trim(),
    serverTags: splitList(form.serverTags),
    serverOsPlatforms: splitList(form.serverOsPlatforms),
    autoSyncEnabled: Boolean(form.autoSyncEnabled),
    fullSyncIntervalHours: Number(form.fullSyncIntervalHours),
    deltaSyncIntervalHours: Number(form.deltaSyncIntervalHours),
    requestsPerMinute: Number(form.requestsPerMinute),
    maxDevicesPerRun: Number(form.maxDevicesPerRun),
    staleDeviceDays: Number(form.staleDeviceDays),
  };
  if (form.teamId) payload.teamId = Number(form.teamId);
  if (form.clientSecret.trim()) payload.clientSecret = form.clientSecret.trim();
  return payload;
};

export const validateConfigForm = (form) => {
  const errors = {};
  const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (form.tenantId.trim() && !guid.test(form.tenantId.trim())) errors.tenantId = "Debe ser un GUID";
  if (form.clientId.trim() && !guid.test(form.clientId.trim())) errors.clientId = "Debe ser un GUID";
  if (!splitList(form.serverTags).length && !splitList(form.serverOsPlatforms).length) {
    errors.serverTags = "Indica al menos un tag o una plataforma de SO";
  }
  const rpm = Number(form.requestsPerMinute);
  if (!Number.isInteger(rpm) || rpm < 1 || rpm > 45) errors.requestsPerMinute = "Entre 1 y 45 (límite Microsoft: 50/min)";
  return errors;
};

export const RUN_STATUS_META = {
  queued: { label: "En cola", tone: "info" },
  running: { label: "En curso", tone: "info" },
  success: { label: "Correcto", tone: "ok" },
  partial: { label: "Parcial", tone: "warn" },
  error: { label: "Error", tone: "crit" },
};

export const runStatusMeta = (status) => RUN_STATUS_META[status] || { label: status || "—", tone: "muted" };

export const isRunPending = (runs) => (runs || []).some((r) => r.status === "queued" || r.status === "running");

export const formatDuration = (ms) => {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return "—";
  if (n < 1000) return `${n} ms`;
  const s = Math.round(n / 1000);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  return `${m} min ${s % 60} s`;
};

export const formatDateTime = (value) => {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString("es-ES", { dateStyle: "short", timeStyle: "short" });
};

/** Orden por gravedad: KEV, luego exploit público, luego críticas, luego altas. */
export const deviceRiskSortKey = (device) => {
  const f = device?.openFindings || {};
  return [f.knownExploited || 0, f.publicExploit || 0, f.critical || 0, f.high || 0, f.total || 0];
};

export const sortDevicesByRisk = (devices) =>
  [...(devices || [])].sort((a, b) => {
    const ka = deviceRiskSortKey(a);
    const kb = deviceRiskSortKey(b);
    for (let i = 0; i < ka.length; i++) if (kb[i] !== ka[i]) return kb[i] - ka[i];
    return String(a.name || "").localeCompare(String(b.name || ""));
  });

export const summarizeDevices = (devices) =>
  (devices || []).reduce(
    (acc, d) => {
      const f = d.openFindings || {};
      acc.devices += 1;
      acc.findings += f.total || 0;
      acc.knownExploited += f.knownExploited || 0;
      acc.critical += f.critical || 0;
      if ((f.knownExploited || 0) > 0) acc.devicesWithKev += 1;
      return acc;
    },
    { devices: 0, findings: 0, knownExploited: 0, critical: 0, devicesWithKev: 0 },
  );

export const SEVERITY_TONE = { critical: "crit", high: "high", medium: "warn", low: "ok" };

export const severityTone = (severity) => SEVERITY_TONE[String(severity || "").toLowerCase()] || "muted";

export const exploitLabel = (finding) => {
  if (finding?.intelligence?.isKnownExploited) return "KEV";
  const level = finding?.exploitabilityLevel;
  if (level === "ExploitIsInKit") return "En kit";
  if (level === "ExploitIsVerified") return "Verificado";
  if (level === "ExploitIsPublic" || finding?.intelligence?.hasPublicExploit) return "Público";
  return "";
};

export const formatEpss = (value) => {
  const n = Number(value);
  if (value === null || value === undefined || !Number.isFinite(n)) return "—";
  return `${(n * 100).toFixed(1)}%`;
};
