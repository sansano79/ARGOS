export const NOTIFICATION_SETTINGS_TABS = [
  { id: "general", label: "General" },
  { id: "immediate", label: "Inmediatas" },
  { id: "digest", label: "Digest / Periódicas" },
  { id: "intelligent", label: "Inteligentes" },
  { id: "templates", label: "Plantillas" },
  { id: "recipients", label: "Destinatarios" },
  { id: "health", label: "Proceso y salud" },
];

export const DIGEST_INTERVAL_OPTIONS = [2, 4, 6, 8, 12, 24];

export const NOTIFICATION_JOB_LABELS = {
  immediate: "Inmediata",
  digest: "Digest",
  intelligent: "Inteligente",
};

export const createDefaultNotificationCenterState = () => ({
  general: {
    processEnabled: true,
    defaultChannel: "email",
    dedupeWindowHours: 24,
    retryBackoffMinutes: [5, 15, 30],
    activeTemplateKey: "normal_v2",
    smtpConfigured: false,
  },
  immediate: {
    enabled: true,
    minSeverity: "HIGH",
    minCvss: 8.5,
    minEpss: 0.2,
    minEpssPercentile: 0.8,
    kevOnly: false,
    publicExploitOnly: false,
    activeExploitationOnly: false,
    patchUnconfirmedOnly: false,
    newVulnerabilityOnly: true,
    onSeverityChange: true,
    onExploitChange: true,
    onPatchChange: true,
    onlySubscribedSystems: true,
    minConfidence: 0.6,
    minSources: 1,
    vendorFilters: [],
    productFilters: [],
    categoryFilters: [],
    exclusions: [],
  },
  digest: {
    enabled: true,
    intervalHours: 12,
    minSeverity: "MEDIUM",
    minCvss: 7,
    minEpss: 0,
    onlySubscribedSystems: true,
    minConfidence: 0.5,
    minSources: 1,
    vendorFilters: [],
    productFilters: [],
    categoryFilters: [],
    exclusions: [],
    groupingMode: "priority",
  },
  intelligent: {
    enabled: true,
    evaluationHour: 8,
    recentWindowHours: 24,
    contextWindowDays: 7,
    onlyWhenFinding: true,
    minConfidence: 0.65,
    scenarioFlags: {
      attackPath: true,
      campaignCluster: true,
      compoundRisk: true,
      postureChange: true,
    },
  },
  templates: {
    available: [],
    activeLegacyTemplateId: null,
    legacyTemplateConfigs: [],
  },
  recipients: {
    totalUsers: 0,
    enabledRecipients: 0,
    pausedRecipients: 0,
    admins: 0,
    viewers: 0,
    subscribers: 0,
  },
  processHealth: {
    enabled: true,
    smtpConfigured: false,
    queuePending: 0,
    retries: 0,
    lastSent: null,
    lastFailed: null,
    jobs: {},
    recentLogs: [],
  },
});

const ensureArray = (value) => Array.isArray(value) ? value : value == null ? [] : [value];
const normalizeStringList = (value) => {
  if (Array.isArray(value)) return value.map((item) => String(item || "").trim()).filter(Boolean);
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return [];
    try {
      return normalizeStringList(JSON.parse(trimmed));
    } catch {
      return trimmed.split(",").map((item) => item.trim()).filter(Boolean);
    }
  }
  return [];
};

export const normalizeNotificationCenterSettings = (value) => {
  const defaults = createDefaultNotificationCenterState();
  const input = value && typeof value === "object" ? value : {};
  return {
    ...defaults,
    ...input,
    general: {
      ...defaults.general,
      ...(input.general || {}),
      retryBackoffMinutes: ensureArray(input?.general?.retryBackoffMinutes ?? defaults.general.retryBackoffMinutes)
        .map((item) => Number(item))
        .filter((item) => Number.isFinite(item) && item > 0),
    },
    immediate: {
      ...defaults.immediate,
      ...(input.immediate || {}),
      vendorFilters: normalizeStringList(input?.immediate?.vendorFilters ?? defaults.immediate.vendorFilters),
      productFilters: normalizeStringList(input?.immediate?.productFilters ?? defaults.immediate.productFilters),
      categoryFilters: normalizeStringList(input?.immediate?.categoryFilters ?? defaults.immediate.categoryFilters),
      exclusions: normalizeStringList(input?.immediate?.exclusions ?? defaults.immediate.exclusions),
    },
    digest: {
      ...defaults.digest,
      ...(input.digest || {}),
      vendorFilters: normalizeStringList(input?.digest?.vendorFilters ?? defaults.digest.vendorFilters),
      productFilters: normalizeStringList(input?.digest?.productFilters ?? defaults.digest.productFilters),
      categoryFilters: normalizeStringList(input?.digest?.categoryFilters ?? defaults.digest.categoryFilters),
      exclusions: normalizeStringList(input?.digest?.exclusions ?? defaults.digest.exclusions),
    },
    intelligent: {
      ...defaults.intelligent,
      ...(input.intelligent || {}),
      scenarioFlags: {
        ...defaults.intelligent.scenarioFlags,
        ...((input.intelligent || {}).scenarioFlags || {}),
      },
    },
    templates: {
      ...defaults.templates,
      ...(input.templates || {}),
      available: Array.isArray(input?.templates?.available) ? input.templates.available : defaults.templates.available,
      legacyTemplateConfigs: Array.isArray(input?.templates?.legacyTemplateConfigs) ? input.templates.legacyTemplateConfigs : defaults.templates.legacyTemplateConfigs,
    },
    recipients: {
      ...defaults.recipients,
      ...(input.recipients || {}),
    },
    processHealth: {
      ...defaults.processHealth,
      ...(input.processHealth || {}),
      jobs: input?.processHealth?.jobs && typeof input.processHealth.jobs === "object" ? input.processHealth.jobs : defaults.processHealth.jobs,
      recentLogs: Array.isArray(input?.processHealth?.recentLogs) ? input.processHealth.recentLogs : defaults.processHealth.recentLogs,
    },
  };
};
