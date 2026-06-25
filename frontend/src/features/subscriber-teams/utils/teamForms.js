export const TEAM_CODE_PATTERN = /^[a-z0-9]+(?:[-_][a-z0-9]+)*$/;
export const MAX_TEXT_191 = 191;
export const TEAM_ROLE_OPTIONS = [
  { value: "TEAM_MANAGER", label: "Gestor del equipo" },
  { value: "TEAM_VIEWER", label: "Solo consulta" },
];
export const RECIPIENT_TYPE_OPTIONS = [
  { value: "USER", label: "Usuario" },
  { value: "MAILBOX", label: "Buzón" },
  { value: "DISTRIBUTION_LIST", label: "Lista de distribución" },
  { value: "EXTERNAL_CONTACT", label: "Contacto externo" },
];
export const LANGUAGE_OPTIONS = [
  { value: "es", label: "Español" },
  { value: "en", label: "English" },
];
export const TIMEZONE_OPTIONS = [
  "Europe/Madrid",
  "UTC",
  "Europe/London",
  "America/New_York",
];
export const ACTIVE_FILTER_OPTIONS = [
  { value: "all", label: "Todos" },
  { value: "active", label: "Activos" },
  { value: "inactive", label: "Inactivos" },
];
export const SYSTEM_RISK_OPTIONS = ["low", "medium", "high", "critical"];

const trim = (value) => String(value || "").trim();
const optionalTrim = (value) => {
  const normalized = trim(value);
  return normalized ? normalized : undefined;
};
const toLowerTrim = (value) => {
  const normalized = trim(value);
  return normalized ? normalized.toLowerCase() : undefined;
};
const parseBoolean = (value, fallback = true) => (value === undefined ? fallback : value === true);

export const splitCsvList = (value) => Array.from(
  new Set(
    String(value || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
  ),
);

export const joinCsvList = (value) => (Array.isArray(value) ? value.filter(Boolean).join(", ") : "");

export const createDefaultTeamForm = () => ({
  name: "",
  code: "",
  description: "",
  isActive: true,
});

export const createDefaultMemberForm = () => ({
  userId: "",
  role: "TEAM_MANAGER",
  isActive: true,
});

export const createDefaultRecipientForm = () => ({
  email: "",
  name: "",
  type: "MAILBOX",
  language: "es",
  timezone: "Europe/Madrid",
  isActive: true,
});

export const createDefaultSubscriptionForm = () => ({
  vendor: "",
  product: "",
  versionsText: "",
  isActive: true,
});

export const createDefaultSystemForm = () => ({
  name: "",
  externalId: "",
  source: "manual",
  hostname: "",
  fqdn: "",
  platform: "",
  osVersion: "",
  description: "",
  riskLevel: "",
  isSelected: true,
  isActive: true,
});

export const sanitizeTeamCode = (value) => trim(value).toLowerCase();

export const validateTeamForm = (form) => {
  const errors = {};
  const name = trim(form?.name);
  const code = sanitizeTeamCode(form?.code);

  if (!name) errors.name = "El nombre es obligatorio.";
  else if (name.length > MAX_TEXT_191) errors.name = "El nombre no puede superar 191 caracteres.";

  if (!code) errors.code = "El código es obligatorio.";
  else if (code.length > MAX_TEXT_191) errors.code = "El código no puede superar 191 caracteres.";
  else if (!TEAM_CODE_PATTERN.test(code)) {
    errors.code = "Usa letras minúsculas, números, guiones o guiones bajos.";
  }

  return errors;
};

export const validateMemberForm = (form) => {
  const errors = {};
  const userId = Number(form?.userId);
  const role = String(form?.role || "");

  if (!Number.isInteger(userId) || userId <= 0) {
    errors.userId = "Selecciona un usuario válido.";
  }
  if (!TEAM_ROLE_OPTIONS.some((option) => option.value === role)) {
    errors.role = "Selecciona un rol de equipo válido.";
  }

  return errors;
};

export const validateRecipientForm = (form) => {
  const errors = {};
  const email = trim(form?.email).toLowerCase();
  const language = trim(form?.language);
  const timezone = trim(form?.timezone);
  const type = String(form?.type || "");

  if (!email) errors.email = "El email es obligatorio.";
  else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.email = "Introduce un email válido.";

  if (trim(form?.name).length > MAX_TEXT_191) {
    errors.name = "El nombre no puede superar 191 caracteres.";
  }
  if (!RECIPIENT_TYPE_OPTIONS.some((option) => option.value === type)) {
    errors.type = "Selecciona un tipo de destinatario válido.";
  }
  if (!language) errors.language = "El idioma es obligatorio.";
  if (!timezone) errors.timezone = "La zona horaria es obligatoria.";

  return errors;
};

export const validateSubscriptionForm = (form) => {
  const errors = {};
  const vendor = trim(form?.vendor);
  const product = trim(form?.product);

  if (!vendor) errors.vendor = "El fabricante es obligatorio.";
  else if (vendor.length > MAX_TEXT_191) errors.vendor = "El fabricante no puede superar 191 caracteres.";

  if (!product) errors.product = "El producto es obligatorio.";
  else if (product.length > MAX_TEXT_191) errors.product = "El producto no puede superar 191 caracteres.";

  return errors;
};

export const validateSystemForm = (form) => {
  const errors = {};
  const fields191 = ["name", "externalId", "source", "hostname", "fqdn", "platform", "osVersion", "riskLevel"];
  const name = trim(form?.name);

  if (!name) errors.name = "El nombre es obligatorio.";

  fields191.forEach((field) => {
    const value = trim(form?.[field]);
    if (value && value.length > MAX_TEXT_191) {
      errors[field] = "Este campo no puede superar 191 caracteres.";
    }
  });

  return errors;
};

export const buildTeamPayload = (form) => ({
  name: trim(form?.name),
  code: sanitizeTeamCode(form?.code),
  ...(optionalTrim(form?.description) !== undefined && { description: optionalTrim(form?.description) }),
  isActive: parseBoolean(form?.isActive, true),
});

export const buildMemberPayload = (form) => ({
  userId: Number(form?.userId),
  role: String(form?.role || "TEAM_MANAGER"),
});

export const buildRecipientPayload = (form) => ({
  email: trim(form?.email).toLowerCase(),
  ...(optionalTrim(form?.name) !== undefined && { name: optionalTrim(form?.name) }),
  type: String(form?.type || "MAILBOX"),
  language: trim(form?.language || "es"),
  timezone: trim(form?.timezone || "Europe/Madrid"),
  isActive: parseBoolean(form?.isActive, true),
});

export const buildSubscriptionPayload = (form) => ({
  vendor: trim(form?.vendor).toLowerCase(),
  product: trim(form?.product).toLowerCase(),
  ...(splitCsvList(form?.versionsText).length > 0 && { versions: splitCsvList(form?.versionsText) }),
  isActive: parseBoolean(form?.isActive, true),
});

export const buildSystemPayload = (form) => ({
  name: trim(form?.name),
  ...(optionalTrim(form?.externalId) !== undefined && { externalId: optionalTrim(form?.externalId) }),
  ...(optionalTrim(form?.source) !== undefined && { source: optionalTrim(form?.source) }),
  ...(optionalTrim(form?.hostname) !== undefined && { hostname: toLowerTrim(form?.hostname) }),
  ...(optionalTrim(form?.fqdn) !== undefined && { fqdn: toLowerTrim(form?.fqdn) }),
  ...(optionalTrim(form?.platform) !== undefined && { platform: optionalTrim(form?.platform) }),
  ...(optionalTrim(form?.osVersion) !== undefined && { osVersion: optionalTrim(form?.osVersion) }),
  ...(optionalTrim(form?.description) !== undefined && { description: optionalTrim(form?.description) }),
  ...(optionalTrim(form?.riskLevel) !== undefined && { riskLevel: optionalTrim(form?.riskLevel) }),
  isSelected: parseBoolean(form?.isSelected, true),
  isActive: parseBoolean(form?.isActive, true),
});

export const buildSystemUpdatePayload = (form) => {
  const payload = buildSystemPayload(form);
  delete payload.source;
  return payload;
};
