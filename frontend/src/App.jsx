import { useState, useEffect, useCallback, useRef } from "react";
import occLogo from "./occ-visual-kit/assets/occ-favicon.svg";
import {
  ACCOUNT_PATH,
  DETAIL_VIEW,
  PORTAL_PATH,
  SUBSCRIBER_TEAMS_PATH,
  VULN_LIST_PATH,
  KEV_LIST_PATH,
  getDetailPathForView,
  getSubscriberTeamDetailPath,
  getListPathForView,
  isViewAllowedForRole,
  normalizeDetailSourceView,
  parseAppRoute,
} from "./utils/appNavigation.js";
import {
  REFERENCE_CATEGORY_META,
  extractReferenceAwareValue,
  groupVulnerabilityReferencesByCategory,
  inferNormalizedReferenceLabel,
  isReferenceUrl,
  normalizeVulnerabilityReferences,
} from "./utils/vulnerabilityReferences.js";
import {
  DIGEST_INTERVAL_OPTIONS,
  NOTIFICATION_JOB_LABELS,
  NOTIFICATION_SETTINGS_TABS,
  createDefaultNotificationCenterState,
  normalizeNotificationCenterSettings,
} from "./utils/notificationCenter.js";
import {
  USER_MANAGEMENT_NOTE,
  buildAssignableTeams,
  getEffectiveGlobalRoleForTeamAssignments,
  buildUserFormState,
  buildUserPayload,
  createDefaultTeamAssignment,
  getGlobalUserRoleLabel,
  shouldValidateTeamAssignments,
  validateTeamAssignments,
} from "./utils/userManagement.js";
import SubscriberTeamsPage from "./features/subscriber-teams/pages/SubscriberTeamsPage.jsx";
import SubscriberTeamDetailPage from "./features/subscriber-teams/pages/SubscriberTeamDetailPage.jsx";
import UserFormModal from "./features/users/components/UserFormModal.jsx";

// ─── Config ──────────────────────────────────────────────────────────────────
const API_BASE = "/api";
// ─── Auth helpers ────────────────────────────────────────────────────────────
const getToken = () => localStorage.getItem("occ_token");
const setToken = (t) => localStorage.setItem("occ_token", t);
const clearToken = () => { localStorage.removeItem("occ_token"); localStorage.removeItem("occ_user"); };
const getUser = () => { try { return JSON.parse(localStorage.getItem("occ_user")); } catch { return null; } };
const setUser = (u) => localStorage.setItem("occ_user", JSON.stringify(u));
const getResetTokenFromPath = () => {
  const m = window.location.pathname.match(/^\/reset-password\/([^/]+)$/);
  return m?.[1] ? decodeURIComponent(m[1]) : "";
};
const apiFetch = async (url, opts = {}) => {
  const token = getToken();
  const headers = { ...opts.headers };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (opts.body && typeof opts.body === "string") headers["Content-Type"] = "application/json";
  const res = await fetch(`${API_BASE}${url}`, { ...opts, headers });
  if (res.status === 401) { clearToken(); window.location.reload(); throw new Error("Unauthorized"); }
  return res;
};
const BACKFILL_ENDPOINTS = [
  "/vulnerabilities/nvd/backfill/lastmodified",
  "/vulnerability-collector/nvd/backfill/lastmodified",
];
const readResponsePayload = async (res) => {
  const raw = await res.text();
  if (!raw) return { raw: "", json: {} };
  try { return { raw, json: JSON.parse(raw) }; } catch { return { raw, json: {} }; }
};
const callBackfillApi = async (suffix, opts = {}) => {
  let lastErr = "";
  for (const base of BACKFILL_ENDPOINTS) {
    const path = `${base}${suffix}`;
    try {
      const res = await apiFetch(path, opts);
      const payload = await readResponsePayload(res);
      if (!res.ok) {
        const msg = payload.json?.message || payload.json?.error || payload.raw || `HTTP ${res.status}`;
        if (res.status === 404 || res.status === 405) {
          lastErr = `${path} no disponible (${res.status})`;
          continue;
        }
        if (res.status === 403) {
          throw new Error(`Necesitas rol ADMIN para esta acción [${res.status}]`);
        }
        throw new Error(`${msg} [${res.status}]`);
      }
      return payload.json;
    } catch (e) {
      lastErr = String(e?.message || e || "Error desconocido");
    }
  }
  throw new Error(lastErr || "No se pudo contactar con el endpoint de backfill");
};

// ─── SEIDOR Brand Colors ─────────────────────────────────────────────────────
const C = {
  navy: "#1e293b", navyDark: "#0f172a", navyDeep: "#020617", navyLight: "#334155",
  blue: "#2563eb", blueLight: "#60a5fa", bluePale: "#eff6ff", accent: "#06b6d4",
  white: "#FFFFFF", gray50: "#f8fafc", gray100: "#f1f5f9", gray200: "#e2e8f0",
  gray300: "#cbd5e1", gray400: "#94a3b8", gray500: "#64748b", gray600: "#475569",
  gray700: "#334155", text: "#0f172a",
  critical: "#dc2626", criticalBg: "#fef2f2", high: "#ea580c", highBg: "#fff7ed",
  medium: "#ca8a04", mediumBg: "#fefce8", low: "#16a34a", lowBg: "#f0fdf4",
  info: "#2563eb", infoBg: "#eff6ff",
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
const sevColor = (s) => ({ CRITICAL: C.critical, HIGH: C.high, MEDIUM: C.medium, LOW: C.low }[s] || C.gray500);
const sevBg = (s) => ({ CRITICAL: C.criticalBg, HIGH: C.highBg, MEDIUM: C.mediumBg, LOW: C.lowBg }[s] || C.gray100);
const timeAgo = (d) => { if (!d) return "-"; const s = Math.floor((Date.now() - new Date(d).getTime()) / 1000); if (s < 60) return `${s}s`; if (s < 3600) return `${Math.floor(s / 60)}m`; if (s < 86400) return `${Math.floor(s / 3600)}h`; return `${Math.floor(s / 86400)}d`; };
const fmtDate = (d) => d ? new Date(d).toLocaleString("es-ES", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" }) : "-";
const fmtEpss = (e) => e != null ? `${(parseFloat(e) * 100).toFixed(1)}%` : "-";
const fmtScore = (s) => s != null ? parseFloat(s).toFixed(1) : "-";
const fmtRiskScore = (s) => s != null ? `${Math.round(parseFloat(s))}` : "-";
const fmtMs = (ms) => ms ? `${(ms / 1000).toFixed(1)}s` : "-";
const parseMaybeJsonObject = (value) => {
  if (!value) return {};
  if (typeof value === "object") return value;
  if (typeof value === "string") {
    try { return JSON.parse(value); } catch { return {}; }
  }
  return {};
};
const ensureArray = (value) => Array.isArray(value) ? value : value == null ? [] : [value];
const hasValue = (value) => {
  if (value == null) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "string") return value.trim().length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
};
const normalizeFieldValue = (value) => {
  if (value == null) return null;
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  if (!trimmed) return null;
  try { return JSON.parse(trimmed); } catch { return value; }
};
const normalizeFieldList = (value) => {
  const normalized = normalizeFieldValue(value);
  if (normalized == null) return [];
  return Array.isArray(normalized) ? normalized.filter((item) => hasValue(item)) : [normalized];
};
const csvStringToList = (value) => String(value || "")
  .split(",")
  .map((item) => item.trim())
  .filter(Boolean);
const listToCsvString = (value) => (Array.isArray(value) ? value.filter(Boolean).join(", ") : "");
const yesNoUnknown = (value) => value === true ? "Sí" : value === false ? "No" : "No informado";
const fmtConfidence = (value) => value != null ? `${Math.round(parseFloat(value) * 100)}%` : "No informado";
const describePatchStatus = (value) => value === true ? "Parche disponible" : value === false ? "Sin parche confirmado" : "Estado de parche no informado";
const toSentence = (value) => String(value || "").replaceAll("_", " ").trim();
const summarizeTextValue = (value) => {
  if (value == null) return "-";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try { return JSON.stringify(value); } catch { return String(value); }
};
const isValidUrl = (value) => isReferenceUrl(value);
const riskTierMeta = (tier) => ({
  informational: { label: "Informational", bg: C.gray100, color: C.gray600, border: C.gray300 },
  monitor: { label: "Monitor", bg: C.infoBg, color: C.info, border: "#BFDBFE" },
  elevated: { label: "Elevated", bg: C.mediumBg, color: C.medium, border: "#FDE68A" },
  high: { label: "High", bg: C.highBg, color: C.high, border: "#FED7AA" },
  urgent: { label: "Urgent", bg: "#FDECEC", color: "#C2410C", border: "#FCA5A5" },
  emergency: { label: "Emergency", bg: C.criticalBg, color: C.critical, border: "#FCA5A5" },
}[String(tier || "").toLowerCase()] || { label: tier || "N/A", bg: C.gray100, color: C.gray600, border: C.gray300 });
const exploitStatusMeta = (status) => ({
  none: { label: "Sin evidencia", bg: C.gray100, color: C.gray600, border: C.gray300 },
  mention: { label: "Mención", bg: C.infoBg, color: C.info, border: "#BFDBFE" },
  poc: { label: "PoC", bg: C.highBg, color: C.high, border: "#FED7AA" },
  reliable_poc: { label: "PoC fiable", bg: "#FFF1E8", color: "#C2410C", border: "#FDBA74" },
  active_exploitation: { label: "Explotación activa", bg: C.criticalBg, color: C.critical, border: "#FCA5A5" },
}[String(status || "").toLowerCase()] || { label: status || "N/A", bg: C.gray100, color: C.gray600, border: C.gray300 });
const recordStatusMeta = (status) => ({
  published_basic: { label: "Base NVD", bg: C.gray100, color: C.gray600 },
  enriched_partial: { label: "Enriquecido parcial", bg: C.infoBg, color: C.info },
  enriched_full: { label: "Enriquecido completo", bg: C.lowBg, color: C.low },
}[String(status || "").toLowerCase()] || { label: status || "N/A", bg: C.gray100, color: C.gray600 });
const componentTypeMeta = (type) => ({
  application: { label: "Aplicación", bg: C.gray50, color: C.gray700, border: C.gray300 },
  library: { label: "Librería", bg: C.bluePale, color: C.navy, border: C.gray200 },
  framework: { label: "Framework", bg: C.infoBg, color: C.info, border: "#BFDBFE" },
  "os-package": { label: "Paquete SO", bg: C.mediumBg, color: C.medium, border: "#FDE68A" },
  "platform-context": { label: "Contexto / plataforma", bg: C.gray100, color: C.gray600, border: C.gray300 },
  unknown: { label: "Tipo no inferido", bg: C.gray100, color: C.gray500, border: C.gray300 },
}[String(type || "").toLowerCase()] || { label: toSentence(type || "unknown"), bg: C.gray100, color: C.gray600, border: C.gray300 });
const isUrgentRisk = (tier) => ["urgent", "emergency"].includes(String(tier || "").toLowerCase());
const hasUnknownPatch = (v) => v?.patchAvailable === false || (!v?.patchAvailable && !(ensureArray(v?.fixedVersions).length));
const getRowPriorityStyle = (v) => {
  if (String(v?.exploitStatus || "").toLowerCase() === "active_exploitation" || v?.isKnownExploited) {
    return { background: C.criticalBg, borderLeft: `3px solid ${C.critical}` };
  }
  if (isUrgentRisk(v?.operationalRiskTier)) {
    return { background: "#FFF8F1", borderLeft: `3px solid ${C.high}` };
  }
  if (hasUnknownPatch(v)) {
    return { background: "#FFFDF7", borderLeft: `3px solid ${C.medium}` };
  }
  return { background: "#fff", borderLeft: "3px solid transparent" };
};
const getChangeTypeLabel = (type) => ({
  nvd_ingestion: "Ingesta NVD",
  kev_enrichment: "Enriquecimiento KEV",
  epss_enrichment: "Enriquecimiento EPSS",
  exploit_enrichment: "Enriquecimiento Exploit",
  cveorg_ingestion: "Ingesta CVE.org",
  manual_update: "Actualización manual",
}[type] || toSentence(type));
const translateFieldName = (name) => ({
  affectedProductsDetailed: "Productos afectados",
  affectedProducts: "Productos afectados",
  cvssV31Score: "Puntuación CVSS",
  cvssV31Severity: "Severidad CVSS",
  epssScore: "Puntuación EPSS",
  epssPercentile: "Percentil EPSS",
  exploitStatus: "Estado de explotación",
  exploitConfidence: "Confianza de explotación",
  exploitReferences: "Referencias de explotación",
  operationalRiskScore: "Puntuación de riesgo",
  operationalRiskTier: "Nivel de riesgo",
  patchAvailable: "Parche disponible",
  recordStatus: "Estado del registro",
  description: "Descripción",
  summary: "Resumen",
  references: "Referencias",
  remediationInfo: "Información de remediación",
  vendorAdvisories: "Advisories del fabricante",
  isKnownExploited: "Explotación conocida (KEV)",
  hasPublicExploit: "Exploit público",
  dataConfidence: "Confianza del dato",
  sourceCount: "Número de fuentes",
}[name] || toSentence(name));
const normalizeSemanticToken = (value) => String(value || "")
  .trim()
  .toLowerCase()
  .replace(/[_\s-]+/g, " ");
const CONTEXT_TAG_PRIORITY = {
  "supply chain": 0,
  "github actions": 1,
  workflow: 2,
  "ci cd": 3,
};
const CATALOG_CONTEXTUAL_VENDORS = new Set([
  "github",
  "github actions",
  "github-actions",
  "gitlab",
  "bitbucket",
  "cert",
  "cisa",
  "mitre",
  "nvd",
  "nist",
  "cve",
  "ghsa",
]);
const productEntityKey = (value) => {
  const vendor = String(value?.vendor || "").trim().toLowerCase();
  const product = String(value?.product || "").trim().toLowerCase();
  return vendor && product ? `${vendor}::${product}` : "";
};
const getPreferredAffectedProducts = (v) => {
  const detailed = normalizeFieldList(v?.affectedProductsDetailed);
  if (detailed.length > 0) return detailed;
  return normalizeFieldList(v?.affectedProducts);
};
const getOperationalAffectedPairs = (v) => {
  const semantic = getSemanticSummary(v);
  const pairs = [];
  const seen = new Set();
  const pushPair = (vendor, product) => {
    const normalizedVendor = String(vendor || "").trim();
    const normalizedProduct = String(product || "").trim();
    if (!normalizedVendor || !normalizedProduct) return;
    const key = `${normalizedVendor.toLowerCase()}::${normalizedProduct.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    pairs.push({ vendor: normalizedVendor, product: normalizedProduct });
  };

  if (semantic.hasReliablePrimaryEntity && semantic.semanticPrimaryProduct) {
    pushPair(semantic.semanticPrimaryVendor, semantic.semanticPrimaryProduct);
  }

  getPreferredAffectedProducts(v).forEach((product) => {
    if (product && typeof product === "object") {
      pushPair(product.vendor, product.product);
    }
  });

  return pairs;
};
const sortContextTags = (tags) => normalizeFieldList(tags).sort((a, b) => {
  const aa = normalizeSemanticToken(a);
  const bb = normalizeSemanticToken(b);
  const pa = CONTEXT_TAG_PRIORITY[aa] ?? 99;
  const pb = CONTEXT_TAG_PRIORITY[bb] ?? 99;
  if (pa !== pb) return pa - pb;
  return aa.localeCompare(bb, "es");
});
const isContextualCatalogVendor = (value) => CATALOG_CONTEXTUAL_VENDORS.has(normalizeSemanticToken(value));
const getFallbackSemanticEntity = (v) => {
  const candidates = getPreferredAffectedProducts(v)
    .filter((item) => item && typeof item === "object")
    .map((item) => ({
      vendor: String(item.vendor || "").trim(),
      product: String(item.product || "").trim(),
      version: String(item.version || "").trim(),
      versionRange: String(item.versionRange || "").trim(),
      cpe: String(item.cpe || "").trim(),
    }))
    .filter((item) => item.product);

  if (candidates.length === 0) return null;

  const scored = candidates.map((item) => {
    const score =
      (item.vendor && !isContextualCatalogVendor(item.vendor) ? 4 : 0) +
      (item.version ? 1 : 0) +
      (item.versionRange ? 1 : 0) +
      (item.cpe ? 1 : 0);
    return { ...item, score };
  });

  scored.sort((a, b) => b.score - a.score || a.product.localeCompare(b.product, "es"));
  return scored[0];
};
const getSemanticSummary = (v) => {
  const contextTags = normalizeFieldList(v?.contextTags);
  const fallbackEntity = getFallbackSemanticEntity(v);
  const semanticPrimaryVendor = String(v?.semanticPrimaryVendor || "").trim() || (fallbackEntity?.vendor || "");
  const semanticPrimaryProduct = String(v?.semanticPrimaryProduct || "").trim() || (fallbackEntity?.product || "");
  const componentType = String(v?.componentType || v?.semanticComponentType || "unknown").toLowerCase();
  const hasReasonablyUsefulPrimary =
    semanticPrimaryProduct.length > 0 &&
    componentType !== "platform-context";
  const hasReliablePrimaryEntity =
    v?.hasReliablePrimaryEntity === true ||
    (semanticPrimaryVendor.length > 0 && semanticPrimaryProduct.length > 0) ||
    hasReasonablyUsefulPrimary;
  const displayTitle = hasReliablePrimaryEntity
    ? [semanticPrimaryVendor, semanticPrimaryProduct].filter(Boolean).join(" / ") || semanticPrimaryProduct
    : "Clasificación pendiente";

  return {
    semanticPrimaryVendor: semanticPrimaryVendor || null,
    semanticPrimaryProduct: semanticPrimaryProduct || null,
    componentType,
    contextTags,
    hasReliablePrimaryEntity,
    displayTitle,
    displaySubtitle: hasReliablePrimaryEntity
      ? componentTypeMeta(componentType).label
      : componentType !== "unknown" && semanticPrimaryProduct
        ? `${componentTypeMeta(componentType).label}: ${semanticPrimaryProduct}`
      : contextTags.length > 0
        ? `Contexto: ${contextTags.slice(0, 3).join(", ")}`
        : componentType !== "unknown"
          ? componentTypeMeta(componentType).label
          : "Se evita mostrar un vendor/producto engañoso",
  };
};
const getDisplayContextTags = ({ contextTags, riskSignals = [], tags = [] }) => {
  const blocked = new Set([
    ...normalizeFieldList(riskSignals).map((item) => normalizeSemanticToken(item)),
    ...ensureArray(tags).map((tag) => normalizeSemanticToken(tag?.name || tag)),
  ]);

  return sortContextTags(normalizeFieldList(contextTags).filter((tag) => {
    const normalized = normalizeSemanticToken(tag);
    return normalized && !blocked.has(normalized);
  }));
};
const getCompactContextTags = (tags, limit = 2) => sortContextTags(tags).slice(0, limit);
const sortKevModuleRows = (rows = []) => rows
  .map((row, index) => ({ row, index }))
  .sort((left, right) => {
    const a = left.row;
    const b = right.row;
    const exploitSignalA = a?.isKnownExploited ? 1 : 0;
    const exploitSignalB = b?.isKnownExploited ? 1 : 0;
    const riskComparison = compareNullableNumbers(b?.operationalRiskScore, a?.operationalRiskScore);
    const publicExploitComparison = compareNullableNumbers(b?.hasPublicExploit ? 1 : 0, a?.hasPublicExploit ? 1 : 0);
    const epssComparison = compareNullableNumbers(b?.epssScore, a?.epssScore);
    const cvssComparison = compareNullableNumbers(b?.cvssV31Score, a?.cvssV31Score);
    const updatedComparison = compareNullableDates(b?.lastModifiedAt, a?.lastModifiedAt);

    return (
      compareNullableNumbers(exploitSignalB, exploitSignalA)
      || riskComparison
      || publicExploitComparison
      || epssComparison
      || cvssComparison
      || updatedComparison
      || left.index - right.index
    );
  })
  .map(({ row }) => row);
const dedupeTextList = (values) => Array.from(new Set(
  ensureArray(values)
    .map((item) => String(item || "").trim())
    .filter(Boolean),
));
const inferReferenceLabel = ({ item, url, index }) => inferNormalizedReferenceLabel({ item, url, index });
const normalizeReferenceEntries = (value, options = {}) => {
  const normalized = normalizeVulnerabilityReferences(value, options);
  return {
    links: normalized.references,
    metadata: normalized.metadata,
  };
};
const groupReferenceLinksByCategory = (links = []) => groupVulnerabilityReferencesByCategory(links);
const splitDisplayProducts = (products, semantic) => {
  const primaryKey = semantic.hasReliablePrimaryEntity
    ? `${String(semantic.semanticPrimaryVendor || "").trim().toLowerCase()}::${String(semantic.semanticPrimaryProduct || "").trim().toLowerCase()}`
    : "";
  const normalized = normalizeFieldList(products);
  if (!primaryKey) {
    return { primaryProducts: [], otherProducts: normalized };
  }

  const primaryProducts = normalized.filter((item) => productEntityKey(item) === primaryKey);
  const otherProducts = normalized.filter((item) => productEntityKey(item) !== primaryKey);
  return { primaryProducts, otherProducts };
};

// ─── SVG Icons ───────────────────────────────────────────────────────────────
const I = ({ name, size = 18, color = "currentColor" }) => {
  const d = {
    shield: <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />,
    alert: <><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" fill="none" stroke={color} strokeWidth="1.5" /><line x1="12" y1="9" x2="12" y2="13" stroke={color} strokeWidth="1.5" /><circle cx="12" cy="17" r="0.5" fill={color} /></>,
    activity: <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />,
    download: <><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></>,
    refresh: <><polyline points="23 4 23 10 17 10" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></>,
    clock: <><circle cx="12" cy="12" r="10" fill="none" stroke={color} strokeWidth="1.5" /><polyline points="12 6 12 12 16 14" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" /></>,
    bug: <><path d="M8 2l1.88 1.88M14.12 3.88L16 2M9 7.13v-1a3 3 0 116 0v1M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 014-4h4a4 4 0 014 4v3c0 3.3-2.7 6-6 6zM12 20v-9M6.53 9C4.6 8.8 3 7.1 3 5M6 13H2M6 17H3M17.47 9C19.4 8.8 21 7.1 21 5M18 13h4M18 17h3" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></>,
    file: <><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" fill="none" stroke={color} strokeWidth="1.5" /><polyline points="14 2 14 8 20 8" fill="none" stroke={color} strokeWidth="1.5" /></>,
    check: <polyline points="20 6 9 17 4 12" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />,
    x: <><line x1="18" y1="6" x2="6" y2="18" stroke={color} strokeWidth="2" strokeLinecap="round" /><line x1="6" y1="6" x2="18" y2="18" stroke={color} strokeWidth="2" strokeLinecap="round" /></>,
    zap: <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />,
    server: <><rect x="2" y="2" width="20" height="8" rx="2" fill="none" stroke={color} strokeWidth="1.5" /><rect x="2" y="14" width="20" height="8" rx="2" fill="none" stroke={color} strokeWidth="1.5" /><circle cx="6" cy="6" r="0.5" fill={color} /><circle cx="6" cy="18" r="0.5" fill={color} /></>,
    search: <><circle cx="11" cy="11" r="8" fill="none" stroke={color} strokeWidth="1.5" /><line x1="21" y1="21" x2="16.65" y2="16.65" stroke={color} strokeWidth="1.5" strokeLinecap="round" /></>,
    users: <><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" fill="none" stroke={color} strokeWidth="1.5" /><circle cx="9" cy="7" r="4" fill="none" stroke={color} strokeWidth="1.5" /><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75" fill="none" stroke={color} strokeWidth="1.5" /></>,
    mail: <><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" fill="none" stroke={color} strokeWidth="1.5" /><polyline points="22 6 12 13 2 6" fill="none" stroke={color} strokeWidth="1.5" /></>,
    brain: <><path d="M12 2a4 4 0 014 4v1a3 3 0 013 3 3 3 0 01-1 5.83V17a4 4 0 01-4 4h-4a4 4 0 01-4-4v-1.17A3 3 0 015 10a3 3 0 013-3V6a4 4 0 014-4z" fill="none" stroke={color} strokeWidth="1.5" /><path d="M12 2v20M8 6h8" fill="none" stroke={color} strokeWidth="1" strokeLinecap="round" opacity="0.4" /></>,
    link: <><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" /><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" /></>,
    edit: <><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7" fill="none" stroke={color} strokeWidth="1.5" /><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z" fill="none" stroke={color} strokeWidth="1.5" /></>,
    plus: <><line x1="12" y1="5" x2="12" y2="19" stroke={color} strokeWidth="2" strokeLinecap="round" /><line x1="5" y1="12" x2="19" y2="12" stroke={color} strokeWidth="2" strokeLinecap="round" /></>,
    trash: <><polyline points="3 6 5 6 21 6" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" /><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" fill="none" stroke={color} strokeWidth="1.5" /></>,
    send: <><line x1="22" y1="2" x2="11" y2="13" stroke={color} strokeWidth="1.5" /><polygon points="22 2 15 22 11 13 2 9 22 2" fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" /></>,
    chevDown: <polyline points="6 9 12 15 18 9" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />,
    arrowRight: <><line x1="5" y1="12" x2="19" y2="12" stroke={color} strokeWidth="1.5" strokeLinecap="round" /><polyline points="12 5 19 12 12 19" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></>,
    settings: <><circle cx="12" cy="12" r="3" fill="none" stroke={color} strokeWidth="1.5" /><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z" fill="none" stroke={color} strokeWidth="1.5" /></>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" style={{ flexShrink: 0, display: "inline-block", verticalAlign: "middle" }}>{d[name]}</svg>;
};

// ─── Sub-Components ──────────────────────────────────────────────────────────
const SevBadge = ({ s, small }) => (
  <span style={{ display: "inline-flex", padding: small ? "1px 6px" : "2px 10px", borderRadius: 4, fontSize: small ? 9 : 9.5, fontWeight: 600, background: sevColor(s), color: "#fff", letterSpacing: "0.5px", fontFamily: "'JetBrains Mono', monospace" }}>{s}</span>
);

const SoftBadge = ({ label, bg = C.gray100, color = C.gray700, border = C.gray300, small }) => (
  <span style={{
    display: "inline-flex",
    alignItems: "center",
    padding: small ? "2px 7px" : "3px 8px",
    borderRadius: 5,
    fontSize: small ? 10 : 10.5,
    fontWeight: 600,
    background: bg,
    color,
    border: `1px solid ${border}`,
    lineHeight: 1.1,
  }}>{label}</span>
);

const RiskTierBadge = ({ tier, small }) => {
  const meta = riskTierMeta(tier);
  return <SoftBadge label={meta.label} bg={meta.bg} color={meta.color} border={meta.border} small={small} />;
};

const buildExploitContext = (detail) => {
  const lines = [];
  const vector = detail.cvssV31Vector || "";
  const avMatch = vector.match(/AV:([NALP])/);
  if (avMatch) {
    const avMap = { N: "red (Network)", A: "adyacente (Adjacent)", L: "local", P: "físico" };
    lines.push(`Vector de ataque: ${avMap[avMatch[1]] || avMatch[1]}`);
  }
  const acMatch = vector.match(/AC:([LH])/);
  if (acMatch) lines.push(`Complejidad: ${acMatch[1] === "L" ? "baja" : "alta"}`);
  const prMatch = vector.match(/PR:([NLH])/);
  if (prMatch) {
    const prMap = { N: "ninguno", L: "bajo", H: "alto" };
    lines.push(`Privilegios requeridos: ${prMap[prMatch[1]] || prMatch[1]}`);
  }
  const uiMatch = vector.match(/UI:([NR])/);
  if (uiMatch) lines.push(`Interacción del usuario: ${uiMatch[1] === "N" ? "no requerida" : "requerida"}`);
  if (detail.isKnownExploited) lines.push("Incluida en el catálogo CISA KEV de vulnerabilidades explotadas conocidas");
  if (detail.hasPublicExploit) lines.push("Existe exploit público disponible (PoC)");
  if (detail.exploitStatus === "active_exploitation") lines.push("Se ha confirmado explotación activa en entornos reales");
  return lines;
};

const ExploitStatusBadge = ({ status, small }) => {
  const meta = exploitStatusMeta(status);
  return <SoftBadge label={meta.label} bg={meta.bg} color={meta.color} border={meta.border} small={small} />;
};

const RecordStatusBadge = ({ status, small }) => {
  const meta = recordStatusMeta(status);
  return <SoftBadge label={meta.label} bg={meta.bg} color={meta.color} border={meta.bg} small={small} />;
};

const ComponentTypeBadge = ({ type, small }) => {
  const meta = componentTypeMeta(type);
  return <SoftBadge label={meta.label} bg={meta.bg} color={meta.color} border={meta.border} small={small} />;
};

const SignalPill = ({ signal }) => (
  <span style={{ display: "inline-flex", padding: "3px 8px", borderRadius: 5, fontSize: 10, fontWeight: 600, background: C.bluePale, color: C.navy, border: `1px solid ${C.gray200}` }}>
    {toSentence(signal)}
  </span>
);

const ContextTagPill = ({ tag, small }) => (
  <SoftBadge
    label={toSentence(tag)}
    bg={C.gray50}
    color={C.gray700}
    border={C.gray300}
    small={small}
  />
);

const SemanticCompactAffected = ({
  vuln,
  small = false,
  contextLimit = 2,
  pendingLabel = "Clasificación pendiente",
  showPendingNote = true,
}) => {
  const semantic = getSemanticSummary(vuln);
  const contextTags = getCompactContextTags(getDisplayContextTags({
    contextTags: semantic.contextTags,
    riskSignals: vuln?.riskSignals,
    tags: vuln?.tags,
  }), contextLimit);
  const title = semantic.hasReliablePrimaryEntity ? semantic.displayTitle : pendingLabel;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: small ? 4 : 6 }}>
      <div style={{ fontSize: small ? 11 : 12, fontWeight: 700, color: semantic.hasReliablePrimaryEntity ? C.text : C.gray600, lineHeight: 1.35 }}>
        {title}
      </div>
      <div style={{ display: "flex", gap: 4, flexWrap: "wrap", alignItems: "center" }}>
        <ComponentTypeBadge type={semantic.componentType} small={small} />
        {contextTags.map((tag) => <ContextTagPill key={tag} tag={tag} small={small} />)}
      </div>
      {!semantic.hasReliablePrimaryEntity && showPendingNote && (
        <div style={{ fontSize: small ? 10 : 11, color: C.gray500, lineHeight: 1.4 }}>
          {semantic.displaySubtitle}
        </div>
      )}
    </div>
  );
};

const Metric = ({ icon, label, value, sub, color = C.navy }) => (
  <div className="occ-panel" style={{ background: "#fff", borderRadius: 12, padding: "16px 18px", border: `1px solid ${C.gray200}`, position: "relative", overflow: "hidden" }}>
    <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: color }} />
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 2 }}>
      <span style={{ fontSize: 10, fontWeight: 600, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.04em" }}>{label}</span>
      <I name={icon} size={14} color={C.gray400} />
    </div>
    <div style={{ fontSize: 26, fontWeight: 800, color: C.text, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "-1px" }}>{value}</div>
    {sub && <div style={{ fontSize: 11, color: C.gray500, marginTop: 2 }}>{sub}</div>}
  </div>
);

const Bar = ({ label, count, total, color }) => {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 0" }}>
      <span style={{ width: 65, fontSize: 10, fontWeight: 700, color: C.gray600, textTransform: "uppercase" }}>{label}</span>
      <div style={{ flex: 1, height: 20, background: C.gray100, borderRadius: 3, overflow: "hidden", position: "relative" }}>
        <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 3, transition: "width 0.6s ease", minWidth: count > 0 ? 2 : 0 }} />
      </div>
      <span style={{ width: 32, textAlign: "right", fontSize: 11, fontWeight: 700, color: C.gray700, fontFamily: "monospace" }}>{count}</span>
    </div>
  );
};

const compareNullableNumbers = (a, b) => {
  const aa = Number.isFinite(Number(a)) ? Number(a) : null;
  const bb = Number.isFinite(Number(b)) ? Number(b) : null;
  if (aa == null && bb == null) return 0;
  if (aa == null) return 1;
  if (bb == null) return -1;
  return aa - bb;
};

const compareNullableDates = (a, b) => {
  const aa = a ? new Date(a).getTime() : NaN;
  const bb = b ? new Date(b).getTime() : NaN;
  const hasA = Number.isFinite(aa);
  const hasB = Number.isFinite(bb);
  if (!hasA && !hasB) return 0;
  if (!hasA) return 1;
  if (!hasB) return -1;
  return aa - bb;
};

const compareNullableText = (a, b) => {
  const aa = String(a || "").trim().toLocaleLowerCase("es");
  const bb = String(b || "").trim().toLocaleLowerCase("es");
  if (!aa && !bb) return 0;
  if (!aa) return 1;
  if (!bb) return -1;
  return aa.localeCompare(bb, "es", { sensitivity: "base" });
};

const RISK_TIER_SORT_ORDER = {
  informational: 0,
  monitor: 1,
  elevated: 2,
  high: 3,
  urgent: 4,
  emergency: 5,
};

const EXPLOIT_STATUS_SORT_ORDER = {
  none: 0,
  mention: 1,
  poc: 2,
  reliable_poc: 3,
  active_exploitation: 4,
};

const RECORD_STATUS_SORT_ORDER = {
  published_basic: 0,
  enriched_partial: 1,
  enriched_full: 2,
};

const getKevSortDirectionIndicator = (key, sortState) => {
  if (sortState.key !== key || sortState.direction === "default") return "↕";
  return sortState.direction === "asc" ? "↑" : "↓";
};

const Btn = ({ children, onClick, primary, danger, small, disabled, style: s = {} }) => (
  <button onClick={onClick} disabled={disabled} style={{
    display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 6,
    padding: small ? "5px 10px" : "8px 16px", fontSize: small ? 11 : 12.5, fontWeight: 600,
    borderRadius: 8, border: primary || danger ? "none" : `1px solid ${C.gray200}`,
    background: disabled ? C.gray300 : primary ? C.navy : danger ? C.critical : "#fff",
    color: primary || danger ? "#fff" : C.gray700,
    cursor: disabled ? "not-allowed" : "pointer", transition: "all 0.12s", ...s,
  }}>{children}</button>
);

const Input = ({ value, onChange, placeholder, icon, style: s = {} }) => (
  <div style={{ position: "relative", ...s }}>
    {icon && <span style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)" }}><I name={icon} size={16} color={C.gray400} /></span>}
    <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} style={{
      width: "100%", padding: icon ? "9px 12px 9px 38px" : "9px 12px", fontSize: 13,
      border: `1px solid ${C.gray200}`, borderRadius: 8, background: "#fff", color: C.text,
      outline: "none", transition: "border-color 0.12s, box-shadow 0.12s", boxSizing: "border-box",
    }} onFocus={e => { e.target.style.borderColor = C.blue; e.target.style.boxShadow = "0 0 0 3px rgba(37,99,235,0.08)"; }} onBlur={e => { e.target.style.borderColor = C.gray200; e.target.style.boxShadow = "none"; }} />
  </div>
);

const Card = ({ title, icon, action, children, noPad, style: s = {} }) => (
  <div className="occ-panel" style={{ background: "#fff", borderRadius: 12, border: `1px solid ${C.gray200}`, overflow: "hidden", ...s }}>
    {title && (
      <div style={{ padding: "12px 18px", borderBottom: `1px solid ${C.gray100}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {icon && <I name={icon} size={15} color={C.gray600} />}
          <span style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{title}</span>
        </div>
        {action}
      </div>
    )}
    {noPad ? children : <div style={{ padding: 18 }}>{children}</div>}
  </div>
);

const DetailBlock = ({ title, icon, children, style = {} }) => (
  <Card title={title} icon={icon} style={style}>
    {children}
  </Card>
);

const DetailList = ({ items, empty = "Sin datos disponibles" }) => {
  const values = ensureArray(items).filter((item) => hasValue(item));
  if (values.length === 0) return <div style={{ fontSize: 12, color: C.gray500 }}>{empty}</div>;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {values.map((item, idx) => {
        if (typeof item === "string" || typeof item === "number" || typeof item === "boolean") {
          return <div key={idx} style={{ fontSize: 12, color: C.gray700, lineHeight: 1.5 }}>{String(item)}</div>;
        }
        return (
          <div key={idx} style={{ fontSize: 11, color: C.gray700, background: C.gray50, border: `1px solid ${C.gray200}`, borderRadius: 8, padding: "8px 10px" }}>
            <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word", fontFamily: "inherit" }}>{JSON.stringify(item, null, 2)}</pre>
          </div>
        );
      })}
    </div>
  );
};

const KV = ({ label, value, tone }) => (
  <div style={{ padding: "10px 12px", borderRadius: 10, background: tone || C.gray50, border: `1px solid ${C.gray200}` }}>
    <div style={{ fontSize: 10, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 4 }}>{label}</div>
    <div style={{ fontSize: 12, color: C.gray700, fontWeight: 600, lineHeight: 1.4 }}>{value}</div>
  </div>
);

const RichValue = ({ value, empty = "Sin datos disponibles" }) => {
  const { references, metadata, residual } = extractReferenceAwareValue(value);
  const normalized = residual != null ? normalizeFieldValue(residual) : null;
  const hasReferences = references.length > 0 || metadata.length > 0;
  if (!hasValue(normalized) && !hasReferences) return <div style={{ fontSize: 12, color: C.gray500 }}>{empty}</div>;

  if (Array.isArray(normalized)) {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {hasReferences && (
          <ReferenceGrid
            references={references}
            metadata={metadata}
            empty={empty}
            accent={C.gray200}
          />
        )}
        {normalized.map((item, idx) => {
          if (typeof item === "string" || typeof item === "number" || typeof item === "boolean") {
            return <div key={idx} style={{ fontSize: 12, color: C.gray700, lineHeight: 1.5 }}>{String(item)}</div>;
          }
          const entries = Object.entries(item || {}).filter(([, itemValue]) => hasValue(itemValue));
          return (
            <div key={idx} style={{ padding: "10px 12px", borderRadius: 10, border: `1px solid ${C.gray200}`, background: C.gray50 }}>
              {entries.length === 0 ? (
                <div style={{ fontSize: 12, color: C.gray500 }}>Sin datos disponibles</div>
              ) : (
                <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 8 }}>
                  {entries.map(([key, itemValue]) => (
                    <KV key={key} label={toSentence(key)} value={summarizeTextValue(itemValue)} />
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  }

  if (typeof normalized === "object") {
    const entries = Object.entries(normalized).filter(([, itemValue]) => hasValue(itemValue));
    if (entries.length === 0 && hasReferences) {
      return <ReferenceGrid references={references} metadata={metadata} empty={empty} accent={C.gray200} />;
    }
    if (entries.length === 0) return <div style={{ fontSize: 12, color: C.gray500 }}>{empty}</div>;
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {hasReferences && (
          <ReferenceGrid
            references={references}
            metadata={metadata}
            empty={empty}
            accent={C.gray200}
          />
        )}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 8 }}>
          {entries.map(([key, itemValue]) => (
            <KV key={key} label={toSentence(key)} value={summarizeTextValue(itemValue)} />
          ))}
        </div>
      </div>
    );
  }

  if (hasReferences) {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <ReferenceGrid references={references} metadata={metadata} empty={empty} accent={C.gray200} />
        {hasValue(normalized) && (
          <div style={{ fontSize: 12, color: C.gray700, whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.6 }}>{String(normalized)}</div>
        )}
      </div>
    );
  }

  return <div style={{ fontSize: 12, color: C.gray700, whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.6 }}>{String(normalized)}</div>;
};

const ReferenceCard = ({ reference, accent = C.gray200, index = 0 }) => (
  <a
    href={reference.url}
    target="_blank"
    rel="noopener noreferrer"
    className="occ-ref-card"
    style={{
      display: "flex",
      alignItems: "center",
      gap: 8,
      flex: "1 1 200px",
      minWidth: 160,
      maxWidth: "100%",
      padding: "7px 10px",
      borderRadius: 8,
      border: `1px solid ${accent}`,
      background: "#fff",
      textDecoration: "none",
      color: C.navy,
      boxSizing: "border-box",
      position: "relative",
      fontSize: 11,
    }}
  >
    <I name="link" size={11} color={C.gray400} />
    <span style={{ fontWeight: 700, color: C.navy, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11 }}>
      {reference.label || inferReferenceLabel({ item: reference, url: reference.url, index })}
    </span>
    {(reference.source || reference.domain) && (
      <span style={{ fontSize: 9, color: C.gray500, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.5px", flexShrink: 0 }}>
        {reference.source || reference.domain}
      </span>
    )}
    <div className="occ-ref-tooltip">
      <div style={{ fontSize: 11, fontWeight: 700, color: "#E2E8F0", marginBottom: 4 }}>
        {reference.label || inferReferenceLabel({ item: reference, url: reference.url, index })}
      </div>
      {(reference.source || reference.domain) && (
        <div style={{ fontSize: 10, color: "#94A3B8", fontWeight: 600, textTransform: "uppercase", marginBottom: 6 }}>
          {reference.source || reference.domain}
        </div>
      )}
      <div style={{ fontSize: 10, color: "#93C5FD", wordBreak: "break-all", marginBottom: reference.tags?.length > 0 ? 6 : 0 }}>
        {reference.url}
      </div>
      {reference.tags?.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
          {reference.tags.slice(0, 5).map((tag) => (
            <span key={`${reference.url}-${tag}`} style={{ padding: "1px 6px", borderRadius: 4, background: "rgba(255,255,255,0.1)", fontSize: 9, color: "#CBD5E1", fontWeight: 600 }}>
              {toSentence(tag)}
            </span>
          ))}
        </div>
      )}
    </div>
  </a>
);

const ReferenceGrid = ({ references, metadata, empty = "Sin referencias disponibles", accent = C.gray200 }) => {
  if (references.length === 0 && metadata.length === 0) {
    return <div style={{ fontSize: 12, color: C.gray500 }}>{empty}</div>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {references.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
          {references.map((reference, idx) => (
            <ReferenceCard key={`${reference.url}-${idx}`} reference={reference} index={idx} accent={accent} />
          ))}
        </div>
      )}
      {metadata.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {metadata.map((text, idx) => (
            <div
              key={`${text}-${idx}`}
              style={{
                padding: "8px 10px",
                borderRadius: 8,
                border: `1px dashed ${C.gray300}`,
                background: C.gray50,
                fontSize: 11,
                color: C.gray600,
                lineHeight: 1.5,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {text}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const ReferencesSection = ({
  title,
  items,
  empty = "Sin referencias disponibles",
  accent = C.gray200,
  defaultLabel = "",
  defaultSource = "",
  defaultCategory = "",
  showTitle = true,
}) => {
  const normalized = normalizeVulnerabilityReferences(items, { defaultLabel, defaultSource, defaultCategory });
  if (normalized.references.length === 0 && normalized.metadata.length === 0) {
    return showTitle ? (
      <div>
        {title && <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 8 }}>{title}</div>}
        <div style={{ fontSize: 12, color: C.gray500 }}>{empty}</div>
      </div>
    ) : (
      <div style={{ fontSize: 12, color: C.gray500 }}>{empty}</div>
    );
  }
  return (
    <div>
      {title && <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 8 }}>{title}</div>}
      <ReferenceGrid references={normalized.references} metadata={normalized.metadata} empty={empty} accent={accent} />
    </div>
  );
};

const LinkList = ({ items, empty = "Sin referencias disponibles", accent = C.gray200, defaultLabel = "", defaultSource = "", defaultCategory = "" }) => (
  <ReferencesSection
    items={items}
    empty={empty}
    accent={accent}
    defaultLabel={defaultLabel}
    defaultSource={defaultSource}
    defaultCategory={defaultCategory}
    showTitle={false}
  />
);

const ProductDetailList = ({ items, primaryKey = "" }) => {
  const products = normalizeFieldList(items);
  if (products.length === 0) return <div style={{ fontSize: 12, color: C.gray500 }}>Sin detalle de productos afectados</div>;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {products.map((product, idx) => {
        if (typeof product === "string") {
          return <div key={idx} style={{ fontSize: 12, color: C.gray700 }}>{product}</div>;
        }

        return (
          <div key={idx} style={{ padding: "10px 12px", borderRadius: 10, border: `1px solid ${C.gray200}`, background: "#fff" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.navy }}>{product.vendor || "Vendor no informado"}</span>
              <span style={{ fontSize: 12, color: C.gray500 }}>/</span>
              <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{product.product || "Producto no informado"}</span>
              {primaryKey && productEntityKey(product) === primaryKey && <SoftBadge label="Principal" small bg={C.white} color={C.navy} border={C.gray300} />}
              {hasValue(product.version) && <SoftBadge label={`Versión ${product.version}`} small />}
              {hasValue(product.versionRange) && <SoftBadge label={String(product.versionRange)} small bg={C.gray50} color={C.gray700} border={C.gray300} />}
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {hasValue(product.cpe) && <SoftBadge label={String(product.cpe)} small bg={C.bluePale} color={C.navy} border={C.gray200} />}
              {hasValue(product.source) && <SoftBadge label={`Fuente ${product.source}`} small bg={C.gray50} color={C.gray700} border={C.gray300} />}
            </div>
          </div>
        );
      })}
    </div>
  );
};

const VisualBanner = () => (
  <div style={{
    height: 4,
    background: "linear-gradient(90deg, #1e3a5f 0%, #2563eb 35%, #06b6d4 70%, #1e3a5f 100%)",
    borderRadius: 2,
    margin: "20px 0 24px",
  }} aria-hidden="true" />
);

const PageHeader = ({ title, subtitle, actions }) => (
  <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20, gap: 16 }}>
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 700, color: C.text, margin: 0, letterSpacing: "-0.01em" }}>{title}</h1>
      {subtitle && <p style={{ color: C.gray500, fontSize: 12, margin: "4px 0 0", lineHeight: 1.4 }}>{subtitle}</p>}
    </div>
    {actions && <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>{actions}</div>}
  </div>
);

const TabBar = ({ tabs, active, onChange }) => (
  <div style={{ display: "flex", gap: 2, padding: 3, background: C.gray100, borderRadius: 10, marginBottom: 20, width: "fit-content" }}>
    {tabs.map(t => {
      const isActive = active === t.id;
      return (
        <button key={t.id} onClick={() => onChange(t.id)} style={{
          padding: "7px 16px", fontSize: 12, fontWeight: isActive ? 600 : 500,
          background: isActive ? "#fff" : "transparent",
          color: isActive ? C.text : C.gray500,
          border: "none", borderRadius: 8, cursor: "pointer",
          boxShadow: isActive ? "0 1px 3px rgba(0,0,0,0.08)" : "none",
          transition: "all 0.15s ease",
        }}>
          {t.label}
        </button>
      );
    })}
  </div>
);

// ─── Main Component ──────────────────────────────────────────────────────────
export default function VulnDashboard() {
  const initialResetToken = getResetTokenFromPath();
  const VULN_PAGE_LIMIT = 50;

  // Auth state
  const [isLoggedIn, setIsLoggedIn] = useState(!!getToken());
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPass, setLoginPass] = useState("");
  const [loginErr, setLoginErr] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);
  const [authMode, setAuthMode] = useState(initialResetToken ? "reset" : "login");
  const [mfaToken, setMfaToken] = useState("");
  const [mfaQr, setMfaQr] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaErr, setMfaErr] = useState("");
  const [mfaLoading, setMfaLoading] = useState(false);
  const [forgotEmail, setForgotEmail] = useState("");
  const [forgotErr, setForgotErr] = useState("");
  const [forgotMsg, setForgotMsg] = useState("");
  const [forgotLoading, setForgotLoading] = useState(false);
  const [resetToken, setResetToken] = useState(initialResetToken);
  const [tokenCheckLoading, setTokenCheckLoading] = useState(initialResetToken.length > 0);
  const [tokenValid, setTokenValid] = useState(false);
  const [resetPass, setResetPass] = useState("");
  const [resetConfirm, setResetConfirm] = useState("");
  const [resetErr, setResetErr] = useState("");
  const [resetMsg, setResetMsg] = useState("");
  const [resetLoading, setResetLoading] = useState(false);
  const [authProviders, setAuthProviders] = useState({ local: true, azureOidc: false, azureSaml: false });

  // Navigation
  const [view, setView] = useState("overview");
  const [collapsed, setCollapsed] = useState(false);
  const [subscriberTeamsRoute, setSubscriberTeamsRoute] = useState({ teamId: null });

  useEffect(() => {
    if (isLoggedIn) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(`${API_BASE}/auth/providers`);
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled) {
          setAuthProviders({
            local: true,
            azureOidc: Boolean(data?.azureOidc),
            azureSaml: Boolean(data?.azureSaml),
          });
        }
      } catch {
      }
    })();
    return () => { cancelled = true; };
  }, [isLoggedIn]);

  // Data from API
  const [dash, setDash] = useState({
    totalAll: 0,
    today: [],
    week: [],
    last30d: [],
    month: [],
    exploitablesLast30d: 0,
    topExploited: [],
    lastRun: null,
  });
  const [vulns, setVulns] = useState([]);
  const [vulnsTotal, setVulnsTotal] = useState(0);
  const [vulnsPage, setVulnsPage] = useState(1);
  const [vulnsHasMore, setVulnsHasMore] = useState(false);
  const [vulnsLoading, setVulnsLoading] = useState(false);
  const [vulnsLoadingMore, setVulnsLoadingMore] = useState(false);
  const [runs, setRuns] = useState([]);
  const [contacts, setContacts] = useState([]);
  const [reports, setReports] = useState([]);
  const [users, setUsers] = useState([]);
  const [userMgmtTeams, setUserMgmtTeams] = useState([]);
  const [subscriptionCatalog, setSubscriptionCatalog] = useState([]);
  const [portalProfile, setPortalProfile] = useState(null);
  const [portalSubscriptions, setPortalSubscriptions] = useState([]);
  const [portalVendors, setPortalVendors] = useState([]);
  const [portalActiveVendor, setPortalActiveVendor] = useState("");
  const [portalLoading, setPortalLoading] = useState(false);
  const [portalSaving, setPortalSaving] = useState(false);
  const [portalMsg, setPortalMsg] = useState(null);
  const [accountProfile, setAccountProfile] = useState(null);
  const [accountLoading, setAccountLoading] = useState(false);
  const [accountSaving, setAccountSaving] = useState(false);
  const [accountMsg, setAccountMsg] = useState(null);
  const [tags, setTags] = useState([]);
  const [notifHistory, setNotifHistory] = useState([]);
  const [notifDetail, setNotifDetail] = useState(null);
  const [notifMsg, setNotifMsg] = useState(null);
  const [templateConfig, setTemplateConfig] = useState({
    headerImageUrl: "",
    introMessage: "",
    showExploitProbability: true,
    showExploitExists: true,
    showAffectedSoftware: true,
    showDescription: true,
    showReferences: true,
    showPatchLink: true,
  });
  const [templateName, setTemplateName] = useState("Plantilla CVE");
  const [templateList, setTemplateList] = useState([]);
  const [selectedTemplateId, setSelectedTemplateId] = useState("");
  const [templateLoading, setTemplateLoading] = useState(false);
  const [templateSaving, setTemplateSaving] = useState(false);
  const [previewVulnId, setPreviewVulnId] = useState("");
  const [templatePreviewHtml, setTemplatePreviewHtml] = useState("");
  const [templatePreviewMeta, setTemplatePreviewMeta] = useState({ cveId: "", manufacturer: "" });
  const [templatePreviewLoading, setTemplatePreviewLoading] = useState(false);
  const [notificationSettingsTab, setNotificationSettingsTab] = useState("general");
  const [notificationCenterLoading, setNotificationCenterLoading] = useState(false);
  const [notificationCenterSaving, setNotificationCenterSaving] = useState(false);
  const [notificationCenterMsg, setNotificationCenterMsg] = useState(null);
  const [notificationProcessRunning, setNotificationProcessRunning] = useState("");
  const [notificationTestRunning, setNotificationTestRunning] = useState("");
  const [notificationOpsEmail, setNotificationOpsEmail] = useState("");
  const [notificationCenter, setNotificationCenter] = useState(createDefaultNotificationCenterState());
  const [intelligentTestOpen, setIntelligentTestOpen] = useState(false);
  const [intelligentTestForm, setIntelligentTestForm] = useState({
    subscriberId: "",
    mode: "dry_run",
    language: "es",
    primaryWindowHours: 24,
    recentContextDays: 7,
    historicalContextDays: 60,
    useRecentRealData: true,
    targetEmail: "",
  });
  const [intelligentTestResult, setIntelligentTestResult] = useState(null);
  const [intelligentTestHistory, setIntelligentTestHistory] = useState([]);
  const [manufacturers, setManufacturers] = useState([]);
  const [allManufacturers, setAllManufacturers] = useState([]);
  const [manufacturersCatalogMeta, setManufacturersCatalogMeta] = useState(null);
  const [selectedManufacturer, setSelectedManufacturer] = useState("");
  const [newManufacturerName, setNewManufacturerName] = useState("");
  const [newProductForm, setNewProductForm] = useState({ vendor: "", product: "", versions: "" });
  const [mergeForm, setMergeForm] = useState({ targetName: "", sourceNames: [] });
  const [manufacturersLoading, setManufacturersLoading] = useState(false);
  const [mfrSearch, setMfrSearch] = useState("");
  const [mfrTab, setMfrTab] = useState("catalog");
  const [mfrAliases, setMfrAliases] = useState(null);
  const [mfrAliasesLoading, setMfrAliasesLoading] = useState(false);
  const [mfrMsg, setMfrMsg] = useState(null);
  const loadManufacturers = async () => {
    setManufacturersLoading(true);
    try {
      const [operationalR, allR, metaR] = await Promise.all([
        apiFetch("/manufacturers"),
        apiFetch("/manufacturers?includeHidden=true"),
        apiFetch("/manufacturers/catalog-metadata"),
      ]);
      const data = await operationalR.json();
      const allData = await allR.json();
      const meta = await metaR.json();
      const list = Array.isArray(data) ? data : [];
      setManufacturers(list);
      setAllManufacturers(Array.isArray(allData) ? allData : []);
      setManufacturersCatalogMeta(meta && typeof meta === "object" ? meta : null);
      if ((!selectedManufacturer || !list.some((item) => item.name === selectedManufacturer)) && list.length > 0) {
        const preferred = list[0];
        if (preferred) setSelectedManufacturer(preferred.name);
      }
    } catch (e) { console.error(e); }
    finally { setManufacturersLoading(false); }
  };

  // Filters & search
  const [searchQ, setSearchQ] = useState("");
  const [searchType, setSearchType] = useState("all");
  const [searchTagId, setSearchTagId] = useState("");
  const [searchPublishedFrom, setSearchPublishedFrom] = useState("");
  const [searchPublishedTo, setSearchPublishedTo] = useState("");
  const [searchMinScore, setSearchMinScore] = useState("");
  const [searchExploit, setSearchExploit] = useState("all");
  const [searchSeverity, setSearchSeverity] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [riskTierFilter, setRiskTierFilter] = useState("");
  const [exploitStatusFilter, setExploitStatusFilter] = useState("");
  const [vendorFilter, setVendorFilter] = useState("");
  const [productFilter, setProductFilter] = useState("");
  const [changedSinceHoursFilter, setChangedSinceHoursFilter] = useState("");
  const [notificableFilter, setNotificableFilter] = useState("");
  const [notificadaFilter, setNotificadaFilter] = useState("");
  const [instantFilter, setInstantFilter] = useState("");
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [detailContext, setDetailContext] = useState({ sourceView: "vulns", cveId: "" });
  const [kevTableSort, setKevTableSort] = useState({ key: "default", direction: "default" });

  // Contacts CRUD
  const [editContact, setEditContact] = useState(null);
  const [showContactForm, setShowContactForm] = useState(false);

  // Users CRUD
  const [editUser, setEditUser] = useState(null);
  const [showUserForm, setShowUserForm] = useState(false);

  // Collector & Reports
  const [collecting, setCollecting] = useState(false);
  const [backfillJobId, setBackfillJobId] = useState(() => localStorage.getItem("occ_backfill_job_id") || "");
  const [backfillBusy, setBackfillBusy] = useState(false);
  const [backfillStatus, setBackfillStatus] = useState(null);
  const [backfillMsg, setBackfillMsg] = useState(null);
  const [generating, setGenerating] = useState(false);
  const [reportResult, setReportResult] = useState(null);
  const [reportHours, setReportHours] = useState("24");
  const [reportSev, setReportSev] = useState("MEDIUM");

  // AI
  const [aiQuery, setAiQuery] = useState("");
  const [aiMessages, setAiMessages] = useState([]);
  const [aiLoading, setAiLoading] = useState(false);

  // Settings
  const [settingsTab, setSettingsTab] = useState("smtp");
  const [now, setNow] = useState(Date.now());
  const [smtpConfig, setSmtpConfig] = useState({ host: "", port: "", user: "", pass: "", secure: false, from: "" });
  const [smtpLoading, setSmtpLoading] = useState(false);
  const [smtpSaving, setSmtpSaving] = useState(false);
  const [testEmail, setTestEmail] = useState("");
  const [testSending, setTestSending] = useState(false);
  const DEFAULT_AI_MODEL = "krith/qwen2.5-32b-instruct:IQ1_M";
  const [aiConfig, setAiConfig] = useState({ provider: "ollama", baseUrl: "", model: DEFAULT_AI_MODEL, source: "env" });
  const [aiModels, setAiModels] = useState([]);
  const [aiConfigLoading, setAiConfigLoading] = useState(false);
  const [aiConfigSaving, setAiConfigSaving] = useState(false);
  const [smtpMsg, setSmtpMsg] = useState(null);

  // Tags CRUD (consolidated)
  const [newTagName, setNewTagName] = useState("");
  const [newTagColor, setNewTagColor] = useState("#3B6CB5");

  // API Keys Management
  const [apiKeys, setApiKeys] = useState([]);
  const [apiKeysLoading, setApiKeysLoading] = useState(false);
  const [showApiKeyForm, setShowApiKeyForm] = useState(false);
  const [newApiKeyName, setNewApiKeyName] = useState("");
  const [newApiKeyScopes, setNewApiKeyScopes] = useState(["vulnerabilities:read", "products:read", "catalog:read", "collector:read", "reports:read"]);
  const [newApiKeyExpiry, setNewApiKeyExpiry] = useState("");
  const [apiKeyCreating, setApiKeyCreating] = useState(false);
  const [createdApiKey, setCreatedApiKey] = useState(null);
  const [apiKeyCopied, setApiKeyCopied] = useState(false);

  // Vulnerability Detail & Actions (consolidated)
  const [vulnDetail, setVulnDetail] = useState(null);
  const [vulnLoading, setVulnLoading] = useState(false);
  const [detailProductFilter, setDetailProductFilter] = useState("");
  const [detailExploitFilter, setDetailExploitFilter] = useState("");
  const [notifSending, setNotifSending] = useState(false);
  const [showNotifModal, setShowNotifModal] = useState(false);
  const [notifContactsLoading, setNotifContactsLoading] = useState(false);

  const aiEndRef = useRef(null);
  const validatedTokenRef = useRef("");
  const routeInitRef = useRef(false);

  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 30000); return () => clearInterval(t); }, []);
  useEffect(() => { aiEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [aiMessages]);
  useEffect(() => {
    const closePopovers = () => document.querySelectorAll(".occ-popover-wrap.occ-open").forEach((el) => el.classList.remove("occ-open"));
    document.addEventListener("click", closePopovers);
    return () => document.removeEventListener("click", closePopovers);
  }, []);

  useEffect(() => {
    const hash = String(window.location.hash || "");
    const m = hash.match(/(?:^#|[&#])token=([^&]+)/);
    if (!m?.[1]) return;
    const token = decodeURIComponent(m[1]);
    if (token) {
      setToken(token);
      window.history.replaceState({}, "", `${window.location.pathname}${window.location.search}`);
      apiFetch("/auth/profile")
        .then((r) => r.json())
        .then((u) => {
          if (u) setUser(u);
          setIsLoggedIn(true);
        })
        .catch(() => { clearToken(); });
    }
  }, []);

  useEffect(() => {
    if (view !== "collector") return undefined;
    if (!backfillJobId) return undefined;
    if ((backfillStatus?.job?.status || "").toUpperCase() !== "RUNNING") return undefined;
    const t = setInterval(() => {
      const jobId = String(backfillJobId || "").trim();
      if (!jobId) return;
      callBackfillApi(`/status/${encodeURIComponent(jobId)}`)
        .then((data) => {
          if (data && !data.error) setBackfillStatus(data);
        })
        .catch(() => undefined);
    }, 6000);
    return () => clearInterval(t);
  }, [view, backfillJobId, backfillStatus?.job?.status]);

  // Login handler
  const handleLogin = async (e) => {
    e.preventDefault(); setLoginErr(""); setLoginLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: loginEmail, password: loginPass }) });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        if (res.status === 502) throw new Error("API no disponible (502 Bad Gateway). Revisa el servicio occ-api.");
        throw new Error(d.message || "Login failed");
      }
      const data = await res.json();
      if (data?.mfaEnrollRequired) {
        setMfaErr("");
        setMfaCode("");
        setMfaQr("");
        setMfaToken(String(data.mfaToken || ""));
        setAuthMode("mfa-enroll");
        setMfaLoading(true);
        try {
          const setupRes = await fetch(`${API_BASE}/auth/mfa/setup`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mfaToken: String(data.mfaToken || "") }),
          });
          const setupData = await setupRes.json().catch(() => ({}));
          if (!setupRes.ok) throw new Error(setupData?.message || "No se pudo iniciar MFA");
          setMfaQr(String(setupData.qrDataUrl || ""));
        } finally {
          setMfaLoading(false);
        }
        return;
      }
      if (data?.mfaRequired) {
        setMfaErr("");
        setMfaCode("");
        setMfaToken(String(data.mfaToken || ""));
        setAuthMode("mfa");
        return;
      }
      setToken(data.access_token); setUser(data.user); setIsLoggedIn(true);
    } catch (e) {
      const msg = String(e?.message || "");
      if (msg.toLowerCase().includes("failed to fetch")) {
        setLoginErr("No se pudo conectar con la API. Verifica que backend/proxy estén levantados.");
      } else {
        setLoginErr(msg || "Error de autenticación");
      }
    }
    setLoginLoading(false);
  };

  const handleMfaEnroll = async (e) => {
    e.preventDefault();
    setMfaErr("");
    setMfaLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/mfa/enroll`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mfaToken, code: mfaCode }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.message || "No se pudo activar MFA");
      setToken(data.access_token); setUser(data.user); setIsLoggedIn(true);
      setAuthMode("login");
      setMfaToken("");
      setMfaCode("");
    } catch (e) {
      setMfaErr(String(e?.message || "Código inválido"));
    } finally {
      setMfaLoading(false);
    }
  };

  const handleMfaVerify = async (e) => {
    e.preventDefault();
    setMfaErr("");
    setMfaLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/mfa/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mfaToken, code: mfaCode }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.message || "No se pudo verificar MFA");
      setToken(data.access_token); setUser(data.user); setIsLoggedIn(true);
      setAuthMode("login");
      setMfaToken("");
      setMfaCode("");
    } catch (e) {
      setMfaErr(String(e?.message || "Código inválido"));
    } finally {
      setMfaLoading(false);
    }
  };
  const handleLogout = () => { clearToken(); setIsLoggedIn(false); };

  const validateResetToken = useCallback(async (token) => {
    if (!token) {
      setTokenValid(false);
      setTokenCheckLoading(false);
      return;
    }
    setTokenCheckLoading(true);
    setResetErr("");
    setResetMsg("");
    try {
      const res = await fetch(`${API_BASE}/auth/reset-password/${encodeURIComponent(token)}`);
      if (!res.ok) throw new Error("No se pudo validar el enlace");
      const data = await res.json();
      setTokenValid(!!data?.valid);
      if (data?.email) setLoginEmail(String(data.email));
      if (!data?.valid) setResetErr("El enlace de recuperación es inválido o ha expirado.");
    } catch {
      setTokenValid(false);
      setResetErr("No se pudo validar el enlace. Intenta solicitar uno nuevo.");
    } finally {
      setTokenCheckLoading(false);
    }
  }, []);

  const handleForgotPassword = async (e) => {
    e.preventDefault();
    setForgotErr("");
    setForgotMsg("");
    setForgotLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: forgotEmail.trim().toLowerCase() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.message || "No se pudo procesar la solicitud");
      setForgotMsg(data?.message || "Si el correo está registrado, recibirás un enlace de recuperación en breve.");
    } catch (e) {
      setForgotErr(e.message || "Error solicitando recuperación");
    } finally {
      setForgotLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setResetErr("");
    setResetMsg("");

    if (resetPass !== resetConfirm) {
      setResetErr("Las contraseñas no coinciden.");
      return;
    }
    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/.test(resetPass)) {
      setResetErr("La contraseña debe tener mínimo 8 caracteres, mayúscula, minúscula y número.");
      return;
    }

    setResetLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/update-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: resetToken, password: resetPass }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.message || "No se pudo actualizar la contraseña");
      setResetMsg(data?.message || "La contraseña se actualizó correctamente.");
      setResetPass("");
      setResetConfirm("");
      setTokenValid(false);
      window.history.replaceState({}, "", "/");
      setTimeout(() => {
        setAuthMode("login");
      }, 1200);
    } catch (e) {
      setResetErr(e.message || "Error al actualizar la contraseña");
    } finally {
      setResetLoading(false);
    }
  };

  useEffect(() => {
    if (isLoggedIn || authMode !== "reset" || !resetToken) return;
    if (validatedTokenRef.current === resetToken) return;
    validatedTokenRef.current = resetToken;
    validateResetToken(resetToken);
  }, [authMode, isLoggedIn, resetToken, validateResetToken]);

  useEffect(() => {
    if (view === "search") {
      setView("vulns");
    }
  }, [view]);

  useEffect(() => {
    if (!isLoggedIn) return;
    const role = (getUser()?.role || "").toUpperCase();
    if (!isViewAllowedForRole(role, view)) {
      setView("vulns");
    }
  }, [isLoggedIn, view]);

  // Load data when view changes
  const loadVulnerabilityExplorer = useCallback(async ({ page = 1, append = false } = {}) => {
    const params = new URLSearchParams();
    params.set("page", String(page));
    params.set("limit", String(VULN_PAGE_LIMIT));
    if (sevFilter) params.set("severity", sevFilter);
    if (riskTierFilter) params.set("riskTier", riskTierFilter);
    if (exploitStatusFilter) params.set("exploitStatus", exploitStatusFilter);
    if (vendorFilter.trim()) params.set("vendor", vendorFilter.trim().toLowerCase());
    if (productFilter.trim()) params.set("product", productFilter.trim().toLowerCase());
    if (changedSinceHoursFilter) params.set("changedSinceHours", changedSinceHoursFilter);
    // Server-side search filters
    if (searchQ.trim().length >= 2) params.set("search", searchQ.trim());
    if (searchTagId) params.set("tag", searchTagId);
    if (searchMinScore) { const n = parseFloat(searchMinScore); if (!Number.isNaN(n)) params.set("minCvss", String(n)); }
    if (searchPublishedFrom) params.set("publishedFrom", searchPublishedFrom);
    if (searchPublishedTo) params.set("publishedTo", searchPublishedTo);
    if (notificableFilter) params.set("notificable", notificableFilter);
    if (notificadaFilter) params.set("notificada", notificadaFilter);

    if (append) setVulnsLoadingMore(true);
    else setVulnsLoading(true);

    try {
      const [vulnsR, tagsR] = await Promise.all([
        apiFetch(`/vulnerabilities?${params.toString()}`),
        apiFetch("/tags"),
      ]);
      const vulnData = await vulnsR.json();
      const nextRows = Array.isArray(vulnData?.data) ? vulnData.data : [];
      const total = Number(vulnData?.total || 0);
      const limit = Number(vulnData?.limit || VULN_PAGE_LIMIT);

      setVulns((prev) => append ? [...prev, ...nextRows] : nextRows);
      setVulnsTotal(total);
      setVulnsPage(page);
      setVulnsHasMore(page * limit < total);

      const tagsData = await tagsR.json();
      setTags(Array.isArray(tagsData) ? tagsData : []);
    } finally {
      setVulnsLoading(false);
      setVulnsLoadingMore(false);
    }
  }, [VULN_PAGE_LIMIT, sevFilter, riskTierFilter, exploitStatusFilter, vendorFilter, productFilter, changedSinceHoursFilter, searchQ, searchTagId, searchMinScore, searchPublishedFrom, searchPublishedTo, notificableFilter, notificadaFilter]);

  const loadSubscriberPortal = useCallback(async () => {
    setPortalLoading(true);
    try {
      const [profileR, catalogR] = await Promise.all([
        apiFetch("/subscriber-portal/profile"),
        apiFetch("/subscriber-portal/subscription-catalog"),
      ]);
      const profile = await profileR.json();
      const catalog = await catalogR.json();
      const subs = Array.isArray(profile?.subscriptions)
        ? profile.subscriptions.map((s) => ({
          vendor: String(s.vendor || "").toLowerCase(),
          product: String(s.product || "").toLowerCase(),
          versions: Array.isArray(s.versions) ? s.versions : [],
        }))
        : [];
      setPortalProfile(profile || null);
      setPortalSubscriptions(subs);
      const vendors = [...new Set(subs.map((s) => s.vendor))];
      setPortalVendors(vendors);
      setPortalActiveVendor(vendors[0] || (Array.isArray(catalog) ? String(catalog[0]?.vendor || "").toLowerCase() : ""));
      setSubscriptionCatalog(Array.isArray(catalog) ? catalog.map((v) => ({
        vendor: String(v.vendor || "").toLowerCase(),
        products: Array.isArray(v.products) ? v.products.map((p) => ({
          product: String(p.product || "").toLowerCase(),
          versions: Array.isArray(p.versions) ? p.versions : [],
        })) : [],
      })) : []);
    } finally {
      setPortalLoading(false);
    }
  }, []);

  const togglePortalVendorSelection = (vendor, checked) => {
    const normalizedVendor = String(vendor || "").toLowerCase();
    if (checked) {
      setPortalVendors((prev) => prev.includes(normalizedVendor) ? prev : [...prev, normalizedVendor]);
      setPortalActiveVendor(normalizedVendor);
      // Auto-select all products from this vendor
      const catalogEntry = subscriptionCatalog.find(v => v.vendor === normalizedVendor);
      if (catalogEntry?.products?.length) {
        setPortalSubscriptions((prev) => {
          const current = Array.isArray(prev) ? prev : [];
          const existing = new Set(current.filter(s => s.vendor === normalizedVendor).map(s => s.product));
          const newSubs = catalogEntry.products
            .filter(p => !existing.has(String(p.product || "").toLowerCase()))
            .map(p => ({ vendor: normalizedVendor, product: String(p.product || "").toLowerCase(), versions: [] }));
          return [...current, ...newSubs];
        });
      }
      return;
    }
    setPortalVendors((prev) => {
      const next = prev.filter((v) => v !== normalizedVendor);
      setPortalActiveVendor((active) => active === normalizedVendor ? (next[0] || "") : active);
      return next;
    });
    setPortalSubscriptions((prev) => (prev || []).filter((s) => s.vendor !== normalizedVendor));
  };

  const togglePortalProductSubscription = (vendor, product, checked) => {
    const normalizedVendor = String(vendor || "").toLowerCase();
    const normalizedProduct = String(product || "").toLowerCase();
    setPortalSubscriptions((prev) => {
      const current = Array.isArray(prev) ? prev : [];
      const exists = current.find((s) => s.vendor === normalizedVendor && s.product === normalizedProduct);
      if (checked && !exists) return [...current, { vendor: normalizedVendor, product: normalizedProduct, versions: [] }];
      if (!checked && exists) return current.filter((s) => !(s.vendor === normalizedVendor && s.product === normalizedProduct));
      return current;
    });
    if (checked) {
      setPortalVendors((prev) => prev.includes(normalizedVendor) ? prev : [...prev, normalizedVendor]);
      setPortalActiveVendor(normalizedVendor);
    }
  };

  const togglePortalSubscriptionVersion = (vendor, product, version, checked) => {
    const normalizedVendor = String(vendor || "").toLowerCase();
    const normalizedProduct = String(product || "").toLowerCase();
    const ver = String(version || "").trim();
    if (!ver) return;
    setPortalSubscriptions((prev) => (prev || []).map((s) => {
      if (s.vendor !== normalizedVendor || s.product !== normalizedProduct) return s;
      const currentVersions = Array.isArray(s.versions) ? s.versions : [];
      const nextVersions = checked
        ? [...new Set([...currentVersions, ver])]
        : currentVersions.filter((v) => v !== ver);
      return { ...s, versions: nextVersions };
    }));
  };

  const savePortalSubscriptions = async () => {
    setPortalSaving(true);
    setPortalMsg(null);
    try {
      const payload = {
        subscriptions: (portalSubscriptions || []).map((s) => ({
          vendor: s.vendor,
          product: s.product,
          versions: Array.isArray(s.versions) ? s.versions : [],
        })),
      };
      const res = await apiFetch("/subscriber-portal/subscriptions", {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const data = await readResponsePayload(res);
        const msg = data?.json?.message || data?.json?.error || data?.raw || "No se pudo guardar la suscripción";
        throw new Error(msg);
      }
      const updated = await res.json();
      setPortalProfile(updated || null);
      const subs = Array.isArray(updated?.subscriptions)
        ? updated.subscriptions.map((s) => ({
          vendor: String(s.vendor || "").toLowerCase(),
          product: String(s.product || "").toLowerCase(),
          versions: Array.isArray(s.versions) ? s.versions : [],
        }))
        : [];
      setPortalSubscriptions(subs);
      setPortalVendors([...new Set(subs.map((s) => s.vendor))]);
      setPortalMsg({ type: "success", text: "Suscripción guardada correctamente" });
      setTimeout(() => setPortalMsg(null), 3000);
    } catch (e) {
      setPortalMsg({ type: "error", text: e.message || "Error guardando la suscripción" });
      setTimeout(() => setPortalMsg(null), 3500);
    } finally {
      setPortalSaving(false);
    }
  };

  const loadData = useCallback(async (v) => {
    try {
      if (v === "overview") {
        const r = await apiFetch("/vulnerabilities/dashboard"); setDash(await r.json());
      } else if (v === "account") {
        setAccountLoading(true);
        try {
          const r = await apiFetch("/auth/me");
          const d = await r.json();
          if (d && typeof d === "object" && !d.statusCode) {
            setAccountProfile(d);
            setUser({
              id: d.id,
              email: d.email,
              name: d.name,
              role: d.role,
              isSubscriber: d.isSubscriber,
              authProvider: d.authProvider,
              communicationLanguage: d.communicationLanguage || "es",
            });
          } else {
            setAccountProfile(null);
          }
        } finally {
          setAccountLoading(false);
        }
      } else if (v === "vulns" || v === "search") {
        await loadVulnerabilityExplorer({ page: 1, append: false });
      } else if (v === "exploited") {
        const params = new URLSearchParams();
        params.set("limit", "100");
        if (v === "exploited") {
          params.set("exploited", "true");
        }
        const q = `?${params.toString()}`;
        const r = await apiFetch(`/vulnerabilities${q}`); const d = await r.json(); setVulns(d.data || []); setVulnsTotal(d.total || 0);
      } else if (v === "contacts") {
        const r = await apiFetch("/users"); const allUsers = await r.json();
        setContacts((Array.isArray(allUsers) ? allUsers : []).filter(u => u.isSubscriber));
      } else if (v === "reports") {
        const r = await apiFetch("/vulnerabilities/reports"); const d = await r.json(); setReports(d.data || []);
      } else if (v === "portal") {
        await loadSubscriberPortal();
      } else if (v === "user-mgmt") {
        const [usersRes, teamsRes] = await Promise.allSettled([
          apiFetch("/users"),
          apiFetch("/subscriber-teams"),
        ]);
        if (usersRes.status === "fulfilled") {
          const json = await usersRes.value.json();
          setUsers(Array.isArray(json) ? json : []);
        }
        if (teamsRes.status === "fulfilled") {
          const json = await teamsRes.value.json();
          setUserMgmtTeams(Array.isArray(json) ? json : []);
        }
      } else if (v === "collector") {
        const [runsR, dashR] = await Promise.all([
          apiFetch("/vulnerabilities/runs?limit=30"),
          apiFetch("/vulnerabilities/dashboard"),
        ]);
        const runsData = await runsR.json();
        const dashData = await dashR.json();
        setRuns(Array.isArray(runsData) ? runsData : (Array.isArray(runsData?.data) ? runsData.data : []));
        setDash(dashData || {
          totalAll: 0,
          today: [],
          week: [],
          last30d: [],
          month: [],
          exploitablesLast30d: 0,
          topExploited: [],
          lastRun: null,
        });
        if (backfillJobId) {
          try {
            const statusData = await callBackfillApi(`/status/${encodeURIComponent(backfillJobId)}`);
            if (!statusData?.error) {
              setBackfillStatus(statusData);
            } else {
              setBackfillStatus(null);
            }
          } catch {
            setBackfillStatus(null);
          }
        }
      } else if (v === "manufacturers") {
        setManufacturersLoading(true);
        const [operationalR, allR, metaR] = await Promise.all([
          apiFetch("/manufacturers"),
          apiFetch("/manufacturers?includeHidden=true"),
          apiFetch("/manufacturers/catalog-metadata"),
        ]);
        const data = await operationalR.json();
        const allData = await allR.json();
        const meta = await metaR.json();
        const list = Array.isArray(data) ? data : [];
        setManufacturers(list);
        setAllManufacturers(Array.isArray(allData) ? allData : []);
        setManufacturersCatalogMeta(meta && typeof meta === "object" ? meta : null);
        const preferred = list[0];
        if (!selectedManufacturer && preferred) {
          setSelectedManufacturer(preferred.name);
          setMergeForm({ targetName: preferred.name, sourceNames: [preferred.name] });
        }
        setManufacturersLoading(false);
      } else if (v === "settings") {
        setSmtpLoading(true);
        try {
          const smtpR = await apiFetch("/notifications/config");
          const smtpD = await smtpR.json();
          if (smtpD) setSmtpConfig({ ...smtpD, pass: "" });
        } finally {
          setSmtpLoading(false);
        }

        const [tagsRes] = await Promise.allSettled([
          apiFetch("/tags").then(r => r.json()),
        ]);

        if (tagsRes.status === "fulfilled") {
          setTags(Array.isArray(tagsRes.value) ? tagsRes.value : []);
        }

        // Load API keys
        setApiKeysLoading(true);
        apiFetch("/api-keys").then(r => r.json()).then(d => setApiKeys(Array.isArray(d) ? d : [])).catch(() => {}).finally(() => setApiKeysLoading(false));

        setAiConfigLoading(true);
        const [aiConfigRes, aiModelsRes] = await Promise.allSettled([
          apiFetch("/ai/config").then(r => r.json()),
          apiFetch("/ai/models").then(r => r.json()),
        ]);
        if (aiConfigRes.status === "fulfilled" && aiConfigRes.value) {
          setAiConfig({
            provider: aiConfigRes.value.provider || "ollama",
            baseUrl: aiConfigRes.value.baseUrl || "",
            model: aiConfigRes.value.model || DEFAULT_AI_MODEL,
            source: aiConfigRes.value.source || "env",
          });
        }
        if (aiModelsRes.status === "fulfilled") {
          const models = Array.isArray(aiModelsRes.value?.models) ? aiModelsRes.value.models : [];
          setAiModels(models);
        }
        setAiConfigLoading(false);
        if (settingsTab === "notifications") {
          setNotificationCenterLoading(true);
          const [centerRes, usersRes, templateRes, vulnsRes, intelligentTestsRes] = await Promise.allSettled([
            apiFetch("/notifications/settings-center").then(r => r.json()),
            apiFetch("/users").then(r => r.json()),
            apiFetch("/notifications/template-config").then(r => r.json()),
            apiFetch("/vulnerabilities?limit=300").then(r => r.json()),
            apiFetch("/smart-notifications/intelligent/test-history?limit=12").then(r => r.json()),
          ]);
          if (centerRes.status === "fulfilled") {
            const normalized = normalizeNotificationCenterSettings(centerRes.value);
            setNotificationCenter(normalized);
            const activeLegacyId = normalized.templates?.activeLegacyTemplateId;
            if (activeLegacyId) setSelectedTemplateId(String(activeLegacyId));
            if (Array.isArray(normalized.templates?.legacyTemplateConfigs)) {
              setTemplateList(normalized.templates.legacyTemplateConfigs);
            }
          }
          if (usersRes.status === "fulfilled") {
            const allUsers = Array.isArray(usersRes.value) ? usersRes.value : [];
            setUsers(allUsers);
            if (!notificationOpsEmail) {
              const preferredUser = allUsers.find((user) => user.canReceiveNotifications && !user.notificationsPaused)
                || allUsers.find((user) => !!user.notificationEmail)
                || allUsers[0];
              if (preferredUser) {
                setNotificationOpsEmail(preferredUser.notificationEmail || preferredUser.email || "");
                setIntelligentTestForm((prev) => ({
                  ...prev,
                  subscriberId: prev.subscriberId || String(preferredUser.id || ""),
                  targetEmail: prev.targetEmail || preferredUser.notificationEmail || preferredUser.email || "",
                  language: preferredUser.communicationLanguage || prev.language || "es",
                }));
              }
            }
          }
          if (templateRes.status === "fulfilled" && templateRes.value) {
            setTemplateConfig(prev => ({ ...prev, ...templateRes.value }));
            setTemplateName(templateRes.value?.name || "Plantilla CVE");
          }
          if (vulnsRes.status === "fulfilled") {
            setVulns(Array.isArray(vulnsRes.value?.data) ? vulnsRes.value.data : []);
          }
          if (intelligentTestsRes.status === "fulfilled") {
            setIntelligentTestHistory(Array.isArray(intelligentTestsRes.value?.items) ? intelligentTestsRes.value.items : []);
          }
          setNotificationCenterLoading(false);
        }
      } else if (v === "notifications") {
        const [historyRes, healthRes] = await Promise.allSettled([
          apiFetch("/notifications/history").then(r => r.json()),
          apiFetch("/notifications/process-health").then(r => r.json()),
        ]);
        if (historyRes.status === "fulfilled") {
          setNotifHistory(historyRes.value?.data || []);
        }
        if (healthRes.status === "fulfilled") {
          setNotificationCenter((prev) => normalizeNotificationCenterSettings({
            ...prev,
            processHealth: healthRes.value,
          }));
        }
      }
    } catch (e) {
      setSmtpLoading(false);
      setAiConfigLoading(false);
      setTemplateLoading(false);
      setManufacturersLoading(false);
      setNotificationCenterLoading(false);
      console.error("Load error:", e.message);
    }
  }, [loadVulnerabilityExplorer, loadSubscriberPortal, backfillJobId, settingsTab]);

  useEffect(() => { if (isLoggedIn) loadData(view); }, [view, isLoggedIn, loadData]);

  useEffect(() => {
    if (!isLoggedIn || routeInitRef.current) return;
    routeInitRef.current = true;
    const route = parseAppRoute(window.location.pathname);
    if (!route) return;
    if (route.view === "subscriber-teams") {
      setSubscriberTeamsRoute({ teamId: route.teamId || null });
      setView("subscriber-teams");
      return;
    }
    if (route.view === DETAIL_VIEW && route.cveId) {
      setDetailContext({ sourceView: normalizeDetailSourceView(route.sourceView), cveId: route.cveId });
      setView(DETAIL_VIEW);
      loadVulnDetailByCveId(route.cveId);
      return;
    }
    if (route.view) setView(route.view);
  }, [isLoggedIn]);

  useEffect(() => {
    if (!isLoggedIn) return undefined;
    const handlePopState = () => {
      const route = parseAppRoute(window.location.pathname);
      if (!route) {
        setVulnDetail(null);
        setSelectedVuln(null);
        setView("overview");
        return;
      }
      if (route.view === "subscriber-teams") {
        setSubscriberTeamsRoute({ teamId: route.teamId || null });
        setVulnDetail(null);
        setSelectedVuln(null);
        setView("subscriber-teams");
        return;
      }
      if (route.view === DETAIL_VIEW && route.cveId) {
        setDetailContext({ sourceView: normalizeDetailSourceView(route.sourceView), cveId: route.cveId });
        setView(DETAIL_VIEW);
        loadVulnDetailByCveId(route.cveId);
        return;
      }
      setVulnDetail(null);
      setSelectedVuln(null);
      setView(route.view);
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, [isLoggedIn]);

  useEffect(() => {
    if (!isLoggedIn || authMode === "reset") return;
    const nextPath = view === DETAIL_VIEW && detailContext.cveId
      ? getDetailPathForView(detailContext.sourceView, detailContext.cveId)
      : view === "vulns"
        ? VULN_LIST_PATH
        : view === "exploited"
          ? KEV_LIST_PATH
          : view === "account"
            ? ACCOUNT_PATH
            : view === "portal"
              ? PORTAL_PATH
              : view === "subscriber-teams"
                ? (subscriberTeamsRoute.teamId ? getSubscriberTeamDetailPath(subscriberTeamsRoute.teamId) : SUBSCRIBER_TEAMS_PATH)
          : (
            window.location.pathname.startsWith(VULN_LIST_PATH)
            || window.location.pathname.startsWith(KEV_LIST_PATH)
            || window.location.pathname === ACCOUNT_PATH
            || window.location.pathname === PORTAL_PATH
            || window.location.pathname.startsWith(SUBSCRIBER_TEAMS_PATH)
          )
            ? "/"
            : "";
    if (nextPath && window.location.pathname !== nextPath) {
      window.history.replaceState({}, "", nextPath);
    }
  }, [authMode, detailContext.cveId, detailContext.sourceView, isLoggedIn, subscriberTeamsRoute.teamId, view]);

  useEffect(() => {
    if (!isLoggedIn || view !== DETAIL_VIEW || !detailContext.sourceView || vulns.length > 0) return;
    loadData(detailContext.sourceView);
  }, [detailContext.sourceView, isLoggedIn, loadData, view, vulns.length]);

  // Debounced server-side search: re-fetch when search filters change
  const searchDebounceRef = useRef(null);
  useEffect(() => {
    if (!isLoggedIn || (view !== "vulns" && view !== "search")) return;
    if (searchDebounceRef.current) clearTimeout(searchDebounceRef.current);
    searchDebounceRef.current = setTimeout(() => {
      loadVulnerabilityExplorer({ page: 1, append: false });
    }, 400);
    return () => clearTimeout(searchDebounceRef.current);
  }, [searchQ, searchTagId, searchMinScore, searchPublishedFrom, searchPublishedTo]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleCreateTest = async () => {
    if (!testEmail) return;
    setTestSending(true);
    try {
      const res = await apiFetch("/notifications/test", { method: "POST", body: JSON.stringify({ email: testEmail }) });
      if (res.ok) setSmtpMsg({ type: "success", text: "Email de prueba enviado correctamente" });
      else throw new Error("Error enviando email");
    } catch (e) {
      setSmtpMsg({ type: "error", text: "Error enviando email de prueba" });
    }
    setTestSending(false);
    setTimeout(() => setSmtpMsg(null), 3000);
  };

  const saveAiConfig = async () => {
    setAiConfigSaving(true);
    try {
      const res = await apiFetch("/ai/config", {
        method: "POST",
        body: JSON.stringify({
          provider: aiConfig.provider || "ollama",
          baseUrl: aiConfig.baseUrl || "",
          model: aiConfig.model || "",
        }),
      });
      if (!res.ok) throw new Error("No se pudo guardar la configuración IA");
      const data = await res.json();
      setAiConfig({
        provider: data.provider || "ollama",
        baseUrl: data.baseUrl || "",
        model: data.model || DEFAULT_AI_MODEL,
        source: data.source || "db",
      });
      setSmtpMsg({ type: "success", text: "Configuración IA guardada correctamente" });
      const modelsRes = await apiFetch("/ai/models");
      const modelsData = await modelsRes.json();
      setAiModels(Array.isArray(modelsData?.models) ? modelsData.models : []);
    } catch (e) {
      setSmtpMsg({ type: "error", text: e.message || "Error guardando configuración IA" });
    } finally {
      setAiConfigSaving(false);
      setTimeout(() => setSmtpMsg(null), 3000);
    }
  };

  const refreshAiModels = async () => {
    try {
      const modelsRes = await apiFetch("/ai/models");
      const modelsData = await modelsRes.json();
      setAiModels(Array.isArray(modelsData?.models) ? modelsData.models : []);
    } catch {
      setAiModels([]);
    }
  };

  const handleSaveSmtp = async () => {
    setSmtpSaving(true);
    try {
      const res = await apiFetch("/notifications/config", { method: "POST", body: JSON.stringify(smtpConfig) });
      if (res.ok) setSmtpMsg({ type: "success", text: "Configuración guardada correctamente" });
      else throw new Error("Error guardando configuración");
    } catch (e) {
      setSmtpMsg({ type: "error", text: "Error guardando configuración" });
    }
    setSmtpSaving(false);
    setTimeout(() => setSmtpMsg(null), 3000);
  };

  const todayT = dash?.publishedLast24hTotal ?? (dash?.today || []).reduce((s, c) => s + (c?._count || 0), 0);
  const weekT = dash?.publishedLast7dTotal ?? (dash?.week || []).reduce((s, c) => s + (c?._count || 0), 0);
  const last30dT = dash?.publishedLast30dTotal ?? (dash?.last30d || dash?.month || []).reduce((s, c) => s + (c?._count || 0), 0);
  const exploitablesLast30dT = Number(dash?.exploitablesLast30d || 0);
  const kevConfirmedT = Number(dash?.kevConfirmedTotal ?? (dash?.topKevConfirmed || dash?.topExploited || []).length);
  const gc = (arr, sev) => (arr || []).find(c => c?.cvssV31Severity === sev)?._count || 0;
  const nextRun = () => { if (!dash?.lastRun?.finishedAt) return "-"; return Math.max(0, Math.floor((new Date(dash?.lastRun?.finishedAt).getTime() + 1800000 - now) / 60000)) + "m"; };
  const toggleKevTableSort = (key) => {
    setKevTableSort((current) => {
      if (current.key !== key || current.direction === "default") {
        return { key, direction: "asc" };
      }
      if (current.direction === "asc") {
        return { key, direction: "desc" };
      }
      return { key: "default", direction: "default" };
    });
  };
  const kevRows = dash?.topKevConfirmed || dash?.topExploited || [];
  const sortedKevRows = kevRows
    .map((row, index) => ({ row, index }))
    .sort((left, right) => {
      if (kevTableSort.direction === "default" || kevTableSort.key === "default") {
        return left.index - right.index;
      }

      const a = left.row;
      const b = right.row;
      const aSemantic = getSemanticSummary(a);
      const bSemantic = getSemanticSummary(b);
      let comparison = 0;

      switch (kevTableSort.key) {
        case "cve":
          comparison = compareNullableText(a.cveId, b.cveId);
          break;
        case "risk":
          comparison = compareNullableNumbers(a.operationalRiskScore, b.operationalRiskScore);
          if (comparison === 0) comparison = compareNullableNumbers(
            RISK_TIER_SORT_ORDER[String(a.operationalRiskTier || "").toLowerCase()],
            RISK_TIER_SORT_ORDER[String(b.operationalRiskTier || "").toLowerCase()],
          );
          break;
        case "cvss":
          comparison = compareNullableNumbers(a.cvssV31Score, b.cvssV31Score);
          if (comparison === 0) comparison = compareNullableText(a.cvssV31Severity, b.cvssV31Severity);
          break;
        case "epss":
          comparison = compareNullableNumbers(a.epssScore, b.epssScore);
          break;
        case "product":
          comparison = compareNullableText(aSemantic.displayTitle, bSemantic.displayTitle);
          if (comparison === 0) comparison = compareNullableText(aSemantic.componentType, bSemantic.componentType);
          break;
        case "exploitation":
          comparison = compareNullableNumbers(
            EXPLOIT_STATUS_SORT_ORDER[String(a.exploitStatus || "").toLowerCase()],
            EXPLOIT_STATUS_SORT_ORDER[String(b.exploitStatus || "").toLowerCase()],
          );
          if (comparison === 0) comparison = compareNullableNumbers(a.hasPublicExploit ? 1 : 0, b.hasPublicExploit ? 1 : 0);
          break;
        case "status":
          comparison = compareNullableNumbers(
            RECORD_STATUS_SORT_ORDER[String(a.recordStatus || "").toLowerCase()],
            RECORD_STATUS_SORT_ORDER[String(b.recordStatus || "").toLowerCase()],
          );
          break;
        case "published":
          comparison = compareNullableDates(a.publishedAt, b.publishedAt);
          break;
        case "updated":
          comparison = compareNullableDates(a.lastModifiedAt, b.lastModifiedAt);
          break;
        default:
          comparison = 0;
      }

      if (comparison === 0) return left.index - right.index;
      return kevTableSort.direction === "asc" ? comparison : -comparison;
    })
    .map(({ row }) => row);

  // Search criteria detection (server-side search — results come from API)
  const hasSearchCriteria = (
    searchQ.trim().length >= 2 ||
    searchTagId !== "" ||
    searchPublishedFrom !== "" ||
    searchPublishedTo !== "" ||
    searchMinScore !== "" ||
    searchExploit !== "all" ||
    searchSeverity !== "" ||
    notificableFilter !== "" ||
    notificadaFilter !== ""
  );

  // Client-side exploit/severity filtering (lightweight, applied on top of server results)
  const searchResults = vulns.filter(v => {
    const severityMatch = searchSeverity === "" || v.cvssV31Severity === searchSeverity;
    let exploitMatch = true;
    if (searchExploit === "known") exploitMatch = !!v.isKnownExploited;
    else if (searchExploit === "public") exploitMatch = !!v.hasPublicExploit;
    else if (searchExploit === "any") exploitMatch = !!v.isKnownExploited || !!v.hasPublicExploit;
    else if (searchExploit === "none") exploitMatch = !v.isKnownExploited && !v.hasPublicExploit;
    return severityMatch && exploitMatch;
  });

  // Client-side instant free-text filter across all visible fields
  const applyInstantFilter = (rows) => {
    const q = instantFilter.trim().toLowerCase();
    if (!q) return rows;
    const tokens = q.split(/\s+/).filter(Boolean);
    return rows.filter((v) => {
      const semantic = getSemanticSummary(v);
      const haystack = [
        v.cveId,
        v.cvssV31Severity,
        fmtScore(v.cvssV31Score),
        fmtEpss(v.epssScore),
        riskTierMeta(v.operationalRiskTier).label,
        fmtRiskScore(v.operationalRiskScore),
        exploitStatusMeta(v.exploitStatus).label,
        semantic.displayTitle,
        semantic.displaySubtitle,
        componentTypeMeta(semantic.componentType).label,
        recordStatusMeta(v.recordStatus).label,
        v.patchAvailable === true ? "parche disponible" : "parche no confirmado",
        v.isKnownExploited ? "kev" : "",
        v.hasPublicExploit ? "exploit público" : "",
        v.notificable ? "notificable si" : "no notificable",
        v.notificada ? "notificada si" : "no notificada",
        (v.tags || []).map(t => t.name).join(" "),
        normalizeFieldList(v.sourcesPresent).map(s => String(s)).join(" "),
        v.description || "",
        v.summary || "",
        v.shortDescription || "",
      ].join(" ").toLowerCase();
      return tokens.every((token) => haystack.includes(token));
    });
  };

  const clearExplorerFilters = () => {
    setSearchQ("");
    setSearchType("all");
    setSearchTagId("");
    setSearchPublishedFrom("");
    setSearchPublishedTo("");
    setSearchMinScore("");
    setSearchExploit("all");
    setSearchSeverity("");
    setSevFilter("");
    setRiskTierFilter("");
    setExploitStatusFilter("");
    setVendorFilter("");
    setProductFilter("");
    setChangedSinceHoursFilter("");
    setNotificableFilter("");
    setNotificadaFilter("");
    setInstantFilter("");
  };
  const loadMoreVulns = async () => {
    if (vulnsLoadingMore || !vulnsHasMore) return;
    await loadVulnerabilityExplorer({ page: vulnsPage + 1, append: true });
  };
  const visibleManufacturers = manufacturers;
  const visibleManufacturersCount = Number(
    manufacturersCatalogMeta?.visibleManufacturers ?? visibleManufacturers.length,
  );
  const visibleProductsCount = Number(
    manufacturersCatalogMeta?.visibleProducts
      ?? visibleManufacturers.reduce((sum, item) => sum + (item.productsCount || 0), 0),
  );
  const hiddenManufacturersCount = Number(manufacturersCatalogMeta?.hiddenManufacturers || 0);
  const hiddenProductsCount = Number(manufacturersCatalogMeta?.hiddenProducts || 0);
  const hiddenReasonLabelMap = {
    contextual_vendor: "contexto/plataforma",
    advisory_emitter: "emisor de advisory",
    cert_org: "CERT/CSIRT",
    unknown_vendor: "desconocido",
  };
  const hiddenReasonSummary = Array.isArray(manufacturersCatalogMeta?.hiddenByReason)
    ? manufacturersCatalogMeta.hiddenByReason
      .map((item) => {
        const count = Number(item?.count || 0);
        if (!count) return null;
        const label = hiddenReasonLabelMap[item?.reason] || item?.reason || "otros";
        return `${count} ${label}`;
      })
      .filter(Boolean)
      .slice(0, 4)
      .join(", ")
    : "";
  const hiddenSamplesSummary = Array.isArray(manufacturersCatalogMeta?.hiddenSamples)
    ? manufacturersCatalogMeta.hiddenSamples
      .map((item) => item?.vendor)
      .filter(Boolean)
      .slice(0, 4)
      .join(", ")
    : "";
  const preInstantRows = (searchExploit !== "all" || searchSeverity !== "") ? searchResults : vulns;
  const explorerRows = applyInstantFilter(preInstantRows);
  const explorerResultLabel = instantFilter.trim()
    ? `${explorerRows.length} de ${preInstantRows.length} CVEs (filtro local)`
    : hasSearchCriteria
      ? `${explorerRows.length} resultados de ${vulnsTotal} CVEs (búsqueda servidor)`
      : `Mostrando ${vulns.length} de ${vulnsTotal} CVEs`;
  const kevListRows = sortKevModuleRows(vulns.filter((v) => v.isKnownExploited));
  const detailSourceView = normalizeDetailSourceView(detailContext.sourceView);
  const detailNavigationRows = detailSourceView === "exploited" ? kevListRows : explorerRows;
  const detailCveId = String(vulnDetail?.cveId || detailContext.cveId || "").trim().toUpperCase();
  const detailIndex = detailNavigationRows.findIndex((item) => String(item?.cveId || "").trim().toUpperCase() === detailCveId);
  const previousDetailRow = detailIndex > 0 ? detailNavigationRows[detailIndex - 1] : null;
  const nextDetailRow = detailIndex >= 0 && detailIndex < detailNavigationRows.length - 1 ? detailNavigationRows[detailIndex + 1] : null;
  const closeVulnerabilityDetail = () => {
    setVulnDetail(null);
    setSelectedVuln(null);
    setView(detailSourceView);
  };
  const openAdjacentVulnerability = (offset) => {
    const target = offset < 0 ? previousDetailRow : nextDetailRow;
    if (!target) return;
    openVulnerabilityDetail(target, { sourceView: detailSourceView });
  };
  const copyText = async (value, successText = "Copiado") => {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(String(value || ""));
        return;
      }
    } catch {
      // noop
    }
    alert(successText);
  };
  const renderVulnerabilityDetailPage = () => {
    if (vulnLoading && !vulnDetail) {
      return (
        <Card style={{ padding: 28 }}>
          <div style={{ padding: 40, textAlign: "center", color: C.gray500, fontSize: 13 }}>Cargando detalle de vulnerabilidad...</div>
        </Card>
      );
    }

    if (!vulnDetail || vulnDetail?.error) {
      return (
        <Card style={{ padding: 28 }}>
          <div style={{ fontSize: 18, fontWeight: 800, color: C.text, marginBottom: 8 }}>Vulnerabilidad no disponible</div>
          <div style={{ fontSize: 13, color: C.gray500, marginBottom: 16 }}>
            No se pudo cargar el detalle solicitado o la CVE no existe en la colección actual.
          </div>
          <Btn onClick={closeVulnerabilityDetail}>Volver al listado</Btn>
        </Card>
      );
    }

    const detail = vulnDetail;
    const semantic = getSemanticSummary(detail);
    const riskSignals = normalizeFieldList(detail.riskSignals);
    const detailedProducts = normalizeFieldList(detail.affectedProductsDetailed);
    const summaryProducts = normalizeFieldList(detail.affectedProducts);
    const displayProducts = detailedProducts.length > 0 ? detailedProducts : summaryProducts;
    const { primaryProducts, otherProducts } = splitDisplayProducts(displayProducts, semantic);
    const displayContextTags = getDisplayContextTags({
      contextTags: semantic.contextTags,
      riskSignals,
      tags: detail.tags,
    });
    const remediationInfo = normalizeFieldValue(detail.remediationInfo);
    const fixedVersions = normalizeFieldValue(detail.fixedVersions);
    const workarounds = normalizeFieldValue(detail.workarounds);
    const detectionOpportunities = normalizeFieldValue(detail.detectionOpportunities);
    const references = normalizeFieldValue(detail.references);
    const allReferences = normalizeFieldValue(detail.allReferences);
    const exploitReferences = normalizeFieldValue(detail.exploitReferences);
    const vendorAdvisories = normalizeFieldValue(detail.vendorAdvisories ?? remediationInfo?.vendorAdvisories);
    const patchUrls = normalizeFieldValue(detail.patchUrls ?? remediationInfo?.patchUrls);
    const linksField = normalizeFieldValue(detail.links ?? remediationInfo?.links);
    const advisoriesField = normalizeFieldValue(detail.advisories ?? remediationInfo?.advisories);
    const sourcesPresent = normalizeFieldList(detail.sourcesPresent);
    const changeTimeline = normalizeFieldList(detail.changeTimeline);
    const cweIds = normalizeFieldList(detail.cweIds);
    const cweNames = normalizeFieldList(detail.cweNames);
    const executiveSummary = String(detail.summary || detail.shortDescription || detail.description || "").trim();
    const summaryText = executiveSummary || "No hay resumen ejecutivo disponible.";
    const technicalText = String(detail.description || executiveSummary || "").trim() || "Sin descripción técnica adicional.";
    const nvdBundle = normalizeReferenceEntries([{
      label: "NVD NIST",
      source: "NIST",
      category: "nvd",
      tags: ["NVD"],
      url: `https://nvd.nist.gov/vuln/detail/${detail.cveId}`,
    }], { defaultCategory: "nvd", defaultSource: "NIST", defaultLabel: "NVD NIST" });
    const exploitBundle = normalizeReferenceEntries(exploitReferences, {
      defaultCategory: "exploit",
      defaultSource: "exploit",
      defaultLabel: "Referencia de explotación",
    });
    const vendorBundle = normalizeReferenceEntries([patchUrls, vendorAdvisories, advisoriesField], {
      defaultCategory: "vendor",
      defaultSource: "advisory",
      defaultLabel: "Advisory del fabricante",
    });
    const generalBundle = normalizeReferenceEntries([references, allReferences, linksField], {
      defaultCategory: "other",
      defaultSource: "reference",
      defaultLabel: "Referencia",
    });
    const referenceGroups = {
      vendor: { links: [], metadata: [] },
      government: { links: [], metadata: [] },
      nvd: { links: [], metadata: [] },
      exploit: { links: [], metadata: [] },
      other: { links: [], metadata: [] },
    };
    const mergedReferenceUrls = new Set();
    const mergeReferenceBundle = (bundle, fallbackCategory) => {
      const groupedLinks = groupReferenceLinksByCategory(bundle.links);
      Object.entries(groupedLinks).forEach(([category, links]) => {
        links.forEach((link) => {
          if (mergedReferenceUrls.has(link.url)) return;
          mergedReferenceUrls.add(link.url);
          referenceGroups[category].links.push(link);
        });
      });
      referenceGroups[fallbackCategory].metadata.push(...bundle.metadata);
    };
    mergeReferenceBundle(nvdBundle, "nvd");
    mergeReferenceBundle(vendorBundle, "vendor");
    mergeReferenceBundle(exploitBundle, "exploit");
    mergeReferenceBundle(generalBundle, "other");
    Object.values(referenceGroups).forEach((group) => {
      group.metadata = dedupeTextList(group.metadata);
    });
    const primaryReferenceUrl =
      referenceGroups.vendor.links[0]?.url ||
      referenceGroups.government.links[0]?.url ||
      referenceGroups.nvd.links[0]?.url ||
      referenceGroups.other.links[0]?.url ||
      null;
    const keyFacts = [
      { label: "CVE", value: detail.cveId },
      { label: "Producto principal", value: semantic.hasReliablePrimaryEntity ? semantic.displayTitle : "Clasificación pendiente" },
      { label: "Tipo de componente", value: componentTypeMeta(semantic.componentType).label },
      { label: "Estado del registro", value: recordStatusMeta(detail.recordStatus).label },
      { label: "Fuente canónica", value: detail.canonicalSource || "No informada" },
      { label: "Fuentes presentes", value: sourcesPresent.length > 0 ? sourcesPresent.map((item) => summarizeTextValue(item)).join(", ") : "No informadas" },
      { label: "Confianza del dato", value: fmtConfidence(detail.dataConfidence) },
      { label: "Último cambio detectado", value: fmtDate(detail.lastChangeDetectedAt) },
    ];

    // ── Riesgo Real score ──
    const riskScore = detail.operationalRiskScore != null ? Math.round(parseFloat(detail.operationalRiskScore)) : null;
    const riskScoreColor = riskScore >= 75 ? C.critical : riskScore >= 50 ? C.high : riskScore >= 25 ? "#d97706" : C.low;

    // ── Products grouped by vendor (deduplicated) ──
    const vendorGroups = {};
    displayProducts.forEach((p) => {
      if (typeof p === "string") { (vendorGroups["Otros"] = vendorGroups["Otros"] || []).push({ product: p, vendor: "Otros" }); return; }
      const vName = p.vendor || "Vendor no informado";
      (vendorGroups[vName] = vendorGroups[vName] || []).push(p);
    });
    Object.keys(vendorGroups).forEach((vName) => {
      const seen = new Map();
      vendorGroups[vName] = vendorGroups[vName].filter((p) => {
        const key = `${p.product || ""}|${p.version || ""}|${p.versionRange || ""}`;
        if (seen.has(key)) return false;
        seen.set(key, true);
        return true;
      });
    });

    // ── Exploit links for scrollable list ──
    const exploitLinks = referenceGroups.exploit.links || [];

    return (
      <div className="fade" style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {/* ═══ HEADER ═══ */}
        <Card style={{ padding: 20, overflow: "visible" }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 20, flexWrap: "wrap" }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 6, flex: 1 }}>
              <div style={{ fontSize: 11, color: C.gray500, fontWeight: 700, letterSpacing: "0.8px", textTransform: "uppercase" }}>
                {detailSourceView === "exploited" ? "KEV / Explotación confirmada" : "Catálogo de vulnerabilidades"} / Detalle CVE
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                <h1 style={{ fontSize: 28, fontWeight: 900, margin: 0, fontFamily: "'JetBrains Mono', monospace", color: C.navy }}>{detail.cveId}</h1>
                <span className="occ-tooltip-wrap">
                  <SevBadge s={detail.cvssV31Severity} />
                  <span className="occ-tooltip" style={{ width: 260 }}>
                    <strong>Severidad: {detail.cvssV31Severity || "N/A"}</strong><br /><br />
                    Origen: CVSS v3.1 Base Score<br />
                    Puntuación: {fmtScore(detail.cvssV31Score)} / 10.0<br />
                    Vector: {detail.cvssV31Vector || "No informado"}<br /><br />
                    <em style={{ color: "#94A3B8" }}>Clasificación asignada por NVD (NIST).</em>
                  </span>
                </span>
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 2 }}>
                <SoftBadge label={`Publicado ${fmtDate(detail.publishedAt)}`} bg={C.gray50} color={C.gray700} border={C.gray300} />
                <SoftBadge label={`Actualizado ${fmtDate(detail.lastModifiedAt)}`} bg={C.gray50} color={C.gray700} border={C.gray300} />
                {hasValue(detail.enrichedAt) && <SoftBadge label={`Enriquecido ${fmtDate(detail.enrichedAt)}`} bg={C.bluePale} color={C.navy} border={C.gray200} />}
              </div>
              <div className="occ-vuln-header-actions" style={{ justifyContent: "flex-start", marginTop: 4 }}>
                <Btn onClick={closeVulnerabilityDetail}><I name="arrowRight" size={14} /> Volver</Btn>
                <Btn onClick={() => openAdjacentVulnerability(-1)} disabled={!previousDetailRow}>Anterior</Btn>
                <Btn onClick={() => openAdjacentVulnerability(1)} disabled={!nextDetailRow}>Siguiente</Btn>
                <Btn onClick={() => copyText(detail.cveId, "CVE copiada")}>Copiar CVE</Btn>
                <Btn onClick={() => primaryReferenceUrl && window.open(primaryReferenceUrl, "_blank", "noopener,noreferrer")} disabled={!primaryReferenceUrl}>Abrir advisory</Btn>
                <Btn onClick={() => analyzeVulnerabilityWithAi(detail)}><I name="brain" size={14} /> Analizar con IA</Btn>
              </div>
            </div>

            {/* ═══ RIESGO REAL BOX ═══ */}
            <div style={{ background: "#fff", borderRadius: 14, padding: "16px 20px", minWidth: 280, border: `2px solid ${C.gray200}`, position: "relative" }}>
              <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3, background: `linear-gradient(90deg, ${C.high}, ${C.critical})`, borderRadius: "14px 14px 0 0" }} />
              <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px", color: C.gray500, marginBottom: 10 }}>Riesgo Real</div>
              <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginBottom: 12 }}>
                {detail.exploitStatus === "active_exploitation" && <span style={{ padding: "2px 8px", borderRadius: 5, fontSize: 10, fontWeight: 700, background: C.criticalBg, color: C.critical, border: "1px solid #FCA5A5" }}>● Explotación activa</span>}
                {detail.isKnownExploited && <span style={{ padding: "2px 8px", borderRadius: 5, fontSize: 10, fontWeight: 700, background: C.highBg, color: C.high, border: "1px solid #FDBA74" }}>KEV{detail.epssScore != null ? ` · EPSS ${fmtEpss(detail.epssScore)}` : ""}</span>}
                {detail.hasPublicExploit && <span style={{ padding: "2px 8px", borderRadius: 5, fontSize: 10, fontWeight: 700, background: "#FFFBEB", color: "#B45309", border: "1px solid #FDE68A" }}>Exploit público</span>}
                <span style={{ padding: "2px 8px", borderRadius: 5, fontSize: 10, fontWeight: 700, background: detail.patchAvailable ? C.lowBg : C.criticalBg, color: detail.patchAvailable ? C.low : C.critical, border: `1px solid ${detail.patchAvailable ? "#BBF7D0" : "#FCA5A5"}` }}>
                  {detail.patchAvailable ? "✓ Parche disponible" : "✗ Sin parche"}
                </span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ height: 6, background: "#F1F5F9", borderRadius: 3, overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${riskScore || 0}%`, borderRadius: 3, background: `linear-gradient(90deg, ${C.high}, ${C.critical})`, transition: "width 0.6s ease" }} />
                  </div>
                  <div style={{ fontSize: 10, color: C.gray500, fontWeight: 600, marginTop: 4 }}>Puntuación compuesta</div>
                </div>
                <span className="occ-tooltip-wrap occ-tooltip-right occ-tooltip-below">
                  <span style={{ fontSize: 28, fontWeight: 900, fontFamily: "'JetBrains Mono', monospace", color: riskScoreColor, cursor: "help" }}>
                    {riskScore != null ? riskScore : "-"}<span style={{ fontSize: 14, fontWeight: 600, color: C.gray400 }}>/100</span>
                  </span>
                  <span className="occ-tooltip" style={{ width: 280 }}>
                    <strong>Cálculo del Riesgo Real (0-100):</strong><br /><br />
                    Composición ponderada de:<br />
                    • CVSS v3.1: {fmtScore(detail.cvssV31Score)} (peso 30%)<br />
                    • EPSS probabilidad: {detail.epssScore != null ? parseFloat(detail.epssScore).toFixed(3) : "N/A"} (peso 20%)<br />
                    • KEV / Explotación activa: {detail.isKnownExploited ? "+15" : "+0"}<br />
                    • Exploit público: {detail.hasPublicExploit ? "+10" : "+0"}<br />
                    • Parche no disponible: {detail.patchAvailable === false ? "+10" : "+0"}<br />
                    • Confianza del dato: {fmtConfidence(detail.dataConfidence)}<br /><br />
                    <em style={{ color: "#94A3B8" }}>Pasa el ratón por encima para ver este detalle.</em>
                  </span>
                </span>
              </div>
            </div>
          </div>
        </Card>

        {/* ═══ LAYOUT 2 COLUMNAS ═══ */}
        <div className="occ-vuln-detail-layout">
          <div className="occ-vuln-detail-main">

            {/* ═══ DESCRIPCIÓN (compacta) ═══ */}
            <Card>
              <div style={{ fontSize: 13, color: C.gray700, lineHeight: 1.7 }}>{summaryText}</div>
              {summaryText !== technicalText && technicalText !== "Sin descripción técnica adicional." && (
                <div style={{ marginTop: 12, paddingTop: 12, borderTop: `1px solid ${C.gray100}` }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 6 }}>Descripción técnica</div>
                  <div style={{ fontSize: 13, color: C.gray700, lineHeight: 1.7, whiteSpace: "pre-wrap" }}>{technicalText}</div>
                </div>
              )}
            </Card>

            {/* ═══ MÉTRICAS COMPACTAS (4 en 1 línea) ═══ */}
            <div className="occ-vuln-metrics-grid">
              <div className="occ-tooltip-wrap" style={{ background: "#fff", borderRadius: 10, padding: "12px 14px", border: `1px solid ${C.gray200}`, position: "relative", overflow: "hidden" }}>
                <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: sevColor(detail.cvssV31Severity) }} />
                <div style={{ fontSize: 10, fontWeight: 600, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 2 }}>CVSS v3.1</div>
                <div style={{ fontSize: 20, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace", color: C.text, letterSpacing: "-0.5px" }}>{fmtScore(detail.cvssV31Score)}</div>
                <span className="occ-tooltip">
                  <strong>CVSS v3.1:</strong> {fmtScore(detail.cvssV31Score)} {detail.cvssV31Severity || "N/A"}<br />
                  Vector: {detail.cvssV31Vector || "No informado"}<br /><br />
                  {detail.cvssV40Score != null && <><strong>CVSS v4.0:</strong> {fmtScore(detail.cvssV40Score)} {detail.cvssV40Severity || "N/A"}<br />Vector: {detail.cvssV40Vector || "No informado"}</>}
                </span>
              </div>
              <div className="occ-tooltip-wrap" style={{ background: "#fff", borderRadius: 10, padding: "12px 14px", border: `1px solid ${C.gray200}`, position: "relative", overflow: "hidden" }}>
                <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: C.blue }} />
                <div style={{ fontSize: 10, fontWeight: 600, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 2 }}>EPSS</div>
                <div style={{ fontSize: 20, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace", color: C.text }}>{fmtEpss(detail.epssScore)}</div>
                <span className="occ-tooltip">
                  <strong>Probabilidad de explotación:</strong> {detail.epssScore != null ? parseFloat(detail.epssScore).toFixed(3) : "N/A"}<br />
                  <strong>Percentil:</strong> {(Number(detail.epssPercentile || 0) * 100).toFixed(0)}%<br />
                  Posición relativa frente a todas las CVE conocidas.
                </span>
              </div>
              <div className="occ-tooltip-wrap" style={{ background: "#fff", borderRadius: 10, padding: "12px 14px", border: `1px solid ${C.gray200}`, position: "relative", overflow: "hidden" }}>
                <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: C.high }} />
                <div style={{ fontSize: 10, fontWeight: 600, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 2 }}>CWE</div>
                <div style={{ fontSize: 16, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace", color: C.text }}>{cweIds[0] || "N/A"}</div>
                <span className="occ-tooltip">
                  <strong>{cweIds[0] || "N/A"}:</strong> {cweNames[0] || "Sin nombre"}<br />
                  {detail.weaknessCategory && <>Categoría: {detail.weaknessCategory}</>}
                </span>
              </div>
              <div className="occ-tooltip-wrap" style={{ background: "#fff", borderRadius: 10, padding: "12px 14px", border: `1px solid ${C.gray200}`, position: "relative", overflow: "hidden" }}>
                <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: C.navy }} />
                <div style={{ fontSize: 10, fontWeight: 600, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 2 }}>Confianza</div>
                <div style={{ fontSize: 20, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace", color: C.text }}>{fmtConfidence(detail.dataConfidence)}</div>
                <span className="occ-tooltip">
                  <strong>Confianza del dato:</strong> {fmtConfidence(detail.dataConfidence)}<br />
                  Basado en {detail.sourceCount || "?"} fuentes independientes:<br />
                  {sourcesPresent.length > 0 ? sourcesPresent.map(s => String(s)).join(", ") : "No informadas"}
                </span>
              </div>
            </div>

            {/* ═══ ESTADO NOTIFICACIÓN (con popover suscriptores) ═══ */}
            <Card title="Estado de notificación" icon="bell" style={{ overflow: "visible" }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10 }}>
                <div style={{ padding: 10, background: detail.notificable ? "#D1FAE5" : C.gray50, borderRadius: 8, textAlign: "center", border: `1px solid ${detail.notificable ? "#6EE7B7" : C.gray200}` }}>
                  <div style={{ fontSize: 9, color: C.gray500, marginBottom: 3, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em" }}>Notificable</div>
                  <div style={{ fontSize: 15, fontWeight: 800, color: detail.notificable ? "#065F46" : C.gray400 }}>{detail.notificable ? "SI" : "NO"}</div>
                </div>
                <div style={{ padding: 10, background: detail.notificada ? "#DBEAFE" : C.gray50, borderRadius: 8, textAlign: "center", border: `1px solid ${detail.notificada ? "#93C5FD" : C.gray200}` }}>
                  <div style={{ fontSize: 9, color: C.gray500, marginBottom: 3, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em" }}>Notificada</div>
                  <div style={{ fontSize: 15, fontWeight: 800, color: detail.notificada ? "#1E40AF" : C.gray400 }}>{detail.notificada ? "SI" : "NO"}</div>
                </div>
                <div style={{ padding: 10, background: C.gray50, borderRadius: 8, textAlign: "center", border: `1px solid ${C.gray200}` }}>
                  <div style={{ fontSize: 9, color: C.gray500, marginBottom: 3, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em" }}>Fecha</div>
                  <div style={{ fontSize: 11, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", color: detail.fechaNotificacion ? C.text : C.gray400 }}>
                    {detail.fechaNotificacion ? fmtDate(detail.fechaNotificacion) : "—"}
                  </div>
                </div>
                <div
                  className={`occ-popover-wrap${(detail.suscriptoresNotificados || []).length > 0 ? "" : ""}`}
                  style={{ padding: 10, background: C.gray50, borderRadius: 8, textAlign: "center", border: `1px solid ${C.gray200}`, cursor: (detail.suscriptoresNotificados || []).length > 0 ? "pointer" : "default" }}
                  onClick={(e) => { if ((detail.suscriptoresNotificados || []).length > 0) { e.currentTarget.classList.toggle("occ-open"); e.stopPropagation(); } }}
                >
                  <div style={{ fontSize: 9, color: C.gray500, marginBottom: 3, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em" }}>Suscriptores</div>
                  <div style={{ fontSize: 15, fontWeight: 800, color: (detail.suscriptoresNotificados || []).length > 0 ? C.blue : C.gray400 }}>
                    {(detail.suscriptoresNotificados || []).length}
                    {(detail.suscriptoresNotificados || []).length > 0 && <span style={{ fontSize: 9, fontWeight: 600, color: C.gray400, marginLeft: 4 }}>▼</span>}
                  </div>
                  {(detail.suscriptoresNotificados || []).length > 0 && (
                    <div className="occ-popover-content" onClick={(e) => e.stopPropagation()}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: C.gray500, textTransform: "uppercase", marginBottom: 8 }}>Suscriptores notificados</div>
                      {(detail.suscriptoresNotificados || []).map((s, idx) => (
                        <div key={idx} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 8px", borderRadius: 6 }}>
                          <div style={{ width: 26, height: 26, borderRadius: "50%", background: C.bluePale, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700, color: C.blue }}>
                            {(s.recipientName || s.recipientEmail || "?")[0].toUpperCase()}
                          </div>
                          <div style={{ flex: 1, textAlign: "left" }}>
                            <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{s.recipientName || "Sin nombre"}</div>
                            <div style={{ fontSize: 10, color: C.gray500 }}>{s.recipientEmail}</div>
                          </div>
                          <div style={{ fontSize: 10, color: "#94A3B8", fontFamily: "'JetBrains Mono', monospace" }}>{fmtDate(s.sentAt)}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </Card>

            {/* ═══ PRODUCTOS AFECTADOS (doble nivel con scroll y búsqueda) ═══ */}
            <Card title="Productos afectados" icon="server" action={<span style={{ fontSize: 10, color: C.gray500 }}>{displayProducts.length} producto{displayProducts.length !== 1 ? "s" : ""}</span>}>
              {displayProducts.length === 0 ? (
                <div style={{ fontSize: 12, color: C.gray500 }}>Sin detalle de productos afectados.</div>
              ) : (() => {
                const [prodFilter, setProdFilter] = [detailProductFilter, setDetailProductFilter];
                const filteredVendorGroups = Object.entries(vendorGroups).map(([vendor, products]) => {
                  const q = (prodFilter || "").toLowerCase();
                  if (!q) return { vendor, products, visible: true };
                  const vendorMatch = vendor.toLowerCase().includes(q);
                  const filteredProducts = vendorMatch ? products : products.filter((p) => {
                    const text = `${p.product || ""} ${p.version || ""} ${p.versionRange || ""}`.toLowerCase();
                    return text.includes(q);
                  });
                  return { vendor, products: filteredProducts, visible: filteredProducts.length > 0 };
                }).filter((g) => g.visible);

                return (
                  <>
                    <div style={{ position: "relative", marginBottom: 8 }}>
                      <span style={{ position: "absolute", left: 10, top: 9, color: "#94A3B8", fontSize: 13 }}>⌕</span>
                      <input
                        value={prodFilter}
                        onChange={(e) => setProdFilter(e.target.value)}
                        placeholder="Buscar fabricante o producto..."
                        style={{ width: "100%", padding: "8px 12px 8px 32px", border: `1px solid ${C.gray200}`, borderRadius: 8, fontSize: 12, background: "#F8FAFC", outline: "none", boxSizing: "border-box" }}
                      />
                    </div>
                    <div className="occ-scroll-list">
                      {filteredVendorGroups.map(({ vendor, products }) => (
                        <div key={vendor} className="occ-vendor-group">
                          <div className="occ-vendor-header" onClick={(e) => e.currentTarget.classList.toggle("occ-collapsed")}>
                            <span className="occ-vendor-arrow">▼</span>
                            {vendor}
                            <span style={{ fontSize: 10, fontWeight: 600, color: C.gray500, marginLeft: "auto" }}>{products.length} producto{products.length !== 1 ? "s" : ""}</span>
                          </div>
                          <div className="occ-vendor-products">
                            {products.map((p, idx) => (
                              <div key={idx} className="occ-product-row">
                                <span style={{ color: C.gray700, flex: 1 }}>{typeof p === "string" ? p : (p.product || "Producto no informado")}</span>
                                {p.version && <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: C.gray500 }}>{p.version}</span>}
                                {p.versionRange && <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: C.gray500 }}>{String(p.versionRange)}</span>}
                                {semantic.hasReliablePrimaryEntity && primaryProducts.includes(p) && <SoftBadge label="Principal" small bg={C.criticalBg} color={C.critical} border="#FCA5A5" />}
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                      {filteredVendorGroups.length === 0 && <div style={{ fontSize: 12, color: C.gray500, padding: 8 }}>Sin resultados para "{prodFilter}"</div>}
                    </div>
                  </>
                );
              })()}
            </Card>

            {/* ═══ EXPLOTACIÓN (compacta + scroll exploits) ═══ */}
            <DetailBlock title="Explotación" icon="zap">
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 10, marginBottom: 12 }}>
                <KV label="Estado" value={<ExploitStatusBadge status={detail.exploitStatus} small />} />
                <KV label="Confianza" value={fmtConfidence(detail.exploitConfidence)} />
                <KV label="Primera detección" value={fmtDate(detail.exploitFirstSeenAt)} />
              </div>
              {(() => {
                const exploitContext = buildExploitContext(detail);
                return exploitContext.length > 0 ? (
                  <div style={{ padding: "10px 14px", borderRadius: 8, background: "#FFFBEB", border: "1px solid #FDE68A", marginBottom: 12 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: "#92400E", textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 6 }}>Contexto de explotación</div>
                    <ul style={{ margin: 0, paddingLeft: 16, fontSize: 12, color: "#78350F", lineHeight: 1.7 }}>
                      {exploitContext.map((line, idx) => <li key={idx}>{line}</li>)}
                    </ul>
                  </div>
                ) : null;
              })()}
              {exploitLinks.length > 0 && (() => {
                const [exFilter, setExFilter] = [detailExploitFilter, setDetailExploitFilter];
                const q = (exFilter || "").toLowerCase();
                const filtered = q ? exploitLinks.filter((l) => `${l.label || ""} ${l.url || ""} ${l.source || ""}`.toLowerCase().includes(q)) : exploitLinks;
                return (
                  <>
                    <div style={{ fontSize: 10, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 6 }}>Referencias de exploits</div>
                    <div style={{ position: "relative", marginBottom: 8 }}>
                      <span style={{ position: "absolute", left: 10, top: 9, color: "#94A3B8", fontSize: 13 }}>⌕</span>
                      <input
                        value={exFilter}
                        onChange={(e) => setExFilter(e.target.value)}
                        placeholder="Filtrar exploits..."
                        style={{ width: "100%", padding: "8px 12px 8px 32px", border: `1px solid ${C.gray200}`, borderRadius: 8, fontSize: 12, background: "#F8FAFC", outline: "none", boxSizing: "border-box" }}
                      />
                    </div>
                    <div className="occ-scroll-list">
                      {filtered.map((link, idx) => (
                        <div key={idx} className="occ-exploit-row" onClick={() => link.url && window.open(link.url, "_blank", "noopener,noreferrer")}>
                          <span style={{ fontWeight: 700, color: "#1E40AF", minWidth: 80, fontSize: 10, textTransform: "uppercase" }}>{link.source || "Ref"}</span>
                          <span style={{ color: C.gray700, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{link.label || link.url}</span>
                          <span style={{ color: "#94A3B8", fontSize: 14 }}>→</span>
                        </div>
                      ))}
                      {filtered.length === 0 && <div style={{ fontSize: 12, color: C.gray500, padding: 8 }}>Sin resultados</div>}
                    </div>
                  </>
                );
              })()}
              {exploitLinks.length === 0 && (
                <div style={{ fontSize: 12, color: C.gray500 }}>No hay referencias de exploit disponibles.</div>
              )}
            </DetailBlock>

            {/* ═══ REMEDIACIÓN ═══ */}
            <DetailBlock title="Remediación" icon="check">
              <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 10, marginBottom: 12 }}>
                <KV label="Estado de parche" value={describePatchStatus(detail.patchAvailable)} tone={detail.patchAvailable === true ? C.lowBg : detail.patchAvailable === false ? C.highBg : C.gray50} />
                <KV label="Prioridad" value={detail.patchPriority || "No informada"} />
              </div>
              {hasValue(fixedVersions) && (
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 6 }}>Versiones corregidas</div>
                  <RichValue value={fixedVersions} />
                </div>
              )}
              {hasValue(workarounds) && (
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 6 }}>Mitigaciones</div>
                  <RichValue value={workarounds} />
                </div>
              )}
              {hasValue(detectionOpportunities) && (
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 6 }}>Oportunidades de detección</div>
                  <RichValue value={detectionOpportunities} />
                </div>
              )}
            </DetailBlock>

            {/* ═══ REFERENCIAS ═══ */}
            <DetailBlock title="Referencias" icon="link">
              {Object.entries(REFERENCE_CATEGORY_META).map(([category, meta]) => {
                const group = referenceGroups[category];
                if (group.links.length === 0 && group.metadata.length === 0) return null;
                return (
                  <div key={category} style={{ marginBottom: category === "other" ? 0 : 14 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 6 }}>{meta.title}</div>
                    <LinkList items={group.links} empty={meta.empty} accent={meta.accent} />
                  </div>
                );
              })}
            </DetailBlock>

            {/* ═══ HISTORIAL DE CAMBIOS ═══ */}
            {changeTimeline.length > 0 && (() => {
              const groupKey = (d) => {
                if (!d) return "Fecha desconocida";
                const dt = new Date(d);
                if (isNaN(dt)) return "Fecha desconocida";
                return `${dt.toLocaleDateString("es-ES", { year: "numeric", month: "short", day: "numeric" })} · ${dt.toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit" })}`;
              };
              const grouped = [];
              const seen = new Map();
              changeTimeline.forEach((change) => {
                const key = groupKey(change.detectedAt);
                if (!seen.has(key)) { seen.set(key, grouped.length); grouped.push({ key, changes: [] }); }
                grouped[seen.get(key)].changes.push(change);
              });
              return (
                <DetailBlock title="Historial de cambios" icon="clock">
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {grouped.map((group) => {
                      const hasSignificant = group.changes.some((c) => c.isSignificant);
                      return (
                        <div key={group.key} style={{ borderRadius: 8, border: `1px solid ${hasSignificant ? "#FCA5A5" : C.gray200}`, overflow: "hidden" }}>
                          <div style={{ padding: "6px 14px", background: hasSignificant ? "#FEF2F2" : "#F8FAFC", borderBottom: `1px solid ${hasSignificant ? "#FECACA" : C.gray100}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                            <span style={{ fontSize: 11, fontWeight: 700, color: hasSignificant ? C.critical : C.gray700, fontFamily: "'JetBrains Mono', monospace" }}>{group.key}</span>
                            <span style={{ fontSize: 10, color: C.gray500 }}>{group.changes.length} cambio{group.changes.length !== 1 ? "s" : ""}</span>
                          </div>
                          <div style={{ display: "flex", flexDirection: "column" }}>
                            {group.changes.map((change, idx) => (
                              <div key={change.id || idx} style={{ padding: "8px 14px", borderBottom: idx < group.changes.length - 1 ? `1px solid ${C.gray100}` : "none", background: change.isSignificant ? C.criticalBg : "#fff" }}>
                                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                                  <SoftBadge label={getChangeTypeLabel(change.changeType)} small bg={C.white} color={C.navy} border={C.gray300} />
                                  <SoftBadge label={translateFieldName(change.fieldName || "campo")} small bg={C.white} color={C.gray700} border={C.gray300} />
                                  {change.isSignificant && <SoftBadge label="Significativo" small bg={C.criticalBg} color={C.critical} border="#FCA5A5" />}
                                </div>
                                <div style={{ fontSize: 11, color: C.gray700, fontWeight: 600, marginTop: 3 }}>
                                  {change.summary || "Cambio detectado sin resumen adicional."}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </DetailBlock>
              );
            })()}
          </div>

          {/* ═══ SIDEBAR ═══ */}
          <aside className="occ-vuln-detail-side">
            <Card title="Datos clave" icon="bug">
              <div style={{ display: "flex", flexDirection: "column" }}>
                {[
                  { label: "CVE", value: detail.cveId },
                  { label: "Producto", value: semantic.hasReliablePrimaryEntity ? semantic.displayTitle : "Clasificación pendiente" },
                  { label: "Tipo", value: componentTypeMeta(semantic.componentType).label },
                  { label: "Estado", value: recordStatusMeta(detail.recordStatus).label },
                  { label: "Fuente", value: detail.canonicalSource || "NVD" },
                  { label: "Nº fuentes", value: detail.sourceCount != null ? String(detail.sourceCount) : "?" },
                  { label: "Confianza", value: fmtConfidence(detail.dataConfidence) },
                  { label: "Último cambio", value: fmtDate(detail.lastChangeDetectedAt) },
                ].map((item) => (
                  <div key={item.label} style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: `1px solid ${C.gray100}`, fontSize: 11 }}>
                    <span style={{ color: C.gray500, fontWeight: 600 }}>{item.label}</span>
                    <span style={{ color: C.text, fontWeight: 700, textAlign: "right" }}>{item.value}</span>
                  </div>
                ))}
              </div>
            </Card>
          </aside>
        </div>
      </div>
    );
  };

  // Find contacts (subscribers) affected by a CVE
  const getAffectedContacts = (vuln) => {
    if (!vuln) return [];
    const prods = getOperationalAffectedPairs(vuln).map((product) => `${product.vendor}/${product.product}`.toLowerCase());
    return contacts.filter(c => (c.subscriptions || []).some(s => prods.includes(`${s.vendor}/${s.product}`.toLowerCase())));
  };

  // AI Chat handler
  const handleAiSend = async (messageOverride = null) => {
    const prompt = (typeof messageOverride === "string" ? messageOverride : aiQuery).trim();
    if (!prompt) return;
    const userMsg = prompt;
    setAiMessages(prev => [...prev, { role: "user", content: userMsg }]);
    if (messageOverride == null) setAiQuery("");
    setAiLoading(true);

    const context = `Eres el asistente de IA de la Oficina de Ciberseguridad Corporativa (OCC) de SEIDOR. Tu rol es analizar vulnerabilidades (CVEs), evaluar impacto en la infraestructura corporativa, y recomendar acciones de remediación.

Base de datos actual: ${dash.totalAll || vulns.length} CVEs indexados.
Top CVEs con explotación activa: ${(dash.topExploited || []).map(v => v.cveId).join(", ")}.

Responde siempre en español, con rigor técnico. Incluye CVE IDs específicos cuando sea relevante.
Usa únicamente datos técnicos de vulnerabilidades y no incluyas datos de usuarios/contactos.`;

    try {
      const res = await apiFetch("/ai/chat", {
        method: "POST",
        body: JSON.stringify({
          messages: [
            { role: "system", content: context },
            ...aiMessages.map(m => ({ role: m.role, content: m.content })),
            { role: "user", content: userMsg },
          ],
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setAiMessages(prev => [...prev, { role: "assistant", content: data?.content || "Sin respuesta del modelo." }]);
      } else {
        throw new Error("AI API error");
      }
    } catch (e) {
      setAiMessages(prev => [...prev, {
        role: "assistant",
        content: `No se pudo obtener respuesta del asistente IA. Verifica la configuración de Ollama en el backend.\n\nDetalle: ${e?.message || "Error desconocido"}`,
      }]);
    }
    setAiLoading(false);
  };

  const analyzeVulnerabilityWithAi = async (v) => {
    if (!v) return;
    const semantic = getSemanticSummary(v);
    const affectedLabel = semantic.hasReliablePrimaryEntity
      ? semantic.displayTitle
      : getOperationalAffectedPairs(v).slice(0, 4).map((product) => `${product.vendor}/${product.product}`).join(", ") || "Clasificación pendiente";
    const prompt = `Analiza el impacto de ${v.cveId} en nuestra infraestructura.
Entidad o componentes afectados: ${affectedLabel}.
CVSS: ${v.cvssV31Score ?? "N/A"} (${v.cvssV31Severity || "N/A"}).
EPSS: ${fmtEpss(v.epssScore)}.
Indica prioridad, acciones inmediatas y plan de mitigación.`;
    setView("ai");
    setVulnDetail(null);
    setAiQuery(prompt);
    await handleAiSend(prompt);
  };

  const generateSimulatedResponse = (q) => {
    const ql = q.toLowerCase();
    if (ql.includes("cve-2025-21298") || ql.includes("windows ole")) return `**CVE-2025-21298 — Windows OLE RCE**\n\n**Severidad:** CRITICAL (CVSS 9.8) | **EPSS:** 94.3% probabilidad de explotación\n**Estado:** ⚠️ Explotación activa confirmada (CISA KEV)\n\n**Impacto en infraestructura OCC:**\n- Afecta a microsoft/windows_11 y windows_server_2022\n- **Equipo afectado:** Infraestructura Windows (infra-windows@corp.local)\n- Ventana de parcheo configurada: domingos 02:00-06:00\n\n**Recomendación:**\nDada la explotación activa, recomiendo solicitar parcheo de emergencia fuera de la ventana habitual. El vector de ataque es via documentos manipulados (OLE), lo que implica riesgo directo por phishing.\n\n**Acciones inmediatas:**\n1. Notificar a Pedro Gómez (infra-windows) para parcheo urgente\n2. Bloquear adjuntos OLE en el gateway de correo temporalmente\n3. Verificar detecciones en EDR para intentos de explotación`;
    if (ql.includes("fortinet") || ql.includes("fortigate") || ql.includes("fortios")) return `**Análisis FortiOS — CVE-2024-55591**\n\n**Severidad:** CRITICAL (CVSS 9.8) | Authentication Bypass\n**Estado:** Explotación activa confirmada\n\n**Detalle técnico:**\nBypass de autenticación via Node.js websocket en FortiOS permite a un atacante no autenticado obtener privilegios de super-admin mediante requests CSF proxy manipulados.\n\n**Impacto en OCC:**\n- **Equipo afectado:** Redes y Firewalls (redes-fw@corp.local)\n- FortiOS configurado en HA activo-pasivo según notas del equipo\n- Requiere CAB approval excepto P1 — esta vulnerabilidad califica como P1\n\n**Remediación:**\n1. Actualizar a FortiOS ≥7.0.17 inmediatamente\n2. Verificar logs de admin para accesos no autorizados\n3. Revisar reglas CSF proxy y deshabilitar si no se usa\n4. Contactar a Laura Martín para coordinar`;
    if (ql.includes("resumen") || ql.includes("estado") || ql.includes("informe")) return `**Resumen ejecutivo — Estado de vulnerabilidades**\n\n📊 **Publicadas en 24h:** ${todayT} CVEs\n- 🔴 Critical: ${gc(dash.today, "CRITICAL")} | 🟠 High: ${gc(dash.today, "HIGH")} | 🟡 Medium: ${gc(dash.today, "MEDIUM")}\n\n⚡ **KEV confirmadas:** ${kevConfirmedT} CVEs confirmados en CISA KEV\n\n**Top prioridades:**\n1. **CVE-2025-21298** (Windows OLE) — CVSS 9.8, EPSS 94.3% → Equipo Infra Windows\n2. **CVE-2024-55591** (FortiOS) — CVSS 9.8, EPSS 87.6% → Equipo Redes\n3. **CVE-2025-0282** (Ivanti CS) — CVSS 9.0, EPSS 89.1% → Equipo VPN\n\n**Recomendación:** Convocar reunión de emergencia con los equipos afectados para coordinar parcheo prioritario de las CVEs KEV y las de mayor criticidad.`;
    if (ql.includes("ivanti")) return `**Análisis Ivanti — Múltiples CVEs activas**\n\n**CVE-2025-0282** (Connect Secure) — CVSS 9.0\nBuffer overflow en stack permite RCE sin autenticación. Exploit público disponible.\n\n**CVE-2024-8963** (CSA) — CVSS 9.4\nPath traversal permite acceso no autenticado a funcionalidad restringida.\n\n**Impacto OCC:**\n- **Equipo VPN y Acceso Remoto** (vpn-team@corp.local)\n- 2 appliances en producción (Madrid y Barcelona)\n- Contacto: Carlos Ruiz\n\n**Acciones:**\n1. Verificar versión actual de Connect Secure (vulnerable si <22.7R2.5)\n2. Aplicar parche fuera de horario laboral según protocolo del equipo\n3. Ejecutar Integrity Checker Tool de Ivanti post-parcheo\n4. Revisar logs de acceso VPN de las últimas 2 semanas`;
    return `Procesando consulta: "${q}"\n\n**Análisis basado en la base de datos OCC:**\n\nActualmente hay ${dash.totalAll || vulns.length} CVEs indexados.\n\nLos equipos IT con mayor exposición son:\n${contacts.map(c => `- **${c.name}**: ${(c.products || []).length} productos monitorizados`).join("\n")}\n\n¿Necesitas un análisis más específico? Puedo detallar:\n- Impacto de un CVE concreto en la infraestructura\n- Vulnerabilidades que afectan a un producto/vendor\n- Priorización de parcheo recomendada\n- Draft de comunicación a un equipo IT`;
  };

  const handleCollect = async () => {
    setCollecting(true);
    try { await apiFetch("/vulnerabilities/collect", { method: "POST" }); await loadData("overview"); } catch (e) { console.error(e); }
    setCollecting(false);
  };

  const setStoredBackfillJobId = (jobId) => {
    const value = String(jobId || "").trim();
    setBackfillJobId(value);
    if (value) localStorage.setItem("occ_backfill_job_id", value);
    else localStorage.removeItem("occ_backfill_job_id");
  };

  const refreshBackfillStatus = async (jobIdOverride) => {
    const jobId = String(jobIdOverride || backfillJobId || "").trim();
    if (!jobId) {
      setBackfillMsg({ type: "error", text: "No hay jobId de backfill para consultar." });
      return;
    }
    try {
      const data = await callBackfillApi(`/status/${encodeURIComponent(jobId)}`);
      if (data?.error) throw new Error(data.error);
      setBackfillStatus(data);
      if (data?.job?.jobId) {
        setStoredBackfillJobId(data.job.jobId);
      }
      setBackfillMsg({ type: "success", text: `Estado cargado (${data?.job?.status || "N/A"})` });
    } catch (e) {
      setBackfillMsg({ type: "error", text: e?.message || "No se pudo consultar el estado del backfill" });
    }
  };

  const startBackfill = async () => {
    setBackfillBusy(true);
    setBackfillMsg(null);
    try {
      const data = await callBackfillApi("/start", { method: "POST" });
      if (!data?.jobId) throw new Error("Respuesta inválida al iniciar/reanudar backfill");
      setStoredBackfillJobId(data.jobId);
      setBackfillMsg({
        type: "success",
        text: data?.resumed ? `Backfill reanudado (${data.jobId})` : `Backfill iniciado (${data.jobId})`,
      });
      await refreshBackfillStatus(data.jobId);
    } catch (e) {
      setBackfillMsg({ type: "error", text: e?.message || "No se pudo iniciar/reanudar el backfill" });
    }
    setBackfillBusy(false);
  };

  const runBackfillToCompletion = async () => {
    const jobId = String(backfillJobId || "").trim();
    if (!jobId) {
      setBackfillMsg({ type: "error", text: "Primero inicia/reanuda un backfill para obtener jobId." });
      return;
    }
    setBackfillBusy(true);
    setBackfillMsg(null);
    try {
      const data = await callBackfillApi(`/run/${encodeURIComponent(jobId)}`, { method: "POST" });
      setBackfillMsg({
        type: "success",
        text: data?.alreadyRunning
          ? "Backfill ya estaba ejecutándose en segundo plano."
          : "Backfill lanzado en segundo plano. Usa Estado para seguimiento.",
      });
      await refreshBackfillStatus(jobId);
      await loadData("collector");
    } catch (e) {
      setBackfillMsg({ type: "error", text: e?.message || "Fallo al ejecutar el backfill" });
    }
    setBackfillBusy(false);
  };

  const handleReport = async () => {
    setGenerating(true); setReportResult(null);
    try {
      const r = await apiFetch(`/vulnerabilities/report?hours=${reportHours}&minSeverity=${reportSev}`, { method: "POST" });
      const d = await r.json(); setReportResult(d); await loadData("reports");
    } catch (e) { console.error(e); } setGenerating(false);
  };

  const saveContact = async (c) => {
    try {
      // Build User-compatible payload
      const payload = {
        name: c.name,
        email: c.email,
        isSubscriber: true,
        canLogin: false,
        notificationEmail: c.email,
        contactPerson: c.contactPerson || null,
        department: c.department || null,
        phone: c.phone || null,
        notes: c.notes || null,
        subscriptions: (c.products || []).map(p => {
          if (typeof p === 'string') {
            const parts = p.split('/');
            return parts.length >= 2
              ? { vendor: parts[0].trim().toLowerCase(), product: parts.slice(1).join('/').trim().toLowerCase(), versions: [] }
              : null;
          }
          if (p && typeof p === 'object') return { vendor: (p.vendor || '').toLowerCase(), product: (p.product || '').toLowerCase(), versions: p.versions || [] };
          return null;
        }).filter(Boolean),
      };
      if (c.id) { await apiFetch(`/users/${c.id}`, { method: "PUT", body: JSON.stringify(payload) }); }
      else { await apiFetch("/users", { method: "POST", body: JSON.stringify(payload) }); }
      await loadData("contacts");
    } catch (e) { console.error(e); }
    setEditContact(null); setShowContactForm(false);
  };
  const deleteContact = async (id) => { try { await apiFetch(`/users/${id}`, { method: "DELETE" }); await loadData("contacts"); } catch (e) { console.error(e); } };

  // Users CRUD
  const openUserForm = (u = null) => {
    const state = buildUserFormState(u || {});
    setEditUser(state);
    setShowUserForm(true);
  };

  const updateUserField = (field, value, extra = {}) => {
    setEditUser((prev) => ({
      ...prev,
      [field]: value,
      ...extra,
    }));
  };

  const addUserTeamAssignment = () => {
    setEditUser((prev) => ({
      ...prev,
      teamAssignmentsTouched: true,
      teamAssignments: [...(prev?.teamAssignments || []), createDefaultTeamAssignment()],
    }));
  };

  const updateUserTeamAssignment = (index, patch) => {
    setEditUser((prev) => ({
      ...prev,
      teamAssignmentsTouched: true,
      teamAssignments: (prev?.teamAssignments || []).map((assignment, currentIndex) => (
        currentIndex === index ? { ...assignment, ...patch } : assignment
      )),
    }));
  };

  const removeUserTeamAssignment = (index) => {
    setEditUser((prev) => ({
      ...prev,
      teamAssignmentsTouched: true,
      teamAssignments: (prev?.teamAssignments || []).filter((_, currentIndex) => currentIndex !== index),
    }));
  };

  const saveUser = async (u) => {
    try {
      const payload = buildUserPayload(u);

      if (u.id) { await apiFetch(`/users/${u.id}`, { method: "PUT", body: JSON.stringify(payload) }); }
      else { await apiFetch("/users", { method: "POST", body: JSON.stringify(payload) }); }
      await loadData("user-mgmt");
    } catch (e) { console.error(e); }
    setEditUser(null); setShowUserForm(false);
  };
  const deleteUser = async (id) => { try { await apiFetch(`/users/${id}`, { method: "DELETE" }); await loadData("user-mgmt"); } catch (e) { console.error(e); } };

  // Tags CRUD
  // Vulnerability Detail & Actions

  // Load full detail
  async function loadVulnDetail(id) {
    setVulnLoading(true);
    try {
      const r = await apiFetch(`/vulnerabilities/${id}`);
      setVulnDetail(await r.json());
    } catch (e) { console.error(e); }
    setVulnLoading(false);
  }

  async function loadVulnDetailByCveId(cveId) {
    const normalizedCveId = String(cveId || "").trim().toUpperCase();
    if (!normalizedCveId) return;
    setVulnLoading(true);
    try {
      const r = await apiFetch(`/vulnerabilities/cve/${encodeURIComponent(normalizedCveId)}`);
      setVulnDetail(await r.json());
    } catch (e) { console.error(e); }
    setVulnLoading(false);
  }

  const openVulnerabilityDetail = useCallback((v, options = {}) => {
    const sourceView = normalizeDetailSourceView(options.sourceView || (view === "exploited" ? "exploited" : "vulns"));
    const cveId = String(v?.cveId || "").trim().toUpperCase();
    const id = v?.id || vulns.find((x) => x.cveId === cveId)?.id;
    if (!cveId && !id) return;
    setSelectedVuln(v);
    setDetailProductFilter("");
    setDetailExploitFilter("");
    setDetailContext({ sourceView, cveId: cveId || String(v?.cveId || "").trim() });
    setView(DETAIL_VIEW);
    window.history.pushState({}, "", getDetailPathForView(sourceView, cveId || v?.cveId));
    if (id) loadVulnDetail(id);
    else loadVulnDetailByCveId(cveId || v?.cveId);
  }, [loadVulnDetail, loadVulnDetailByCveId, view, vulns]);

  const openNotifyModal = async () => {
    setShowNotifModal(true);
    if (contacts.length > 0) return;
    setNotifContactsLoading(true);
    try {
      const r = await apiFetch("/users");
      const data = await r.json();
      const subscribers = (Array.isArray(data) ? data : []).filter(u => u.isSubscriber);
      setContacts(subscribers);
    } catch (e) {
      console.error(e);
    } finally {
      setNotifContactsLoading(false);
    }
  };

  // Send notification
  const handleNotifyContact = async (contactId) => {
    if (!vulnDetail) return;
    const parsedContactId = Number(contactId);
    if (!Number.isInteger(parsedContactId) || parsedContactId <= 0) {
      alert("Contacto inválido");
      return;
    }
    setNotifSending(true);
    try {
      const res = await apiFetch(`/vulnerabilities/${vulnDetail.id}/notify`, {
        method: "POST",
        body: JSON.stringify({ contactId: parsedContactId })
      });
      if (res.ok) {
        await loadVulnDetail(vulnDetail.id); // Reload to see history
        setShowNotifModal(false);
        alert("Notificación enviada correctamente");
      } else {
        throw new Error("Error enviando notificación");
      }
    } catch (e) { alert(e.message); }
    setNotifSending(false);
  };

  // Manage tags on vuln
  const handleVulnTags = async (newTags) => {
    if (!vulnDetail) return;
    try {
      const tagIds = newTags.map(t => t.id);
      await apiFetch(`/vulnerabilities/${vulnDetail.id}/tags`, {
        method: "POST",
        body: JSON.stringify({ tagIds })
      });
      setVulnDetail({ ...vulnDetail, tags: newTags });
      // Update list view too if possible
      setVulns(vulns.map(v => v.id === vulnDetail.id ? { ...v, tags: newTags } : v));
    } catch (e) { console.error(e); }
  };

  const addTag = async () => {
    if (!newTagName.trim()) return;
    try { await apiFetch("/tags", { method: "POST", body: JSON.stringify({ name: newTagName, color: newTagColor }) }); setNewTagName(""); await loadData("settings"); } catch (e) { console.error(e); }
  };
  const deleteTag = async (id) => { try { await apiFetch(`/tags/${id}`, { method: "DELETE" }); await loadData("settings"); } catch (e) { console.error(e); } };

  const createManufacturer = async () => {
    const name = newManufacturerName.trim().toLowerCase();
    if (!name) return;
    try {
      const res = await apiFetch("/manufacturers", {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      if (!res.ok) throw new Error("No se pudo crear fabricante");
      setNewManufacturerName("");
      await loadData("manufacturers");
      await loadData("settings");
      setSelectedManufacturer(name);
      setMergeForm({ targetName: name, sourceNames: [name] });
    } catch (e) {
      alert(e.message);
    }
  };

  const createManufacturerProduct = async () => {
    const vendor = String(newProductForm.vendor || "").trim().toLowerCase();
    const product = String(newProductForm.product || "").trim().toLowerCase();
    if (!vendor || !product) return;

    const versions = String(newProductForm.versions || "")
      .split(",")
      .map(v => v.trim())
      .filter(Boolean);

    try {
      const res = await apiFetch("/manufacturers/products", {
        method: "POST",
        body: JSON.stringify({ vendor, product, versions }),
      });
      if (!res.ok) throw new Error("No se pudo crear producto");
      setNewProductForm({ vendor, product: "", versions: "" });
      await loadData("manufacturers");
      await loadData("settings");
      setSelectedManufacturer(vendor);
    } catch (e) {
      alert(e.message);
    }
  };

  const toggleMergeSource = (name, checked) => {
    setMergeForm(prev => ({
      ...prev,
      sourceNames: checked
        ? [...new Set([...(prev.sourceNames || []), name])]
        : (prev.sourceNames || []).filter(v => v !== name),
    }));
  };

  const applyManufacturerMerge = async () => {
    const targetName = String(mergeForm.targetName || "").trim().toLowerCase();
    const sourceNames = [...new Set((mergeForm.sourceNames || []).map(v => String(v || "").trim().toLowerCase()).filter(Boolean))];
    if (!targetName || sourceNames.length === 0) return;

    try {
      const res = await apiFetch("/manufacturers/merge", {
        method: "POST",
        body: JSON.stringify({ targetName, sourceNames }),
      });
      if (!res.ok) throw new Error("No se pudo armonizar fabricantes");
      await loadData("manufacturers");
      await loadData("settings");
      setSelectedManufacturer(targetName);
      setMergeForm({ targetName, sourceNames: [targetName] });
      alert("Fabricantes armonizados correctamente");
    } catch (e) {
      alert(e.message);
    }
  };

  // Notification detail
  const viewNotification = async (id) => {
    try { const r = await apiFetch(`/notifications/history/${id}`); setNotifDetail(await r.json()); } catch (e) { console.error(e); }
  };

  const updateNotificationCenterSection = (section, patch) => {
    setNotificationCenter((prev) => normalizeNotificationCenterSettings({
      ...prev,
      [section]: {
        ...(prev?.[section] || {}),
        ...(patch || {}),
      },
    }));
  };

  const saveNotificationCenterSettings = async () => {
    setNotificationCenterSaving(true);
    setNotificationCenterMsg(null);
    try {
      const res = await apiFetch("/notifications/settings-center", {
        method: "POST",
        body: JSON.stringify(notificationCenter),
      });
      if (!res.ok) throw new Error("No se pudo guardar la configuración de notificaciones");
      const data = await res.json();
      setNotificationCenter(normalizeNotificationCenterSettings(data));
      setNotificationCenterMsg({ type: "success", text: "Configuración de notificaciones actualizada" });
    } catch (e) {
      setNotificationCenterMsg({ type: "error", text: e?.message || "Error guardando la configuración" });
    } finally {
      setNotificationCenterSaving(false);
      setTimeout(() => setNotificationCenterMsg(null), 3500);
    }
  };

  const runNotificationJobNow = async (jobType) => {
    setNotificationProcessRunning(jobType);
    setNotificationCenterMsg(null);
    try {
      let res;
      if (jobType === "intelligent_notification_job") {
        res = await apiFetch("/smart-notifications/intelligent/run", {
          method: "POST",
          body: JSON.stringify({}),
        });
      } else {
        res = await apiFetch("/notifications/process/run-now", {
          method: "POST",
          body: JSON.stringify({ jobType }),
        });
      }
      const data = await res.json();
      if (!res.ok || data?.success === false) throw new Error(data?.message || "No se pudo ejecutar el proceso");
      setNotificationCenterMsg({ type: "success", text: data?.message || "Proceso ejecutado correctamente" });
      await loadData("settings");
      await loadData("notifications");
    } catch (e) {
      setNotificationCenterMsg({ type: "error", text: e?.message || "Error ejecutando el proceso" });
    } finally {
      setNotificationProcessRunning("");
      setTimeout(() => setNotificationCenterMsg(null), 4000);
    }
  };

  const sendNotificationProcessTest = async (jobType) => {
    if (jobType === "intelligent_notification_job") {
      setIntelligentTestOpen(true);
      return;
    }
    if (!notificationOpsEmail.trim()) {
      setNotificationCenterMsg({ type: "error", text: "Indica un email de prueba" });
      return;
    }
    setNotificationTestRunning(jobType);
    setNotificationCenterMsg(null);
    try {
      const endpoint = jobType === "immediate_notification_job"
        ? "/notifications/test-instant"
        : jobType === "digest_notification_job"
          ? "/notifications/test-periodic"
          : "/notifications/test-smart";
      const res = await apiFetch(endpoint, {
        method: "POST",
        body: JSON.stringify({ email: notificationOpsEmail.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.message || "No se pudo enviar la prueba");
      setNotificationCenterMsg({ type: "success", text: `Prueba enviada a ${notificationOpsEmail.trim()}` });
      await loadData("notifications");
      await loadData("settings");
    } catch (e) {
      setNotificationCenterMsg({ type: "error", text: e?.message || "Error enviando la prueba" });
    } finally {
      setNotificationTestRunning("");
      setTimeout(() => setNotificationCenterMsg(null), 4000);
    }
  };

  const executeIntelligentTest = async () => {
    setNotificationTestRunning("intelligent_notification_job");
    setNotificationCenterMsg(null);
    try {
      const payload = {
        subscriberId: intelligentTestForm.subscriberId ? Number(intelligentTestForm.subscriberId) : undefined,
        mode: intelligentTestForm.mode,
        language: intelligentTestForm.language === "en" ? "en" : "es",
        primaryWindowHours: Number(intelligentTestForm.primaryWindowHours || 24),
        recentContextDays: Number(intelligentTestForm.recentContextDays || 7),
        historicalContextDays: Number(intelligentTestForm.historicalContextDays || 60),
        useRecentRealData: intelligentTestForm.useRecentRealData !== false,
        targetEmail: intelligentTestForm.mode === "send_test" ? (intelligentTestForm.targetEmail || notificationOpsEmail || "") : undefined,
      };
      const res = await apiFetch("/smart-notifications/intelligent/test", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.message || "No se pudo ejecutar la prueba inteligente");
      setIntelligentTestResult(data);
      setIntelligentTestOpen(true);
      setNotificationCenterMsg({
        type: "success",
        text: data?.findingsDetected > 0
          ? `Prueba inteligente completada con ${data.findingsDetected} hallazgo(s)`
          : "Prueba inteligente completada sin hallazgos relevantes",
      });
      await loadData("settings");
      await loadData("notifications");
    } catch (e) {
      setNotificationCenterMsg({ type: "error", text: e?.message || "Error ejecutando la prueba inteligente" });
    } finally {
      setNotificationTestRunning("");
      setTimeout(() => setNotificationCenterMsg(null), 5000);
    }
  };

  const resendCommunication = async (id) => {
    try {
      const res = await apiFetch(`/notifications/history/${id}/resend`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.message || "No se pudo reenviar la comunicación");
      setNotifMsg({ type: "success", text: "Comunicación reenviada correctamente" });
      await loadData("notifications");
    } catch (e) {
      setNotifMsg({ type: "error", text: e?.message || "Error reenviando la comunicación" });
    } finally {
      setTimeout(() => setNotifMsg(null), 3500);
    }
  };

  const saveTemplateConfig = async () => {
    setTemplateSaving(true);
    try {
      const res = await apiFetch("/notifications/template-config", {
        method: "POST",
        body: JSON.stringify({
          ...templateConfig,
          name: templateName,
          templateId: selectedTemplateId ? Number(selectedTemplateId) : undefined,
        }),
      });
      if (!res.ok) throw new Error("Error guardando plantilla");
      setNotificationCenterMsg({ type: "success", text: "Plantilla guardada correctamente" });
      await loadData("settings");
    } catch (e) {
      setNotificationCenterMsg({ type: "error", text: "Error guardando plantilla" });
    } finally {
      setTemplateSaving(false);
      setTimeout(() => setNotificationCenterMsg(null), 3000);
    }
  };

  const loadTemplateById = async (id) => {
    if (!id) return;
    setTemplateLoading(true);
    try {
      const res = await apiFetch(`/notifications/template-config/${id}`);
      if (!res.ok) throw new Error("Error cargando plantilla");
      const data = await res.json();
      setTemplateConfig(prev => ({ ...prev, ...data }));
      setTemplateName(data?.name || "Plantilla CVE");
      setSelectedTemplateId(String(id));
    } catch (e) {
      setNotificationCenterMsg({ type: "error", text: "Error cargando plantilla" });
      setTimeout(() => setNotificationCenterMsg(null), 3000);
    } finally {
      setTemplateLoading(false);
    }
  };

  const activateTemplate = async () => {
    if (!selectedTemplateId) return;
    try {
      const res = await apiFetch(`/notifications/template-config/${selectedTemplateId}/activate`, {
        method: "POST",
      });
      if (!res.ok) throw new Error("Error activando plantilla");
      setNotificationCenterMsg({ type: "success", text: "Plantilla activada" });
      await loadData("settings");
    } catch (e) {
      setNotificationCenterMsg({ type: "error", text: "Error activando plantilla" });
    } finally {
      setTimeout(() => setNotificationCenterMsg(null), 3000);
    }
  };

  const onTemplateHeaderUpload = (file) => {
    if (!file) return;
    if (file.size > 1.5 * 1024 * 1024) {
      setNotificationCenterMsg({ type: "error", text: "La imagen de cabecera es demasiado grande (máx. 1.5MB)" });
      setTimeout(() => setNotificationCenterMsg(null), 3500);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setTemplateConfig(prev => ({ ...prev, headerImageUrl: String(reader.result || "") }));
    };
    reader.readAsDataURL(file);
  };

  const generateTemplatePreview = async () => {
    if (!previewVulnId) return;
    setTemplatePreviewLoading(true);
    try {
      const res = await apiFetch("/notifications/template-preview", {
        method: "POST",
        body: JSON.stringify({
          vulnerabilityId: Number(previewVulnId),
          config: templateConfig,
        }),
      });
      if (!res.ok) throw new Error("Error generando vista previa");
      const data = await res.json();
      setTemplatePreviewHtml(data.html || "");
      setTemplatePreviewMeta({
        cveId: data.cveId || "",
        manufacturer: data.manufacturer || "",
      });
    } catch {
      setNotificationCenterMsg({ type: "error", text: "Error generando vista previa" });
      setTimeout(() => setNotificationCenterMsg(null), 3000);
    } finally {
      setTemplatePreviewLoading(false);
    }
  };

  const sw = collapsed ? 56 : 232;
  const currentUser = getUser();
  const allNav = [
    { id: "overview", label: "Visión General", icon: "shield" },
    { id: "vulns", label: "Catálogo de vulnerabilidades", icon: "bug" },
    { id: "exploited", label: "Explotación CVE", icon: "zap" },
    { id: "portal", label: "Mis Suscripciones", icon: "mail" },
    { id: "account", label: "Tu cuenta", icon: "users" },
    { id: "manufacturers", label: "Fabricantes", icon: "server" },
    { id: "notifications", label: "Comunicaciones", icon: "mail" },
    { id: "reports", label: "Informes", icon: "file" },
    { id: "ai", label: "Asistente IA", icon: "brain" },
    { id: "collector", label: "Collector", icon: "server" },
    { id: "subscriber-teams", label: "Equipos suscriptores", icon: "users" },
    { id: "user-mgmt", label: "Gestión usuarios", icon: "users" },
    { id: "settings", label: "Configuración", icon: "settings" },
  ];
  {
    const ids = allNav.map((n) => n.id);
    const unique = new Set(ids);
    if (unique.size !== ids.length) throw new Error("Invalid navigation: duplicate ids");
    if (!unique.has("vulns")) throw new Error("Invalid navigation: missing vulns");
    if (!unique.has("exploited")) throw new Error("Invalid navigation: missing exploited");
    if (ids.indexOf("exploited") < ids.indexOf("vulns")) throw new Error("Invalid navigation: exploited before vulns");
    const exploitedItem = allNav.find((n) => n.id === "exploited");
    if (exploitedItem?.parent) throw new Error("Invalid navigation: exploited must be top-level");
  }
  const role = (currentUser?.role || "USER").toUpperCase();
  const isAdmin = role === "ADMIN";
  const isGlobalTeamManager = role === "TEAM_MANAGER";
  const isSubscriber = role === "SUBSCRIBER";
  const isViewer = role === "VIEWER";
  const subscriberAllowedViews = ["vulns", "exploited", "portal", "account"];
  const viewerAllowedViews = ["vulns", "exploited", "account"];
  const teamManagerAllowedViews = ["overview", "vulns", "exploited", "account", "subscriber-teams"];
  const nav = isAdmin
    ? allNav
    : (
      isGlobalTeamManager
        ? allNav.filter((n) => teamManagerAllowedViews.includes(n.id))
        : (
      isSubscriber
        ? allNav.filter((n) => subscriberAllowedViews.includes(n.id))
        : (isViewer ? allNav.filter((n) => viewerAllowedViews.includes(n.id)) : allNav.filter((n) => !["user-mgmt", "subscriber-teams"].includes(n.id)))
        )
    );
  const userTeamAssignmentErrors = editUser && shouldValidateTeamAssignments(editUser)
    ? validateTeamAssignments(
      editUser.teamAssignments || [],
      getEffectiveGlobalRoleForTeamAssignments(editUser),
    )
    : {};
  const navActiveView = view === DETAIL_VIEW ? normalizeDetailSourceView(detailContext.sourceView) : view;
  const currentSection = view === DETAIL_VIEW
    ? `${nav.find((n) => n.id === navActiveView)?.label || "Vulnerabilidades"} · ${detailContext.cveId || "Detalle CVE"}`
    : view === "subscriber-teams" && subscriberTeamsRoute.teamId
      ? "Equipos suscriptores · Detalle"
    : nav.find((n) => n.id === view)?.label || "Panel";
  const backfillMetrics = parseMaybeJsonObject(backfillStatus?.metrics || backfillStatus?.job?.metrics);
  const backfillCheckpointSummary = parseMaybeJsonObject(backfillStatus?.checkpointSummary);
  const backfillProgress = parseMaybeJsonObject(backfillStatus?.progress);
  const backfillCheckpointTotal = Number(
    backfillCheckpointSummary.total ||
    ((backfillStatus?.remaining || 0) + (backfillStatus?.checkpoints?.DONE || 0)),
  );
  const backfillCheckpointDone = Number(
    backfillCheckpointSummary.done || backfillStatus?.checkpoints?.DONE || 0,
  );
  const backfillRequestsProcessed = Number(
    backfillProgress.requestsProcessed || backfillMetrics.requestsProcessed || backfillMetrics.pagesProcessed || 0,
  );
  const backfillItemsFetched = Number(
    backfillProgress.itemsFetched || backfillMetrics.itemsFetched || 0,
  );
  const backfillInserted = Number(
    backfillProgress.inserted || backfillMetrics.inserted || 0,
  );
  const backfillUpdated = Number(
    backfillProgress.updated || backfillMetrics.updated || 0,
  );
  const backfillUnchanged = Number(
    backfillProgress.unchanged || backfillMetrics.unchanged || 0,
  );
  const backfillErrors = Number(
    backfillProgress.errors || backfillMetrics.errors || 0,
  );

  const navIds = nav.map((n) => n.id).join("|");
  useEffect(() => {
    if (view === DETAIL_VIEW) return;
    if (!nav.some((n) => n.id === view)) {
      setView(nav[0]?.id || "overview");
    }
  }, [detailContext.sourceView, navIds, view]);

  return (
    !isLoggedIn ? (
      <div className="occ-login-shell" style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 24, fontFamily: "var(--occ-font-sans)" }}>
        <div className="occ-login-card occ-panel" style={{ background: "#fff", borderRadius: 16, padding: "36px 32px", width: 380 }}>
          <div style={{ textAlign: "center", marginBottom: 28 }}>
            <div style={{ width: 56, height: 56, background: "linear-gradient(135deg, var(--occ-primary) 0%, #3d8bff 100%)", borderRadius: 14, display: "inline-flex", alignItems: "center", justifyContent: "center", marginBottom: 12, padding: 10 }}>
              <img src={occLogo} alt="OCC" style={{ width: "100%", height: "100%", objectFit: "contain" }} />
            </div>
            <h1 style={{ fontSize: 20, fontWeight: 700, color: C.text, margin: "0 0 4px", letterSpacing: "-0.01em" }}>OCC-TVM</h1>
            <p style={{ fontSize: 11, color: C.gray500, margin: 0, letterSpacing: 1, textTransform: "uppercase" }}>Oficina de Ciberseguridad Corporativa</p>
          </div>
          {authMode === "login" && (
            <form onSubmit={handleLogin}>
              <div style={{ marginBottom: 14 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Email</label>
                <input value={loginEmail} onChange={e => setLoginEmail(e.target.value)} type="email" required style={{ width: "100%", padding: "11px 14px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 8, boxSizing: "border-box", outline: "none" }} />
              </div>
              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Contraseña</label>
                <input value={loginPass} onChange={e => setLoginPass(e.target.value)} type="password" required style={{ width: "100%", padding: "11px 14px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 8, boxSizing: "border-box", outline: "none" }} />
              </div>
              <div style={{ textAlign: "right", marginBottom: 16 }}>
                <button type="button" onClick={() => { setAuthMode("forgot"); setForgotEmail(loginEmail); setLoginErr(""); }} style={{ background: "none", border: "none", color: C.blue, fontSize: 12, fontWeight: 600, cursor: "pointer", padding: 0 }}>
                  ¿Olvidaste tu contraseña?
                </button>
              </div>
              {loginErr && <div style={{ background: C.criticalBg, color: C.critical, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>{loginErr}</div>}
              <button type="submit" disabled={loginLoading} style={{ width: "100%", padding: "12px", fontSize: 14, fontWeight: 700, background: C.navy, color: "#fff", border: "none", borderRadius: 8, cursor: "pointer" }}>{loginLoading ? "Accediendo..." : "Iniciar Sesión"}</button>
              {authProviders.azureOidc && (
                <>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "14px 0" }}>
                    <div style={{ height: 1, background: C.gray200, flex: 1 }} />
                    <div style={{ fontSize: 11, color: C.gray500, fontWeight: 700 }}>o</div>
                    <div style={{ height: 1, background: C.gray200, flex: 1 }} />
                  </div>
                  <a href={`${API_BASE}/auth/azure/login`} style={{ display: "block", textAlign: "center", width: "100%", padding: "11px", fontSize: 13, fontWeight: 800, background: "#fff", color: C.navy, border: `1px solid ${C.gray300}`, borderRadius: 8, textDecoration: "none" }}>
                    Entrar con Azure
                  </a>
                </>
              )}
            </form>
          )}

          {authMode === "mfa-enroll" && (
            <form onSubmit={handleMfaEnroll}>
              <div style={{ fontSize: 12, color: C.gray600, marginBottom: 14 }}>
                Activa MFA para continuar. Escanea el QR con tu autenticador y escribe el código.
              </div>
              {mfaQr && (
                <div style={{ display: "flex", justifyContent: "center", marginBottom: 14 }}>
                  <img src={mfaQr} alt="QR MFA" style={{ width: 200, height: 200, borderRadius: 12, border: `1px solid ${C.gray200}` }} />
                </div>
              )}
              {!mfaQr && (
                <div style={{ background: C.infoBg, color: C.info, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 600 }}>
                  Generando QR...
                </div>
              )}
              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Código MFA</label>
                <input value={mfaCode} onChange={e => setMfaCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required style={{ width: "100%", padding: "11px 14px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 8, boxSizing: "border-box", outline: "none" }} />
              </div>
              {mfaErr && <div style={{ background: C.criticalBg, color: C.critical, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 600 }}>{mfaErr}</div>}
              <button type="submit" disabled={mfaLoading} style={{ width: "100%", padding: "12px", fontSize: 14, fontWeight: 800, background: C.navy, color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", marginBottom: 10 }}>{mfaLoading ? "Verificando..." : "Activar MFA"}</button>
              <button type="button" onClick={() => { setAuthMode("login"); setMfaErr(""); setMfaCode(""); setMfaQr(""); setMfaToken(""); }} style={{ width: "100%", padding: "11px", fontSize: 13, fontWeight: 700, background: "#fff", color: C.gray700, border: `1px solid ${C.gray300}`, borderRadius: 8, cursor: "pointer" }}>
                Volver al login
              </button>
            </form>
          )}

          {authMode === "mfa" && (
            <form onSubmit={handleMfaVerify}>
              <div style={{ fontSize: 12, color: C.gray600, marginBottom: 14 }}>
                Introduce el código de tu autenticador para continuar.
              </div>
              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Código MFA</label>
                <input value={mfaCode} onChange={e => setMfaCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required style={{ width: "100%", padding: "11px 14px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 8, boxSizing: "border-box", outline: "none" }} />
              </div>
              {mfaErr && <div style={{ background: C.criticalBg, color: C.critical, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 600 }}>{mfaErr}</div>}
              <button type="submit" disabled={mfaLoading} style={{ width: "100%", padding: "12px", fontSize: 14, fontWeight: 800, background: C.navy, color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", marginBottom: 10 }}>{mfaLoading ? "Verificando..." : "Continuar"}</button>
              <button type="button" onClick={() => { setAuthMode("login"); setMfaErr(""); setMfaCode(""); setMfaToken(""); }} style={{ width: "100%", padding: "11px", fontSize: 13, fontWeight: 700, background: "#fff", color: C.gray700, border: `1px solid ${C.gray300}`, borderRadius: 8, cursor: "pointer" }}>
                Volver al login
              </button>
            </form>
          )}

          {authMode === "forgot" && (
            <form onSubmit={handleForgotPassword}>
              <div style={{ fontSize: 12, color: C.gray600, marginBottom: 14 }}>
                Ingresa tu correo y te enviaremos un enlace de recuperación.
              </div>
              <div style={{ marginBottom: 14 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Email</label>
                <input value={forgotEmail} onChange={e => setForgotEmail(e.target.value)} type="email" required style={{ width: "100%", padding: "11px 14px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 8, boxSizing: "border-box", outline: "none" }} />
              </div>
              {forgotErr && <div style={{ background: C.criticalBg, color: C.critical, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>{forgotErr}</div>}
              {forgotMsg && <div style={{ background: C.infoBg, color: C.info, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>{forgotMsg}</div>}
              <button type="submit" disabled={forgotLoading} style={{ width: "100%", padding: "12px", fontSize: 14, fontWeight: 700, background: C.navy, color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", marginBottom: 10 }}>{forgotLoading ? "Enviando..." : "Enviar enlace"}</button>
              <button type="button" onClick={() => { setAuthMode("login"); setForgotErr(""); }} style={{ width: "100%", padding: "11px", fontSize: 13, fontWeight: 700, background: "#fff", color: C.gray700, border: `1px solid ${C.gray300}`, borderRadius: 8, cursor: "pointer" }}>Volver al login</button>
            </form>
          )}

          {authMode === "reset" && (
            <>
              {tokenCheckLoading && <div style={{ background: C.infoBg, color: C.info, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>Validando enlace de recuperación...</div>}
              {!tokenCheckLoading && !tokenValid && (
                <>
                  {resetErr && <div style={{ background: C.criticalBg, color: C.critical, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>{resetErr}</div>}
                  <button type="button" onClick={() => { window.history.replaceState({}, "", "/"); setAuthMode("forgot"); }} style={{ width: "100%", padding: "11px", fontSize: 13, fontWeight: 700, background: C.navy, color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", marginBottom: 10 }}>Solicitar nuevo enlace</button>
                  <button type="button" onClick={() => { window.history.replaceState({}, "", "/"); setAuthMode("login"); }} style={{ width: "100%", padding: "11px", fontSize: 13, fontWeight: 700, background: "#fff", color: C.gray700, border: `1px solid ${C.gray300}`, borderRadius: 8, cursor: "pointer" }}>Volver al login</button>
                </>
              )}

              {!tokenCheckLoading && tokenValid && (
                <form onSubmit={handleResetPassword}>
                  <div style={{ fontSize: 12, color: C.gray600, marginBottom: 14 }}>
                    Define tu nueva contraseña para la cuenta <strong>{loginEmail || ""}</strong>.
                  </div>
                  <div style={{ marginBottom: 12 }}>
                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Nueva contraseña</label>
                    <input value={resetPass} onChange={e => setResetPass(e.target.value)} type="password" required style={{ width: "100%", padding: "11px 14px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 8, boxSizing: "border-box", outline: "none" }} />
                  </div>
                  <div style={{ marginBottom: 16 }}>
                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Confirmar contraseña</label>
                    <input value={resetConfirm} onChange={e => setResetConfirm(e.target.value)} type="password" required style={{ width: "100%", padding: "11px 14px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 8, boxSizing: "border-box", outline: "none" }} />
                  </div>
                  {resetErr && <div style={{ background: C.criticalBg, color: C.critical, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>{resetErr}</div>}
                  {resetMsg && <div style={{ background: C.infoBg, color: C.info, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>{resetMsg}</div>}
                  <button type="submit" disabled={resetLoading} style={{ width: "100%", padding: "12px", fontSize: 14, fontWeight: 700, background: C.navy, color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", marginBottom: 10 }}>{resetLoading ? "Actualizando..." : "Actualizar contraseña"}</button>
                  <button type="button" onClick={() => { window.history.replaceState({}, "", "/"); setAuthMode("login"); }} style={{ width: "100%", padding: "11px", fontSize: 13, fontWeight: 700, background: "#fff", color: C.gray700, border: `1px solid ${C.gray300}`, borderRadius: 8, cursor: "pointer" }}>Volver al login</button>
                </form>
              )}
            </>
          )}
        </div>
      </div>
    ) : (
      <div className="occ-app-shell" style={{ display: "flex", minHeight: "100vh", background: "var(--occ-bg-page)", fontFamily: "var(--occ-font-sans)" }}>
        <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:translateY(0)} }
        @keyframes spin { to{transform:rotate(360deg)} }
        .fade { animation: fadeIn 0.25s ease both; }
        .rh:hover { background: ${C.gray50} !important; }
        .bh:hover { filter: brightness(0.93); }
        .occ-vuln-detail-layout { display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(280px, 360px); gap: 20px; align-items: start; }
        .occ-vuln-detail-main { display: flex; flex-direction: column; gap: 16px; min-width: 0; }
        .occ-vuln-detail-side { display: flex; flex-direction: column; gap: 16px; position: sticky; top: 24px; }
        .occ-vuln-metrics-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
        .occ-vuln-header-actions { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
        .occ-tooltip-wrap { position: relative; cursor: help; }
        .occ-tooltip-wrap .occ-tooltip { visibility: hidden; opacity: 0; position: absolute; bottom: calc(100% + 8px); left: 50%; transform: translateX(-50%); background: #0f172a; color: #E2E8F0; padding: 10px 14px; border-radius: 8px; font-size: 11px; line-height: 1.5; z-index: 100; pointer-events: none; transition: opacity 0.15s, visibility 0.15s; box-shadow: 0 4px 12px rgba(0,0,0,0.25); max-width: 320px; white-space: normal; font-weight: 400; letter-spacing: 0; text-transform: none; }
        .occ-tooltip-wrap .occ-tooltip::after { content: ""; position: absolute; top: 100%; left: 50%; transform: translateX(-50%); border: 5px solid transparent; border-top-color: #0f172a; }
        .occ-tooltip-wrap:hover .occ-tooltip { visibility: visible; opacity: 1; }
        .occ-tooltip-right .occ-tooltip { left: auto; right: 0; transform: none; }
        .occ-tooltip-right .occ-tooltip::after { left: auto; right: 16px; transform: none; }
        .occ-tooltip-below .occ-tooltip { bottom: auto; top: calc(100% + 8px); }
        .occ-tooltip-below .occ-tooltip::after { top: auto; bottom: 100%; border-top-color: transparent; border-bottom-color: #0f172a; }
        .occ-popover-wrap { position: relative; cursor: pointer; }
        .occ-popover-content { display: none; position: absolute; bottom: calc(100% + 6px); left: 50%; transform: translateX(-50%); background: #fff; border: 1px solid ${C.gray200}; border-radius: 10px; padding: 12px 14px; box-shadow: 0 8px 24px rgba(0,0,0,0.12); z-index: 200; min-width: 300px; max-width: 380px; }
        .occ-popover-wrap.occ-open .occ-popover-content { display: block; }
        .occ-vendor-group { margin-bottom: 6px; }
        .occ-vendor-header { display: flex; align-items: center; gap: 8px; padding: 9px 12px; background: #EEF2FF; border-radius: 8px 8px 0 0; border: 1px solid #C7D2FE; border-left: 3px solid #818CF8; font-size: 13px; font-weight: 800; color: #1e293b; cursor: pointer; user-select: none; letter-spacing: -0.01em; }
        .occ-vendor-header .occ-vendor-arrow { font-size: 10px; color: #64748B; transition: transform 0.15s; }
        .occ-vendor-header.occ-collapsed .occ-vendor-arrow { transform: rotate(-90deg); }
        .occ-vendor-products { border: 1px solid ${C.gray200}; border-top: none; border-radius: 0 0 8px 8px; overflow: hidden; }
        .occ-vendor-header.occ-collapsed + .occ-vendor-products { display: none; }
        .occ-product-row { display: flex; align-items: center; gap: 8px; padding: 7px 12px 7px 28px; background: #F8FAFC; border-bottom: 1px solid #F1F5F9; font-size: 12px; }
        .occ-product-row:last-child { border-bottom: none; }
        .occ-scroll-list { max-height: 220px; overflow-y: auto; display: flex; flex-direction: column; gap: 4px; }
        .occ-exploit-row { display: flex; align-items: center; gap: 8px; padding: 7px 12px; border-radius: 8px; border: 1px solid #F1F5F9; font-size: 11px; cursor: pointer; transition: background 0.1s; }
        .occ-exploit-row:hover { background: #EFF6FF; }
        .occ-ref-card { transition: border-color 0.12s, box-shadow 0.12s; }
        .occ-ref-card:hover { border-color: #93C5FD !important; box-shadow: 0 2px 8px rgba(37,99,235,0.08); }
        .occ-ref-tooltip { visibility: hidden; opacity: 0; position: absolute; bottom: calc(100% + 6px); left: 0; background: #0f172a; color: #E2E8F0; padding: 10px 12px; border-radius: 8px; z-index: 150; pointer-events: none; transition: opacity 0.15s, visibility 0.15s; box-shadow: 0 4px 16px rgba(0,0,0,0.3); min-width: 260px; max-width: 380px; white-space: normal; }
        .occ-ref-tooltip::after { content: ""; position: absolute; top: 100%; left: 16px; border: 5px solid transparent; border-top-color: #0f172a; }
        .occ-ref-card:hover .occ-ref-tooltip { visibility: visible; opacity: 1; }
        @media (max-width: 1280px) {
          .occ-vuln-metrics-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        }
        @media (max-width: 1180px) {
          .occ-vuln-detail-layout { grid-template-columns: minmax(0, 1fr); }
          .occ-vuln-detail-side { position: static; }
        }
        @media (max-width: 860px) {
          .occ-vuln-metrics-grid { grid-template-columns: minmax(0, 1fr); }
          .occ-vuln-header-actions { justify-content: flex-start; }
        }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: ${C.gray300}; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: ${C.gray400}; }
        ::selection { background: rgba(37, 99, 235, 0.15); }
        input:focus-visible, select:focus-visible, button:focus-visible, textarea:focus-visible {
          outline: 2px solid rgba(37, 99, 235, 0.4);
          outline-offset: 1px;
        }
        textarea:focus, select:focus { outline: none; border-color: ${C.blue} !important; box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.08); }
      `}</style>

        {/* ── SIDEBAR ── */}
        <nav className="occ-sidebar" style={{ width: sw, position: "fixed", top: 0, left: 0, height: "100vh", zIndex: 100, transition: "width 0.2s ease", overflow: "hidden" }}>
          <div className="occ-brand" style={{ padding: collapsed ? "14px 10px" : "16px 16px", borderBottom: "1px solid rgba(255,255,255,0.06)", justifyContent: collapsed ? "center" : "flex-start" }}>
            <div className="occ-brand-logo" style={{ width: 36, height: 36, borderRadius: 10, flexShrink: 0, padding: 7 }}>
              <img src={occLogo} alt="OCC" style={{ width: "100%", height: "100%", objectFit: "contain" }} />
            </div>
            {!collapsed && <div><div style={{ fontSize: 14, fontWeight: 700, color: "#fff", letterSpacing: "-0.01em" }}>OCC-TVM</div><div className="occ-brand-subtitle" style={{ fontSize: 10, color: "rgba(148,163,184,0.7)" }}>Threat &amp; Vulnerability Management</div></div>}
          </div>
          <div style={{ flex: 1, padding: "10px 0", overflowY: "auto" }}>
            {!collapsed && <div style={{ padding: "4px 20px 6px", fontSize: 9, fontWeight: 600, color: "rgba(148,163,184,0.5)", letterSpacing: "1.5px", textTransform: "uppercase" }}>Módulos</div>}
            {nav.map((n, idx) => {
              const isActive = navActiveView === n.id;
              const isChild = !!n.parent;
              const adminSectionIds = ["manufacturers", "notifications", "reports", "ai", "collector", "user-mgmt", "settings"];
              const isFirstAdmin = isAdmin && n.id === "manufacturers" && idx > 0;
              return (
                <div key={n.id}>
                  {isFirstAdmin && !collapsed && (
                    <>
                      <div style={{ height: 1, background: "rgba(255,255,255,0.06)", margin: "8px 20px" }} />
                      <div style={{ padding: "6px 20px 6px", fontSize: 9, fontWeight: 600, color: "rgba(148,163,184,0.5)", letterSpacing: "1.5px", textTransform: "uppercase" }}>Administración</div>
                    </>
                  )}
                  {isFirstAdmin && collapsed && <div style={{ height: 1, background: "rgba(255,255,255,0.06)", margin: "6px 12px" }} />}
                  <div className="occ-sidebar-nav-item" onClick={() => { setVulnDetail(null); setSelectedVuln(null); if (n.id === "subscriber-teams") setSubscriberTeamsRoute({ teamId: null }); setView(n.id); }} style={{ display: "flex", alignItems: "center", gap: 10, padding: collapsed ? "9px 16px" : isChild ? "8px 14px 8px 30px" : "9px 14px", cursor: "pointer", color: isActive ? "#fff" : "rgba(255,255,255,0.5)", background: isActive ? "rgba(37,99,235,0.12)" : "transparent", borderLeft: "none", transition: "all 0.12s", margin: collapsed ? "1px 6px" : "1px 10px", borderRadius: 8 }} onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = "transparent"; }}>
                    <I name={n.icon} size={16} color={isActive ? C.blueLight : "rgba(255,255,255,0.4)"} />
                    {!collapsed && <span style={{ fontSize: 12.5, fontWeight: isActive ? 600 : 400, letterSpacing: "-0.005em" }}>{n.label}</span>}
                  </div>
                </div>
              );
            })}
          </div>
          <div style={{ padding: "8px 12px", borderTop: "1px solid rgba(255,255,255,0.06)", fontSize: 10 }}>
            {currentUser && (
              <div
                onClick={handleLogout}
                title="Cerrar Sesión"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  padding: collapsed ? "8px 6px" : "8px 10px",
                  borderRadius: 8,
                  cursor: "pointer",
                  marginBottom: 8,
                  transition: "background 0.12s ease",
                }}
                onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                <div style={{ width: 32, height: 32, borderRadius: 8, background: "rgba(37,99,235,0.18)", display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontWeight: 700, fontSize: 12, flexShrink: 0 }}>
                  {(currentUser?.name || currentUser?.email || "A")[0].toUpperCase()}
                </div>
                {!collapsed && (
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: "#fff", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {currentUser.name || currentUser.email}
                    </div>
                    <div style={{ fontSize: 10, color: "rgba(148,163,184,0.6)" }}>Cerrar sesión</div>
                  </div>
                )}
              </div>
            )}
            <div onClick={() => setCollapsed(!collapsed)} style={{ cursor: "pointer", color: "rgba(148,163,184,0.5)", display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", borderRadius: 6, transition: "color 0.12s" }} onMouseEnter={e => e.currentTarget.style.color = "rgba(148,163,184,0.8)"} onMouseLeave={e => e.currentTarget.style.color = "rgba(148,163,184,0.5)"}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ transform: collapsed ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}><polyline points="15 18 9 12 15 6" /></svg>
              {!collapsed && <span style={{ fontSize: 11 }}>Colapsar</span>}
            </div>
          </div>
        </nav>

        {/* ── MAIN ── */}
        <main className="occ-app-main" style={{ flex: 1, marginLeft: sw, transition: "margin-left 0.2s ease", minHeight: "100vh", display: "flex", flexDirection: "column" }}>
          <div style={{ padding: "0 24px 24px", flex: 1 }} className="fade" key={view}>
            <VisualBanner />

            {/* ═══ OVERVIEW ═══ */}
            {view === "overview" && <>
              <PageHeader title="Panel de Vulnerabilidades" subtitle={`Última actualización: ${fmtDate(dash?.lastRun?.finishedAt)}`} />

              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, marginBottom: 20 }}>
                <Metric icon="bug" label="Total CVEs" value={dash?.totalAll ?? 0} sub="En base de datos" color={C.navy} />
                <Metric icon="alert" label="Publicadas 24h" value={todayT} sub={`${gc(dash?.today, "CRITICAL")} críticas por publishedAt`} color={C.critical} />
                <Metric icon="zap" label="KEV confirmadas" value={kevConfirmedT} sub="Total marcado como CISA KEV" color="#B91C1C" />
                <Metric icon="activity" label="Publicadas 7d" value={weekT} sub={`${gc(dash?.week, "HIGH")} altas por publishedAt`} color={C.high} />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                <Card title="Severidad (últimos 30d)" icon="shield">
                  <Bar label="Critical" count={gc(dash?.last30d || dash?.month, "CRITICAL")} total={last30dT} color={C.critical} />
                  <Bar label="High" count={gc(dash?.last30d || dash?.month, "HIGH")} total={last30dT} color={C.high} />
                  <Bar label="Medium" count={gc(dash?.last30d || dash?.month, "MEDIUM")} total={last30dT} color={C.medium} />
                  <Bar label="Low" count={gc(dash?.last30d || dash?.month, "LOW")} total={last30dT} color={C.low} />
                  <Bar label="Explotables" count={exploitablesLast30dT} total={last30dT || exploitablesLast30dT} color={C.info} />
                </Card>
                <Card title="Estado Collector" icon="server">
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 12 }}>
                    {[["CVEs", dash?.lastRun?.cvesFetched ?? 0], ["Nuevos", dash?.lastRun?.cvesNew ?? 0], ["Duración", fmtMs(dash?.lastRun?.durationMs ?? 0)]].map(([l, v]) => (
                      <div key={l} style={{ background: C.gray50, borderRadius: 6, padding: "8px 10px", textAlign: "center" }}>
                        <div style={{ fontSize: 9, color: C.gray500, fontWeight: 600, textTransform: "uppercase" }}>{l}</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: C.text, fontFamily: "monospace" }}>{v}</div>
                      </div>
                    ))}
                  </div>
                  <Btn primary onClick={handleCollect} disabled={collecting} style={{ width: "100%" }}>
                    {collecting ? <><span style={{ animation: "spin 1s linear infinite", display: "inline-block" }}>⟳</span> Recolectando...</> : <><I name="refresh" size={14} color="#fff" /> Recolección manual</>}
                  </Btn>
                </Card>
              </div>

              <Card title="KEV Confirmadas — Acción Inmediata" icon="zap" noPad style={{ marginTop: 16 }} action={<span onClick={() => setView("exploited")} style={{ fontSize: 11, color: C.blue, cursor: "pointer", fontWeight: 600 }}>Ver todas →</span>}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead><tr style={{ background: C.gray50 }}>
                    {[
                      { key: "cve", label: "CVE" },
                      { key: "risk", label: "Riesgo" },
                      { key: "cvss", label: "CVSS" },
                      { key: "epss", label: "EPSS" },
                      { key: "exploitation", label: "Explotación" },
                      { key: "product", label: "Producto" },
                      { key: "status", label: "Estado" },
                      { key: "published", label: "Publicada" },
                      { key: "updated", label: "Actualizada" },
                    ].map((column) => (
                      <th
                        key={column.key}
                        onClick={() => toggleKevTableSort(column.key)}
                        style={{
                          padding: 0,
                          textAlign: "left",
                          fontSize: 10,
                          borderBottom: `1px solid ${C.gray200}`,
                          whiteSpace: "nowrap",
                          cursor: "pointer",
                          userSelect: "none",
                        }}
                      >
                        <div style={{
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "space-between",
                          gap: 8,
                          padding: "9px 12px",
                          fontWeight: 700,
                          color: kevTableSort.key === column.key && kevTableSort.direction !== "default" ? C.navy : C.gray500,
                          textTransform: "uppercase",
                          letterSpacing: "0.7px",
                        }}>
                          <span>{column.label}</span>
                          <span style={{ fontSize: 10, color: kevTableSort.key === column.key && kevTableSort.direction !== "default" ? C.blue : C.gray400 }}>
                            {getKevSortDirectionIndicator(column.key, kevTableSort)}
                          </span>
                        </div>
                      </th>
                    ))}
                  </tr></thead>
                  <tbody>{sortedKevRows.map(v => {
                    const semantic = getSemanticSummary(v);
                    const displayContextTags = getDisplayContextTags({
                      contextTags: semantic.contextTags,
                      riskSignals: v.riskSignals,
                      tags: v.tags,
                    });
                    const modifiedAt = v.lastModifiedAt ? new Date(v.lastModifiedAt) : null;
                    const publishedAt = v.publishedAt ? new Date(v.publishedAt) : null;
                    const hasUpdate = !!(modifiedAt && publishedAt && modifiedAt.getTime() > publishedAt.getTime());
                    const trend = String(v.updateTrend || "").toLowerCase();
                    const isUp = hasUpdate && trend === "up";
                    const arrow = hasUpdate ? (isUp ? "▲" : "▼") : "＝";
                    const arrowColor = hasUpdate ? (isUp ? C.critical : C.low) : C.gray400;
                    return (
                      <tr key={v.cveId} className="rh" onClick={() => openVulnerabilityDetail(v, { sourceView: "exploited" })} style={{ cursor: "pointer", ...getRowPriorityStyle(v), transition: "background 0.1s" }}>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ fontWeight: 700, fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>{v.cveId}</div>
                          <div style={{ marginTop: 4, display: "flex", gap: 4, flexWrap: "wrap" }}>
                            <SevBadge s={v.cvssV31Severity} small />
                            {v.isKnownExploited && <SoftBadge label="KEV" bg={C.criticalBg} color={C.critical} border="#FCA5A5" small />}
                            {v.hasPublicExploit && <SoftBadge label="Exploit" bg={C.highBg} color={C.high} border="#FDBA74" small />}
                          </div>
                        </td>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                            <RiskTierBadge tier={v.operationalRiskTier} small />
                            <span style={{ fontFamily: "monospace", fontSize: 11, fontWeight: 700, color: isUrgentRisk(v.operationalRiskTier) ? C.critical : C.text }}>
                              Score {fmtRiskScore(v.operationalRiskScore)}
                            </span>
                          </div>
                        </td>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ fontFamily: "monospace", fontSize: 11, fontWeight: 700 }}>{fmtScore(v.cvssV31Score)}</div>
                          <div style={{ fontSize: 10, color: C.gray500 }}>{v.cvssV31Severity || "N/A"}</div>
                        </td>
                        <td style={{ padding: "10px 12px", fontFamily: "monospace", fontSize: 11, color: (v.epssScore || 0) > 0.1 ? C.high : C.text }}>{fmtEpss(v.epssScore)}</td>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                            <ExploitStatusBadge status={v.exploitStatus} small />
                            <span style={{ fontSize: 10, color: C.gray500 }}>
                              {v.exploitConfidence != null ? `${Math.round(v.exploitConfidence * 100)}% confianza` : "Sin confianza"}
                            </span>
                          </div>
                        </td>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ fontSize: 11, fontWeight: 700, color: semantic.hasReliablePrimaryEntity ? C.text : C.gray600 }}>{semantic.displayTitle}</div>
                          <div style={{ fontSize: 10, color: C.gray500 }}>{semantic.displaySubtitle}</div>
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 6 }}>
                            <ComponentTypeBadge type={semantic.componentType} small />
                            {displayContextTags.slice(0, 2).map((tag) => <ContextTagPill key={tag} tag={tag} small />)}
                          </div>
                        </td>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                            <RecordStatusBadge status={v.recordStatus} small />
                            <span style={{ fontSize: 10, color: hasUnknownPatch(v) ? C.high : C.gray500, fontWeight: hasUnknownPatch(v) ? 700 : 500 }}>
                              {v.patchAvailable === true ? "Parche disponible" : "Parche no confirmado"}
                            </span>
                          </div>
                        </td>
                        <td style={{ padding: "10px 12px", fontSize: 10, color: C.gray500, fontFamily: "monospace" }}>{fmtDate(v.publishedAt).split(",")[0]}</td>
                        <td style={{ padding: "10px 12px", fontSize: 10, color: C.gray500, fontFamily: "monospace", whiteSpace: "nowrap" }}>
                          <span style={{ color: arrowColor, fontWeight: 900, marginRight: 6 }}>{arrow}</span>
                          {hasUpdate ? fmtDate(v.lastModifiedAt).split(",")[0] : ""}
                        </td>
                      </tr>
                    );
                  })}</tbody>
                </table>
              </Card>
            </>}

            {/* ═══ VULNERABILITIES ═══ */}
            {
              view === "vulns" && <>
                <PageHeader title="Catálogo de vulnerabilidades" subtitle="Catálogo completo con búsqueda, filtros y carga progresiva." actions={
                  <div style={{ display: "flex", gap: 4 }}>
                    {["", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => (
                      <button key={s} onClick={() => setSevFilter(s)} className="bh" style={{ padding: "5px 12px", borderRadius: 6, fontSize: 10, fontWeight: 600, border: sevFilter === s ? "none" : `1px solid ${C.gray200}`, background: sevFilter === s ? (s ? sevColor(s) : C.navy) : "#fff", color: sevFilter === s ? "#fff" : C.gray600, cursor: "pointer", transition: "all 0.12s" }}>{s || "Todas"}</button>
                    ))}
                  </div>
                } />

                <Card style={{ marginBottom: 14 }}>
                  <div style={{ display: "grid", gridTemplateColumns: "minmax(280px, 2fr) minmax(140px, 160px)", gap: 10, marginBottom: 12 }}>
                    <Input value={searchQ} onChange={setSearchQ} placeholder="Buscar por CVE, descripción, vendor, producto o contexto..." icon="search" />
                    <select value={searchType} onChange={e => setSearchType(e.target.value)} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 8, fontSize: 12, background: "#fff" }}>
                      <option value="all">Búsqueda global</option>
                      <option value="cve">Solo CVE</option>
                      <option value="product">Producto / vendor</option>
                    </select>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(5, minmax(0, 1fr))", gap: 10, marginBottom: 10 }}>
                    <select value={riskTierFilter} onChange={e => setRiskTierFilter(e.target.value)} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 8, background: "#fff", fontSize: 12 }}>
                      <option value="">Risk tier (todos)</option>
                      {["informational", "monitor", "elevated", "high", "urgent", "emergency"].map(t => <option key={t} value={t}>{riskTierMeta(t).label}</option>)}
                    </select>
                    <select value={exploitStatusFilter} onChange={e => setExploitStatusFilter(e.target.value)} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 8, background: "#fff", fontSize: 12 }}>
                      <option value="">Estado exploit (todos)</option>
                      {["none", "mention", "poc", "reliable_poc", "active_exploitation"].map(s => <option key={s} value={s}>{exploitStatusMeta(s).label}</option>)}
                    </select>
                    <Input value={vendorFilter} onChange={setVendorFilter} placeholder="Vendor principal" />
                    <Input value={productFilter} onChange={setProductFilter} placeholder="Producto principal" />
                    <select value={changedSinceHoursFilter} onChange={e => setChangedSinceHoursFilter(e.target.value)} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 8, background: "#fff", fontSize: 12 }}>
                      <option value="">Cambios recientes</option>
                      <option value="4">Últimas 4h</option>
                      <option value="12">Últimas 12h</option>
                      <option value="24">Últimas 24h</option>
                      <option value="72">Últimos 3 días</option>
                      <option value="168">Última semana</option>
                    </select>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(5, minmax(0, 1fr))", gap: 10, marginBottom: 10 }}>
                    <select value={searchTagId} onChange={e => setSearchTagId(e.target.value)} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 8, fontSize: 12, background: "#fff" }}>
                      <option value="">Etiqueta (todas)</option>
                      {tags.map(t => <option key={t.id} value={String(t.id)}>{t.name}</option>)}
                    </select>
                    <select value={searchSeverity} onChange={e => setSearchSeverity(e.target.value)} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 8, fontSize: 12, background: "#fff" }}>
                      <option value="">Criticidad libre</option>
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                    <select value={searchExploit} onChange={e => setSearchExploit(e.target.value)} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 8, fontSize: 12, background: "#fff" }}>
                      <option value="all">Exploit libre</option>
                      <option value="known">KEV / confirmada</option>
                      <option value="public">Exploit público</option>
                      <option value="any">Cualquier explotación</option>
                      <option value="none">Sin explotación</option>
                    </select>
                    <select value={notificableFilter} onChange={e => setNotificableFilter(e.target.value)} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 8, fontSize: 12, background: "#fff" }}>
                      <option value="">Notificable (todos)</option>
                      <option value="true">SI - Notificable</option>
                      <option value="false">NO - No notificable</option>
                    </select>
                    <select value={notificadaFilter} onChange={e => setNotificadaFilter(e.target.value)} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 8, fontSize: 12, background: "#fff" }}>
                      <option value="">Notificada (todos)</option>
                      <option value="true">SI - Notificada</option>
                      <option value="false">NO - Sin notificar</option>
                    </select>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 10, marginBottom: 10 }}>
                    <input
                      type="number"
                      min="0"
                      max="10"
                      step="0.1"
                      value={searchMinScore}
                      onChange={e => setSearchMinScore(e.target.value)}
                      placeholder="CVSS mínimo"
                      style={{ width: "100%", padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 8, fontSize: 12, background: "#fff", boxSizing: "border-box" }}
                    />
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                      <input
                        type="date"
                        value={searchPublishedFrom}
                        onChange={e => setSearchPublishedFrom(e.target.value)}
                        style={{ width: "100%", padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 8, fontSize: 12, background: "#fff", boxSizing: "border-box" }}
                      />
                      <input
                        type="date"
                        value={searchPublishedTo}
                        onChange={e => setSearchPublishedTo(e.target.value)}
                        style={{ width: "100%", padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 8, fontSize: 12, background: "#fff", boxSizing: "border-box" }}
                      />
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
                    <span style={{ fontSize: 11, color: C.gray500, lineHeight: "26px" }}>Búsquedas rápidas:</span>
                    {["fortinet", "microsoft", "ivanti", "cisco", "CVE-2025", "sonicwall", "apple"].map(q => (
                      <span key={q} onClick={() => { setSearchQ(q); setSearchType(q.startsWith("CVE") ? "cve" : "product"); }} style={{ padding: "3px 10px", background: C.bluePale, color: C.navy, borderRadius: 4, fontSize: 11, fontWeight: 600, cursor: "pointer", transition: "all 0.1s" }}>{q}</span>
                    ))}
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10 }}>
                    <div style={{ fontSize: 11, color: C.gray500 }}>
                      {explorerResultLabel}. {hasSearchCriteria ? "Busqueda sobre toda la base de datos." : "Se priorizan explotacion conocida, riesgo operativo y CVSS."}
                    </div>
                    <Btn small onClick={clearExplorerFilters}>Limpiar filtros</Btn>
                  </div>
                </Card>

                {/* Filtro instantáneo local */}
                <div style={{ position: "relative", marginBottom: 0 }}>
                  <span style={{ position: "absolute", left: 14, top: 11, color: "#94A3B8", fontSize: 15, pointerEvents: "none" }}>⌕</span>
                  <input
                    value={instantFilter}
                    onChange={(e) => setInstantFilter(e.target.value)}
                    placeholder="Filtro rápido: escribe cualquier texto para filtrar en tiempo real (CVE, producto, vendor, severidad, estado...)"
                    style={{ width: "100%", padding: "10px 14px 10px 38px", border: `2px solid ${instantFilter.trim() ? C.blue : C.gray200}`, borderRadius: 10, fontSize: 13, background: "#fff", outline: "none", boxSizing: "border-box", transition: "border-color 0.15s", fontFamily: "inherit" }}
                    onFocus={(e) => { e.target.style.borderColor = C.blue; e.target.style.boxShadow = "0 0 0 3px rgba(37,99,235,0.08)"; }}
                    onBlur={(e) => { e.target.style.borderColor = instantFilter.trim() ? C.blue : C.gray200; e.target.style.boxShadow = "none"; }}
                  />
                  {instantFilter.trim() && (
                    <span
                      onClick={() => setInstantFilter("")}
                      style={{ position: "absolute", right: 14, top: 11, color: C.gray400, fontSize: 14, cursor: "pointer", fontWeight: 700 }}
                      title="Limpiar filtro"
                    >✕</span>
                  )}
                </div>

                <Card noPad>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead><tr style={{ background: C.gray50 }}>
                      {["CVE", "Riesgo", "CVSS", "EPSS", "Explotación", "Producto", "Estado", "Notificable", "Notificada", "Tags", "Origen", "Publicada"].map(h => (
                        <th key={h} style={{ padding: "9px 12px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${C.gray200}`, whiteSpace: "nowrap" }}>{h}</th>
                      ))}
                    </tr></thead>
                    <tbody>{explorerRows.map(v => {
                      const semantic = getSemanticSummary(v);
                      const displayContextTags = getDisplayContextTags({
                        contextTags: semantic.contextTags,
                        riskSignals: v.riskSignals,
                        tags: v.tags,
                      });
                      return (
                      <tr key={v.cveId} className="rh" onClick={() => openVulnerabilityDetail(v)} style={{ cursor: "pointer", ...getRowPriorityStyle(v), transition: "background 0.1s" }}>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ fontWeight: 700, fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>{v.cveId}</div>
                          <div style={{ marginTop: 4, display: "flex", gap: 4, flexWrap: "wrap" }}>
                            <SevBadge s={v.cvssV31Severity} small />
                            {v.isKnownExploited && <SoftBadge label="KEV" bg={C.criticalBg} color={C.critical} border="#FCA5A5" small />}
                            {v.hasPublicExploit && <SoftBadge label="Exploit" bg={C.highBg} color={C.high} border="#FDBA74" small />}
                          </div>
                        </td>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                            <RiskTierBadge tier={v.operationalRiskTier} small />
                            <span style={{ fontFamily: "monospace", fontSize: 11, fontWeight: 700, color: isUrgentRisk(v.operationalRiskTier) ? C.critical : C.text }}>
                              Score {fmtRiskScore(v.operationalRiskScore)}
                            </span>
                          </div>
                        </td>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ fontFamily: "monospace", fontSize: 11, fontWeight: 700 }}>{fmtScore(v.cvssV31Score)}</div>
                          <div style={{ fontSize: 10, color: C.gray500 }}>{v.cvssV31Severity || "N/A"}</div>
                        </td>
                        <td style={{ padding: "10px 12px", fontFamily: "monospace", fontSize: 11, color: (v.epssScore || 0) > 0.1 ? C.high : C.text }}>{fmtEpss(v.epssScore)}</td>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                            <ExploitStatusBadge status={v.exploitStatus} small />
                            <span style={{ fontSize: 10, color: C.gray500 }}>
                              {v.exploitConfidence != null ? `${Math.round(v.exploitConfidence * 100)}% confianza` : "Sin confianza"}
                            </span>
                          </div>
                        </td>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ fontSize: 11, fontWeight: 700, color: semantic.hasReliablePrimaryEntity ? C.text : C.gray600 }}>{semantic.displayTitle}</div>
                          <div style={{ fontSize: 10, color: C.gray500 }}>{semantic.displaySubtitle}</div>
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 6 }}>
                            <ComponentTypeBadge type={semantic.componentType} small />
                            {displayContextTags.slice(0, 2).map((tag) => <ContextTagPill key={tag} tag={tag} small />)}
                          </div>
                        </td>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                            <RecordStatusBadge status={v.recordStatus} small />
                            <span style={{ fontSize: 10, color: hasUnknownPatch(v) ? C.high : C.gray500, fontWeight: hasUnknownPatch(v) ? 700 : 500 }}>
                              {v.patchAvailable === true ? "Parche disponible" : "Parche no confirmado"}
                            </span>
                          </div>
                        </td>
                        <td style={{ padding: "10px 12px", textAlign: "center" }}>
                          {v.notificable
                            ? <SoftBadge label="SI" bg="#D1FAE5" color="#065F46" border="#6EE7B7" small />
                            : <SoftBadge label="NO" bg={C.gray100} color={C.gray500} border={C.gray200} small />
                          }
                        </td>
                        <td style={{ padding: "10px 12px", textAlign: "center" }}>
                          {v.notificada
                            ? <span title={(v.suscriptoresNotificados || []).map(s => `${s.recipientName || s.recipientEmail} (${fmtDate(s.sentAt)})`).join("\n")}>
                                <SoftBadge label="SI" bg="#DBEAFE" color="#1E40AF" border="#93C5FD" small />
                                {v.fechaNotificacion && <div style={{ fontSize: 9, color: C.gray500, marginTop: 2, fontFamily: "monospace" }}>{fmtDate(v.fechaNotificacion).split(",")[0]}</div>}
                                {(v.suscriptoresNotificados || []).length > 0 && <div style={{ fontSize: 9, color: C.gray400, marginTop: 1 }}>{(v.suscriptoresNotificados || []).length} suscriptor{(v.suscriptoresNotificados || []).length !== 1 ? "es" : ""}</div>}
                              </span>
                            : <SoftBadge label="NO" bg={C.gray100} color={C.gray500} border={C.gray200} small />
                          }
                        </td>
                        <td style={{ padding: "10px 12px" }}>{(v.tags || []).map(t => <span key={t.id} style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: t.color, marginRight: 2 }} title={t.name} />)}</td>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
                            {(() => {
                              const src = normalizeFieldList(v.sourcesPresent).map(s => String(s).toLowerCase());
                              const sourceMap = [
                                { key: "nvd", label: "NVD", bg: "#DBEAFE", color: "#1E40AF" },
                                { key: "cveorg", label: "MITRE", bg: "#E0E7FF", color: "#4338CA" },
                                { key: "mitre", label: "MITRE", bg: "#E0E7FF", color: "#4338CA" },
                                { key: "kev", label: "KEV", bg: "#FEE2E2", color: "#991B1B" },
                                { key: "epss", label: "EPSS", bg: "#FEF3C7", color: "#92400E" },
                                { key: "github", label: "GitHub", bg: "#F3F4F6", color: "#1F2937" },
                                { key: "exploitdb", label: "EDB", bg: "#FDE68A", color: "#78350F" },
                                { key: "osv", label: "OSV", bg: "#D1FAE5", color: "#065F46" },
                              ];
                              const seen = new Set();
                              const badges = [];
                              for (const m of sourceMap) {
                                if (src.some(s => s.includes(m.key)) && !seen.has(m.label)) {
                                  seen.add(m.label);
                                  badges.push(m);
                                }
                              }
                              if (badges.length === 0) badges.push({ label: "NVD", bg: "#DBEAFE", color: "#1E40AF" });
                              return badges.map(b => (
                                <span key={b.label} style={{ padding: "1px 5px", borderRadius: 3, fontSize: 8, fontWeight: 700, background: b.bg, color: b.color, whiteSpace: "nowrap" }}>{b.label}</span>
                              ));
                            })()}
                          </div>
                        </td>
                        <td style={{ padding: "10px 12px", fontSize: 10, color: C.gray500, fontFamily: "monospace" }}>{fmtDate(v.publishedAt).split(",")[0]}</td>
                      </tr>
                      );
                    })}</tbody>
                  </table>
                  {vulnsLoading && <div style={{ padding: 24, textAlign: "center", color: C.gray500, fontSize: 12 }}>Cargando vulnerabilidades...</div>}
                  {!vulnsLoading && explorerRows.length === 0 && <div style={{ padding: 40, textAlign: "center", color: C.gray400, fontSize: 13 }}>No hay vulnerabilidades que mostrar con los filtros actuales</div>}
                  {(vulnsHasMore || vulnsLoadingMore) && (
                    <div style={{ padding: 18, borderTop: `1px solid ${C.gray200}`, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
                      <div style={{ fontSize: 11, color: C.gray500 }}>
                        {vulns.length} CVEs cargadas localmente de {vulnsTotal}.
                      </div>
                      <Btn onClick={loadMoreVulns} disabled={vulnsLoadingMore}>
                        {vulnsLoadingMore ? "Cargando..." : "Cargar más"}
                      </Btn>
                    </div>
                  )}
                </Card>

                {/* VULN DETAIL OVERLAY */}
                {vulnDetail && (
                  <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.5)", zIndex: 110, display: "flex", justifyContent: "flex-end" }} onClick={() => setVulnDetail(null)}>
                    <div style={{ width: 800, background: "#fff", height: "100%", overflowY: "auto", padding: 32, boxShadow: "-10px 0 40px rgba(0,0,0,0.2)" }} onClick={e => e.stopPropagation()}>
                      {vulnLoading ? <div style={{ padding: 40, textAlign: "center" }}>Cargando...</div> : (() => {
                        const detailedProducts = normalizeFieldList(vulnDetail.affectedProductsDetailed);
                        const summaryProducts = normalizeFieldList(vulnDetail.affectedProducts);
                        const displayProducts = detailedProducts.length > 0 ? detailedProducts : summaryProducts;
                        const semantic = getSemanticSummary(vulnDetail);
                        const primaryEntityKey = semantic.hasReliablePrimaryEntity
                          ? `${String(semantic.semanticPrimaryVendor || "").trim().toLowerCase()}::${String(semantic.semanticPrimaryProduct || "").trim().toLowerCase()}`
                          : "";
                        const { primaryProducts, otherProducts } = splitDisplayProducts(displayProducts, semantic);
                        const riskSignals = normalizeFieldList(vulnDetail.riskSignals);
                        const displayContextTags = getDisplayContextTags({
                          contextTags: semantic.contextTags,
                          riskSignals,
                          tags: vulnDetail.tags,
                        });
                        const exploitReferences = normalizeFieldValue(vulnDetail.exploitReferences);
                        const remediationInfo = normalizeFieldValue(vulnDetail.remediationInfo);
                        const fixedVersions = normalizeFieldValue(vulnDetail.fixedVersions);
                        const workarounds = normalizeFieldValue(vulnDetail.workarounds);
                        const detectionOpportunities = normalizeFieldValue(vulnDetail.detectionOpportunities);
                        const sourcesPresent = normalizeFieldList(vulnDetail.sourcesPresent);
                        const references = normalizeFieldValue(vulnDetail.references);
                        const allReferences = normalizeFieldValue(vulnDetail.allReferences);
                        const vendorAdvisories = normalizeFieldValue(vulnDetail.vendorAdvisories ?? remediationInfo?.vendorAdvisories);
                        const linksField = normalizeFieldValue(vulnDetail.links ?? remediationInfo?.links);
                        const advisoriesField = normalizeFieldValue(vulnDetail.advisories ?? remediationInfo?.advisories);
                        const patchUrls = normalizeFieldList(remediationInfo?.patchUrls);
                        const exploitReferenceBundle = normalizeReferenceEntries(exploitReferences, {
                          defaultSource: "exploit",
                          defaultLabel: "Referencia de explotación",
                        });
                        const patchAndAdvisoryBundle = normalizeReferenceEntries(
                          [patchUrls, vendorAdvisories, advisoriesField],
                          {
                            defaultSource: "advisory",
                            defaultLabel: "Advisory del fabricante",
                          },
                        );
                        const generalReferenceBundle = normalizeReferenceEntries(
                          [references, allReferences, linksField],
                          {
                            defaultSource: "reference",
                            defaultLabel: "Referencia",
                          },
                        );
                        const changeTimeline = normalizeFieldList(vulnDetail.changeTimeline).slice(0, 20);
                        const summaryText = vulnDetail.description || "Sin descripción disponible.";
                        const compactChangeValue = (value) => {
                          const rendered = summarizeTextValue(value);
                          return rendered.length > 180 ? `${rendered.slice(0, 177)}...` : rendered;
                        };
                        const showWhyBlock = riskSignals.length > 0;
                        const showProductsBlock = displayProducts.length > 0 || semantic.hasReliablePrimaryEntity || semantic.componentType !== "unknown" || semantic.contextTags.length > 0;
                        const showContextBlock = displayContextTags.length > 0;
                        const showExploitBlock = hasValue(vulnDetail.exploitStatus) || hasValue(vulnDetail.exploitConfidence) || hasValue(vulnDetail.exploitFirstSeenAt) || hasValue(vulnDetail.exploitLastCheckedAt) || exploitReferenceBundle.links.length > 0 || exploitReferenceBundle.metadata.length > 0 || vulnDetail.isKnownExploited != null || vulnDetail.hasPublicExploit != null;
                        const showRemediationBlock = vulnDetail.patchAvailable != null || hasValue(vulnDetail.patchPriority) || hasValue(fixedVersions) || hasValue(workarounds) || hasValue(detectionOpportunities) || hasValue(remediationInfo);
                        const showSourcesBlock = sourcesPresent.length > 0 || hasValue(vulnDetail.recordStatus) || hasValue(vulnDetail.lastChangeDetectedAt);
                        const showReferencesBlock = patchAndAdvisoryBundle.links.length > 0
                          || patchAndAdvisoryBundle.metadata.length > 0
                          || generalReferenceBundle.links.length > 0
                          || generalReferenceBundle.metadata.length > 0;

                        return <>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24, gap: 16 }}>
                            <div style={{ flex: 1 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
                                <h2 style={{ fontSize: 28, fontWeight: 800, margin: 0, fontFamily: "'JetBrains Mono', monospace", color: C.navy }}>{vulnDetail.cveId}</h2>
                                <SevBadge s={vulnDetail.cvssV31Severity} />
                                <RiskTierBadge tier={vulnDetail.operationalRiskTier} />
                                <ExploitStatusBadge status={vulnDetail.exploitStatus} />
                                <ComponentTypeBadge type={semantic.componentType} />
                                {vulnDetail.isKnownExploited && <SoftBadge label="KEV / explotación activa" bg={C.criticalBg} color={C.critical} border="#FCA5A5" />}
                                {hasValue(vulnDetail.recordStatus) && <RecordStatusBadge status={vulnDetail.recordStatus} />}
                              </div>
                              <p style={{ margin: "0 0 14px", fontSize: 13, lineHeight: 1.65, color: C.gray700, maxWidth: 680 }}>
                                {summaryText}
                              </p>
                              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
                                {semantic.hasReliablePrimaryEntity ? (
                                  <SoftBadge label={`Entidad principal ${semantic.displayTitle}`} bg={C.white} color={C.navy} border={C.gray300} />
                                ) : (
                                  <SoftBadge label="Sin entidad principal fiable" bg={C.gray50} color={C.gray600} border={C.gray300} />
                                )}
                                {displayContextTags.slice(0, 2).map((tag) => <ContextTagPill key={tag} tag={tag} />)}
                              </div>
                              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                                <SoftBadge label={`Publicado ${fmtDate(vulnDetail.publishedAt)}`} bg={C.gray50} color={C.gray700} border={C.gray300} />
                                <SoftBadge label={`Actualizado ${fmtDate(vulnDetail.lastModifiedAt)}`} bg={C.gray50} color={C.gray700} border={C.gray300} />
                                {hasValue(vulnDetail.lastChangeDetectedAt) && <SoftBadge label={`Cambio detectado ${fmtDate(vulnDetail.lastChangeDetectedAt)}`} bg={C.bluePale} color={C.navy} border={C.gray200} />}
                                {hasValue(vulnDetail.exploitFirstSeenAt) && <SoftBadge label={`Exploit visto ${fmtDate(vulnDetail.exploitFirstSeenAt)}`} bg={C.highBg} color={C.high} border="#FDBA74" />}
                              </div>
                            </div>
                            <button onClick={() => setVulnDetail(null)} style={{ border: "none", background: "transparent", cursor: "pointer" }}><I name="x" size={24} color={C.gray400} /></button>
                          </div>

                          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 12, marginBottom: 24 }}>
                            <Metric icon="shield" label="CVSS" value={fmtScore(vulnDetail.cvssV31Score)} sub={`${vulnDetail.cvssV31Severity || "N/A"} · ${vulnDetail.cvssV31Vector || "Vector no informado"}`} color={sevColor(vulnDetail.cvssV31Severity)} />
                            <Metric icon="activity" label="EPSS" value={fmtEpss(vulnDetail.epssScore)} sub={`Percentil ${(Number(vulnDetail.epssPercentile || 0) * 100).toFixed(0)}%`} color={C.blue} />
                            <Metric icon="alert" label="Riesgo Operativo" value={fmtRiskScore(vulnDetail.operationalRiskScore)} sub={riskTierMeta(vulnDetail.operationalRiskTier).label} color={riskTierMeta(vulnDetail.operationalRiskTier).color} />
                            <Metric icon="bug" label="Explotación" value={exploitStatusMeta(vulnDetail.exploitStatus).label} sub={`Confianza ${fmtConfidence(vulnDetail.exploitConfidence)}`} color={exploitStatusMeta(vulnDetail.exploitStatus).color} />
                          </div>

                          <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 16, marginBottom: 16 }}>
                            <DetailBlock title="Cabecera Operativa" icon="shield">
                              <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 8 }}>
                                <KV label="Entidad principal" value={semantic.hasReliablePrimaryEntity ? semantic.displayTitle : "No inferida con suficiente evidencia"} />
                                <KV label="Tipo de componente" value={componentTypeMeta(semantic.componentType).label} />
                                <KV label="Estado de registro" value={recordStatusMeta(vulnDetail.recordStatus).label} />
                                <KV label="Prioridad de parche" value={vulnDetail.patchPriority || "No informada"} />
                              </div>
                            </DetailBlock>

                            <DetailBlock title="Etiquetas" icon="edit">
                              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 12 }}>
                                {(vulnDetail.tags || []).map(t => (
                                  <span key={t.id} style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 10px", borderRadius: 12, background: `${t.color}15`, color: t.color, fontSize: 11, fontWeight: 600, border: `1px solid ${t.color}30` }}>
                                    {t.name}
                                    <span style={{ cursor: "pointer", opacity: 0.6 }} onClick={() => handleVulnTags((vulnDetail.tags || []).filter(x => x.id !== t.id))}>×</span>
                                  </span>
                                ))}
                                <div style={{ position: "relative" }}>
                                  <button onClick={() => document.getElementById("tag-dropdown").style.display = "block"} style={{ background: C.gray100, border: "none", borderRadius: 12, width: 24, height: 24, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}><I name="plus" size={14} color={C.gray600} /></button>
                                  <div id="tag-dropdown" style={{ display: "none", position: "absolute", top: 30, left: 0, background: "#fff", border: `1px solid ${C.gray200}`, boxShadow: "0 10px 20px rgba(0,0,0,0.1)", borderRadius: 8, padding: 8, width: 220, zIndex: 120 }}>
                                    {tags.filter(t => !(vulnDetail.tags || []).find(vt => vt.id === t.id)).map(t => (
                                      <div key={t.id} onClick={() => { handleVulnTags([...(vulnDetail.tags || []), t]); document.getElementById("tag-dropdown").style.display = "none"; }} style={{ padding: "6px 10px", fontSize: 12, cursor: "pointer", borderRadius: 4 }} className="rh">
                                        <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: t.color, marginRight: 8 }} />
                                        {t.name}
                                      </div>
                                    ))}
                                    {tags.length === 0 && <div style={{ fontSize: 11, color: C.gray500, padding: 8 }}>No hay tags disponibles. Créalos en Configuración.</div>}
                                    <div style={{ borderTop: `1px solid ${C.gray100}`, marginTop: 4, paddingTop: 4, textAlign: "center", fontSize: 10, color: C.blue, cursor: "pointer" }} onClick={() => document.getElementById("tag-dropdown").style.display = "none"}>Cerrar</div>
                                  </div>
                                </div>
                              </div>
                              {(vulnDetail.tags || []).length === 0 && <div style={{ fontSize: 12, color: C.gray500 }}>Sin etiquetas asignadas.</div>}
                            </DetailBlock>
                          </div>

                          {showWhyBlock && (
                            <DetailBlock title="Por Qué Destaca" icon="zap" style={{ marginBottom: 16 }}>
                              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                                {riskSignals.map((signal, idx) => <SignalPill key={`${signal}-${idx}`} signal={signal} />)}
                              </div>
                            </DetailBlock>
                          )}

                          {showContextBlock && (
                            <DetailBlock title="Contexto Operativo" icon="server" style={{ marginBottom: 16 }}>
                              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                                {displayContextTags.map((tag) => <ContextTagPill key={tag} tag={tag} />)}
                              </div>
                            </DetailBlock>
                          )}

                          {showProductsBlock && (
                            <DetailBlock title="Productos Afectados" icon="server" style={{ marginBottom: 16 }}>
                              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 8, marginBottom: 12 }}>
                                <KV label="Entidad principal" value={semantic.hasReliablePrimaryEntity ? semantic.displayTitle : "No inferida con suficiente evidencia"} />
                                <KV label="Tipo inferido" value={componentTypeMeta(semantic.componentType).label} />
                                <KV label="Elementos detectados" value={String(displayProducts.length || 0)} />
                              </div>

                              {semantic.hasReliablePrimaryEntity && primaryProducts.length > 0 && (
                                <div style={{ marginBottom: otherProducts.length > 0 ? 16 : 0 }}>
                                  <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 8 }}>Entidad principal afectada</div>
                                  <ProductDetailList items={primaryProducts} primaryKey={primaryEntityKey} />
                                </div>
                              )}

                              {otherProducts.length > 0 && (
                                <div>
                                  <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 8 }}>
                                    {semantic.hasReliablePrimaryEntity ? "Otros productos o componentes afectados" : "Productos o componentes detectados"}
                                  </div>
                                  {detailedProducts.length > 0 ? (
                                    <details open>
                                      <summary style={{ cursor: "pointer", fontSize: 12, fontWeight: 700, color: C.navy, marginBottom: 12 }}>
                                        Ver detalle completo
                                      </summary>
                                      <ProductDetailList items={otherProducts} primaryKey={primaryEntityKey} />
                                    </details>
                                  ) : (
                                    <ProductDetailList items={otherProducts} primaryKey={primaryEntityKey} />
                                  )}
                                </div>
                              )}

                              {!semantic.hasReliablePrimaryEntity && otherProducts.length === 0 && displayProducts.length > 0 && (
                                <ProductDetailList items={displayProducts} primaryKey={primaryEntityKey} />
                              )}
                            </DetailBlock>
                          )}

                          {showExploitBlock && (
                            <DetailBlock title="Explotación" icon="bug" style={{ marginBottom: 16 }}>
                              <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 8, marginBottom: 12 }}>
                                <KV label="En KEV" value={yesNoUnknown(vulnDetail.isKnownExploited)} tone={vulnDetail.isKnownExploited ? C.criticalBg : C.gray50} />
                                <KV label="Exploit público" value={yesNoUnknown(vulnDetail.hasPublicExploit)} tone={vulnDetail.hasPublicExploit ? C.highBg : C.gray50} />
                                <KV label="Estado de exploit" value={exploitStatusMeta(vulnDetail.exploitStatus).label} />
                                <KV label="Confianza" value={fmtConfidence(vulnDetail.exploitConfidence)} />
                                <KV label="Primera detección" value={fmtDate(vulnDetail.exploitFirstSeenAt)} />
                                <KV label="Última comprobación" value={fmtDate(vulnDetail.exploitLastCheckedAt)} />
                              </div>
                              {(exploitReferenceBundle.links.length > 0 || exploitReferenceBundle.metadata.length > 0) && <>
                                <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 8 }}>Referencias de explotación</div>
                                <LinkList
                                  items={exploitReferences}
                                  empty="Sin referencias de explotación"
                                  accent="#FED7AA"
                                  defaultLabel="Referencia de explotación"
                                  defaultSource="exploit"
                                />
                              </>}
                            </DetailBlock>
                          )}

                          {showRemediationBlock && (
                            <DetailBlock title="Remediación" icon="check" style={{ marginBottom: 16 }}>
                              <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 8, marginBottom: 14 }}>
                                <KV label="Parche" value={describePatchStatus(vulnDetail.patchAvailable)} tone={vulnDetail.patchAvailable === true ? C.lowBg : vulnDetail.patchAvailable === false ? C.highBg : C.gray50} />
                                <KV label="Prioridad de parche" value={vulnDetail.patchPriority || "No informada"} />
                              </div>
                              {hasValue(fixedVersions) && <div style={{ marginBottom: 14 }}>
                                <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 8 }}>Versiones corregidas</div>
                                <RichValue value={fixedVersions} />
                              </div>}
                              {hasValue(workarounds) && <div style={{ marginBottom: 14 }}>
                                <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 8 }}>Workarounds</div>
                                <RichValue value={workarounds} />
                              </div>}
                              {hasValue(detectionOpportunities) && <div style={{ marginBottom: 14 }}>
                                <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 8 }}>Oportunidades de detección</div>
                                <RichValue value={detectionOpportunities} />
                              </div>}
                              {hasValue(remediationInfo) && <div>
                                <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 8 }}>Información adicional</div>
                                <RichValue value={remediationInfo} />
                              </div>}
                            </DetailBlock>
                          )}

                          {showSourcesBlock && (
                            <DetailBlock title="Procedencia y Estado" icon="file" style={{ marginBottom: 16 }}>
                              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 8 }}>
                                <KV label="Fuentes presentes" value={sourcesPresent.length > 0 ? sourcesPresent.map((item) => summarizeTextValue(item)).join(", ") : "No informadas"} />
                                <KV label="Estado del registro" value={recordStatusMeta(vulnDetail.recordStatus).label} />
                                <KV label="Último cambio detectado" value={fmtDate(vulnDetail.lastChangeDetectedAt)} />
                              </div>
                            </DetailBlock>
                          )}

                          {showReferencesBlock && (
                            <DetailBlock title="Referencias" icon="link" style={{ marginBottom: 16 }}>
                              <div style={{ marginBottom: 14 }}>
                                <LinkList
                                  items={[{
                                    label: "NVD NIST",
                                    source: "NIST",
                                    tags: ["NVD"],
                                    url: `https://nvd.nist.gov/vuln/detail/${vulnDetail.cveId}`,
                                  }]}
                                  empty="Sin referencia NVD"
                                  accent={C.gray300}
                                />
                              </div>
                              {(patchAndAdvisoryBundle.links.length > 0 || patchAndAdvisoryBundle.metadata.length > 0) && <div style={{ marginBottom: 14 }}>
                                <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 8 }}>Parches y advisories</div>
                                <LinkList
                                  items={[patchUrls, vendorAdvisories, advisoriesField]}
                                  empty="Sin URLs de parche"
                                  accent="#BBF7D0"
                                  defaultLabel="Advisory del fabricante"
                                  defaultSource="advisory"
                                />
                              </div>}
                              {(generalReferenceBundle.links.length > 0 || generalReferenceBundle.metadata.length > 0) && <div>
                                <div style={{ fontSize: 11, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", marginBottom: 8 }}>Referencias generales</div>
                                <LinkList
                                  items={[references, allReferences, linksField]}
                                  empty="Sin referencias generales"
                                  defaultLabel="Referencia"
                                  defaultSource="reference"
                                />
                              </div>}
                            </DetailBlock>
                          )}

                          {changeTimeline.length > 0 && (
                            <DetailBlock title="Historial de Cambios" icon="clock" style={{ marginBottom: 16 }}>
                              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                                {changeTimeline.map((change) => (
                                  <div key={change.id} style={{ padding: "12px 14px", borderRadius: 12, border: `1px solid ${change.isSignificant ? "#FCA5A5" : C.gray200}`, background: change.isSignificant ? C.criticalBg : C.gray50 }}>
                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, marginBottom: 6 }}>
                                      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                                        <SoftBadge label={getChangeTypeLabel(change.changeType)} small bg={C.white} color={C.navy} border={C.gray300} />
                                        <SoftBadge label={translateFieldName(change.fieldName || "campo")} small bg={C.white} color={C.gray700} border={C.gray300} />
                                        {change.isSignificant && <SoftBadge label="Significativo" small bg={C.criticalBg} color={C.critical} border="#FCA5A5" />}
                                      </div>
                                      <span style={{ fontSize: 10, color: C.gray500, fontFamily: "monospace" }}>{fmtDate(change.detectedAt)}</span>
                                    </div>
                                    <div style={{ fontSize: 12, color: C.gray700, fontWeight: 600, marginBottom: (hasValue(change.oldValue) || hasValue(change.newValue)) ? 8 : 0 }}>
                                      {change.summary || "Cambio detectado sin resumen adicional."}
                                    </div>
                                    {(hasValue(change.oldValue) || hasValue(change.newValue)) && (
                                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                                        <KV label="Valor anterior" value={compactChangeValue(change.oldValue)} />
                                        <KV label="Valor nuevo" value={compactChangeValue(change.newValue)} tone={change.isSignificant ? "#FFF1F2" : C.white} />
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </DetailBlock>
                          )}

                          <div style={{ background: C.gray50, borderRadius: 8, padding: 20, border: `1px solid ${C.gray200}` }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                              <h3 style={{ fontSize: 14, fontWeight: 700, color: C.navy, margin: 0, display: "flex", alignItems: "center", gap: 8 }}><I name="mail" size={16} /> Notificaciones y Alertas</h3>
                              <Btn small primary onClick={openNotifyModal}><I name="send" size={12} /> Notificar a contacto</Btn>
                            </div>

                            {showNotifModal && (
                              <div style={{ marginBottom: 16, background: "#fff", padding: 16, borderRadius: 6, border: `1px solid ${C.blue}`, animation: "fadeIn 0.2s" }}>
                                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>Selecciona un contacto para enviar alerta sobre {vulnDetail.cveId}:</div>
                                <div style={{ display: "flex", gap: 8 }}>
                                  <select id="contact-select" disabled={notifContactsLoading || contacts.length === 0} style={{ flex: 1, padding: 8, borderRadius: 4, border: `1px solid ${C.gray300}` }}>
                                    {notifContactsLoading && <option value="">Cargando contactos...</option>}
                                    {!notifContactsLoading && contacts.length === 0 && <option value="">No hay contactos disponibles</option>}
                                    {!notifContactsLoading && contacts.map(c => <option key={c.id} value={c.id}>{c.name} ({c.email})</option>)}
                                  </select>
                                  <Btn small primary disabled={notifSending || notifContactsLoading || contacts.length === 0} onClick={() => handleNotifyContact(document.getElementById("contact-select").value)}>
                                    {notifSending ? "Enviando..." : "Enviar Email"}
                                  </Btn>
                                  <Btn small onClick={() => setShowNotifModal(false)}>Cancelar</Btn>
                                </div>
                              </div>
                            )}

                            <table style={{ width: "100%", borderCollapse: "collapse", background: "#fff", borderRadius: 6, overflow: "hidden" }}>
                              <thead><tr style={{ background: C.gray100, borderBottom: `1px solid ${C.gray200}` }}>
                                {["Fecha", "Destinatario", "Estado"].map(h => <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 10, color: C.gray600 }}>{h}</th>)}
                              </tr></thead>
                              <tbody>
                                {(vulnDetail.notifications || []).length === 0 ? (
                                  <tr><td colSpan={3} style={{ padding: 12, textAlign: "center", fontSize: 11, color: C.gray500 }}>Sin notificaciones enviadas</td></tr>
                                ) : vulnDetail.notifications.map(n => (
                                  <tr key={n.id} style={{ borderBottom: `1px solid ${C.gray100}` }}>
                                    <td style={{ padding: "8px 12px", fontSize: 11, fontFamily: "monospace" }}>{fmtDate(n.sentAt)}</td>
                                    <td style={{ padding: "8px 12px", fontSize: 11 }}>{n.recipientName} ({n.recipientEmail})</td>
                                    <td style={{ padding: "8px 12px", fontSize: 10, fontWeight: 700, color: n.status === "sent" ? C.low : C.critical }}>{n.status.toUpperCase()}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>

                          <div style={{ marginTop: 24, textAlign: "right" }}>
                            <Btn onClick={() => analyzeVulnerabilityWithAi(vulnDetail)} style={{ marginRight: 12 }}><I name="brain" size={14} /> Analizar con IA</Btn>
                            <Btn onClick={() => setVulnDetail(null)}>Cerrar</Btn>
                          </div>
                        </>;
                      })()}
                    </div>
                  </div>
                )}
              </>
            }

            {/* ═══ VULNERABILITY DETAIL PAGE ═══ */}
            {view === DETAIL_VIEW && <>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, marginBottom: 18, flexWrap: "wrap" }}>
                <div>
                  <div style={{ fontSize: 10, color: C.gray500, fontWeight: 600, letterSpacing: "0.04em", textTransform: "uppercase", marginBottom: 6 }}>
                    {detailSourceView === "exploited" ? "KEV / Explotación confirmada" : "Catálogo de vulnerabilidades"}
                  </div>
                  <h1 style={{ fontSize: 20, fontWeight: 700, color: C.text, margin: 0, letterSpacing: "-0.01em" }}>
                    {detailCveId || "Detalle de vulnerabilidad"}
                  </h1>
                  <p style={{ color: C.gray500, fontSize: 12, margin: "4px 0 0" }}>
                    Página dedicada de detalle, con referencias normalizadas y navegación contextual.
                  </p>
                </div>
                <Btn onClick={closeVulnerabilityDetail}>Volver al listado</Btn>
              </div>
              {renderVulnerabilityDetailPage()}
            </>}

            {/* ═══ EXPLOITED ═══ */}
            {view === "exploited" && <>
              <PageHeader title="KEV / Explotación Confirmada" />
              <div style={{ background: C.critical, color: "#fff", borderRadius: 8, padding: "14px 18px", marginBottom: 16, display: "flex", alignItems: "center", gap: 10 }}>
                <I name="alert" size={20} color="#fff" />
                <div><div style={{ fontWeight: 700, fontSize: 13 }}>{kevListRows.length} vulnerabilidades con explotación confirmada</div><div style={{ fontSize: 11, opacity: 0.85 }}>Casos priorizados por KEV, riesgo operacional y evidencia de exploit</div></div>
              </div>
              {kevListRows.map(v => {
                const aff = getAffectedContacts(v);
                return (
                  <Card key={v.cveId} style={{ marginBottom: 10, borderLeft: `4px solid ${C.critical}` }}>
                    <div
                      onClick={() => openVulnerabilityDetail(v, { sourceView: "exploited" })}
                      style={{ cursor: "pointer" }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                          <span style={{ fontSize: 16, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace" }}>{v.cveId}</span>
                          <SevBadge s={v.cvssV31Severity} /><span style={{ fontFamily: "monospace", fontWeight: 800, fontSize: 14 }}>{fmtScore(v.cvssV31Score)}</span>
                        </div>
                        <span style={{ fontSize: 10, color: C.gray500 }}>EPSS {fmtEpss(v.epssScore)}</span>
                      </div>
                      <p style={{ color: C.gray600, fontSize: 11, lineHeight: 1.5, marginBottom: 10 }}>{v.description}</p>
                      <div style={{ marginBottom: 8 }}>
                        <SemanticCompactAffected vuln={v} contextLimit={2} />
                      </div>
                      {aff.length > 0 && (
                        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
                          {aff.map(c => (
                            <div key={c.id} style={{ display: "flex", alignItems: "center", gap: 6, background: C.gray50, padding: "4px 10px", borderRadius: 4, fontSize: 10 }}>
                              <I name="mail" size={12} color={C.blue} />
                              <strong>{c.name.split(" ").slice(1, 3).join(" ")}</strong>
                              <span style={{ color: C.gray500 }}>{c.email}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      <div style={{ padding: "8px 10px", borderRadius: 4, background: v.patchAvailable ? C.lowBg : C.highBg, fontSize: 11, borderLeft: `3px solid ${v.patchAvailable ? C.low : C.high}` }}>
                        <strong>{v.patchAvailable ? "✅ Parche disponible" : "❌ Sin parche confirmado"}</strong>
                      </div>
                    </div>
                  </Card>
                );
              })}
            </>}

            {/* ═══ SUBSCRIBER PORTAL ═══ */}
            {view === "portal" && <>
              <PageHeader title="Mis Suscripciones" subtitle="Gestiona el software que monitoriza OCC-TVM para tus alertas." actions={
                <div style={{ display: "flex", gap: 8 }}>
                  <Btn onClick={() => loadData("portal")} disabled={portalLoading || portalSaving}><I name="refresh" size={12} /> Actualizar</Btn>
                  <Btn primary onClick={savePortalSubscriptions} disabled={portalLoading || portalSaving}>
                    {portalSaving ? "Guardando..." : "Guardar"}
                  </Btn>
                </div>
              } />

              {portalMsg && (
                <div style={{
                  marginBottom: 12,
                  padding: "10px 12px",
                  borderRadius: 8,
                  fontSize: 12,
                  fontWeight: 700,
                  background: portalMsg.type === "error" ? C.criticalBg : C.lowBg,
                  color: portalMsg.type === "error" ? C.critical : C.low,
                  border: `1px solid ${portalMsg.type === "error" ? "#fecaca" : "#bbf7d0"}`,
                }}>
                  {portalMsg.text}
                </div>
              )}

              <Card>
                {portalLoading && <div style={{ padding: 10, fontSize: 12, color: C.gray500 }}>Cargando portal...</div>}
                {!portalLoading && (
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 14 }}>
                    <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 8, background: "#fff", maxHeight: 420, overflow: "auto" }}>
                      <div style={{ padding: "10px 12px", borderBottom: `1px solid ${C.gray100}`, fontSize: 11, fontWeight: 800, color: C.gray600 }}>
                        Fabricantes
                      </div>
                      {subscriptionCatalog.length === 0 && <div style={{ padding: 12, fontSize: 11, color: C.gray500 }}>Sin catálogo disponible.</div>}
                      {subscriptionCatalog.map(item => {
                        const checked = portalVendors.includes(item.vendor);
                        return (
                          <label key={item.vendor} style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 12px", borderBottom: `1px solid ${C.gray100}`, cursor: "pointer", fontSize: 12 }}>
                            <input type="checkbox" checked={checked} onChange={e => togglePortalVendorSelection(item.vendor, e.target.checked)} />
                            <span onClick={() => setPortalActiveVendor(item.vendor)} style={{ color: portalActiveVendor === item.vendor ? C.navy : C.text, fontWeight: portalActiveVendor === item.vendor ? 800 : 600 }}>
                              {item.vendor}
                            </span>
                          </label>
                        );
                      })}
                    </div>

                    <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 8, background: "#fff", maxHeight: 420, overflow: "auto" }}>
                      <div style={{ padding: "10px 12px", borderBottom: `1px solid ${C.gray100}`, fontSize: 11, fontWeight: 800, color: C.gray600 }}>
                        Software {portalActiveVendor ? `de ${portalActiveVendor}` : ""}
                      </div>
                      {!portalActiveVendor && <div style={{ padding: 12, fontSize: 11, color: C.gray500 }}>Selecciona un fabricante.</div>}
                      {portalActiveVendor && ((subscriptionCatalog.find(v => v.vendor === portalActiveVendor)?.products) || []).map(p => {
                        const sub = (portalSubscriptions || []).find(s => s.vendor === portalActiveVendor && s.product === p.product);
                        const checked = !!sub;
                        const selectedVersions = sub?.versions || [];
                        return (
                          <div key={`${portalActiveVendor}-${p.product}`} style={{ padding: "10px 12px", borderBottom: `1px solid ${C.gray100}` }}>
                            <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, fontWeight: 700 }}>
                              <input type="checkbox" checked={checked} onChange={e => togglePortalProductSubscription(portalActiveVendor, p.product, e.target.checked)} />
                              {p.product}
                            </label>
                            {checked && (
                              <div style={{ marginTop: 8, marginLeft: 22 }}>
                                <div style={{ fontSize: 10, color: C.gray500, marginBottom: 6 }}>Versiones (si no marcas ninguna, se notifican todas)</div>
                                {(!p.versions || p.versions.length === 0) && <div style={{ fontSize: 10, color: C.gray400 }}>No hay versiones catalogadas.</div>}
                                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                                  {(p.versions || []).map(ver => (
                                    <label key={ver} style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 10, padding: "2px 6px", background: C.gray50, border: `1px solid ${C.gray200}`, borderRadius: 12 }}>
                                      <input
                                        type="checkbox"
                                        checked={selectedVersions.includes(ver)}
                                        onChange={e => togglePortalSubscriptionVersion(portalActiveVendor, p.product, ver, e.target.checked)}
                                      />
                                      <span>{ver}</span>
                                    </label>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </Card>
            </>}

            {/* ═══ MANUFACTURERS ═══ */}
            {view === "manufacturers" && <>
              <PageHeader title="Fabricantes y Catálogo" subtitle="Catálogo operativo apoyado en la semántica actual de vulnerabilidades, con herramientas de armonización y normalización." />

              {/* ── Stats bar ── */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 14 }}>
                {[
                  { label: "Fabricantes operativos", value: visibleManufacturersCount, color: C.blue },
                  { label: "Productos operativos", value: visibleProductsCount, color: "#059669" },
                  { label: "Aliases configurados", value: mfrAliases?.totalAliases || "—", color: "#7C3AED" },
                  { label: "Entradas no operativas ocultas", value: hiddenManufacturersCount, color: hiddenManufacturersCount > 0 ? C.high : "#059669" },
                ].map((s, i) => (
                  <div key={i} style={{ background: "#fff", border: `1px solid ${C.gray200}`, borderRadius: 8, padding: "12px 14px", textAlign: "center" }}>
                    <div style={{ fontSize: 24, fontWeight: 800, color: s.color }}>{s.value}</div>
                    <div style={{ fontSize: 11, color: C.gray500, fontWeight: 600 }}>{s.label}</div>
                  </div>
                ))}
              </div>

              {/* ── Message banner ── */}
              {mfrMsg && (
                <div style={{ padding: "10px 14px", borderRadius: 6, marginBottom: 14, fontSize: 12, fontWeight: 600, background: mfrMsg.type === "error" ? C.criticalBg : "#ECFDF5", color: mfrMsg.type === "error" ? C.critical : "#065F46", border: `1px solid ${mfrMsg.type === "error" ? "#FECACA" : "#A7F3D0"}` }}>
                  {mfrMsg.text}
                  <button onClick={() => setMfrMsg(null)} style={{ float: "right", background: "none", border: "none", cursor: "pointer", fontWeight: 700, fontSize: 14, lineHeight: 1 }}>×</button>
                </div>
              )}
              {hiddenManufacturersCount > 0 && (
                <div style={{ padding: "10px 14px", borderRadius: 6, marginBottom: 14, fontSize: 12, background: "#FFFBEB", color: "#92400E", border: "1px solid #FDE68A" }}>
                  Se ocultan <strong>{hiddenManufacturersCount}</strong> fabricantes y <strong>{hiddenProductsCount}</strong> productos del catálogo operativo para no reforzar clasificaciones históricas no operativas.
                  {hiddenReasonSummary ? ` Motivos principales: ${hiddenReasonSummary}.` : ""}
                  {hiddenSamplesSummary ? ` Ejemplos: ${hiddenSamplesSummary}.` : ""}
                </div>
              )}

              {/* ── Tabs ── */}
              <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 4, marginBottom: 16 }}>
                <div style={{ display: "flex", gap: 2, padding: 3, background: C.gray100, borderRadius: 10, width: "fit-content" }}>
                  {[
                    { id: "catalog", label: "Catálogo" },
                    { id: "aliases", label: "Aliases" },
                    { id: "merge", label: "Armonizar" },
                    { id: "add", label: "Añadir" },
                  ].map(t => (
                    <button key={t.id} onClick={() => {
                      setMfrTab(t.id);
                      setMfrMsg(null);
                      if (t.id === "aliases" && !mfrAliases) {
                        setMfrAliasesLoading(true);
                        apiFetch("/manufacturers/aliases").then(r => r.json()).then(d => setMfrAliases(d)).catch(() => {}).finally(() => setMfrAliasesLoading(false));
                      }
                    }} style={{
                      padding: "7px 16px", fontSize: 12, fontWeight: mfrTab === t.id ? 600 : 500, borderRadius: 8, border: "none",
                      background: mfrTab === t.id ? "#fff" : "transparent", color: mfrTab === t.id ? C.text : C.gray500,
                      cursor: "pointer", transition: "all 0.15s", whiteSpace: "nowrap",
                      boxShadow: mfrTab === t.id ? "0 1px 3px rgba(0,0,0,0.08)" : "none",
                    }}>{t.label}</button>
                  ))}
                </div>
              </div>

              {/* ── TAB: Catálogo ── */}
              {mfrTab === "catalog" && (
                <div style={{ display: "grid", gridTemplateColumns: "340px 1fr", gap: 12 }}>
                  {/* Left: vendor list with search */}
                  <Card title="Fabricantes" icon="server" noPad>
                    <div style={{ padding: "8px 10px", borderBottom: `1px solid ${C.gray200}` }}>
                      <input
                        type="text"
                        value={mfrSearch}
                        onChange={e => setMfrSearch(e.target.value)}
                        placeholder="🔍 Buscar fabricante..."
                        style={{ width: "100%", padding: "8px 10px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, boxSizing: "border-box" }}
                      />
                    </div>
                    <div style={{ maxHeight: 520, overflow: "auto", padding: "6px 8px" }}>
                      {manufacturersLoading && <div style={{ padding: 20, textAlign: "center", color: C.gray500, fontSize: 12 }}>Cargando...</div>}
                      {!manufacturersLoading && visibleManufacturers
                        .filter(m => !mfrSearch || m.name.toLowerCase().includes(mfrSearch.toLowerCase()))
                        .map(m => (
                        <div
                          key={m.name}
                          onClick={() => {
                            setSelectedManufacturer(m.name);
                            setNewProductForm(prev => ({ ...prev, vendor: m.name }));
                            setMergeForm({ targetName: m.name, sourceNames: [m.name] });
                          }}
                          style={{
                            padding: "8px 10px",
                            borderRadius: 6,
                            border: `1px solid ${selectedManufacturer === m.name ? C.blue : C.gray200}`,
                            background: selectedManufacturer === m.name ? C.bluePale : "#fff",
                            cursor: "pointer",
                            marginBottom: 4,
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                          }}
                        >
                          <div>
                            <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{m.name}</div>
                          </div>
                          <span style={{ background: C.gray100, color: C.gray600, padding: "2px 8px", borderRadius: 10, fontSize: 11, fontWeight: 600 }}>
                            {m.productsCount}
                          </span>
                        </div>
                      ))}
                      {!manufacturersLoading && visibleManufacturers.filter(m => !mfrSearch || m.name.toLowerCase().includes(mfrSearch.toLowerCase())).length === 0 && (
                        <div style={{ padding: 20, textAlign: "center", fontSize: 12, color: C.gray400 }}>
                          {mfrSearch ? `Sin resultados para "${mfrSearch}"` : "No hay fabricantes todavía."}
                        </div>
                      )}
                    </div>
                  </Card>

                  {/* Right: product detail */}
                  <div>
                    {selectedManufacturer ? (
                      <Card title={`Software — ${selectedManufacturer}`} icon="edit"
                        action={<button onClick={async () => {
                          if (!confirm(`¿Eliminar fabricante "${selectedManufacturer}" y todos sus productos?`)) return;
                          try {
                            await apiFetch(`/manufacturers/${encodeURIComponent(selectedManufacturer)}`, { method: "DELETE" });
                            setMfrMsg({ type: "success", text: `Fabricante "${selectedManufacturer}" eliminado` });
                            setSelectedManufacturer("");
                            loadManufacturers();
                          } catch (e) { setMfrMsg({ type: "error", text: e.message }); }
                        }} style={{ background: "none", border: "none", cursor: "pointer", fontSize: 12, color: C.critical, fontWeight: 600 }}>🗑️ Eliminar fabricante</button>}
                      >
                        {((manufacturers.find(m => m.name === selectedManufacturer)?.products) || []).length === 0 ? (
                          <div style={{ padding: 20, textAlign: "center", fontSize: 12, color: C.gray500 }}>No hay productos vinculados a este fabricante.</div>
                        ) : (
                          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: 8 }}>
                            {((manufacturers.find(m => m.name === selectedManufacturer)?.products) || []).map(p => (
                              <div key={`${p.id}-${p.product}`} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 8, background: C.gray50, position: "relative" }}>
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                  <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{p.product}</div>
                                  <button onClick={async () => {
                                    if (!confirm(`¿Eliminar producto "${p.product}"?`)) return;
                                    try {
                                      await apiFetch(`/manufacturers/products/${p.id}`, { method: "DELETE" });
                                      setMfrMsg({ type: "success", text: `Producto "${p.product}" eliminado` });
                                      loadManufacturers();
                                    } catch (e) { setMfrMsg({ type: "error", text: e.message }); }
                                  }} style={{ background: "none", border: "none", cursor: "pointer", fontSize: 11, color: C.gray400, padding: 2 }} title="Eliminar producto">✕</button>
                                </div>
                                <div style={{ fontSize: 11, color: C.gray500, marginTop: 4 }}>
                                  {(p.versions || []).length > 0 ? (
                                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 2 }}>
                                      {p.versions.slice(0, 8).map((v, i) => (
                                        <span key={i} style={{ background: "#fff", border: `1px solid ${C.gray200}`, padding: "1px 6px", borderRadius: 4, fontSize: 10 }}>{v}</span>
                                      ))}
                                      {p.versions.length > 8 && <span style={{ fontSize: 10, color: C.gray400 }}>+{p.versions.length - 8} más</span>}
                                    </div>
                                  ) : <span style={{ fontStyle: "italic" }}>Todas las versiones</span>}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </Card>
                    ) : (
                      <Card title="Software vinculado" icon="edit">
                        <div style={{ padding: 30, textAlign: "center", fontSize: 12, color: C.gray500 }}>
                          ← Selecciona un fabricante de la lista para ver su software y versiones.
                        </div>
                      </Card>
                    )}
                  </div>
                </div>
              )}

              {/* ── TAB: Aliases / Normalización ── */}
              {mfrTab === "aliases" && (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                  <Card title="Mapa de Aliases" icon="link">
                    {mfrAliasesLoading ? (
                      <div style={{ padding: 20, textAlign: "center", color: C.gray500, fontSize: 12 }}>Cargando aliases...</div>
                    ) : mfrAliases?.aliases ? (
                      <div style={{ maxHeight: 480, overflow: "auto" }}>
                        {Object.entries(mfrAliases.aliases).sort((a, b) => a[0].localeCompare(b[0])).map(([canonical, aliases]) => (
                          <div key={canonical} style={{ marginBottom: 10, padding: "8px 10px", border: `1px solid ${C.gray200}`, borderRadius: 6, background: C.gray50 }}>
                            <div style={{ fontSize: 13, fontWeight: 700, color: C.blue, marginBottom: 4 }}>
                              🏷️ {canonical}
                            </div>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                              {aliases.map((a, i) => (
                                <span key={i} style={{ background: "#fff", border: `1px solid ${C.gray200}`, padding: "2px 8px", borderRadius: 4, fontSize: 11, color: C.gray600 }}>
                                  {a} →
                                </span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div style={{ padding: 20, textAlign: "center", color: C.gray500, fontSize: 12 }}>No se pudieron cargar los aliases.</div>
                    )}
                  </Card>

                  <div>
                    {/* Duplicates detected */}
                    <Card title="Duplicados Detectados" icon="warning" style={{ marginBottom: 12 }}>
                      {mfrAliases?.stats?.duplicateGroups?.length > 0 ? (
                        <div style={{ maxHeight: 220, overflow: "auto" }}>
                          {mfrAliases.stats.duplicateGroups.map((g, i) => (
                            <div key={i} style={{ padding: "8px 10px", border: `1px solid #FDE68A`, borderRadius: 6, background: "#FFFBEB", marginBottom: 6 }}>
                              <div style={{ fontSize: 12, fontWeight: 700, color: "#92400E", marginBottom: 4 }}>
                                ⚠️ "{g.canonical}" — {g.count} variantes en catálogo
                              </div>
                              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                                {g.variants.map((v, j) => (
                                  <span key={j} style={{ background: "#fff", border: "1px solid #FDE68A", padding: "2px 8px", borderRadius: 4, fontSize: 11 }}>{v}</span>
                                ))}
                              </div>
                              <button onClick={() => {
                                setMfrTab("merge");
                                setMergeForm({ targetName: g.canonical, sourceNames: g.variants });
                              }} style={{ marginTop: 6, background: "none", border: "none", color: C.blue, fontSize: 11, fontWeight: 600, cursor: "pointer", padding: 0 }}>
                                → Armonizar ahora
                              </button>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div style={{ padding: 20, textAlign: "center", fontSize: 12, color: "#059669" }}>
                          ✅ No se detectaron duplicados. El catálogo está limpio.
                        </div>
                      )}
                    </Card>

                    {/* Vendors with subscriptions */}
                    <Card title="Vendors con Suscripciones Activas" icon="users">
                      {mfrAliases?.stats?.vendorsWithSubscriptions?.length > 0 ? (
                        <div style={{ maxHeight: 200, overflow: "auto" }}>
                          {mfrAliases.stats.vendorsWithSubscriptions.map((v, i) => (
                            <div key={i} style={{ display: "flex", justifyContent: "space-between", padding: "6px 8px", borderBottom: `1px solid ${C.gray100}`, fontSize: 12 }}>
                              <span style={{ fontWeight: 600 }}>{v.vendor}</span>
                              <span style={{ background: C.bluePale, color: C.blue, padding: "1px 8px", borderRadius: 10, fontSize: 11, fontWeight: 600 }}>
                                {v.subscriptionCount} subs
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div style={{ padding: 16, textAlign: "center", fontSize: 12, color: C.gray500 }}>No hay suscripciones activas por vendor.</div>
                      )}
                    </Card>
                  </div>
                </div>
              )}

              {/* ── TAB: Armonizar ── */}
              {mfrTab === "merge" && (
                <Card title="Armonizar / Unir Fabricantes" icon="merge">
                  <p style={{ fontSize: 12, color: C.gray500, marginBottom: 14 }}>
                    Selecciona fabricantes a fusionar en un nombre canónico. Sus productos, suscripciones y CVEs se actualizarán automáticamente.
                  </p>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                    <div>
                      <label style={{ fontSize: 11, color: C.gray600, display: "block", marginBottom: 4, fontWeight: 600 }}>Nombre final (canónico)</label>
                      <Input value={mergeForm.targetName} onChange={v => setMergeForm({ ...mergeForm, targetName: v })} placeholder="fabricante objetivo" />
                      <div style={{ marginTop: 12 }}>
                        <Btn primary onClick={async () => {
                          setMfrMsg(null);
                          try {
                            const res = await apiFetch("/manufacturers/merge", {
                              method: "POST",
                              headers: { "Content-Type": "application/json" },
                              body: JSON.stringify({ targetName: mergeForm.targetName, sourceNames: mergeForm.sourceNames }),
                            });
                            const data = await res.json();
                            if (data.error || !data.success) throw new Error(data.message || data.error || "Error en armonización");
                            setMfrMsg({ type: "success", text: `✅ Armonización completada: ${data.merged?.length || 0} fabricantes fusionados en "${data.target}"` });
                            setMergeForm({ targetName: "", sourceNames: [] });
                            loadManufacturers();
                            // Reload aliases
                            apiFetch("/manufacturers/aliases").then(r => r.json()).then(d => setMfrAliases(d)).catch(() => {});
                          } catch (e) {
                            setMfrMsg({ type: "error", text: `Error: ${e.message}` });
                          }
                        }} disabled={!mergeForm.targetName || mergeForm.sourceNames.length < 2}>
                          🔄 Aplicar armonización
                        </Btn>
                        <div style={{ fontSize: 11, color: C.gray400, marginTop: 6 }}>
                          Seleccionados: {mergeForm.sourceNames.length} fabricantes
                        </div>
                      </div>
                    </div>
                    <div>
                      <label style={{ fontSize: 11, color: C.gray600, display: "block", marginBottom: 4, fontWeight: 600 }}>Fabricantes a fusionar</label>
                      <input
                        type="text"
                        placeholder="🔍 Filtrar..."
                        id="merge-filter"
                        onChange={e => { document.getElementById("merge-filter").dataset.filter = e.target.value; document.getElementById("merge-list").querySelectorAll("[data-vendor]").forEach(el => { el.style.display = el.dataset.vendor.includes(e.target.value.toLowerCase()) ? "" : "none"; }); }}
                        style={{ width: "100%", padding: "8px 10px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, boxSizing: "border-box", marginBottom: 6 }}
                      />
                      <div id="merge-list" style={{ maxHeight: 320, overflow: "auto", border: `1px solid ${C.gray200}`, borderRadius: 6, padding: 8, background: "#fff" }}>
                        {allManufacturers.map(m => {
                          const checked = (mergeForm.sourceNames || []).includes(m.name);
                          return (
                            <label key={`merge-${m.name}`} data-vendor={m.name.toLowerCase()} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 2px", fontSize: 12, cursor: "pointer" }}>
                              <input type="checkbox" checked={checked} onChange={e => toggleMergeSource(m.name, e.target.checked)} />
                              <span style={{ flex: 1 }}>{m.name}</span>
                              <span style={{ fontSize: 10, color: C.gray400 }}>{m.productsCount} prod.</span>
                            </label>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </Card>
              )}

              {/* ── TAB: Añadir ── */}
              {mfrTab === "add" && (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                  <Card title="Nuevo Fabricante" icon="plus">
                    <p style={{ fontSize: 12, color: C.gray500, marginBottom: 10 }}>
                      El nombre se normaliza automáticamente (minúsculas + aliases).
                    </p>
                    <div style={{ display: "flex", gap: 8 }}>
                      <Input value={newManufacturerName} onChange={setNewManufacturerName} placeholder="ej: Adobe Systems" style={{ flex: 1 }} />
                      <Btn primary onClick={async () => {
                        setMfrMsg(null);
                        try {
                          await createManufacturer();
                          setMfrMsg({ type: "success", text: `Fabricante "${newManufacturerName}" creado correctamente` });
                          setNewManufacturerName("");
                        } catch (e) { setMfrMsg({ type: "error", text: e.message }); }
                      }}>Crear</Btn>
                    </div>
                  </Card>
                  <Card title="Nuevo Producto" icon="plus">
                    <p style={{ fontSize: 12, color: C.gray500, marginBottom: 10 }}>
                      Asocia un producto a un fabricante existente con versiones opcionales.
                    </p>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 8 }}>
                      <select
                        value={newProductForm.vendor}
                        onChange={e => setNewProductForm({ ...newProductForm, vendor: e.target.value })}
                        style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff", fontSize: 12 }}
                      >
                        <option value="">Selecciona fabricante</option>
                        {allManufacturers.map(m => <option key={m.name} value={m.name}>{m.name}</option>)}
                      </select>
                      <Input value={newProductForm.product} onChange={v => setNewProductForm({ ...newProductForm, product: v })} placeholder="nombre del producto" />
                    </div>
                    <div style={{ display: "flex", gap: 8 }}>
                      <Input value={newProductForm.versions} onChange={v => setNewProductForm({ ...newProductForm, versions: v })} placeholder="versiones (coma separadas, opcional)" style={{ flex: 1 }} />
                      <Btn primary onClick={async () => {
                        setMfrMsg(null);
                        try {
                          await createManufacturerProduct();
                          setMfrMsg({ type: "success", text: `Producto "${newProductForm.product}" creado correctamente` });
                          setNewProductForm({ vendor: "", product: "", versions: "" });
                        } catch (e) { setMfrMsg({ type: "error", text: e.message }); }
                      }}>Crear</Btn>
                    </div>
                  </Card>
                </div>
              )}
            </>}

            {/* ═══ CONTACTS ═══ */}
            {view === "contacts" && <>
              <PageHeader title="Servicios IT" subtitle="Directorio de equipos IT para comunicación de vulnerabilidades" actions={
                <Btn primary onClick={() => { setEditContact({ id: null, name: "", email: "", products: [], notes: "", contactPerson: "", phone: "", department: "" }); setShowContactForm(true); }}><I name="plus" size={14} color="#fff" /> Nuevo servicio</Btn>
              } />

              {showContactForm && editContact && (
                <Card title={editContact.id ? "Editar servicio IT" : "Nuevo servicio IT"} icon="edit" style={{ marginBottom: 16 }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                    <div>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Nombre del equipo</label>
                      <Input value={editContact.name} onChange={v => setEditContact({ ...editContact, name: v })} placeholder="Ej: Equipo Infraestructura Windows" />
                    </div>
                    <div>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Email de contacto</label>
                      <Input value={editContact.email} onChange={v => setEditContact({ ...editContact, email: v })} placeholder="equipo@corp.local" icon="mail" />
                    </div>
                    <div>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Persona de contacto</label>
                      <Input value={editContact.contactPerson} onChange={v => setEditContact({ ...editContact, contactPerson: v })} placeholder="Nombre y apellido" />
                    </div>
                    <div>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Teléfono</label>
                      <Input value={editContact.phone} onChange={v => setEditContact({ ...editContact, phone: v })} placeholder="+34 6XX XXX XXX" />
                    </div>
                  </div>
                  <div style={{ marginTop: 12 }}>
                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Productos asignados (vendor/product, separados por coma)</label>
                    <Input value={(editContact.products || []).join(", ")} onChange={v => setEditContact({ ...editContact, products: v.split(",").map(x => x.trim()).filter(Boolean) })} placeholder="microsoft/windows_11, fortinet/fortios" />
                  </div>
                  <div style={{ marginTop: 12 }}>
                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Notas / Observaciones</label>
                    <textarea value={editContact.notes} onChange={e => setEditContact({ ...editContact, notes: e.target.value })} placeholder="Ventana de parcheo, restricciones, observaciones..." rows={3} style={{ width: "100%", padding: "10px 12px", fontSize: 12, border: `1px solid ${C.gray200}`, borderRadius: 6, resize: "vertical", fontFamily: "inherit", boxSizing: "border-box" }} />
                  </div>
                  <div style={{ display: "flex", gap: 8, marginTop: 14, justifyContent: "flex-end" }}>
                    <Btn onClick={() => { setShowContactForm(false); setEditContact(null); }}>Cancelar</Btn>
                    <Btn primary onClick={() => saveContact(editContact)}>Guardar</Btn>
                  </div>
                </Card>
              )}

              {contacts.map(c => {
                const contactProds = (c.subscriptions || []).map(s => `${s.vendor}/${s.product}`.toLowerCase());
                const affectedVulns = vulns.filter(v => getOperationalAffectedPairs(v).some(product => contactProds.includes(`${product.vendor}/${product.product}`.toLowerCase())));
                const critCount = affectedVulns.filter(v => v.cvssV31Severity === "CRITICAL").length;
                const exploitedCount = affectedVulns.filter(v => v.isKnownExploited).length;
                return (
                  <Card key={c.id} style={{ marginBottom: 10, borderLeft: exploitedCount > 0 ? `4px solid ${C.critical}` : critCount > 0 ? `4px solid ${C.high}` : `4px solid ${C.gray200}` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                          <span style={{ fontSize: 15, fontWeight: 800, color: C.text }}>{c.name}</span>
                          {exploitedCount > 0 && <span style={{ background: C.criticalBg, color: C.critical, padding: "1px 8px", borderRadius: 3, fontSize: 9, fontWeight: 700 }}>⚠ {exploitedCount} explotadas</span>}
                          {critCount > 0 && <span style={{ background: C.highBg, color: C.high, padding: "1px 8px", borderRadius: 3, fontSize: 9, fontWeight: 700 }}>{critCount} críticas</span>}
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: 14, fontSize: 12, color: C.gray600, marginBottom: 6 }}>
                          <span style={{ display: "flex", alignItems: "center", gap: 4 }}><I name="mail" size={13} color={C.blue} /> {c.email}</span>
                          <span>{c.contactPerson}</span>
                          {c.phone && <span style={{ color: C.gray400 }}>{c.phone}</span>}
                        </div>
                        <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 6 }}>
                          {(c.subscriptions || []).map(s => <span key={`${s.vendor}/${s.product}`} style={{ background: C.bluePale, color: C.navy, padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 600 }}>{s.vendor}/{s.product}</span>)}
                        </div>
                        {c.notes && <div style={{ fontSize: 11, color: C.gray500, background: C.gray50, padding: "6px 10px", borderRadius: 4, borderLeft: `2px solid ${C.gray300}`, lineHeight: 1.5 }}>{c.notes}</div>}
                      </div>
                      <div style={{ display: "flex", gap: 6, flexShrink: 0, marginLeft: 12 }}>
                        <Btn small onClick={() => { setEditContact({ ...c, products: (c.subscriptions || []).map(s => `${s.vendor}/${s.product}`) }); setShowContactForm(true); }}><I name="edit" size={12} /></Btn>
                      </div>
                    </div>
                    {affectedVulns.length > 0 && (
                      <div style={{ marginTop: 10, padding: "8px 10px", background: C.gray50, borderRadius: 4 }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: C.gray500, marginBottom: 4, textTransform: "uppercase" }}>CVEs que afectan a este equipo ({affectedVulns.length})</div>
                        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                          {affectedVulns.map(v => (
                            <span key={v.cveId} onClick={() => openVulnerabilityDetail(v)} style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "2px 8px", background: sevBg(v.cvssV31Severity), border: `1px solid ${sevColor(v.cvssV31Severity)}30`, borderRadius: 3, fontSize: 9, fontWeight: 700, fontFamily: "monospace", cursor: "pointer", color: sevColor(v.cvssV31Severity) }}>
                              {v.cveId} {v.isKnownExploited && "🔴"}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </Card>
                );
              })}
            </>}

            {/* ═══ NOTIFICATIONS HISTORY ═══ */}
            {view === "notifications" && <>
              <PageHeader title="Comunicaciones" />
              {notifMsg && (
                <div className="fade" style={{ marginBottom: 12, padding: "10px 12px", borderRadius: 6, fontSize: 12, fontWeight: 700, background: notifMsg.type === "success" ? C.lowBg : C.criticalBg, color: notifMsg.type === "success" ? C.low : C.critical }}>
                  {notifMsg.text}
                </div>
              )}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 16 }}>
                <Metric icon="mail" label="Enviadas" value={notifHistory.filter((item) => item.status === "sent").length} color={C.low} />
                <Metric icon="x" label="Fallidas" value={notifHistory.filter((item) => item.status !== "sent").length} color={C.critical} />
                <Metric icon="activity" label="Cola pendiente" value={notificationCenter.processHealth?.queuePending || 0} color={C.high} />
                <Metric icon="settings" label="Proceso" value={notificationCenter.processHealth?.enabled ? "Activo" : "Pausado"} sub={notificationCenter.processHealth?.smtpConfigured ? "SMTP OK" : "SMTP pendiente"} color={notificationCenter.processHealth?.enabled ? C.blue : C.gray500} />
              </div>
              <Card title="Histórico operativo de envíos" icon="mail" noPad>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead><tr style={{ background: C.gray50 }}>
                    {["Fecha/Hora", "Tipo", "Destinatario", "Asunto", "Plantilla", "Vulns", "Canal", "Estado", "Motivo"].map(h => (
                      <th key={h} style={{ padding: "9px 12px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${C.gray200}` }}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>{notifHistory.length === 0 ? (
                    <tr><td colSpan={9} style={{ padding: 30, textAlign: "center", color: C.gray400, fontSize: 12 }}>No hay comunicaciones registradas aún</td></tr>
                  ) : notifHistory.map(n => (
                    <tr key={n.id} className="rh" style={{ cursor: "pointer" }} onClick={() => viewNotification(n.id)}>
                      <td style={{ padding: "8px 12px", fontSize: 10, fontFamily: "monospace" }}>{fmtDate(n.sentAt)}</td>
                      <td style={{ padding: "8px 12px", fontSize: 11, fontWeight: 700 }}>{toSentence(n.notificationType || n.type || "normal")}</td>
                      <td style={{ padding: "8px 12px", fontSize: 11 }}>{n.to}</td>
                      <td style={{ padding: "8px 12px", fontSize: 11, fontWeight: 500 }}>{n.subject}</td>
                      <td style={{ padding: "8px 12px" }}><span style={{ padding: "2px 8px", borderRadius: 3, fontSize: 9, fontWeight: 600, background: C.bluePale, color: C.blue }}>{n.template || "legacy"}</span></td>
                      <td style={{ padding: "8px 12px", fontSize: 11, fontWeight: 700 }}>{n.vulnerabilityCount || (Array.isArray(n.cveIds) ? n.cveIds.length : 0)}</td>
                      <td style={{ padding: "8px 12px", fontSize: 11 }}>{String(n.channel || "email").toUpperCase()}</td>
                      <td style={{ padding: "8px 12px" }}><span style={{ color: n.status === "sent" ? C.low : C.critical, fontWeight: 600, fontSize: 10 }}>{n.status === "sent" ? "✓ Enviado" : "✗ Error"}</span></td>
                      <td style={{ padding: "8px 12px", fontSize: 10, color: C.gray500 }}>{n.triggerReason || "-"}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </Card>
              {notifDetail && (
                <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.4)", zIndex: 200, display: "flex", alignItems: "center", justifyContent: "center" }} onClick={() => setNotifDetail(null)}>
                  <div style={{ background: "#fff", borderRadius: 12, padding: 28, width: 560, maxHeight: "80vh", overflow: "auto" }} onClick={e => e.stopPropagation()}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                      <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>Detalle de Notificación</h3>
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <Btn small onClick={() => resendCommunication(notifDetail.id)}>Reenviar</Btn>
                        <span style={{ cursor: "pointer" }} onClick={() => setNotifDetail(null)}><I name="x" size={18} /></span>
                      </div>
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 16 }}>
                      <div><span style={{ fontSize: 10, fontWeight: 600, color: C.gray500 }}>DESTINATARIO</span><div style={{ fontSize: 12 }}>{notifDetail.to}</div></div>
                      <div><span style={{ fontSize: 10, fontWeight: 600, color: C.gray500 }}>FECHA</span><div style={{ fontSize: 12 }}>{fmtDate(notifDetail.sentAt)}</div></div>
                      <div><span style={{ fontSize: 10, fontWeight: 600, color: C.gray500 }}>ASUNTO</span><div style={{ fontSize: 12 }}>{notifDetail.subject}</div></div>
                      <div><span style={{ fontSize: 10, fontWeight: 600, color: C.gray500 }}>TIPO</span><div style={{ fontSize: 12 }}>{toSentence(notifDetail.notificationType || notifDetail.type || "normal")}</div></div>
                      <div><span style={{ fontSize: 10, fontWeight: 600, color: C.gray500 }}>PLANTILLA</span><div style={{ fontSize: 12 }}>{notifDetail.templateKey || notifDetail.template || "legacy"}</div></div>
                      <div><span style={{ fontSize: 10, fontWeight: 600, color: C.gray500 }}>VULNERABILIDADES</span><div style={{ fontSize: 12 }}>{notifDetail.vulnerabilityCount || ensureArray(notifDetail.cveIds).length}</div></div>
                      <div><span style={{ fontSize: 10, fontWeight: 600, color: C.gray500 }}>CANAL</span><div style={{ fontSize: 12 }}>{String(notifDetail.channel || "email").toUpperCase()}</div></div>
                      <div><span style={{ fontSize: 10, fontWeight: 600, color: C.gray500 }}>MOTIVO</span><div style={{ fontSize: 12 }}>{notifDetail.triggerReason || "-"}</div></div>
                      <div><span style={{ fontSize: 10, fontWeight: 600, color: C.gray500 }}>ESTADO</span><div style={{ fontSize: 12, color: notifDetail.status === "sent" ? C.low : C.critical, fontWeight: 600 }}>{notifDetail.status}</div></div>
                    </div>
                    {Array.isArray(notifDetail.cveIds) && notifDetail.cveIds.length > 0 && (
                      <div style={{ marginBottom: 12 }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: C.gray500, marginBottom: 6 }}>CVEs incluidas</div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                          {notifDetail.cveIds.map((cveId) => (
                            <span key={cveId} style={{ padding: "3px 8px", borderRadius: 999, background: C.gray100, fontSize: 11, fontFamily: "monospace", color: C.gray700 }}>{cveId}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {(notifDetail.errorMessage || notifDetail.error) && <div style={{ background: C.criticalBg, color: C.critical, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 12 }}>Error: {notifDetail.errorMessage || notifDetail.error}</div>}
                    <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 8, overflow: "hidden", background: "#fff" }}>
                      {notifDetail.htmlContent ? (
                        <iframe title="Vista previa de comunicación" srcDoc={notifDetail.htmlContent} style={{ width: "100%", height: 460, border: 0 }} />
                      ) : (
                        <div style={{ padding: 16, fontSize: 12, color: C.gray500 }}>No hay vista previa HTML almacenada para esta comunicación.</div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </>}

            {/* ═══ REPORTS ═══ */}
            {view === "reports" && <>
              <PageHeader title="Informes" />
              <Card title="Módulo en construcción" icon="file">
                <div style={{ textAlign: "center", padding: "22px 10px" }}>
                  <div style={{ fontSize: 14, fontWeight: 700, color: C.gray700, marginBottom: 8 }}>
                    Esta sección estará disponible próximamente.
                  </div>
                  <div style={{ fontSize: 12, color: C.gray500, marginBottom: 14 }}>
                    Estamos preparando el nuevo módulo de generación y gestión de informes.
                  </div>
                  <Btn onClick={() => setView("overview")}>Volver a Visión General</Btn>
                </div>
              </Card>
            </>}

            {/* ═══ AI ASSISTANT ═══ */}
            {view === "ai" && <>
              <PageHeader title="Asistente IA" subtitle="Análisis de impacto, recomendaciones de parcheo, correlación con infraestructura. Conectado a Ollama." />

              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 14 }}>
                {[
                  "Dame un resumen del estado actual de vulnerabilidades",
                  "Analiza el impacto de CVE-2025-21298",
                  "¿Qué vulnerabilidades afectan a Fortinet?",
                  "¿Qué equipos IT necesitan actuar urgentemente?",
                  "Draft de comunicación para el equipo de Ivanti",
                ].map(q => (
                  <span key={q} onClick={() => { setAiQuery(q); }} style={{ padding: "4px 10px", background: C.bluePale, color: C.navy, borderRadius: 4, fontSize: 10, fontWeight: 600, cursor: "pointer" }}>{q}</span>
                ))}
              </div>

              <Card noPad style={{ height: "calc(100vh - 280px)", display: "flex", flexDirection: "column" }}>
                <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
                  {aiMessages.length === 0 && (
                    <div style={{ textAlign: "center", padding: "60px 20px", color: C.gray400 }}>
                      <I name="brain" size={40} color={C.gray300} />
                      <div style={{ fontSize: 14, fontWeight: 600, marginTop: 12 }}>Asistente IA OCC</div>
                      <div style={{ fontSize: 12, marginTop: 4 }}>Consulta sobre CVEs, impacto en infraestructura, o solicita análisis y recomendaciones</div>
                    </div>
                  )}
                  {aiMessages.map((m, i) => (
                    <div key={i} className="fade" style={{ display: "flex", justifyContent: m.role === "user" ? "flex-end" : "flex-start", marginBottom: 10 }}>
                      <div style={{
                        maxWidth: "80%", padding: "10px 14px", borderRadius: 10,
                        background: m.role === "user" ? C.navy : C.gray50,
                        color: m.role === "user" ? "#fff" : C.text,
                        fontSize: 12, lineHeight: 1.7, whiteSpace: "pre-wrap",
                        borderTopRightRadius: m.role === "user" ? 2 : 10,
                        borderTopLeftRadius: m.role === "user" ? 10 : 2,
                      }}>
                        {m.content.split(/(\*\*.*?\*\*)/).map((part, j) =>
                          part.startsWith("**") && part.endsWith("**")
                            ? <strong key={j}>{part.slice(2, -2)}</strong>
                            : <span key={j}>{part}</span>
                        )}
                      </div>
                    </div>
                  ))}
                  {aiLoading && (
                    <div style={{ display: "flex", gap: 4, padding: "8px 14px" }}>
                      {[0, 1, 2].map(i => <div key={i} style={{ width: 8, height: 8, borderRadius: "50%", background: C.gray300, animation: `pulse 1.2s ${i * 0.2}s infinite` }} />)}
                    </div>
                  )}
                  <div ref={aiEndRef} />
                </div>
                <div style={{ padding: "10px 14px", borderTop: `1px solid ${C.gray200}`, display: "flex", gap: 8 }}>
                  <input
                    value={aiQuery}
                    onChange={e => setAiQuery(e.target.value)}
                    onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleAiSend(); } }}
                    placeholder="Pregunta sobre vulnerabilidades, impacto, recomendaciones..."
                    style={{ flex: 1, padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, outline: "none" }}
                  />
                  <Btn primary onClick={handleAiSend} disabled={aiLoading || !aiQuery.trim()}><I name="send" size={14} color="#fff" /></Btn>
                </div>
              </Card>
            </>}

            {/* ═══ ACCOUNT ═══ */}
            {view === "account" && <>
              <PageHeader title="Tu cuenta" />
              <Card
                title="Perfil"
                icon="users"
                action={<Btn onClick={() => loadData("account")} disabled={accountLoading || accountSaving}><I name="refresh" size={12} /> Actualizar</Btn>}
              >
                {accountLoading ? (
                  <div style={{ padding: 18, textAlign: "center", color: C.gray500 }}>Cargando perfil...</div>
                ) : (
                  <>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Nombre</label>
                        <Input
                          value={accountProfile?.name || ""}
                          onChange={(v) => setAccountProfile((p) => ({ ...(p || {}), name: v }))}
                          placeholder="Nombre"
                        />
                      </div>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Email</label>
                        <Input value={accountProfile?.email || ""} onChange={() => { }} placeholder="Email" style={{ opacity: 0.85 }} />
                      </div>
                    </div>

                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 14 }}>
                      <span style={{ padding: "3px 10px", borderRadius: 10, fontSize: 11, fontWeight: 800, background: C.bluePale, color: C.blue }}>
                        {String(accountProfile?.role || role || "USER").toUpperCase()}
                      </span>
                      <span style={{ padding: "3px 10px", borderRadius: 10, fontSize: 11, fontWeight: 800, background: C.gray100, color: C.gray600 }}>
                        {String(accountProfile?.authProvider || currentUser?.authProvider || "LOCAL")}
                      </span>
                      <span style={{ padding: "3px 10px", borderRadius: 10, fontSize: 11, fontWeight: 800, background: C.gray50, color: C.gray500 }}>
                        Último acceso: {fmtDate(accountProfile?.lastLoginAt)}
                      </span>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14, marginBottom: 14 }}>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Email de notificaciones</label>
                        <Input
                          value={accountProfile?.notificationEmail || ""}
                          onChange={(v) => setAccountProfile((p) => ({ ...(p || {}), notificationEmail: v }))}
                          placeholder="destinatario@empresa.com"
                          icon="mail"
                        />
                      </div>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Teléfono</label>
                        <Input
                          value={accountProfile?.phone || ""}
                          onChange={(v) => setAccountProfile((p) => ({ ...(p || {}), phone: v }))}
                          placeholder="+34..."
                        />
                      </div>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Idioma de comunicación</label>
                        <select
                          value={accountProfile?.communicationLanguage || "es"}
                          onChange={(e) => setAccountProfile((p) => ({ ...(p || {}), communicationLanguage: e.target.value }))}
                          style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff", boxSizing: "border-box" }}
                        >
                          <option value="es">Español</option>
                          <option value="en">English</option>
                        </select>
                      </div>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14, marginBottom: 14 }}>
                      <label style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 12px", borderRadius: 8, background: C.gray50, border: `1px solid ${C.gray200}` }}>
                        <input
                          type="checkbox"
                          checked={!!accountProfile?.canReceiveNotifications}
                          onChange={(e) => setAccountProfile((p) => ({ ...(p || {}), canReceiveNotifications: e.target.checked }))}
                        />
                        <span style={{ fontSize: 12, color: C.text, fontWeight: 600 }}>Puede recibir notificaciones</span>
                      </label>
                      <label style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 12px", borderRadius: 8, background: C.gray50, border: `1px solid ${C.gray200}` }}>
                        <input
                          type="checkbox"
                          checked={!!accountProfile?.notificationsPaused}
                          onChange={(e) => setAccountProfile((p) => ({ ...(p || {}), notificationsPaused: e.target.checked }))}
                        />
                        <span style={{ fontSize: 12, color: C.text, fontWeight: 600 }}>Notificaciones en pausa</span>
                      </label>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Pausa hasta</label>
                        <input
                          type="datetime-local"
                          value={accountProfile?.notificationsPausedUntil ? String(accountProfile.notificationsPausedUntil).slice(0, 16) : ""}
                          onChange={(e) => setAccountProfile((p) => ({ ...(p || {}), notificationsPausedUntil: e.target.value || null }))}
                          style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 6, boxSizing: "border-box" }}
                        />
                      </div>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Persona de contacto</label>
                        <Input
                          value={accountProfile?.contactPerson || ""}
                          onChange={(v) => setAccountProfile((p) => ({ ...(p || {}), contactPerson: v }))}
                          placeholder="Contacto"
                        />
                      </div>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Departamento</label>
                        <Input
                          value={accountProfile?.department || ""}
                          onChange={(v) => setAccountProfile((p) => ({ ...(p || {}), department: v }))}
                          placeholder="Departamento"
                        />
                      </div>
                    </div>

                    <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
                      <Btn
                        primary
                        onClick={async () => {
                          setAccountSaving(true);
                          setAccountMsg(null);
                          try {
                            const payload = {
                              name: accountProfile?.name || "",
                              notificationEmail: accountProfile?.notificationEmail || "",
                              canReceiveNotifications: !!accountProfile?.canReceiveNotifications,
                              notificationsPaused: !!accountProfile?.notificationsPaused,
                              notificationsPausedUntil: accountProfile?.notificationsPausedUntil || null,
                              communicationLanguage: accountProfile?.communicationLanguage || "es",
                              contactPerson: accountProfile?.contactPerson || "",
                              department: accountProfile?.department || "",
                              phone: accountProfile?.phone || "",
                            };
                            const r = await apiFetch("/auth/me", { method: "PUT", body: JSON.stringify(payload) });
                            const d = await r.json();
                            if (!r.ok) throw new Error(d?.message || "No se pudo guardar");
                            setAccountProfile(d);
                            setAccountMsg({ type: "success", text: "Perfil actualizado" });
                            setTimeout(() => setAccountMsg(null), 2500);
                          } catch (e) {
                            setAccountMsg({ type: "error", text: e?.message || "Error guardando perfil" });
                            setTimeout(() => setAccountMsg(null), 3500);
                          } finally {
                            setAccountSaving(false);
                          }
                        }}
                        disabled={accountSaving || accountLoading}
                      >
                        {accountSaving ? "Guardando..." : "Guardar"}
                      </Btn>
                    </div>

                    {accountMsg && (
                      <div className="fade" style={{ marginTop: 12, padding: "10px 12px", borderRadius: 6, fontSize: 12, fontWeight: 700, background: accountMsg.type === "success" ? C.lowBg : C.criticalBg, color: accountMsg.type === "success" ? C.low : C.critical }}>
                        {accountMsg.text}
                      </div>
                    )}
                  </>
                )}
              </Card>

              {String(accountProfile?.role || role).toUpperCase() === "SUBSCRIBER" && (
                <Card title="Suscripciones" icon="mail" action={<Btn onClick={() => setView("portal")}>Gestionar</Btn>}>
                  <div style={{ fontSize: 12, color: C.gray600, marginBottom: 10 }}>
                    Gestiona aquí tus datos de usuario y utiliza <strong>Mis Suscripciones</strong> para editar productos/versiones.
                  </div>
                  {Array.isArray(accountProfile?.subscriptions) && accountProfile.subscriptions.length > 0 ? (
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                      {accountProfile.subscriptions.slice(0, 12).map((s) => (
                        <span key={s.id} style={{ padding: "4px 10px", borderRadius: 999, background: C.gray100, fontSize: 11, color: C.gray700 }}>
                          {s.vendor}/{s.product}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div style={{ padding: 10, color: C.gray500, fontSize: 12 }}>No hay suscripciones activas.</div>
                  )}
                </Card>
              )}
            </>}

            {/* ═══ USER MANAGEMENT ═══ */}
            {view === "user-mgmt" && <>
              <PageHeader title="Gestión de usuarios" />
              <Card
                title="Gestión de Usuarios"
                icon="users"
                action={(
                  <div style={{ display: "flex", gap: 8 }}>
                    <Btn small onClick={() => { setSubscriberTeamsRoute({ teamId: null }); setView("subscriber-teams"); }}>
                      Gestionar equipos
                    </Btn>
                    <Btn small primary onClick={() => openUserForm()}><I name="plus" size={14} /> Nuevo</Btn>
                  </div>
                )}
              >
                <div style={{ marginBottom: 14, fontSize: 12, color: C.gray600 }}>
                  {USER_MANAGEMENT_NOTE}
                </div>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead><tr style={{ background: C.gray50 }}>
                    {["Nombre", "Email", "Rol global", "Acceso", "Estado", "Último acceso", "Acciones"].map(h => (
                      <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${C.gray200}` }}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>{users.map(u => (
                    <tr key={u.id} className="rh">
                      <td style={{ padding: "8px 12px", fontWeight: 600, fontSize: 12 }}>{u.name}</td>
                      <td style={{ padding: "8px 12px", fontSize: 11, fontFamily: "monospace" }}>{u.email}</td>
                      <td style={{ padding: "8px 12px" }}><span style={{ padding: "2px 8px", borderRadius: 3, fontSize: 9, fontWeight: 700, background: u.role === "ADMIN" ? C.bluePale : C.gray100, color: u.role === "ADMIN" ? C.blue : C.gray600 }}>{getGlobalUserRoleLabel(u.role)}</span></td>
                      <td style={{ padding: "8px 12px", fontSize: 10 }}>
                        <span style={{ color: u.canLogin ? C.low : C.gray500, fontWeight: 700 }}>
                          {u.canLogin ? "Permitido" : "Sin acceso"}
                        </span>
                      </td>
                      <td style={{ padding: "8px 12px" }}><span style={{ color: u.isActive ? C.low : C.critical, fontWeight: 600, fontSize: 10 }}>{u.isActive ? "● Activo" : "○ Inactivo"}</span></td>
                      <td style={{ padding: "8px 12px", fontSize: 10, color: C.gray400 }}>{fmtDate(u.lastLoginAt)}</td>
                      <td style={{ padding: "8px 12px" }}>
                        <span style={{ cursor: "pointer", marginRight: 8 }} onClick={() => openUserForm(u)}><I name="edit" size={14} color={C.blue} /></span>
                        <span style={{ cursor: "pointer" }} onClick={() => deleteUser(u.id)}><I name="trash" size={14} color={C.critical} /></span>
                      </td>
                    </tr>
                  ))}</tbody>
                </table>
              </Card>
              {showUserForm && editUser && (
                <UserFormModal
                  user={editUser}
                  getTeamOptions={(index) => buildAssignableTeams(userMgmtTeams, editUser.teamAssignments || [], index)}
                  assignmentErrors={userTeamAssignmentErrors}
                  onClose={() => setShowUserForm(false)}
                  onSave={saveUser}
                  onFieldChange={updateUserField}
                  onAddAssignment={addUserTeamAssignment}
                  onUpdateAssignment={updateUserTeamAssignment}
                  onRemoveAssignment={removeUserTeamAssignment}
                  saveDisabled={Object.keys(userTeamAssignmentErrors).length > 0}
                  colors={C}
                  ButtonComponent={Btn}
                  InputComponent={Input}
                />
              )}
            </>}

            {view === "subscriber-teams" && (
              subscriberTeamsRoute.teamId
                ? (
                  <SubscriberTeamDetailPage
                    apiFetch={apiFetch}
                    currentUser={currentUser}
                    teamId={subscriberTeamsRoute.teamId}
                    onBack={() => setSubscriberTeamsRoute({ teamId: null })}
                  />
                )
                : (
                  <SubscriberTeamsPage
                    apiFetch={apiFetch}
                    currentUser={currentUser}
                    onOpenTeam={(teamId) => setSubscriberTeamsRoute({ teamId })}
                  />
                )
            )}

            {/* ═══ SETTINGS ═══ */}
            {view === "settings" && <>
              <PageHeader title="Configuración" />
              <TabBar tabs={[{ id: "smtp", label: "SMTP" }, { id: "notifications", label: "Notificaciones" }, { id: "ia", label: "IA" }, { id: "tags", label: "Etiquetas" }, { id: "api-keys", label: "API Keys" }]} active={settingsTab} onChange={setSettingsTab} />

              {/* SMTP Tab */}
              {settingsTab === "smtp" && <Card title="Configuración SMTP" icon="settings">
                {smtpLoading ? (
                  <div style={{ padding: 20, textAlign: "center", color: C.gray500 }}>Cargando configuración...</div>
                ) : (
                  <>
                    <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16, marginBottom: 16 }}>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Servidor SMTP (Host)</label>
                        <Input value={smtpConfig.host} onChange={v => setSmtpConfig({ ...smtpConfig, host: v })} placeholder="smtp.example.com" />
                      </div>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Puerto</label>
                        <Input value={smtpConfig.port} onChange={v => setSmtpConfig({ ...smtpConfig, port: v })} placeholder="587" />
                      </div>
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Usuario</label>
                        <Input value={smtpConfig.user} onChange={v => setSmtpConfig({ ...smtpConfig, user: v })} placeholder="user@example.com" />
                      </div>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Contraseña</label>
                        <Input value={smtpConfig.pass} onChange={v => setSmtpConfig({ ...smtpConfig, pass: v })} placeholder="••••••••" />
                      </div>
                    </div>
                    <div style={{ marginBottom: 16 }}>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Remitente (From)</label>
                      <Input value={smtpConfig.from} onChange={v => setSmtpConfig({ ...smtpConfig, from: v })} placeholder="noreply@example.com" />
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 20 }}>
                      <input type="checkbox" checked={smtpConfig.secure} onChange={e => setSmtpConfig({ ...smtpConfig, secure: e.target.checked })} id="secureCheck" />
                      <label htmlFor="secureCheck" style={{ fontSize: 12, color: C.text }}>Usar conexión segura (SSL/TLS)</label>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", borderTop: `1px solid ${C.gray100}`, paddingTop: 16 }}>
                      <div style={{ display: "flex", gap: 8 }}>
                        <Input value={testEmail} onChange={setTestEmail} placeholder="Email de prueba" style={{ width: 250 }} />
                        <Btn onClick={handleCreateTest} disabled={testSending || !testEmail}>{testSending ? "Enviando..." : "Probar"}</Btn>
                      </div>
                      <Btn primary onClick={handleSaveSmtp} disabled={smtpSaving}>{smtpSaving ? "Guardando..." : "Guardar Configuración"}</Btn>
                    </div>
                    {smtpMsg && (
                      <div className="fade" style={{ marginTop: 12, padding: "10px 12px", borderRadius: 4, fontSize: 12, fontWeight: 600, background: smtpMsg.type === "success" ? C.lowBg : C.criticalBg, color: smtpMsg.type === "success" ? C.low : C.critical, borderLeft: `3px solid ${smtpMsg.type === "success" ? C.low : C.critical}` }}>
                        {smtpMsg.text}
                      </div>
                    )}
                  </>
                )}
              </Card>}

              {settingsTab === "notifications" && <>
                <Card title="Centro de Notificaciones" icon="mail" style={{ marginBottom: 16 }}>
                  <TabBar tabs={NOTIFICATION_SETTINGS_TABS} active={notificationSettingsTab} onChange={setNotificationSettingsTab} />

                  {notificationCenterMsg && (
                    <div className="fade" style={{ marginBottom: 12, padding: "10px 12px", borderRadius: 6, fontSize: 12, fontWeight: 700, background: notificationCenterMsg.type === "success" ? C.lowBg : C.criticalBg, color: notificationCenterMsg.type === "success" ? C.low : C.critical }}>
                      {notificationCenterMsg.text}
                    </div>
                  )}

                  {notificationCenterLoading ? (
                    <div style={{ padding: 20, textAlign: "center", color: C.gray500 }}>Cargando configuración de notificaciones...</div>
                  ) : (
                    <>
                      {notificationSettingsTab === "general" && (
                        <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr 1fr", gap: 14 }}>
                          <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 10, padding: 14, background: C.gray50 }}>
                            <div style={{ fontSize: 12, fontWeight: 800, color: C.text, marginBottom: 10 }}>Gobierno del proceso</div>
                            <label style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                              <input type="checkbox" checked={!!notificationCenter.general.processEnabled} onChange={(e) => updateNotificationCenterSection("general", { processEnabled: e.target.checked })} />
                              <span style={{ fontSize: 12, fontWeight: 600 }}>Proceso de envío habilitado</span>
                            </label>
                            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                              <div>
                                <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Ventana dedupe (h)</label>
                                <Input value={String(notificationCenter.general.dedupeWindowHours || 24)} onChange={(v) => updateNotificationCenterSection("general", { dedupeWindowHours: Number(v) || 24 })} />
                              </div>
                              <div>
                                <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Template por defecto</label>
                                <select value={notificationCenter.general.activeTemplateKey || "normal_v2"} onChange={(e) => updateNotificationCenterSection("general", { activeTemplateKey: e.target.value })} style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff" }}>
                                  {(notificationCenter.templates.available || []).map((item) => <option key={item.key} value={item.key}>{item.name}</option>)}
                                </select>
                              </div>
                            </div>
                            <div style={{ marginTop: 10 }}>
                              <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Backoff de reintentos (min)</label>
                              <Input value={listToCsvString(notificationCenter.general.retryBackoffMinutes)} onChange={(v) => updateNotificationCenterSection("general", { retryBackoffMinutes: csvStringToList(v).map((item) => Number(item)).filter((item) => Number.isFinite(item) && item > 0) })} placeholder="5, 15, 30" />
                            </div>
                          </div>
                          <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 10, padding: 14 }}>
                            <div style={{ fontSize: 12, fontWeight: 800, color: C.text, marginBottom: 10 }}>Estado operativo</div>
                            <div style={{ fontSize: 12, color: C.gray600, lineHeight: 1.7 }}>
                              <div>SMTP: <strong>{notificationCenter.general.smtpConfigured ? "Configurado" : "Pendiente"}</strong></div>
                              <div>Última enviada: <strong>{fmtDate(notificationCenter.processHealth.lastSent?.sentAt)}</strong></div>
                              <div>Última fallida: <strong>{fmtDate(notificationCenter.processHealth.lastFailed?.sentAt)}</strong></div>
                              <div>Cola pendiente: <strong>{notificationCenter.processHealth.queuePending || 0}</strong></div>
                            </div>
                          </div>
                          <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 10, padding: 14 }}>
                            <div style={{ fontSize: 12, fontWeight: 800, color: C.text, marginBottom: 10 }}>Receptores</div>
                            <div style={{ fontSize: 12, color: C.gray600, lineHeight: 1.7 }}>
                              <div>Usuarios activos: <strong>{notificationCenter.recipients.totalUsers || 0}</strong></div>
                              <div>Con recepción activa: <strong>{notificationCenter.recipients.enabledRecipients || 0}</strong></div>
                              <div>En pausa: <strong>{notificationCenter.recipients.pausedRecipients || 0}</strong></div>
                            </div>
                          </div>
                        </div>
                      )}

                      {notificationSettingsTab === "immediate" && (
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.immediate.enabled} onChange={(e) => updateNotificationCenterSection("immediate", { enabled: e.target.checked })} /> <span style={{ fontSize: 12, fontWeight: 600 }}>Habilitada</span></label>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.immediate.kevOnly} onChange={(e) => updateNotificationCenterSection("immediate", { kevOnly: e.target.checked })} /> <span style={{ fontSize: 12 }}>Solo KEV</span></label>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.immediate.publicExploitOnly} onChange={(e) => updateNotificationCenterSection("immediate", { publicExploitOnly: e.target.checked })} /> <span style={{ fontSize: 12 }}>Solo exploit público</span></label>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.immediate.activeExploitationOnly} onChange={(e) => updateNotificationCenterSection("immediate", { activeExploitationOnly: e.target.checked })} /> <span style={{ fontSize: 12 }}>Solo explotación activa</span></label>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.immediate.patchUnconfirmedOnly} onChange={(e) => updateNotificationCenterSection("immediate", { patchUnconfirmedOnly: e.target.checked })} /> <span style={{ fontSize: 12 }}>Parche no confirmado</span></label>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.immediate.onlySubscribedSystems} onChange={(e) => updateNotificationCenterSection("immediate", { onlySubscribedSystems: e.target.checked })} /> <span style={{ fontSize: 12 }}>Solo sistemas suscritos</span></label>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.immediate.newVulnerabilityOnly} onChange={(e) => updateNotificationCenterSection("immediate", { newVulnerabilityOnly: e.target.checked })} /> <span style={{ fontSize: 12 }}>Solo vulnerabilidad nueva</span></label>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.immediate.onSeverityChange} onChange={(e) => updateNotificationCenterSection("immediate", { onSeverityChange: e.target.checked })} /> <span style={{ fontSize: 12 }}>Cambio de criticidad</span></label>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.immediate.onExploitChange} onChange={(e) => updateNotificationCenterSection("immediate", { onExploitChange: e.target.checked })} /> <span style={{ fontSize: 12 }}>Cambio de explotación</span></label>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.immediate.onPatchChange} onChange={(e) => updateNotificationCenterSection("immediate", { onPatchChange: e.target.checked })} /> <span style={{ fontSize: 12 }}>Cambio de patch status</span></label>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Severidad mínima</label><select value={notificationCenter.immediate.minSeverity || "HIGH"} onChange={(e) => updateNotificationCenterSection("immediate", { minSeverity: e.target.value })} style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff" }}><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>CVSS mínimo</label><Input value={String(notificationCenter.immediate.minCvss || 0)} onChange={(v) => updateNotificationCenterSection("immediate", { minCvss: Number(v) || 0 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>EPSS mínimo</label><Input value={String(notificationCenter.immediate.minEpss || 0)} onChange={(v) => updateNotificationCenterSection("immediate", { minEpss: Number(v) || 0 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Percentil EPSS mínimo</label><Input value={String(notificationCenter.immediate.minEpssPercentile || 0)} onChange={(v) => updateNotificationCenterSection("immediate", { minEpssPercentile: Number(v) || 0 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Confianza mínima</label><Input value={String(notificationCenter.immediate.minConfidence || 0)} onChange={(v) => updateNotificationCenterSection("immediate", { minConfidence: Number(v) || 0 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Mínimo de fuentes</label><Input value={String(notificationCenter.immediate.minSources || 1)} onChange={(v) => updateNotificationCenterSection("immediate", { minSources: Number(v) || 1 })} /></div>
                          <div style={{ gridColumn: "1 / -1" }}><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Fabricantes / productos / categorías / exclusiones</label><div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}><Input value={listToCsvString(notificationCenter.immediate.vendorFilters)} onChange={(v) => updateNotificationCenterSection("immediate", { vendorFilters: csvStringToList(v) })} placeholder="microsoft, vmware" /><Input value={listToCsvString(notificationCenter.immediate.productFilters)} onChange={(v) => updateNotificationCenterSection("immediate", { productFilters: csvStringToList(v) })} placeholder="exchange, esxi" /><Input value={listToCsvString(notificationCenter.immediate.categoryFilters)} onChange={(v) => updateNotificationCenterSection("immediate", { categoryFilters: csvStringToList(v) })} placeholder="rce, auth-bypass" /><Input value={listToCsvString(notificationCenter.immediate.exclusions)} onChange={(v) => updateNotificationCenterSection("immediate", { exclusions: csvStringToList(v) })} placeholder="cve-2026-1234" /></div></div>
                        </div>
                      )}

                      {notificationSettingsTab === "digest" && (
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.digest.enabled} onChange={(e) => updateNotificationCenterSection("digest", { enabled: e.target.checked })} /> <span style={{ fontSize: 12, fontWeight: 600 }}>Digest habilitado</span></label>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.digest.onlySubscribedSystems} onChange={(e) => updateNotificationCenterSection("digest", { onlySubscribedSystems: e.target.checked })} /> <span style={{ fontSize: 12 }}>Solo sistemas suscritos</span></label>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Frecuencia</label><select value={String(notificationCenter.digest.intervalHours || 12)} onChange={(e) => updateNotificationCenterSection("digest", { intervalHours: Number(e.target.value) || 12 })} style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff" }}>{DIGEST_INTERVAL_OPTIONS.map((hours) => <option key={hours} value={String(hours)}>{hours} horas</option>)}</select></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Severidad mínima</label><select value={notificationCenter.digest.minSeverity || "MEDIUM"} onChange={(e) => updateNotificationCenterSection("digest", { minSeverity: e.target.value })} style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff" }}><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>CVSS mínimo</label><Input value={String(notificationCenter.digest.minCvss || 0)} onChange={(v) => updateNotificationCenterSection("digest", { minCvss: Number(v) || 0 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>EPSS mínimo</label><Input value={String(notificationCenter.digest.minEpss || 0)} onChange={(v) => updateNotificationCenterSection("digest", { minEpss: Number(v) || 0 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Confianza mínima</label><Input value={String(notificationCenter.digest.minConfidence || 0)} onChange={(v) => updateNotificationCenterSection("digest", { minConfidence: Number(v) || 0 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Mínimo de fuentes</label><Input value={String(notificationCenter.digest.minSources || 1)} onChange={(v) => updateNotificationCenterSection("digest", { minSources: Number(v) || 1 })} /></div>
                          <div style={{ gridColumn: "1 / -1" }}><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Filtros y exclusiones</label><div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}><Input value={listToCsvString(notificationCenter.digest.vendorFilters)} onChange={(v) => updateNotificationCenterSection("digest", { vendorFilters: csvStringToList(v) })} placeholder="fabricantes" /><Input value={listToCsvString(notificationCenter.digest.productFilters)} onChange={(v) => updateNotificationCenterSection("digest", { productFilters: csvStringToList(v) })} placeholder="productos" /><Input value={listToCsvString(notificationCenter.digest.categoryFilters)} onChange={(v) => updateNotificationCenterSection("digest", { categoryFilters: csvStringToList(v) })} placeholder="categorías" /><Input value={listToCsvString(notificationCenter.digest.exclusions)} onChange={(v) => updateNotificationCenterSection("digest", { exclusions: csvStringToList(v) })} placeholder="exclusiones" /></div></div>
                        </div>
                      )}

                      {notificationSettingsTab === "intelligent" && (
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.intelligent.enabled} onChange={(e) => updateNotificationCenterSection("intelligent", { enabled: e.target.checked })} /> <span style={{ fontSize: 12, fontWeight: 600 }}>Evaluación inteligente habilitada</span></label>
                          <label style={{ display: "flex", alignItems: "center", gap: 8 }}><input type="checkbox" checked={!!notificationCenter.intelligent.onlyWhenFinding} onChange={(e) => updateNotificationCenterSection("intelligent", { onlyWhenFinding: e.target.checked })} /> <span style={{ fontSize: 12 }}>Solo si hay hallazgo relevante</span></label>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Hora diaria</label><Input value={String(notificationCenter.intelligent.evaluationHour || 8)} onChange={(v) => updateNotificationCenterSection("intelligent", { evaluationHour: Number(v) || 8 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Frecuencia análisis (h)</label><Input value={String(notificationCenter.intelligent.analysisFrequencyHours || 24)} onChange={(v) => updateNotificationCenterSection("intelligent", { analysisFrequencyHours: Number(v) || 24 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Ventana principal (h)</label><Input value={String(notificationCenter.intelligent.primaryWindowHours || 24)} onChange={(v) => updateNotificationCenterSection("intelligent", { primaryWindowHours: Number(v) || 24 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Contexto táctico (días)</label><Input value={String(notificationCenter.intelligent.recentContextDays || 7)} onChange={(v) => updateNotificationCenterSection("intelligent", { recentContextDays: Number(v) || 7 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Contexto histórico (días)</label><Input value={String(notificationCenter.intelligent.historicalContextDays || 60)} onChange={(v) => updateNotificationCenterSection("intelligent", { historicalContextDays: Number(v) || 60 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Confianza mínima</label><Input value={String(notificationCenter.intelligent.minConfidence || 0)} onChange={(v) => updateNotificationCenterSection("intelligent", { minConfidence: Number(v) || 0 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Relevancia mínima</label><Input value={String(notificationCenter.intelligent.minRelevanceScore || 0)} onChange={(v) => updateNotificationCenterSection("intelligent", { minRelevanceScore: Number(v) || 0 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Cooldown (h)</label><Input value={String(notificationCenter.intelligent.cooldownHours || 24)} onChange={(v) => updateNotificationCenterSection("intelligent", { cooldownHours: Number(v) || 24 })} /></div>
                          <div><label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Máx. por suscriptor/día</label><Input value={String(notificationCenter.intelligent.maxNotificationsPerSubscriberPerDay || 2)} onChange={(v) => updateNotificationCenterSection("intelligent", { maxNotificationsPerSubscriberPerDay: Number(v) || 2 })} /></div>
                          {[
                            ["attackPath", "Attack path plausible"],
                            ["campaignCluster", "Campaña o clúster"],
                            ["compoundRisk", "KEV + exploit + EPSS + riesgo"],
                            ["postureChange", "Cambio fuerte de postura"],
                          ].map(([key, label]) => (
                            <label key={key} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                              <input type="checkbox" checked={!!notificationCenter.intelligent.scenarioFlags?.[key]} onChange={(e) => updateNotificationCenterSection("intelligent", { scenarioFlags: { ...(notificationCenter.intelligent.scenarioFlags || {}), [key]: e.target.checked } })} />
                              <span style={{ fontSize: 12 }}>{label}</span>
                            </label>
                          ))}
                          <div style={{ gridColumn: "1 / -1", padding: "12px 14px", borderRadius: 10, background: C.gray50, border: `1px solid ${C.gray200}`, fontSize: 12, color: C.gray600, lineHeight: 1.6 }}>
                            Esta capa evalúa la ventana principal reciente, la contrasta contra contexto táctico de 7 días y contexto histórico de 60 días, y solo emite cuando detecta un hallazgo explicable, relevante y alineado con las suscripciones del destinatario.
                          </div>
                        </div>
                      )}

                      {notificationSettingsTab === "templates" && (
                        <>
                          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 16 }}>
                            {(notificationCenter.templates.available || []).map((item) => (
                              <div key={item.key} style={{ border: `1px solid ${C.gray200}`, borderRadius: 10, padding: 14, background: notificationCenter.general.activeTemplateKey === item.key ? C.bluePale : "#fff" }}>
                                <div style={{ fontSize: 13, fontWeight: 800, color: C.text, marginBottom: 4 }}>{item.name}</div>
                                <div style={{ fontSize: 11, color: C.gray600, lineHeight: 1.6 }}>{item.description}</div>
                                <div style={{ marginTop: 10 }}>
                                  <Btn small onClick={() => updateNotificationCenterSection("general", { activeTemplateKey: item.key })}>Usar por defecto</Btn>
                                </div>
                              </div>
                            ))}
                          </div>
                          <Card title="Editor de plantilla normal / compatibilidad" icon="mail">
                            {templateLoading ? (
                              <div style={{ padding: 20, textAlign: "center", color: C.gray500 }}>Cargando plantilla...</div>
                            ) : (
                              <>
                                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto auto", gap: 8, alignItems: "end", marginBottom: 12 }}>
                                  <div>
                                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 6 }}>Plantillas legacy guardadas</label>
                                    <select value={selectedTemplateId} onChange={e => loadTemplateById(e.target.value)} style={{ width: "100%", padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, background: "#fff" }}>
                                      <option value="">(Nueva plantilla)</option>
                                      {templateList.map(t => (
                                        <option key={t.id} value={String(t.id)}>{t.name}{t.isActive ? " (activa)" : ""}</option>
                                      ))}
                                    </select>
                                  </div>
                                  <div>
                                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 6 }}>Nombre de plantilla</label>
                                    <Input value={templateName} onChange={setTemplateName} placeholder="Ej: Digest premium" />
                                  </div>
                                  <Btn onClick={() => { setSelectedTemplateId(""); setTemplateName("Plantilla CVE"); setTemplateConfig({ headerImageUrl: "", introMessage: "La Oficina de Ciberseguridad Corporativa informa de nuevas vulnerabilidades relevantes para tus activos suscritos.", showExploitProbability: true, showExploitExists: true, showAffectedSoftware: true, showDescription: true, showReferences: true, showPatchLink: true }); }}>Nueva</Btn>
                                  <Btn onClick={activateTemplate} disabled={!selectedTemplateId}>Activar</Btn>
                                </div>
                                <div style={{ marginBottom: 12 }}>
                                  <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 6 }}>Encabezado (imagen)</label>
                                  <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                                    <input type="file" accept="image/*" onChange={e => onTemplateHeaderUpload(e.target.files?.[0])} style={{ fontSize: 12 }} />
                                    {templateConfig.headerImageUrl && <Btn small onClick={() => setTemplateConfig({ ...templateConfig, headerImageUrl: "" })}>Quitar imagen</Btn>}
                                  </div>
                                </div>
                                <div style={{ marginBottom: 12 }}>
                                  <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 6 }}>Mensaje inicial</label>
                                  <textarea value={templateConfig.introMessage} onChange={e => setTemplateConfig({ ...templateConfig, introMessage: e.target.value })} rows={5} style={{ width: "100%", padding: "10px 12px", fontSize: 12, border: `1px solid ${C.gray200}`, borderRadius: 6, resize: "vertical", fontFamily: "inherit", boxSizing: "border-box" }} />
                                </div>
                                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, marginBottom: 12 }}>
                                  {[
                                    ["showExploitProbability", "Posibilidad de explotación"],
                                    ["showExploitExists", "Existencia de exploit"],
                                    ["showAffectedSoftware", "Software afectado"],
                                    ["showDescription", "Descripción"],
                                    ["showReferences", "Referencias"],
                                    ["showPatchLink", "Enlace de parche"],
                                  ].map(([key, label]) => (
                                    <label key={key} style={{ fontSize: 12, color: C.gray700, display: "flex", alignItems: "center", gap: 6 }}>
                                      <input type="checkbox" checked={!!templateConfig[key]} onChange={e => setTemplateConfig({ ...templateConfig, [key]: e.target.checked })} />
                                      {label}
                                    </label>
                                  ))}
                                </div>
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "end", gap: 12 }}>
                                  <div style={{ flex: 1 }}>
                                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 6 }}>Vista previa con CVE</label>
                                    <select value={previewVulnId} onChange={e => setPreviewVulnId(e.target.value)} style={{ width: "100%", padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, background: "#fff" }}>
                                      <option value="">Selecciona un CVE...</option>
                                      {vulns.map(v => <option key={v.id} value={String(v.id)}>{v.cveId} ({v.cvssV31Severity || "N/A"})</option>)}
                                    </select>
                                  </div>
                                  <div style={{ display: "flex", gap: 8 }}>
                                    <Btn onClick={generateTemplatePreview} disabled={!previewVulnId || templatePreviewLoading}>{templatePreviewLoading ? "Generando..." : "Vista previa"}</Btn>
                                    <Btn primary onClick={saveTemplateConfig} disabled={templateSaving}>{templateSaving ? "Guardando..." : "Guardar plantilla"}</Btn>
                                  </div>
                                </div>
                                <div style={{ marginTop: 12, border: `1px solid ${C.gray200}`, borderRadius: 8, overflow: "hidden", background: "#fff" }}>
                                  {templatePreviewHtml ? <iframe title="Preview plantilla" srcDoc={templatePreviewHtml} style={{ width: "100%", height: 460, border: 0 }} /> : <div style={{ padding: 16, fontSize: 12, color: C.gray500 }}>Genera una vista previa para revisar la plantilla.</div>}
                                </div>
                              </>
                            )}
                          </Card>
                        </>
                      )}

                      {notificationSettingsTab === "recipients" && (
                        <div>
                          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 16 }}>
                            <Metric icon="users" label="Usuarios" value={notificationCenter.recipients.totalUsers || 0} color={C.navy} />
                            <Metric icon="mail" label="Activos" value={notificationCenter.recipients.enabledRecipients || 0} color={C.low} />
                            <Metric icon="clock" label="Pausados" value={notificationCenter.recipients.pausedRecipients || 0} color={C.high} />
                            <Metric icon="shield" label="Suscriptores" value={notificationCenter.recipients.subscribers || 0} color={C.blue} />
                          </div>
                          <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 10, overflow: "hidden" }}>
                            <table style={{ width: "100%", borderCollapse: "collapse" }}>
                              <thead><tr style={{ background: C.gray50 }}>
                                {["Usuario", "Rol", "Email notif.", "Recepción", "Pausa", "Último envío"].map(h => (
                                  <th key={h} style={{ padding: "9px 12px", textAlign: "left", fontSize: 9, fontWeight: 700, color: C.gray500, textTransform: "uppercase", borderBottom: `1px solid ${C.gray200}` }}>{h}</th>
                                ))}
                              </tr></thead>
                              <tbody>
                                {(users || []).map((user) => (
                                  <tr key={user.id}>
                                    <td style={{ padding: "8px 12px", fontSize: 12, fontWeight: 600 }}>{user.name}</td>
                                    <td style={{ padding: "8px 12px", fontSize: 11 }}>{user.role}</td>
                                    <td style={{ padding: "8px 12px", fontSize: 11 }}>{user.notificationEmail || user.email}</td>
                                    <td style={{ padding: "8px 12px", fontSize: 11 }}>{user.canReceiveNotifications ? "Activa" : "Desactivada"}</td>
                                    <td style={{ padding: "8px 12px", fontSize: 11 }}>{user.notificationsPaused ? `Hasta ${fmtDate(user.notificationsPausedUntil)}` : "No"}</td>
                                    <td style={{ padding: "8px 12px", fontSize: 11 }}>{fmtDate(user.lastNotificationSentAt)}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}

                      {notificationSettingsTab === "health" && (
                        <div>
                          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 16 }}>
                            <Metric icon="settings" label="Proceso" value={notificationCenter.processHealth.enabled ? "Activo" : "Pausado"} sub={notificationCenter.processHealth.smtpConfigured ? "SMTP configurado" : "SMTP pendiente"} color={notificationCenter.processHealth.enabled ? C.blue : C.gray500} />
                            <Metric icon="mail" label="Última enviada" value={fmtDate(notificationCenter.processHealth.lastSent?.sentAt)} color={C.low} />
                            <Metric icon="x" label="Última fallida" value={fmtDate(notificationCenter.processHealth.lastFailed?.sentAt)} color={C.critical} />
                            <Metric icon="activity" label="Reintentos" value={notificationCenter.processHealth.retries || 0} color={C.high} />
                          </div>
                          <div style={{ display: "grid", gridTemplateColumns: "1.25fr 1fr", gap: 16 }}>
                            <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 10, overflow: "hidden" }}>
                              <div style={{ padding: "12px 14px", borderBottom: `1px solid ${C.gray200}`, fontSize: 12, fontWeight: 800, color: C.text }}>Jobs y ejecución</div>
                              <div style={{ padding: 14, display: "grid", gap: 12 }}>
                                {[
                                  ["immediate", "immediate_notification_job"],
                                  ["digest", "digest_notification_job"],
                                  ["intelligent", "intelligent_notification_job"],
                                ].map(([labelKey, jobKey]) => {
                                  const job = notificationCenter.processHealth.jobs?.[labelKey] || {};
                                  return (
                                    <div key={jobKey} style={{ border: `1px solid ${C.gray200}`, borderRadius: 10, padding: 12, background: C.gray50 }}>
                                      <div style={{ display: "flex", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
                                        <div>
                                          <div style={{ fontSize: 13, fontWeight: 800, color: C.text }}>{NOTIFICATION_JOB_LABELS[labelKey]}</div>
                                          <div style={{ fontSize: 11, color: C.gray500 }}>Próxima ejecución: {job.nextExecution || "N/D"}</div>
                                        </div>
                                        <span style={{ padding: "3px 8px", borderRadius: 999, fontSize: 10, fontWeight: 800, background: job.status === "completed" ? C.lowBg : job.status === "failed" ? C.criticalBg : C.gray100, color: job.status === "completed" ? C.low : job.status === "failed" ? C.critical : C.gray600 }}>{toSentence(job.status || "idle")}</span>
                                      </div>
                                      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, fontSize: 11, color: C.gray600, marginBottom: 10 }}>
                                        <div>Enviadas: <strong>{job.notificationsSent || 0}</strong></div>
                                        <div>Fallidas: <strong>{job.notificationsFailed || 0}</strong></div>
                                        <div>Analizadas: <strong>{job.vulnerabilitiesConsidered || 0}</strong></div>
                                        <div>Cola: <strong>{job.queuePending || 0}</strong></div>
                                      </div>
                                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, fontSize: 11, color: C.gray600, marginBottom: 10 }}>
                                        <div>Último ciclo: <strong>{fmtDate(job.finishedAt || job.startedAt)}</strong></div>
                                        <div>Modo: <strong>{toSentence(job.mode || "manual")}</strong></div>
                                        <div>Última correcta: <strong>{fmtDate(job.lastSuccessfulAt)}</strong></div>
                                        <div>Última fallida: <strong>{fmtDate(job.lastFailedAt)}</strong></div>
                                        <div>Duración: <strong>{job.durationMs ? `${Math.round(job.durationMs / 1000)} s` : "N/D"}</strong></div>
                                        <div>Scheduler: <strong>{toSentence(job.schedulerStatus || "active")}</strong></div>
                                        <div style={{ gridColumn: "1 / -1" }}>
                                          Ventana: <strong>{job.watermarkFrom ? fmtDate(job.watermarkFrom) : "N/D"}</strong>
                                          {" → "}
                                          <strong>{job.watermarkTo ? fmtDate(job.watermarkTo) : "N/D"}</strong>
                                        </div>
                                        {labelKey === "intelligent" && (
                                          <>
                                            <div>Hallazgos: <strong>{job.findingsDetected || 0}</strong></div>
                                            <div>Suscriptores impactados: <strong>{job.impactedSubscribers || 0}</strong></div>
                                            <div>Suprimidas: <strong>{job.notificationsSuppressed || 0}</strong></div>
                                            <div>Próxima ejecución: <strong>{job.nextExecution ? fmtDate(job.nextExecution) : "N/D"}</strong></div>
                                          </>
                                        )}
                                      </div>
                                      {job.errorMessage && <div style={{ fontSize: 11, color: C.critical, marginBottom: 8 }}>{job.errorMessage}</div>}
                                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                                        <Btn small onClick={() => runNotificationJobNow(jobKey)} disabled={notificationProcessRunning === jobKey}>{notificationProcessRunning === jobKey ? "Ejecutando..." : "Ejecutar ahora"}</Btn>
                                        <Btn small onClick={() => sendNotificationProcessTest(jobKey)} disabled={notificationTestRunning === jobKey}>{notificationTestRunning === jobKey ? "Probando..." : "Probar"}</Btn>
                                      </div>
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                            <div style={{ display: "grid", gap: 16 }}>
                              <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 10, padding: 14 }}>
                                <div style={{ fontSize: 12, fontWeight: 800, color: C.text, marginBottom: 8 }}>Operación rápida</div>
                                <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Email de prueba</label>
                                <Input value={notificationOpsEmail} onChange={setNotificationOpsEmail} placeholder="operaciones@empresa.com" icon="mail" />
                              </div>
                              <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 10, padding: 14, background: intelligentTestOpen ? C.bluePale : "#fff" }}>
                                <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center", marginBottom: 10 }}>
                                  <div>
                                    <div style={{ fontSize: 12, fontWeight: 800, color: C.text }}>Test inteligente</div>
                                    <div style={{ fontSize: 11, color: C.gray600 }}>Dry run, preview o envío real a email de prueba</div>
                                  </div>
                                  <Btn small onClick={() => setIntelligentTestOpen((value) => !value)}>{intelligentTestOpen ? "Ocultar" : "Configurar"}</Btn>
                                </div>
                                {intelligentTestOpen && (
                                  <div style={{ display: "grid", gap: 10 }}>
                                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                                      <div>
                                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Suscriptor objetivo</label>
                                        <select value={intelligentTestForm.subscriberId} onChange={(e) => setIntelligentTestForm((prev) => ({ ...prev, subscriberId: e.target.value }))} style={{ width: "100%", padding: "10px 12px", fontSize: 12, border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff" }}>
                                          <option value="">Todos los receptores elegibles</option>
                                          {(users || []).filter((user) => user.canReceiveNotifications).map((user) => (
                                            <option key={user.id} value={String(user.id)}>{user.name} · {user.notificationEmail || user.email}</option>
                                          ))}
                                        </select>
                                      </div>
                                      <div>
                                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Modo</label>
                                        <select value={intelligentTestForm.mode} onChange={(e) => setIntelligentTestForm((prev) => ({ ...prev, mode: e.target.value }))} style={{ width: "100%", padding: "10px 12px", fontSize: 12, border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff" }}>
                                          <option value="dry_run">Dry run</option>
                                          <option value="preview">Preview</option>
                                          <option value="send_test">Enviar prueba</option>
                                        </select>
                                      </div>
                                      <div>
                                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Idioma</label>
                                        <select value={intelligentTestForm.language} onChange={(e) => setIntelligentTestForm((prev) => ({ ...prev, language: e.target.value }))} style={{ width: "100%", padding: "10px 12px", fontSize: 12, border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff" }}>
                                          <option value="es">Español</option>
                                          <option value="en">English</option>
                                        </select>
                                      </div>
                                      <div>
                                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Ventana principal (h)</label>
                                        <Input value={String(intelligentTestForm.primaryWindowHours || 24)} onChange={(v) => setIntelligentTestForm((prev) => ({ ...prev, primaryWindowHours: Number(v) || 24 }))} />
                                      </div>
                                      <div>
                                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Contexto táctico (días)</label>
                                        <Input value={String(intelligentTestForm.recentContextDays || 7)} onChange={(v) => setIntelligentTestForm((prev) => ({ ...prev, recentContextDays: Number(v) || 7 }))} />
                                      </div>
                                      <div>
                                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Contexto histórico (días)</label>
                                        <Input value={String(intelligentTestForm.historicalContextDays || 60)} onChange={(v) => setIntelligentTestForm((prev) => ({ ...prev, historicalContextDays: Number(v) || 60 }))} />
                                      </div>
                                    </div>
                                    <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: C.gray700 }}>
                                      <input type="checkbox" checked={!!intelligentTestForm.useRecentRealData} onChange={(e) => setIntelligentTestForm((prev) => ({ ...prev, useRecentRealData: e.target.checked }))} />
                                      Usar datos reales recientes
                                    </label>
                                    {intelligentTestForm.mode === "send_test" && (
                                      <div>
                                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Email destino de prueba</label>
                                        <Input value={intelligentTestForm.targetEmail} onChange={(v) => setIntelligentTestForm((prev) => ({ ...prev, targetEmail: v }))} placeholder="analista@empresa.com" icon="mail" />
                                      </div>
                                    )}
                                    <div style={{ display: "flex", justifyContent: "flex-end" }}>
                                      <Btn small primary onClick={executeIntelligentTest} disabled={notificationTestRunning === "intelligent_notification_job"}>
                                        {notificationTestRunning === "intelligent_notification_job" ? "Ejecutando..." : "Lanzar prueba inteligente"}
                                      </Btn>
                                    </div>
                                    {intelligentTestResult && (
                                      <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 10, background: "#fff", overflow: "hidden" }}>
                                        <div style={{ padding: "10px 12px", borderBottom: `1px solid ${C.gray200}`, fontSize: 12, fontWeight: 800, color: C.text }}>Resultado del test</div>
                                        <div style={{ padding: 12, display: "grid", gap: 10 }}>
                                          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, fontSize: 11, color: C.gray600 }}>
                                            <div>Hallazgos: <strong>{intelligentTestResult.findingsDetected || 0}</strong></div>
                                            <div>Impactados: <strong>{intelligentTestResult.impactedSubscribers || 0}</strong></div>
                                            <div>Enviadas: <strong>{intelligentTestResult.notificationsSent || 0}</strong></div>
                                            <div>Suprimidas: <strong>{intelligentTestResult.notificationsSuppressed || 0}</strong></div>
                                          </div>
                                          <div style={{ fontSize: 11, color: C.gray600 }}>
                                            <div>Asunto: <strong>{intelligentTestResult.previewPayload?.subject || "N/D"}</strong></div>
                                            <div>Idioma: <strong>{intelligentTestResult.previewPayload?.language || intelligentTestForm.language}</strong></div>
                                            <div>Plantilla: <strong>{intelligentTestResult.previewPayload?.templateKey || "intelligent"}</strong></div>
                                          </div>
                                          {intelligentTestResult.signalCoverage && (
                                            <div style={{ padding: "10px 12px", borderRadius: 8, background: C.gray50, fontSize: 11, color: C.gray700, lineHeight: 1.7 }}>
                                              <div style={{ fontWeight: 800, color: C.text, marginBottom: 4 }}>Cobertura de señales</div>
                                              <div>KEV: <strong>{intelligentTestResult.signalCoverage.kev || 0}</strong> · Exploit: <strong>{intelligentTestResult.signalCoverage.exploit || 0}</strong> · Sin parche: <strong>{intelligentTestResult.signalCoverage.unpatched || 0}</strong></div>
                                              <div>EPSS alto: <strong>{intelligentTestResult.signalCoverage.highEpss || 0}</strong> · CVSS alto: <strong>{intelligentTestResult.signalCoverage.highCvss || 0}</strong> · Concentración vendor/stack: <strong>{intelligentTestResult.signalCoverage.vendorConcentration || 0}</strong></div>
                                            </div>
                                          )}
                                          {(intelligentTestResult.findings || []).length > 0 && (
                                            <div style={{ display: "grid", gap: 8 }}>
                                              {(intelligentTestResult.findings || []).slice(0, 3).map((finding) => (
                                                <div key={finding.findingKey || finding.title} style={{ border: `1px solid ${C.gray200}`, borderRadius: 8, padding: 10, background: C.gray50 }}>
                                                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                                                    <div style={{ fontSize: 12, fontWeight: 800, color: C.text }}>{finding.title}</div>
                                                    <span style={{ fontSize: 10, fontWeight: 700, color: C.blue, background: C.bluePale, borderRadius: 999, padding: "3px 8px" }}>{toSentence(finding.type || "finding")}</span>
                                                  </div>
                                                  <div style={{ fontSize: 11, color: C.gray600, lineHeight: 1.6, marginTop: 4 }}>{finding.summary}</div>
                                                  <div style={{ fontSize: 11, color: C.gray600, marginTop: 6 }}>Confianza <strong>{Number(finding.confidence || 0).toFixed(2)}</strong> · Relevancia <strong>{Number(finding.relevanceScore || 0).toFixed(1)}</strong></div>
                                                  {!!(finding.recommendedActions || []).length && (
                                                    <div style={{ fontSize: 11, color: C.gray700, marginTop: 6 }}>
                                                      Acciones: <strong>{(finding.recommendedActions || []).slice(0, 2).join(" · ")}</strong>
                                                    </div>
                                                  )}
                                                  {!!(finding.affectedVulnerabilityIds || []).length && (
                                                    <div style={{ fontSize: 11, color: C.gray700, marginTop: 6 }}>
                                                      CVEs implicadas: <strong>{(finding.affectedVulnerabilityIds || []).length}</strong>
                                                    </div>
                                                  )}
                                                </div>
                                              ))}
                                            </div>
                                          )}
                                          {(intelligentTestResult.matches || []).length > 0 && (
                                            <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 8, overflow: "hidden" }}>
                                              <div style={{ padding: "8px 10px", borderBottom: `1px solid ${C.gray200}`, fontSize: 11, fontWeight: 800, color: C.text }}>Decisión por destinatario</div>
                                              <div style={{ display: "grid", gap: 0 }}>
                                                {(intelligentTestResult.matches || []).slice(0, 6).map((match, idx) => (
                                                  <div key={`${match.subscriberId}-${match.findingKey || idx}`} style={{ padding: "10px 12px", borderTop: idx === 0 ? "none" : `1px solid ${C.gray100}`, background: idx % 2 === 0 ? "#fff" : C.gray50 }}>
                                                    <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                                                      <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>
                                                        Suscriptor #{match.subscriberId} · {toSentence(match.matchLevel || "none")}
                                                      </div>
                                                      <div style={{ fontSize: 10, color: match.shouldNotify ? C.low : C.gray500, fontWeight: 700 }}>
                                                        {match.shouldNotify ? "Se enviaría" : `Suprimida${match.suppressionReason ? ` · ${toSentence(match.suppressionReason)}` : ""}`}
                                                      </div>
                                                    </div>
                                                    <div style={{ fontSize: 11, color: C.gray600, marginTop: 4 }}>
                                                      Match score <strong>{Number(match.matchScore || 0).toFixed(2)}</strong> · Delivery score <strong>{Number(match.deliveryScore || 0).toFixed(2)}</strong>
                                                    </div>
                                                    {!!(match.reasons || []).length && (
                                                      <div style={{ fontSize: 11, color: C.gray600, marginTop: 4, lineHeight: 1.6 }}>
                                                        {(match.reasons || []).slice(0, 3).join(" · ")}
                                                      </div>
                                                    )}
                                                  </div>
                                                ))}
                                              </div>
                                            </div>
                                          )}
                                          {intelligentTestResult.qualityAssessment && (
                                            <div style={{ padding: "10px 12px", borderRadius: 8, background: C.gray50, fontSize: 11, color: C.gray700, lineHeight: 1.7 }}>
                                              <div>Cobertura hallazgos: <strong>{intelligentTestResult.qualityAssessment.findingsDetected || 0}</strong></div>
                                              <div>Matching exact/family/contextual: <strong>{intelligentTestResult.qualityAssessment.matching?.exact || 0}</strong> / <strong>{intelligentTestResult.qualityAssessment.matching?.family || 0}</strong> / <strong>{intelligentTestResult.qualityAssessment.matching?.contextual || 0}</strong></div>
                                              <div>Suprimidas por score o política: <strong>{intelligentTestResult.qualityAssessment.matching?.suppressed || 0}</strong></div>
                                              <div>Valor estimado: <strong>{toSentence(intelligentTestResult.qualityAssessment.quality?.valueAssessment || "none")}</strong> · Hallazgos accionables: <strong>{intelligentTestResult.qualityAssessment.quality?.actionableFindings || 0}</strong> · Débiles: <strong>{intelligentTestResult.qualityAssessment.quality?.weakFindings || 0}</strong></div>
                                              {!!Object.keys(intelligentTestResult.qualityAssessment.suppressionReasons || {}).length && (
                                                <div>Motivos de supresión: <strong>{Object.entries(intelligentTestResult.qualityAssessment.suppressionReasons || {}).map(([key, value]) => `${toSentence(key)} ${value}`).join(" · ")}</strong></div>
                                              )}
                                            </div>
                                          )}
                                          {intelligentTestResult.previewPayload?.html && (
                                            <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 8, overflow: "hidden" }}>
                                              <iframe title="Preview inteligente" srcDoc={intelligentTestResult.previewPayload.html} style={{ width: "100%", height: 420, border: 0 }} />
                                            </div>
                                          )}
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                              <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 10, overflow: "hidden" }}>
                                <div style={{ padding: "12px 14px", borderBottom: `1px solid ${C.gray200}`, fontSize: 12, fontWeight: 800, color: C.text }}>Tests recientes</div>
                                <div style={{ maxHeight: 220, overflow: "auto" }}>
                                  {(intelligentTestHistory || []).length === 0 ? (
                                    <div style={{ padding: 14, fontSize: 12, color: C.gray500 }}>Sin pruebas inteligentes recientes.</div>
                                  ) : intelligentTestHistory.map((item) => (
                                    <div key={item.id} style={{ padding: "10px 12px", borderBottom: `1px solid ${C.gray100}` }}>
                                      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 4 }}>
                                        <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{toSentence(item.mode || "dry_run")} · {item.subscriber?.name || "Global"}</div>
                                        <div style={{ fontSize: 10, color: C.gray500 }}>{fmtDate(item.startedAt)}</div>
                                      </div>
                                      <div style={{ fontSize: 11, color: C.gray600 }}>Hallazgos {item.findingsDetected || 0} · Enviadas {item.notificationsSent || 0} · Suprimidas {item.notificationsSuppressed || 0}</div>
                                      <div style={{ fontSize: 11, color: item.status === "completed" ? C.low : C.critical }}>{item.status === "completed" ? "Completada" : `Fallida${item.errorMessage ? ` · ${item.errorMessage}` : ""}`}</div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                              <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 10, overflow: "hidden" }}>
                                <div style={{ padding: "12px 14px", borderBottom: `1px solid ${C.gray200}`, fontSize: 12, fontWeight: 800, color: C.text }}>Logs recientes</div>
                                <div style={{ maxHeight: 320, overflow: "auto" }}>
                                  {(notificationCenter.processHealth.recentLogs || []).length === 0 ? (
                                    <div style={{ padding: 14, fontSize: 12, color: C.gray500 }}>Sin logs recientes.</div>
                                  ) : (notificationCenter.processHealth.recentLogs || []).map((log) => (
                                    <div key={log.id} style={{ padding: "10px 12px", borderBottom: `1px solid ${C.gray100}` }}>
                                      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 4 }}>
                                        <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{log.subject}</div>
                                        <div style={{ fontSize: 10, color: C.gray500 }}>{fmtDate(log.sentAt)}</div>
                                      </div>
                                      <div style={{ fontSize: 11, color: C.gray600 }}>{toSentence(log.notificationType || "normal")} · {log.recipientEmail}</div>
                                      <div style={{ fontSize: 11, color: log.status === "sent" ? C.low : C.critical }}>{log.status === "sent" ? "Enviado" : `Fallo${log.errorMessage ? ` · ${log.errorMessage}` : ""}`}</div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      )}

                      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 16 }}>
                        <Btn primary onClick={saveNotificationCenterSettings} disabled={notificationCenterSaving}>
                          {notificationCenterSaving ? "Guardando..." : "Guardar configuración de notificaciones"}
                        </Btn>
                      </div>
                    </>
                  )}
                </Card>
              </>}

              {/* IA Tab */}
              {settingsTab === "ia" && <Card title="Configuración IA (Ollama)" icon="brain">
                {aiConfigLoading ? (
                  <div style={{ padding: 20, textAlign: "center", color: C.gray500 }}>Cargando configuración IA...</div>
                ) : (
                  <>
                    <div style={{ marginBottom: 12, background: C.gray50, border: `1px solid ${C.gray200}`, borderRadius: 6, padding: "10px 12px", fontSize: 11, color: C.gray600 }}>
                      Fuente actual: <strong>{aiConfig.source === "db" ? "Base de datos" : ".env"}</strong>. Si guardas aquí, pasará a usar configuración en base de datos.
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Proveedor</label>
                        <select
                          value={aiConfig.provider || "ollama"}
                          onChange={e => setAiConfig({ ...aiConfig, provider: e.target.value })}
                          style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff" }}
                        >
                          <option value="ollama">Ollama</option>
                        </select>
                      </div>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Base URL Ollama</label>
                        <Input value={aiConfig.baseUrl || ""} onChange={v => setAiConfig({ ...aiConfig, baseUrl: v })} placeholder="http://192.168.1.30:11434" />
                      </div>
                    </div>

                    <div style={{ marginBottom: 14 }}>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Modelo</label>
                      <select
                        value={aiConfig.model || ""}
                        onChange={e => setAiConfig({ ...aiConfig, model: e.target.value })}
                        style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff" }}
                      >
                        <option value="">Selecciona modelo...</option>
                        {[...new Set([DEFAULT_AI_MODEL, "sylink/sylink:8b", ...(aiModels || [])])].map(m => (
                          <option key={m} value={m}>{m}</option>
                        ))}
                      </select>
                      <div style={{ marginTop: 8 }}>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Modelo manual (opcional)</label>
                        <Input
                          value={aiConfig.model || ""}
                          onChange={v => setAiConfig({ ...aiConfig, model: v })}
                          placeholder={`Ej: ${DEFAULT_AI_MODEL} o sylink/sylink:8b`}
                        />
                      </div>
                      {(aiModels || []).length === 0 && (
                        <div style={{ fontSize: 11, color: C.gray500, marginTop: 6 }}>
                          No se pudieron listar modelos automáticamente. Puedes escribir el modelo manualmente en `.env` o revisar conectividad con Ollama.
                        </div>
                      )}
                    </div>

                    <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
                      <Btn onClick={refreshAiModels}>Recargar modelos</Btn>
                      <Btn onClick={() => loadData("settings")}>Recargar</Btn>
                      <Btn primary onClick={saveAiConfig} disabled={aiConfigSaving}>
                        {aiConfigSaving ? "Guardando..." : "Guardar Configuración IA"}
                      </Btn>
                    </div>
                  </>
                )}
              </Card>}

              {/* Tags Tab */}
              {settingsTab === "tags" && <Card title="Etiquetas de Vulnerabilidades" icon="edit">
                <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                  <Input value={newTagName} onChange={setNewTagName} placeholder="Nombre de etiqueta" style={{ flex: 1 }} />
                  <input type="color" value={newTagColor} onChange={e => setNewTagColor(e.target.value)} style={{ width: 40, height: 38, border: `1px solid ${C.gray200}`, borderRadius: 6, cursor: "pointer" }} />
                  <Btn primary onClick={addTag}><I name="plus" size={14} /> Añadir</Btn>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                  {tags.map(t => (
                    <div key={t.id} style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "6px 14px", borderRadius: 16, background: `${t.color}18`, border: `1px solid ${t.color}40`, fontSize: 12, fontWeight: 600, color: t.color }}>
                      <span style={{ width: 10, height: 10, borderRadius: "50%", background: t.color }} />
                      {t.name}
                      <span style={{ cursor: "pointer", marginLeft: 4, opacity: 0.6 }} onClick={() => deleteTag(t.id)}>×</span>
                    </div>
                  ))}
                  {tags.length === 0 && <div style={{ color: C.gray400, fontSize: 12, padding: 8 }}>No hay etiquetas. Añade una para empezar.</div>}
                </div>
              </Card>}

              {/* API Keys Tab */}
              {settingsTab === "api-keys" && <>
                <Card title="API Keys — Acceso para Aplicaciones Externas" icon="link" action={
                  <Btn primary onClick={() => { setShowApiKeyForm(true); setCreatedApiKey(null); setNewApiKeyName(""); setNewApiKeyExpiry(""); setNewApiKeyScopes(["vulnerabilities:read", "products:read", "catalog:read", "collector:read", "reports:read"]); }}>
                    <I name="plus" size={14} /> Nueva API Key
                  </Btn>
                }>
                  <div style={{ fontSize: 12, color: C.gray500, marginBottom: 16 }}>
                    Las API Keys permiten que aplicaciones externas (SIEMs, dashboards, scripts) accedan a los datos de la plataforma vía <code style={{ background: C.gray100, padding: "1px 6px", borderRadius: 4 }}>/api/v1/*</code> con el header <code style={{ background: C.gray100, padding: "1px 6px", borderRadius: 4 }}>X-API-Key</code>.
                  </div>

                  {apiKeysLoading ? (
                    <div style={{ textAlign: "center", padding: 24, color: C.gray400 }}>Cargando...</div>
                  ) : apiKeys.length === 0 ? (
                    <div style={{ textAlign: "center", padding: 24, color: C.gray400, fontSize: 13 }}>No hay API keys creadas. Crea una para empezar a consumir la API externa.</div>
                  ) : (
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                      <thead>
                        <tr style={{ borderBottom: `1px solid ${C.gray200}`, textAlign: "left" }}>
                          <th style={{ padding: "8px 12px", fontWeight: 700, color: C.gray600 }}>Nombre</th>
                          <th style={{ padding: "8px 12px", fontWeight: 700, color: C.gray600 }}>Prefijo</th>
                          <th style={{ padding: "8px 12px", fontWeight: 700, color: C.gray600 }}>Scopes</th>
                          <th style={{ padding: "8px 12px", fontWeight: 700, color: C.gray600 }}>Estado</th>
                          <th style={{ padding: "8px 12px", fontWeight: 700, color: C.gray600 }}>Último uso</th>
                          <th style={{ padding: "8px 12px", fontWeight: 700, color: C.gray600 }}>Expira</th>
                          <th style={{ padding: "8px 12px", fontWeight: 700, color: C.gray600 }}>Creado por</th>
                          <th style={{ padding: "8px 12px", fontWeight: 700, color: C.gray600 }}></th>
                        </tr>
                      </thead>
                      <tbody>
                        {apiKeys.map(k => {
                          const keyIsActive = k.isActive !== false;
                          return (
                          <tr key={k.id} style={{ borderBottom: `1px solid ${C.gray100}` }}>
                            <td style={{ padding: "10px 12px", fontWeight: 600, color: C.text }}>{k.name}</td>
                            <td style={{ padding: "10px 12px" }}>
                              <code style={{ background: C.gray100, padding: "2px 8px", borderRadius: 4, fontSize: 11, fontFamily: "monospace" }}>{k.keyPrefix}...</code>
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                                {(Array.isArray(k.scopes) ? k.scopes : []).map(s => (
                                  <span key={s} style={{ background: `${C.blue}15`, color: C.blue, padding: "2px 8px", borderRadius: 10, fontSize: 10, fontWeight: 600 }}>{s.split(":")[0]}</span>
                                ))}
                              </div>
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "3px 10px", borderRadius: 10, fontSize: 10, fontWeight: 700, background: keyIsActive ? `${C.low}18` : `${C.critical}18`, color: keyIsActive ? C.low : C.critical }}>
                                <span style={{ width: 6, height: 6, borderRadius: "50%", background: keyIsActive ? C.low : C.critical }} />
                                {keyIsActive ? "Activa" : "Revocada"}
                              </span>
                            </td>
                            <td style={{ padding: "10px 12px", color: C.gray500, fontSize: 11 }}>
                              {k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleDateString("es", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }) : "Nunca"}
                            </td>
                            <td style={{ padding: "10px 12px", color: C.gray500, fontSize: 11 }}>
                              {k.expiresAt ? new Date(k.expiresAt).toLocaleDateString("es", { day: "2-digit", month: "short", year: "numeric" }) : "—"}
                            </td>
                            <td style={{ padding: "10px 12px", color: C.gray500, fontSize: 11 }}>{k.user?.name || "—"}</td>
                            <td style={{ padding: "10px 12px" }}>
                              {keyIsActive && (
                                <Btn small danger onClick={async () => {
                                  if (!confirm("¿Revocar esta API key? Las aplicaciones que la usen dejarán de funcionar.")) return;
                                  try { await apiFetch(`/api-keys/${k.id}`, { method: "DELETE" }); setApiKeys(apiKeys.map(ak => ak.id === k.id ? { ...ak, isActive: false } : ak)); } catch (e) { console.error(e); }
                                }}>Revocar</Btn>
                              )}
                            </td>
                          </tr>
                        )})}
                      </tbody>
                    </table>
                  )}
                </Card>

                {/* Modal: Create API Key */}
                {showApiKeyForm && (
                  <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.5)", zIndex: 9999, display: "flex", alignItems: "center", justifyContent: "center" }} onClick={() => { if (!createdApiKey) setShowApiKeyForm(false); }}>
                    <div style={{ background: "#fff", borderRadius: 12, padding: 28, width: 520, maxHeight: "80vh", overflow: "auto", boxShadow: "0 20px 60px rgba(0,0,0,0.3)" }} onClick={e => e.stopPropagation()}>

                      {createdApiKey ? (
                        <>
                          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
                            <div style={{ width: 36, height: 36, borderRadius: "50%", background: `${C.low}18`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                              <I name="check" size={18} color={C.low} />
                            </div>
                            <div>
                              <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: C.text }}>API Key creada</h3>
                              <div style={{ fontSize: 11, color: C.gray500 }}>Copia la key ahora — no se mostrará de nuevo</div>
                            </div>
                          </div>

                          <div style={{ background: C.gray100, borderRadius: 8, padding: 14, marginBottom: 16, position: "relative" }}>
                            <div style={{ fontSize: 10, color: C.gray500, marginBottom: 4, fontWeight: 600 }}>API KEY</div>
                            <code style={{ fontSize: 13, fontFamily: "monospace", wordBreak: "break-all", color: C.navy, fontWeight: 700 }}>{createdApiKey.key}</code>
                            <Btn small style={{ position: "absolute", top: 10, right: 10 }} onClick={() => {
                              navigator.clipboard.writeText(createdApiKey.key);
                              setApiKeyCopied(true);
                              setTimeout(() => setApiKeyCopied(false), 2000);
                            }}>
                              {apiKeyCopied ? <><I name="check" size={12} /> Copiada</> : <><I name="link" size={12} /> Copiar</>}
                            </Btn>
                          </div>

                          <div style={{ background: `${C.high}10`, border: `1px solid ${C.high}30`, borderRadius: 8, padding: 12, marginBottom: 16, fontSize: 12, color: C.high, fontWeight: 600 }}>
                            <I name="alert" size={14} /> Guarda esta key de forma segura. No se puede recuperar después de cerrar este diálogo.
                          </div>

                          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
                            <div style={{ flex: 1 }}>
                              <div style={{ fontSize: 10, color: C.gray500, fontWeight: 600, marginBottom: 2 }}>Nombre</div>
                              <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{createdApiKey.name}</div>
                            </div>
                            <div style={{ flex: 1 }}>
                              <div style={{ fontSize: 10, color: C.gray500, fontWeight: 600, marginBottom: 2 }}>Expira</div>
                              <div style={{ fontSize: 13, color: C.text }}>{createdApiKey.expiresAt ? new Date(createdApiKey.expiresAt).toLocaleDateString("es") : "Nunca"}</div>
                            </div>
                          </div>

                          <div style={{ marginBottom: 16 }}>
                            <div style={{ fontSize: 10, color: C.gray500, fontWeight: 600, marginBottom: 4 }}>Scopes</div>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                              {(createdApiKey.scopes || []).map(s => (
                                <span key={s} style={{ background: `${C.blue}15`, color: C.blue, padding: "3px 10px", borderRadius: 10, fontSize: 11, fontWeight: 600 }}>{s}</span>
                              ))}
                            </div>
                          </div>

                          <div style={{ fontSize: 12, color: C.gray500, marginBottom: 16 }}>
                            <strong>Ejemplo de uso:</strong>
                            <pre style={{ background: C.gray100, borderRadius: 6, padding: 12, marginTop: 6, fontSize: 11, overflow: "auto", whiteSpace: "pre-wrap" }}>{`curl -H "X-API-Key: ${createdApiKey.key}" \\\n     "${window.location.origin}/api/v1/vulnerabilities?limit=5"`}</pre>
                          </div>

                          <div style={{ textAlign: "right" }}>
                            <Btn primary onClick={() => { setShowApiKeyForm(false); setCreatedApiKey(null); }}>Cerrar</Btn>
                          </div>
                        </>
                      ) : (
                        <>
                          <h3 style={{ margin: "0 0 16px", fontSize: 16, fontWeight: 800, color: C.text }}>
                            <I name="link" size={18} color={C.navy} /> Nueva API Key
                          </h3>

                          <div style={{ marginBottom: 14 }}>
                            <label style={{ display: "block", fontSize: 11, fontWeight: 700, color: C.gray600, marginBottom: 4 }}>Nombre *</label>
                            <Input value={newApiKeyName} onChange={setNewApiKeyName} placeholder="Ej: Dashboard SIEM, Script de auditoría" />
                          </div>

                          <div style={{ marginBottom: 14 }}>
                            <label style={{ display: "block", fontSize: 11, fontWeight: 700, color: C.gray600, marginBottom: 4 }}>Fecha de expiración (opcional)</label>
                            <input type="date" value={newApiKeyExpiry} onChange={e => setNewApiKeyExpiry(e.target.value)}
                              style={{ width: "100%", padding: "8px 12px", borderRadius: 6, border: `1px solid ${C.gray200}`, fontSize: 13, fontFamily: "inherit" }} />
                          </div>

                          <div style={{ marginBottom: 18 }}>
                            <label style={{ display: "block", fontSize: 11, fontWeight: 700, color: C.gray600, marginBottom: 8 }}>Permisos (scopes)</label>
                            {[
                              { id: "vulnerabilities:read", label: "Vulnerabilidades", desc: "CVEs, estadísticas, historial de cambios" },
                              { id: "products:read", label: "Productos y Activos", desc: "Assets, dependencias, impacto de vulns" },
                              { id: "catalog:read", label: "Catálogo", desc: "Fabricantes, tags, KEV, exploits" },
                              { id: "collector:read", label: "Collector", desc: "Ejecuciones, salud de fuentes" },
                              { id: "reports:read", label: "Reportes", desc: "Reportes generados" },
                            ].map(scope => (
                              <label key={scope.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", borderRadius: 6, cursor: "pointer", background: newApiKeyScopes.includes(scope.id) ? `${C.blue}08` : "transparent", border: `1px solid ${newApiKeyScopes.includes(scope.id) ? C.blue + "30" : C.gray200}`, marginBottom: 6, transition: "all 0.15s" }}>
                                <input type="checkbox" checked={newApiKeyScopes.includes(scope.id)} onChange={() => {
                                  setNewApiKeyScopes(prev => prev.includes(scope.id) ? prev.filter(s => s !== scope.id) : [...prev, scope.id]);
                                }} style={{ width: 16, height: 16, accentColor: C.blue }} />
                                <div style={{ flex: 1 }}>
                                  <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{scope.label}</div>
                                  <div style={{ fontSize: 11, color: C.gray500 }}>{scope.desc}</div>
                                </div>
                              </label>
                            ))}
                          </div>

                          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                            <Btn onClick={() => setShowApiKeyForm(false)}>Cancelar</Btn>
                            <Btn primary disabled={!newApiKeyName.trim() || newApiKeyScopes.length === 0 || apiKeyCreating} onClick={async () => {
                              setApiKeyCreating(true);
                              try {
                                const body = { name: newApiKeyName.trim(), scopes: newApiKeyScopes };
                                if (newApiKeyExpiry) body.expiresAt = new Date(newApiKeyExpiry).toISOString();
                                const r = await apiFetch("/api-keys", { method: "POST", body: JSON.stringify(body) });
                                const d = await r.json();
                                if (d.key) {
                                  setCreatedApiKey(d);
                                  setApiKeys(prev => [{ ...d, isActive: d.isActive !== false, user: { name: currentUser?.name } }, ...prev]);
                                }
                              } catch (e) { console.error(e); }
                              setApiKeyCreating(false);
                            }}>
                              {apiKeyCreating ? "Creando..." : "Crear API Key"}
                            </Btn>
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                )}
              </>}
            </>}

            {/* ═══ COLLECTOR ═══ */}
            {view === "collector" && <>
              <PageHeader title="Collector" />
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, marginBottom: 18 }}>
                <Metric icon="clock" label="Intervalo" value="30m" sub="*/30 * * * *" color={C.navy} />
                <Metric icon="server" label="Fuentes" value="7" sub="NVD · MITRE · KEV · EPSS · GitHub · ExploitDB · OSV" color={C.blue} />
                <Metric icon="check" label="Estado" value={dash.lastRun?.status || "-"} sub={timeAgo(dash.lastRun?.finishedAt) + " ago"} color={C.low} />
                <Metric icon="activity" label="Duración" value={fmtMs(dash.lastRun?.durationMs)} color={C.high} />
              </div>

              <Card title="Pipeline" icon="arrowRight" style={{ marginBottom: 16 }}>
                <div style={{ display: "flex", gap: 0, alignItems: "center" }}>
                  {[
                    { label: "NVD API", desc: "CVE + CVSS + CPE", color: C.blue, icon: "shield" },
                    { label: "MITRE CVE.org", desc: "Backup / Early detect", color: "#6366F1", icon: "globe" },
                    { label: "CISA KEV", desc: "Explotación activa", color: C.critical, icon: "zap" },
                    { label: "EPSS", desc: "Prob. explotación", color: C.high, icon: "activity" },
                    { label: "GitHub PoC", desc: "Exploits públicos", color: C.navy, icon: "bug" },
                    { label: "ExploitDB", desc: "Exploits curados", color: "#D97706", icon: "code" },
                    { label: "OSV Google", desc: "Open Source vulns", color: "#059669", icon: "package" },
                    { label: "MySQL", desc: "Persistencia", color: C.low, icon: "server" },
                  ].map((s, i, a) => (
                    <div key={s.label} style={{ display: "flex", alignItems: "center", flex: 1 }}>
                      <div style={{ flex: 1, padding: "12px 10px", background: `${s.color}10`, border: `1px solid ${s.color}25`, borderRadius: 6, textAlign: "center" }}>
                        <I name={s.icon} size={18} color={s.color} />
                        <div style={{ fontWeight: 700, fontSize: 10, color: s.color, marginTop: 4 }}>{s.label}</div>
                        <div style={{ fontSize: 8, color: C.gray500 }}>{s.desc}</div>
                      </div>
                      {i < a.length - 1 && <span style={{ color: C.gray300, padding: "0 3px", fontSize: 14 }}>→</span>}
                    </div>
                  ))}
                </div>
              </Card>

              <Card
                title="Restore NVD (Backfill 10 años)"
                icon="refresh"
                style={{ marginBottom: 16 }}
                action={(
                  <div style={{ display: "flex", gap: 8 }}>
                    <Btn small onClick={() => refreshBackfillStatus()} disabled={backfillBusy || !backfillJobId}>
                      <I name="refresh" size={12} /> Estado
                    </Btn>
                    <Btn small onClick={() => setStoredBackfillJobId("")} disabled={backfillBusy || !backfillJobId}>
                      Limpiar jobId
                    </Btn>
                  </div>
                )}
              >
                <div style={{ display: "grid", gridTemplateColumns: "1fr auto auto", gap: 8, alignItems: "center", marginBottom: 12 }}>
                  <Input
                    value={backfillJobId}
                    onChange={(v) => setStoredBackfillJobId(v)}
                    placeholder="jobId backfill (se guarda en este navegador)"
                    icon="clock"
                  />
                  <Btn primary onClick={startBackfill} disabled={backfillBusy}>
                    {backfillBusy ? "Procesando..." : "Iniciar/Reanudar"}
                  </Btn>
                  <Btn onClick={runBackfillToCompletion} disabled={backfillBusy || !backfillJobId}>
                    Ejecutar hasta completar
                  </Btn>
                </div>

                {backfillMsg && (
                  <div style={{
                    marginBottom: 10,
                    padding: "8px 10px",
                    borderRadius: 6,
                    fontSize: 12,
                    fontWeight: 600,
                    background: backfillMsg.type === "error" ? C.criticalBg : C.lowBg,
                    color: backfillMsg.type === "error" ? C.critical : C.low,
                    border: `1px solid ${backfillMsg.type === "error" ? "#fecaca" : "#bbf7d0"}`,
                  }}>
                    {backfillMsg.text}
                  </div>
                )}

                {backfillStatus?.job ? (
                  <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 6, overflow: "hidden" }}>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(6, minmax(0, 1fr))", gap: 0 }}>
                      <div style={{ padding: "10px 12px", borderRight: `1px solid ${C.gray100}` }}>
                        <div style={{ fontSize: 10, color: C.gray500, textTransform: "uppercase", fontWeight: 700 }}>Estado</div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{backfillStatus.job.status || "-"}</div>
                      </div>
                      <div style={{ padding: "10px 12px", borderRight: `1px solid ${C.gray100}` }}>
                        <div style={{ fontSize: 10, color: C.gray500, textTransform: "uppercase", fontWeight: 700 }}>Checkpoints</div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{backfillCheckpointDone} / {backfillCheckpointTotal}</div>
                        <div style={{ fontSize: 10, color: C.gray500 }}>
                          {Number(backfillCheckpointSummary.inProgress || backfillStatus?.checkpoints?.IN_PROGRESS || 0)} en curso · {Number(backfillCheckpointSummary.pending || backfillStatus?.checkpoints?.PENDING || 0)} pendientes
                        </div>
                      </div>
                      <div style={{ padding: "10px 12px", borderRight: `1px solid ${C.gray100}` }}>
                        <div style={{ fontSize: 10, color: C.gray500, textTransform: "uppercase", fontWeight: 700 }}>Requests NVD</div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{backfillRequestsProcessed}</div>
                        <div style={{ fontSize: 10, color: C.gray500 }}>Páginas / requests procesados</div>
                      </div>
                      <div style={{ padding: "10px 12px", borderRight: `1px solid ${C.gray100}` }}>
                        <div style={{ fontSize: 10, color: C.gray500, textTransform: "uppercase", fontWeight: 700 }}>Items recuperados</div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{backfillItemsFetched}</div>
                        <div style={{ fontSize: 10, color: C.gray500 }}>CVEs devueltos por NVD</div>
                      </div>
                      <div style={{ padding: "10px 12px", borderRight: `1px solid ${C.gray100}` }}>
                        <div style={{ fontSize: 10, color: C.gray500, textTransform: "uppercase", fontWeight: 700 }}>Escrituras en DB</div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{backfillInserted} insertados · {backfillUpdated} actualizados</div>
                        <div style={{ fontSize: 10, color: C.gray500 }}>Cambios persistidos</div>
                      </div>
                      <div style={{ padding: "10px 12px" }}>
                        <div style={{ fontSize: 10, color: C.gray500, textTransform: "uppercase", fontWeight: 700 }}>Sin cambios / Errores</div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: backfillErrors > 0 ? C.high : C.text }}>{backfillUnchanged} sin cambios · {backfillErrors} errores</div>
                        <div style={{ fontSize: 10, color: C.gray500 }}>Mucho histórico existente aparecerá aquí</div>
                      </div>
                    </div>
                    <div style={{ borderTop: `1px solid ${C.gray100}`, padding: "8px 12px", fontSize: 11, color: C.gray600, fontFamily: "monospace" }}>
                      jobId: {backfillStatus.job.jobId} · rango: {fmtDate(backfillStatus.job.fromTs)} → {fmtDate(backfillStatus.job.toTs)}
                    </div>
                    {backfillStatus?.latestError?.lastError && (
                      <div style={{ borderTop: `1px solid ${C.gray100}`, padding: "8px 12px", fontSize: 11, color: C.critical, background: C.criticalBg }}>
                        Último error checkpoint #{backfillStatus.latestError.id} (intentos: {backfillStatus.latestError.attempts}):
                        {" "}
                        {String(backfillStatus.latestError.lastError)}
                      </div>
                    )}
                  </div>
                ) : (
                  <div style={{ fontSize: 11, color: C.gray500 }}>No hay estado cargado. Inicia/reanuda un backfill o pega un `jobId` y pulsa `Estado`.</div>
                )}
              </Card>

              <Card title="Historial de ejecuciones" icon="clock" noPad>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead><tr style={{ background: C.gray50 }}>
                    {["#", "Inicio", "Fuente", "Estado", "Obtenidos", "Nuevos", "Duración"].map(h => (
                      <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${C.gray200}` }}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>{(Array.isArray(runs) ? runs : []).map(r => (
                    <tr key={r.id} className="rh">
                      <td style={{ padding: "8px 12px", fontFamily: "monospace", fontSize: 11, color: C.gray400 }}>#{r.id}</td>
                      <td style={{ padding: "8px 12px", fontSize: 10, fontFamily: "monospace" }}>{fmtDate(r.startedAt)}</td>
                      <td style={{ padding: "8px 12px" }}><span style={{ padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 600, background: r.source === "manual" ? C.bluePale : C.gray100, color: r.source === "manual" ? C.blue : C.gray600 }}>{r.source}</span></td>
                      <td style={{ padding: "8px 12px", color: r.status === "success" ? C.low : C.critical, fontWeight: 600, fontSize: 10 }}>{r.status === "success" ? "✓" : "✗"} {r.status}</td>
                      <td style={{ padding: "8px 12px", fontFamily: "monospace", fontSize: 11, fontWeight: 600 }}>{r.cvesFetched}</td>
                      <td style={{ padding: "8px 12px", fontFamily: "monospace", fontSize: 11, color: r.cvesNew > 0 ? C.low : C.gray400, fontWeight: r.cvesNew > 0 ? 700 : 400 }}>+{r.cvesNew}</td>
                      <td style={{ padding: "8px 12px", fontFamily: "monospace", fontSize: 11, color: C.gray400 }}>{fmtMs(r.durationMs)}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </Card>
            </>}

          </div>
        </main>
      </div>
    )
  );
}
