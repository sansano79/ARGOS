// Patch availability is tri-state. `null` means "no source confirms it", which is not the same
// as "there is no patch" (only stated when a source says so explicitly, e.g. end-of-life).

const parseMaybeJson = (value) => {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
};

export const getPatchState = (vuln) => {
  const remediation = parseMaybeJson(vuln?.remediationInfo) || {};
  const status = String(vuln?.patchStatus || remediation.patchStatus || "").toLowerCase();
  if (vuln?.patchAvailable === true || status === "available") return "available";
  if (status === "workaround_only") return "workaround_only";
  if (vuln?.patchAvailable === false || status === "unavailable") return "unavailable";
  return "unknown";
};

export const PATCH_STATE_LABELS = {
  available: "Parche disponible",
  workaround_only: "Mitigación disponible · parche no confirmado",
  unavailable: "Sin parche (indicado por la fuente)",
  unknown: "Parche no confirmado",
};

export const describePatchState = (vuln) => PATCH_STATE_LABELS[getPatchState(vuln)];

const SOURCE_LABELS = {
  nvd: "NVD",
  cveorg: "CVE.org",
  cisa_kev: "CISA KEV",
  osv: "OSV",
};

const KIND_LABELS = {
  patch_reference: "Referencia etiquetada como parche",
  release_notes: "Notas de versión con la corrección",
  vendor_fix_advisory: "Boletín de corrección del fabricante",
  vendor_advisory: "Advisory del fabricante",
  mitigation_reference: "Guía de mitigación",
  fixed_version: "Versión corregida",
  vendor_solution: "Solución publicada por el fabricante",
  vendor_workaround: "Workaround del fabricante",
  kev_required_action: "Acción requerida por CISA",
  unsupported_product: "Producto sin soporte",
  legacy: "Parche indicado en una ingesta anterior",
};

const SIGNAL_LABELS = {
  patch: "Confirma parche",
  no_patch: "Indica que no hay parche",
  workaround: "Mitigación",
  advisory: "Informativo",
};

const SIGNAL_ORDER = { patch: 0, no_patch: 1, workaround: 2, advisory: 3 };

// Rows for the "why do we say this" list in the vulnerability detail.
export const getRemediationEvidence = (remediationInfo) => {
  const remediation = parseMaybeJson(remediationInfo) || {};
  const evidence = Array.isArray(remediation.evidence) ? remediation.evidence : [];
  return evidence
    .filter((item) => item && item.kind && item.signal)
    .map((item) => {
      const vendorDoc = item.kind === "vendor_fix_advisory" && item.detail ? ` · ${item.detail}` : "";
      return {
        signal: item.signal,
        signalLabel: SIGNAL_LABELS[item.signal] || item.signal,
        sourceLabel: SOURCE_LABELS[item.source] || String(item.source || "Fuente"),
        kindLabel: `${KIND_LABELS[item.kind] || item.kind}${vendorDoc}`,
        url: typeof item.url === "string" && /^https?:\/\//i.test(item.url) ? item.url : null,
        text: item.kind === "vendor_fix_advisory" ? null : item.detail || null,
      };
    })
    .sort((a, b) => (SIGNAL_ORDER[a.signal] ?? 9) - (SIGNAL_ORDER[b.signal] ?? 9));
};
