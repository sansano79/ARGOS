import test from "node:test";
import assert from "node:assert/strict";

import { describePatchState, getPatchState, getRemediationEvidence } from "./remediation.js";

test("patch state is tri-state: unknown is never shown as 'no patch'", () => {
  assert.equal(getPatchState({ patchAvailable: true }), "available");
  assert.equal(getPatchState({ patchAvailable: null }), "unknown");
  assert.equal(getPatchState({}), "unknown");
  assert.equal(getPatchState({ patchAvailable: false }), "unavailable");
  assert.equal(describePatchState({ patchAvailable: null }), "Parche no confirmado");
});

test("patch state uses the backend status for workarounds and list rows without it", () => {
  assert.equal(getPatchState({ patchAvailable: null, patchStatus: "workaround_only" }), "workaround_only");
  assert.equal(getPatchState({ patchAvailable: null, remediationInfo: '{"patchStatus":"available"}' }), "available");
});

test("evidence rows explain the verdict, patch confirmations first", () => {
  const rows = getRemediationEvidence({
    evidence: [
      { source: "cisa_kev", kind: "kev_required_action", signal: "advisory", detail: "Apply mitigations per vendor instructions." },
      { source: "nvd", kind: "vendor_fix_advisory", signal: "patch", url: "https://me.sap.com/notes/3594142", detail: "SAP Security Note" },
      { source: "osv", kind: "fixed_version", signal: "patch", detail: "2.31.0" },
      { source: "nvd", kind: "patch_reference", signal: "patch", url: "javascript:alert(1)" },
    ],
  });

  assert.equal(rows.length, 4);
  assert.deepEqual(rows[0], {
    signal: "patch",
    signalLabel: "Confirma parche",
    sourceLabel: "NVD",
    kindLabel: "Boletín de corrección del fabricante · SAP Security Note",
    url: "https://me.sap.com/notes/3594142",
    text: null,
  });
  assert.equal(rows[1].text, "2.31.0");
  assert.equal(rows[2].url, null, "non-http URLs are never rendered as links");
  assert.equal(rows[3].sourceLabel, "CISA KEV");
  assert.deepEqual(getRemediationEvidence(null), []);
});
