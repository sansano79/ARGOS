import test from "node:test";
import assert from "node:assert/strict";

import {
  configToForm,
  exploitLabel,
  formToPayload,
  formatDuration,
  formatEpss,
  isRunPending,
  sortDevicesByRisk,
  splitList,
  summarizeDevices,
  validateConfigForm,
} from "./defenderViewModel.js";

test("splitList limpia, deduplica y descarta vacíos", () => {
  assert.deepEqual(splitList(" server, srv ,server,, "), ["server", "srv"]);
});

test("el formulario nunca rellena el secreto y solo lo envía si se escribe uno nuevo", () => {
  const form = configToForm({ tenantId: "t", hasClientSecret: true, serverTags: ["server"], teamId: 3 });
  assert.equal(form.clientSecret, "");
  assert.equal(form.teamId, "3");
  assert.equal("clientSecret" in formToPayload(form), false);
  assert.equal(formToPayload({ ...form, clientSecret: " nuevo " }).clientSecret, "nuevo");
});

test("formToPayload convierte listas y números", () => {
  const payload = formToPayload({ ...configToForm({}), serverTags: "server, prod-server", requestsPerMinute: "30" });
  assert.deepEqual(payload.serverTags, ["server", "prod-server"]);
  assert.equal(payload.requestsPerMinute, 30);
  assert.equal("teamId" in payload, false);
});

test("validación: GUIDs, filtros de servidor y ritmo de peticiones", () => {
  const errors = validateConfigForm({ ...configToForm({}), tenantId: "no-guid", serverTags: "", requestsPerMinute: "60" });
  assert.ok(errors.tenantId);
  assert.ok(errors.serverTags);
  assert.ok(errors.requestsPerMinute);
  assert.deepEqual(validateConfigForm(configToForm({})), {});
});

test("ordena servidores por KEV, exploit público, críticas y altas", () => {
  const sorted = sortDevicesByRisk([
    { name: "b", openFindings: { critical: 9 } },
    { name: "a", openFindings: { knownExploited: 1 } },
    { name: "c", openFindings: { publicExploit: 2 } },
  ]);
  assert.deepEqual(sorted.map((d) => d.name), ["a", "c", "b"]);
});

test("resumen del parque", () => {
  assert.deepEqual(
    summarizeDevices([
      { openFindings: { total: 10, knownExploited: 2, critical: 1 } },
      { openFindings: { total: 5 } },
    ]),
    { devices: 2, findings: 15, knownExploited: 2, critical: 1, devicesWithKev: 1 },
  );
});

test("detecta sincronizaciones pendientes", () => {
  assert.equal(isRunPending([{ status: "success" }, { status: "running" }]), true);
  assert.equal(isRunPending([{ status: "error" }]), false);
});

test("etiqueta de explotación prioriza KEV sobre Defender", () => {
  assert.equal(exploitLabel({ intelligence: { isKnownExploited: true }, exploitabilityLevel: "ExploitIsPublic" }), "KEV");
  assert.equal(exploitLabel({ exploitabilityLevel: "ExploitIsInKit" }), "En kit");
  assert.equal(exploitLabel({ intelligence: { hasPublicExploit: true } }), "Público");
  assert.equal(exploitLabel({}), "");
});

test("formatos", () => {
  assert.equal(formatDuration(65_000), "1 min 5 s");
  assert.equal(formatDuration(null), "—");
  assert.equal(formatEpss(0.1234), "12.3%");
  assert.equal(formatEpss(null), "—");
});
