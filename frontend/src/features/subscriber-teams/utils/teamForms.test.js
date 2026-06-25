import test from "node:test";
import assert from "node:assert/strict";

import {
  buildRecipientPayload,
  buildSystemPayload,
  buildSystemUpdatePayload,
  buildTeamPayload,
  buildSubscriptionPayload,
  splitCsvList,
  validateRecipientForm,
  validateSystemForm,
  validateTeamForm,
} from "./teamForms.js";

test("team validation requires name and normalized code", () => {
  assert.deepEqual(validateTeamForm({ name: "", code: "" }), {
    name: "El nombre es obligatorio.",
    code: "El código es obligatorio.",
  });

  assert.deepEqual(validateTeamForm({ name: "IT España", code: "it es" }), {
    code: "Usa letras minúsculas, números, guiones o guiones bajos.",
  });
});

test("team payload trims and lowercases code", () => {
  assert.deepEqual(buildTeamPayload({
    name: " IT España ",
    code: " IT-ES ",
    description: " Equipo corporativo ",
    isActive: true,
  }), {
    name: "IT España",
    code: "it-es",
    description: "Equipo corporativo",
    isActive: true,
  });
});

test("recipient payload excludes verifiedAt and normalizes email", () => {
  const payload = buildRecipientPayload({
    email: " Vulnerabilidades-IT@example.local ",
    name: " IT España ",
    type: "MAILBOX",
    language: "es",
    timezone: "Europe/Madrid",
    isActive: true,
    verifiedAt: "2026-01-01T00:00:00.000Z",
  });

  assert.equal(payload.email, "vulnerabilidades-it@example.local");
  assert.equal("verifiedAt" in payload, false);
});

test("system payload emits healthStatus and tags, never rawData, and update payload omits source", () => {
  const createPayload = buildSystemPayload({
    name: " Servidor ERP España ",
    source: " manual ",
    hostname: " ERP01 ",
    fqdn: " ERP01.CORP.LOCAL ",
    healthStatus: " healthy ",
    tags: " erp, production ",
    rawData: "{\"debug\":true}",
  });

  assert.deepEqual(createPayload, {
    name: "Servidor ERP España",
    source: "manual",
    hostname: "erp01",
    fqdn: "erp01.corp.local",
    healthStatus: "healthy",
    tags: "erp, production",
    isSelected: true,
    isActive: true,
  });
  assert.equal("rawData" in createPayload, false);

  const updatePayload = buildSystemUpdatePayload({
    ...createPayload,
    source: "manual",
  });
  assert.equal("source" in updatePayload, false);
});

test("subscription payload parses versions as CSV and lowercases vendor and product", () => {
  assert.deepEqual(splitCsvList("2022, 2025, 2022"), ["2022", "2025"]);
  assert.deepEqual(buildSubscriptionPayload({
    vendor: " Microsoft ",
    product: " Windows Server ",
    versionsText: "2022, 2025",
    isActive: true,
  }), {
    vendor: "microsoft",
    product: "windows server",
    versions: ["2022", "2025"],
    isActive: true,
  });
});

test("recipient and system validation catch invalid values", () => {
  assert.deepEqual(validateRecipientForm({
    email: "no-valido",
    language: "",
    timezone: "",
    type: "ALIEN",
  }), {
    email: "Introduce un email válido.",
    type: "Selecciona un tipo de destinatario válido.",
    language: "El idioma es obligatorio.",
    timezone: "La zona horaria es obligatoria.",
  });

  assert.deepEqual(validateSystemForm({ name: "" }), {
    name: "El nombre es obligatorio.",
  });
});
