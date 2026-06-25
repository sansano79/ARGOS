import test from "node:test";
import assert from "node:assert/strict";

import {
  attachTeamStats,
  buildUserSelectOptions,
  filterAndSortTeams,
  parseJsonStringArray,
  summarizeTeamWorkspace,
  toErrorMessage,
} from "./teamViewModel.js";

test("workspace summary counts members, managers and active related records", () => {
  assert.deepEqual(summarizeTeamWorkspace({
    members: [
      { role: "TEAM_MANAGER", isActive: true },
      { role: "TEAM_VIEWER", isActive: true },
      { role: "TEAM_VIEWER", isActive: false },
    ],
    recipients: [{ isActive: true }, { isActive: false }],
    subscriptions: [{ isActive: true }],
    systems: [{ isActive: true }, { isActive: true }],
  }), {
    members: 3,
    activeMembers: 2,
    managers: 1,
    viewers: 1,
    recipients: 2,
    activeRecipients: 1,
    subscriptions: 1,
    activeSubscriptions: 1,
    systems: 2,
    activeSystems: 2,
  });
});

test("attachTeamStats and filterAndSortTeams enrich and filter by text and status", () => {
  const teams = attachTeamStats([
    { id: 2, name: "Redes", code: "redes", isActive: false, updatedAt: "2026-06-25T08:00:00.000Z" },
    { id: 1, name: "IT España", code: "it-es", isActive: true, updatedAt: "2026-06-25T10:00:00.000Z" },
  ], {
    1: { members: 3, recipients: 1, subscriptions: 2, systems: 4 },
    2: { members: 1, recipients: 0, subscriptions: 0, systems: 1 },
  });

  assert.equal(teams[0].stats.systems, 1);

  const filtered = filterAndSortTeams(teams, { query: "it", status: "active" });
  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].code, "it-es");
});

test("buildUserSelectOptions marks existing team members", () => {
  const options = buildUserSelectOptions(
    [
      { id: 2, name: "Laura", email: "laura@example.local", role: "ADMIN" },
      { id: 1, name: "Ana", email: "ana@example.local", role: "USER" },
    ],
    [
      { user: { id: 1 } },
    ],
  );

  assert.equal(options[0].name, "Ana");
  assert.equal(options[0].disabled, true);
  assert.equal(options[1].disabled, false);
});

test("parseJsonStringArray and error mapping handle backend payloads", () => {
  assert.deepEqual(parseJsonStringArray("[\"2022\",\"2025\"]"), ["2022", "2025"]);
  assert.deepEqual(parseJsonStringArray("lts, current"), ["lts", "current"]);
  assert.equal(toErrorMessage({ statusCode: 401 }), "La sesión ha caducado. Vuelve a iniciar sesión.");
  assert.equal(toErrorMessage({ statusCode: 403 }), "No tienes permisos para realizar esta acción.");
  assert.equal(toErrorMessage({ statusCode: 404 }), "El recurso solicitado ya no está disponible.");
  assert.equal(toErrorMessage({ statusCode: 409, message: "Código duplicado" }), "Código duplicado");
  assert.equal(toErrorMessage({ statusCode: 0 }), "Servicio no disponible. Comprueba la conexión.");
});

