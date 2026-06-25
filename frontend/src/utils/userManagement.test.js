import test from "node:test";
import assert from "node:assert/strict";
import {
  LEGACY_USER_FIELDS,
  USER_GLOBAL_ROLE_OPTIONS,
  USER_MANAGEMENT_FIELDS,
  USER_MANAGEMENT_NOTE,
  USER_MANAGEMENT_TEAM_NOTE,
  USER_TEAM_ASSIGNMENTS_NOTE,
  buildAssignableTeams,
  buildUserFormState,
  buildUserPayload,
  canAssignTeamRoleForGlobalRole,
  getAllowedTeamRolesForGlobalRole,
  getGlobalUserRoleLabel,
  getTeamRoleCompatibilityMessage,
  validateTeamAssignments,
} from "./userManagement.js";

test("user management fields keep ordinary forms free of legacy subscriber controls and include team assignments", () => {
  assert.deepEqual(USER_MANAGEMENT_FIELDS.create, ["name", "email", "canLogin", "role", "password", "teamAssignments"]);
  assert.deepEqual(USER_MANAGEMENT_FIELDS.edit, ["name", "email", "canLogin", "role", "password", "isActive", "teamAssignments"]);

  for (const field of LEGACY_USER_FIELDS) {
    assert.equal(USER_MANAGEMENT_FIELDS.create.includes(field), false);
    assert.equal(USER_MANAGEMENT_FIELDS.edit.includes(field), false);
  }
});

test("visible global role selector keeps ADMIN, TEAM_MANAGER and USER only", () => {
  assert.deepEqual(
    USER_GLOBAL_ROLE_OPTIONS,
    [
      { value: "ADMIN", label: "Administrador de plataforma" },
      { value: "TEAM_MANAGER", label: "Gestor de equipo" },
      { value: "USER", label: "Usuario" },
    ],
  );
});

test("buildUserFormState preserves legacy role internally and maps active team memberships", () => {
  const state = buildUserFormState({
    id: 9,
    name: "Legacy Subscriber",
    email: "legacy@example.local",
    role: "SUBSCRIBER",
    canLogin: false,
    isActive: true,
    teamMemberships: [
      { team: { id: 7 }, role: "TEAM_MANAGER", isActive: true },
      { team: { id: 8 }, role: "TEAM_VIEWER", isActive: false },
    ],
  });

  assert.deepEqual(state, {
    id: 9,
    name: "Legacy Subscriber",
    email: "legacy@example.local",
    password: "",
    role: "USER",
    originalRole: "SUBSCRIBER",
    roleTouched: false,
    canLogin: false,
    isActive: true,
    teamAssignments: [{ teamId: "7", role: "TEAM_MANAGER" }],
    teamAssignmentsTouched: false,
  });
});

test("team role compatibility follows provisional global authorization model", () => {
  assert.equal(canAssignTeamRoleForGlobalRole("ADMIN", "TEAM_MANAGER"), true);
  assert.equal(canAssignTeamRoleForGlobalRole("TEAM_MANAGER", "TEAM_MANAGER"), true);
  assert.equal(canAssignTeamRoleForGlobalRole("USER", "TEAM_MANAGER"), false);
  assert.deepEqual(getAllowedTeamRolesForGlobalRole("USER"), ["TEAM_VIEWER"]);
  assert.equal(
    getTeamRoleCompatibilityMessage("USER", "TEAM_MANAGER"),
    "Solo un Administrador de plataforma o un Gestor de equipo pueden recibir el rol interno Gestor del equipo.",
  );
});

test("team assignment helpers prevent duplicate teams and manual invalid ids", () => {
  assert.deepEqual(
    buildAssignableTeams(
      [{ id: 1, name: "IT Global", code: "it-global" }, { id: 2, name: "Infraestructura", code: "infra" }],
      [{ teamId: "1", role: "TEAM_MANAGER" }],
      0,
    ),
    [
      { value: "2", label: "Infraestructura · infra", disabled: false },
      { value: "1", label: "IT Global · it-global", disabled: false },
    ],
  );

  assert.deepEqual(validateTeamAssignments([
    { teamId: "", role: "TEAM_VIEWER" },
    { teamId: "3", role: "TEAM_MANAGER" },
    { teamId: "3", role: "TEAM_VIEWER" },
  ], "USER"), {
    0: "Selecciona un equipo válido.",
    1: "Solo un Administrador de plataforma o un Gestor de equipo pueden recibir el rol interno Gestor del equipo.",
    2: "Este equipo ya está asignado.",
  });
});

test("buildUserPayload for create sends only visible user fields plus explicit team assignments", () => {
  const payload = buildUserPayload({
    name: " Luis ",
    email: " luis@example.local ",
    canLogin: true,
    role: "TEAM_MANAGER",
    password: "ChangeMeNow!123",
    teamAssignments: [
      { teamId: "1", role: "TEAM_MANAGER" },
      { teamId: "2", role: "TEAM_VIEWER" },
    ],
  });

  assert.deepEqual(payload, {
    name: "Luis",
    email: "luis@example.local",
    canLogin: true,
    role: "TEAM_MANAGER",
    password: "ChangeMeNow!123",
    teamAssignments: [
      { teamId: 1, role: "TEAM_MANAGER" },
      { teamId: 2, role: "TEAM_VIEWER" },
    ],
  });

  for (const field of LEGACY_USER_FIELDS) {
    assert.equal(field in payload, false);
  }
});

test("buildUserPayload for hidden legacy roles preserves legacy backend data by omitting untouched role and memberships", () => {
  const payload = buildUserPayload({
    id: 15,
    name: "Ana",
    email: "ana@example.local",
    canLogin: true,
    role: "USER",
    originalRole: "SUBSCRIBER",
    roleTouched: false,
    isActive: false,
    teamAssignments: [{ teamId: "7", role: "TEAM_MANAGER" }],
    teamAssignmentsTouched: false,
  });

  assert.deepEqual(payload, {
    name: "Ana",
    email: "ana@example.local",
    canLogin: true,
    isActive: false,
  });
});

test("buildUserPayload for visible roles syncs full team assignment state during edit", () => {
  const payload = buildUserPayload({
    id: 21,
    name: "Luis",
    email: "luis@example.local",
    canLogin: true,
    role: "TEAM_MANAGER",
    originalRole: "TEAM_MANAGER",
    roleTouched: false,
    isActive: true,
    teamAssignments: [{ teamId: "2", role: "TEAM_VIEWER" }],
    teamAssignmentsTouched: false,
  });

  assert.deepEqual(payload, {
    name: "Luis",
    email: "luis@example.local",
    canLogin: true,
    isActive: true,
    role: "TEAM_MANAGER",
    teamAssignments: [{ teamId: 2, role: "TEAM_VIEWER" }],
  });
});

test("user management copy and role labels explain responsibility split", () => {
  assert.equal(USER_MANAGEMENT_NOTE, "Los accesos se gestionan desde Usuarios. Los destinatarios, suscripciones y sistemas se gestionan desde Equipos suscriptores.");
  assert.equal(USER_MANAGEMENT_TEAM_NOTE, "Las notificaciones y suscripciones se configuran en Equipos suscriptores.");
  assert.equal(USER_TEAM_ASSIGNMENTS_NOTE, "La asignación inicial a equipos se gestiona aquí. La operación usa reemplazo completo: las asignaciones no incluidas se desactivan.");
  assert.equal(getGlobalUserRoleLabel("ADMIN"), "Administrador de plataforma");
  assert.equal(getGlobalUserRoleLabel("TEAM_MANAGER"), "Gestor de equipo");
  assert.equal(getGlobalUserRoleLabel("USER"), "Usuario");
});
