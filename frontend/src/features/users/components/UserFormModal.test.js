import test from "node:test";
import assert from "node:assert/strict";
import { buildUserFormViewModel } from "./userFormViewModel.js";

const baseUser = {
  id: null,
  name: "Luis",
  email: "luis@example.local",
  password: "",
  role: "USER",
  originalRole: "",
  roleTouched: false,
  canLogin: true,
  isActive: true,
  teamAssignments: [],
  teamAssignmentsTouched: false,
};

const buildViewModel = (userOverrides = {}, extra = {}) => buildUserFormViewModel({
  user: { ...baseUser, ...userOverrides },
  getTeamOptions: () => [
    { value: "1", label: "IT Global · it-global", disabled: false },
    { value: "2", label: "Infraestructura · infra", disabled: false },
  ],
  assignmentErrors: {},
  ...extra,
});

test("real user modal view model removes legacy notification and subscriber controls", () => {
  const viewModel = buildViewModel();

  assert.deepEqual(viewModel.fields, [
    "Nombre",
    "Email",
    "Permitir inicio de sesión",
    "Rol global",
    "Contraseña",
    "Equipos asignados",
  ]);
  assert.equal(viewModel.fields.includes("Usuario suscriptor de alertas"), false);
  assert.equal(viewModel.fields.includes("Puede recibir notificaciones"), false);
  assert.equal(viewModel.fields.includes("Notificaciones en pausa"), false);
  assert.equal(viewModel.fields.includes("Pausa hasta"), false);
  assert.equal(viewModel.assignmentsTitle, "Equipos asignados");
});

test("real user modal view model shows only visible global roles for ordinary creation", () => {
  const viewModel = buildViewModel();

  assert.deepEqual(viewModel.roleOptions, [
    { value: "ADMIN", label: "Administrador de plataforma" },
    { value: "TEAM_MANAGER", label: "Gestor de equipo" },
    { value: "USER", label: "Usuario" },
  ]);
});

test("real user modal view model applies internal team role compatibility by global role", () => {
  const userView = buildViewModel({
    role: "USER",
    teamAssignments: [{ teamId: "1", role: "TEAM_VIEWER" }],
  });
  assert.deepEqual(userView.assignmentRows[0].teamRoleOptions, [
    { value: "TEAM_VIEWER", label: "Solo consulta" },
  ]);

  const managerView = buildViewModel({
    role: "TEAM_MANAGER",
    teamAssignments: [{ teamId: "1", role: "TEAM_MANAGER" }],
  });
  assert.deepEqual(managerView.assignmentRows[0].teamRoleOptions, [
    { value: "TEAM_MANAGER", label: "Gestor del equipo" },
    { value: "TEAM_VIEWER", label: "Solo consulta" },
  ]);

  const adminView = buildViewModel({
    role: "ADMIN",
    teamAssignments: [{ teamId: "1", role: "TEAM_MANAGER" }],
  });
  assert.deepEqual(adminView.assignmentRows[0].teamRoleOptions, [
    { value: "TEAM_MANAGER", label: "Gestor del equipo" },
    { value: "TEAM_VIEWER", label: "Solo consulta" },
  ]);
});

test("real user modal view model keeps legacy roles controlled without exposing them as ordinary options", () => {
  const viewModel = buildViewModel({
    id: 4,
    role: "SUBSCRIBER",
    originalRole: "SUBSCRIBER",
    teamAssignments: [{ teamId: "1", role: "TEAM_MANAGER" }],
  });

  assert.equal(viewModel.hiddenCurrentRole, true);
  assert.equal(viewModel.hiddenRoleMessage.includes("rol legacy reservado"), true);
  assert.deepEqual(viewModel.roleOptions, [
    { value: "SUBSCRIBER", label: "Rol legacy actual: Suscriptor (reservado)", hidden: true },
    { value: "ADMIN", label: "Administrador de plataforma" },
    { value: "TEAM_MANAGER", label: "Gestor de equipo" },
    { value: "USER", label: "Usuario" },
  ]);
  assert.equal(viewModel.canAddAssignments, false);
});
