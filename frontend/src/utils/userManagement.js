const trim = (value) => String(value || "").trim();
const normalizeRole = (value) => trim(value).toUpperCase();

export const VISIBLE_USER_GLOBAL_ROLES = ["ADMIN", "TEAM_MANAGER", "USER"];
export const USER_GLOBAL_ROLES = VISIBLE_USER_GLOBAL_ROLES;
export const USER_GLOBAL_ROLE_LABELS = {
  ADMIN: "Administrador de plataforma",
  TEAM_MANAGER: "Gestor de equipo",
  USER: "Usuario",
  VIEWER: "Viewer",
  SUBSCRIBER: "Suscriptor",
};

export const USER_GLOBAL_ROLE_OPTIONS = VISIBLE_USER_GLOBAL_ROLES.map((value) => ({
  value,
  label: USER_GLOBAL_ROLE_LABELS[value],
}));

export const USER_MANAGEMENT_FIELDS = {
  create: ["name", "email", "canLogin", "role", "password", "teamAssignments"],
  edit: ["name", "email", "canLogin", "role", "password", "isActive", "teamAssignments"],
};

export const LEGACY_USER_FIELDS = [
  "isSubscriber",
  "canReceiveNotifications",
  "notificationsPaused",
  "notificationsPausedUntil",
  "notificationEmail",
  "communicationLanguage",
  "subscriptions",
  "systems",
];

export const USER_MANAGEMENT_NOTE =
  "Los accesos se gestionan desde Usuarios. Los destinatarios, suscripciones y sistemas se gestionan desde Equipos suscriptores.";

export const USER_MANAGEMENT_TEAM_NOTE =
  "Las notificaciones y suscripciones se configuran en Equipos suscriptores.";

export const USER_TEAM_ASSIGNMENTS_NOTE =
  "La asignación inicial a equipos se gestiona aquí. La operación usa reemplazo completo: las asignaciones no incluidas se desactivan.";

export const createDefaultTeamAssignment = () => ({
  teamId: "",
  role: "TEAM_VIEWER",
});

export const normalizeGlobalUserRole = (value) => {
  const normalized = normalizeRole(value);
  return VISIBLE_USER_GLOBAL_ROLES.includes(normalized) ? normalized : "USER";
};

export const getGlobalUserRoleLabel = (value) => {
  const normalized = normalizeRole(value);
  return USER_GLOBAL_ROLE_LABELS[normalized] || normalized || "Sin rol";
};

export const getAllowedTeamRolesForGlobalRole = (globalRole) => {
  const normalized = normalizeRole(globalRole);
  if (normalized === "ADMIN" || normalized === "TEAM_MANAGER") {
    return ["TEAM_MANAGER", "TEAM_VIEWER"];
  }
  return ["TEAM_VIEWER"];
};

export const canAssignTeamRoleForGlobalRole = (globalRole, teamRole) =>
  getAllowedTeamRolesForGlobalRole(globalRole).includes(normalizeRole(teamRole));

export const getTeamRoleCompatibilityMessage = (globalRole, teamRole) => {
  if (canAssignTeamRoleForGlobalRole(globalRole, teamRole)) return "";
  if (normalizeRole(teamRole) === "TEAM_MANAGER") {
    return "Solo un Administrador de plataforma o un Gestor de equipo pueden recibir el rol interno Gestor del equipo.";
  }
  return "El rol interno seleccionado no es compatible con el rol global actual.";
};

export const buildAssignableTeams = (teams = [], assignments = [], currentIndex = -1) => {
  const takenTeamIds = new Set(
    assignments
      .filter((assignment, index) => index !== currentIndex)
      .map((assignment) => Number(assignment.teamId))
      .filter((teamId) => Number.isInteger(teamId) && teamId > 0),
  );

  return [...teams]
    .map((team) => ({
      value: String(team.id),
      label: `${team.name} · ${team.code}`,
      disabled: takenTeamIds.has(Number(team.id)),
    }))
    .sort((left, right) => left.label.localeCompare(right.label, "es", { sensitivity: "base" }));
};

export const normalizeTeamAssignments = (assignments = []) => {
  const seen = new Set();
  const normalized = [];

  for (const assignment of assignments) {
    const teamId = Number(assignment?.teamId);
    const role = normalizeRole(assignment?.role || "TEAM_VIEWER");
    if (!Number.isInteger(teamId) || teamId <= 0) continue;
    if (seen.has(teamId)) continue;
    seen.add(teamId);
    normalized.push({ teamId, role });
  }

  return normalized;
};

export const validateTeamAssignments = (assignments = [], globalRole = "USER") => {
  const errors = {};
  const seen = new Set();

  assignments.forEach((assignment, index) => {
    const teamId = Number(assignment?.teamId);
    const role = normalizeRole(assignment?.role);

    if (!Number.isInteger(teamId) || teamId <= 0) {
      errors[index] = "Selecciona un equipo válido.";
      return;
    }
    if (seen.has(teamId)) {
      errors[index] = "Este equipo ya está asignado.";
      return;
    }
    seen.add(teamId);
    if (!canAssignTeamRoleForGlobalRole(globalRole, role)) {
      errors[index] = getTeamRoleCompatibilityMessage(globalRole, role);
    }
  });

  return errors;
};

export const buildUserFormState = (user = {}) => {
  const originalRole = normalizeRole(user.role);
  const memberships = Array.isArray(user.teamMemberships) ? user.teamMemberships : [];

  return {
    id: user.id || null,
    name: user.name || "",
    email: user.email || "",
    password: "",
    role: normalizeGlobalUserRole(originalRole),
    originalRole,
    roleTouched: false,
    canLogin: user.canLogin !== false,
    isActive: user.isActive !== false,
    teamAssignments: memberships
      .filter((membership) => membership?.isActive !== false && membership?.team?.id)
      .map((membership) => ({
        teamId: String(membership.team.id),
        role: normalizeRole(membership.role || "TEAM_VIEWER"),
      })),
    teamAssignmentsTouched: false,
  };
};

export const buildUserPayload = (user) => {
  const payload = {
    name: trim(user?.name),
    email: trim(user?.email),
    canLogin: !!user?.canLogin,
  };

  if (user?.id) {
    payload.isActive = user.isActive !== false;
  }

  const originalRole = normalizeRole(user?.originalRole);
  const normalizedRole = normalizeGlobalUserRole(user?.role);
  const shouldIncludeRole = !user?.id || user?.roleTouched || VISIBLE_USER_GLOBAL_ROLES.includes(originalRole);
  if (shouldIncludeRole) {
    payload.role = normalizedRole;
  }

  const password = trim(user?.password);
  if (password) {
    payload.password = password;
  }

  const shouldSyncTeamAssignments = !user?.id
    ? Array.isArray(user?.teamAssignments) && user.teamAssignments.length > 0
    : (
      !!user?.teamAssignmentsTouched
      || VISIBLE_USER_GLOBAL_ROLES.includes(originalRole)
      || (!!user?.roleTouched && VISIBLE_USER_GLOBAL_ROLES.includes(normalizedRole))
    );

  if (shouldSyncTeamAssignments) {
    payload.teamAssignments = normalizeTeamAssignments(user?.teamAssignments || []);
  }

  return payload;
};
