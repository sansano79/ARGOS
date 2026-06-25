const trim = (value) => String(value || "").trim();
const normalizeRole = (value) => trim(value).toUpperCase();

const TEAM_ROLE_COMPATIBILITY_MATRIX = Object.freeze({
  ADMIN: ["TEAM_MANAGER", "TEAM_VIEWER"],
  TEAM_MANAGER: ["TEAM_MANAGER", "TEAM_VIEWER"],
  USER: ["TEAM_VIEWER"],
});

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

export const USER_MANAGEMENT_TEAM_NOTE = USER_MANAGEMENT_NOTE;

export const USER_TEAM_ASSIGNMENTS_NOTE =
  "La asignación inicial a equipos se gestiona aquí. Si envías esta sección, la operación usa reemplazo completo: las asignaciones no incluidas se desactivan.";

export const createDefaultTeamAssignment = () => ({
  teamId: "",
  role: "TEAM_VIEWER",
});

export const isVisibleUserGlobalRole = (value) => VISIBLE_USER_GLOBAL_ROLES.includes(normalizeRole(value));

export const normalizeGlobalUserRole = (value) => {
  const normalized = normalizeRole(value);
  return isVisibleUserGlobalRole(normalized) ? normalized : "USER";
};

export const getGlobalUserRoleLabel = (value) => {
  const normalized = normalizeRole(value);
  return USER_GLOBAL_ROLE_LABELS[normalized] || normalized || "Sin rol";
};

export const getAllowedTeamRolesForGlobalRole = (globalRole) => {
  const normalized = normalizeRole(globalRole);
  return TEAM_ROLE_COMPATIBILITY_MATRIX[normalized] || [];
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

export const getEffectiveGlobalRoleForTeamAssignments = (user = {}) => {
  if (user?.id && !user?.roleTouched) {
    return normalizeRole(user?.originalRole);
  }
  return normalizeRole(user?.role);
};

export const shouldValidateTeamAssignments = (user = {}) => {
  if (!user?.id) return true;
  return !!user?.teamAssignmentsTouched
    || !!user?.roleTouched
    || isVisibleUserGlobalRole(user?.originalRole);
};

export const getUserGlobalRoleOptions = (user = {}) => {
  const currentRole = normalizeRole(user?.role);
  const visibleOptions = [...USER_GLOBAL_ROLE_OPTIONS];

  if (!currentRole || isVisibleUserGlobalRole(currentRole)) {
    return visibleOptions;
  }

  return [
    {
      value: currentRole,
      label: `Rol legacy actual: ${getGlobalUserRoleLabel(currentRole)} (reservado)`,
      hidden: true,
    },
    ...visibleOptions,
  ];
};

export const getUserTeamRoleOptions = (user = {}, currentRole = "") => {
  const allowedRoles = getAllowedTeamRolesForGlobalRole(getEffectiveGlobalRoleForTeamAssignments(user));
  const normalizedCurrentRole = normalizeRole(currentRole);

  if (!normalizedCurrentRole || allowedRoles.includes(normalizedCurrentRole)) {
    return allowedRoles;
  }

  return [normalizedCurrentRole, ...allowedRoles];
};

export const buildUserFormState = (user = {}) => {
  const originalRole = normalizeRole(user.role);
  const role = originalRole || "USER";
  const memberships = Array.isArray(user.teamMemberships) ? user.teamMemberships : [];

  return {
    id: user.id || null,
    name: user.name || "",
    email: user.email || "",
    password: "",
    role,
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
  const currentRole = normalizeRole(user?.role);
  const normalizedRole = normalizeGlobalUserRole(currentRole);
  const shouldIncludeRole = !user?.id || !!user?.roleTouched || isVisibleUserGlobalRole(originalRole);
  if (shouldIncludeRole) {
    payload.role = normalizedRole;
  }

  const password = trim(user?.password);
  if (password) {
    payload.password = password;
  }

  const normalizedAssignments = normalizeTeamAssignments(user?.teamAssignments || []);
  const shouldSyncTeamAssignments = !user?.id
    ? normalizedAssignments.length > 0
    : !!user?.teamAssignmentsTouched;

  if (shouldSyncTeamAssignments) {
    payload.teamAssignments = normalizedAssignments;
  }

  return payload;
};
