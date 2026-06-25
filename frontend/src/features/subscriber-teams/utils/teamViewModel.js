import {
  TEAM_ROLE_OPTIONS,
  RECIPIENT_TYPE_OPTIONS,
} from "./teamForms.js";

const compareText = (left, right) => String(left || "").localeCompare(String(right || ""), "es", { sensitivity: "base" });
const compareDateDesc = (left, right) => {
  const a = left ? new Date(left).getTime() : 0;
  const b = right ? new Date(right).getTime() : 0;
  return b - a;
};

export const formatDateTime = (value) => (
  value
    ? new Date(value).toLocaleString("es-ES", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    })
    : "-"
);

export const getTeamRoleLabel = (value) => (
  TEAM_ROLE_OPTIONS.find((option) => option.value === value)?.label || value || "Sin rol"
);

export const getRecipientTypeLabel = (value) => (
  RECIPIENT_TYPE_OPTIONS.find((option) => option.value === value)?.label || value || "Sin tipo"
);

export const parseJsonStringArray = (value) => {
  if (Array.isArray(value)) return value.filter(Boolean);
  if (!value) return [];
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed.filter(Boolean) : [];
    } catch {
      return value.split(",").map((item) => item.trim()).filter(Boolean);
    }
  }
  return [];
};

export const summarizeTeamWorkspace = ({ members = [], recipients = [], subscriptions = [], systems = [] } = {}) => {
  const activeMembers = members.filter((member) => member?.isActive !== false);
  const activeRecipients = recipients.filter((recipient) => recipient?.isActive !== false);
  const activeSubscriptions = subscriptions.filter((subscription) => subscription?.isActive !== false);
  const activeSystems = systems.filter((system) => system?.isActive !== false);

  return {
    members: members.length,
    activeMembers: activeMembers.length,
    managers: activeMembers.filter((member) => member?.role === "TEAM_MANAGER").length,
    viewers: activeMembers.filter((member) => member?.role === "TEAM_VIEWER").length,
    recipients: recipients.length,
    activeRecipients: activeRecipients.length,
    subscriptions: subscriptions.length,
    activeSubscriptions: activeSubscriptions.length,
    systems: systems.length,
    activeSystems: activeSystems.length,
  };
};

export const attachTeamStats = (teams = [], statsById = {}) => teams.map((team, index) => {
  const stats = statsById[team.id] || {};
  return {
    ...team,
    stats: {
      members: Number(stats.members ?? team?._count?.members ?? 0),
      recipients: Number(stats.recipients ?? 0),
      subscriptions: Number(stats.subscriptions ?? 0),
      systems: Number(stats.systems ?? 0),
      managers: Number(stats.managers ?? 0),
      viewers: Number(stats.viewers ?? 0),
    },
    _sortIndex: index,
  };
});

export const filterAndSortTeams = (teams = [], { query = "", status = "all" } = {}) => {
  const normalizedQuery = String(query || "").trim().toLowerCase();

  return teams
    .filter((team) => {
      if (status === "active" && team?.isActive === false) return false;
      if (status === "inactive" && team?.isActive !== false) return false;
      if (!normalizedQuery) return true;
      const haystack = [team?.name, team?.code]
        .map((value) => String(value || "").toLowerCase())
        .join(" ");
      return haystack.includes(normalizedQuery);
    })
    .sort((left, right) => (
      compareText(left?.name, right?.name)
      || compareText(left?.code, right?.code)
      || compareDateDesc(left?.updatedAt, right?.updatedAt)
      || Number(left?._sortIndex || 0) - Number(right?._sortIndex || 0)
    ));
};

export const buildUserSelectOptions = (users = [], members = []) => {
  const memberIds = new Set(
    members
      .filter((member) => member?.user?.id)
      .map((member) => Number(member.user.id)),
  );

  return [...users]
    .map((user) => ({
      id: Number(user.id),
      name: user.name || user.email || `Usuario ${user.id}`,
      email: user.email || "",
      globalRole: user.role || "USER",
      disabled: memberIds.has(Number(user.id)),
    }))
    .sort((left, right) => compareText(left.name, right.name) || compareText(left.email, right.email));
};

export const toErrorMessage = (error, fallback = "No se pudo completar la operación.") => {
  const statusCode = Number(error?.statusCode || error?.status || 0);
  if (statusCode === 400) return "Revisa los campos del formulario.";
  if (statusCode === 401) return "La sesión ha caducado. Vuelve a iniciar sesión.";
  if (statusCode === 403) return "No tienes permisos para realizar esta acción.";
  if (statusCode === 404) return "El recurso solicitado ya no está disponible.";
  if (statusCode === 409) return error?.message || "Ya existe un registro con esos datos.";
  if (statusCode >= 500) return "Se ha producido un error interno.";
  if (statusCode === 0) return "Servicio no disponible. Comprueba la conexión.";
  return error?.message || fallback;
};
