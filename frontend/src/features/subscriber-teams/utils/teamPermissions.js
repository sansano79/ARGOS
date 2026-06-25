const ADMIN_ROLE = "ADMIN";
const TEAM_MANAGER = "TEAM_MANAGER";
const TEAM_VIEWER = "TEAM_VIEWER";

const normalizeRole = (value) => String(value || "").trim().toUpperCase();

const readTeamRole = (team, explicitRole) =>
  normalizeRole(explicitRole || team?.role || team?.teamRole);

const readFlag = (team, key) => {
  if (!team || typeof team !== "object") return false;
  return team[key] === true;
};

export const isAdminRole = (globalRole) => normalizeRole(globalRole) === ADMIN_ROLE;

export const canAccessSubscriberTeamsAdmin = (globalRole) => isAdminRole(globalRole);

export const canViewTeam = ({ globalRole, team, teamRole, canRead } = {}) => (
  isAdminRole(globalRole)
  || canRead === true
  || readFlag(team, "canRead")
  || [TEAM_MANAGER, TEAM_VIEWER].includes(readTeamRole(team, teamRole))
);

export const canManageTeam = ({ globalRole } = {}) => isAdminRole(globalRole);

export const canManageMembers = ({ globalRole } = {}) => isAdminRole(globalRole);

export const canManageRecipients = ({ globalRole, team, teamRole } = {}) => (
  isAdminRole(globalRole)
  || readFlag(team, "canManageRecipients")
  || readTeamRole(team, teamRole) === TEAM_MANAGER
);

export const canManageSubscriptions = ({ globalRole, team, teamRole } = {}) => (
  isAdminRole(globalRole)
  || readFlag(team, "canManageSubscriptions")
  || readTeamRole(team, teamRole) === TEAM_MANAGER
);

export const canManageSystems = ({ globalRole, team, teamRole } = {}) => (
  isAdminRole(globalRole)
  || readFlag(team, "canManageSystems")
  || readTeamRole(team, teamRole) === TEAM_MANAGER
);

