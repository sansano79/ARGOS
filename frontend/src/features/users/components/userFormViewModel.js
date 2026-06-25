import {
  USER_MANAGEMENT_NOTE,
  USER_TEAM_ASSIGNMENTS_NOTE,
  getUserGlobalRoleOptions,
  getUserTeamRoleOptions,
  isVisibleUserGlobalRole,
} from "../../../utils/userManagement.js";

const getTeamRoleLabel = (teamRole) => (teamRole === "TEAM_MANAGER" ? "Gestor del equipo" : "Solo consulta");

export const buildUserFormViewModel = ({
  user,
  getTeamOptions = () => [],
  assignmentErrors = {},
}) => {
  if (!user) return null;

  return {
    title: user.id ? "Editar Usuario" : "Nuevo Usuario",
    note: USER_MANAGEMENT_NOTE,
    hiddenCurrentRole: !isVisibleUserGlobalRole(user.role),
    hiddenRoleMessage: "Este usuario tiene un rol legacy reservado. No se sustituirá automáticamente hasta que un administrador elija un rol global visible.",
    fields: ["Nombre", "Email", "Permitir inicio de sesión", "Rol global", "Contraseña", "Equipos asignados"],
    roleOptions: getUserGlobalRoleOptions(user),
    canAddAssignments: getUserTeamRoleOptions(user).length > 0,
    assignmentsTitle: "Equipos asignados",
    assignmentsNote: USER_TEAM_ASSIGNMENTS_NOTE,
    assignmentRows: (user.teamAssignments || []).map((assignment, index) => ({
      teamId: assignment.teamId || "",
      role: assignment.role || "TEAM_VIEWER",
      teamOptions: getTeamOptions(index),
      teamRoleOptions: getUserTeamRoleOptions(user, assignment.role).map((teamRole) => ({
        value: teamRole,
        label: getTeamRoleLabel(teamRole),
      })),
      error: assignmentErrors[index] || "",
    })),
  };
};
