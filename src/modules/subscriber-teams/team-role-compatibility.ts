import { BadRequestException } from '@nestjs/common';
import { TEAM_ROLES } from './constants/team-roles';

const normalizeRole = (value: string | undefined | null) => String(value || '').trim().toUpperCase();

export const canReceiveManagerTeamRole = (globalRole: string | undefined | null) => {
  const role = normalizeRole(globalRole);
  return role === 'ADMIN' || role === 'TEAM_MANAGER';
};

export const canReceiveViewerTeamRole = (_globalRole: string | undefined | null) => {
  return true;
};

export const canAssignTeamRoleForGlobalRole = (
  globalRole: string | undefined | null,
  teamRole: string | undefined | null,
) => {
  const normalizedTeamRole = normalizeRole(teamRole);

  if (normalizedTeamRole === TEAM_ROLES.MANAGER) {
    return canReceiveManagerTeamRole(globalRole);
  }
  if (normalizedTeamRole === TEAM_ROLES.VIEWER) {
    return canReceiveViewerTeamRole(globalRole);
  }
  return false;
};

export const assertTeamRoleCompatibility = (
  globalRole: string | undefined | null,
  teamRole: string | undefined | null,
) => {
  if (canAssignTeamRoleForGlobalRole(globalRole, teamRole)) {
    return;
  }

  if (normalizeRole(teamRole) === TEAM_ROLES.MANAGER) {
    throw new BadRequestException('Only ADMIN or TEAM_MANAGER users can be assigned as team managers');
  }

  throw new BadRequestException('Invalid team role assignment for the selected global role');
};
