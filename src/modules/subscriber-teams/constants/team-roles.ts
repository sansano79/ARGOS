export const TEAM_ROLES = {
  MANAGER: 'TEAM_MANAGER',
  VIEWER: 'TEAM_VIEWER',
} as const;

export type TeamRole = (typeof TEAM_ROLES)[keyof typeof TEAM_ROLES];

export const ALL_TEAM_ROLES: TeamRole[] = [TEAM_ROLES.MANAGER, TEAM_ROLES.VIEWER];
