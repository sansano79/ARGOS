import { Injectable, ForbiddenException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { TEAM_ROLES } from './constants/team-roles';

function normalizeRole(value: string | undefined | null) {
  return String(value || '').trim().toUpperCase();
}

function resolveUserContext(userOrId: number | { id: number; role?: string }, role?: string) {
  if (typeof userOrId === 'number') {
    return { id: userOrId, role: role ? normalizeRole(role) : '' };
  }
  return {
    id: Number(userOrId?.id || 0),
    role: normalizeRole(role || userOrId?.role),
  };
}

function computePermissions(teamRole: string, globalRole?: string) {
  const canManage = teamRole === TEAM_ROLES.MANAGER
    && (!globalRole || globalRole === 'ADMIN' || globalRole === 'TEAM_MANAGER');
  return {
    canRead: true,
    canManageMembers: canManage,
    canManageSubscriptions: canManage,
    canManageSystems: canManage,
    canManageRecipients: canManage,
  };
}

@Injectable()
export class TeamAccessService {
  constructor(private readonly prisma: PrismaService) {}

  assertAdmin(user: { role: string }): void {
    if (user.role !== 'ADMIN') {
      throw new ForbiddenException('Admin access required');
    }
  }

  async assertTeamReadable(userOrId: number | { id: number; role?: string }, teamId: number): Promise<void> {
    const user = resolveUserContext(userOrId);
    if (user.role === 'ADMIN') {
      return;
    }
    const member = await this.prisma.teamMember.findFirst({
      where: { teamId, userId: user.id, isActive: true, team: { isActive: true } },
      select: { role: true },
    });
    if (!member) {
      throw new NotFoundException(`Team ${teamId} not found`);
    }
  }

  async assertTeamWritable(userOrId: number | { id: number; role?: string }, teamId: number): Promise<void> {
    const user = resolveUserContext(userOrId);
    if (user.role === 'ADMIN') {
      return;
    }
    const member = await this.prisma.teamMember.findFirst({
      where: { teamId, userId: user.id, isActive: true, team: { isActive: true } },
      select: { role: true },
    });
    if (!member) {
      throw new NotFoundException(`Team ${teamId} not found`);
    }
    if (user.role && user.role !== 'TEAM_MANAGER') {
      throw new ForbiddenException('Global team manager role required');
    }
    if (member.role !== TEAM_ROLES.MANAGER) {
      throw new ForbiddenException('Team manager access required');
    }
  }

  async getAccessibleTeams(userOrId: number | { id: number; role?: string }, role?: string) {
    const user = resolveUserContext(userOrId, role);
    const memberships = await this.prisma.teamMember.findMany({
      where: { userId: user.id, isActive: true, team: { isActive: true } },
      select: {
        role: true,
        team: {
          select: {
            id: true,
            name: true,
            code: true,
            description: true,
            isActive: true,
            createdAt: true,
            updatedAt: true,
          },
        },
      },
    });
    return memberships.map((m) => ({
      ...m.team,
      role: m.role,
      ...computePermissions(m.role, user.role),
    }));
  }

  async getTeamForMember(userOrId: number | { id: number; role?: string }, teamId: number, role?: string) {
    const user = resolveUserContext(userOrId, role);
    const member = await this.prisma.teamMember.findFirst({
      where: { teamId, userId: user.id, isActive: true, team: { isActive: true } },
      select: {
        role: true,
        team: {
          select: {
            id: true,
            name: true,
            code: true,
            description: true,
            isActive: true,
            createdAt: true,
            updatedAt: true,
          },
        },
      },
    });
    if (!member) {
      throw new NotFoundException(`Team ${teamId} not found`);
    }
    return {
      ...member.team,
      role: member.role,
      ...computePermissions(member.role, user.role),
    };
  }

  async assertResourceBelongsToTeam(
    resource: 'teamMember' | 'notificationRecipient' | 'teamSubscription' | 'teamSystem',
    resourceId: number,
    teamId: number,
  ): Promise<void> {
    const record = await (this.prisma[resource] as any).findFirst({
      where: { id: resourceId, teamId },
      select: { id: true },
    });
    if (!record) {
      throw new NotFoundException(`Resource ${resourceId} not found in team ${teamId}`);
    }
  }
}
