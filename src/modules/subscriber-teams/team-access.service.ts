import { Injectable, ForbiddenException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { TEAM_ROLES } from './constants/team-roles';

function computePermissions(role: string) {
  const canManage = role === TEAM_ROLES.MANAGER;
  return {
    canRead: true,
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

  async assertTeamReadable(userId: number, teamId: number): Promise<void> {
    const member = await this.prisma.teamMember.findFirst({
      where: { teamId, userId, isActive: true, team: { isActive: true } },
      select: { role: true },
    });
    if (!member) {
      throw new NotFoundException(`Team ${teamId} not found`);
    }
  }

  async assertTeamWritable(userId: number, teamId: number): Promise<void> {
    const member = await this.prisma.teamMember.findFirst({
      where: { teamId, userId, isActive: true, team: { isActive: true } },
      select: { role: true },
    });
    if (!member) {
      throw new NotFoundException(`Team ${teamId} not found`);
    }
    if (member.role !== TEAM_ROLES.MANAGER) {
      throw new ForbiddenException('Team manager access required');
    }
  }

  async getAccessibleTeams(userId: number) {
    const memberships = await this.prisma.teamMember.findMany({
      where: { userId, isActive: true, team: { isActive: true } },
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
      ...computePermissions(m.role),
    }));
  }

  async getTeamForMember(userId: number, teamId: number) {
    const member = await this.prisma.teamMember.findFirst({
      where: { teamId, userId, isActive: true, team: { isActive: true } },
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
      ...computePermissions(member.role),
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
