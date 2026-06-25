import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { TeamAccessService } from './team-access.service';
import { TEAM_ROLES } from './constants/team-roles';

const makePrisma = () => ({
  teamMember: {
    findFirst: jest.fn(),
    findMany: jest.fn(),
  },
  notificationRecipient: { findFirst: jest.fn() },
  teamSubscription: { findFirst: jest.fn() },
  teamSystem: { findFirst: jest.fn() },
});

describe('TeamAccessService', () => {
  let prisma: ReturnType<typeof makePrisma>;
  let service: TeamAccessService;

  beforeEach(() => {
    prisma = makePrisma();
    service = new TeamAccessService(prisma as any);
    jest.clearAllMocks();
  });

  // ── assertAdmin ───────────────────────────────────────────────

  describe('assertAdmin', () => {
    it('passes for ADMIN role', () => {
      expect(() => service.assertAdmin({ role: 'ADMIN' })).not.toThrow();
    });

    it('throws ForbiddenException for USER', () => {
      expect(() => service.assertAdmin({ role: 'USER' })).toThrow(ForbiddenException);
    });

    it('throws ForbiddenException for VIEWER', () => {
      expect(() => service.assertAdmin({ role: 'VIEWER' })).toThrow(ForbiddenException);
    });

    it('throws ForbiddenException for SUBSCRIBER', () => {
      expect(() => service.assertAdmin({ role: 'SUBSCRIBER' })).toThrow(ForbiddenException);
    });

    it('throws ForbiddenException for TEAM_MANAGER (not global admin)', () => {
      expect(() => service.assertAdmin({ role: 'TEAM_MANAGER' })).toThrow(ForbiddenException);
    });
  });

  // ── assertTeamReadable ────────────────────────────────────────

  describe('assertTeamReadable', () => {
    it('passes when active membership exists in active team (any role)', async () => {
      prisma.teamMember.findFirst.mockResolvedValue({ role: TEAM_ROLES.VIEWER });
      await expect(service.assertTeamReadable(5, 1)).resolves.toBeUndefined();
    });

    it('passes for TEAM_MANAGER as well', async () => {
      prisma.teamMember.findFirst.mockResolvedValue({ role: TEAM_ROLES.MANAGER });
      await expect(service.assertTeamReadable(5, 1)).resolves.toBeUndefined();
    });

    it('throws NotFoundException when no active membership', async () => {
      prisma.teamMember.findFirst.mockResolvedValue(null);
      await expect(service.assertTeamReadable(5, 1)).rejects.toThrow(NotFoundException);
    });

    it('returns NotFoundException (not ForbiddenException) to hide team existence from non-members', async () => {
      prisma.teamMember.findFirst.mockResolvedValue(null);
      const err = await service.assertTeamReadable(99, 1).catch((e) => e);
      expect(err).toBeInstanceOf(NotFoundException);
      expect(err).not.toBeInstanceOf(ForbiddenException);
    });

    it('blocks inactive member (isActive:true filter in query)', async () => {
      prisma.teamMember.findFirst.mockResolvedValue(null); // inactive member returns null
      await expect(service.assertTeamReadable(5, 1)).rejects.toThrow(NotFoundException);
      expect(prisma.teamMember.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: expect.objectContaining({ isActive: true }) }),
      );
    });

    it('blocks access to inactive team (team.isActive filter in query)', async () => {
      prisma.teamMember.findFirst.mockResolvedValue(null); // inactive team returns null
      await expect(service.assertTeamReadable(5, 1)).rejects.toThrow(NotFoundException);
      expect(prisma.teamMember.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ team: { isActive: true } }),
        }),
      );
    });
  });

  // ── assertTeamWritable ────────────────────────────────────────

  describe('assertTeamWritable', () => {
    it('passes for global TEAM_MANAGER with active membership in active team', async () => {
      prisma.teamMember.findFirst.mockResolvedValue({ role: TEAM_ROLES.MANAGER });
      await expect(service.assertTeamWritable({ id: 5, role: 'TEAM_MANAGER' }, 1)).resolves.toBeUndefined();
    });

    it('passes for TEAM_MANAGER with active membership in active team', async () => {
      prisma.teamMember.findFirst.mockResolvedValue({ role: TEAM_ROLES.MANAGER });
      await expect(service.assertTeamWritable(5, 1)).resolves.toBeUndefined();
    });

    it('blocks USER even with historical manager membership', async () => {
      prisma.teamMember.findFirst.mockResolvedValue({ role: TEAM_ROLES.MANAGER });
      await expect(service.assertTeamWritable({ id: 5, role: 'USER' }, 1)).rejects.toThrow(ForbiddenException);
    });

    it('allows ADMIN without membership lookup', async () => {
      await expect(service.assertTeamWritable({ id: 1, role: 'ADMIN' }, 99)).resolves.toBeUndefined();
      expect(prisma.teamMember.findFirst).not.toHaveBeenCalled();
    });

    it('throws ForbiddenException for TEAM_VIEWER (member but read-only)', async () => {
      // First call returns the member (any role), but role is VIEWER
      prisma.teamMember.findFirst.mockResolvedValue({ role: TEAM_ROLES.VIEWER });
      await expect(service.assertTeamWritable(5, 1)).rejects.toThrow(ForbiddenException);
    });

    it('throws NotFoundException for non-member (hides team existence)', async () => {
      prisma.teamMember.findFirst.mockResolvedValue(null);
      const err = await service.assertTeamWritable(99, 1).catch((e) => e);
      expect(err).toBeInstanceOf(NotFoundException);
      expect(err).not.toBeInstanceOf(ForbiddenException);
    });

    it('blocks inactive member', async () => {
      prisma.teamMember.findFirst.mockResolvedValue(null);
      await expect(service.assertTeamWritable(5, 1)).rejects.toThrow(NotFoundException);
      expect(prisma.teamMember.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: expect.objectContaining({ isActive: true }) }),
      );
    });

    it('blocks access to inactive team', async () => {
      prisma.teamMember.findFirst.mockResolvedValue(null);
      await expect(service.assertTeamWritable(5, 1)).rejects.toThrow(NotFoundException);
      expect(prisma.teamMember.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ team: { isActive: true } }),
        }),
      );
    });
  });

  // ── getAccessibleTeams ────────────────────────────────────────

  describe('getAccessibleTeams', () => {
    it('returns teams with role and computed permission flags', async () => {
      prisma.teamMember.findMany.mockResolvedValue([
        { role: TEAM_ROLES.MANAGER, team: { id: 1, name: 'Alpha', code: 'alpha', description: null, isActive: true, createdAt: new Date(), updatedAt: new Date() } },
        { role: TEAM_ROLES.VIEWER, team: { id: 2, name: 'Beta', code: 'beta', description: null, isActive: true, createdAt: new Date(), updatedAt: new Date() } },
      ]);
      const result = await service.getAccessibleTeams(5);
      expect(result).toHaveLength(2);
      expect(result[0]).toMatchObject({ id: 1, role: TEAM_ROLES.MANAGER, canRead: true, canManageSubscriptions: true, canManageSystems: true, canManageRecipients: true });
      expect(result[1]).toMatchObject({ id: 2, role: TEAM_ROLES.VIEWER, canRead: true, canManageSubscriptions: false, canManageSystems: false, canManageRecipients: false });
    });

    it('returns empty array when user has no memberships', async () => {
      prisma.teamMember.findMany.mockResolvedValue([]);
      const result = await service.getAccessibleTeams(99);
      expect(result).toHaveLength(0);
    });

    it('removes manage flags for USER even if historical team role is TEAM_MANAGER', async () => {
      prisma.teamMember.findMany.mockResolvedValue([
        { role: TEAM_ROLES.MANAGER, team: { id: 1, name: 'Alpha', code: 'alpha', description: null, isActive: true, createdAt: new Date(), updatedAt: new Date() } },
      ]);
      const result = await service.getAccessibleTeams({ id: 5, role: 'USER' });
      expect(result[0]).toMatchObject({
        canRead: true,
        canManageMembers: false,
        canManageSubscriptions: false,
        canManageSystems: false,
        canManageRecipients: false,
      });
    });

    it('filters by userId and isActive:true on member AND team.isActive:true', async () => {
      prisma.teamMember.findMany.mockResolvedValue([]);
      await service.getAccessibleTeams(5);
      expect(prisma.teamMember.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { userId: 5, isActive: true, team: { isActive: true } },
        }),
      );
    });

    it('does not expose inactive teams even if user is member', async () => {
      prisma.teamMember.findMany.mockResolvedValue([]); // filtered out by team.isActive
      const result = await service.getAccessibleTeams(5);
      expect(result).toHaveLength(0);
    });
  });

  // ── getTeamForMember ──────────────────────────────────────────

  describe('getTeamForMember', () => {
    it('returns team info with role and permission flags for MANAGER', async () => {
      prisma.teamMember.findFirst.mockResolvedValue({
        role: TEAM_ROLES.MANAGER,
        team: { id: 1, name: 'Alpha', code: 'alpha', description: null, isActive: true, createdAt: new Date(), updatedAt: new Date() },
      });
      const result = await service.getTeamForMember(5, 1);
      expect(result).toMatchObject({
        id: 1,
        role: TEAM_ROLES.MANAGER,
        canRead: true,
        canManageSubscriptions: true,
        canManageSystems: true,
        canManageRecipients: true,
      });
    });

    it('returns team info with restricted flags for VIEWER', async () => {
      prisma.teamMember.findFirst.mockResolvedValue({
        role: TEAM_ROLES.VIEWER,
        team: { id: 1, name: 'Alpha', code: 'alpha', description: null, isActive: true, createdAt: new Date(), updatedAt: new Date() },
      });
      const result = await service.getTeamForMember(5, 1);
      expect(result).toMatchObject({
        canRead: true,
        canManageSubscriptions: false,
        canManageSystems: false,
        canManageRecipients: false,
      });
    });

    it('throws NotFoundException for non-member or inactive team', async () => {
      prisma.teamMember.findFirst.mockResolvedValue(null);
      await expect(service.getTeamForMember(99, 1)).rejects.toThrow(NotFoundException);
    });
  });

  // ── assertResourceBelongsToTeam ───────────────────────────────

  describe('assertResourceBelongsToTeam', () => {
    it('passes when teamSystem belongs to team', async () => {
      prisma.teamSystem.findFirst.mockResolvedValue({ id: 5 });
      await expect(service.assertResourceBelongsToTeam('teamSystem', 5, 1)).resolves.toBeUndefined();
    });

    it('throws NotFoundException when teamSystem belongs to different team (IDOR)', async () => {
      prisma.teamSystem.findFirst.mockResolvedValue(null);
      await expect(service.assertResourceBelongsToTeam('teamSystem', 5, 2)).rejects.toThrow(NotFoundException);
    });

    it('queries by id AND teamId in the same query (not separately)', async () => {
      prisma.teamMember.findFirst.mockResolvedValue(null);
      await service.assertResourceBelongsToTeam('teamMember', 10, 3).catch(() => {});
      expect(prisma.teamMember.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: 10, teamId: 3 } }),
      );
    });

    it('checks notificationRecipient by id+teamId', async () => {
      prisma.notificationRecipient.findFirst.mockResolvedValue(null);
      await service.assertResourceBelongsToTeam('notificationRecipient', 7, 2).catch(() => {});
      expect(prisma.notificationRecipient.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: 7, teamId: 2 } }),
      );
    });

    it('checks teamSubscription by id+teamId', async () => {
      prisma.teamSubscription.findFirst.mockResolvedValue(null);
      await service.assertResourceBelongsToTeam('teamSubscription', 3, 1).catch(() => {});
      expect(prisma.teamSubscription.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: 3, teamId: 1 } }),
      );
    });
  });
});
