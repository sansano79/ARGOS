import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { TeamPortalController } from './team-portal.controller';
import { TEAM_ROLES } from './constants/team-roles';

function getGuards(target: any): any[] {
  return (Reflect as any).getMetadata('__guards__', target) || [];
}

const makeService = () => ({
  findTeamById: jest.fn(),
  findTeamMembers: jest.fn(),
  findAssignableUsers: jest.fn(),
  addMember: jest.fn(),
  updateMember: jest.fn(),
  removeMember: jest.fn(),
  findSubscriptions: jest.fn(),
  createSubscription: jest.fn(),
  updateSubscription: jest.fn(),
  removeSubscription: jest.fn(),
  findSystems: jest.fn(),
  createSystem: jest.fn(),
  updateSystem: jest.fn(),
  removeSystem: jest.fn(),
  findRecipients: jest.fn(),
  createRecipient: jest.fn(),
  updateRecipient: jest.fn(),
  removeRecipient: jest.fn(),
});

const makeAccess = () => ({
  getAccessibleTeams: jest.fn(),
  getTeamForMember: jest.fn(),
  assertTeamReadable: jest.fn(),
  assertTeamWritable: jest.fn(),
});

const req = (userId: number, role = 'TEAM_MANAGER') => ({ user: { id: userId, role } });

describe('TeamPortalController', () => {
  let service: ReturnType<typeof makeService>;
  let access: ReturnType<typeof makeAccess>;
  let controller: TeamPortalController;

  beforeEach(() => {
    service = makeService();
    access = makeAccess();
    controller = new TeamPortalController(service as any, access as any);
    jest.clearAllMocks();
  });

  // ── Guard metadata ────────────────────────────────────────────

  describe('class-level security metadata', () => {
    it('applies JwtAuthGuard at class level', () => {
      const guards = getGuards(TeamPortalController);
      expect(guards).toContain(JwtAuthGuard);
    });

    it('does NOT apply RolesGuard (authorization via TeamAccessService)', () => {
      const guards = getGuards(TeamPortalController);
      const guardNames = guards.map((g: any) => g?.name || g?.constructor?.name || String(g));
      expect(guardNames).not.toContain('RolesGuard');
    });
  });

  // ── GET /me/teams ─────────────────────────────────────────────

  describe('GET /me/teams', () => {
    it('returns teams with permissions for authenticated user', async () => {
      const teams = [
        { id: 1, name: 'Alpha', role: TEAM_ROLES.MANAGER, canRead: true, canManageSubscriptions: true, canManageSystems: true, canManageRecipients: true },
      ];
      access.getAccessibleTeams.mockResolvedValue(teams);
      const result = await controller.getMyTeams(req(5));
      expect(result).toHaveLength(1);
      expect(access.getAccessibleTeams).toHaveBeenCalledWith({ id: 5, role: 'TEAM_MANAGER' });
    });

    it('returns empty array for user with no memberships', async () => {
      access.getAccessibleTeams.mockResolvedValue([]);
      const result = await controller.getMyTeams(req(99));
      expect(result).toHaveLength(0);
    });

    it('does not leak other users teams (uses req.user.id)', async () => {
      access.getAccessibleTeams.mockResolvedValue([]);
      await controller.getMyTeams(req(42));
      expect(access.getAccessibleTeams).toHaveBeenCalledWith({ id: 42, role: 'TEAM_MANAGER' });
    });
  });

  // ── GET /teams/:teamId ────────────────────────────────────────

  describe('GET /teams/:teamId', () => {
    it('returns team info with role and permission flags for MANAGER', async () => {
      const teamDetail = { id: 1, name: 'Alpha', code: 'alpha', role: TEAM_ROLES.MANAGER, canRead: true, canManageSubscriptions: true, canManageSystems: true, canManageRecipients: true };
      access.getTeamForMember.mockResolvedValue(teamDetail);
      const result = await controller.getTeam(req(5), 1);
      expect(result).toMatchObject({ id: 1, role: TEAM_ROLES.MANAGER, canManageSubscriptions: true });
    });

    it('ADMIN uses the full admin team detail service', async () => {
      service.findTeamById.mockResolvedValue({ id: 1, name: 'Alpha' });
      const result = await controller.getTeam(req(1, 'ADMIN'), 1);
      expect(result).toEqual({ id: 1, name: 'Alpha' });
      expect(service.findTeamById).toHaveBeenCalledWith(1);
      expect(access.getTeamForMember).not.toHaveBeenCalled();
    });

    it('returns team info with restricted flags for VIEWER', async () => {
      const teamDetail = { id: 1, name: 'Alpha', code: 'alpha', role: TEAM_ROLES.VIEWER, canRead: true, canManageSubscriptions: false, canManageSystems: false, canManageRecipients: false };
      access.getTeamForMember.mockResolvedValue(teamDetail);
      const result = await controller.getTeam(req(5), 1);
      expect(result).toMatchObject({ canManageSubscriptions: false });
    });

    it('throws NotFoundException for non-member (hides team existence)', async () => {
      access.getTeamForMember.mockRejectedValue(new NotFoundException());
      await expect(controller.getTeam(req(99), 1)).rejects.toThrow(NotFoundException);
    });
  });

  describe('Members portal endpoints', () => {
    it('TEAM_MANAGER can list assignable users and manage members without changing global roles', async () => {
      access.assertTeamReadable.mockResolvedValue(undefined);
      access.assertTeamWritable.mockResolvedValue(undefined);
      service.findTeamMembers.mockResolvedValue([{ id: 10 }]);
      service.findAssignableUsers.mockResolvedValue([{ id: 5, role: 'TEAM_MANAGER' }]);
      service.addMember.mockResolvedValue({ id: 10, role: 'TEAM_MANAGER' });
      service.updateMember.mockResolvedValue({ id: 10, role: 'TEAM_VIEWER' });
      service.removeMember.mockResolvedValue({ deleted: true });

      await expect(controller.getMembers(req(5), 1)).resolves.toEqual([{ id: 10 }]);
      await expect(controller.getAssignableUsers(req(5), 1)).resolves.toEqual([{ id: 5, role: 'TEAM_MANAGER' }]);
      await expect(controller.addMember(req(5), 1, { userId: 5, role: 'TEAM_MANAGER' })).resolves.toEqual({ id: 10, role: 'TEAM_MANAGER' });
      await expect(controller.updateMember(req(5), 1, 10, { role: 'TEAM_VIEWER' })).resolves.toEqual({ id: 10, role: 'TEAM_VIEWER' });
      await expect(controller.removeMember(req(5), 1, 10)).resolves.toEqual({ deleted: true });
      expect(access.assertTeamWritable).toHaveBeenCalledWith({ id: 5, role: 'TEAM_MANAGER' }, 1);
    });
  });

  // ── Subscriptions ─────────────────────────────────────────────

  describe('GET /teams/:teamId/subscriptions', () => {
    it('allows TEAM_VIEWER to read (read access)', async () => {
      access.assertTeamReadable.mockResolvedValue(undefined);
      service.findSubscriptions.mockResolvedValue([{ id: 1, vendor: 'ms' }]);
      const result = await controller.getSubscriptions(req(5), 1);
      expect(result).toHaveLength(1);
      expect(access.assertTeamReadable).toHaveBeenCalledWith({ id: 5, role: 'TEAM_MANAGER' }, 1);
    });

    it('blocks non-member (returns NotFoundException not ForbiddenException)', async () => {
      access.assertTeamReadable.mockRejectedValue(new NotFoundException());
      await expect(controller.getSubscriptions(req(99), 1)).rejects.toThrow(NotFoundException);
      expect(service.findSubscriptions).not.toHaveBeenCalled();
    });
  });

  describe('POST /teams/:teamId/subscriptions', () => {
    it('requires TEAM_MANAGER write access', async () => {
      access.assertTeamWritable.mockResolvedValue(undefined);
      service.createSubscription.mockResolvedValue({ id: 1 });
      await controller.createSubscription(req(5), 1, { vendor: 'ms', product: 'edge' });
      expect(access.assertTeamWritable).toHaveBeenCalledWith({ id: 5, role: 'TEAM_MANAGER' }, 1);
    });

    it('blocks TEAM_VIEWER (write forbidden)', async () => {
      access.assertTeamWritable.mockRejectedValue(new ForbiddenException());
      await expect(controller.createSubscription(req(5), 1, { vendor: 'ms', product: 'edge' })).rejects.toThrow(ForbiddenException);
      expect(service.createSubscription).not.toHaveBeenCalled();
    });

    it('blocks non-member with NotFoundException', async () => {
      access.assertTeamWritable.mockRejectedValue(new NotFoundException());
      await expect(controller.createSubscription(req(99), 1, { vendor: 'ms', product: 'edge' })).rejects.toThrow(NotFoundException);
    });
  });

  describe('PATCH /teams/:teamId/subscriptions/:subscriptionId', () => {
    it('requires write access', async () => {
      access.assertTeamWritable.mockResolvedValue(undefined);
      service.updateSubscription.mockResolvedValue({ id: 5, isActive: false });
      await controller.updateSubscription(req(5), 1, 5, { isActive: false });
      expect(access.assertTeamWritable).toHaveBeenCalledWith({ id: 5, role: 'TEAM_MANAGER' }, 1);
    });

    it('blocks TEAM_VIEWER from updating subscription', async () => {
      access.assertTeamWritable.mockRejectedValue(new ForbiddenException());
      await expect(controller.updateSubscription(req(5), 1, 5, { isActive: false })).rejects.toThrow(ForbiddenException);
      expect(service.updateSubscription).not.toHaveBeenCalled();
    });
  });

  describe('DELETE /teams/:teamId/subscriptions/:subscriptionId', () => {
    it('requires write access', async () => {
      access.assertTeamWritable.mockResolvedValue(undefined);
      service.removeSubscription.mockResolvedValue({ deleted: true });
      await controller.removeSubscription(req(5), 1, 10);
      expect(access.assertTeamWritable).toHaveBeenCalledWith({ id: 5, role: 'TEAM_MANAGER' }, 1);
    });
  });

  // ── Systems ───────────────────────────────────────────────────

  describe('GET /teams/:teamId/systems', () => {
    it('allows any member to read systems', async () => {
      access.assertTeamReadable.mockResolvedValue(undefined);
      service.findSystems.mockResolvedValue([{ id: 1, name: 'Srv' }]);
      expect(await controller.getSystems(req(5), 1)).toHaveLength(1);
    });

    it('blocks non-member with NotFoundException', async () => {
      access.assertTeamReadable.mockRejectedValue(new NotFoundException());
      await expect(controller.getSystems(req(99), 1)).rejects.toThrow(NotFoundException);
      expect(service.findSystems).not.toHaveBeenCalled();
    });
  });

  describe('POST /teams/:teamId/systems', () => {
    it('requires write access (TEAM_MANAGER)', async () => {
      access.assertTeamWritable.mockResolvedValue(undefined);
      service.createSystem.mockResolvedValue({ id: 1, name: 'Srv' });
      await controller.createSystem(req(5), 1, { name: 'Srv' });
      expect(access.assertTeamWritable).toHaveBeenCalledWith({ id: 5, role: 'TEAM_MANAGER' }, 1);
    });

    it('blocks TEAM_VIEWER from creating systems', async () => {
      access.assertTeamWritable.mockRejectedValue(new ForbiddenException());
      await expect(controller.createSystem(req(5), 1, { name: 'Srv' })).rejects.toThrow(ForbiddenException);
      expect(service.createSystem).not.toHaveBeenCalled();
    });
  });

  describe('PATCH /teams/:teamId/systems/:systemId', () => {
    it('requires write access', async () => {
      access.assertTeamWritable.mockResolvedValue(undefined);
      service.updateSystem.mockResolvedValue({ id: 5 });
      await controller.updateSystem(req(5), 1, 5, { name: 'Updated' });
      expect(access.assertTeamWritable).toHaveBeenCalledWith({ id: 5, role: 'TEAM_MANAGER' }, 1);
    });
  });

  describe('DELETE /teams/:teamId/systems/:systemId', () => {
    it('requires write access', async () => {
      access.assertTeamWritable.mockResolvedValue(undefined);
      service.removeSystem.mockResolvedValue({ deleted: true });
      expect(await controller.removeSystem(req(5), 1, 5)).toEqual({ deleted: true });
    });
  });

  // ── Recipients ────────────────────────────────────────────────

  describe('GET /teams/:teamId/recipients', () => {
    it('allows any member to read recipients', async () => {
      access.assertTeamReadable.mockResolvedValue(undefined);
      service.findRecipients.mockResolvedValue([{ id: 1, email: 'r@x.com' }]);
      expect(await controller.getRecipients(req(5), 1)).toHaveLength(1);
    });
  });

  describe('POST /teams/:teamId/recipients', () => {
    it('requires write access', async () => {
      access.assertTeamWritable.mockResolvedValue(undefined);
      service.createRecipient.mockResolvedValue({ id: 1, email: 'r@x.com' });
      await controller.createRecipient(req(5), 1, { email: 'r@x.com' });
      expect(access.assertTeamWritable).toHaveBeenCalledWith({ id: 5, role: 'TEAM_MANAGER' }, 1);
    });

    it('blocks TEAM_VIEWER from creating recipients', async () => {
      access.assertTeamWritable.mockRejectedValue(new ForbiddenException());
      await expect(controller.createRecipient(req(5), 1, { email: 'r@x.com' })).rejects.toThrow(ForbiddenException);
      expect(service.createRecipient).not.toHaveBeenCalled();
    });
  });

  describe('PATCH /teams/:teamId/recipients/:recipientId', () => {
    it('requires write access', async () => {
      access.assertTeamWritable.mockResolvedValue(undefined);
      service.updateRecipient.mockResolvedValue({ id: 1 });
      await controller.updateRecipient(req(5), 1, 1, { email: 'new@x.com' });
      expect(access.assertTeamWritable).toHaveBeenCalledWith({ id: 5, role: 'TEAM_MANAGER' }, 1);
    });
  });

  describe('DELETE /teams/:teamId/recipients/:recipientId', () => {
    it('requires write access', async () => {
      access.assertTeamWritable.mockResolvedValue(undefined);
      service.removeRecipient.mockResolvedValue({ deleted: true });
      expect(await controller.removeRecipient(req(5), 1, 1)).toEqual({ deleted: true });
    });
  });

  // ── Cross-team IDOR scenarios ─────────────────────────────────

  describe('Cross-team IDOR prevention', () => {
    it('user from team B cannot read team A resources (systems)', async () => {
      access.assertTeamReadable.mockRejectedValue(new NotFoundException());
      await expect(controller.getSystems(req(99), 1)).rejects.toThrow(NotFoundException);
      expect(service.findSystems).not.toHaveBeenCalled();
    });

    it('user from team B cannot write to team A resources (subscriptions)', async () => {
      access.assertTeamWritable.mockRejectedValue(new NotFoundException());
      await expect(controller.createSubscription(req(99), 1, { vendor: 'a', product: 'b' })).rejects.toThrow(NotFoundException);
      expect(service.createSubscription).not.toHaveBeenCalled();
    });

    it('user from team B cannot read team A recipients', async () => {
      access.assertTeamReadable.mockRejectedValue(new NotFoundException());
      await expect(controller.getRecipients(req(99), 1)).rejects.toThrow(NotFoundException);
      expect(service.findRecipients).not.toHaveBeenCalled();
    });

    it('service method is never called without access check passing', async () => {
      access.assertTeamWritable.mockRejectedValue(new ForbiddenException());
      await controller.createSystem(req(5), 1, { name: 'X' }).catch(() => {});
      expect(service.createSystem).not.toHaveBeenCalled();
    });
  });
});
