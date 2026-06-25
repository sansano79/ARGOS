import 'reflect-metadata';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { SubscriberTeamsController } from './subscriber-teams.controller';

// ── Helpers for metadata inspection ──────────────────────────────

function getGuards(target: any): any[] {
  return Reflect.getMetadata('__guards__', target) || [];
}

function getRoles(target: any): string[] {
  return Reflect.getMetadata('roles', target) || [];
}

const makeService = () => ({
  findAllTeams: jest.fn(),
  createTeam: jest.fn(),
  findTeamById: jest.fn(),
  updateTeam: jest.fn(),
  findTeamMembers: jest.fn(),
  addMember: jest.fn(),
  updateMember: jest.fn(),
  removeMember: jest.fn(),
  findRecipients: jest.fn(),
  createRecipient: jest.fn(),
  updateRecipient: jest.fn(),
  removeRecipient: jest.fn(),
  findSubscriptions: jest.fn(),
  createSubscription: jest.fn(),
  updateSubscription: jest.fn(),
  removeSubscription: jest.fn(),
  findSystems: jest.fn(),
  createSystem: jest.fn(),
  updateSystem: jest.fn(),
  removeSystem: jest.fn(),
});

const makeAccess = () => ({
  assertAdmin: jest.fn(),
  assertTeamReadable: jest.fn(),
  assertTeamWritable: jest.fn(),
  getAccessibleTeams: jest.fn(),
  getTeamForMember: jest.fn(),
  assertResourceBelongsToTeam: jest.fn(),
});

describe('SubscriberTeamsController', () => {
  let service: ReturnType<typeof makeService>;
  let access: ReturnType<typeof makeAccess>;
  let controller: SubscriberTeamsController;

  beforeEach(() => {
    service = makeService();
    access = makeAccess();
    controller = new SubscriberTeamsController(service as any, access as any);
    jest.clearAllMocks();
  });

  // ── Guard metadata ────────────────────────────────────────────

  describe('class-level security metadata', () => {
    it('applies JwtAuthGuard at class level', () => {
      const guards = getGuards(SubscriberTeamsController);
      expect(guards).toContain(JwtAuthGuard);
    });

    it('applies RolesGuard at class level', () => {
      const guards = getGuards(SubscriberTeamsController);
      expect(guards).toContain(RolesGuard);
    });

    it('requires ADMIN role at class level', () => {
      const roles = getRoles(SubscriberTeamsController);
      expect(roles).toContain('ADMIN');
    });
  });

  // ── Teams ─────────────────────────────────────────────────────

  describe('GET / (findAll)', () => {
    it('returns all teams', async () => {
      service.findAllTeams.mockResolvedValue([{ id: 1, name: 'Alpha' }]);
      const result = await controller.findAll();
      expect(result).toHaveLength(1);
    });
  });

  describe('POST / (create)', () => {
    it('creates team', async () => {
      service.createTeam.mockResolvedValue({ id: 2, name: 'Beta', code: 'beta' });
      const result = await controller.create({ name: 'Beta', code: 'beta' });
      expect(result).toMatchObject({ code: 'beta' });
    });
  });

  describe('GET /:teamId (findOne)', () => {
    it('returns team by id', async () => {
      service.findTeamById.mockResolvedValue({ id: 1, name: 'Alpha', members: [] });
      await expect(controller.findOne(1)).resolves.toMatchObject({ id: 1 });
    });

    it('propagates NotFoundException from service', async () => {
      service.findTeamById.mockRejectedValue(new NotFoundException());
      await expect(controller.findOne(999)).rejects.toThrow(NotFoundException);
    });
  });

  describe('PATCH /:teamId (update)', () => {
    it('updates team', async () => {
      service.updateTeam.mockResolvedValue({ id: 1, name: 'Updated' });
      const result = await controller.update(1, { name: 'Updated' });
      expect(result).toMatchObject({ name: 'Updated' });
    });
  });

  // ── Members ───────────────────────────────────────────────────

  describe('GET /:teamId/members', () => {
    it('returns members', async () => {
      service.findTeamMembers.mockResolvedValue([{ id: 10, role: 'TEAM_MANAGER' }]);
      const result = await controller.findMembers(1);
      expect(result).toHaveLength(1);
    });
  });

  describe('POST /:teamId/members (addMember)', () => {
    it('adds member', async () => {
      service.addMember.mockResolvedValue({ id: 10, role: 'TEAM_MANAGER' });
      const result = await controller.addMember(1, { userId: 5, role: 'TEAM_MANAGER' });
      expect(result).toMatchObject({ role: 'TEAM_MANAGER' });
    });
  });

  describe('PATCH /:teamId/members/:memberId', () => {
    it('updates member role', async () => {
      service.updateMember.mockResolvedValue({ id: 10, role: 'TEAM_VIEWER' });
      const result = await controller.updateMember(1, 10, { role: 'TEAM_VIEWER' });
      expect(result.role).toBe('TEAM_VIEWER');
    });
  });

  describe('DELETE /:teamId/members/:memberId', () => {
    it('removes member', async () => {
      service.removeMember.mockResolvedValue({ deleted: true });
      expect(await controller.removeMember(1, 10)).toEqual({ deleted: true });
    });
  });

  // ── Recipients ────────────────────────────────────────────────

  describe('GET /:teamId/recipients', () => {
    it('returns recipients', async () => {
      service.findRecipients.mockResolvedValue([{ id: 1, email: 'r@example.com' }]);
      expect(await controller.findRecipients(1)).toHaveLength(1);
    });
  });

  describe('POST /:teamId/recipients', () => {
    it('creates recipient', async () => {
      service.createRecipient.mockResolvedValue({ id: 1, email: 'r@example.com' });
      const result = await controller.createRecipient(1, { email: 'r@example.com' });
      expect(result.email).toBe('r@example.com');
    });
  });

  describe('PATCH /:teamId/recipients/:recipientId', () => {
    it('updates recipient', async () => {
      service.updateRecipient.mockResolvedValue({ id: 1, email: 'new@example.com' });
      const result = await controller.updateRecipient(1, 1, { email: 'new@example.com' });
      expect(result.email).toBe('new@example.com');
    });
  });

  describe('DELETE /:teamId/recipients/:recipientId', () => {
    it('removes recipient', async () => {
      service.removeRecipient.mockResolvedValue({ deleted: true });
      expect(await controller.removeRecipient(1, 1)).toEqual({ deleted: true });
    });
  });

  // ── Subscriptions ─────────────────────────────────────────────

  describe('GET /:teamId/subscriptions', () => {
    it('returns subscriptions', async () => {
      service.findSubscriptions.mockResolvedValue([{ id: 1, vendor: 'ms', product: 'edge' }]);
      expect(await controller.findSubscriptions(1)).toHaveLength(1);
    });
  });

  describe('POST /:teamId/subscriptions', () => {
    it('creates subscription', async () => {
      service.createSubscription.mockResolvedValue({ id: 1, vendor: 'ms', product: 'edge' });
      const result = await controller.createSubscription(1, { vendor: 'ms', product: 'edge' });
      expect(result.vendor).toBe('ms');
    });
  });

  describe('PATCH /:teamId/subscriptions/:subscriptionId', () => {
    it('updates subscription', async () => {
      service.updateSubscription.mockResolvedValue({ id: 5, isActive: false });
      const result = await controller.updateSubscription(1, 5, { isActive: false });
      expect(result.isActive).toBe(false);
    });
  });

  describe('DELETE /:teamId/subscriptions/:subscriptionId', () => {
    it('removes subscription', async () => {
      service.removeSubscription.mockResolvedValue({ deleted: true });
      expect(await controller.removeSubscription(1, 5)).toEqual({ deleted: true });
    });
  });

  // ── Systems ───────────────────────────────────────────────────

  describe('GET /:teamId/systems', () => {
    it('returns systems', async () => {
      service.findSystems.mockResolvedValue([{ id: 1, name: 'Srv1' }]);
      expect(await controller.findSystems(1)).toHaveLength(1);
    });
  });

  describe('POST /:teamId/systems', () => {
    it('creates system', async () => {
      service.createSystem.mockResolvedValue({ id: 1, name: 'Srv1' });
      expect((await controller.createSystem(1, { name: 'Srv1' })).name).toBe('Srv1');
    });
  });

  describe('PATCH /:teamId/systems/:systemId', () => {
    it('updates system', async () => {
      service.updateSystem.mockResolvedValue({ id: 5, name: 'Updated' });
      expect((await controller.updateSystem(1, 5, { name: 'Updated' })).name).toBe('Updated');
    });
  });

  describe('DELETE /:teamId/systems/:systemId', () => {
    it('removes system', async () => {
      service.removeSystem.mockResolvedValue({ deleted: true });
      expect(await controller.removeSystem(1, 5)).toEqual({ deleted: true });
    });
  });
});
