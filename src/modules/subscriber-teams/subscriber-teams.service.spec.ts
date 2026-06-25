import { NotFoundException, ConflictException, BadRequestException } from '@nestjs/common';
import { SubscriberTeamsService } from './subscriber-teams.service';

const makeTeam = (overrides = {}) => ({
  id: 1, name: 'Alpha Team', code: 'alpha', description: null,
  isActive: true, createdAt: new Date(), updatedAt: new Date(), members: [], ...overrides,
});

const makePrisma = () => ({
  subscriberTeam: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  },
  teamMember: {
    findMany: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  notificationRecipient: {
    findMany: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  teamSubscription: {
    findMany: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  teamSystem: {
    findMany: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  user: {
    findUnique: jest.fn(),
  },
});

describe('SubscriberTeamsService', () => {
  let prisma: ReturnType<typeof makePrisma>;
  let service: SubscriberTeamsService;

  beforeEach(() => {
    prisma = makePrisma();
    service = new SubscriberTeamsService(prisma as any);
    jest.clearAllMocks();
  });

  // ── findAllTeams ──────────────────────────────────────────────

  describe('findAllTeams', () => {
    it('returns all teams ordered by name', async () => {
      const teams = [makeTeam({ name: 'Alpha' }), makeTeam({ id: 2, name: 'Beta' })];
      prisma.subscriberTeam.findMany.mockResolvedValue(teams);
      const result = await service.findAllTeams();
      expect(result).toHaveLength(2);
      expect(prisma.subscriberTeam.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ orderBy: { name: 'asc' } }),
      );
    });
  });

  // ── findTeamById ──────────────────────────────────────────────

  describe('findTeamById', () => {
    it('returns team when found', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(makeTeam());
      await expect(service.findTeamById(1)).resolves.toMatchObject({ id: 1 });
    });

    it('throws NotFoundException when team does not exist', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(null);
      await expect(service.findTeamById(999)).rejects.toThrow(NotFoundException);
    });

    it('ADMIN can access inactive team', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(makeTeam({ isActive: false }));
      const result = await service.findTeamById(1);
      expect(result.isActive).toBe(false);
    });
  });

  // ── createTeam ────────────────────────────────────────────────

  describe('createTeam', () => {
    it('creates team with required fields', async () => {
      const team = makeTeam();
      prisma.subscriberTeam.create.mockResolvedValue(team);
      const result = await service.createTeam({ name: 'Alpha Team', code: 'alpha' });
      expect(result).toMatchObject({ id: 1 });
    });

    it('normalizes code to lowercase and trimmed', async () => {
      prisma.subscriberTeam.create.mockResolvedValue(makeTeam({ code: 'alpha' }));
      await service.createTeam({ name: 'Alpha', code: '  Alpha  ' });
      expect(prisma.subscriberTeam.create).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ code: 'alpha' }) }),
      );
    });

    it('normalizes name to trimmed', async () => {
      prisma.subscriberTeam.create.mockResolvedValue(makeTeam());
      await service.createTeam({ name: '  Alpha Team  ', code: 'alpha' });
      expect(prisma.subscriberTeam.create).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ name: 'Alpha Team' }) }),
      );
    });

    it('maps P2002 (duplicate code) to ConflictException', async () => {
      prisma.subscriberTeam.create.mockRejectedValue(Object.assign(new Error(), { code: 'P2002' }));
      await expect(service.createTeam({ name: 'Alpha', code: 'alpha' })).rejects.toThrow(ConflictException);
    });
  });

  // ── updateTeam ────────────────────────────────────────────────

  describe('updateTeam', () => {
    it('updates team fields', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(makeTeam());
      prisma.subscriberTeam.update.mockResolvedValue(makeTeam({ name: 'Beta' }));
      const result = await service.updateTeam(1, { name: 'Beta' });
      expect(result).toMatchObject({ name: 'Beta' });
    });

    it('normalizes code on update', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(makeTeam());
      prisma.subscriberTeam.update.mockResolvedValue(makeTeam({ code: 'beta' }));
      await service.updateTeam(1, { code: '  BETA  ' });
      expect(prisma.subscriberTeam.update).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ code: 'beta' }) }),
      );
    });

    it('throws NotFoundException when team not found', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(null);
      await expect(service.updateTeam(999, { name: 'X' })).rejects.toThrow(NotFoundException);
    });

    it('maps P2002 (duplicate code) to ConflictException', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(makeTeam());
      prisma.subscriberTeam.update.mockRejectedValue(Object.assign(new Error(), { code: 'P2002' }));
      await expect(service.updateTeam(1, { code: 'existing' })).rejects.toThrow(ConflictException);
    });
  });

  // ── addMember ─────────────────────────────────────────────────

  describe('addMember', () => {
    it('adds member with TEAM_MANAGER role', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(makeTeam());
      prisma.user.findUnique.mockResolvedValue({ id: 5, role: 'TEAM_MANAGER' });
      const member = { id: 10, role: 'TEAM_MANAGER', isActive: true, createdAt: new Date(), updatedAt: new Date(), user: { id: 5, email: 'a@b.com', name: 'A', role: 'TEAM_MANAGER' } };
      prisma.teamMember.create.mockResolvedValue(member);
      const result = await service.addMember(1, { userId: 5, role: 'TEAM_MANAGER' });
      expect(result).toMatchObject({ role: 'TEAM_MANAGER' });
    });

    it('throws NotFoundException when team not found', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(null);
      await expect(service.addMember(999, { userId: 1, role: 'TEAM_VIEWER' })).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException when user not found', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(makeTeam());
      prisma.user.findUnique.mockResolvedValue(null);
      await expect(service.addMember(1, { userId: 999, role: 'TEAM_VIEWER' })).rejects.toThrow(NotFoundException);
    });

    it('rejects assigning TEAM_MANAGER internal role to a USER global role', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(makeTeam());
      prisma.user.findUnique.mockResolvedValue({ id: 5, role: 'USER' });
      await expect(service.addMember(1, { userId: 5, role: 'TEAM_MANAGER' })).rejects.toThrow(BadRequestException);
      expect(prisma.teamMember.create).not.toHaveBeenCalled();
    });

    it('maps P2002 to ConflictException when user already member', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(makeTeam());
      prisma.user.findUnique.mockResolvedValue({ id: 5, role: 'USER' });
      prisma.teamMember.create.mockRejectedValue(Object.assign(new Error(), { code: 'P2002' }));
      await expect(service.addMember(1, { userId: 5, role: 'TEAM_VIEWER' })).rejects.toThrow(ConflictException);
    });
  });

  // ── updateMember ──────────────────────────────────────────────

  describe('updateMember', () => {
    it('updates member role', async () => {
      prisma.teamMember.findFirst.mockResolvedValue({ id: 10, user: { role: 'TEAM_MANAGER' } });
      const updated = { id: 10, role: 'TEAM_VIEWER', isActive: true, updatedAt: new Date(), createdAt: new Date(), user: { id: 5, email: 'a@b.com', name: 'A', role: 'TEAM_MANAGER' } };
      prisma.teamMember.update.mockResolvedValue(updated);
      const result = await service.updateMember(1, 10, { role: 'TEAM_VIEWER' });
      expect(result.role).toBe('TEAM_VIEWER');
    });

    it('activates/deactivates member', async () => {
      prisma.teamMember.findFirst.mockResolvedValue({ id: 10, user: { role: 'TEAM_MANAGER' } });
      prisma.teamMember.update.mockResolvedValue({ id: 10, isActive: false, role: 'TEAM_VIEWER', updatedAt: new Date(), createdAt: new Date(), user: { id: 5, email: 'a@b.com', name: 'A', role: 'TEAM_MANAGER' } });
      const result = await service.updateMember(1, 10, { isActive: false });
      expect(result.isActive).toBe(false);
    });

    it('throws NotFoundException for memberId from different team (IDOR prevention)', async () => {
      prisma.teamMember.findFirst.mockResolvedValue(null);
      await expect(service.updateMember(1, 99, { role: 'TEAM_VIEWER' })).rejects.toThrow(NotFoundException);
    });

    it('queries by id AND teamId together (not separately)', async () => {
      prisma.teamMember.findFirst.mockResolvedValue(null);
      await service.updateMember(1, 99, {}).catch(() => {});
      expect(prisma.teamMember.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: 99, teamId: 1 } }),
      );
    });
  });

  // ── removeMember ─────────────────────────────────────────────

  describe('removeMember', () => {
    it('deletes member and returns deleted:true', async () => {
      prisma.teamMember.findFirst.mockResolvedValue({ id: 10 });
      prisma.teamMember.delete.mockResolvedValue({});
      const result = await service.removeMember(1, 10);
      expect(result).toEqual({ deleted: true });
    });

    it('throws NotFoundException for memberId from different team (IDOR)', async () => {
      prisma.teamMember.findFirst.mockResolvedValue(null);
      await expect(service.removeMember(1, 99)).rejects.toThrow(NotFoundException);
    });
  });

  // ── createRecipient ───────────────────────────────────────────

  describe('createRecipient', () => {
    it('creates recipient with defaults', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(makeTeam());
      prisma.notificationRecipient.create.mockResolvedValue({ id: 1, email: 'r@example.com', teamId: 1 });
      const result = await service.createRecipient(1, { email: 'R@Example.COM' });
      expect(prisma.notificationRecipient.create).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ email: 'r@example.com' }) }),
      );
      expect(result).toMatchObject({ email: 'r@example.com' });
    });

    it('normalizes email to lowercase+trim', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(makeTeam());
      prisma.notificationRecipient.create.mockResolvedValue({ id: 1, email: 'r@example.com' });
      await service.createRecipient(1, { email: '  R@EXAMPLE.COM  ' });
      expect(prisma.notificationRecipient.create).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ email: 'r@example.com' }) }),
      );
    });

    it('maps P2002 to ConflictException for duplicate email+team', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(makeTeam());
      prisma.notificationRecipient.create.mockRejectedValue(Object.assign(new Error(), { code: 'P2002' }));
      await expect(service.createRecipient(1, { email: 'dup@example.com' })).rejects.toThrow(ConflictException);
    });
  });

  // ── updateRecipient ───────────────────────────────────────────

  describe('updateRecipient', () => {
    it('normalizes email on update', async () => {
      prisma.notificationRecipient.findFirst.mockResolvedValue({ id: 1 });
      prisma.notificationRecipient.update.mockResolvedValue({ id: 1 });
      await service.updateRecipient(1, 1, { email: '  New@EXAMPLE.COM  ' });
      expect(prisma.notificationRecipient.update).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ email: 'new@example.com' }) }),
      );
    });

    it('throws NotFoundException for recipientId from different team (IDOR)', async () => {
      prisma.notificationRecipient.findFirst.mockResolvedValue(null);
      await expect(service.updateRecipient(1, 99, { email: 'x@x.com' })).rejects.toThrow(NotFoundException);
    });

    it('queries recipient by id AND teamId (not separately)', async () => {
      prisma.notificationRecipient.findFirst.mockResolvedValue(null);
      await service.updateRecipient(1, 99, {}).catch(() => {});
      expect(prisma.notificationRecipient.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: 99, teamId: 1 } }),
      );
    });
  });

  // ── removeRecipient ───────────────────────────────────────────

  describe('removeRecipient', () => {
    it('deletes and returns deleted:true', async () => {
      prisma.notificationRecipient.findFirst.mockResolvedValue({ id: 1 });
      prisma.notificationRecipient.delete.mockResolvedValue({});
      expect(await service.removeRecipient(1, 1)).toEqual({ deleted: true });
    });

    it('throws NotFoundException for recipientId from different team (IDOR)', async () => {
      prisma.notificationRecipient.findFirst.mockResolvedValue(null);
      await expect(service.removeRecipient(1, 99)).rejects.toThrow(NotFoundException);
    });
  });

  // ── createSubscription ────────────────────────────────────────

  describe('createSubscription', () => {
    it('normalizes vendor/product to lowercase+trim', async () => {
      prisma.teamSubscription.create.mockResolvedValue({ id: 1, vendor: 'microsoft', product: 'windows' });
      await service.createSubscription(1, { vendor: '  Microsoft  ', product: '  Windows  ' });
      expect(prisma.teamSubscription.create).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ vendor: 'microsoft', product: 'windows' }) }),
      );
    });

    it('maps P2002 to ConflictException for duplicate vendor+product+team', async () => {
      prisma.teamSubscription.create.mockRejectedValue(Object.assign(new Error(), { code: 'P2002' }));
      await expect(service.createSubscription(1, { vendor: 'a', product: 'b' })).rejects.toThrow(ConflictException);
    });
  });

  // ── updateSubscription ────────────────────────────────────────

  describe('updateSubscription', () => {
    it('updates versions and isActive', async () => {
      prisma.teamSubscription.findFirst.mockResolvedValue({ id: 5 });
      prisma.teamSubscription.update.mockResolvedValue({ id: 5, versions: '["1.0"]', isActive: false });
      const result = await service.updateSubscription(1, 5, { versions: ['1.0'], isActive: false });
      expect(result).toMatchObject({ isActive: false });
    });

    it('normalizes vendor/product on update', async () => {
      prisma.teamSubscription.findFirst.mockResolvedValue({ id: 5 });
      prisma.teamSubscription.update.mockResolvedValue({ id: 5 });
      await service.updateSubscription(1, 5, { vendor: '  Microsoft  ', product: '  Edge  ' });
      expect(prisma.teamSubscription.update).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ vendor: 'microsoft', product: 'edge' }) }),
      );
    });

    it('throws NotFoundException for subscriptionId from different team (IDOR)', async () => {
      prisma.teamSubscription.findFirst.mockResolvedValue(null);
      await expect(service.updateSubscription(1, 99, { isActive: false })).rejects.toThrow(NotFoundException);
    });

    it('queries subscription by id AND teamId (IDOR prevention)', async () => {
      prisma.teamSubscription.findFirst.mockResolvedValue(null);
      await service.updateSubscription(1, 99, {}).catch(() => {});
      expect(prisma.teamSubscription.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: 99, teamId: 1 } }),
      );
    });
  });

  // ── removeSubscription ────────────────────────────────────────

  describe('removeSubscription', () => {
    it('throws NotFoundException for subscriptionId from different team (IDOR)', async () => {
      prisma.teamSubscription.findFirst.mockResolvedValue(null);
      await expect(service.removeSubscription(1, 99)).rejects.toThrow(NotFoundException);
    });

    it('deletes and returns deleted:true', async () => {
      prisma.teamSubscription.findFirst.mockResolvedValue({ id: 5 });
      prisma.teamSubscription.delete.mockResolvedValue({});
      expect(await service.removeSubscription(1, 5)).toEqual({ deleted: true });
    });
  });

  // ── findSystems ───────────────────────────────────────────────

  describe('findSystems', () => {
    it('does not include rawData in list (projection check)', async () => {
      prisma.teamSystem.findMany.mockResolvedValue([]);
      await service.findSystems(1);
      const call = prisma.teamSystem.findMany.mock.calls[0][0];
      expect(call.select).toBeDefined();
      expect(call.select.rawData).toBeUndefined();
    });
  });

  // ── createSystem ──────────────────────────────────────────────

  describe('createSystem', () => {
    it('creates system with required name', async () => {
      prisma.teamSystem.create.mockResolvedValue({ id: 1, teamId: 1, name: 'Srv1' });
      const result = await service.createSystem(1, { name: 'Srv1' });
      expect(result).toMatchObject({ name: 'Srv1' });
    });

    it('normalizes hostname and fqdn to lowercase+trim', async () => {
      prisma.teamSystem.create.mockResolvedValue({ id: 1, name: 'Srv' });
      await service.createSystem(1, { name: 'Srv', hostname: '  SRV.EXAMPLE.COM  ', fqdn: '  SRV.EXAMPLE.COM  ' });
      expect(prisma.teamSystem.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ hostname: 'srv.example.com', fqdn: 'srv.example.com' }),
        }),
      );
    });

    it('normalizes name to trimmed', async () => {
      prisma.teamSystem.create.mockResolvedValue({ id: 1, name: 'Srv' });
      await service.createSystem(1, { name: '  Srv  ' });
      expect(prisma.teamSystem.create).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ name: 'Srv' }) }),
      );
    });

    it('persists healthStatus and tags when provided', async () => {
      prisma.teamSystem.create.mockResolvedValue({ id: 1, name: 'Srv' });
      await service.createSystem(1, {
        name: 'Srv',
        healthStatus: ' healthy ',
        tags: ' erp, production ',
      });
      expect(prisma.teamSystem.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            healthStatus: 'healthy',
            tags: 'erp, production',
          }),
        }),
      );
    });
  });

  // ── updateSystem ──────────────────────────────────────────────

  describe('updateSystem', () => {
    it('throws NotFoundException for systemId from different team (IDOR)', async () => {
      prisma.teamSystem.findFirst.mockResolvedValue(null);
      await expect(service.updateSystem(1, 99, { name: 'X' })).rejects.toThrow(NotFoundException);
    });

    it('updates system fields when found', async () => {
      prisma.teamSystem.findFirst.mockResolvedValue({ id: 5 });
      prisma.teamSystem.update.mockResolvedValue({ id: 5, name: 'Updated' });
      const result = await service.updateSystem(1, 5, { name: 'Updated' });
      expect(result).toMatchObject({ name: 'Updated' });
    });

    it('normalizes hostname/fqdn on update', async () => {
      prisma.teamSystem.findFirst.mockResolvedValue({ id: 5 });
      prisma.teamSystem.update.mockResolvedValue({ id: 5 });
      await service.updateSystem(1, 5, { hostname: '  HOST.LOCAL  ' });
      expect(prisma.teamSystem.update).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ hostname: 'host.local' }) }),
      );
    });

    it('updates healthStatus and tags when provided', async () => {
      prisma.teamSystem.findFirst.mockResolvedValue({ id: 5 });
      prisma.teamSystem.update.mockResolvedValue({ id: 5 });
      await service.updateSystem(1, 5, {
        healthStatus: ' degraded ',
        tags: ' critical, erp ',
      });
      expect(prisma.teamSystem.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            healthStatus: 'degraded',
            tags: 'critical, erp',
          }),
        }),
      );
    });

    it('queries system by id AND teamId (IDOR prevention)', async () => {
      prisma.teamSystem.findFirst.mockResolvedValue(null);
      await service.updateSystem(1, 99, {}).catch(() => {});
      expect(prisma.teamSystem.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: 99, teamId: 1 } }),
      );
    });
  });

  // ── removeSystem ──────────────────────────────────────────────

  describe('removeSystem', () => {
    it('throws NotFoundException for systemId from different team (IDOR)', async () => {
      prisma.teamSystem.findFirst.mockResolvedValue(null);
      await expect(service.removeSystem(1, 99)).rejects.toThrow(NotFoundException);
    });

    it('deletes and returns deleted:true', async () => {
      prisma.teamSystem.findFirst.mockResolvedValue({ id: 5 });
      prisma.teamSystem.delete.mockResolvedValue({});
      const result = await service.removeSystem(1, 5);
      expect(result).toEqual({ deleted: true });
    });
  });

  // ── Prisma error mapping ──────────────────────────────────────

  describe('Prisma error mapping', () => {
    it('P2003 maps to BadRequestException', async () => {
      prisma.subscriberTeam.create.mockRejectedValue(Object.assign(new Error(), { code: 'P2003' }));
      await expect(service.createTeam({ name: 'X', code: 'x' })).rejects.toThrow(BadRequestException);
    });

    it('P2025 maps to NotFoundException', async () => {
      prisma.subscriberTeam.findUnique.mockResolvedValue(makeTeam());
      prisma.subscriberTeam.update.mockRejectedValue(Object.assign(new Error(), { code: 'P2025' }));
      await expect(service.updateTeam(1, { name: 'Y' })).rejects.toThrow(NotFoundException);
    });

    it('unknown errors are re-thrown as-is (not leaked as HTTP details)', async () => {
      const internalError = new Error('internal db error');
      prisma.subscriberTeam.create.mockRejectedValue(internalError);
      await expect(service.createTeam({ name: 'X', code: 'x' })).rejects.toThrow('internal db error');
    });
  });
});
