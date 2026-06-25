import { runCleanupTestData, runSeedTestData } from './test-data.executor';
import { TEST_RECIPIENTS, TEST_SUBSCRIPTIONS, TEST_SYSTEMS, TEST_TEAMS, TEST_USERS } from './test-data.definitions';

jest.mock('bcrypt', () => ({
  hash: jest.fn().mockResolvedValue('hashed-test-password'),
}));

describe('test-data executor', () => {
  const makePrisma = () => {
    const tx = {
      subscriberTeam: { upsert: jest.fn(), deleteMany: jest.fn() },
      user: { upsert: jest.fn(), deleteMany: jest.fn() },
      teamMember: { upsert: jest.fn(), deleteMany: jest.fn(), count: jest.fn() },
      notificationRecipient: { upsert: jest.fn(), deleteMany: jest.fn(), count: jest.fn() },
      teamSubscription: { upsert: jest.fn(), deleteMany: jest.fn(), count: jest.fn() },
      teamSystem: { upsert: jest.fn(), deleteMany: jest.fn(), count: jest.fn() },
      userSubscription: { deleteMany: jest.fn() },
      pendingDigestNotification: { deleteMany: jest.fn() },
      loginAttempt: { deleteMany: jest.fn() },
    };

    const prisma = {
      ...tx,
      user: {
        ...tx.user,
        findMany: jest.fn(),
      },
      subscriberTeam: {
        ...tx.subscriberTeam,
        findMany: jest.fn(),
      },
      $transaction: jest.fn(async (callback: any) => callback(tx)),
    } as any;

    return { prisma, tx };
  };

  it('creates the full test fixture set idempotently via upserts', async () => {
    const { prisma, tx } = makePrisma();
    const logs: string[] = [];
    let teamId = 100;
    let userId = 200;

    tx.subscriberTeam.upsert.mockImplementation(async ({ where }: any) => ({ id: teamId++, code: where.code }));
    tx.user.upsert.mockImplementation(async ({ where }: any) => ({ id: userId++, email: where.email }));

    await runSeedTestData(prisma, {
      enabled: 'true',
      occEnv: 'development',
      password: 'ChangeMeNow!123',
    }, (line) => logs.push(line));

    expect(tx.subscriberTeam.upsert).toHaveBeenCalledTimes(TEST_TEAMS.length);
    expect(tx.user.upsert).toHaveBeenCalledTimes(TEST_USERS.length);
    expect(tx.teamMember.upsert).toHaveBeenCalledTimes(TEST_USERS.reduce((count, user) => count + user.memberships.length, 0));
    expect(tx.notificationRecipient.upsert).toHaveBeenCalledTimes(TEST_RECIPIENTS.length);
    expect(tx.teamSubscription.upsert).toHaveBeenCalledTimes(TEST_SUBSCRIPTIONS.length);
    expect(tx.teamSystem.upsert).toHaveBeenCalledTimes(TEST_SYSTEMS.length);
    expect(logs).toContain('[seed:test-data] Completed successfully');

    const viewerOnlyUser = TEST_USERS.find((user) => user.email === 'test.viewer.it@occ.local');
    expect(viewerOnlyUser?.memberships.every((membership) => membership.role === 'TEAM_VIEWER')).toBe(true);

    const unassignedManager = TEST_USERS.find((user) => user.email === 'test.manager.unassigned@occ.local');
    expect(unassignedManager?.memberships).toEqual([]);
  });

  it('never logs the configured password', async () => {
    const { prisma, tx } = makePrisma();
    const logs: string[] = [];
    let teamId = 1;
    let userId = 1;

    tx.subscriberTeam.upsert.mockImplementation(async () => ({ id: teamId++ }));
    tx.user.upsert.mockImplementation(async () => ({ id: userId++ }));

    await runSeedTestData(prisma, {
      enabled: 'true',
      occEnv: 'development',
      password: 'SuperSecret!123',
    }, (line) => logs.push(line));

    expect(logs.some((line) => line.includes('SuperSecret!123'))).toBe(false);
  });

  it('cleanup removes only test-scoped objects and keeps real users safe', async () => {
    const { prisma, tx } = makePrisma();
    const logs: string[] = [];

    prisma.user.findMany.mockResolvedValue([
      { id: 1, email: 'test.admin@occ.local' },
      { id: 2, email: 'test.viewer.it@occ.local' },
    ]);
    prisma.subscriberTeam.findMany.mockResolvedValue([
      { id: 11, code: 'test-it-global' },
      { id: 12, code: 'test-infra' },
    ]);
    prisma.notificationRecipient.count.mockResolvedValue(4);
    prisma.teamSubscription.count.mockResolvedValue(3);
    prisma.teamSystem.count.mockResolvedValue(2);
    prisma.teamMember.count.mockResolvedValue(5);

    await runCleanupTestData(prisma, {
      enabled: 'true',
      occEnv: 'development',
      confirm: true,
    }, (line) => logs.push(line));

    expect(tx.notificationRecipient.deleteMany).toHaveBeenCalledWith({ where: { teamId: { in: [11, 12] } } });
    expect(tx.teamSubscription.deleteMany).toHaveBeenCalledWith({ where: { teamId: { in: [11, 12] } } });
    expect(tx.teamSystem.deleteMany).toHaveBeenCalledWith({ where: { teamId: { in: [11, 12] } } });
    expect(tx.subscriberTeam.deleteMany).toHaveBeenCalledWith({ where: { id: { in: [11, 12] } } });
    expect(tx.user.deleteMany).toHaveBeenCalledWith({
      where: {
        id: { in: [1, 2] },
        email: { startsWith: 'test.' },
        NOT: { email: 'admin@occ.local' },
      },
    });
    expect(logs).toContain('[cleanup:test-data] Completed successfully');
  });

  it('seed dry run does not hash passwords or write to the database', async () => {
    const { prisma, tx } = makePrisma();
    const logs: string[] = [];

    await runSeedTestData(prisma, {
      enabled: 'true',
      occEnv: 'test',
      password: 'ChangeMeNow!123',
      dryRun: true,
    }, (line) => logs.push(line));

    expect(prisma.$transaction).not.toHaveBeenCalled();
    expect(tx.subscriberTeam.upsert).not.toHaveBeenCalled();
    expect(logs).toContain('[seed:test-data] Dry run mode enabled; no database writes will be performed');
  });

  it('cleanup dry run does not read or delete data', async () => {
    const { prisma, tx } = makePrisma();
    const logs: string[] = [];

    await runCleanupTestData(prisma, {
      enabled: 'true',
      occEnv: 'test',
      confirm: true,
      dryRun: true,
    }, (line) => logs.push(line));

    expect(prisma.user.findMany).not.toHaveBeenCalled();
    expect(prisma.subscriberTeam.findMany).not.toHaveBeenCalled();
    expect(prisma.$transaction).not.toHaveBeenCalled();
    expect(tx.user.deleteMany).not.toHaveBeenCalled();
    expect(logs).toContain('[cleanup:test-data] Completed dry run successfully');
  });
});
