import * as bcrypt from 'bcrypt';
import {
  TEST_RECIPIENTS,
  TEST_SUBSCRIPTIONS,
  TEST_SYSTEMS,
  TEST_TEAMS,
  TEST_USERS,
} from './test-data.definitions';
import {
  assertCleanupAllowed,
  assertNoSecretInLogs,
  assertTestDataExecutionAllowed,
  buildTestDataSummary,
  getCleanupPrefixes,
  getSerializedTags,
  validateTestUserMemberships,
} from './test-data.utils';

type LoggerFn = (line: string) => void;

export const runSeedTestData = async (
  prisma: any,
  config: { enabled?: string; occEnv?: string; password?: string; dryRun?: boolean },
  log: LoggerFn = console.log,
) => {
  const password = String(config.password || '');
  assertTestDataExecutionAllowed(config);
  validateTestUserMemberships();

  const summary = buildTestDataSummary();
  const summaryLine = `[seed:test-data] Teams=${summary.teams} Users=${summary.users} Memberships=${summary.memberships} Recipients=${summary.recipients} Subscriptions=${summary.subscriptions} Systems=${summary.systems}`;
  assertNoSecretInLogs(summaryLine, password);
  log(summaryLine);

  if (config.dryRun) {
    log('[seed:test-data] Dry run mode enabled; no database writes will be performed');
    log('[seed:test-data] Completed dry run successfully');
    return;
  }

  const passwordHash = await bcrypt.hash(password, 12);

  await prisma.$transaction(async (tx: any) => {
    const teamsByCode = new Map<string, number>();

    for (const team of TEST_TEAMS) {
      const record = await tx.subscriberTeam.upsert({
        where: { code: team.code },
        update: {
          name: team.name,
          description: team.description,
          isActive: team.isActive,
        },
        create: {
          code: team.code,
          name: team.name,
          description: team.description,
          isActive: team.isActive,
        },
      });
      teamsByCode.set(team.code, record.id);
    }

    const usersByEmail = new Map<string, number>();
    for (const user of TEST_USERS) {
      const record = await tx.user.upsert({
        where: { email: user.email },
        update: {
          name: user.name,
          role: user.role,
          authProvider: 'LOCAL',
          canLogin: user.canLogin,
          isActive: user.isActive,
          passwordHash: user.canLogin ? passwordHash : null,
          isSubscriber: false,
          notificationEmail: null,
          canReceiveNotifications: false,
          notificationsPaused: false,
          notificationsPausedUntil: null,
          communicationLanguage: 'es',
          contactPerson: null,
          department: null,
          phone: null,
          notes: 'TEST data account',
          mfaEnabled: false,
          mfaSecretEnc: null,
          mfaSecretIv: null,
          mfaSecretTag: null,
        },
        create: {
          email: user.email,
          name: user.name,
          role: user.role,
          authProvider: 'LOCAL',
          canLogin: user.canLogin,
          isActive: user.isActive,
          passwordHash: user.canLogin ? passwordHash : null,
          isSubscriber: false,
          notificationEmail: null,
          canReceiveNotifications: false,
          notificationsPaused: false,
          notificationsPausedUntil: null,
          communicationLanguage: 'es',
          notes: 'TEST data account',
          mfaEnabled: false,
        },
      });
      usersByEmail.set(user.email, record.id);
    }

    for (const user of TEST_USERS) {
      const userId = usersByEmail.get(user.email);
      if (!userId) throw new Error(`Missing seeded user ${user.email}`);

      for (const membership of user.memberships) {
        const teamId = teamsByCode.get(membership.teamCode);
        if (!teamId) throw new Error(`Missing seeded team ${membership.teamCode}`);
        await tx.teamMember.upsert({
          where: { teamId_userId: { teamId, userId } },
          update: {
            role: membership.role,
            isActive: true,
          },
          create: {
            teamId,
            userId,
            role: membership.role,
            isActive: true,
          },
        });
      }
    }

    for (const recipient of TEST_RECIPIENTS) {
      const teamId = teamsByCode.get(recipient.teamCode);
      if (!teamId) throw new Error(`Missing team for recipient ${recipient.email}`);
      await tx.notificationRecipient.upsert({
        where: { teamId_email: { teamId, email: recipient.email } },
        update: {
          name: recipient.name,
          type: recipient.type,
          language: recipient.language,
          timezone: recipient.timezone,
          isActive: recipient.isActive,
        },
        create: {
          teamId,
          email: recipient.email,
          name: recipient.name,
          type: recipient.type,
          language: recipient.language,
          timezone: recipient.timezone,
          isActive: recipient.isActive,
        },
      });
    }

    for (const subscription of TEST_SUBSCRIPTIONS) {
      const teamId = teamsByCode.get(subscription.teamCode);
      if (!teamId) throw new Error(`Missing team for subscription ${subscription.vendor}/${subscription.product}`);
      await tx.teamSubscription.upsert({
        where: { teamId_vendor_product: { teamId, vendor: subscription.vendor, product: subscription.product } },
        update: {
          versions: JSON.stringify(subscription.versions),
          isActive: subscription.isActive,
        },
        create: {
          teamId,
          vendor: subscription.vendor,
          product: subscription.product,
          versions: JSON.stringify(subscription.versions),
          isActive: subscription.isActive,
        },
      });
    }

    for (const system of TEST_SYSTEMS) {
      const teamId = teamsByCode.get(system.teamCode);
      if (!teamId) throw new Error(`Missing team for system ${system.externalId}`);
      await tx.teamSystem.upsert({
        where: { teamId_externalId: { teamId, externalId: system.externalId } },
        update: {
          name: system.name,
          source: system.source,
          hostname: system.hostname,
          fqdn: system.fqdn,
          platform: system.platform,
          osVersion: system.osVersion,
          riskLevel: system.riskLevel,
          healthStatus: system.healthStatus,
          isSelected: true,
          isActive: true,
          tags: getSerializedTags(system.tags),
          rawData: null,
          description: null,
        },
        create: {
          teamId,
          externalId: system.externalId,
          source: system.source,
          name: system.name,
          hostname: system.hostname,
          fqdn: system.fqdn,
          platform: system.platform,
          osVersion: system.osVersion,
          riskLevel: system.riskLevel,
          healthStatus: system.healthStatus,
          isSelected: true,
          isActive: true,
          tags: getSerializedTags(system.tags),
          rawData: null,
        },
      });
    }
  });

  log('[seed:test-data] Completed successfully');
};

export const runCleanupTestData = async (
  prisma: any,
  config: { enabled?: string; occEnv?: string; confirm?: boolean; dryRun?: boolean },
  log: LoggerFn = console.log,
) => {
  assertCleanupAllowed(config);
  const { userEmailPrefix, teamCodePrefix } = getCleanupPrefixes();

  if (config.dryRun) {
    log(`[cleanup:test-data] Dry run mode enabled; would target users starting with ${userEmailPrefix} and teams starting with ${teamCodePrefix}`);
    log('[cleanup:test-data] Completed dry run successfully');
    return;
  }

  const [users, teams] = await Promise.all([
    prisma.user.findMany({
      where: { email: { startsWith: userEmailPrefix } },
      select: { id: true, email: true },
      orderBy: { email: 'asc' },
    }),
    prisma.subscriberTeam.findMany({
      where: { code: { startsWith: teamCodePrefix } },
      select: { id: true, code: true },
      orderBy: { code: 'asc' },
    }),
  ]);

  const userIds = users.map((user: any) => user.id);
  const teamIds = teams.map((team: any) => team.id);

  const [recipientCount, subscriptionCount, systemCount, membershipCount] = await Promise.all([
    prisma.notificationRecipient.count({ where: { teamId: { in: teamIds } } }),
    prisma.teamSubscription.count({ where: { teamId: { in: teamIds } } }),
    prisma.teamSystem.count({ where: { teamId: { in: teamIds } } }),
    prisma.teamMember.count({ where: { OR: [{ teamId: { in: teamIds } }, { userId: { in: userIds } }] } }),
  ]);

  log(`[cleanup:test-data] Users=${users.length} Teams=${teams.length} Memberships=${membershipCount} Recipients=${recipientCount} Subscriptions=${subscriptionCount} Systems=${systemCount}`);

  await prisma.$transaction(async (tx: any) => {
    if (teamIds.length > 0) {
      await tx.notificationRecipient.deleteMany({ where: { teamId: { in: teamIds } } });
      await tx.teamSubscription.deleteMany({ where: { teamId: { in: teamIds } } });
      await tx.teamSystem.deleteMany({ where: { teamId: { in: teamIds } } });
      await tx.teamMember.deleteMany({ where: { teamId: { in: teamIds } } });
      await tx.subscriberTeam.deleteMany({ where: { id: { in: teamIds } } });
    }

    if (userIds.length > 0) {
      await tx.teamMember.deleteMany({ where: { userId: { in: userIds } } });
      await tx.userSubscription.deleteMany({ where: { userId: { in: userIds } } });
      await tx.pendingDigestNotification.deleteMany({ where: { userId: { in: userIds } } });
      await tx.loginAttempt.deleteMany({ where: { email: { startsWith: userEmailPrefix } } });
      await tx.user.deleteMany({
        where: {
          id: { in: userIds },
          email: { startsWith: userEmailPrefix },
          NOT: { email: 'admin@occ.local' },
        },
      });
    }
  });

  log('[cleanup:test-data] Completed successfully');
};
