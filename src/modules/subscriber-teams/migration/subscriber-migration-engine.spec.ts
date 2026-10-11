import {
  analyzeMigration,
  parseVersionsColumn,
  MigrationEngineInput,
} from './subscriber-migration-engine';

describe('SubscriberMigrationEngine Unit Tests (Pure Logic, 10 Scenarios)', () => {
  const baseTeam1 = { id: 10, name: 'Team Alpha', code: 'TEAM-ALPHA', isActive: true };
  const baseTeam2 = { id: 20, name: 'Team Beta', code: 'TEAM-BETA', isActive: true };

  // 1. Usuario sin equipo
  it('1. handles subscriber user with no team -> proposes PROVISION_INDIVIDUAL', () => {
    const input: MigrationEngineInput = {
      users: [
        { id: 1, email: 'solo@example.com', name: 'Solo User', isSubscriber: true, isActive: true, role: 'SUBSCRIBER' },
      ],
      userSubscriptions: [
        { id: 101, userId: 1, vendor: 'nginx', product: 'nginx', versions: '["1.20"]', isActive: true },
      ],
      teams: [],
      teamMembers: [],
      legacyNotifications: [],
    };

    const report = analyzeMigration(input);

    expect(report.summary.usersWithNoTeam).toBe(1);
    expect(report.summary.unresolvedConflictUsers).toBe(0);
    const candidate = report.users.find((u) => u.userId === 1)!;
    expect(candidate.targetTeamAction).toBe('PROVISION_INDIVIDUAL');
    expect(candidate.resolutionReason).toBe('AUTO_PROVISIONED_INDIVIDUAL_TEAM');
    expect(candidate.targetTeamCode).toContain('TEAM-1-solo-user');
    expect(candidate.migrationStatus).toBe('PROVISIONED_IN_TEAM');
  });

  // 2. Usuario con un equipo
  it('2. handles subscriber user with single team -> maps to existing team', () => {
    const input: MigrationEngineInput = {
      users: [
        { id: 2, email: 'member@example.com', name: 'Member User', isSubscriber: true, isActive: true, role: 'SUBSCRIBER' },
      ],
      userSubscriptions: [
        { id: 102, userId: 2, vendor: 'apache', product: 'tomcat', versions: '["9.0"]', isActive: true },
      ],
      teams: [baseTeam1],
      teamMembers: [
        { id: 1, teamId: 10, userId: 2, role: 'TEAM_MANAGER', isActive: true },
      ],
      legacyNotifications: [],
    };

    const report = analyzeMigration(input);

    expect(report.summary.usersWithSingleTeam).toBe(1);
    const candidate = report.users.find((u) => u.userId === 2)!;
    expect(candidate.targetTeamAction).toBe('MAP_TO_EXISTING');
    expect(candidate.targetTeamId).toBe(10);
    expect(candidate.resolutionReason).toBe('SINGLE_ACTIVE_MEMBERSHIP');
    expect(candidate.migrationStatus).toBe('PROVISIONED_IN_TEAM');
  });

  // 3. Usuario con varios equipos sin mapping
  it('3. handles subscriber user with multiple teams without mapping -> marks UNRESOLVED_MULTI_MEMBERSHIP conflict', () => {
    const input: MigrationEngineInput = {
      users: [
        { id: 3, email: 'multi@example.com', name: 'Multi User', isSubscriber: true, isActive: true, role: 'SUBSCRIBER' },
      ],
      userSubscriptions: [
        { id: 103, userId: 3, vendor: 'oracle', product: 'database', versions: '["19c"]', isActive: true },
      ],
      teams: [baseTeam1, baseTeam2],
      teamMembers: [
        { id: 2, teamId: 10, userId: 3, role: 'TEAM_VIEWER', isActive: true },
        { id: 3, teamId: 20, userId: 3, role: 'TEAM_MANAGER', isActive: true },
      ],
      legacyNotifications: [],
    };

    const report = analyzeMigration(input);

    expect(report.summary.usersWithMultipleTeams).toBe(1);
    expect(report.summary.unresolvedConflictUsers).toBe(1);
    const candidate = report.users.find((u) => u.userId === 3)!;
    expect(candidate.targetTeamAction).toBe('RETAIN_LEGACY_CONFLICT');
    expect(candidate.targetTeamId).toBeNull();
    expect(candidate.migrationStatus).toBe('MIGRATION_CONFLICT_PENDING_REVIEW');
    expect(report.unresolvedConflicts).toHaveLength(1);
    expect(report.unresolvedConflicts[0].candidateTeams).toHaveLength(2);
  });

  // 4. Usuario con varios equipos con mapping
  it('4. handles subscriber user with multiple teams resolved via explicit mappings.json', () => {
    const input: MigrationEngineInput = {
      users: [
        { id: 4, email: 'resolved@example.com', name: 'Resolved User', isSubscriber: true, isActive: true, role: 'SUBSCRIBER' },
      ],
      userSubscriptions: [
        { id: 104, userId: 4, vendor: 'redis', product: 'redis', versions: '["7.0"]', isActive: true },
      ],
      teams: [baseTeam1, baseTeam2],
      teamMembers: [
        { id: 4, teamId: 10, userId: 4, role: 'TEAM_VIEWER', isActive: true },
        { id: 5, teamId: 20, userId: 4, role: 'TEAM_MANAGER', isActive: true },
      ],
      legacyNotifications: [],
      explicitMappings: {
        userMappings: {
          4: { targetTeamId: 20, notes: 'Designated to Team Beta' },
        },
      },
    };

    const report = analyzeMigration(input);

    expect(report.summary.resolvedViaExplicitMappingUsers).toBe(1);
    expect(report.summary.unresolvedConflictUsers).toBe(0);
    const candidate = report.users.find((u) => u.userId === 4)!;
    expect(candidate.targetTeamAction).toBe('MAP_TO_EXISTING');
    expect(candidate.targetTeamId).toBe(20);
    expect(candidate.resolutionReason).toBe('EXPLICIT_MAPPING_RESOLVED');
  });

  // 5. Suscripciones duplicadas
  it('5. detects duplicate subscriptions when two members of the same team subscribe to same vendor/product', () => {
    const input: MigrationEngineInput = {
      users: [
        { id: 5, email: 'u5@example.com', name: 'User 5', isSubscriber: true, isActive: true, role: 'SUBSCRIBER' },
        { id: 6, email: 'u6@example.com', name: 'User 6', isSubscriber: true, isActive: true, role: 'SUBSCRIBER' },
      ],
      userSubscriptions: [
        { id: 105, userId: 5, vendor: 'nginx', product: 'nginx', versions: '["1.18", "1.19"]', isActive: true },
        { id: 106, userId: 6, vendor: 'nginx', product: 'nginx', versions: '["1.19", "1.20"]', isActive: true },
      ],
      teams: [baseTeam1],
      teamMembers: [
        { id: 6, teamId: 10, userId: 5, role: 'TEAM_MANAGER', isActive: true },
        { id: 7, teamId: 10, userId: 6, role: 'TEAM_VIEWER', isActive: true },
      ],
      legacyNotifications: [],
    };

    const report = analyzeMigration(input);

    expect(report.summary.duplicateSubscriptionGroupsCount).toBe(1);
    expect(report.duplicateSubscriptions).toHaveLength(1);
    const dupe = report.duplicateSubscriptions[0];
    expect(dupe.vendor).toBe('nginx');
    expect(dupe.product).toBe('nginx');
    expect(dupe.targetTeamId).toBe(10);
    expect(dupe.mergedVersions).toEqual(['1.18', '1.19', '1.20']);
  });

  // 6. Versiones JSON inválidas
  it('6. safely handles invalid and malformed JSON versions without crashing', () => {
    const valid = parseVersionsColumn('["1.0", "2.0"]');
    expect(valid.isValidJsonVersions).toBe(true);
    expect(valid.parsedVersions).toEqual(['1.0', '2.0']);

    const malformed = parseVersionsColumn('v1.0, v2.0 not valid json');
    expect(malformed.isValidJsonVersions).toBe(false);
    expect(malformed.parsedVersions).toEqual(['v1.0, v2.0 not valid json']);

    const empty = parseVersionsColumn(null);
    expect(empty.isValidJsonVersions).toBe(true);
    expect(empty.parsedVersions).toEqual([]);
  });

  // 7. Usuario sin suscripciones
  it('7. handles subscriber user with no active subscriptions -> NO_OP', () => {
    const input: MigrationEngineInput = {
      users: [
        { id: 7, email: 'nosubs@example.com', name: 'No Subs User', isSubscriber: true, isActive: true, role: 'SUBSCRIBER' },
      ],
      userSubscriptions: [],
      teams: [baseTeam1],
      teamMembers: [
        { id: 8, teamId: 10, userId: 7, role: 'TEAM_VIEWER', isActive: true },
      ],
      legacyNotifications: [],
    };

    const report = analyzeMigration(input);

    const candidate = report.users.find((u) => u.userId === 7)!;
    expect(candidate.activeSubscriptions).toHaveLength(0);
    expect(candidate.migrationStatus).toBe('LEGACY_ACTIVE');
  });

  // 8. Alerta legacy sin usuario
  it('8. classifies legacy notification with null subscriberUserId as orphan', () => {
    const input: MigrationEngineInput = {
      users: [],
      userSubscriptions: [],
      teams: [],
      teamMembers: [],
      legacyNotifications: [
        {
          id: 501,
          vulnerabilityId: 99,
          subscriberUserId: null,
          recipientEmail: 'orphan@example.com',
          sentAt: new Date('2026-01-01'),
          status: 'sent',
          notificationLogId: null,
        },
      ],
    };

    const report = analyzeMigration(input);

    expect(report.summary.orphanNotificationsCount).toBe(1);
    expect(report.orphanNotifications[0].reason).toBe('USER_NOT_FOUND');
  });

  // 9. Alerta legacy enviada varias veces
  it('9. deduplicates multiple historical notifications for the same vulnerability into single backfill item', () => {
    const input: MigrationEngineInput = {
      users: [
        { id: 9, email: 'notified@example.com', name: 'Notified User', isSubscriber: true, isActive: true, role: 'SUBSCRIBER' },
      ],
      userSubscriptions: [
        { id: 109, userId: 9, vendor: 'nginx', product: 'nginx', versions: '["1.20"]', isActive: true },
      ],
      teams: [baseTeam1],
      teamMembers: [
        { id: 9, teamId: 10, userId: 9, role: 'TEAM_MANAGER', isActive: true },
      ],
      legacyNotifications: [
        {
          id: 601,
          vulnerabilityId: 1234,
          subscriberUserId: 9,
          recipientEmail: 'notified@example.com',
          sentAt: new Date('2026-02-01'),
          status: 'sent',
          notificationLogId: 11,
        },
        {
          id: 602,
          vulnerabilityId: 1234, // same vulnerability sent again (e.g. retry or reminder)
          subscriberUserId: 9,
          recipientEmail: 'notified@example.com',
          sentAt: new Date('2026-02-02'),
          status: 'sent',
          notificationLogId: 12,
        },
      ],
    };

    const report = analyzeMigration(input);

    expect(report.summary.totalLegacyNotifications).toBe(2);
    // Backfillable distinct alerts should be exactly 1!
    expect(report.summary.backfillableNotificationsCount).toBe(1);
  });

  // 10. Ejecución repetida del dry-run con salida determinista
  it('10. produces 100% deterministic report output across repeated runs with unordered input', () => {
    const inputA: MigrationEngineInput = {
      users: [
        { id: 2, email: 'b@example.com', name: 'B', isSubscriber: true, isActive: true, role: 'SUBSCRIBER' },
        { id: 1, email: 'a@example.com', name: 'A', isSubscriber: true, isActive: true, role: 'SUBSCRIBER' },
      ],
      userSubscriptions: [
        { id: 20, userId: 2, vendor: 'redis', product: 'redis', versions: '["6"]', isActive: true },
        { id: 10, userId: 1, vendor: 'nginx', product: 'nginx', versions: '["1"]', isActive: true },
      ],
      teams: [baseTeam1],
      teamMembers: [
        { id: 2, teamId: 10, userId: 2, role: 'TEAM_VIEWER', isActive: true },
        { id: 1, teamId: 10, userId: 1, role: 'TEAM_MANAGER', isActive: true },
      ],
      legacyNotifications: [],
    };

    const inputB: MigrationEngineInput = {
      users: [
        { id: 1, email: 'a@example.com', name: 'A', isSubscriber: true, isActive: true, role: 'SUBSCRIBER' },
        { id: 2, email: 'b@example.com', name: 'B', isSubscriber: true, isActive: true, role: 'SUBSCRIBER' },
      ],
      userSubscriptions: [
        { id: 10, userId: 1, vendor: 'nginx', product: 'nginx', versions: '["1"]', isActive: true },
        { id: 20, userId: 2, vendor: 'redis', product: 'redis', versions: '["6"]', isActive: true },
      ],
      teams: [baseTeam1],
      teamMembers: [
        { id: 1, teamId: 10, userId: 1, role: 'TEAM_MANAGER', isActive: true },
        { id: 2, teamId: 10, userId: 2, role: 'TEAM_VIEWER', isActive: true },
      ],
      legacyNotifications: [],
    };

    const reportA = analyzeMigration(inputA);
    const reportB = analyzeMigration(inputB);

    // Summary counts must be strictly equal
    expect(reportA.summary).toEqual(reportB.summary);
    // User ordering must be normalized by id
    expect(reportA.users.map((u) => u.userId)).toEqual([1, 2]);
    expect(reportB.users.map((u) => u.userId)).toEqual([1, 2]);
  });
});
