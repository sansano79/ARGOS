import {
  MigrationAnalysisReport,
  UserMigrationCandidate,
  UnresolvedConflictReportItem,
  DuplicateSubscriptionFinding,
  NotificationBackfillItem,
  OrphanNotificationFinding,
  UserSubscriptionItem,
} from '../contracts/migration-status.contract';

export interface RawUserData {
  id: number;
  email: string;
  name: string;
  isSubscriber: boolean;
  isActive: boolean;
  role: string;
}

export interface RawUserSubscriptionData {
  id: number;
  userId: number;
  vendor: string;
  product: string;
  versions: string | null;
  isActive: boolean;
}

export interface RawSubscriberTeamData {
  id: number;
  name: string;
  code: string;
  isActive: boolean;
}

export interface RawTeamMemberData {
  id: number;
  teamId: number;
  userId: number;
  role: string;
  isActive: boolean;
}

export interface RawVulnerabilityNotificationData {
  id: number;
  vulnerabilityId: number;
  subscriberUserId: number | null;
  recipientEmail: string;
  sentAt: Date;
  status: string;
  notificationLogId: number | null;
}

export interface ExplicitMappingConfig {
  userMappings?: Record<
    string | number,
    {
      targetTeamId: number;
      notes?: string;
    }
  >;
}

export interface MigrationEngineInput {
  users: RawUserData[];
  userSubscriptions: RawUserSubscriptionData[];
  teams: RawSubscriberTeamData[];
  teamMembers: RawTeamMemberData[];
  legacyNotifications: RawVulnerabilityNotificationData[];
  explicitMappings?: ExplicitMappingConfig;
}

/**
 * Safely parses versions column (expected to be JSON array or null).
 */
export function parseVersionsColumn(raw: string | null): {
  parsedVersions: string[];
  isValidJsonVersions: boolean;
} {
  if (raw === null || raw === undefined || raw.trim() === '') {
    return { parsedVersions: [], isValidJsonVersions: true };
  }

  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return {
        parsedVersions: parsed.map((v) => String(v).trim().toLowerCase()).filter(Boolean),
        isValidJsonVersions: true,
      };
    }
    // If JSON is valid but not an array (e.g. number or object)
    return {
      parsedVersions: [String(parsed).trim().toLowerCase()],
      isValidJsonVersions: false,
    };
  } catch {
    // Malformed JSON string
    return {
      parsedVersions: [raw.trim().toLowerCase()],
      isValidJsonVersions: false,
    };
  }
}

/**
 * Creates a slug for automatic team code generation.
 */
function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'team';
}

/**
 * Pure, deterministic analysis engine for subscriber-to-team migration.
 * Does not mutate data or execute SQL.
 */
export function analyzeMigration(input: MigrationEngineInput): MigrationAnalysisReport {
  const activeTeamsById = new Map<number, RawSubscriberTeamData>();
  for (const team of input.teams) {
    if (team.isActive) {
      activeTeamsById.set(team.id, team);
    }
  }

  const activeMembershipsByUser = new Map<number, Array<{ teamId: number; role: string }>>();
  for (const member of input.teamMembers) {
    if (member.isActive && activeTeamsById.has(member.teamId)) {
      if (!activeMembershipsByUser.has(member.userId)) {
        activeMembershipsByUser.set(member.userId, []);
      }
      activeMembershipsByUser.get(member.userId)!.push({
        teamId: member.teamId,
        role: member.role,
      });
    }
  }

  const activeSubscriptionsByUser = new Map<number, RawUserSubscriptionData[]>();
  for (const sub of input.userSubscriptions) {
    if (sub.isActive) {
      if (!activeSubscriptionsByUser.has(sub.userId)) {
        activeSubscriptionsByUser.set(sub.userId, []);
      }
      activeSubscriptionsByUser.get(sub.userId)!.push(sub);
    }
  }

  const explicitMappings = input.explicitMappings?.userMappings || {};

  // Sort users by ID for complete determinism
  const sortedUsers = [...input.users].sort((a, b) => a.id - b.id);

  const candidates: UserMigrationCandidate[] = [];
  const unresolvedConflicts: UnresolvedConflictReportItem[] = [];
  const migratableTeamSubscriptions = new Map<
    string,
    {
      vendor: string;
      product: string;
      targetTeamId: number;
      occurrences: Array<{ sourceSubscriptionId: number; sourceUserId: number; versions: string[] }>;
    }
  >();

  let usersWithNoTeam = 0;
  let usersWithSingleTeam = 0;
  let usersWithMultipleTeams = 0;
  let unresolvedConflictUsers = 0;
  let resolvedViaExplicitMappingUsers = 0;
  let migratableSubscriptionsCount = 0;

  for (const user of sortedUsers) {
    // Only analyze users that are subscribers or have active subscriptions
    const rawSubs = activeSubscriptionsByUser.get(user.id) || [];
    const isSubscriber = Boolean(user.isSubscriber);

    if (!isSubscriber && rawSubs.length === 0) {
      continue;
    }

    const memberships = (activeMembershipsByUser.get(user.id) || [])
      .map((m) => {
        const team = activeTeamsById.get(m.teamId)!;
        return {
          teamId: team.id,
          teamName: team.name,
          teamCode: team.code,
          roleInTeam: m.role,
        };
      })
      .sort((a, b) => a.teamId - b.teamId);

    const parsedSubscriptions: UserSubscriptionItem[] = rawSubs
      .map((s) => {
        const { parsedVersions, isValidJsonVersions } = parseVersionsColumn(s.versions);
        return {
          id: s.id,
          vendor: s.vendor.trim().toLowerCase(),
          product: s.product.trim().toLowerCase(),
          rawVersions: s.versions,
          parsedVersions,
          isValidJsonVersions,
        };
      })
      .sort((a, b) => a.vendor.localeCompare(b.vendor) || a.product.localeCompare(b.product));

    let targetTeamId: number | null = null;
    let targetTeamCode: string | undefined;
    let targetTeamName: string | undefined;
    let targetTeamAction: UserMigrationCandidate['targetTeamAction'] = 'NO_OP';
    let resolutionReason: UserMigrationCandidate['resolutionReason'] = 'NO_ACTIVE_SUBSCRIPTIONS';
    let migrationStatus: UserMigrationCandidate['migrationStatus'] = 'LEGACY_ACTIVE';

    const explicitMapping = explicitMappings[user.id] || explicitMappings[String(user.email).toLowerCase()];

    if (memberships.length === 0) {
      usersWithNoTeam++;
      if (parsedSubscriptions.length > 0) {
        targetTeamId = null; // To be provisioned
        targetTeamCode = `TEAM-${user.id}-${slugify(user.name || user.email)}`;
        targetTeamName = `Equipo - ${user.name || user.email}`;
        targetTeamAction = 'PROVISION_INDIVIDUAL';
        resolutionReason = 'AUTO_PROVISIONED_INDIVIDUAL_TEAM';
        migrationStatus = 'PROVISIONED_IN_TEAM';
      } else {
        targetTeamAction = 'NO_OP';
        resolutionReason = 'NO_ACTIVE_SUBSCRIPTIONS';
        migrationStatus = 'LEGACY_ACTIVE';
      }
    } else if (memberships.length === 1) {
      usersWithSingleTeam++;
      const singleTeam = memberships[0];
      targetTeamId = singleTeam.teamId;
      targetTeamCode = singleTeam.teamCode;
      targetTeamName = singleTeam.teamName;
      targetTeamAction = 'MAP_TO_EXISTING';
      resolutionReason = 'SINGLE_ACTIVE_MEMBERSHIP';
      migrationStatus = parsedSubscriptions.length > 0 ? 'PROVISIONED_IN_TEAM' : 'LEGACY_ACTIVE';
    } else {
      // Multiple team memberships
      usersWithMultipleTeams++;
      if (explicitMapping && activeTeamsById.has(explicitMapping.targetTeamId)) {
        resolvedViaExplicitMappingUsers++;
        const targetTeam = activeTeamsById.get(explicitMapping.targetTeamId)!;
        targetTeamId = targetTeam.id;
        targetTeamCode = targetTeam.code;
        targetTeamName = targetTeam.name;
        targetTeamAction = 'MAP_TO_EXISTING';
        resolutionReason = 'EXPLICIT_MAPPING_RESOLVED';
        migrationStatus = 'PROVISIONED_IN_TEAM';
      } else if (parsedSubscriptions.length === 0) {
        // User has multiple teams but no legacy subscriptions to migrate
        targetTeamId = null;
        targetTeamAction = 'NO_OP';
        resolutionReason = 'NO_ACTIVE_SUBSCRIPTIONS';
        migrationStatus = 'LEGACY_ACTIVE';
      } else {
        // Unresolved conflict!
        unresolvedConflictUsers++;
        targetTeamId = null;
        targetTeamAction = 'RETAIN_LEGACY_CONFLICT';
        resolutionReason = 'UNRESOLVED_MULTI_MEMBERSHIP';
        migrationStatus = 'MIGRATION_CONFLICT_PENDING_REVIEW';

        unresolvedConflicts.push({
          userId: user.id,
          email: user.email,
          name: user.name,
          activeSubscriptionsCount: parsedSubscriptions.length,
          subscriptions: parsedSubscriptions.map((s) => ({
            id: s.id,
            vendor: s.vendor,
            product: s.product,
          })),
          candidateTeams: memberships,
          requiredAction: 'Definir asignacion formal en mappings.json para evitar desvio de alertas',
        });
      }
    }

    // Accumulate migratable subscriptions if target team is determined
    if (targetTeamId !== null && parsedSubscriptions.length > 0) {
      for (const s of parsedSubscriptions) {
        migratableSubscriptionsCount++;
        const key = `${targetTeamId}:${s.vendor}:${s.product}`;
        if (!migratableTeamSubscriptions.has(key)) {
          migratableTeamSubscriptions.set(key, {
            vendor: s.vendor,
            product: s.product,
            targetTeamId,
            occurrences: [],
          });
        }
        migratableTeamSubscriptions.get(key)!.occurrences.push({
          sourceSubscriptionId: s.id,
          sourceUserId: user.id,
          versions: s.parsedVersions,
        });
      }
    }

    candidates.push({
      userId: user.id,
      email: user.email,
      name: user.name,
      isSubscriber: Boolean(user.isSubscriber),
      globalRole: user.role,
      activeTeamMemberships: memberships,
      activeSubscriptions: parsedSubscriptions,
      targetTeamId,
      targetTeamCode,
      targetTeamName,
      targetTeamAction,
      resolutionReason,
      migrationStatus,
    });
  }

  // Detect duplicates across merged team subscriptions
  const duplicateSubscriptions: DuplicateSubscriptionFinding[] = [];
  for (const group of migratableTeamSubscriptions.values()) {
    if (group.occurrences.length > 1) {
      const mergedVersions = Array.from(
        new Set(group.occurrences.flatMap((o) => o.versions)),
      ).sort();
      duplicateSubscriptions.push({
        vendor: group.vendor,
        product: group.product,
        targetTeamId: group.targetTeamId,
        occurrences: group.occurrences,
        mergedVersions,
      });
    }
  }

  // Analyze legacy notifications
  const usersById = new Map<number, RawUserData>();
  for (const u of input.users) {
    usersById.set(u.id, u);
  }

  const resolvedTargetTeamByUserId = new Map<number, number>();
  for (const c of candidates) {
    if (c.targetTeamId !== null) {
      resolvedTargetTeamByUserId.set(c.userId, c.targetTeamId);
    }
  }

  const orphanNotifications: OrphanNotificationFinding[] = [];
  const backfillSample: NotificationBackfillItem[] = [];
  let backfillableCount = 0;

  // Deduplicate legacy notifications for same vulnerability & target team
  const backfillKeysSeen = new Set<string>();

  for (const notif of input.legacyNotifications) {
    if (!notif.subscriberUserId) {
      orphanNotifications.push({
        notificationId: notif.id,
        vulnerabilityId: notif.vulnerabilityId,
        subscriberUserId: null,
        recipientEmail: notif.recipientEmail,
        sentAt: notif.sentAt,
        reason: 'USER_NOT_FOUND',
      });
      continue;
    }

    const sourceUser = usersById.get(notif.subscriberUserId);
    if (!sourceUser) {
      orphanNotifications.push({
        notificationId: notif.id,
        vulnerabilityId: notif.vulnerabilityId,
        subscriberUserId: notif.subscriberUserId,
        recipientEmail: notif.recipientEmail,
        sentAt: notif.sentAt,
        reason: 'USER_NOT_FOUND',
      });
      continue;
    }

    if (!sourceUser.isActive) {
      orphanNotifications.push({
        notificationId: notif.id,
        vulnerabilityId: notif.vulnerabilityId,
        subscriberUserId: notif.subscriberUserId,
        recipientEmail: notif.recipientEmail,
        sentAt: notif.sentAt,
        reason: 'USER_INACTIVE',
      });
      continue;
    }

    const targetTeamId = resolvedTargetTeamByUserId.get(sourceUser.id);
    if (targetTeamId !== undefined) {
      const dedupeKey = `${targetTeamId}:${notif.vulnerabilityId}`;
      if (!backfillKeysSeen.has(dedupeKey)) {
        backfillKeysSeen.add(dedupeKey);
        backfillableCount++;
        if (backfillSample.length < 50) {
          backfillSample.push({
            vulnerabilityId: notif.vulnerabilityId,
            sourceNotificationId: notif.id,
            sourceSubscriberUserId: sourceUser.id,
            targetTeamId,
            sentAt: notif.sentAt,
            status: notif.status,
            notificationLogId: notif.notificationLogId,
          });
        }
      }
    }
  }

  return {
    generatedAt: new Date().toISOString(),
    executionMode: 'DRY_RUN',
    isDeterministic: true,

    summary: {
      totalUsersEvaluated: candidates.length,
      totalSubscribers: candidates.filter((c) => c.isSubscriber).length,
      usersWithNoTeam,
      usersWithSingleTeam,
      usersWithMultipleTeams,
      unresolvedConflictUsers,
      resolvedViaExplicitMappingUsers,

      totalLegacySubscriptions: input.userSubscriptions.filter((s) => s.isActive).length,
      migratableSubscriptionsCount,
      duplicateSubscriptionGroupsCount: duplicateSubscriptions.length,

      totalLegacyNotifications: input.legacyNotifications.length,
      backfillableNotificationsCount: backfillableCount,
      orphanNotificationsCount: orphanNotifications.length,
    },

    users: candidates,
    unresolvedConflicts,
    duplicateSubscriptions,
    orphanNotifications,
    backfillSample,
  };
}
