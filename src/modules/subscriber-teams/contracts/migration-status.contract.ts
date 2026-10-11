export type UserMigrationStatus =
  | 'LEGACY_ACTIVE'
  | 'PROVISIONED_IN_TEAM'
  | 'MIGRATION_CONFLICT_PENDING_REVIEW'
  | 'SHADOW_VERIFIED'
  | 'CUTOVER_TEAMS'
  | 'LEGACY_DEPRECATED';

export type ConflictResolutionReason =
  | 'SINGLE_ACTIVE_MEMBERSHIP'
  | 'AUTO_PROVISIONED_INDIVIDUAL_TEAM'
  | 'NO_ACTIVE_SUBSCRIPTIONS'
  | 'EXPLICIT_MAPPING_RESOLVED'
  | 'UNRESOLVED_MULTI_MEMBERSHIP';

export type TargetTeamAction =
  | 'MAP_TO_EXISTING'
  | 'PROVISION_INDIVIDUAL'
  | 'RETAIN_LEGACY_CONFLICT'
  | 'NO_OP';

export interface UserSubscriptionItem {
  id: number;
  vendor: string;
  product: string;
  rawVersions: string | null;
  parsedVersions: string[];
  isValidJsonVersions: boolean;
}

export interface UserTeamMembershipItem {
  teamId: number;
  teamName: string;
  teamCode: string;
  roleInTeam: string;
}

export interface UserMigrationCandidate {
  userId: number;
  email: string;
  name: string;
  isSubscriber: boolean;
  globalRole: string;
  activeTeamMemberships: UserTeamMembershipItem[];
  activeSubscriptions: UserSubscriptionItem[];
  targetTeamId: number | null;
  targetTeamCode?: string;
  targetTeamName?: string;
  targetTeamAction: TargetTeamAction;
  resolutionReason: ConflictResolutionReason;
  migrationStatus: UserMigrationStatus;
}

export interface UnresolvedConflictReportItem {
  userId: number;
  email: string;
  name: string;
  activeSubscriptionsCount: number;
  subscriptions: Array<{ id: number; vendor: string; product: string }>;
  candidateTeams: UserTeamMembershipItem[];
  requiredAction: string;
}

export interface DuplicateSubscriptionFinding {
  vendor: string;
  product: string;
  targetTeamId: number;
  occurrences: Array<{
    sourceSubscriptionId: number;
    sourceUserId: number;
    versions: string[];
  }>;
  mergedVersions: string[];
}

export interface NotificationBackfillItem {
  vulnerabilityId: number;
  sourceNotificationId: number;
  sourceSubscriberUserId: number;
  targetTeamId: number;
  sentAt: Date;
  status: string;
  notificationLogId: number | null;
}

export interface OrphanNotificationFinding {
  notificationId: number;
  vulnerabilityId: number;
  subscriberUserId: number | null;
  recipientEmail: string;
  sentAt: Date;
  reason: 'USER_NOT_FOUND' | 'USER_INACTIVE' | 'USER_NOT_SUBSCRIBER';
}

export interface MigrationAnalysisReport {
  generatedAt: string;
  executionMode: 'DRY_RUN';
  isDeterministic: boolean;

  summary: {
    totalUsersEvaluated: number;
    totalSubscribers: number;
    usersWithNoTeam: number;
    usersWithSingleTeam: number;
    usersWithMultipleTeams: number;
    unresolvedConflictUsers: number;
    resolvedViaExplicitMappingUsers: number;

    totalLegacySubscriptions: number;
    migratableSubscriptionsCount: number;
    duplicateSubscriptionGroupsCount: number;

    totalLegacyNotifications: number;
    backfillableNotificationsCount: number;
    orphanNotificationsCount: number;
  };

  users: UserMigrationCandidate[];
  unresolvedConflicts: UnresolvedConflictReportItem[];
  duplicateSubscriptions: DuplicateSubscriptionFinding[];
  orphanNotifications: OrphanNotificationFinding[];
  backfillSample: NotificationBackfillItem[];
}
