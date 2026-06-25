import { BadRequestException } from '@nestjs/common';
import { assertOccEnvAllowsTestCapabilities } from '../../common/occ-env.util';
import { assertTeamRoleCompatibility } from '../subscriber-teams/team-role-compatibility';
import {
  TEST_RECIPIENTS,
  TEST_SUBSCRIPTIONS,
  TEST_SYSTEMS,
  TEST_TEAMS,
  TEST_USERS,
} from './test-data.definitions';

const MIN_PASSWORD_LENGTH = 8;

export const normalizeBooleanEnv = (value: string | undefined | null) => String(value || '').trim().toLowerCase() === 'true';

export const assertTestDataExecutionAllowed = (config: { enabled?: string; occEnv?: string; password?: string }) => {
  const enabled = normalizeBooleanEnv(config.enabled);
  const occEnv = assertOccEnvAllowsTestCapabilities(config.occEnv);
  if (!enabled) {
    throw new Error('TEST_DATA_SEED_ENABLED must be true to run this script');
  }

  const password = String(config.password || '');
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`TEST_USERS_PASSWORD must be at least ${MIN_PASSWORD_LENGTH} characters long`);
  }

  return { enabled: true, occEnv, passwordMinLength: MIN_PASSWORD_LENGTH };
};

export const assertCleanupAllowed = (config: { enabled?: string; occEnv?: string; confirm?: boolean; dryRun?: boolean }) => {
  const enabled = normalizeBooleanEnv(config.enabled);
  assertOccEnvAllowsTestCapabilities(config.occEnv);
  if (!enabled) {
    throw new Error('TEST_DATA_SEED_ENABLED must be true to run cleanup');
  }
  if (!config.dryRun && !config.confirm) {
    throw new Error('Cleanup requires the explicit --confirm flag');
  }
};

export const buildTestDataSummary = () => ({
  teams: TEST_TEAMS.length,
  users: TEST_USERS.length,
  memberships: TEST_USERS.reduce((count, user) => count + user.memberships.length, 0),
  recipients: TEST_RECIPIENTS.length,
  subscriptions: TEST_SUBSCRIPTIONS.length,
  systems: TEST_SYSTEMS.length,
});

export const getSerializedTags = (tags: readonly string[]) => JSON.stringify([...tags]);

export const validateTestUserMemberships = () => {
  for (const user of TEST_USERS) {
    for (const membership of user.memberships) {
      assertTeamRoleCompatibility(user.role, membership.role);
    }
  }
};

export const getCleanupPrefixes = () => ({
  userEmailPrefix: 'test.',
  teamCodePrefix: 'test-',
});

export const getTestUserEmails = () => TEST_USERS.map((user) => user.email);
export const getTestTeamCodes = () => TEST_TEAMS.map((team) => team.code);

export const assertNoSecretInLogs = (line: string, password: string) => {
  if (!line) return;
  if (password && line.includes(password)) {
    throw new BadRequestException('Sensitive password data must not be logged');
  }
};
