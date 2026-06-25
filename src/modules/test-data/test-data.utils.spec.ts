import { BadRequestException } from '@nestjs/common';
import { TEST_USERS } from './test-data.definitions';
import {
  assertCleanupAllowed,
  assertNoSecretInLogs,
  assertTestDataExecutionAllowed,
  buildTestDataSummary,
  getCleanupPrefixes,
  getSerializedTags,
  getTestTeamCodes,
  getTestUserEmails,
  validateTestUserMemberships,
} from './test-data.utils';

describe('test data utils', () => {
  it('validates the static test data definitions', () => {
    expect(buildTestDataSummary()).toEqual({
      teams: 4,
      users: 10,
      memberships: 11,
      recipients: 4,
      subscriptions: 5,
      systems: 4,
    });
    expect(() => validateTestUserMemberships()).not.toThrow();
    expect(TEST_USERS.find((user) => user.email === 'test.manager.unassigned@occ.local')?.memberships).toEqual([]);
  });

  it('rejects disabled or production execution', () => {
    expect(() => assertTestDataExecutionAllowed({
      enabled: 'false',
      occEnv: 'development',
      password: 'ChangeMeNow!123',
    })).toThrow('TEST_DATA_SEED_ENABLED must be true');

    expect(() => assertTestDataExecutionAllowed({
      enabled: 'true',
      occEnv: 'production',
      password: 'ChangeMeNow!123',
    })).toThrow('only allowed when OCC_ENV is development or test');
  });

  it('requires password length and confirm for cleanup', () => {
    expect(() => assertTestDataExecutionAllowed({
      enabled: 'true',
      occEnv: 'development',
      password: 'short',
    })).toThrow('at least 8 characters');

    expect(() => assertCleanupAllowed({
      enabled: 'true',
      occEnv: 'development',
      confirm: false,
    })).toThrow('--confirm');

    expect(() => assertCleanupAllowed({
      enabled: 'true',
      occEnv: 'development',
      confirm: false,
      dryRun: true,
    })).not.toThrow();
  });

  it('rejects unknown OCC_ENV values fail-closed', () => {
    expect(() => assertTestDataExecutionAllowed({
      enabled: 'true',
      occEnv: '',
      password: 'ChangeMeNow!123',
    })).toThrow('OCC_ENV must be one of');
  });

  it('serializes tags and exposes exact cleanup prefixes', () => {
    expect(getSerializedTags(['test', 'windows'])).toBe('["test","windows"]');
    expect(getCleanupPrefixes()).toEqual({
      userEmailPrefix: 'test.',
      teamCodePrefix: 'test-',
    });
    expect(getTestUserEmails()).toContain('test.admin@occ.local');
    expect(getTestTeamCodes()).toContain('test-it-global');
  });

  it('detects accidental password leakage in logs', () => {
    expect(() => assertNoSecretInLogs('all good', 'ChangeMeNow!123')).not.toThrow();
    expect(() => assertNoSecretInLogs('password=ChangeMeNow!123', 'ChangeMeNow!123')).toThrow(BadRequestException);
  });
});
