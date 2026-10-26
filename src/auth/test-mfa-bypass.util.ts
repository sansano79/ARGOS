import { assertOccEnvAllowsTestCapabilities } from '../common/occ-env.util';

type TestMfaBypassConfig = {
  occEnv?: string;
  enabled?: string;
  emails?: string;
  developmentEnabled?: string;
};

const normalizeEmail = (value: string | undefined | null) => String(value || '').trim().toLowerCase();

export class TestMfaBypassConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TestMfaBypassConfigError';
  }
}

export const parseTestMfaBypassEmails = (raw: string | undefined | null): string[] => {
  const entries = String(raw || '')
    .split(',')
    .map((item) => normalizeEmail(item))
    .filter(Boolean);

  const unique = new Set<string>();
  for (const email of entries) {
    if (!email.startsWith('test.')) {
      throw new TestMfaBypassConfigError('MFA test bypass allowlist only accepts emails starting with test.');
    }
    if (unique.has(email)) {
      throw new TestMfaBypassConfigError('MFA test bypass allowlist contains duplicate emails');
    }
    unique.add(email);
  }

  return [...unique];
};

export const getTestMfaBypassStartupStatus = (config: TestMfaBypassConfig) => {
  const developmentEnabled = String(config.developmentEnabled || '').trim().toLowerCase() === 'true';
  if (developmentEnabled) {
    try {
      assertOccEnvAllowsTestCapabilities(config.occEnv);
    } catch (error) {
      throw new TestMfaBypassConfigError(error instanceof Error ? error.message : 'Invalid OCC_ENV for development MFA bypass');
    }
  }
  const enabled = String(config.enabled || '').trim().toLowerCase() === 'true';

  if (!enabled) {
    if (!developmentEnabled) return { enabled: false, allowlistCount: 0 };
    return { enabled: true, allowlistCount: 0, developmentEnabled: true };
  }
  try {
    assertOccEnvAllowsTestCapabilities(config.occEnv);
  } catch (error) {
    throw new TestMfaBypassConfigError(error instanceof Error ? error.message : 'Invalid OCC_ENV for MFA test bypass');
  }

  const emails = parseTestMfaBypassEmails(config.emails);
  if (emails.length === 0 && !developmentEnabled) {
    throw new TestMfaBypassConfigError('MFA test bypass enabled without an explicit allowlist');
  }

  return {
    enabled: true,
    allowlistCount: emails.length,
    emails,
    developmentEnabled,
  };
};

export const shouldBypassMfaForUser = (
  user: { email?: string | null; isActive?: boolean | null; canLogin?: boolean | null },
  config: TestMfaBypassConfig,
) => {
  const status = getTestMfaBypassStartupStatus(config);
  if (!status.enabled) return false;

  const email = normalizeEmail(user?.email);
  if (status.developmentEnabled && user?.isActive && user?.canLogin) return true;
  if (!email.startsWith('test.')) return false;
  if (!user?.isActive || !user?.canLogin) return false;

  return (status.emails || []).includes(email);
};
