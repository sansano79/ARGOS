import { TestMfaBypassConfigError, getTestMfaBypassStartupStatus, parseTestMfaBypassEmails, shouldBypassMfaForUser } from './test-mfa-bypass.util';

describe('test-mfa-bypass util', () => {
  it('production rejects active bypass', () => {
    expect(() => getTestMfaBypassStartupStatus({
      occEnv: 'production',
      enabled: 'true',
      emails: 'test.admin@occ.local',
    })).toThrow(TestMfaBypassConfigError);
  });

  it('bypass disabled returns disabled status', () => {
    expect(getTestMfaBypassStartupStatus({
      occEnv: 'development',
      enabled: 'false',
      emails: 'test.admin@occ.local',
    })).toEqual({ enabled: false, allowlistCount: 0 });
  });

  it('requires explicit allowlist when enabled', () => {
    expect(() => getTestMfaBypassStartupStatus({
      occEnv: 'development',
      enabled: 'true',
      emails: '',
    })).toThrow(TestMfaBypassConfigError);
  });

  it('rejects unknown or empty OCC_ENV when bypass is enabled', () => {
    expect(() => getTestMfaBypassStartupStatus({
      occEnv: '',
      enabled: 'true',
      emails: 'test.admin@occ.local',
    })).toThrow(TestMfaBypassConfigError);

    expect(() => getTestMfaBypassStartupStatus({
      occEnv: 'staging',
      enabled: 'true',
      emails: 'test.admin@occ.local',
    })).toThrow(TestMfaBypassConfigError);
  });

  it('rejects non test emails in allowlist', () => {
    expect(() => parseTestMfaBypassEmails('admin@occ.local')).toThrow(TestMfaBypassConfigError);
  });

  it('matches exact normalized emails only', () => {
    expect(shouldBypassMfaForUser(
      { email: 'test.admin@occ.local', isActive: true, canLogin: true },
      { occEnv: 'development', enabled: 'true', emails: 'test.admin@occ.local' },
    )).toBe(true);

    expect(shouldBypassMfaForUser(
      { email: 'test.admin+alias@occ.local', isActive: true, canLogin: true },
      { occEnv: 'development', enabled: 'true', emails: 'test.admin@occ.local' },
    )).toBe(false);
  });

  it('rejects inactive or non login users', () => {
    expect(shouldBypassMfaForUser(
      { email: 'test.admin@occ.local', isActive: false, canLogin: true },
      { occEnv: 'development', enabled: 'true', emails: 'test.admin@occ.local' },
    )).toBe(false);

    expect(shouldBypassMfaForUser(
      { email: 'test.admin@occ.local', isActive: true, canLogin: false },
      { occEnv: 'development', enabled: 'true', emails: 'test.admin@occ.local' },
    )).toBe(false);
  });
});
