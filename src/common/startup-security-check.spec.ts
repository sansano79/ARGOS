import { checkStartupSecurity } from './startup-security-check';

const KEY_32 = Buffer.alloc(32, 7).toString('base64');
const SECRET = 'x'.repeat(64);

const prodEnv = (overrides: Record<string, string> = {}) => ({
  NODE_ENV: 'production',
  OCC_ENV: 'production',
  JWT_SECRET: SECRET,
  MFA_ENCRYPTION_KEY: KEY_32,
  CORS_ORIGIN: 'https://argos.example.com',
  ...overrides,
});

describe('checkStartupSecurity', () => {
  it('accepts a hardened production configuration', () => {
    const result = checkStartupSecurity(prodEnv());
    expect(result.errors).toEqual([]);
    expect(result.swaggerEnabled).toBe(false);
  });

  it.each([
    ['MFA_TEST_BYPASS_ENABLED', 'true'],
    ['MFA_DEV_BYPASS_ENABLED', 'true'],
    ['DEV_AUTH_BYPASS', 'true'],
    ['TEST_DATA_SEED_ENABLED', 'true'],
    ['PRISMA_DB_PUSH_ON_START', 'true'],
    ['CORS_ORIGIN', '*'],
    ['OCC_ENV', 'development'],
    ['JWT_SECRET', 'short'],
    ['MFA_ENCRYPTION_KEY', ''],
  ])('rejects %s=%s in production', (key, value) => {
    expect(checkStartupSecurity(prodEnv({ [key]: value })).errors.length).toBeGreaterThan(0);
  });

  it('disables Swagger in production unless explicitly double-confirmed', () => {
    expect(checkStartupSecurity(prodEnv({ ENABLE_SWAGGER: 'true' })).swaggerEnabled).toBe(false);
    expect(checkStartupSecurity(prodEnv({ ENABLE_SWAGGER: 'true', ENABLE_SWAGGER_IN_PRODUCTION: 'true' })).swaggerEnabled).toBe(true);
  });

  it('only warns outside production', () => {
    const result = checkStartupSecurity({ NODE_ENV: 'development', JWT_SECRET: 'short', MFA_TEST_BYPASS_ENABLED: 'true' });
    expect(result.errors).toEqual([]);
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.swaggerEnabled).toBe(true);
  });

  it('always requires JWT_SECRET', () => {
    expect(checkStartupSecurity({ NODE_ENV: 'development' }).errors).toContain('JWT_SECRET no está definido');
  });
});
