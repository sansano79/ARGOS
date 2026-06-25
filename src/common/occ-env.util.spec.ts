import { assertOccEnvAllowsTestCapabilities, parseOccEnv } from './occ-env.util';

describe('occ env util', () => {
  it('accepts only the supported OCC_ENV values', () => {
    expect(parseOccEnv('development')).toBe('development');
    expect(parseOccEnv('test')).toBe('test');
    expect(parseOccEnv('preproduction')).toBe('preproduction');
    expect(parseOccEnv('production')).toBe('production');
  });

  it('rejects empty or unknown OCC_ENV values', () => {
    expect(() => parseOccEnv('')).toThrow('OCC_ENV must be one of');
    expect(() => parseOccEnv('staging')).toThrow('OCC_ENV must be one of');
  });

  it('allows test capabilities only in development and test', () => {
    expect(assertOccEnvAllowsTestCapabilities('development')).toBe('development');
    expect(assertOccEnvAllowsTestCapabilities('test')).toBe('test');
    expect(() => assertOccEnvAllowsTestCapabilities('preproduction')).toThrow(
      'Test capabilities are only allowed when OCC_ENV is development or test',
    );
    expect(() => assertOccEnvAllowsTestCapabilities('production')).toThrow(
      'Test capabilities are only allowed when OCC_ENV is development or test',
    );
  });
});
