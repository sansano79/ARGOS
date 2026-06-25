export const ALLOWED_OCC_ENVS = ['development', 'test', 'preproduction', 'production'] as const;

export type OccEnv = typeof ALLOWED_OCC_ENVS[number];

const TEST_CAPABILITY_OCC_ENVS: readonly OccEnv[] = ['development', 'test'];

const normalizeOccEnv = (value: string | undefined | null) => String(value || '').trim().toLowerCase();

export const parseOccEnv = (value: string | undefined | null): OccEnv => {
  const normalized = normalizeOccEnv(value);
  if (ALLOWED_OCC_ENVS.includes(normalized as OccEnv)) {
    return normalized as OccEnv;
  }

  throw new Error(
    `OCC_ENV must be one of: ${ALLOWED_OCC_ENVS.join(', ')}`,
  );
};

export const assertOccEnvAllowsTestCapabilities = (value: string | undefined | null): OccEnv => {
  const occEnv = parseOccEnv(value);
  if (!TEST_CAPABILITY_OCC_ENVS.includes(occEnv)) {
    throw new Error('Test capabilities are only allowed when OCC_ENV is development or test');
  }
  return occEnv;
};
