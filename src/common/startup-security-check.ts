/**
 * Comprobaciones de configuración al arrancar. Con NODE_ENV=production la API
 * no arranca si la configuración desactiva controles de seguridad.
 */
export interface StartupSecurityResult {
  errors: string[];
  warnings: string[];
  swaggerEnabled: boolean;
}

const isTrue = (value: string | undefined) => String(value || '').trim().toLowerCase() === 'true';

const MIN_JWT_SECRET_LENGTH = 32;

function decodedKeyLength(raw: string | undefined): number {
  const value = String(raw || '').trim();
  if (!value) return 0;
  try {
    return Buffer.from(value, 'base64').length;
  } catch {
    return 0;
  }
}

export function checkStartupSecurity(env: NodeJS.ProcessEnv): StartupSecurityResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const isProduction = env.NODE_ENV === 'production';

  const jwtSecret = String(env.JWT_SECRET || '');
  if (!jwtSecret) {
    errors.push('JWT_SECRET no está definido');
  } else if (jwtSecret.length < MIN_JWT_SECRET_LENGTH) {
    (isProduction ? errors : warnings).push(`JWT_SECRET debe tener al menos ${MIN_JWT_SECRET_LENGTH} caracteres`);
  }

  // Swagger en producción solo con doble confirmación explícita.
  let swaggerEnabled = isTrue(env.ENABLE_SWAGGER) || !isProduction;
  if (isProduction && isTrue(env.ENABLE_SWAGGER) && !isTrue(env.ENABLE_SWAGGER_IN_PRODUCTION)) {
    swaggerEnabled = false;
    warnings.push('ENABLE_SWAGGER=true ignorado en producción (requiere ENABLE_SWAGGER_IN_PRODUCTION=true)');
  }

  if (!isProduction) return { errors, warnings, swaggerEnabled };

  const occEnv = String(env.OCC_ENV || '').trim().toLowerCase();
  if (occEnv === 'development' || occEnv === 'test') {
    errors.push(`OCC_ENV=${occEnv} no está permitido con NODE_ENV=production (habilita capacidades de prueba)`);
  }

  for (const flag of ['MFA_TEST_BYPASS_ENABLED', 'MFA_DEV_BYPASS_ENABLED', 'DEV_AUTH_BYPASS', 'TEST_DATA_SEED_ENABLED']) {
    if (isTrue(env[flag])) errors.push(`${flag}=true no está permitido en producción`);
  }

  if (isTrue(env.PRISMA_DB_PUSH_ON_START)) {
    errors.push('PRISMA_DB_PUSH_ON_START=true no está permitido en producción (usa prisma migrate deploy)');
  }

  const corsOrigins = String(env.CORS_ORIGIN || '').split(',').map((o) => o.trim());
  if (corsOrigins.includes('*')) {
    errors.push('CORS_ORIGIN=* no está permitido en producción (la API usa credentials)');
  }

  if (decodedKeyLength(env.MFA_ENCRYPTION_KEY) !== 32) {
    errors.push('MFA_ENCRYPTION_KEY debe ser una clave base64 de 32 bytes');
  }

  return { errors, warnings, swaggerEnabled };
}
