/**
 * Separación de tokens JWT: el token de acceso y el token intermedio de MFA
 * comparten secreto, por lo que se distinguen por audiencia y tipo. La
 * estrategia JWT solo acepta tokens de acceso (ver JwtStrategy).
 */
export const JWT_ISSUER = 'argos';
export const JWT_ALGORITHM = 'HS256' as const;

export const ACCESS_TOKEN_AUDIENCE = 'argos-api';
export const ACCESS_TOKEN_TYPE = 'access';

export const MFA_TOKEN_AUDIENCE = 'argos-mfa';
export const MFA_TOKEN_TYPE = 'mfa';

export function isAccessTokenPayload(payload: any): boolean {
  return !!payload
    && payload.typ === ACCESS_TOKEN_TYPE
    && payload.purpose === undefined;
}
