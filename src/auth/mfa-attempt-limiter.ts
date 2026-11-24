/**
 * Control en memoria de intentos MFA (proceso único de API).
 *
 * - Limita fallos por usuario en una ventana deslizante (bloqueo temporal).
 * - Limita fallos por mfaToken (jti) y hace los mfaToken de un solo uso.
 * - Impide reutilizar un código TOTP ya aceptado (time-step).
 *
 * Fase 0: estado en memoria. Si la API escala a varias réplicas o se reinicia,
 * el estado se pierde; migrar a Redis (plan de corrección, tarea 1.7).
 */
export interface MfaAttemptLimiterOptions {
  maxFailuresPerUser: number;
  maxFailuresPerToken: number;
  windowMs: number;
  now?: () => number;
}

const DEFAULTS: MfaAttemptLimiterOptions = {
  maxFailuresPerUser: 5,
  maxFailuresPerToken: 3,
  windowMs: 15 * 60 * 1000,
};

export class MfaAttemptLimiter {
  private readonly opts: MfaAttemptLimiterOptions;
  private readonly userFailures = new Map<number, number[]>();
  private readonly tokenFailures = new Map<string, number>();
  /** jti → expiración (ms). Tokens consumidos o invalidados. */
  private readonly revokedTokens = new Map<string, number>();
  /** userId → último time-step TOTP aceptado. */
  private readonly lastAcceptedStep = new Map<number, number>();

  constructor(options: Partial<MfaAttemptLimiterOptions> = {}) {
    this.opts = { ...DEFAULTS, ...options };
  }

  private now(): number {
    return this.opts.now ? this.opts.now() : Date.now();
  }

  private recentUserFailures(userId: number): number[] {
    const cutoff = this.now() - this.opts.windowMs;
    const list = (this.userFailures.get(userId) || []).filter((t) => t > cutoff);
    if (list.length) this.userFailures.set(userId, list);
    else this.userFailures.delete(userId);
    return list;
  }

  private purgeRevoked(): void {
    const now = this.now();
    for (const [jti, exp] of this.revokedTokens) {
      if (exp <= now) this.revokedTokens.delete(jti);
    }
  }

  isUserLocked(userId: number): boolean {
    return this.recentUserFailures(userId).length >= this.opts.maxFailuresPerUser;
  }

  isTokenRevoked(jti: string): boolean {
    this.purgeRevoked();
    return this.revokedTokens.has(jti);
  }

  revokeToken(jti: string, expiresAtMs: number): void {
    this.revokedTokens.set(jti, expiresAtMs);
    this.tokenFailures.delete(jti);
  }

  /** Registra un fallo; devuelve true si el token ha quedado invalidado. */
  recordFailure(userId: number, jti: string, tokenExpiresAtMs: number): boolean {
    const list = this.recentUserFailures(userId);
    list.push(this.now());
    this.userFailures.set(userId, list);

    const count = (this.tokenFailures.get(jti) || 0) + 1;
    this.tokenFailures.set(jti, count);
    if (count >= this.opts.maxFailuresPerToken) {
      this.revokeToken(jti, tokenExpiresAtMs);
      return true;
    }
    return false;
  }

  /** true si el time-step ya se usó (replay) para este usuario. */
  isReplayedStep(userId: number, step: number): boolean {
    const last = this.lastAcceptedStep.get(userId);
    return last !== undefined && step <= last;
  }

  recordSuccess(userId: number, step: number, jti: string, tokenExpiresAtMs: number): void {
    this.userFailures.delete(userId);
    this.lastAcceptedStep.set(userId, step);
    this.revokeToken(jti, tokenExpiresAtMs);
  }
}
