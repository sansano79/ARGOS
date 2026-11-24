import { ForbiddenException, Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { authenticator } from 'otplib';
import crypto from 'crypto';
import { AuthService } from './auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { ACCESS_TOKEN_AUDIENCE, JWT_ISSUER } from './token-claims';
import { MfaAttemptLimiter } from './mfa-attempt-limiter';

const JWT_SECRET = 'a'.repeat(64);
const MFA_KEY = crypto.randomBytes(32).toString('base64');

function encryptForUser(secret: string) {
  const key = Buffer.from(MFA_KEY, 'base64');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return {
    mfaSecretEnc: enc.toString('base64'),
    mfaSecretIv: iv.toString('base64'),
    mfaSecretTag: cipher.getAuthTag().toString('base64'),
  };
}

describe('MFA hardening', () => {
  const originalEnv = process.env;
  const totpSecret = authenticator.generateSecret();
  const jwtService = new JwtService({ secret: JWT_SECRET, signOptions: { expiresIn: '8h' } });

  const baseUser = () => ({
    id: 7,
    email: 'admin@argos.local',
    name: 'Admin',
    role: 'ADMIN',
    authProvider: 'LOCAL',
    isActive: true,
    canLogin: true,
    isSubscriber: false,
    mfaEnabled: true,
    ...encryptForUser(totpSecret),
  });

  let prisma: any;
  let service: AuthService;
  let strategy: JwtStrategy;

  beforeEach(() => {
    process.env = { ...originalEnv, MFA_ENCRYPTION_KEY: MFA_KEY, OCC_ENV: 'production', NODE_ENV: 'production' };
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    prisma = {
      user: {
        findUnique: jest.fn().mockImplementation(async () => baseUser()),
        update: jest.fn().mockResolvedValue(undefined),
      },
      loginAttempt: { count: jest.fn().mockResolvedValue(0), create: jest.fn() },
    };
    service = new AuthService(prisma, jwtService);
    strategy = new JwtStrategy({ get: () => JWT_SECRET } as any, prisma);
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
  });

  const loginMfaToken = async () => {
    const result: any = await service.loginLocal(baseUser());
    expect(result.mfaRequired).toBe(true);
    return result.mfaToken as string;
  };

  it('C1: an MFA token is not accepted as an API access token', async () => {
    const mfaToken = await loginMfaToken();
    const decoded: any = jwtService.decode(mfaToken);
    expect(decoded.aud).not.toBe(ACCESS_TOKEN_AUDIENCE);
    // passport-jwt verificaría la audiencia; además validate() rechaza el payload.
    expect(() => jwtService.verify(mfaToken, { audience: ACCESS_TOKEN_AUDIENCE, issuer: JWT_ISSUER })).toThrow();
    await expect(strategy.validate(decoded)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('C1: legacy tokens without typ are rejected by the strategy', async () => {
    await expect(strategy.validate({ sub: 7, email: 'admin@argos.local', role: 'ADMIN' })).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('access tokens carry the access audience and pass the strategy', async () => {
    const { access_token } = await service.issueAccessToken(baseUser());
    const payload: any = jwtService.verify(access_token, { audience: ACCESS_TOKEN_AUDIENCE, issuer: JWT_ISSUER });
    await expect(strategy.validate(payload)).resolves.toEqual(expect.objectContaining({ id: 7, role: 'ADMIN' }));
  });

  it('C2: mfa/setup is refused when MFA is already enabled', async () => {
    const mfaToken = await loginMfaToken();
    await expect(service.mfaSetup({ body: { mfaToken } })).rejects.toBeInstanceOf(ForbiddenException);
    expect(prisma.user.update).not.toHaveBeenCalled();
  });

  it('C2: mfa/setup still works for first enrolment', async () => {
    prisma.user.findUnique.mockImplementation(async () => ({ ...baseUser(), mfaEnabled: false }));
    const result: any = await service.loginLocal({ ...baseUser(), mfaEnabled: false });
    await expect(service.mfaSetup({ body: { mfaToken: result.mfaToken } })).resolves.toEqual(
      expect.objectContaining({ otpauthUrl: expect.any(String) }),
    );
  });

  it('A2: a valid code works once; the MFA token and the code cannot be replayed', async () => {
    const mfaToken = await loginMfaToken();
    const code = authenticator.generate(totpSecret);
    await expect(service.mfaVerify({ body: { mfaToken, code } })).resolves.toEqual(
      expect.objectContaining({ access_token: expect.any(String) }),
    );
    // Mismo token reutilizado → rechazado.
    await expect(service.mfaVerify({ body: { mfaToken, code } })).rejects.toBeInstanceOf(UnauthorizedException);
    // Token nuevo con el mismo código → replay del time-step rechazado.
    const second = await loginMfaToken();
    await expect(service.mfaVerify({ body: { mfaToken: second, code } })).rejects.toThrow('Invalid MFA code');
  });

  it('A2: a token is revoked after repeated failures and the user is locked', async () => {
    const mfaToken = await loginMfaToken();
    for (let i = 0; i < 3; i++) {
      await expect(service.mfaVerify({ body: { mfaToken, code: '000000' } })).rejects.toThrow();
    }
    const valid = authenticator.generate(totpSecret);
    await expect(service.mfaVerify({ body: { mfaToken, code: valid } })).rejects.toThrow('Invalid MFA token');

    const t2 = await loginMfaToken();
    await expect(service.mfaVerify({ body: { mfaToken: t2, code: '000000' } })).rejects.toThrow();
    await expect(service.mfaVerify({ body: { mfaToken: t2, code: '000000' } })).rejects.toThrow();
    const t3 = await loginMfaToken();
    await expect(service.mfaVerify({ body: { mfaToken: t3, code: valid } })).rejects.toThrow('Too many MFA attempts');
  });
});

describe('MfaAttemptLimiter', () => {
  it('unlocks the user after the window expires', () => {
    let now = 0;
    const limiter = new MfaAttemptLimiter({ maxFailuresPerUser: 2, maxFailuresPerToken: 10, windowMs: 1000, now: () => now });
    limiter.recordFailure(1, 'a', 5000);
    limiter.recordFailure(1, 'a', 5000);
    expect(limiter.isUserLocked(1)).toBe(true);
    now = 1500;
    expect(limiter.isUserLocked(1)).toBe(false);
  });
});
