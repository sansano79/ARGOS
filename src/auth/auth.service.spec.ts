import { Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { AuthService } from './auth.service';

jest.mock('bcrypt', () => ({
  compare: jest.fn(),
}));

describe('AuthService', () => {
  const prisma = {
    loginAttempt: {
      count: jest.fn(),
      create: jest.fn(),
      deleteMany: jest.fn(),
    },
    user: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
  } as any;

  const jwtService = {
    sign: jest.fn().mockReturnValue('signed-token'),
    verify: jest.fn(),
  } as unknown as JwtService;

  let service: AuthService;
  let loggerWarnSpy: jest.SpyInstance;
  const originalEnv = process.env;

  const makeUser = (overrides: Record<string, any> = {}) => ({
    id: 1,
    email: 'test.manager.it@occ.local',
    name: 'Test Manager',
    role: 'TEAM_MANAGER',
    authProvider: 'LOCAL',
    isActive: true,
    canLogin: true,
    passwordHash: 'stored-hash',
    isSubscriber: false,
    mfaEnabled: true,
    loginContext: { ipAddress: '127.0.0.1' },
    ...overrides,
  });

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = {
      ...originalEnv,
      NODE_ENV: 'production',
      OCC_ENV: 'development',
      MFA_TEST_BYPASS_ENABLED: 'false',
      MFA_TEST_BYPASS_EMAILS: '',
    };
    service = new AuthService(prisma, jwtService);
    loggerWarnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    prisma.loginAttempt.count.mockResolvedValue(0);
    prisma.loginAttempt.create.mockResolvedValue(undefined);
    prisma.user.update.mockResolvedValue(undefined);
  });

  afterEach(() => {
    loggerWarnSpy.mockRestore();
    process.env = originalEnv;
  });

  it('keeps MFA flow when bypass is disabled', async () => {
    const result = await service.loginLocal(makeUser({ mfaEnabled: true }));

    expect(result).toEqual({
      mfaRequired: true,
      mfaToken: 'signed-token',
      user: { email: 'test.manager.it@occ.local', name: 'Test Manager' },
    });
    expect(loggerWarnSpy).not.toHaveBeenCalled();
  });

  it('returns access token for an allowlisted test account after password validation', async () => {
    process.env.OCC_ENV = 'test';
    process.env.MFA_TEST_BYPASS_ENABLED = 'true';
    process.env.MFA_TEST_BYPASS_EMAILS = 'test.manager.it@occ.local';

    const result = await service.loginLocal(makeUser());

    expect(result).toEqual({
      access_token: 'signed-token',
      user: {
        id: 1,
        email: 'test.manager.it@occ.local',
        name: 'Test Manager',
        role: 'TEAM_MANAGER',
        isSubscriber: false,
      },
    });
    expect(loggerWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining('TEST_MFA_BYPASS_USED email=test.manager.it@occ.local ip=127.0.0.1 timestamp='),
    );
    expect(prisma.user.update).not.toHaveBeenCalled();
  });

  it('keeps MFA for real admin accounts even if bypass is enabled', async () => {
    process.env.OCC_ENV = 'test';
    process.env.MFA_TEST_BYPASS_ENABLED = 'true';
    process.env.MFA_TEST_BYPASS_EMAILS = 'test.manager.it@occ.local';

    const result = await service.loginLocal(makeUser({
      email: 'admin@occ.local',
      role: 'ADMIN',
      name: 'Real Admin',
    }));

    expect(result).toEqual({
      mfaRequired: true,
      mfaToken: 'signed-token',
      user: { email: 'admin@occ.local', name: 'Real Admin' },
    });
    expect(loggerWarnSpy).not.toHaveBeenCalled();
  });

  it('validateUser rejects inactive users before bypass can apply', async () => {
    prisma.user.findUnique.mockResolvedValue(makeUser({ isActive: false }));

    const result = await service.validateUser('test.manager.it@occ.local', 'ChangeMeNow!123');

    expect(result).toBeNull();
    expect(prisma.loginAttempt.create).toHaveBeenCalledWith({
      data: { email: 'test.manager.it@occ.local', ipAddress: '0.0.0.0', success: false },
    });
  });

  it('validateUser rejects users without login permission before bypass can apply', async () => {
    prisma.user.findUnique.mockResolvedValue(makeUser({ canLogin: false }));

    const result = await service.validateUser('test.manager.it@occ.local', 'ChangeMeNow!123');

    expect(result).toBeNull();
    expect(prisma.loginAttempt.create).toHaveBeenCalledWith({
      data: { email: 'test.manager.it@occ.local', ipAddress: '0.0.0.0', success: false },
    });
  });

  it('validateUser rejects invalid passwords and never reaches bypass', async () => {
    prisma.user.findUnique.mockResolvedValue(makeUser());
    (bcrypt.compare as jest.Mock).mockResolvedValue(false);

    const result = await service.validateUser('test.manager.it@occ.local', 'WrongPassword!1');

    expect(result).toBeNull();
    expect(prisma.user.update).not.toHaveBeenCalled();
  });

  it('validateUser returns sanitized user when password is correct', async () => {
    prisma.user.findUnique.mockResolvedValue(makeUser());
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);

    const result = await service.validateUser('test.manager.it@occ.local', 'ChangeMeNow!123');

    expect(result).toEqual(expect.objectContaining({
      email: 'test.manager.it@occ.local',
      role: 'TEAM_MANAGER',
    }));
    expect(result.passwordHash).toBeUndefined();
    expect(prisma.user.update).toHaveBeenCalledWith({
      where: { id: 1 },
      data: { lastLoginAt: expect.any(Date) },
    });
    expect(prisma.loginAttempt.create).toHaveBeenCalledWith({
      data: { email: 'test.manager.it@occ.local', ipAddress: '0.0.0.0', success: true },
    });
  });

  it('keeps MFA when OCC_ENV is production even if NODE_ENV stays production and bypass is requested', async () => {
    process.env.OCC_ENV = 'production';
    process.env.MFA_TEST_BYPASS_ENABLED = 'true';
    process.env.MFA_TEST_BYPASS_EMAILS = 'test.manager.it@occ.local';

    expect(() => service.getTestMfaBypassStatus()).toThrow('Test capabilities are only allowed when OCC_ENV is development or test');
  });
});
