jest.mock('crypto', () => ({
  randomBytes: jest.fn(),
}));
jest.mock('bcrypt', () => ({
  hash: jest.fn(),
}));

import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

import { ApiKeysService } from './api-keys.service';

describe('ApiKeysService', () => {
  const makePrisma = () => ({
    apiKey: {
      create: jest.fn(),
    },
  });

  beforeEach(() => {
    jest.restoreAllMocks();
  });

  it('creates and persists a new API key with hashed secret and keyPrefix', async () => {
    const prisma = makePrisma();
    prisma.apiKey.create.mockResolvedValue({
      id: 10,
      name: 'Key 1',
      keyPrefix: 'occ_deadbeef00',
      isActive: true,
      expiresAt: null,
      createdAt: new Date('2026-04-02T00:00:00.000Z'),
    });

    (crypto as any).randomBytes.mockReturnValue(Buffer.from('deadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 'hex'));
    (bcrypt as any).hash.mockResolvedValue('bcrypt-hash');

    const service = new ApiKeysService(prisma as any);
    const result = await service.create(1, { name: 'Key 1', scopes: ['vulnerabilities:read'] });

    expect(prisma.apiKey.create).toHaveBeenCalledTimes(1);
    const arg = prisma.apiKey.create.mock.calls[0][0];
    expect(arg.data.userId).toBe(1);
    expect(arg.data.name).toBe('Key 1');
    expect(arg.data.keyHash).toBe('bcrypt-hash');
    expect(String(arg.data.keyPrefix)).toHaveLength(12);
    expect(arg.data.keyPrefix.startsWith('occ_')).toBe(true);
    expect(arg.data.scopes).toBe(JSON.stringify(['vulnerabilities:read']));

    expect(result.key).toMatch(/^occ_[0-9a-f]+$/);
    expect(result.keyPrefix).toBe(result.key.substring(0, 12));
    expect(result.isActive).toBe(true);
    expect(result.message).toContain('Store this key securely');
  });

  it('rejects invalid scopes', async () => {
    const prisma = makePrisma();
    const service = new ApiKeysService(prisma as any);
    await expect(service.create(1, { name: 'Key 1', scopes: ['admin:all'] as any })).rejects.toMatchObject({
      status: 400,
    });
    expect(prisma.apiKey.create).not.toHaveBeenCalled();
  });

  it('maps missing table errors to a 503 with actionable message', async () => {
    const prisma = makePrisma();
    prisma.apiKey.create.mockRejectedValue(Object.assign(new Error("Table 'argos.api_keys' doesn't exist"), { code: 'P2021' }));

    (crypto as any).randomBytes.mockReturnValue(Buffer.from('deadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 'hex'));
    (bcrypt as any).hash.mockResolvedValue('bcrypt-hash');

    const service = new ApiKeysService(prisma as any);
    await expect(service.create(1, { name: 'Key 1' })).rejects.toMatchObject({
      status: 503,
    });
  });
});
