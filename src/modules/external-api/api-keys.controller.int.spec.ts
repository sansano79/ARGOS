import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';

import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { PrismaService } from '../../prisma/prisma.service';
import { ExternalApiModule } from './external-api.module';

describe('ApiKeysController (integration)', () => {
  let app: INestApplication;
  let prisma: any;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  beforeAll(async () => {
    prisma = {
      apiKey: {
        create: jest.fn().mockResolvedValue({
          id: 1,
          name: 'Key',
          keyPrefix: 'occ_12345678',
          isActive: true,
          expiresAt: null,
          createdAt: new Date('2026-04-02T00:00:00.000Z'),
        }),
      },
    };

    const moduleRef = await Test.createTestingModule({
      imports: [ExternalApiModule],
    })
      .overrideProvider(PrismaService)
      .useValue(prisma)
      .overrideGuard(JwtAuthGuard)
      .useValue({
        canActivate: (context: any) => {
          const req = context.switchToHttp().getRequest();
          req.user = { id: 99, roles: ['ADMIN'] };
          return true;
        },
      })
      .overrideGuard(RolesGuard)
      .useValue({ canActivate: () => true })
      .compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    app.setGlobalPrefix('api');
    await app.init();
    await app.listen(0);
  });

  afterAll(async () => {
    if (app) await app.close();
  });

  const postJson = async (url: string, body: any) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  };

  it('POST /api/api-keys persists and returns the raw key once', async () => {
    const server = app.getHttpServer();
    const address = server.address();
    const port = typeof address === 'string' ? 80 : address.port;
    const baseUrl = `http://127.0.0.1:${port}`;

    const res = await postJson(`${baseUrl}/api/api-keys`, { name: 'Key', scopes: ['vulnerabilities:read'] });
    expect(res.status).toBe(201);
    expect(res.body.id).toBe(1);
    expect(typeof res.body.key).toBe('string');
    expect(res.body.key.startsWith('occ_')).toBe(true);
    expect(res.body.isActive).toBe(true);
    expect(prisma.apiKey.create).toHaveBeenCalledTimes(1);
  });

  it('rejects empty name via DTO validation', async () => {
    const server = app.getHttpServer();
    const address = server.address();
    const port = typeof address === 'string' ? 80 : address.port;
    const baseUrl = `http://127.0.0.1:${port}`;

    const res = await postJson(`${baseUrl}/api/api-keys`, { name: '' });
    expect(res.status).toBe(400);
    expect(prisma.apiKey.create).toHaveBeenCalledTimes(0);
  });
});
