import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../../../prisma/prisma.service';
import { API_KEY_SCOPES_KEY } from '../decorators/api-key-scopes.decorator';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const apiKey = request.headers['x-api-key'] as string;

    if (!apiKey) {
      throw new UnauthorizedException('Missing X-API-Key header');
    }

    const prefix = apiKey.substring(0, 12);

    const candidates = await this.prisma.apiKey.findMany({
      where: { keyPrefix: prefix, isActive: true },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            name: true,
            role: true,
            isSubscriber: true,
            isActive: true,
          },
        },
      },
    });

    let matched: (typeof candidates)[0] | null = null;
    for (const candidate of candidates) {
      if (candidate.expiresAt && candidate.expiresAt < new Date()) continue;
      const isValid = await bcrypt.compare(apiKey, candidate.keyHash);
      if (isValid) {
        matched = candidate;
        break;
      }
    }

    if (!matched) {
      throw new UnauthorizedException('Invalid API key');
    }

    if (!matched.user || !matched.user.isActive) {
      throw new UnauthorizedException('User associated with API key is disabled');
    }

    // Check scopes
    const requiredScopes = this.reflector.getAllAndOverride<string[]>(
      API_KEY_SCOPES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (requiredScopes && requiredScopes.length > 0) {
      const keyScopes: string[] = JSON.parse(matched.scopes || '[]');
      const hasScope = requiredScopes.some((s) => keyScopes.includes(s));
      if (!hasScope) {
        throw new ForbiddenException('API key lacks required scope');
      }
    }

    // Attach user info (same shape as JWT strategy)
    request.user = {
      id: matched.user.id,
      email: matched.user.email,
      name: matched.user.name,
      role: matched.user.role,
      isSubscriber: !!matched.user.isSubscriber,
    };
    request.apiKeyId = matched.id;

    // Update lastUsedAt async (fire-and-forget)
    this.prisma.apiKey
      .update({ where: { id: matched.id }, data: { lastUsedAt: new Date() } })
      .catch(() => {});

    return true;
  }
}
