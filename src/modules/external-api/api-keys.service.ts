import { Injectable, NotFoundException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { PrismaService } from '../../prisma/prisma.service';

const ALL_SCOPES = [
  'vulnerabilities:read',
  'products:read',
  'catalog:read',
  'collector:read',
  'reports:read',
];

@Injectable()
export class ApiKeysService {
  constructor(private readonly prisma: PrismaService) {}

  async create(
    userId: number,
    data: { name: string; scopes?: string[]; expiresAt?: string },
  ) {
    const rawKey = 'occ_' + crypto.randomBytes(20).toString('hex');
    const keyPrefix = rawKey.substring(0, 12);
    const keyHash = await bcrypt.hash(rawKey, 10);
    const scopes = data.scopes && data.scopes.length > 0 ? data.scopes : ALL_SCOPES;

    const apiKey = await this.prisma.apiKey.create({
      data: {
        name: data.name,
        keyHash,
        keyPrefix,
        userId,
        scopes: JSON.stringify(scopes),
        expiresAt: data.expiresAt ? new Date(data.expiresAt) : null,
      },
    });

    return {
      id: apiKey.id,
      name: apiKey.name,
      key: rawKey,
      keyPrefix,
      scopes,
      expiresAt: apiKey.expiresAt,
      createdAt: apiKey.createdAt,
      message: 'Store this key securely — it will not be shown again.',
    };
  }

  async findAll() {
    const keys = await this.prisma.apiKey.findMany({
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        name: true,
        keyPrefix: true,
        scopes: true,
        isActive: true,
        expiresAt: true,
        lastUsedAt: true,
        createdAt: true,
        user: { select: { id: true, name: true, email: true } },
      },
    });

    return keys.map((k) => ({
      ...k,
      scopes: JSON.parse(k.scopes || '[]'),
    }));
  }

  async update(id: number, data: { name?: string; scopes?: string[]; isActive?: boolean }) {
    const existing = await this.prisma.apiKey.findUnique({ where: { id } });
    if (!existing) throw new NotFoundException('API key not found');

    const updateData: any = {};
    if (data.name !== undefined) updateData.name = data.name;
    if (data.scopes !== undefined) updateData.scopes = JSON.stringify(data.scopes);
    if (data.isActive !== undefined) updateData.isActive = data.isActive;

    const updated = await this.prisma.apiKey.update({
      where: { id },
      data: updateData,
      select: {
        id: true,
        name: true,
        keyPrefix: true,
        scopes: true,
        isActive: true,
        expiresAt: true,
        lastUsedAt: true,
        createdAt: true,
      },
    });

    return { ...updated, scopes: JSON.parse(updated.scopes || '[]') };
  }

  async revoke(id: number) {
    const existing = await this.prisma.apiKey.findUnique({ where: { id } });
    if (!existing) throw new NotFoundException('API key not found');

    await this.prisma.apiKey.update({
      where: { id },
      data: { isActive: false },
    });

    return { message: 'API key revoked' };
  }

  getAvailableScopes() {
    return ALL_SCOPES;
  }
}
