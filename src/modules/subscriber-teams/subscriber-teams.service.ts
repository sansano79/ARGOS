import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { CreateTeamDto } from './dto/create-team.dto';
import { UpdateTeamDto } from './dto/update-team.dto';
import { AddMemberDto } from './dto/add-member.dto';
import { UpdateMemberDto } from './dto/update-member.dto';
import { CreateRecipientDto } from './dto/create-recipient.dto';
import { UpdateRecipientDto } from './dto/update-recipient.dto';
import { CreateSubscriptionDto } from './dto/create-subscription.dto';
import { UpdateSubscriptionDto } from './dto/update-subscription.dto';
import { CreateSystemDto } from './dto/create-system.dto';
import { UpdateSystemDto } from './dto/update-system.dto';

const PRISMA_UNIQUE_VIOLATION = 'P2002';
const PRISMA_FK_VIOLATION = 'P2003';
const PRISMA_NOT_FOUND = 'P2025';

function mapPrismaError(err: any): never {
  if (err?.code === PRISMA_UNIQUE_VIOLATION) throw new ConflictException('Duplicate value: resource already exists');
  if (err?.code === PRISMA_FK_VIOLATION) throw new BadRequestException('Referenced resource does not exist');
  if (err?.code === PRISMA_NOT_FOUND) throw new NotFoundException('Resource not found');
  throw err;
}

const trim = (v: string | undefined) => (v !== undefined ? v.trim() : v);
const lower = (v: string | undefined) => (v !== undefined ? v.trim().toLowerCase() : v);

// ── Selects ──────────────────────────────────────────────────────

const MEMBER_SELECT = {
  id: true,
  role: true,
  isActive: true,
  createdAt: true,
  updatedAt: true,
  user: { select: { id: true, email: true, name: true } },
} as const;

const SYSTEM_LIST_SELECT = {
  id: true,
  teamId: true,
  externalId: true,
  source: true,
  name: true,
  description: true,
  hostname: true,
  fqdn: true,
  platform: true,
  osVersion: true,
  riskLevel: true,
  healthStatus: true,
  isSelected: true,
  isActive: true,
  tags: true,
  createdAt: true,
  updatedAt: true,
  // rawData intentionally excluded from list; available via dedicated detail endpoint if added
} as const;

@Injectable()
export class SubscriberTeamsService {
  constructor(private readonly prisma: PrismaService) {}

  // ── Admin: teams ──────────────────────────────────────────────

  async findAllTeams() {
    return this.prisma.subscriberTeam.findMany({
      orderBy: { name: 'asc' },
      select: {
        id: true,
        name: true,
        code: true,
        description: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
        _count: { select: { members: { where: { isActive: true } } } },
      },
    });
  }

  async findTeamById(teamId: number) {
    const team = await this.prisma.subscriberTeam.findUnique({
      where: { id: teamId },
      select: {
        id: true,
        name: true,
        code: true,
        description: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
        members: {
          where: { isActive: true },
          select: MEMBER_SELECT,
        },
      },
    });
    if (!team) throw new NotFoundException(`Team ${teamId} not found`);
    return team;
  }

  async createTeam(dto: CreateTeamDto) {
    try {
      return await this.prisma.subscriberTeam.create({
        data: {
          name: dto.name.trim(),
          code: dto.code.trim().toLowerCase(),
          description: dto.description?.trim() ?? null,
          isActive: dto.isActive ?? true,
        },
      });
    } catch (err) {
      mapPrismaError(err);
    }
  }

  async updateTeam(teamId: number, dto: UpdateTeamDto) {
    await this.findTeamById(teamId);
    try {
      return await this.prisma.subscriberTeam.update({
        where: { id: teamId },
        data: {
          ...(dto.name !== undefined && { name: dto.name.trim() }),
          ...(dto.code !== undefined && { code: dto.code.trim().toLowerCase() }),
          ...(dto.description !== undefined && { description: dto.description.trim() }),
          ...(dto.isActive !== undefined && { isActive: dto.isActive }),
        },
      });
    } catch (err) {
      mapPrismaError(err);
    }
  }

  // ── Admin: members ────────────────────────────────────────────

  async findTeamMembers(teamId: number) {
    await this.findTeamById(teamId);
    return this.prisma.teamMember.findMany({
      where: { teamId },
      select: MEMBER_SELECT,
      orderBy: { createdAt: 'asc' },
    });
  }

  async addMember(teamId: number, dto: AddMemberDto) {
    await this.findTeamById(teamId);
    const user = await this.prisma.user.findUnique({ where: { id: dto.userId }, select: { id: true } });
    if (!user) throw new NotFoundException(`User ${dto.userId} not found`);
    try {
      return await this.prisma.teamMember.create({
        data: { teamId, userId: dto.userId, role: dto.role, isActive: true },
        select: MEMBER_SELECT,
      });
    } catch (err) {
      mapPrismaError(err);
    }
  }

  async updateMember(teamId: number, memberId: number, dto: UpdateMemberDto) {
    const member = await this.prisma.teamMember.findFirst({
      where: { id: memberId, teamId },
      select: { id: true },
    });
    if (!member) throw new NotFoundException(`Member ${memberId} not found in team ${teamId}`);
    return this.prisma.teamMember.update({
      where: { id: memberId },
      data: {
        ...(dto.role !== undefined && { role: dto.role }),
        ...(dto.isActive !== undefined && { isActive: dto.isActive }),
      },
      select: MEMBER_SELECT,
    });
  }

  async removeMember(teamId: number, memberId: number) {
    const member = await this.prisma.teamMember.findFirst({
      where: { id: memberId, teamId },
      select: { id: true },
    });
    if (!member) throw new NotFoundException(`Member ${memberId} not found in team ${teamId}`);
    await this.prisma.teamMember.delete({ where: { id: memberId } });
    return { deleted: true };
  }

  // ── Admin: recipients ─────────────────────────────────────────

  async findRecipients(teamId: number) {
    await this.findTeamById(teamId);
    return this.prisma.notificationRecipient.findMany({
      where: { teamId },
      orderBy: { email: 'asc' },
    });
  }

  async createRecipient(teamId: number, dto: CreateRecipientDto) {
    await this.findTeamById(teamId);
    try {
      return await this.prisma.notificationRecipient.create({
        data: {
          teamId,
          email: dto.email.trim().toLowerCase(),
          name: dto.name?.trim() ?? null,
          type: dto.type ?? 'MAILBOX',
          language: dto.language?.trim() ?? 'es',
          timezone: dto.timezone?.trim() ?? 'Europe/Madrid',
          isActive: dto.isActive ?? true,
        },
      });
    } catch (err) {
      mapPrismaError(err);
    }
  }

  async updateRecipient(teamId: number, recipientId: number, dto: UpdateRecipientDto) {
    const rec = await this.prisma.notificationRecipient.findFirst({
      where: { id: recipientId, teamId },
      select: { id: true },
    });
    if (!rec) throw new NotFoundException(`Recipient ${recipientId} not found in team ${teamId}`);
    try {
      return await this.prisma.notificationRecipient.update({
        where: { id: recipientId },
        data: {
          ...(dto.email !== undefined && { email: dto.email.trim().toLowerCase() }),
          ...(dto.name !== undefined && { name: dto.name.trim() }),
          ...(dto.type !== undefined && { type: dto.type }),
          ...(dto.language !== undefined && { language: dto.language.trim() }),
          ...(dto.timezone !== undefined && { timezone: dto.timezone.trim() }),
          ...(dto.isActive !== undefined && { isActive: dto.isActive }),
        },
      });
    } catch (err) {
      mapPrismaError(err);
    }
  }

  async removeRecipient(teamId: number, recipientId: number) {
    const rec = await this.prisma.notificationRecipient.findFirst({
      where: { id: recipientId, teamId },
      select: { id: true },
    });
    if (!rec) throw new NotFoundException(`Recipient ${recipientId} not found in team ${teamId}`);
    await this.prisma.notificationRecipient.delete({ where: { id: recipientId } });
    return { deleted: true };
  }

  // ── Shared: subscriptions ─────────────────────────────────────

  async findSubscriptions(teamId: number) {
    return this.prisma.teamSubscription.findMany({
      where: { teamId },
      orderBy: [{ vendor: 'asc' }, { product: 'asc' }],
    });
  }

  async createSubscription(teamId: number, dto: CreateSubscriptionDto) {
    const vendor = dto.vendor.trim().toLowerCase();
    const product = dto.product.trim().toLowerCase();
    try {
      return await this.prisma.teamSubscription.create({
        data: {
          teamId,
          vendor,
          product,
          versions: dto.versions ? JSON.stringify(dto.versions) : null,
          isActive: dto.isActive ?? true,
        },
      });
    } catch (err) {
      mapPrismaError(err);
    }
  }

  async updateSubscription(teamId: number, subscriptionId: number, dto: UpdateSubscriptionDto) {
    const sub = await this.prisma.teamSubscription.findFirst({
      where: { id: subscriptionId, teamId },
      select: { id: true },
    });
    if (!sub) throw new NotFoundException(`Subscription ${subscriptionId} not found in team ${teamId}`);
    try {
      return await this.prisma.teamSubscription.update({
        where: { id: subscriptionId },
        data: {
          ...(dto.vendor !== undefined && { vendor: dto.vendor.trim().toLowerCase() }),
          ...(dto.product !== undefined && { product: dto.product.trim().toLowerCase() }),
          ...(dto.versions !== undefined && { versions: JSON.stringify(dto.versions) }),
          ...(dto.isActive !== undefined && { isActive: dto.isActive }),
        },
      });
    } catch (err) {
      mapPrismaError(err);
    }
  }

  async removeSubscription(teamId: number, subscriptionId: number) {
    const sub = await this.prisma.teamSubscription.findFirst({
      where: { id: subscriptionId, teamId },
      select: { id: true },
    });
    if (!sub) throw new NotFoundException(`Subscription ${subscriptionId} not found in team ${teamId}`);
    await this.prisma.teamSubscription.delete({ where: { id: subscriptionId } });
    return { deleted: true };
  }

  // ── Shared: systems ───────────────────────────────────────────

  async findSystems(teamId: number) {
    return this.prisma.teamSystem.findMany({
      where: { teamId },
      orderBy: { name: 'asc' },
      select: SYSTEM_LIST_SELECT,
    });
  }

  async createSystem(teamId: number, dto: CreateSystemDto) {
    try {
      return await this.prisma.teamSystem.create({
        data: {
          teamId,
          name: dto.name.trim(),
          externalId: trim(dto.externalId) ?? null,
          source: trim(dto.source) ?? 'manual',
          description: trim(dto.description) ?? null,
          hostname: lower(dto.hostname) ?? null,
          fqdn: lower(dto.fqdn) ?? null,
          platform: trim(dto.platform) ?? null,
          osVersion: trim(dto.osVersion) ?? null,
          riskLevel: trim(dto.riskLevel) ?? null,
          healthStatus: trim(dto.healthStatus) ?? null,
          isSelected: dto.isSelected ?? true,
          isActive: dto.isActive ?? true,
          tags: trim(dto.tags) ?? null,
        },
      });
    } catch (err) {
      mapPrismaError(err);
    }
  }

  async updateSystem(teamId: number, systemId: number, dto: UpdateSystemDto) {
    const sys = await this.prisma.teamSystem.findFirst({
      where: { id: systemId, teamId },
      select: { id: true },
    });
    if (!sys) throw new NotFoundException(`System ${systemId} not found in team ${teamId}`);
    try {
      return await this.prisma.teamSystem.update({
        where: { id: systemId },
        data: {
          ...(dto.name !== undefined && { name: dto.name.trim() }),
          ...(dto.externalId !== undefined && { externalId: trim(dto.externalId) }),
          ...(dto.description !== undefined && { description: trim(dto.description) }),
          ...(dto.hostname !== undefined && { hostname: lower(dto.hostname) }),
          ...(dto.fqdn !== undefined && { fqdn: lower(dto.fqdn) }),
          ...(dto.platform !== undefined && { platform: trim(dto.platform) }),
          ...(dto.osVersion !== undefined && { osVersion: trim(dto.osVersion) }),
          ...(dto.riskLevel !== undefined && { riskLevel: trim(dto.riskLevel) }),
          ...(dto.healthStatus !== undefined && { healthStatus: trim(dto.healthStatus) }),
          ...(dto.isSelected !== undefined && { isSelected: dto.isSelected }),
          ...(dto.isActive !== undefined && { isActive: dto.isActive }),
          ...(dto.tags !== undefined && { tags: trim(dto.tags) }),
        },
      });
    } catch (err) {
      mapPrismaError(err);
    }
  }

  async removeSystem(teamId: number, systemId: number) {
    const sys = await this.prisma.teamSystem.findFirst({
      where: { id: systemId, teamId },
      select: { id: true },
    });
    if (!sys) throw new NotFoundException(`System ${systemId} not found in team ${teamId}`);
    await this.prisma.teamSystem.delete({ where: { id: systemId } });
    return { deleted: true };
  }
}
