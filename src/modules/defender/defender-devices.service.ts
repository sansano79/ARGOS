import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { DEFENDER_SOURCE } from './defender.types';

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
type SeverityCounts = Record<(typeof SEVERITIES)[number] | 'other', number>;

const emptyCounts = (): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, other: 0 });

const parseJson = (raw: string | null | undefined) => {
  if (!raw) return {};
  try {
    return JSON.parse(raw) || {};
  } catch {
    return {};
  }
};

export interface FindingsQuery {
  status?: string;
  search?: string;
  page?: number;
  pageSize?: number;
}

@Injectable()
export class DefenderDevicesService {
  constructor(private readonly prisma: PrismaService) {}

  async listDevices(options: { includeInactive?: boolean; search?: string } = {}) {
    const search = String(options.search || '').trim();
    const systems = await this.prisma.teamSystem.findMany({
      where: {
        source: DEFENDER_SOURCE,
        ...(options.includeInactive ? {} : { isActive: true }),
        ...(search ? { OR: [{ name: { contains: search } }, { tags: { contains: search } }] } : {}),
      },
      include: { team: { select: { id: true, name: true } } },
      orderBy: { name: 'asc' },
    });
    const ids = systems.map((s) => s.id);
    if (!ids.length) return { items: [], total: 0 };

    const [bySeverity, kev, publicExploit, unknown] = await Promise.all([
      this.prisma.deviceVulnerabilityFinding.groupBy({
        by: ['teamSystemId', 'defenderSeverity'],
        where: { teamSystemId: { in: ids }, status: 'open' },
        _count: { _all: true },
      }),
      this.countOpen(ids, { vulnerability: { isKnownExploited: true } }),
      this.countOpen(ids, {
        OR: [
          { vulnerability: { hasPublicExploit: true } },
          { exploitabilityLevel: { in: ['ExploitIsPublic', 'ExploitIsVerified', 'ExploitIsInKit'] } },
        ],
      }),
      this.countOpen(ids, { vulnerabilityId: null }),
    ]);

    const counts = new Map<number, SeverityCounts>();
    for (const row of bySeverity) {
      const c = counts.get(row.teamSystemId) || emptyCounts();
      const sev = String(row.defenderSeverity || '').toLowerCase() as keyof SeverityCounts;
      c[(SEVERITIES as readonly string[]).includes(sev) ? sev : 'other'] += row._count._all;
      counts.set(row.teamSystemId, c);
    }

    const items = systems.map((s) => {
      const raw = parseJson(s.rawData);
      const sev = counts.get(s.id) || emptyCounts();
      return {
        id: s.id,
        externalId: s.externalId,
        name: s.name,
        fqdn: s.fqdn,
        platform: s.platform,
        osVersion: s.osVersion,
        tags: s.tags,
        isActive: s.isActive,
        team: s.team,
        defenderRiskScore: s.riskLevel,
        exposureLevel: raw.exposureLevel ?? null,
        deviceValue: raw.deviceValue ?? null,
        rbacGroupName: raw.rbacGroupName ?? null,
        lastIpAddress: raw.lastIpAddress ?? null,
        lastSeen: raw.lastSeen ?? null,
        healthStatus: s.healthStatus,
        updatedAt: s.updatedAt,
        openFindings: {
          total: Object.values(sev).reduce((a, b) => a + b, 0),
          ...sev,
          knownExploited: kev.get(s.id) || 0,
          publicExploit: publicExploit.get(s.id) || 0,
          notInCatalog: unknown.get(s.id) || 0,
        },
      };
    });

    return { items, total: items.length };
  }

  private async countOpen(ids: number[], where: Prisma.DeviceVulnerabilityFindingWhereInput) {
    const rows = await this.prisma.deviceVulnerabilityFinding.groupBy({
      by: ['teamSystemId'],
      where: { teamSystemId: { in: ids }, status: 'open', ...where },
      _count: { _all: true },
    });
    return new Map(rows.map((r) => [r.teamSystemId, r._count._all]));
  }

  async getDevice(id: number) {
    const system = await this.prisma.teamSystem.findFirst({
      where: { id, source: DEFENDER_SOURCE },
      include: { team: { select: { id: true, name: true } } },
    });
    if (!system) throw new NotFoundException('Servidor de Defender no encontrado');
    return system;
  }

  async listFindings(teamSystemId: number, query: FindingsQuery = {}) {
    await this.getDevice(teamSystemId);
    const status = query.status === 'fixed' || query.status === 'all' ? query.status : 'open';
    const page = Math.max(1, Number(query.page) || 1);
    const pageSize = Math.min(500, Math.max(1, Number(query.pageSize) || 100));
    const search = String(query.search || '').trim();

    const where: Prisma.DeviceVulnerabilityFindingWhereInput = {
      teamSystemId,
      ...(status === 'all' ? {} : { status }),
      ...(search
        ? { OR: [{ cveId: { contains: search } }, { productName: { contains: search } }, { fixingKbId: { contains: search } }] }
        : {}),
    };

    const [total, rows] = await Promise.all([
      this.prisma.deviceVulnerabilityFinding.count({ where }),
      this.prisma.deviceVulnerabilityFinding.findMany({
        where,
        orderBy: [
          { vulnerability: { isKnownExploited: 'desc' } },
          { vulnerability: { cvssV31Score: { sort: 'desc', nulls: 'last' } } },
          { cveId: 'desc' },
        ],
        skip: (page - 1) * pageSize,
        take: pageSize,
        include: {
          vulnerability: {
            select: {
              cveId: true,
              cvssV31Score: true,
              cvssV31Severity: true,
              cvssV31Vector: true,
              epssScore: true,
              epssPercentile: true,
              isKnownExploited: true,
              hasPublicExploit: true,
              exploitStatus: true,
              patchAvailable: true,
              weaknessCategory: true,
            },
          },
        },
      }),
    ]);

    return {
      items: rows.map((r) => ({
        id: r.id,
        cveId: r.cveId,
        status: r.status,
        productVendor: r.productVendor,
        productName: r.productName,
        productVersion: r.productVersion,
        defenderSeverity: r.defenderSeverity,
        defenderCvss: r.defenderCvss,
        exploitabilityLevel: r.exploitabilityLevel,
        fixingKbId: r.fixingKbId,
        recommendedUpdate: r.recommendedUpdate,
        firstSeenAt: r.firstSeenAt,
        lastSeenAt: r.lastSeenAt,
        fixedAt: r.fixedAt,
        inCatalog: Boolean(r.vulnerability),
        intelligence: r.vulnerability,
      })),
      total,
      page,
      pageSize,
    };
  }
}
