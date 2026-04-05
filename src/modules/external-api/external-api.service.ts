import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { PaginatedResponse } from './dto/paginated-response.dto';
import {
  VulnerabilityQueryDto,
  ProductAssetQueryDto,
  CollectorRunQueryDto,
  SoftwareCatalogQueryDto,
  PaginationQueryDto,
} from './dto/vulnerability-query.dto';

@Injectable()
export class ExternalApiService {
  constructor(private readonly prisma: PrismaService) {}

  private paginate(query: PaginationQueryDto) {
    const page = query.page ?? 1;
    const limit = query.limit ?? 50;
    return { page, limit, take: limit, skip: (page - 1) * limit };
  }

  // ── Vulnerabilities ────────────────────────────────────────

  async listVulnerabilities(query: VulnerabilityQueryDto): Promise<PaginatedResponse<any>> {
    const { page, take, skip } = this.paginate(query);
    const where: any = {};

    if (query.severity) where.cvssV31Severity = query.severity.toUpperCase();
    if (query.exploited === 'true') where.isKnownExploited = true;
    if (query.riskTier) where.operationalRiskTier = query.riskTier.toLowerCase();
    if (query.exploitStatus) where.exploitStatus = query.exploitStatus.toLowerCase();
    if (query.vendor) where.primaryVendor = query.vendor.trim().toLowerCase();
    if (query.product) where.primaryProduct = query.product.trim().toLowerCase();
    if (query.weaknessCategory) where.weaknessCategory = query.weaknessCategory.trim().toLowerCase();
    if (query.hasPublicExploit === 'true') where.hasPublicExploit = true;
    if (query.patchAvailable === 'true') where.patchAvailable = true;
    if (query.patchAvailable === 'false') where.patchAvailable = false;

    if (query.minCvss !== undefined && query.minCvss > 0) {
      where.cvssV31Score = { ...(where.cvssV31Score || {}), gte: query.minCvss };
    }
    if (query.maxCvss !== undefined) {
      where.cvssV31Score = { ...(where.cvssV31Score || {}), lte: query.maxCvss };
    }
    if (query.minEpss !== undefined) {
      where.epssScore = { gte: query.minEpss };
    }

    if (query.publishedFrom) {
      const from = new Date(query.publishedFrom);
      if (!isNaN(from.getTime())) {
        where.publishedAt = { ...(where.publishedAt || {}), gte: from };
      }
    }
    if (query.publishedTo) {
      const to = new Date(query.publishedTo);
      if (!isNaN(to.getTime())) {
        where.publishedAt = { ...(where.publishedAt || {}), lte: to };
      }
    }

    if (query.search && query.search.trim().length >= 2) {
      const q = query.search.trim();
      if (/^CVE-\d{4}/i.test(q)) {
        where.cveId = { contains: q.toUpperCase() };
      } else {
        where.OR = [
          { cveId: { contains: q } },
          { description: { contains: q } },
          { primaryVendor: { contains: q.toLowerCase() } },
          { primaryProduct: { contains: q.toLowerCase() } },
        ];
      }
    }

    if (query.tag) {
      const tagId = parseInt(query.tag, 10);
      if (Number.isFinite(tagId)) {
        where.tags = { some: { id: tagId } };
      } else {
        where.tags = { some: { name: query.tag } };
      }
    }

    // Notification filters
    if (query.notificable === 'true') where.isNotificable = true;
    if (query.notificable === 'false') where.isNotificable = false;
    if (query.notificada === 'true') where.notifications = { some: { status: 'sent' } };
    if (query.notificada === 'false') where.notifications = { none: { status: 'sent' } };

    const [data, total] = await Promise.all([
      this.prisma.vulnerability.findMany({
        where,
        orderBy: [
          { isKnownExploited: 'desc' },
          { operationalRiskScore: 'desc' },
          { cvssV31Score: 'desc' },
          { publishedAt: 'desc' },
        ],
        take,
        skip,
        select: {
          id: true, cveId: true, description: true,
          cvssV31Score: true, cvssV31Severity: true, cvssV31Vector: true,
          cvssV40Score: true, cvssV40Severity: true, cvssV40Vector: true,
          epssScore: true, epssPercentile: true,
          isKnownExploited: true, kevDateAdded: true, kevDueDate: true,
          hasPublicExploit: true, exploitStatus: true, exploitConfidence: true,
          primaryVendor: true, primaryProduct: true,
          affectedProducts: true, affectedProductsDetailed: true,
          patchAvailable: true, patchPriority: true, fixedVersions: true,
          operationalRiskScore: true, operationalRiskTier: true,
          cweIds: true, cweNames: true, weaknessCategory: true,
          sourcesPresent: true, sourceCount: true,
          publishedAt: true, lastModifiedAt: true, firstSeenAt: true,
          isNotificable: true,
          tags: { select: { id: true, name: true, color: true } },
          notifications: {
            where: { status: 'sent' },
            select: {
              id: true, sentAt: true, recipientEmail: true, recipientName: true,
              subscriberUser: { select: { id: true, name: true, email: true } },
            },
            orderBy: { sentAt: 'desc' as const },
            take: 10,
          },
        },
      }),
      this.prisma.vulnerability.count({ where }),
    ]);

    return PaginatedResponse.create(
      data.map((v) => this.serializeVuln(v)),
      total,
      page,
      take,
    );
  }

  async getVulnerabilityByCveId(cveId: string) {
    const vuln = await this.prisma.vulnerability.findUnique({
      where: { cveId: cveId.trim().toUpperCase() },
      include: {
        tags: { select: { id: true, name: true, color: true } },
        sourceRecords: {
          select: {
            sourceName: true, sourceUrl: true, confidence: true,
            isCanonical: true, firstSeenAt: true, lastSeenAt: true,
          },
        },
      },
    });

    if (!vuln) throw new NotFoundException(`CVE ${cveId} not found`);

    return this.serializeVulnDetail(vuln);
  }

  async getVulnerabilityChanges(cveId: string, query: PaginationQueryDto) {
    const { page, take, skip } = this.paginate(query);

    const vuln = await this.prisma.vulnerability.findUnique({
      where: { cveId: cveId.trim().toUpperCase() },
      select: { id: true },
    });
    if (!vuln) throw new NotFoundException(`CVE ${cveId} not found`);

    const where = { vulnerabilityId: vuln.id };
    const [data, total] = await Promise.all([
      this.prisma.vulnerabilityChangeEvent.findMany({
        where,
        orderBy: { detectedAt: 'desc' },
        take,
        skip,
        select: {
          id: true, source: true, changeType: true, fieldName: true,
          oldValue: true, newValue: true, isSignificant: true,
          summary: true, detectedAt: true,
        },
      }),
      this.prisma.vulnerabilityChangeEvent.count({ where }),
    ]);

    return PaginatedResponse.create(
      data.map((e) => ({
        ...e,
        oldValue: this.parseJson(e.oldValue),
        newValue: this.parseJson(e.newValue),
      })),
      total,
      page,
      take,
    );
  }

  async getVulnerabilityStats() {
    const [total, critical, high, medium, low, exploited, withExploits, patchAvailable] =
      await Promise.all([
        this.prisma.vulnerability.count(),
        this.prisma.vulnerability.count({ where: { cvssV31Severity: 'CRITICAL' } }),
        this.prisma.vulnerability.count({ where: { cvssV31Severity: 'HIGH' } }),
        this.prisma.vulnerability.count({ where: { cvssV31Severity: 'MEDIUM' } }),
        this.prisma.vulnerability.count({ where: { cvssV31Severity: 'LOW' } }),
        this.prisma.vulnerability.count({ where: { isKnownExploited: true } }),
        this.prisma.vulnerability.count({ where: { hasPublicExploit: true } }),
        this.prisma.vulnerability.count({ where: { patchAvailable: true } }),
      ]);

    const last24h = await this.prisma.vulnerability.count({
      where: { firstSeenAt: { gte: new Date(Date.now() - 24 * 3600000) } },
    });
    const last7d = await this.prisma.vulnerability.count({
      where: { firstSeenAt: { gte: new Date(Date.now() - 7 * 24 * 3600000) } },
    });

    return {
      total,
      bySeverity: { critical, high, medium, low },
      exploited,
      withPublicExploits: withExploits,
      patchAvailable,
      newLast24h: last24h,
      newLast7d: last7d,
    };
  }

  // ── KEV & Exploits ─────────────────────────────────────────

  async listKev(query: PaginationQueryDto) {
    const { page, take, skip } = this.paginate(query);
    const where = { isKnownExploited: true };

    const [data, total] = await Promise.all([
      this.prisma.vulnerability.findMany({
        where,
        orderBy: [{ kevDateAdded: 'desc' }, { publishedAt: 'desc' }],
        take,
        skip,
        select: {
          id: true, cveId: true, description: true,
          cvssV31Score: true, cvssV31Severity: true,
          epssScore: true, epssPercentile: true,
          kevDateAdded: true, kevDueDate: true,
          primaryVendor: true, primaryProduct: true,
          patchAvailable: true, patchPriority: true,
          publishedAt: true,
        },
      }),
      this.prisma.vulnerability.count({ where }),
    ]);

    return PaginatedResponse.create(data, total, page, take);
  }

  async listExploits(query: PaginationQueryDto) {
    const { page, take, skip } = this.paginate(query);
    const where = { hasPublicExploit: true };

    const [data, total] = await Promise.all([
      this.prisma.vulnerability.findMany({
        where,
        orderBy: [{ exploitFirstSeenAt: 'desc' }, { publishedAt: 'desc' }],
        take,
        skip,
        select: {
          id: true, cveId: true, description: true,
          cvssV31Score: true, cvssV31Severity: true,
          epssScore: true, epssPercentile: true,
          exploitStatus: true, exploitConfidence: true,
          exploitReferences: true, exploitFirstSeenAt: true,
          primaryVendor: true, primaryProduct: true,
          publishedAt: true,
        },
      }),
      this.prisma.vulnerability.count({ where }),
    ]);

    return PaginatedResponse.create(
      data.map((v) => ({
        ...v,
        exploitReferences: this.parseJson(v.exploitReferences),
      })),
      total,
      page,
      take,
    );
  }

  // ── Product Assets ─────────────────────────────────────────

  async listProductAssets(query: ProductAssetQueryDto) {
    const { page, take, skip } = this.paginate(query);
    const where: any = {};

    if (query.environment) where.environment = query.environment;
    if (query.criticality) where.criticality = query.criticality;
    if (query.productType) where.productType = query.productType;
    if (query.isActive === 'true') where.isActive = true;
    if (query.isActive === 'false') where.isActive = false;
    if (query.search) where.name = { contains: query.search };

    const [data, total] = await Promise.all([
      this.prisma.productAsset.findMany({
        where,
        orderBy: { updatedAt: 'desc' },
        take,
        skip,
        select: {
          id: true, name: true, slug: true, owner: true,
          environment: true, criticality: true, productType: true,
          source: true, version: true, repositoryUrl: true,
          isActive: true, lastSeenAt: true,
          createdAt: true, updatedAt: true,
          _count: { select: { dependencyInventory: true, vulnerabilityImpacts: true } },
        },
      }),
      this.prisma.productAsset.count({ where }),
    ]);

    return PaginatedResponse.create(
      data.map((a) => ({
        ...a,
        dependencyCount: a._count.dependencyInventory,
        vulnerabilityCount: a._count.vulnerabilityImpacts,
        _count: undefined,
      })),
      total,
      page,
      take,
    );
  }

  async getProductAssetDependencies(assetId: number, query: PaginationQueryDto) {
    const { page, take, skip } = this.paginate(query);
    const where = { productAssetId: assetId };

    const asset = await this.prisma.productAsset.findUnique({ where: { id: assetId }, select: { id: true } });
    if (!asset) throw new NotFoundException('Product asset not found');

    const [data, total] = await Promise.all([
      this.prisma.productDependencyInventory.findMany({
        where,
        orderBy: { lastSeenAt: 'desc' },
        take,
        skip,
        select: {
          id: true, componentName: true, componentVendor: true,
          componentVersion: true, componentType: true, ecosystem: true,
          purl: true, cpe: true, evidenceSource: true,
          directDependency: true, devDependency: true,
          confidence: true, firstSeenAt: true, lastSeenAt: true,
        },
      }),
      this.prisma.productDependencyInventory.count({ where }),
    ]);

    return PaginatedResponse.create(data, total, page, take);
  }

  async getProductAssetVulnerabilities(assetId: number, query: PaginationQueryDto) {
    const { page, take, skip } = this.paginate(query);
    const where = { productAssetId: assetId };

    const asset = await this.prisma.productAsset.findUnique({ where: { id: assetId }, select: { id: true } });
    if (!asset) throw new NotFoundException('Product asset not found');

    const [data, total] = await Promise.all([
      this.prisma.vulnerabilityProductImpact.findMany({
        where,
        orderBy: { firstDetectedAt: 'desc' },
        take,
        skip,
        select: {
          id: true, cveId: true, impactType: true, impactStatus: true,
          confidence: true, evidenceSource: true, evidenceSummary: true,
          matchedComponentName: true, matchedComponentVendor: true,
          matchedComponentVersion: true, fixedVersion: true,
          isDirectDependency: true, isRuntimeRelevant: true,
          firstDetectedAt: true, lastValidatedAt: true, resolvedAt: true,
          vulnerability: {
            select: {
              cvssV31Score: true, cvssV31Severity: true,
              epssScore: true, isKnownExploited: true,
              primaryVendor: true, primaryProduct: true,
            },
          },
        },
      }),
      this.prisma.vulnerabilityProductImpact.count({ where }),
    ]);

    return PaginatedResponse.create(data, total, page, take);
  }

  // ── Software Catalog ───────────────────────────────────────

  async listSoftwareCatalog(query: SoftwareCatalogQueryDto) {
    const { page, take, skip } = this.paginate(query);
    const where: any = {};

    if (query.vendor) where.vendor = { contains: query.vendor.toLowerCase() };
    if (query.product) where.product = { contains: query.product.toLowerCase() };

    const [data, total] = await Promise.all([
      this.prisma.softwareCatalog.findMany({
        where,
        orderBy: [{ vendor: 'asc' }, { product: 'asc' }],
        take,
        skip,
        select: {
          id: true, vendor: true, product: true, versions: true,
          createdAt: true, updatedAt: true,
        },
      }),
      this.prisma.softwareCatalog.count({ where }),
    ]);

    return PaginatedResponse.create(
      data.map((c) => ({ ...c, versions: this.parseJson(c.versions) })),
      total,
      page,
      take,
    );
  }

  // ── Manufacturers ──────────────────────────────────────────

  async listManufacturers(query: PaginationQueryDto) {
    const { page, take, skip } = this.paginate(query);

    const [data, total] = await Promise.all([
      this.prisma.manufacturer.findMany({
        orderBy: { name: 'asc' },
        take,
        skip,
        select: { id: true, name: true, isActive: true, createdAt: true, updatedAt: true },
      }),
      this.prisma.manufacturer.count(),
    ]);

    return PaginatedResponse.create(data, total, page, take);
  }

  // ── Tags ───────────────────────────────────────────────────

  async listTags() {
    const tags = await this.prisma.vulnerabilityTag.findMany({
      orderBy: { name: 'asc' },
      select: {
        id: true, name: true, color: true, isAutoGenerated: true,
        _count: { select: { vulnerabilities: true } },
      },
    });

    return tags.map((t) => ({
      id: t.id,
      name: t.name,
      color: t.color,
      isAutoGenerated: t.isAutoGenerated,
      vulnerabilityCount: t._count.vulnerabilities,
    }));
  }

  // ── Collector ──────────────────────────────────────────────

  async listCollectorRuns(query: CollectorRunQueryDto) {
    const { page, take, skip } = this.paginate(query);
    const where: any = {};

    if (query.source) where.source = query.source;
    if (query.status) where.status = query.status;

    const [data, total] = await Promise.all([
      this.prisma.collectorRun.findMany({
        where,
        orderBy: { startedAt: 'desc' },
        take,
        skip,
        select: {
          id: true, startedAt: true, finishedAt: true, source: true,
          cvesFetched: true, cvesNew: true, cvesUpdated: true,
          status: true, errorMessage: true, durationMs: true,
        },
      }),
      this.prisma.collectorRun.count({ where }),
    ]);

    return PaginatedResponse.create(data, total, page, take);
  }

  async listSourcesHealth() {
    const sources = await this.prisma.collectorSourceHealth.findMany({
      orderBy: { runDate: 'desc' },
      take: 50,
      select: {
        id: true, source: true, runDate: true, fetchStatus: true,
        itemsFetched: true, itemsProcessed: true, itemsErrored: true,
        durationMs: true, errorMessage: true,
      },
    });

    return sources;
  }

  // ── Reports ────────────────────────────────────────────────

  async listReports(query: PaginationQueryDto) {
    const { page, take, skip } = this.paginate(query);

    const [data, total] = await Promise.all([
      this.prisma.vulnerabilityReport.findMany({
        orderBy: { reportDate: 'desc' },
        take,
        skip,
        select: {
          id: true, reportDate: true, periodStart: true, periodEnd: true,
          totalCves: true, criticalCount: true, highCount: true,
          exploitedCount: true, createdAt: true,
          user: { select: { id: true, name: true } },
        },
      }),
      this.prisma.vulnerabilityReport.count(),
    ]);

    return PaginatedResponse.create(data, total, page, take);
  }

  // ── Helpers ────────────────────────────────────────────────

  private parseJson(value: unknown): unknown {
    if (value === null || value === undefined) return null;
    if (typeof value !== 'string') return value;
    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  }

  private serializeVuln(vuln: any) {
    const { notifications: rawNotifs, ...rest } = vuln;
    const sentNotifs = Array.isArray(rawNotifs) ? rawNotifs : [];
    return {
      ...rest,
      affectedProducts: this.parseJson(rest.affectedProducts),
      affectedProductsDetailed: this.parseJson(rest.affectedProductsDetailed),
      fixedVersions: this.parseJson(rest.fixedVersions),
      sourcesPresent: this.parseJson(rest.sourcesPresent),
      cweIds: this.parseJson(rest.cweIds),
      cweNames: this.parseJson(rest.cweNames),
      notificable: vuln.isNotificable ?? false,
      notificada: sentNotifs.length > 0,
      fechaNotificacion: sentNotifs.length > 0 ? sentNotifs[0].sentAt : null,
      suscriptoresNotificados: sentNotifs.map((n: any) => ({
        sentAt: n.sentAt,
        recipientEmail: n.recipientEmail,
        recipientName: n.recipientName,
        subscriberUser: n.subscriberUser,
      })),
    };
  }

  private serializeVulnDetail(vuln: any) {
    const { notifications: rawNotifs, ...rest } = vuln;
    const sentNotifs = Array.isArray(rawNotifs) ? rawNotifs.filter((n: any) => n.status === 'sent' || !n.status) : [];
    return {
      ...rest,
      affectedProducts: this.parseJson(rest.affectedProducts),
      affectedProductsDetailed: this.parseJson(rest.affectedProductsDetailed),
      remediationInfo: this.parseJson(rest.remediationInfo),
      exploitReferences: this.parseJson(rest.exploitReferences),
      references: this.parseJson(rest.references),
      riskSignals: this.parseJson(rest.riskSignals),
      rawData: this.parseJson(rest.rawData),
      fixedVersions: this.parseJson(rest.fixedVersions),
      workarounds: this.parseJson(rest.workarounds),
      detectionOpportunities: this.parseJson(rest.detectionOpportunities),
      sourcesPresent: this.parseJson(rest.sourcesPresent),
      cweIds: this.parseJson(rest.cweIds),
      cweNames: this.parseJson(rest.cweNames),
      affectedCpes: this.parseJson(rest.affectedCpes),
      notificable: vuln.isNotificable ?? false,
      notificada: sentNotifs.length > 0,
      fechaNotificacion: sentNotifs.length > 0 ? sentNotifs[0].sentAt : null,
      suscriptoresNotificados: sentNotifs.map((n: any) => ({
        sentAt: n.sentAt,
        recipientEmail: n.recipientEmail,
        recipientName: n.recipientName,
        subscriberUser: n.subscriberUser,
      })),
    };
  }
}
