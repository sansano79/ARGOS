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
    const andClauses: any[] = [];

    if (query.severity) where.cvssV31Severity = query.severity.toUpperCase();
    if (query.exploited === 'true') where.isKnownExploited = true;
    if (query.riskTier) where.operationalRiskTier = query.riskTier.toLowerCase();
    if (query.exploitStatus) where.exploitStatus = query.exploitStatus.toLowerCase();
    if (query.vendor) where.primaryVendor = query.vendor.trim().toLowerCase();
    if (query.product) where.primaryProduct = query.product.trim().toLowerCase();
    if (query.weaknessCategory) where.weaknessCategory = query.weaknessCategory.trim().toLowerCase();
    if (query.hasPublicExploit === 'true') where.hasPublicExploit = true;
    if (query.hasPublicExploit === 'false') where.hasPublicExploit = false;
    if (query.patchAvailable === 'true') where.patchAvailable = true;
    if (query.patchAvailable === 'false') where.patchAvailable = false;
    if (query.recordStatus) where.recordStatus = query.recordStatus.trim();

    if (query.exploitType) {
      const et = query.exploitType.trim().toLowerCase();
      if (et === 'kev' || et === 'cisa_kev') {
        where.isKnownExploited = true;
      } else if (et === 'public_exploit' || et === 'exploitdb') {
        where.hasPublicExploit = true;
      } else if (et === 'confirmed') {
        andClauses.push({
          OR: [
            { isKnownExploited: true },
            { exploitStatus: 'active_exploitation' },
            { exploitStatus: 'confirmed' },
          ],
        });
      }
    }

    if (query.source) {
      const src = query.source.trim().toLowerCase();
      andClauses.push({
        OR: [
          { source: src },
          { canonicalSource: src },
          { sourcesPresent: { contains: src } },
          { sourceRecords: { some: { sourceName: src } } },
        ],
      });
    }

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

    // Incremental synchronization filter
    if (query.updatedSince) {
      const since = new Date(query.updatedSince);
      if (!isNaN(since.getTime())) {
        andClauses.push({
          OR: [
            { lastChangeDetectedAt: { gte: since } },
            { updatedAt: { gte: since } },
          ],
        });
      }
    }

    // Cursor navigation support
    if (query.cursor) {
      let cursorId: number | undefined;
      try {
        const raw = Buffer.from(query.cursor, 'base64').toString('utf8');
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed.id === 'number') {
          cursorId = parsed.id;
        }
      } catch {
        const num = parseInt(query.cursor, 10);
        if (Number.isFinite(num)) {
          cursorId = num;
        }
      }
      if (cursorId !== undefined) {
        where.id = { gt: cursorId };
      }
    }

    if (query.search && query.search.trim().length >= 2) {
      const q = query.search.trim();
      if (/^CVE-\d{4}/i.test(q)) {
        where.cveId = { contains: q.toUpperCase() };
      } else {
        andClauses.push({
          OR: [
            { cveId: { contains: q } },
            { description: { contains: q } },
            { primaryVendor: { contains: q.toLowerCase() } },
            { primaryProduct: { contains: q.toLowerCase() } },
          ],
        });
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

    // Notification filters (retaining filter capability without leaking subscriber data)
    if (query.notificable === 'true') where.isNotificable = true;
    if (query.notificable === 'false') where.isNotificable = false;
    if (query.notificada === 'true') where.notifications = { some: { status: 'sent' } };
    if (query.notificada === 'false') where.notifications = { none: { status: 'sent' } };

    if (andClauses.length > 0) {
      where.AND = andClauses;
    }

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
          id: true,
          cveId: true,
          description: true,
          cvssV31Score: true,
          cvssV31Severity: true,
          cvssV31Vector: true,
          cvssV40Score: true,
          cvssV40Severity: true,
          cvssV40Vector: true,
          cvssVersion: true,
          epssScore: true,
          epssPercentile: true,
          isKnownExploited: true,
          kevDateAdded: true,
          kevDueDate: true,
          hasPublicExploit: true,
          exploitStatus: true,
          exploitConfidence: true,
          exploitFirstSeenAt: true,
          exploitLastCheckedAt: true,
          primaryVendor: true,
          primaryProduct: true,
          affectedProducts: true,
          affectedProductsDetailed: true,
          affectedCpes: true,
          patchAvailable: true,
          patchPriority: true,
          fixedVersions: true,
          workarounds: true,
          detectionOpportunities: true,
          operationalRiskScore: true,
          operationalRiskTier: true,
          riskSignals: true,
          dataConfidence: true,
          canonicalSource: true,
          sourceCount: true,
          sourcesPresent: true,
          recordStatus: true,
          cweIds: true,
          cweNames: true,
          weaknessCategory: true,
          source: true,
          processingStatus: true,
          needsEnrichment: true,
          firstSeenAt: true,
          publishedAt: true,
          lastModifiedAt: true,
          lastChangeDetectedAt: true,
          enrichedAt: true,
          isNotificable: true,
          createdAt: true,
          updatedAt: true,
          tags: { select: { id: true, name: true, color: true } },
          notifications: {
            where: { status: 'sent' },
            select: { id: true, sentAt: true },
            orderBy: { sentAt: 'desc' as const },
            take: 1,
          },
          _count: {
            select: { notifications: { where: { status: 'sent' } } },
          },
        },
      }),
      this.prisma.vulnerability.count({ where }),
    ]);

    // Compute incremental sync metadata
    const hasMore = page * take < total;
    let nextCursor: string | null = null;
    let watermark: string | null = null;

    if (data.length > 0) {
      const lastItem = data[data.length - 1];
      if (hasMore) {
        nextCursor = Buffer.from(
          JSON.stringify({ id: lastItem.id, updatedAt: lastItem.updatedAt }),
        ).toString('base64');
      }

      const dates = data
        .map((v) => v.lastChangeDetectedAt ?? v.updatedAt)
        .filter(Boolean)
        .map((d) => new Date(d!).getTime());
      if (dates.length > 0) {
        watermark = new Date(Math.max(...dates)).toISOString();
      }
    }
    if (!watermark && query.updatedSince) {
      watermark = query.updatedSince;
    }

    return PaginatedResponse.create(
      data.map((v) => this.serializeVuln(v)),
      total,
      page,
      take,
      { hasMore, nextCursor, watermark },
    );
  }

  async getVulnerabilityByCveId(cveId: string, include?: string) {
    const vuln = await this.prisma.vulnerability.findUnique({
      where: { cveId: cveId.trim().toUpperCase() },
      include: {
        tags: { select: { id: true, name: true, color: true } },
        sourceRecords: {
          select: {
            id: true,
            sourceName: true,
            sourceUrl: true,
            confidence: true,
            isCanonical: true,
            firstSeenAt: true,
            lastSeenAt: true,
            sourcePublishedAt: true,
            sourceModifiedAt: true,
            normalizedData: true,
          },
        },
        notifications: {
          where: { status: 'sent' },
          select: { id: true, sentAt: true },
          orderBy: { sentAt: 'desc' as const },
          take: 1,
        },
        _count: {
          select: { notifications: { where: { status: 'sent' } } },
        },
      },
    });

    if (!vuln) throw new NotFoundException(`CVE ${cveId} not found`);

    const includeRaw = (include || '').toLowerCase().split(',').includes('raw');
    return this.serializeVulnDetail(vuln, includeRaw);
  }

  async getVulnerabilityEvidence(cveId: string, query: PaginationQueryDto) {
    const vuln = await this.prisma.vulnerability.findUnique({
      where: { cveId: cveId.trim().toUpperCase() },
      select: { id: true, cveId: true },
    });
    if (!vuln) throw new NotFoundException(`CVE ${cveId} not found`);

    const { page, take, skip } = this.paginate(query);
    const where = { cveId: vuln.cveId };

    const [records, total] = await Promise.all([
      this.prisma.vulnerabilitySourceRecord.findMany({
        where,
        orderBy: [{ isCanonical: 'desc' }, { lastSeenAt: 'desc' }],
        take,
        skip,
        select: {
          id: true,
          sourceName: true,
          sourceRecordId: true,
          sourceUrl: true,
          confidence: true,
          isCanonical: true,
          firstSeenAt: true,
          lastSeenAt: true,
          sourcePublishedAt: true,
          sourceModifiedAt: true,
          normalizedData: true,
        },
      }),
      this.prisma.vulnerabilitySourceRecord.count({ where }),
    ]);

    const data = records.map((r) => {
      const norm = this.parseJson(r.normalizedData) as any;
      return {
        id: r.id,
        source: r.sourceName,
        sourceUrl: r.sourceUrl,
        evidenceType: norm?.evidenceType ?? this.computeEvidenceType(r.sourceName),
        summary: norm?.summary ?? norm?.description ?? this.computeEvidenceSummary(r.sourceName, vuln.cveId),
        observedAt: r.firstSeenAt ?? r.sourcePublishedAt ?? null,
        lastValidatedAt: r.lastSeenAt ?? r.sourceModifiedAt ?? null,
        confidence: r.confidence ?? 1.0,
        isCanonical: r.isCanonical,
        status: r.lastSeenAt ? 'verified' : 'active',
      };
    });

    return PaginatedResponse.create(data, total, page, take);
  }

  async getCoverage() {
    const [
      totalVulnerabilities,
      totalEnriched,
      totalPending,
      totalKev,
      totalWithPublicExploit,
      totalConfirmedExploited,
    ] = await Promise.all([
      this.prisma.vulnerability.count(),
      this.prisma.vulnerability.count({ where: { processingStatus: 'enriched' } }),
      this.prisma.vulnerability.count({ where: { needsEnrichment: true } }),
      this.prisma.vulnerability.count({ where: { isKnownExploited: true } }),
      this.prisma.vulnerability.count({ where: { hasPublicExploit: true } }),
      this.prisma.vulnerability.count({
        where: {
          OR: [
            { isKnownExploited: true },
            { exploitStatus: 'active_exploitation' },
            { exploitStatus: 'confirmed' },
          ],
        },
      }),
    ]);

    const sourceGroups = await this.prisma.vulnerabilitySourceRecord.groupBy({
      by: ['sourceName'],
      _count: { cveId: true },
    });

    const sourceCounts: Record<string, number> = {};
    for (const g of sourceGroups) {
      sourceCounts[g.sourceName] = g._count.cveId;
    }

    const collectorRuns = await this.prisma.collectorRun.findMany({
      orderBy: { startedAt: 'desc' },
      take: 50,
    });

    const healthRecords = await this.prisma.collectorSourceHealth.findMany({
      orderBy: { runDate: 'desc' },
      take: 50,
    });

    const recentErrors = await this.prisma.collectorRun.findMany({
      where: {
        OR: [
          { status: 'failed' },
          { errorMessage: { not: null } },
        ],
      },
      orderBy: { startedAt: 'desc' },
      take: 10,
      select: {
        source: true,
        startedAt: true,
        finishedAt: true,
        errorMessage: true,
        status: true,
      },
    });

    const knownSources = ['nvd', 'cisa_kev', 'exploitdb', 'epss', 'cveorg', 'osv'];

    const coverageBySource: Record<string, any> = {};
    const lastExecutionBySource: Record<string, any> = {};

    for (const src of knownSources) {
      const count = sourceCounts[src];
      const latestRun = collectorRuns.find((r) => r.source.toLowerCase() === src.toLowerCase());
      const latestHealth = healthRecords.find((h) => h.source.toLowerCase() === src.toLowerCase());

      const hasRun = Boolean(latestRun || latestHealth);
      const isError =
        (latestRun && latestRun.status === 'failed') ||
        (latestHealth && latestHealth.fetchStatus === 'error');

      let sourceStatus: string;
      let isAvailable: boolean;

      if (!hasRun && count === undefined) {
        sourceStatus = 'not_configured';
        isAvailable = false;
      } else if (isError) {
        sourceStatus = 'source_unavailable';
        isAvailable = false;
      } else {
        sourceStatus = 'active';
        isAvailable = true;
      }

      const actualCount =
        count ??
        (src === 'nvd'
          ? totalVulnerabilities
          : src === 'cisa_kev'
          ? totalKev
          : src === 'exploitdb'
          ? totalWithPublicExploit
          : hasRun
          ? 0
          : null);

      coverageBySource[src] = {
        total: actualCount,
        percentage:
          totalVulnerabilities > 0 && actualCount !== null
            ? Math.round((actualCount / totalVulnerabilities) * 10000) / 100
            : null,
        status: sourceStatus,
        isAvailable,
        distinction:
          actualCount === 0
            ? 'real_zero'
            : actualCount === null
            ? 'unknown'
            : 'recorded',
      };

      lastExecutionBySource[src] = {
        runDate: latestRun?.startedAt ?? latestHealth?.runDate ?? null,
        status:
          latestRun?.status ?? latestHealth?.fetchStatus ?? (hasRun ? 'unknown' : 'never_run'),
        durationMs: latestRun?.durationMs ?? latestHealth?.durationMs ?? null,
        itemsProcessed: latestRun?.cvesFetched ?? latestHealth?.itemsProcessed ?? 0,
        itemsErrored: latestHealth?.itemsErrored ?? 0,
        errorMessage: latestRun?.errorMessage ?? latestHealth?.errorMessage ?? null,
      };
    }

    const now = Date.now();
    const latestRunTime = collectorRuns[0]?.startedAt
      ? new Date(collectorRuns[0].startedAt).getTime()
      : 0;
    const hoursSinceLastRun =
      latestRunTime > 0 ? (now - latestRunTime) / (1000 * 3600) : 999;

    let freshnessStatus: 'fresh' | 'stale' | 'outdated' | 'degraded';
    if (recentErrors.length > 0 && hoursSinceLastRun > 24) {
      freshnessStatus = 'degraded';
    } else if (hoursSinceLastRun <= 24) {
      freshnessStatus = 'fresh';
    } else if (hoursSinceLastRun <= 72) {
      freshnessStatus = 'stale';
    } else {
      freshnessStatus = 'outdated';
    }

    return {
      totalVulnerabilities,
      totalEnriched,
      totalPending,
      totalKev,
      totalWithPublicExploit,
      totalConfirmedExploited,
      coverageBySource,
      lastExecutionBySource,
      recentErrors: recentErrors.map((e) => ({
        source: e.source,
        timestamp: e.startedAt,
        errorMessage: e.errorMessage,
        status: e.status,
      })),
      calculatedAt: new Date().toISOString(),
      freshnessStatus,
    };
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
          id: true,
          source: true,
          changeType: true,
          fieldName: true,
          oldValue: true,
          newValue: true,
          isSignificant: true,
          summary: true,
          detectedAt: true,
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
          id: true,
          cveId: true,
          description: true,
          cvssV31Score: true,
          cvssV31Severity: true,
          epssScore: true,
          epssPercentile: true,
          kevDateAdded: true,
          kevDueDate: true,
          primaryVendor: true,
          primaryProduct: true,
          patchAvailable: true,
          patchPriority: true,
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
          id: true,
          cveId: true,
          description: true,
          cvssV31Score: true,
          cvssV31Severity: true,
          epssScore: true,
          epssPercentile: true,
          exploitStatus: true,
          exploitConfidence: true,
          exploitReferences: true,
          exploitFirstSeenAt: true,
          primaryVendor: true,
          primaryProduct: true,
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
          id: true,
          name: true,
          slug: true,
          owner: true,
          environment: true,
          criticality: true,
          productType: true,
          source: true,
          version: true,
          repositoryUrl: true,
          isActive: true,
          lastSeenAt: true,
          createdAt: true,
          updatedAt: true,
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

    const asset = await this.prisma.productAsset.findUnique({
      where: { id: assetId },
      select: { id: true },
    });
    if (!asset) throw new NotFoundException('Product asset not found');

    const [data, total] = await Promise.all([
      this.prisma.productDependencyInventory.findMany({
        where,
        orderBy: { lastSeenAt: 'desc' },
        take,
        skip,
        select: {
          id: true,
          componentName: true,
          componentVendor: true,
          componentVersion: true,
          componentType: true,
          ecosystem: true,
          purl: true,
          cpe: true,
          evidenceSource: true,
          directDependency: true,
          devDependency: true,
          confidence: true,
          firstSeenAt: true,
          lastSeenAt: true,
        },
      }),
      this.prisma.productDependencyInventory.count({ where }),
    ]);

    return PaginatedResponse.create(data, total, page, take);
  }

  async getProductAssetVulnerabilities(assetId: number, query: PaginationQueryDto) {
    const { page, take, skip } = this.paginate(query);
    const where = { productAssetId: assetId };

    const asset = await this.prisma.productAsset.findUnique({
      where: { id: assetId },
      select: { id: true },
    });
    if (!asset) throw new NotFoundException('Product asset not found');

    const [data, total] = await Promise.all([
      this.prisma.vulnerabilityProductImpact.findMany({
        where,
        orderBy: { firstDetectedAt: 'desc' },
        take,
        skip,
        select: {
          id: true,
          cveId: true,
          impactType: true,
          impactStatus: true,
          confidence: true,
          evidenceSource: true,
          evidenceSummary: true,
          matchedComponentName: true,
          matchedComponentVendor: true,
          matchedComponentVersion: true,
          fixedVersion: true,
          isDirectDependency: true,
          isRuntimeRelevant: true,
          firstDetectedAt: true,
          lastValidatedAt: true,
          resolvedAt: true,
          vulnerability: {
            select: {
              cvssV31Score: true,
              cvssV31Severity: true,
              epssScore: true,
              isKnownExploited: true,
              primaryVendor: true,
              primaryProduct: true,
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
          id: true,
          vendor: true,
          product: true,
          versions: true,
          createdAt: true,
          updatedAt: true,
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
        id: true,
        name: true,
        color: true,
        isAutoGenerated: true,
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
          id: true,
          startedAt: true,
          finishedAt: true,
          source: true,
          cvesFetched: true,
          cvesNew: true,
          cvesUpdated: true,
          status: true,
          errorMessage: true,
          durationMs: true,
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
        id: true,
        source: true,
        runDate: true,
        fetchStatus: true,
        itemsFetched: true,
        itemsProcessed: true,
        itemsErrored: true,
        durationMs: true,
        errorMessage: true,
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
          id: true,
          reportDate: true,
          periodStart: true,
          periodEnd: true,
          totalCves: true,
          criticalCount: true,
          highCount: true,
          exploitedCount: true,
          createdAt: true,
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

  private computeEvidenceType(sourceName: string): string {
    const s = (sourceName || '').toLowerCase();
    if (s === 'cisa_kev') return 'kev_catalog';
    if (s === 'exploitdb' || s === 'metasploit' || s === 'packetstorm') return 'exploit_poc';
    if (s === 'epss') return 'epss_metric';
    if (s === 'nvd') return 'nvd_cve_advisory';
    if (s === 'osv') return 'package_advisory';
    if (s === 'cveorg') return 'cve_record';
    return 'advisory';
  }

  private computeEvidenceSummary(sourceName: string, cveId: string): string {
    const s = (sourceName || '').toLowerCase();
    if (s === 'cisa_kev') return `Registro en el catálogo CISA KEV (Known Exploited Vulnerabilities) para ${cveId}`;
    if (s === 'exploitdb') return `Prueba de concepto de exploit público en ExploitDB para ${cveId}`;
    if (s === 'epss') return `Puntuación EPSS (Exploit Prediction Scoring System) para ${cveId}`;
    if (s === 'nvd') return `Registro oficial del National Vulnerability Database (NVD) para ${cveId}`;
    if (s === 'osv') return `Aviso de vulnerabilidad en repositorio de código abierto (OSV) para ${cveId}`;
    if (s === 'cveorg') return `Registro oficial CVE.org para ${cveId}`;
    return `Registro de fuente de inteligencia para ${cveId}`;
  }

  private computeEvidenceTypes(vuln: any): string[] {
    const types = new Set<string>();
    types.add('advisory');
    if (vuln.isKnownExploited) types.add('kev_catalog');
    if (vuln.hasPublicExploit) types.add('exploit_poc');
    if (vuln.epssScore !== null && vuln.epssScore !== undefined) types.add('epss_metric');
    if (vuln.sourceRecords && Array.isArray(vuln.sourceRecords)) {
      for (const r of vuln.sourceRecords) {
        types.add(this.computeEvidenceType(r.sourceName));
      }
    }
    const sources = this.parseJson(vuln.sourcesPresent);
    if (Array.isArray(sources)) {
      for (const s of sources) {
        types.add(this.computeEvidenceType(String(s)));
      }
    }
    return Array.from(types);
  }

  private computeIsConfirmedExploited(vuln: any): boolean {
    return Boolean(
      vuln.isKnownExploited ||
      vuln.exploitStatus === 'active_exploitation' ||
      vuln.exploitStatus === 'confirmed',
    );
  }

  private buildExploitationState(vuln: any) {
    const isConfirmed = this.computeIsConfirmedExploited(vuln);
    const exploitSources: string[] = [];

    if (vuln.isKnownExploited) exploitSources.push('cisa_kev');
    if (vuln.hasPublicExploit) exploitSources.push('exploitdb');

    const sources = this.parseJson(vuln.sourcesPresent);
    if (Array.isArray(sources)) {
      for (const s of sources) {
        const str = String(s).toLowerCase();
        if (
          ['cisa_kev', 'exploitdb', 'metasploit', 'packetstorm', 'vulncheck'].includes(str) &&
          !exploitSources.includes(str)
        ) {
          exploitSources.push(str);
        }
      }
    }
    if (Array.isArray(vuln.sourceRecords)) {
      for (const r of vuln.sourceRecords) {
        const str = String(r.sourceName).toLowerCase();
        if (
          ['cisa_kev', 'exploitdb', 'metasploit', 'packetstorm', 'vulncheck'].includes(str) &&
          !exploitSources.includes(str)
        ) {
          exploitSources.push(str);
        }
      }
    }

    let status: 'confirmed' | 'not_found' | 'unknown' | 'not_checked' | 'source_unavailable';
    if (isConfirmed || vuln.hasPublicExploit) {
      status = 'confirmed';
    } else if (
      vuln.exploitLastCheckedAt !== null ||
      vuln.exploitStatus === 'not_found' ||
      vuln.exploitStatus === 'none'
    ) {
      status = 'not_found';
    } else if (vuln.processingStatus === 'enriched' || vuln.enrichedAt !== null) {
      status = 'not_found';
    } else if (vuln.needsEnrichment || vuln.processingStatus === 'new') {
      status = 'not_checked';
    } else {
      status = 'unknown';
    }

    return {
      status,
      isKnownExploited: Boolean(vuln.isKnownExploited),
      hasPublicExploit: Boolean(vuln.hasPublicExploit),
      exploitStatus:
        vuln.exploitStatus ??
        (isConfirmed ? 'active_exploitation' : vuln.hasPublicExploit ? 'public_poc' : 'none'),
      sources: exploitSources,
      lastCheckedAt: vuln.exploitLastCheckedAt ?? vuln.enrichedAt ?? null,
    };
  }

  private buildEpssState(vuln: any) {
    let status: 'confirmed' | 'not_found' | 'unknown' | 'not_checked' | 'source_unavailable';
    if (vuln.epssScore !== null && vuln.epssScore !== undefined) {
      status = 'confirmed';
    } else if (vuln.enrichedAt !== null || vuln.processingStatus === 'enriched') {
      status = 'not_found';
    } else if (vuln.needsEnrichment) {
      status = 'not_checked';
    } else {
      status = 'unknown';
    }

    return {
      status,
      score: vuln.epssScore ?? null,
      percentile: vuln.epssPercentile ?? null,
      lastCheckedAt: vuln.enrichedAt ?? null,
    };
  }

  private buildPatchState(vuln: any, fixedVersions: any, workarounds: any) {
    const hasWorkarounds = Boolean(
      workarounds &&
        (Array.isArray(workarounds)
          ? workarounds.length > 0
          : Object.keys(workarounds).length > 0),
    );

    let status: 'available' | 'unavailable' | 'workaround_only' | 'unknown';
    if (vuln.patchAvailable === true) {
      status = 'available';
    } else if (vuln.patchAvailable === false) {
      status = hasWorkarounds ? 'workaround_only' : 'unavailable';
    } else if (vuln.patchPriority || (Array.isArray(fixedVersions) && fixedVersions.length > 0)) {
      status = 'available';
    } else {
      status = 'unknown';
    }

    return {
      status,
      isAvailable:
        vuln.patchAvailable ??
        (status === 'available' ? true : status === 'unavailable' ? false : null),
      priority: vuln.patchPriority ?? null,
      fixedVersions: Array.isArray(fixedVersions) ? fixedVersions : [],
      hasWorkarounds,
      workaroundsCount: Array.isArray(workarounds)
        ? workarounds.length
        : workarounds
        ? 1
        : 0,
    };
  }

  private buildPrimaryEntityState(vuln: any, cpes: any, detailedProducts: any) {
    let status: 'identified' | 'unresolved' | 'unknown' | 'multiple';
    if (vuln.primaryProduct === 'unresolved' || vuln.primaryVendor === 'unresolved') {
      status = 'unresolved';
    } else if (vuln.primaryVendor && vuln.primaryProduct) {
      status =
        Array.isArray(detailedProducts) && detailedProducts.length > 1
          ? 'multiple'
          : 'identified';
    } else if (vuln.needsEnrichment) {
      status = 'unknown';
    } else {
      status = 'unknown';
    }

    return {
      status,
      vendor: vuln.primaryVendor ?? null,
      product: vuln.primaryProduct ?? null,
      affectedCpes: Array.isArray(cpes) ? cpes : [],
      detailedCount: Array.isArray(detailedProducts) ? detailedProducts.length : 0,
    };
  }

  private buildOperationalRiskState(vuln: any, riskSignals: any) {
    let status: 'assessed' | 'pending' | 'unknown';
    if (vuln.operationalRiskScore !== null && vuln.operationalRiskScore !== undefined) {
      status = 'assessed';
    } else if (vuln.needsEnrichment || vuln.processingStatus === 'new') {
      status = 'pending';
    } else {
      status = 'unknown';
    }

    return {
      status,
      score: vuln.operationalRiskScore ?? null,
      tier: vuln.operationalRiskTier ?? null,
      signals: riskSignals ?? [],
    };
  }

  private serializeVuln(vuln: any) {
    const { notifications: rawNotifs, _count, ...rest } = vuln;
    const sentNotifs = Array.isArray(rawNotifs) ? rawNotifs : [];
    const fixedVersions = this.parseJson(rest.fixedVersions);
    const workarounds = this.parseJson(rest.workarounds);
    const riskSignals = this.parseJson(rest.riskSignals);
    const affectedCpes = this.parseJson(rest.affectedCpes) ?? [];
    const affectedProductsDetailed = this.parseJson(rest.affectedProductsDetailed) ?? [];
    const isConfirmedExploited = this.computeIsConfirmedExploited(vuln);
    const evidenceTypes = this.computeEvidenceTypes(vuln);

    const exploitation = this.buildExploitationState(vuln);
    const epss = this.buildEpssState(vuln);
    const patch = this.buildPatchState(vuln, fixedVersions, workarounds);
    const primaryEntity = this.buildPrimaryEntityState(
      vuln,
      affectedCpes,
      affectedProductsDetailed,
    );
    const operationalRisk = this.buildOperationalRiskState(vuln, riskSignals);

    return {
      ...rest,
      // Parsed legacy / flat fields
      affectedProducts: this.parseJson(rest.affectedProducts),
      affectedProductsDetailed,
      affectedCpes,
      fixedVersions,
      workarounds,
      detectionOpportunities: this.parseJson(rest.detectionOpportunities),
      riskSignals,
      sourcesPresent: this.parseJson(rest.sourcesPresent),
      cweIds: this.parseJson(rest.cweIds),
      cweNames: this.parseJson(rest.cweNames),

      // Contract expansion (Objective 1)
      dataConfidence: vuln.dataConfidence ?? null,
      recordStatus:
        vuln.recordStatus ??
        (vuln.processingStatus === 'enriched'
          ? 'enriched'
          : vuln.needsEnrichment
          ? 'needs_enrichment'
          : vuln.processingStatus),
      canonicalSource: vuln.canonicalSource ?? vuln.source ?? 'nvd',
      sourceCount: vuln.sourceCount ?? 1,
      enrichedAt: vuln.enrichedAt ?? null,
      lastChangeDetectedAt: vuln.lastChangeDetectedAt ?? vuln.updatedAt ?? null,
      exploitFirstSeenAt: vuln.exploitFirstSeenAt ?? null,
      exploitLastCheckedAt: vuln.exploitLastCheckedAt ?? null,
      patchPriority: vuln.patchPriority ?? null,
      evidenceTypes,
      isConfirmedExploited,

      // Intelligence states (Objective 2)
      exploitation,
      epss,
      patch,
      primaryEntity,
      affectedProduct: primaryEntity,
      operationalRisk,

      // Notification fields (Privacy compliant - NO personal data / emails)
      notificable: vuln.isNotificable ?? false,
      notificada: sentNotifs.length > 0,
      fechaNotificacion: sentNotifs.length > 0 ? sentNotifs[0].sentAt : null,
      notificacionesCount: _count?.notifications ?? sentNotifs.length,
    };
  }

  private serializeVulnDetail(vuln: any, includeRaw = false) {
    const base = this.serializeVuln(vuln);
    return {
      ...base,
      remediationInfo: this.parseJson(vuln.remediationInfo),
      exploitReferences: this.parseJson(vuln.exploitReferences),
      references: this.parseJson(vuln.references),
      sourceRecords:
        vuln.sourceRecords?.map((r: any) => ({
          source: r.sourceName,
          sourceUrl: r.sourceUrl,
          confidence: r.confidence ?? 1.0,
          isCanonical: r.isCanonical,
          firstSeenAt: r.firstSeenAt,
          lastSeenAt: r.lastSeenAt,
        })) ?? [],
      rawData: includeRaw ? this.parseJson(vuln.rawData) : undefined,
    };
  }
}
