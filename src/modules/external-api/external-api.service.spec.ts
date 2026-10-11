import { NotFoundException } from '@nestjs/common';
import { ExternalApiService } from './external-api.service';

describe('ExternalApiService', () => {
  let service: ExternalApiService;
  let prismaMock: any;

  beforeEach(() => {
    prismaMock = {
      vulnerability: {
        findMany: jest.fn(),
        findUnique: jest.fn(),
        count: jest.fn(),
      },
      vulnerabilitySourceRecord: {
        findMany: jest.fn(),
        count: jest.fn(),
        groupBy: jest.fn(),
      },
      collectorRun: {
        findMany: jest.fn(),
        count: jest.fn(),
      },
      collectorSourceHealth: {
        findMany: jest.fn(),
      },
      vulnerabilityChangeEvent: {
        findMany: jest.fn(),
        count: jest.fn(),
      },
      productAsset: {
        findMany: jest.fn(),
        findUnique: jest.fn(),
        count: jest.fn(),
      },
      softwareCatalog: {
        findMany: jest.fn(),
        count: jest.fn(),
      },
      manufacturer: {
        findMany: jest.fn(),
        count: jest.fn(),
      },
      vulnerabilityTag: {
        findMany: jest.fn(),
      },
    };

    service = new ExternalApiService(prismaMock as any);
  });

  describe('1. Vulnerability Contract Compatibility & Enhancements', () => {
    it('preserves existing flat fields and includes all new contract attributes in list', async () => {
      const mockVuln = {
        id: 101,
        cveId: 'CVE-2024-1234',
        description: 'Buffer overflow vulnerability in HTTP service',
        cvssV31Score: 9.8,
        cvssV31Severity: 'CRITICAL',
        cvssV31Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        cvssV40Score: null,
        cvssV40Severity: null,
        cvssV40Vector: null,
        cvssVersion: '3.1',
        epssScore: 0.85,
        epssPercentile: 0.98,
        isKnownExploited: true,
        kevDateAdded: new Date('2024-02-01T00:00:00Z'),
        kevDueDate: new Date('2024-02-21T00:00:00Z'),
        hasPublicExploit: true,
        exploitStatus: 'active_exploitation',
        exploitConfidence: 0.95,
        exploitFirstSeenAt: new Date('2024-01-15T00:00:00Z'),
        exploitLastCheckedAt: new Date('2024-02-05T00:00:00Z'),
        primaryVendor: 'apache',
        primaryProduct: 'http_server',
        affectedProducts: JSON.stringify(['apache http_server']),
        affectedProductsDetailed: JSON.stringify([{ vendor: 'apache', product: 'http_server', versions: ['2.4.49'] }]),
        affectedCpes: JSON.stringify(['cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*']),
        patchAvailable: true,
        patchPriority: 'CRITICAL',
        fixedVersions: JSON.stringify(['2.4.50']),
        workarounds: JSON.stringify(['Disable path traversal module']),
        detectionOpportunities: JSON.stringify(['Monitor /cgi-bin requests']),
        operationalRiskScore: 95.0,
        operationalRiskTier: 'critical',
        riskSignals: JSON.stringify(['remote_code_execution', 'in_the_wild']),
        dataConfidence: 0.99,
        canonicalSource: 'nvd',
        sourceCount: 3,
        sourcesPresent: JSON.stringify(['nvd', 'cisa_kev', 'exploitdb']),
        recordStatus: 'enriched',
        cweIds: JSON.stringify(['CWE-22']),
        cweNames: JSON.stringify(['Improper Limitation of a Pathname to a Restricted Directory']),
        weaknessCategory: 'path_traversal',
        source: 'nvd',
        processingStatus: 'enriched',
        needsEnrichment: false,
        firstSeenAt: new Date('2024-01-10T00:00:00Z'),
        publishedAt: new Date('2024-01-10T00:00:00Z'),
        lastModifiedAt: new Date('2024-02-05T00:00:00Z'),
        lastChangeDetectedAt: new Date('2024-02-05T00:00:00Z'),
        enrichedAt: new Date('2024-01-11T00:00:00Z'),
        isNotificable: true,
        createdAt: new Date('2024-01-10T00:00:00Z'),
        updatedAt: new Date('2024-02-05T12:00:00Z'),
        tags: [{ id: 1, name: 'Web Server', color: '#ff0000' }],
        notifications: [{ id: 55, sentAt: new Date('2024-01-12T00:00:00Z') }],
        _count: { notifications: 1 },
      };

      prismaMock.vulnerability.findMany.mockResolvedValue([mockVuln]);
      prismaMock.vulnerability.count.mockResolvedValue(1);

      const result = await service.listVulnerabilities({ page: 1, limit: 50 });

      expect(result.data).toHaveLength(1);
      const item = result.data[0];

      // Flat compatibility fields
      expect(item.cveId).toBe('CVE-2024-1234');
      expect(item.cvssV31Score).toBe(9.8);
      expect(item.cvssV31Severity).toBe('CRITICAL');
      expect(item.epssScore).toBe(0.85);
      expect(item.isKnownExploited).toBe(true);
      expect(item.hasPublicExploit).toBe(true);
      expect(item.primaryVendor).toBe('apache');
      expect(item.primaryProduct).toBe('http_server');
      expect(item.patchAvailable).toBe(true);
      expect(item.operationalRiskScore).toBe(95.0);

      // New contract attributes
      expect(item.dataConfidence).toBe(0.99);
      expect(item.recordStatus).toBe('enriched');
      expect(item.canonicalSource).toBe('nvd');
      expect(item.sourceCount).toBe(3);
      expect(item.enrichedAt).toEqual(mockVuln.enrichedAt);
      expect(item.lastChangeDetectedAt).toEqual(mockVuln.lastChangeDetectedAt);
      expect(item.exploitFirstSeenAt).toEqual(mockVuln.exploitFirstSeenAt);
      expect(item.exploitLastCheckedAt).toEqual(mockVuln.exploitLastCheckedAt);
      expect(item.patchPriority).toBe('CRITICAL');
      expect(item.workarounds).toEqual(['Disable path traversal module']);
      expect(item.detectionOpportunities).toEqual(['Monitor /cgi-bin requests']);
      expect(item.riskSignals).toEqual(['remote_code_execution', 'in_the_wild']);
      expect(item.affectedCpes).toEqual(['cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*']);
      expect(item.isConfirmedExploited).toBe(true);
      expect(item.evidenceTypes).toEqual(expect.arrayContaining(['advisory', 'kev_catalog', 'exploit_poc', 'epss_metric']));

      // Privacy: NO subscriber PII
      expect((item as any).suscriptoresNotificados).toBeUndefined();
      expect((item as any).recipientEmail).toBeUndefined();
      expect((item as any).recipientName).toBeUndefined();
      expect((item as any).subscriberUser).toBeUndefined();
      expect(item.notificada).toBe(true);
      expect(item.notificacionesCount).toBe(1);

      // No rawData in listings
      expect((item as any).rawData).toBeUndefined();
    });
  });

  describe('2. Intelligence States & Scenarios', () => {
    it('generates confirmed exploitation state for KEV CVEs', async () => {
      const kevVuln = {
        id: 201,
        cveId: 'CVE-2023-9999',
        isKnownExploited: true,
        hasPublicExploit: false,
        exploitStatus: 'active_exploitation',
        exploitLastCheckedAt: new Date('2024-03-01T00:00:00Z'),
        sourcesPresent: JSON.stringify(['nvd', 'cisa_kev']),
        processingStatus: 'enriched',
        needsEnrichment: false,
        epssScore: 0.12,
        patchAvailable: true,
        patchPriority: 'HIGH',
        fixedVersions: JSON.stringify(['1.0.1']),
        primaryVendor: 'vendor_a',
        primaryProduct: 'product_a',
        operationalRiskScore: 80,
        operationalRiskTier: 'high',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      prismaMock.vulnerability.findMany.mockResolvedValue([kevVuln]);
      prismaMock.vulnerability.count.mockResolvedValue(1);

      const result = await service.listVulnerabilities({});
      const item = result.data[0];

      expect(item.exploitation).toEqual({
        status: 'confirmed',
        isKnownExploited: true,
        hasPublicExploit: false,
        exploitStatus: 'active_exploitation',
        sources: expect.arrayContaining(['cisa_kev']),
        lastCheckedAt: kevVuln.exploitLastCheckedAt,
      });
      expect(item.isConfirmedExploited).toBe(true);
    });

    it('generates confirmed exploitation state for public exploit POCs', async () => {
      const exploitVuln = {
        id: 202,
        cveId: 'CVE-2023-8888',
        isKnownExploited: false,
        hasPublicExploit: true,
        exploitStatus: 'public_poc',
        exploitLastCheckedAt: new Date('2024-03-01T00:00:00Z'),
        sourcesPresent: JSON.stringify(['nvd', 'exploitdb']),
        processingStatus: 'enriched',
        needsEnrichment: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      prismaMock.vulnerability.findMany.mockResolvedValue([exploitVuln]);
      prismaMock.vulnerability.count.mockResolvedValue(1);

      const result = await service.listVulnerabilities({});
      const item = result.data[0];

      expect(item.exploitation.status).toBe('confirmed');
      expect(item.exploitation.isKnownExploited).toBe(false);
      expect(item.exploitation.hasPublicExploit).toBe(true);
      expect(item.exploitation.sources).toContain('exploitdb');
    });

    it('generates not_found exploitation state when enriched with no exploit signals', async () => {
      const cleanVuln = {
        id: 203,
        cveId: 'CVE-2023-7777',
        isKnownExploited: false,
        hasPublicExploit: false,
        exploitStatus: 'none',
        exploitLastCheckedAt: new Date('2024-03-01T00:00:00Z'),
        sourcesPresent: JSON.stringify(['nvd']),
        processingStatus: 'enriched',
        needsEnrichment: false,
        enrichedAt: new Date('2024-03-01T00:00:00Z'),
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      prismaMock.vulnerability.findMany.mockResolvedValue([cleanVuln]);
      prismaMock.vulnerability.count.mockResolvedValue(1);

      const result = await service.listVulnerabilities({});
      const item = result.data[0];

      expect(item.exploitation.status).toBe('not_found');
      expect(item.exploitation.isKnownExploited).toBe(false);
      expect(item.exploitation.hasPublicExploit).toBe(false);
      expect(item.isConfirmedExploited).toBe(false);
    });

    it('generates explicit not_checked and pending states for unenriched CVEs', async () => {
      const rawVuln = {
        id: 204,
        cveId: 'CVE-2024-5555',
        isKnownExploited: false,
        hasPublicExploit: false,
        exploitStatus: null,
        exploitLastCheckedAt: null,
        epssScore: null,
        patchAvailable: null,
        primaryVendor: null,
        primaryProduct: null,
        operationalRiskScore: null,
        processingStatus: 'new',
        needsEnrichment: true,
        enrichedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      prismaMock.vulnerability.findMany.mockResolvedValue([rawVuln]);
      prismaMock.vulnerability.count.mockResolvedValue(1);

      const result = await service.listVulnerabilities({});
      const item = result.data[0];

      expect(item.recordStatus).toBe('needs_enrichment');
      expect(item.exploitation.status).toBe('not_checked');
      expect(item.epss.status).toBe('not_checked');
      expect(item.patch.status).toBe('unknown');
      expect(item.primaryEntity.status).toBe('unknown');
      expect(item.operationalRisk.status).toBe('pending');
    });
  });

  describe('3. Privacy & Raw Data in Detail View', () => {
    it('omits rawData by default in detail and strips subscriber emails', async () => {
      const vulnDetail = {
        id: 301,
        cveId: 'CVE-2024-4444',
        description: 'Testing privacy',
        rawData: JSON.stringify({ rawNvdPayload: { cve: {} } }),
        notifications: [
          { id: 1, sentAt: new Date(), recipientEmail: 'secret@domain.com', recipientName: 'Alice' },
        ],
        sourceRecords: [
          {
            id: 1,
            sourceName: 'nvd',
            sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4444',
            confidence: 1.0,
            isCanonical: true,
            firstSeenAt: new Date(),
            lastSeenAt: new Date(),
          },
        ],
        tags: [],
      };

      prismaMock.vulnerability.findUnique.mockResolvedValue(vulnDetail);

      const resDefault = await service.getVulnerabilityByCveId('CVE-2024-4444');
      expect(resDefault.rawData).toBeUndefined();
      expect((resDefault as any).suscriptoresNotificados).toBeUndefined();
      expect((resDefault as any).recipientEmail).toBeUndefined();

      const resWithRaw = await service.getVulnerabilityByCveId('CVE-2024-4444', 'raw');
      expect(resWithRaw.rawData).toEqual({ rawNvdPayload: { cve: {} } });
      expect((resWithRaw as any).suscriptoresNotificados).toBeUndefined();
    });
  });

  describe('4. Incremental Synchronization & Query Filters', () => {
    it('applies updatedSince filter on lastChangeDetectedAt or updatedAt and returns watermark', async () => {
      const since = '2024-03-01T12:00:00.000Z';
      const items = [
        {
          id: 401,
          cveId: 'CVE-2024-0001',
          lastChangeDetectedAt: new Date('2024-03-02T10:00:00Z'),
          updatedAt: new Date('2024-03-02T10:00:00Z'),
        },
        {
          id: 402,
          cveId: 'CVE-2024-0002',
          lastChangeDetectedAt: new Date('2024-03-03T15:00:00Z'),
          updatedAt: new Date('2024-03-03T15:00:00Z'),
        },
      ];

      prismaMock.vulnerability.findMany.mockResolvedValue(items);
      prismaMock.vulnerability.count.mockResolvedValue(2);

      const res = await service.listVulnerabilities({ updatedSince: since, page: 1, limit: 10 });

      expect(prismaMock.vulnerability.findMany).toHaveBeenCalled();
      const whereArg = prismaMock.vulnerability.findMany.mock.calls[0][0].where;
      expect(whereArg.AND).toBeDefined();
      expect(whereArg.AND).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            OR: [
              { lastChangeDetectedAt: { gte: new Date(since) } },
              { updatedAt: { gte: new Date(since) } },
            ],
          }),
        ]),
      );

      expect(res.meta.watermark).toBe('2024-03-03T15:00:00.000Z');
      expect(res.meta.hasMore).toBe(false);
    });

    it('supports cursor decoding and cursor pagination', async () => {
      const cursorObj = { id: 500, updatedAt: '2024-03-01T00:00:00.000Z' };
      const cursorBase64 = Buffer.from(JSON.stringify(cursorObj)).toString('base64');

      prismaMock.vulnerability.findMany.mockResolvedValue([]);
      prismaMock.vulnerability.count.mockResolvedValue(0);

      await service.listVulnerabilities({ cursor: cursorBase64 });

      const whereArg = prismaMock.vulnerability.findMany.mock.calls[0][0].where;
      expect(whereArg.id).toEqual({ gt: 500 });
    });

    it('correctly filters by source, exploitType, recordStatus, and CVSS/EPSS ranges', async () => {
      prismaMock.vulnerability.findMany.mockResolvedValue([]);
      prismaMock.vulnerability.count.mockResolvedValue(0);

      await service.listVulnerabilities({
        source: 'cisa_kev',
        exploitType: 'confirmed',
        recordStatus: 'enriched',
        minCvss: 7.5,
        maxCvss: 10.0,
        minEpss: 0.5,
        hasPublicExploit: 'true',
        patchAvailable: 'true',
        vendor: 'cisco',
        product: 'ios_xe',
      });

      const whereArg = prismaMock.vulnerability.findMany.mock.calls[0][0].where;
      expect(whereArg.recordStatus).toBe('enriched');
      expect(whereArg.hasPublicExploit).toBe(true);
      expect(whereArg.patchAvailable).toBe(true);
      expect(whereArg.primaryVendor).toBe('cisco');
      expect(whereArg.primaryProduct).toBe('ios_xe');
      expect(whereArg.cvssV31Score).toEqual({ gte: 7.5, lte: 10.0 });
      expect(whereArg.epssScore).toEqual({ gte: 0.5 });
      expect(whereArg.AND).toBeDefined();
    });
  });

  describe('5. Evidence Endpoint (GET /api/v1/vulnerabilities/:cveId/evidence)', () => {
    it('returns paginated evidences using existing source records without fabrication', async () => {
      prismaMock.vulnerability.findUnique.mockResolvedValue({ id: 50, cveId: 'CVE-2024-9000' });
      prismaMock.vulnerabilitySourceRecord.findMany.mockResolvedValue([
        {
          id: 1,
          sourceName: 'cisa_kev',
          sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
          confidence: 1.0,
          isCanonical: false,
          firstSeenAt: new Date('2024-02-01T00:00:00Z'),
          lastSeenAt: new Date('2024-02-10T00:00:00Z'),
          normalizedData: JSON.stringify({ summary: 'CISA KEV item' }),
        },
        {
          id: 2,
          sourceName: 'nvd',
          sourceUrl: 'https://nvd.nist.gov',
          confidence: 0.9,
          isCanonical: true,
          firstSeenAt: new Date('2024-01-01T00:00:00Z'),
          lastSeenAt: new Date('2024-02-10T00:00:00Z'),
          normalizedData: null,
        },
      ]);
      prismaMock.vulnerabilitySourceRecord.count.mockResolvedValue(2);

      const res = await service.getVulnerabilityEvidence('CVE-2024-9000', { page: 1, limit: 10 });

      expect(res.data).toHaveLength(2);
      expect(res.data[0]).toEqual({
        id: 1,
        source: 'cisa_kev',
        sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        evidenceType: 'kev_catalog',
        summary: 'CISA KEV item',
        observedAt: new Date('2024-02-01T00:00:00Z'),
        lastValidatedAt: new Date('2024-02-10T00:00:00Z'),
        confidence: 1.0,
        isCanonical: false,
        status: 'verified',
      });
      expect(res.data[1].evidenceType).toBe('nvd_cve_advisory');
      expect(res.data[1].isCanonical).toBe(true);
    });

    it('returns empty list if CVE exists but has no source records', async () => {
      prismaMock.vulnerability.findUnique.mockResolvedValue({ id: 51, cveId: 'CVE-2024-9001' });
      prismaMock.vulnerabilitySourceRecord.findMany.mockResolvedValue([]);
      prismaMock.vulnerabilitySourceRecord.count.mockResolvedValue(0);

      const res = await service.getVulnerabilityEvidence('CVE-2024-9001', {});
      expect(res.data).toEqual([]);
      expect(res.meta.total).toBe(0);
    });

    it('throws NotFoundException if CVE does not exist', async () => {
      prismaMock.vulnerability.findUnique.mockResolvedValue(null);
      await expect(service.getVulnerabilityEvidence('CVE-1999-0000', {})).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('6. Coverage Endpoint (GET /api/v1/coverage)', () => {
    it('aggregates vulnerability totals and computes source health distinguishing zero, unknown and error', async () => {
      prismaMock.vulnerability.count
        .mockResolvedValueOnce(400000) // total
        .mockResolvedValueOnce(80000)  // enriched
        .mockResolvedValueOnce(320000) // pending
        .mockResolvedValueOnce(1700)   // kev
        .mockResolvedValueOnce(25000)  // public exploit
        .mockResolvedValueOnce(1800);  // confirmed exploited

      prismaMock.vulnerabilitySourceRecord.groupBy.mockResolvedValue([
        { sourceName: 'nvd', _count: { cveId: 395000 } },
        { sourceName: 'cisa_kev', _count: { cveId: 1700 } },
        { sourceName: 'exploitdb', _count: { cveId: 25000 } },
      ]);

      prismaMock.collectorRun.findMany
        .mockResolvedValueOnce([
          {
            source: 'nvd',
            startedAt: new Date(Date.now() - 3600000), // 1 hour ago
            finishedAt: new Date(),
            status: 'completed',
            cvesFetched: 50,
            durationMs: 12000,
            errorMessage: null,
          },
          {
            source: 'epss',
            startedAt: new Date(Date.now() - 7200000),
            finishedAt: new Date(),
            status: 'failed',
            cvesFetched: 0,
            durationMs: 500,
            errorMessage: 'API rate limit exceeded',
          },
        ])
        .mockResolvedValueOnce([
          // recentErrors
          {
            source: 'epss',
            startedAt: new Date(Date.now() - 7200000),
            finishedAt: new Date(),
            status: 'failed',
            errorMessage: 'API rate limit exceeded',
          },
        ]);

      prismaMock.collectorSourceHealth.findMany.mockResolvedValue([
        {
          source: 'nvd',
          runDate: new Date(),
          fetchStatus: 'success',
          itemsProcessed: 50,
          itemsErrored: 0,
          durationMs: 12000,
          errorMessage: null,
        },
      ]);

      const cov = await service.getCoverage();

      expect(cov.totalVulnerabilities).toBe(400000);
      expect(cov.totalEnriched).toBe(80000);
      expect(cov.totalPending).toBe(320000);
      expect(cov.totalKev).toBe(1700);
      expect(cov.totalWithPublicExploit).toBe(25000);
      expect(cov.totalConfirmedExploited).toBe(1800);

      // Sources
      expect(cov.coverageBySource.nvd.status).toBe('active');
      expect(cov.coverageBySource.nvd.distinction).toBe('recorded');
      expect(cov.coverageBySource.nvd.isAvailable).toBe(true);

      expect(cov.coverageBySource.epss.status).toBe('source_unavailable');
      expect(cov.coverageBySource.epss.isAvailable).toBe(false);

      expect(cov.coverageBySource.osv.status).toBe('not_configured');
      expect(cov.coverageBySource.osv.distinction).toBe('unknown');

      // Recent errors & freshness
      expect(cov.recentErrors).toHaveLength(1);
      expect(cov.recentErrors[0].errorMessage).toBe('API rate limit exceeded');
      expect(cov.freshnessStatus).toBe('fresh'); // run within last hour
      expect(cov.calculatedAt).toBeDefined();
    });
  });
});
