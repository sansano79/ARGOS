import {
  classifyFindingTypeForCluster,
  clusterIntelligentCandidates,
  computeCandidatePriorityScore,
  evaluateSubscriberFindingMatch,
  getRecencyWeight,
} from './intelligent-notification.logic';

describe('intelligent notification logic', () => {
  const now = new Date('2026-03-24T10:00:00.000Z');

  it('weights recency by the configured temporal bands', () => {
    expect(getRecencyWeight(2)).toBe(1);
    expect(getRecencyWeight(14)).toBe(0.65);
    expect(getRecencyWeight(45)).toBe(0.35);
  });

  it('boosts priority for exploitable recent vulnerabilities', () => {
    const strong = computeCandidatePriorityScore({
      id: 1,
      cveId: 'CVE-2026-1001',
      primaryVendor: 'acme',
      primaryProduct: 'gateway',
      severity: 'CRITICAL',
      cvss: 9.8,
      epss: 0.88,
      isKev: true,
      hasPublicExploit: true,
      exploitStatus: 'active_exploitation',
      patchAvailable: false,
      publishedAt: new Date('2026-03-22T00:00:00.000Z'),
    }, now);
    const weak = computeCandidatePriorityScore({
      id: 2,
      cveId: 'CVE-2026-1002',
      primaryVendor: 'acme',
      primaryProduct: 'gateway',
      severity: 'MEDIUM',
      cvss: 5.3,
      epss: 0.01,
      patchAvailable: true,
      publishedAt: new Date('2026-01-30T00:00:00.000Z'),
    }, now);
    expect(strong).toBeGreaterThan(weak);
  });

  it('clusters related candidates by vendor and product', () => {
    const clusters = clusterIntelligentCandidates([
      {
        id: 1,
        cveId: 'CVE-2026-2001',
        primaryVendor: 'Acme',
        primaryProduct: 'Portal',
        cvss: 9.1,
        epss: 0.6,
        publishedAt: new Date('2026-03-23T00:00:00.000Z'),
      },
      {
        id: 2,
        cveId: 'CVE-2026-2002',
        primaryVendor: 'Acme',
        primaryProduct: 'Portal',
        cvss: 8.1,
        epss: 0.2,
        publishedAt: new Date('2026-03-21T00:00:00.000Z'),
      },
      {
        id: 3,
        cveId: 'CVE-2026-2003',
        primaryVendor: 'Beta',
        primaryProduct: 'Agent',
        cvss: 7.1,
        epss: 0.1,
        publishedAt: new Date('2026-03-23T00:00:00.000Z'),
      },
    ], now);

    expect(clusters).toHaveLength(2);
    expect(clusters[0].vendor).toBe('acme');
    expect(clusters[0].product).toBe('portal');
    expect(clusters[0].candidates).toHaveLength(2);
  });

  it('classifies strong clusters as attack-path plausible when exploit signals concentrate', () => {
    const cluster = clusterIntelligentCandidates([
      {
        id: 1,
        cveId: 'CVE-2026-3001',
        primaryVendor: 'Acme',
        primaryProduct: 'Gateway',
        cvss: 9.5,
        epss: 0.75,
        isKev: true,
        hasPublicExploit: true,
        publishedAt: new Date('2026-03-23T00:00:00.000Z'),
      },
      {
        id: 2,
        cveId: 'CVE-2026-3002',
        primaryVendor: 'Acme',
        primaryProduct: 'Gateway',
        cvss: 8.8,
        epss: 0.61,
        hasPublicExploit: true,
        publishedAt: new Date('2026-03-22T00:00:00.000Z'),
      },
    ], now)[0];

    expect(classifyFindingTypeForCluster(cluster)).toBe('attack_path_plausible');
  });

  it('matches subscribers with exact, family and contextual levels', () => {
    const exact = evaluateSubscriberFindingMatch({
      affectedManufacturers: ['microsoft'],
      affectedProducts: ['exchange server'],
      categoryTags: ['mail', 'rce'],
      subscriptions: [{ vendor: 'microsoft', product: 'exchange server' }],
      confidence: 0.9,
      relevanceScore: 8.5,
      recencyWeight: 1,
    });
    expect(exact.matchLevel).toBe('exact');
    expect(exact.shouldNotify).toBe(true);

    const family = evaluateSubscriberFindingMatch({
      affectedManufacturers: ['vmware'],
      affectedProducts: ['workspace one access'],
      categoryTags: ['iam'],
      subscriptions: [{ vendor: 'vmware', product: 'workspace one' }],
      confidence: 0.78,
      relevanceScore: 7.5,
      recencyWeight: 0.65,
    });
    expect(family.matchLevel).toBe('family');

    const contextual = evaluateSubscriberFindingMatch({
      affectedManufacturers: ['unknown'],
      affectedProducts: ['unknown'],
      categoryTags: ['kubernetes', 'container'],
      subscriptions: [],
      systems: [{ platform: 'kubernetes', tags: ['container-platform'] }],
      confidence: 0.7,
      relevanceScore: 6.5,
      recencyWeight: 1,
    });
    expect(contextual.matchLevel).toBe('contextual');
  });

  it('suppresses delivery when exclusions or low match apply', () => {
    const excluded = evaluateSubscriberFindingMatch({
      affectedManufacturers: ['acme'],
      affectedProducts: ['gateway'],
      subscriptions: [{ vendor: 'acme', product: 'gateway' }],
      exclusions: ['gateway'],
      confidence: 0.9,
      relevanceScore: 9,
      recencyWeight: 1,
    });
    expect(excluded.shouldNotify).toBe(false);
    expect(excluded.suppressionReason).toBe('subscriber_exclusion');

    const weak = evaluateSubscriberFindingMatch({
      affectedManufacturers: ['unknown'],
      affectedProducts: ['generic component'],
      subscriptions: [{ vendor: 'adobe', product: 'acrobat' }],
      confidence: 0.3,
      relevanceScore: 3,
      recencyWeight: 0.35,
    });
    expect(weak.shouldNotify).toBe(false);
    expect(weak.suppressionReason).toBe('no_subscriber_match');
  });
});
