import * as fs from 'node:fs';
import * as path from 'node:path';

import { SmartNotificationsService } from './smart-notifications.service';

const renderLikeNotificationService = (template: string, context: Record<string, any>) => {
  let content = template;
  Object.entries(context).forEach(([key, value]) => {
    const regex = new RegExp(`{{ ${key} }}`, 'g');
    content = content.replace(regex, String(value));
    const regexNoSpace = new RegExp(`{{${key}}}`, 'g');
    content = content.replace(regexNoSpace, String(value));
  });
  return content;
};

describe('intelligent email render quality rules', () => {
  const templatePath = path.resolve(__dirname, '../../templates/smart-weekly-report.html');
  const template = fs.readFileSync(templatePath, 'utf8');

  const makeService = () =>
    new SmartNotificationsService({} as any, {} as any, { renderTemplate: async () => '' } as any);

  const baseFinding = (overrides: any = {}) =>
    ({
      findingKey: 'finding-1',
      type: 'vendor_wave',
      title: 'Concentración de vulnerabilidades en Acme / Portal',
      summary: 'raw-summary',
      confidence: 0.82,
      relevanceScore: 8.1,
      riskScore: 8.2,
      detectedAt: new Date('2026-03-24T10:00:00.000Z'),
      windowStart: new Date('2026-03-23T00:00:00.000Z'),
      windowEnd: new Date('2026-03-24T00:00:00.000Z'),
      contextStart: new Date('2026-03-17T00:00:00.000Z'),
      contextEnd: new Date('2026-03-24T00:00:00.000Z'),
      affectedVulnerabilityIds: [1, 2, 3, 4, 5, 6],
      affectedManufacturers: ['Acme'],
      affectedProducts: ['Portal'],
      recommendedActions: [],
      status: 'active',
      recencyWeight: 1,
      clusterKey: 'cluster-1',
      ...overrides,
    }) as any;

  const baseMatch = (overrides: any = {}) =>
    ({
      subscriberId: 1,
      findingKey: 'finding-1',
      findingType: 'vendor_wave',
      matchLevel: 'exact',
      matchScore: 1,
      deliveryScore: 0.81,
      shouldNotify: true,
      reasons: ['Matching exact con suscripciones o activos del suscriptor'],
      matchedSubscriptions: [{ vendor: 'Acme', product: 'Portal', level: 'exact' }],
      language: 'es',
      recipientEmail: 'security@example.com',
      ...overrides,
    }) as any;

  const makeVulnMap = (overrides: Partial<any> = {}) =>
    new Map<number, any>([
      [
        1,
        {
          id: 1,
          cveId: 'CVE-2026-0001',
          cvssV31Score: 9.8,
          epssScore: 0.1,
          isKnownExploited: false,
          hasPublicExploit: false,
          exploitStatus: null,
          patchAvailable: true,
          primaryVendor: 'Acme',
          primaryProduct: 'Portal',
          recordStatus: 'enriched_partial',
          ...overrides,
        },
      ],
      [
        2,
        {
          id: 2,
          cveId: 'CVE-2026-0002',
          cvssV31Score: 8.9,
          epssScore: null,
          isKnownExploited: false,
          hasPublicExploit: false,
          exploitStatus: null,
          patchAvailable: false,
          primaryVendor: 'Acme',
          primaryProduct: 'Portal',
        },
      ],
      [
        3,
        {
          id: 3,
          cveId: 'CVE-2026-0003',
          cvssV31Score: 8.2,
          epssScore: 0.05,
          isKnownExploited: false,
          hasPublicExploit: false,
          exploitStatus: null,
          patchAvailable: true,
          primaryVendor: 'Acme',
          primaryProduct: 'Portal',
        },
      ],
      [
        4,
        {
          id: 4,
          cveId: 'CVE-2026-0004',
          cvssV31Score: 7.9,
          epssScore: 0.02,
          isKnownExploited: false,
          hasPublicExploit: false,
          exploitStatus: null,
          patchAvailable: true,
          primaryVendor: 'Acme',
          primaryProduct: 'Portal',
        },
      ],
      [
        5,
        {
          id: 5,
          cveId: 'CVE-2026-0005',
          cvssV31Score: 7.5,
          epssScore: 0.01,
          isKnownExploited: false,
          hasPublicExploit: false,
          exploitStatus: null,
          patchAvailable: true,
          primaryVendor: 'Acme',
          primaryProduct: 'Portal',
        },
      ],
      [
        6,
        {
          id: 6,
          cveId: 'CVE-2026-0006',
          cvssV31Score: 7.2,
          epssScore: 0.0,
          isKnownExploited: false,
          hasPublicExploit: false,
          exploitStatus: null,
          patchAvailable: true,
          primaryVendor: 'Acme',
          primaryProduct: 'Portal',
        },
      ],
    ]);

  it('does not claim public exploit evidence in the executive summary when exploit count is 0', () => {
    const service = makeService();
    const ctx = (service as any).buildIntelligentEmailContext(
      baseFinding(),
      baseMatch(),
      makeVulnMap(),
      'es',
    );
    expect(String(ctx.executiveSectionHtml).toLowerCase()).not.toContain('exploit público');
  });

  it('does not claim KEV in the executive summary when KEV count is 0', () => {
    const service = makeService();
    const ctx = (service as any).buildIntelligentEmailContext(
      baseFinding(),
      baseMatch(),
      makeVulnMap(),
      'es',
    );
    expect(String(ctx.executiveSectionHtml)).not.toContain('KEV');
  });

  it('does not use attack path terminology when the finding does not support it', () => {
    const service = makeService();
    const ctx = (service as any).buildIntelligentEmailContext(
      baseFinding({ type: 'vendor_wave' }),
      baseMatch(),
      makeVulnMap(),
      'es',
    );
    expect(String(ctx.findingSectionHtml).toLowerCase()).not.toContain('attack path');
    expect(String(ctx.findingSectionHtml).toLowerCase()).not.toContain('ruta de ataque');
  });

  it('does not render an empty greeting placeholder', () => {
    const service = makeService();
    const ctx = (service as any).buildIntelligentEmailContext(
      baseFinding(),
      baseMatch(),
      makeVulnMap(),
      'es',
    );
    const html = renderLikeNotificationService(template, ctx);
    expect(html).toContain('Hola,');
    expect(html).not.toContain('Hola <strong></strong>');
    expect(html).not.toContain('{{ subscriberName }}');
  });

  it('does not leak internal pipeline statuses (e.g., enriched_partial, recordStatus)', () => {
    const service = makeService();
    const ctx = (service as any).buildIntelligentEmailContext(
      baseFinding(),
      baseMatch(),
      makeVulnMap(),
      'es',
    );
    const html = renderLikeNotificationService(template, ctx);
    expect(html).not.toContain('enriched_partial');
    expect(html).not.toContain('recordStatus');
    expect(html).not.toContain('record_status');
  });

  it('does not render weak contextual matches as secondary noise', () => {
    const service = makeService();
    const match = baseMatch({
      matchedSubscriptions: [
        { vendor: 'Acme', product: 'Portal', level: 'exact' },
        { vendor: 'Other', product: 'Sidecar', level: 'contextual' },
      ],
    });
    const ctx = (service as any).buildIntelligentEmailContext(
      baseFinding(),
      match,
      makeVulnMap(),
      'es',
    );
    expect(String(ctx.whyReceivedSectionHtml)).toContain('Acme / Portal');
    expect(String(ctx.whyReceivedSectionHtml)).not.toContain('Other / Sidecar');
  });

  it('compacts the technical base to top N plus a remainder line', () => {
    const service = makeService();
    const ctx = (service as any).buildIntelligentEmailContext(
      baseFinding(),
      baseMatch(),
      makeVulnMap(),
      'es',
    );
    const html = String(ctx.technicalSectionHtml);
    const rows = html.match(/<tr\b/g) || [];
    expect(rows.length).toBe(1 + 4);
    expect(html).toContain('+2 CVEs adicionales');
  });

  it('renders Spanish and English correctly', () => {
    const service = makeService();
    const es = (service as any).buildIntelligentEmailContext(
      baseFinding(),
      baseMatch({ language: 'es' }),
      makeVulnMap(),
      'es',
    );
    expect(String(es.emailTitle)).toContain('Notificación Inteligente ARGOS');
    expect(String(es.executiveSectionHtml)).toContain('Resumen ejecutivo');

    const en = (service as any).buildIntelligentEmailContext(
      baseFinding({ title: 'Prioritized cluster in Acme / Portal' }),
      baseMatch({ language: 'en' }),
      makeVulnMap(),
      'en',
    );
    expect(String(en.emailTitle)).toContain('ARGOS Intelligent Notification');
    expect(String(en.executiveSectionHtml)).toContain('Executive Summary');
    expect(String(en.greetingHtml)).toContain('Hello,');
  });

  it('avoids private IP base URLs in email links', () => {
    const previousFrontendBaseUrl = process.env.FRONTEND_BASE_URL;
    const previousEmailBaseUrl = process.env.EMAIL_FRONTEND_BASE_URL;
    try {
      process.env.FRONTEND_BASE_URL = 'http://10.0.0.1:3000';
      delete process.env.EMAIL_FRONTEND_BASE_URL;

      const service = makeService();
      const ctx = (service as any).buildIntelligentEmailContext(
        baseFinding(),
        baseMatch(),
        makeVulnMap(),
        'es',
      );
      expect(String(ctx.topRiskSectionHtml)).not.toContain('10.0.0.1');
      expect(String(ctx.topRiskSectionHtml)).toContain('nvd.nist.gov');
    } finally {
      process.env.FRONTEND_BASE_URL = previousFrontendBaseUrl;
      process.env.EMAIL_FRONTEND_BASE_URL = previousEmailBaseUrl;
    }
  });
});
