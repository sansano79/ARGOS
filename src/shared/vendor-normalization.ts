/**
 * Centralized vendor/product normalization and subscription matching.
 *
 * Replaces duplicated implementations in:
 *  - NvdIngestionProcessorService.normalizeVendor / normalizeProduct
 *  - ManufacturersService.normalizeName / normalizeProduct
 *  - VulnerabilityCollectorService.matchesSubscription
 *  - SmartNotificationsService.matchesSubscription / getMatchedProducts
 */

// ── Vendor alias map (case-insensitive, trimmed) ──────────────────────
export const VENDOR_ALIASES: Record<string, string> = {
  'ibm corporation': 'ibm',
  'international business machines': 'ibm',
  'apache software foundation': 'apache',
  'the apache software foundation': 'apache',
  'microsoft corporation': 'microsoft',
  'wordfence': 'wordpress',
  'wordpress foundation': 'wordpress',
  'oracle corporation': 'oracle',
  'google llc': 'google',
  'google inc': 'google',
  'google inc.': 'google',
  'amazon.com inc.': 'amazon',
  'amazon.com, inc.': 'amazon',
  'red hat': 'redhat',
  'red hat, inc.': 'redhat',
  'suse llc': 'suse',
  'suse linux': 'suse',
  'canonical ltd.': 'canonical',
  'debian gnu/linux': 'debian',
  'the debian project': 'debian',
  'f5 networks': 'f5',
  'f5, inc.': 'f5',
  'fortinet, inc.': 'fortinet',
  'palo alto networks': 'paloaltonetworks',
  'palo alto networks, inc.': 'paloaltonetworks',
  'cisco systems': 'cisco',
  'cisco systems, inc.': 'cisco',
  'vmware, inc.': 'vmware',
  'broadcom': 'broadcom',
  'symantec corporation': 'broadcom',
  'adobe inc.': 'adobe',
  'adobe systems': 'adobe',
  'adobe systems incorporated': 'adobe',
  'samsung electronics': 'samsung',
  'samsung mobile': 'samsung',
  'huawei technologies': 'huawei',
  'lenovo group ltd.': 'lenovo',
  'hewlett packard enterprise': 'hpe',
  'hp inc.': 'hp',
  'hewlett-packard': 'hp',
  'dell inc.': 'dell',
  'dell technologies': 'dell',
  'siemens ag': 'siemens',
  'sap se': 'sap',
  'mozilla foundation': 'mozilla',
  'mozilla corporation': 'mozilla',
  'the linux foundation': 'linux',
  'linux kernel': 'linux',
  'linux kernel organization, inc.': 'linux',
};

export type SemanticComponentType =
  | 'application'
  | 'library'
  | 'framework'
  | 'os-package'
  | 'platform-context'
  | 'unknown';

export type SemanticAffectedProduct = {
  vendor: string;
  product: string;
  version?: string;
  versionRange?: string;
  cpe?: string;
  source?: string;
  componentType: SemanticComponentType;
  contextualVendor: boolean;
};

export type SemanticReferenceLike = {
  url?: string | null;
  tags?: string[] | null;
  source?: string | null;
  type?: string | null;
  name?: string | null;
};

export type SemanticReferenceCandidate = {
  vendor: string;
  product: string;
  componentType: SemanticComponentType;
  contextualVendor: boolean;
  confidence: number;
  source: 'repository-reference' | 'package-reference';
  contextTags: string[];
};

const CONTEXTUAL_VENDOR_TOKENS = new Set([
  'azure devops',
  'bitbucket',
  'circleci',
  'docker',
  'docker hub',
  'ghcr',
  'github',
  'github actions',
  'github container registry',
  'gitlab',
  'gradle',
  'jenkins',
  'maven',
  'npm',
  'pypi',
  'travis',
]);

const CONTEXT_TAG_PATTERNS: Array<{ tag: string; pattern: RegExp }> = [
  { tag: 'github', pattern: /\bgithub\b/i },
  { tag: 'ghsa', pattern: /\bghsa[-:\s]/i },
  { tag: 'github-actions', pattern: /\bgithub[-\s]?actions?\b/i },
  { tag: 'gitlab', pattern: /\bgitlab\b/i },
  { tag: 'bitbucket', pattern: /\bbitbucket\b/i },
  { tag: 'docker', pattern: /\bdocker\b/i },
  { tag: 'registry', pattern: /\b(ghcr|container registry|docker hub|registry)\b/i },
  { tag: 'package-manager', pattern: /\b(npm|pypi|maven|gradle)\b/i },
  { tag: 'ci-cd', pattern: /\b(ci\/cd|ci-cd|continuous integration|pipeline)\b/i },
  { tag: 'workflow', pattern: /\bworkflow(s)?\b/i },
  { tag: 'supply-chain', pattern: /\b(supply chain|dependency|package|registry)\b/i },
];

const REPOSITORY_REFERENCE_HOSTS = new Set([
  'github.com',
  'gitlab.com',
  'bitbucket.org',
]);

const REPOSITORY_PATH_BLOCKLIST = new Set([
  'advisories',
  'advisory',
  'login',
  'marketplace',
  'orgs',
  'organizations',
  'security',
  'settings',
  'sponsors',
  'users',
]);

const GENERIC_PACKAGE_TOKENS = new Set([
  'action',
  'actions',
  'advisory',
  'application',
  'component',
  'dependency',
  'docker',
  'framework',
  'github',
  'gitlab',
  'library',
  'maven',
  'module',
  'npm',
  'package',
  'plugin',
  'product',
  'pypi',
  'registry',
  'software',
  'workflow',
]);

/**
 * Normalize a vendor name: lowercase, trim, apply alias map.
 */
export function normalizeVendor(vendor: string | undefined | null): string {
  const v = String(vendor || '').trim().toLowerCase();
  if (!v) return 'unknown';
  return VENDOR_ALIASES[v] || v;
}

/**
 * Normalize a product name: lowercase, trim, replace whitespace with hyphens,
 * strip non-alphanumeric (except . - _).
 */
export function normalizeProduct(product: string | undefined | null): string {
  return String(product || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9._-]/g, '');
}

/**
 * Simple normalization (lowercase + trim only). For use in matching logic
 * where we don't want to transform the value further.
 */
export function normalizeName(value: string | undefined | null): string {
  return String(value || '').trim().toLowerCase();
}

function normalizeContextToken(value: string | undefined | null): string {
  return normalizeName(value)
    .replace(/[._/]+/g, ' ')
    .replace(/[-]+/g, ' ')
    .replace(/\s+/g, ' ');
}

export function isContextualVendor(value: string | undefined | null): boolean {
  const normalized = normalizeContextToken(value);
  if (!normalized) return false;
  if (CONTEXTUAL_VENDOR_TOKENS.has(normalized)) return true;

  return (
    normalized.includes('github actions') ||
    normalized.includes('container registry') ||
    normalized.includes('docker hub') ||
    normalized.includes('package registry')
  );
}

export function detectComponentType(
  vendor: string | undefined | null,
  product: string | undefined | null,
  description?: string | undefined | null,
  evidence?: string | string[] | undefined | null,
): SemanticComponentType {
  const normalizedVendor = normalizeName(vendor);
  const normalizedProduct = normalizeName(product);
  const evidenceText = Array.isArray(evidence)
    ? evidence.map((value) => normalizeName(value)).join(' ')
    : normalizeName(evidence);
  const text = `${normalizedVendor} ${normalizedProduct} ${normalizeName(description)} ${evidenceText}`;
  const packageNameSignals =
    /^@[a-z0-9._-]+\/[a-z0-9._-]+$/.test(normalizedProduct) ||
    /^[a-z0-9._-]+\/[a-z0-9._-]+$/.test(normalizedProduct) ||
    /\b(?:npm|pypi|nuget|maven|composer|cargo|crate|gem|package)\b/i.test(text);
  const strongLibrarySignals =
    packageNameSignals ||
    /\b(library|lib\b|sdk|client|module|package|plugin|extension|gem|crate|dependency)\b/i.test(
      text,
    );
  const hasPlatformSignals =
    /\b(actions?|workflow|pipeline|ci\/cd|ci-cd|registry|container registry)\b/i.test(text) ||
    /\b(npm|pypi|maven|gradle|docker hub|ghcr)\b/i.test(text);

  if (
    /\b(framework|django|spring|laravel|rails|struts|angular|react|vue|next\.?js)\b/i.test(
      text,
    )
  ) {
    return 'framework';
  }
  if (strongLibrarySignals) {
    return 'library';
  }
  if (/\b(deb|rpm|apk|apt|yum|dnf|portage|os package|linux package)\b/i.test(text)) {
    return 'os-package';
  }
  if (
    hasPlatformSignals ||
    (isContextualVendor(normalizedVendor) && isContextualVendor(normalizedProduct))
  ) {
    return 'platform-context';
  }
  return normalizedVendor && normalizedProduct ? 'application' : 'unknown';
}

export function normalizeAffectedProductSemantics(
  affectedProduct: {
    vendor?: string | null;
    product?: string | null;
    version?: string | null;
    versionRange?: string | null;
    cpe?: string | null;
    source?: string | null;
  },
  description?: string | undefined | null,
): SemanticAffectedProduct | null {
  const vendor = normalizeName(affectedProduct?.vendor);
  const product = normalizeName(affectedProduct?.product);
  if (!vendor || !product) return null;
  const evidenceText = [
    normalizeName(affectedProduct?.source),
    normalizeName(affectedProduct?.cpe),
    normalizeName(affectedProduct?.versionRange),
  ]
    .filter(Boolean)
    .join(' ');

  return {
    vendor,
    product,
    version: normalizeName(affectedProduct?.version) || undefined,
    versionRange: normalizeName(affectedProduct?.versionRange) || undefined,
    cpe: normalizeName(affectedProduct?.cpe) || undefined,
    source: normalizeName(affectedProduct?.source) || undefined,
    componentType: detectComponentType(vendor, product, description, evidenceText),
    contextualVendor: isContextualVendor(vendor),
  };
}

export function filterOperationalAffectedProducts(
  affectedProducts: Array<{
    vendor?: string | null;
    product?: string | null;
    version?: string | null;
    versionRange?: string | null;
    cpe?: string | null;
    source?: string | null;
  }>,
  description?: string | undefined | null,
): SemanticAffectedProduct[] {
  const normalized = Array.from(
    new Map(
      (affectedProducts || [])
        .map((entry) => normalizeAffectedProductSemantics(entry, description))
        .filter((entry): entry is SemanticAffectedProduct => entry != null)
        .map((entry) => [
          [
            entry.vendor,
            entry.product,
            entry.version || '',
            entry.versionRange || '',
            entry.cpe || '',
          ].join('::'),
          entry,
        ]),
    ).values(),
  );

  const operational = normalized.filter(
    (entry) => entry.componentType !== 'platform-context',
  );

  return (operational.length > 0 ? operational : normalized).sort((left, right) =>
    [
      left.vendor,
      left.product,
      left.versionRange || '',
      left.version || '',
      left.cpe || '',
    ]
      .join('/')
      .localeCompare(
        [right.vendor, right.product, right.versionRange || '', right.version || '', right.cpe || ''].join('/'),
      ),
  );
}

export function selectDominantAffectedEntity(
  affectedProducts: Array<{
    vendor?: string | null;
    product?: string | null;
    version?: string | null;
    versionRange?: string | null;
    cpe?: string | null;
    source?: string | null;
  }>,
  description?: string | undefined | null,
  preferredPrimary?: { vendor?: string | null; product?: string | null },
): (SemanticAffectedProduct & { dominanceScore: number; contextTags: string[] }) | null {
  const normalized = filterOperationalAffectedProducts(affectedProducts, description);
  if (normalized.length === 0) return null;

  const preferredVendor = normalizeName(preferredPrimary?.vendor);
  const preferredProduct = normalizeName(preferredPrimary?.product);
  const candidates = new Map<
    string,
    SemanticAffectedProduct & {
      dominanceScore: number;
      versions: Set<string>;
      ranges: Set<string>;
      cpes: Set<string>;
    }
  >();

  for (const entry of normalized) {
    const key = `${entry.vendor}::${entry.product}`;
    if (!candidates.has(key)) {
      candidates.set(key, {
        ...entry,
        dominanceScore: 40,
        versions: new Set<string>(),
        ranges: new Set<string>(),
        cpes: new Set<string>(),
      });
    }

    const current = candidates.get(key)!;
    current.dominanceScore += 12;
    if (entry.version) current.versions.add(entry.version);
    if (entry.versionRange) current.ranges.add(entry.versionRange);
    if (entry.cpe) current.cpes.add(entry.cpe);
    if (entry.componentType === 'application') current.dominanceScore += 6;
    if (entry.componentType === 'framework' || entry.componentType === 'library') {
      current.dominanceScore += 4;
    }
    if (!entry.contextualVendor) current.dominanceScore += 4;
    if (preferredVendor && preferredProduct && entry.vendor === preferredVendor && entry.product === preferredProduct) {
      current.dominanceScore += 5;
    }
  }

  const ranked = Array.from(candidates.values())
    .map((candidate) => ({
      ...candidate,
      dominanceScore:
        candidate.dominanceScore +
        candidate.versions.size * 2 +
        candidate.ranges.size * 3 +
        candidate.cpes.size * 4,
    }))
    .sort((left, right) => {
      if (right.dominanceScore !== left.dominanceScore) {
        return right.dominanceScore - left.dominanceScore;
      }
      if (left.contextualVendor !== right.contextualVendor) {
        return Number(left.contextualVendor) - Number(right.contextualVendor);
      }
      return `${left.vendor}/${left.product}`.localeCompare(`${right.vendor}/${right.product}`);
    });

  const best = ranked[0];
  if (!best) return null;

  return {
    vendor: best.vendor,
    product: best.product,
    version: best.version,
    versionRange: best.versionRange,
    cpe: best.cpe,
    source: best.source,
    componentType: best.componentType,
    contextualVendor: best.contextualVendor,
    dominanceScore: best.dominanceScore,
    contextTags: extractContextTags({
      products: normalized,
      description,
      primaryVendor: best.vendor,
      primaryProduct: best.product,
    }),
  };
}

export function extractContextTags(params: {
  products?: Array<{
    vendor?: string | null;
    product?: string | null;
    version?: string | null;
    versionRange?: string | null;
    cpe?: string | null;
    source?: string | null;
  }>;
  description?: string | undefined | null;
  primaryVendor?: string | undefined | null;
  primaryProduct?: string | undefined | null;
  references?: SemanticReferenceLike[] | undefined | null;
  additionalText?: Array<string | null | undefined> | undefined | null;
}): string[] {
  const productText = (params.products || [])
    .map((entry) =>
      [
        entry?.vendor,
        entry?.product,
        entry?.source,
        entry?.cpe,
        entry?.version,
        entry?.versionRange,
      ]
        .filter(Boolean)
        .join(' '),
    )
    .join(' ');
  const combined = [
    params.description,
    params.primaryVendor,
    params.primaryProduct,
    productText,
    ...(params.references || []).map((reference) =>
      [
        reference?.url,
        ...(reference?.tags || []),
        reference?.source,
        reference?.type,
        reference?.name,
      ]
        .filter(Boolean)
        .join(' '),
    ),
    ...(params.additionalText || []),
  ]
    .filter(Boolean)
    .join(' ');

  return Array.from(
    new Set(
      CONTEXT_TAG_PATTERNS.filter(({ pattern }) => pattern.test(combined)).map(
        ({ tag }) => tag,
      ),
    ),
  ).sort();
}

export function inferReferenceEntityCandidates(params: {
  description?: string | null;
  references?: SemanticReferenceLike[] | null;
}): SemanticReferenceCandidate[] {
  const description = String(params.description || '');
  const references = Array.isArray(params.references) ? params.references : [];
  const candidates = new Map<string, SemanticReferenceCandidate>();
  const contextTags = extractContextTags({
    description,
    references,
  });
  const addCandidate = (
    vendorValue: string | undefined | null,
    productValue: string | undefined | null,
    confidence: number,
    source: SemanticReferenceCandidate['source'],
    evidenceText?: string,
  ) => {
    const vendor = normalizeName(vendorValue);
    const product = normalizeName(productValue);
    if (!vendor || !product) return;
    if (GENERIC_PACKAGE_TOKENS.has(product)) return;

    const key = `${vendor}::${product}`;
    const componentType = detectComponentType(vendor, product, description, evidenceText);
    const contextualVendor = isContextualVendor(vendor);
    const existing = candidates.get(key);
    if (existing && existing.confidence >= confidence) return;

    candidates.set(key, {
      vendor,
      product,
      componentType,
      contextualVendor,
      confidence,
      source,
      contextTags,
    });
  };

  for (const reference of references) {
    const url = String(reference?.url || '').trim();
    if (!url) continue;

    const repositoryCandidate = extractRepositoryCandidate(url);
    if (repositoryCandidate) {
      const hasStrongRefSignals = /\/(commit|compare|pull|security|releases)\//i.test(url) ||
        (reference.tags || []).some((tag) => /patch|advisory|vendor advisory/i.test(tag));
      addCandidate(
        repositoryCandidate.vendor,
        repositoryCandidate.product,
        hasStrongRefSignals ? 0.9 : 0.78,
        'repository-reference',
        `${url} ${(reference.tags || []).join(' ')}`,
      );
    }

    const packageCandidates = extractPackageCandidates(
      `${description} ${url} ${(reference.tags || []).join(' ')} ${reference.name || ''}`,
    );
    for (const candidate of packageCandidates) {
      if (candidate.vendor) {
        addCandidate(
          candidate.vendor,
          candidate.product,
          candidate.confidence,
          'package-reference',
          `${description} ${url}`,
        );
        continue;
      }

      if (repositoryCandidate && normalizeProduct(repositoryCandidate.product) === normalizeProduct(candidate.product)) {
        addCandidate(
          repositoryCandidate.vendor,
          candidate.product,
          Math.max(candidate.confidence, 0.84),
          'package-reference',
          `${description} ${url}`,
        );
      }
    }
  }

  for (const candidate of extractPackageCandidates(description)) {
    if (candidate.vendor) {
      addCandidate(candidate.vendor, candidate.product, candidate.confidence, 'package-reference', description);
    }
  }

  return Array.from(candidates.values()).sort((left, right) => {
    if (right.confidence !== left.confidence) return right.confidence - left.confidence;
    if (left.contextualVendor !== right.contextualVendor) {
      return Number(left.contextualVendor) - Number(right.contextualVendor);
    }
    return `${left.vendor}/${left.product}`.localeCompare(`${right.vendor}/${right.product}`);
  });
}

function extractRepositoryCandidate(url: string): { vendor: string; product: string } | null {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.replace(/^www\./, '').toLowerCase();
    if (!REPOSITORY_REFERENCE_HOSTS.has(host)) return null;

    const parts = parsed.pathname
      .split('/')
      .map((part) => part.trim())
      .filter(Boolean);
    if (parts.length < 2) return null;
    if (REPOSITORY_PATH_BLOCKLIST.has(parts[0].toLowerCase())) return null;

    const vendor = normalizeName(parts[0]);
    const product = normalizeName(parts[1].replace(/\.git$/i, ''));
    if (!vendor || !product) return null;
    if (GENERIC_PACKAGE_TOKENS.has(product)) return null;

    return { vendor, product };
  } catch {
    return null;
  }
}

function extractPackageCandidates(
  text: string,
): Array<{ vendor: string | null; product: string; confidence: number }> {
  const candidates = new Map<string, { vendor: string | null; product: string; confidence: number }>();
  const patterns = [
    /\b(?:npm|pypi|nuget|maven|composer|cargo|crate|gem)\s+package\s+[`"' ]?(@?[a-z0-9._-]+(?:\/[a-z0-9._-]+)?)/gi,
    /\b(?:package|module|library|component|plugin)\s+[`"' ]?(@?[a-z0-9._-]+(?:\/[a-z0-9._-]+)?)/gi,
    /\bin\s+[`"' ]?(@?[a-z0-9._-]+(?:\/[a-z0-9._-]+)?)\s+(?:before|through|prior to|versions?)/gi,
  ];

  const pushCandidate = (rawName: string, confidence: number) => {
    const normalized = String(rawName || '').trim().replace(/[`"',.:;]+$/g, '');
    if (!normalized) return;

    if (normalized.startsWith('@')) {
      const scopedMatch = normalized.match(/^@([^/]+)\/(.+)$/);
      const vendor = normalizeName(scopedMatch?.[1]);
      const product = normalizeName(scopedMatch?.[2]);
      if (vendor && product && !GENERIC_PACKAGE_TOKENS.has(product)) {
        candidates.set(`${vendor}::${product}`, { vendor, product, confidence });
      }
      return;
    }

    if (normalized.includes('/')) {
      const [vendorRaw, productRaw] = normalized.split('/', 2);
      const vendor = normalizeName(vendorRaw);
      const product = normalizeName(productRaw);
      if (vendor && product && !GENERIC_PACKAGE_TOKENS.has(product)) {
        candidates.set(`${vendor}::${product}`, { vendor, product, confidence });
      }
      return;
    }

    const product = normalizeName(normalized);
    if (!product || GENERIC_PACKAGE_TOKENS.has(product) || product.length < 2) return;
    candidates.set(`product::${product}`, { vendor: null, product, confidence: Math.min(confidence, 0.72) });
  };

  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      pushCandidate(match[1], pattern === patterns[0] ? 0.9 : 0.8);
    }
  }

  return Array.from(candidates.values()).sort((left, right) => right.confidence - left.confidence);
}

/**
 * Checks if a subscription matches an affected product entry.
 * Matching rules:
 *  - If subscription has vendor, it MUST match (after normalization).
 *  - If subscription has product, it MUST match (after normalization).
 *  - If affectedProduct has no vendor AND no product → false.
 *  - If subscription has specific versions, at least one must match version/versionRange.
 *  - If no version info in the CVE, match anyway (over-notify rather than miss).
 */
export function matchesSubscription(
  subscription: { vendor: string; product: string; versions: string[] },
  affectedProduct: {
    vendor?: string;
    product?: string;
    version?: string;
    versionRange?: string;
    description?: string;
    componentType?: string;
  },
): boolean {
  const sVendor = normalizeVendor(subscription.vendor);
  const sProduct = normalizeProduct(subscription.product);

  const normalizedAffected = normalizeAffectedProductSemantics(
    affectedProduct,
    affectedProduct?.description,
  );
  const pVendor = normalizeVendor(normalizedAffected?.vendor || affectedProduct?.vendor);
  const pProduct = normalizeProduct(normalizedAffected?.product || affectedProduct?.product);
  const affectedComponentType = String(
    affectedProduct?.componentType || normalizedAffected?.componentType || 'unknown',
  ).toLowerCase();
  const subscriptionIsContextual = isContextualVendor(subscription.vendor);

  // Both fields empty → poorly correlated data
  if ((!pVendor || pVendor === 'unknown') && !pProduct) return false;

  // Avoid matching pure platform/context entries against regular product subscriptions.
  if (affectedComponentType === 'platform-context' && !subscriptionIsContextual) {
    return false;
  }

  // If subscription specifies vendor, it must match
  if (sVendor && pVendor && sVendor !== pVendor) return false;
  // If subscription specifies product, it must match
  if (sProduct && pProduct && sProduct !== pProduct) return false;

  // If subscription has no specific versions, match on vendor+product alone
  if (!subscription.versions || subscription.versions.length === 0) return true;

  const pVersion = normalizeName(affectedProduct?.version);
  const pVersionRange = normalizeName(affectedProduct?.versionRange);

  // If CVE doesn't specify version info, still match (better to over-notify)
  if (!pVersion && !pVersionRange) return true;

  return subscription.versions.some((sv) => {
    const nv = normalizeName(sv);
    return nv && (pVersion === nv || pVersionRange.includes(nv));
  });
}

/**
 * Filters affected products to only those matching any of the given subscriptions.
 */
export function getMatchedProducts(
  subscriptions: Array<{ vendor: string; product: string; versions: string[] }>,
  affectedProducts: Array<{
    vendor: string;
    product: string;
    version?: string;
    versionRange?: string;
    description?: string;
    componentType?: string;
  }>,
): Array<{
  vendor: string;
  product: string;
  version?: string;
  versionRange?: string;
  description?: string;
  componentType?: string;
}> {
  return (affectedProducts || []).filter((ap) =>
    subscriptions.some((sub) => matchesSubscription(sub, ap)),
  );
}

/**
 * Normalizes a list of subscriptions (common preprocessing).
 */
export function normalizeSubscriptions(
  subscriptions: Array<{ vendor: any; product: any; versions: any }>,
  parseJsonArray: (val: any) => string[],
): Array<{ vendor: string; product: string; versions: string[] }> {
  return subscriptions.map((s) => ({
    vendor: normalizeName(s.vendor),
    product: normalizeName(s.product),
    versions: parseJsonArray(s.versions || '[]').map((v) => v.toLowerCase()),
  }));
}
