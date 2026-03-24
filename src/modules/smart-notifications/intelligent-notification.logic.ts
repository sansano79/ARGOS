export type IntelligentFindingType =
  | 'attack_path_plausible'
  | 'campaign_cluster'
  | 'vendor_wave'
  | 'stack_risk_accumulation'
  | 'critical_unpatched_exposed_set'
  | 'priority_escalation';

export type IntelligentMatchLevel = 'exact' | 'family' | 'contextual' | 'none';

export type IntelligentCandidate = {
  id: number;
  cveId: string;
  primaryVendor?: string | null;
  primaryProduct?: string | null;
  aliases?: string[];
  category?: string | null;
  severity?: string | null;
  cvss?: number | null;
  epss?: number | null;
  isKev?: boolean;
  hasPublicExploit?: boolean;
  exploitStatus?: string | null;
  patchAvailable?: boolean | null;
  operationalRiskScore?: number | null;
  publishedAt: Date;
  lastModifiedAt?: Date | null;
  lastChangeDetectedAt?: Date | null;
};

export type ClusteredCandidateGroup = {
  key: string;
  vendor: string;
  product: string;
  category: string;
  candidates: IntelligentCandidate[];
  score: number;
  maxCvss: number;
  maxEpss: number;
  hasKev: boolean;
  hasPublicExploit: boolean;
};

export type SubscriberMatchInput = {
  findingType?: IntelligentFindingType | string;
  affectedManufacturers: string[];
  affectedProducts: string[];
  categoryTags?: string[];
  subscriptions: Array<{ vendor?: string | null; product?: string | null }>;
  systems?: Array<{ hostname?: string | null; platform?: string | null; tags?: string[] | null }>;
  exclusions?: string[];
  confidence: number;
  relevanceScore: number;
  recencyWeight: number;
};

export type SubscriberMatchResult = {
  matchLevel: IntelligentMatchLevel;
  matchScore: number;
  deliveryScore: number;
  shouldNotify: boolean;
  reasons: string[];
  matchedSubscriptions: Array<{ vendor: string; product: string; level: IntelligentMatchLevel }>;
  suppressionReason?: string;
};

const HIGH_RECENCY_DAYS = 7;
const MEDIUM_RECENCY_DAYS = 30;
const MAX_CONTEXT_DAYS = 60;

const normalize = (value: unknown) =>
  String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[_/]+/g, ' ')
    .replace(/\s+/g, ' ');

const containsNormalized = (haystack: string, needle: string) =>
  !!haystack && !!needle && (haystack === needle || haystack.includes(needle) || needle.includes(haystack));

const hasExploitSignal = (candidate: IntelligentCandidate) =>
  candidate.isKev === true
  || candidate.hasPublicExploit === true
  || ['active_exploitation', 'reliable_poc', 'poc'].includes(normalize(candidate.exploitStatus));

export const getRecencyWeight = (ageDays: number) => {
  if (!Number.isFinite(ageDays) || ageDays < 0) return 1;
  if (ageDays <= HIGH_RECENCY_DAYS) return 1;
  if (ageDays <= MEDIUM_RECENCY_DAYS) return 0.65;
  if (ageDays <= MAX_CONTEXT_DAYS) return 0.35;
  return 0.15;
};

export const getRecencyBand = (ageDays: number) => {
  if (ageDays <= HIGH_RECENCY_DAYS) return 'primary';
  if (ageDays <= MEDIUM_RECENCY_DAYS) return 'tactical';
  return 'historical';
};

export const computeCandidatePriorityScore = (candidate: IntelligentCandidate, now = new Date()) => {
  const publishedAgeDays = Math.max(0, (now.getTime() - new Date(candidate.publishedAt).getTime()) / 86400000);
  const recencyWeight = getRecencyWeight(publishedAgeDays);
  const cvss = Number(candidate.cvss || 0);
  const epss = Number(candidate.epss || 0);
  const opRisk = Number(candidate.operationalRiskScore || 0);
  const patchPenalty = candidate.patchAvailable === false ? 1.2 : candidate.patchAvailable == null ? 0.4 : 0;
  const kevBoost = candidate.isKev ? 4 : 0;
  const publicExploitBoost = candidate.hasPublicExploit ? 2.5 : 0;
  const activeExploitBoost = normalize(candidate.exploitStatus) === 'active exploitation' || normalize(candidate.exploitStatus) === 'active_exploitation' ? 3 : 0;
  const severityBoost = normalize(candidate.severity) === 'critical' ? 1.5 : normalize(candidate.severity) === 'high' ? 0.8 : 0;
  const score = ((cvss * 0.7) + (epss * 10 * 0.7) + (opRisk * 0.25) + patchPenalty + kevBoost + publicExploitBoost + activeExploitBoost + severityBoost) * recencyWeight;
  return Number(score.toFixed(4));
};

export const clusterIntelligentCandidates = (items: IntelligentCandidate[], now = new Date()): ClusteredCandidateGroup[] => {
  const groups = new Map<string, ClusteredCandidateGroup>();

  for (const item of Array.isArray(items) ? items : []) {
    const vendor = normalize(item.primaryVendor) || 'unknown-vendor';
    const product = normalize(item.primaryProduct) || 'unknown-product';
    const category = normalize(item.category) || 'general';
    const key = product !== 'unknown-product'
      ? `${vendor}::${product}`
      : `${vendor}::${category}`;
    const score = computeCandidatePriorityScore(item, now);

    if (!groups.has(key)) {
      groups.set(key, {
        key,
        vendor,
        product,
        category,
        candidates: [],
        score: 0,
        maxCvss: 0,
        maxEpss: 0,
        hasKev: false,
        hasPublicExploit: false,
      });
    }

    const group = groups.get(key)!;
    group.candidates.push(item);
    group.score += score;
    group.maxCvss = Math.max(group.maxCvss, Number(item.cvss || 0));
    group.maxEpss = Math.max(group.maxEpss, Number(item.epss || 0));
    group.hasKev = group.hasKev || item.isKev === true;
    group.hasPublicExploit = group.hasPublicExploit || hasExploitSignal(item);
  }

  return Array.from(groups.values())
    .map((group) => ({
      ...group,
      score: Number((group.score + (group.candidates.length >= 3 ? 1.25 : group.candidates.length >= 2 ? 0.55 : 0)).toFixed(4)),
      candidates: [...group.candidates].sort((a, b) => computeCandidatePriorityScore(b, now) - computeCandidatePriorityScore(a, now)),
    }))
    .sort((a, b) => {
      const byScore = b.score - a.score;
      if (byScore !== 0) return byScore;
      return b.candidates.length - a.candidates.length;
    });
};

export const classifyFindingTypeForCluster = (cluster: ClusteredCandidateGroup): IntelligentFindingType => {
  const size = cluster.candidates.length;
  if (cluster.hasKev && cluster.hasPublicExploit && cluster.maxCvss >= 8.5) return 'attack_path_plausible';
  if (size >= 4 && cluster.vendor !== 'unknown-vendor') return 'vendor_wave';
  if (size >= 3 && cluster.product !== 'unknown-product') return 'stack_risk_accumulation';
  if (cluster.hasKev && cluster.maxCvss >= 8 && cluster.candidates.some((item) => item.patchAvailable === false || item.patchAvailable == null)) {
    return 'critical_unpatched_exposed_set';
  }
  if (cluster.hasPublicExploit && cluster.maxEpss >= 0.7) return 'priority_escalation';
  return 'campaign_cluster';
};

export const evaluateSubscriberFindingMatch = (input: SubscriberMatchInput): SubscriberMatchResult => {
  const affectedManufacturers = (input.affectedManufacturers || []).map(normalize).filter(Boolean);
  const affectedProducts = (input.affectedProducts || []).map(normalize).filter(Boolean);
  const categoryTags = (input.categoryTags || []).map(normalize).filter(Boolean);
  const exclusions = new Set((input.exclusions || []).map(normalize).filter(Boolean));

  for (const vendor of affectedManufacturers) {
    if (exclusions.has(vendor)) {
      return {
        matchLevel: 'none',
        matchScore: 0,
        deliveryScore: 0,
        shouldNotify: false,
        reasons: ['Fabricante excluido por el suscriptor'],
        matchedSubscriptions: [],
        suppressionReason: 'subscriber_exclusion',
      };
    }
  }
  for (const product of affectedProducts) {
    if (exclusions.has(product)) {
      return {
        matchLevel: 'none',
        matchScore: 0,
        deliveryScore: 0,
        shouldNotify: false,
        reasons: ['Producto excluido por el suscriptor'],
        matchedSubscriptions: [],
        suppressionReason: 'subscriber_exclusion',
      };
    }
  }

  let bestLevel: IntelligentMatchLevel = 'none';
  let bestScore = 0;
  const matchedSubscriptions: Array<{ vendor: string; product: string; level: IntelligentMatchLevel }> = [];

  for (const subscription of input.subscriptions || []) {
    const subVendor = normalize(subscription.vendor);
    const subProduct = normalize(subscription.product);
    let level: IntelligentMatchLevel = 'none';
    let score = 0;

    const vendorExact = !!subVendor && affectedManufacturers.some((vendor) => vendor === subVendor);
    const productExact = !!subProduct && affectedProducts.some((product) => product === subProduct);
    const productFamily = !!subProduct && affectedProducts.some((product) => containsNormalized(product, subProduct));
    const vendorFamily = !!subVendor && affectedManufacturers.some((vendor) => containsNormalized(vendor, subVendor));
    const contextual = categoryTags.some((tag) => containsNormalized(tag, subProduct) || containsNormalized(tag, subVendor));

    if ((vendorExact || vendorFamily) && (productExact || productFamily)) {
      level = productExact ? 'exact' : 'family';
      score = productExact ? 1 : 0.78;
    } else if (vendorExact || vendorFamily) {
      level = 'family';
      score = 0.62;
    } else if (contextual) {
      level = 'contextual';
      score = 0.38;
    }

    if (level !== 'none') {
      matchedSubscriptions.push({ vendor: subVendor, product: subProduct, level });
      if (score > bestScore) {
        bestScore = score;
        bestLevel = level;
      }
    }
  }

  if (bestLevel === 'none') {
    for (const system of input.systems || []) {
      const platform = normalize(system.platform);
      const tags = Array.isArray(system.tags) ? system.tags.map(normalize) : [];
      const platformMatch = affectedProducts.some((product) => containsNormalized(product, platform))
        || affectedManufacturers.some((vendor) => containsNormalized(vendor, platform))
        || categoryTags.some((tag) => containsNormalized(tag, platform))
        || tags.some((tag) => categoryTags.some((category) => containsNormalized(category, tag)));
      if (platformMatch) {
        bestLevel = 'contextual';
        bestScore = 0.34;
        break;
      }
    }
  }

  const confidenceWeight = Math.max(0, Math.min(1, Number(input.confidence || 0)));
  const relevanceWeight = Math.max(0, Math.min(1.25, Number(input.relevanceScore || 0) / 10));
  const recencyWeight = Math.max(0.15, Math.min(1, Number(input.recencyWeight || 0)));
  const deliveryScore = Number((bestScore * 0.45 + confidenceWeight * 0.25 + relevanceWeight * 0.2 + recencyWeight * 0.1).toFixed(4));

  const shouldNotify = bestLevel !== 'none' && deliveryScore >= (bestLevel === 'contextual' ? 0.52 : 0.6);
  const reasons = [];
  if (bestLevel !== 'none') reasons.push(`Matching ${bestLevel} con suscripciones o activos del suscriptor`);
  if (confidenceWeight > 0.7) reasons.push('Confianza alta del hallazgo');
  if (relevanceWeight > 0.7) reasons.push('Relevancia operativa alta');
  if (recencyWeight >= 0.65) reasons.push('Recencia táctica favorable');

  return {
    matchLevel: bestLevel,
    matchScore: Number(bestScore.toFixed(4)),
    deliveryScore,
    shouldNotify,
    reasons,
    matchedSubscriptions,
    suppressionReason: shouldNotify ? undefined : bestLevel === 'none' ? 'no_subscriber_match' : 'low_delivery_score',
  };
};
