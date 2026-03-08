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
const VENDOR_ALIASES: Record<string, string> = {
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
  affectedProduct: { vendor?: string; product?: string; version?: string; versionRange?: string },
): boolean {
  const sVendor = normalizeName(subscription.vendor);
  const sProduct = normalizeName(subscription.product);

  const pVendor = normalizeName(affectedProduct?.vendor);
  const pProduct = normalizeName(affectedProduct?.product);

  // Both fields empty → poorly correlated data
  if (!pVendor && !pProduct) return false;

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
  affectedProducts: Array<{ vendor: string; product: string; version?: string; versionRange?: string }>,
): Array<{ vendor: string; product: string; version?: string; versionRange?: string }> {
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
