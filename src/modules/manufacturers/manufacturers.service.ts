import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import {
  isContextualVendor,
  normalizeName,
  normalizeProduct,
  normalizeVendor,
  VENDOR_ALIASES,
} from '../../shared/vendor-normalization';

type CatalogProduct = { id: number; product: string; versions: string[] };
type CatalogManufacturer = { name: string; products: CatalogProduct[]; productsCount: number };
type CatalogHiddenReason =
  | 'contextual_vendor'
  | 'advisory_emitter'
  | 'cert_org'
  | 'unknown_vendor';

type CatalogMetadata = {
  source: string;
  visibleManufacturers: number;
  visibleProducts: number;
  hiddenManufacturers: number;
  hiddenProducts: number;
  hiddenByReason: Array<{ reason: CatalogHiddenReason; count: number }>;
  hiddenSamples: Array<{ vendor: string; reason: CatalogHiddenReason; productsCount: number }>;
};

@Injectable()
export class ManufacturersService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll(includeHidden = false) {
    if (includeHidden) {
      return this.buildRawCatalogView();
    }
    const { items } = await this.buildOperationalCatalogView();
    return items;
  }

  async getCatalogMetadata(): Promise<CatalogMetadata> {
    const { metadata } = await this.buildOperationalCatalogView();
    return metadata;
  }

  async createManufacturer(name: string) {
    const normalized = normalizeName(name);
    if (!normalized) throw new BadRequestException('Manufacturer name is required');

    await (this.prisma as any).manufacturer.upsert({
      where: { name: normalized },
      create: { name: normalized, isActive: true },
      update: { isActive: true },
    });

    return { success: true, name: normalized };
  }

  async createProduct(data: { vendor: string; product: string; versions?: string[] }) {
    const vendor = normalizeName(data?.vendor);
    const product = normalizeProduct(data?.product);
    if (!vendor || !product) {
      throw new BadRequestException('Vendor and product are required');
    }

    await (this.prisma as any).manufacturer.upsert({
      where: { name: vendor },
      create: { name: vendor, isActive: true },
      update: { isActive: true },
    });

    const incomingVersions = [...new Set((data?.versions || [])
      .map((v) => String(v || '').trim())
      .filter((v) => !!v))];

    const existing = await this.prisma.softwareCatalog.findUnique({
      where: { vendor_product: { vendor, product } },
      select: { versions: true },
    });

    const mergedVersions = [...new Set([
      ...this.parseJsonArray(existing?.versions),
      ...incomingVersions,
    ])];

    const row = await this.prisma.softwareCatalog.upsert({
      where: { vendor_product: { vendor, product } },
      create: {
        vendor,
        product,
        versions: mergedVersions.length ? JSON.stringify(mergedVersions) : null,
      },
      update: {
        versions: mergedVersions.length ? JSON.stringify(mergedVersions) : null,
      },
    });

    return {
      success: true,
      product: { id: row.id, vendor, product, versions: mergedVersions },
    };
  }

  async mergeManufacturers(targetName: string, sourceNames: string[]) {
    const target = normalizeName(targetName);
    const sourceSet = [...new Set((sourceNames || [])
      .map((n) => normalizeName(n))
      .filter((n) => !!n && n !== target))];

    if (!target) throw new BadRequestException('Target manufacturer is required');
    if (sourceSet.length === 0) {
      throw new BadRequestException('At least one source manufacturer is required');
    }

    await (this.prisma as any).manufacturer.upsert({
      where: { name: target },
      create: { name: target, isActive: true },
      update: { isActive: true },
    });

    await this.prisma.$transaction(async (tx) => {
      for (const source of sourceSet) {
        // Merge software catalog rows source -> target by product
        const rows = await tx.softwareCatalog.findMany({
          where: { vendor: source },
          select: { product: true, versions: true },
        });

        for (const row of rows) {
          const existing = await tx.softwareCatalog.findUnique({
            where: { vendor_product: { vendor: target, product: row.product } },
            select: { versions: true },
          });
          const mergedVersions = [...new Set([
            ...this.parseJsonArray(existing?.versions),
            ...this.parseJsonArray(row.versions),
          ])];

          await tx.softwareCatalog.upsert({
            where: { vendor_product: { vendor: target, product: row.product } },
            create: {
              vendor: target,
              product: row.product,
              versions: mergedVersions.length ? JSON.stringify(mergedVersions) : null,
            },
            update: {
              versions: mergedVersions.length ? JSON.stringify(mergedVersions) : null,
            },
          });
        }

        await tx.softwareCatalog.deleteMany({ where: { vendor: source } });

        // Merge user subscriptions source -> target
        const subs = await tx.userSubscription.findMany({
          where: { vendor: source },
          select: { userId: true, product: true, versions: true, isActive: true },
        });

        for (const sub of subs) {
          const existing = await tx.userSubscription.findUnique({
            where: {
              userId_vendor_product: {
                userId: sub.userId,
                vendor: target,
                product: sub.product,
              },
            },
            select: { versions: true },
          });

          const mergedVersions = [...new Set([
            ...this.parseJsonArray(existing?.versions),
            ...this.parseJsonArray(sub.versions),
          ])];

          await tx.userSubscription.upsert({
            where: {
              userId_vendor_product: {
                userId: sub.userId,
                vendor: target,
                product: sub.product,
              },
            },
            create: {
              userId: sub.userId,
              vendor: target,
              product: sub.product,
              versions: mergedVersions.length ? JSON.stringify(mergedVersions) : null,
              isActive: sub.isActive,
            },
            update: {
              versions: mergedVersions.length ? JSON.stringify(mergedVersions) : null,
              isActive: sub.isActive,
            },
          });
        }

        await tx.userSubscription.deleteMany({ where: { vendor: source } });

        // Mark source manufacturer inactive
        await (tx as any).manufacturer.updateMany({
          where: { name: source },
          data: { isActive: false },
        });
      }
    });

    // Harmonize vendor names inside vulnerability affectedProducts JSON
    const vulns = await this.prisma.vulnerability.findMany({
      where: { affectedProducts: { not: null } },
      select: { id: true, affectedProducts: true },
    });
    const sourceLookup = new Set(sourceSet);

    for (const vuln of vulns) {
      const affected = this.parseJson(vuln.affectedProducts);
      if (!Array.isArray(affected)) continue;
      let changed = false;
      const next = affected.map((p: any) => {
        const vendor = normalizeName(p?.vendor);
        if (sourceLookup.has(vendor)) {
          changed = true;
          return { ...p, vendor: target };
        }
        return p;
      });
      if (changed) {
        await this.prisma.vulnerability.update({
          where: { id: vuln.id },
          data: { affectedProducts: JSON.stringify(next) },
        });
      }
    }

    return { success: true, target, merged: sourceSet };
  }

  /**
   * Returns the alias map grouped by canonical name,
   * plus stats about how many vendors in the catalog could benefit from normalization.
   */
  async getAliasesAndStats() {
    // Group aliases by canonical name
    const grouped: Record<string, string[]> = {};
    for (const [alias, canonical] of Object.entries(VENDOR_ALIASES)) {
      if (!grouped[canonical]) grouped[canonical] = [];
      grouped[canonical].push(alias);
    }

    // Get all distinct vendors from the catalog
    const catalogVendors = await this.prisma.softwareCatalog.findMany({
      select: { vendor: true },
      distinct: ['vendor'],
    });

    const allVendorNames = catalogVendors.map((r) => r.vendor);

    // Detect potential duplicates: vendors whose normalizeVendor() result differs from their name
    const potentialDuplicates: Array<{ current: string; suggestedCanonical: string }> = [];
    const canonicalGroups: Record<string, string[]> = {};

    for (const name of allVendorNames) {
      const normalized = normalizeVendor(name);
      if (!canonicalGroups[normalized]) canonicalGroups[normalized] = [];
      canonicalGroups[normalized].push(name);
      if (normalized !== name) {
        potentialDuplicates.push({ current: name, suggestedCanonical: normalized });
      }
    }

    // Find groups where multiple catalog entries map to same canonical
    const duplicateGroups = Object.entries(canonicalGroups)
      .filter(([, names]) => names.length > 1)
      .map(([canonical, names]) => ({ canonical, variants: names, count: names.length }));

    // Get subscription stats per vendor
    const subscriptionCounts = await this.prisma.userSubscription.groupBy({
      by: ['vendor'],
      _count: { vendor: true },
      where: { isActive: true },
    });
    const subCountMap = new Map(subscriptionCounts.map((r) => [r.vendor, r._count.vendor]));

    // CVE count per vendor (from softwareCatalog perspective)
    const totalVendors = allVendorNames.length;
    const totalProducts = await this.prisma.softwareCatalog.count();
    const totalAliases = Object.keys(VENDOR_ALIASES).length;

    return {
      aliases: grouped,
      totalAliases,
      stats: {
        totalVendors,
        totalProducts,
        potentialDuplicates,
        duplicateGroups,
        vendorsWithSubscriptions: subscriptionCounts.map((r) => ({
          vendor: r.vendor,
          subscriptionCount: r._count.vendor,
        })),
      },
    };
  }

  /**
   * Delete a product from the software catalog.
   */
  async deleteProduct(productId: number) {
    if (!productId) throw new BadRequestException('Product ID is required');
    await this.prisma.softwareCatalog.delete({ where: { id: productId } });
    return { success: true };
  }

  /**
   * Delete a manufacturer and all its catalog entries.
   */
  async deleteManufacturer(name: string) {
    const normalized = normalizeName(name);
    if (!normalized) throw new BadRequestException('Manufacturer name is required');

    await this.prisma.$transaction(async (tx) => {
      await tx.softwareCatalog.deleteMany({ where: { vendor: normalized } });
      await (tx as any).manufacturer.updateMany({
        where: { name: normalized },
        data: { isActive: false },
      });
    });

    return { success: true, name: normalized };
  }

  private parseJsonArray(value: any): string[] {
    try {
      if (Array.isArray(value)) return value.map((v) => String(v));
      const parsed = JSON.parse(value || '[]');
      return Array.isArray(parsed) ? parsed.map((v) => String(v)) : [];
    } catch {
      return [];
    }
  }

  private parseJson(value: any): any {
    if (typeof value === 'string') {
      try { return JSON.parse(value); } catch { return value; }
    }
    return value;
  }

  private async buildOperationalCatalogView(): Promise<{
    items: CatalogManufacturer[];
    metadata: CatalogMetadata;
  }> {
    const [manufacturers, catalogRows, vulnerabilityPairs] = await Promise.all([
      (this.prisma as any).manufacturer.findMany({
        where: { isActive: true },
        orderBy: { name: 'asc' },
      }),
      this.prisma.softwareCatalog.findMany({
        orderBy: [{ vendor: 'asc' }, { product: 'asc' }],
      }),
      this.prisma.vulnerability.findMany({
        where: {
          primaryVendor: { not: null },
          primaryProduct: { not: null },
        },
        distinct: ['primaryVendor', 'primaryProduct'],
        select: {
          primaryVendor: true,
          primaryProduct: true,
        },
      }),
    ]);

    const catalogRowByKey = new Map<string, { id: number; versions: string[] }>();
    for (const row of catalogRows) {
      catalogRowByKey.set(`${row.vendor}::${row.product}`, {
        id: row.id,
        versions: this.parseJsonArray(row.versions),
      });
    }

    const visibleMap = new Map<string, { name: string; products: CatalogProduct[] }>();
    const hiddenSamples = new Map<string, { vendor: string; reason: CatalogHiddenReason; productsCount: number }>();
    const hiddenReasonCounts = new Map<CatalogHiddenReason, Set<string>>();

    const pushVisibleProduct = (vendor: string, product: string) => {
      const normalizedVendor = normalizeName(vendor);
      const normalizedProduct = normalizeProduct(product);
      if (!normalizedVendor || !normalizedProduct) return;

      const key = `${normalizedVendor}::${normalizedProduct}`;
      const catalogRow = catalogRowByKey.get(key);
      if (!visibleMap.has(normalizedVendor)) {
        visibleMap.set(normalizedVendor, { name: normalizedVendor, products: [] });
      }

      const current = visibleMap.get(normalizedVendor)!;
      if (current.products.some((item) => item.product === normalizedProduct)) {
        return;
      }

      current.products.push({
        id: catalogRow?.id || 0,
        product: normalizedProduct,
        versions: catalogRow?.versions || [],
      });
    };

    const registerHiddenVendor = (
      vendorValue: string | null | undefined,
      reason: CatalogHiddenReason,
      productsCount = 0,
    ) => {
      const vendor = normalizeName(vendorValue);
      if (!vendor) return;
      if (!hiddenReasonCounts.has(reason)) {
        hiddenReasonCounts.set(reason, new Set<string>());
      }
      hiddenReasonCounts.get(reason)!.add(vendor);
      if (!hiddenSamples.has(vendor)) {
        hiddenSamples.set(vendor, { vendor, reason, productsCount });
      } else {
        hiddenSamples.get(vendor)!.productsCount = Math.max(
          hiddenSamples.get(vendor)!.productsCount,
          productsCount,
        );
      }
    };

    for (const manufacturer of manufacturers) {
      const reason = this.classifyCatalogVendor(manufacturer.name);
      if (!reason) {
        if (!visibleMap.has(manufacturer.name)) {
          visibleMap.set(manufacturer.name, { name: manufacturer.name, products: [] });
        }
        continue;
      }
      const productsCount = catalogRows.filter((row) => row.vendor === manufacturer.name).length;
      registerHiddenVendor(manufacturer.name, reason, productsCount);
    }

    for (const row of catalogRows) {
      const reason = this.classifyCatalogVendor(row.vendor);
      if (reason) {
        registerHiddenVendor(row.vendor, reason, 1);
        continue;
      }
      pushVisibleProduct(row.vendor, row.product);
    }

    for (const pair of vulnerabilityPairs) {
      const vendor = normalizeName(pair.primaryVendor);
      const product = normalizeProduct(pair.primaryProduct);
      if (!vendor || !product) continue;
      const reason = this.classifyCatalogVendor(vendor);
      if (reason) {
        registerHiddenVendor(vendor, reason, 1);
        continue;
      }
      pushVisibleProduct(vendor, product);
    }

    const items = Array.from(visibleMap.values())
      .map((manufacturer) => ({
        name: manufacturer.name,
        products: manufacturer.products.sort((a, b) => a.product.localeCompare(b.product)),
        productsCount: manufacturer.products.length,
      }))
      .sort((left, right) => left.name.localeCompare(right.name));

    const visibleProducts = items.reduce((sum, item) => sum + item.productsCount, 0);
    const hiddenProducts = Array.from(hiddenSamples.values()).reduce(
      (sum, item) => sum + item.productsCount,
      0,
    );
    const hiddenSampleList = Array.from(hiddenSamples.values())
      .sort((left, right) => right.productsCount - left.productsCount || left.vendor.localeCompare(right.vendor))
      .slice(0, 20);

    return {
      items,
      metadata: {
        source: 'operational-catalog-from-vulnerability-semantics+software-catalog',
        visibleManufacturers: items.length,
        visibleProducts,
        hiddenManufacturers: hiddenSamples.size,
        hiddenProducts,
        hiddenByReason: Array.from(hiddenReasonCounts.entries())
          .map(([reason, vendors]) => ({ reason, count: vendors.size }))
          .sort((left, right) => right.count - left.count || left.reason.localeCompare(right.reason)),
        hiddenSamples: hiddenSampleList,
      },
    };
  }

  private async buildRawCatalogView(): Promise<CatalogManufacturer[]> {
    const [manufacturers, catalogRows] = await Promise.all([
      (this.prisma as any).manufacturer.findMany({
        where: { isActive: true },
        orderBy: { name: 'asc' },
      }),
      this.prisma.softwareCatalog.findMany({
        orderBy: [{ vendor: 'asc' }, { product: 'asc' }],
      }),
    ]);

    const map = new Map<string, { name: string; products: CatalogProduct[] }>();

    for (const manufacturer of manufacturers) {
      map.set(manufacturer.name, { name: manufacturer.name, products: [] });
    }

    for (const row of catalogRows) {
      if (!map.has(row.vendor)) {
        map.set(row.vendor, { name: row.vendor, products: [] });
      }
      map.get(row.vendor)?.products.push({
        id: row.id,
        product: row.product,
        versions: this.parseJsonArray(row.versions),
      });
    }

    return Array.from(map.values())
      .map((manufacturer) => ({
        name: manufacturer.name,
        products: manufacturer.products.sort((a, b) => a.product.localeCompare(b.product)),
        productsCount: manufacturer.products.length,
      }))
      .sort((left, right) => left.name.localeCompare(right.name));
  }

  private classifyCatalogVendor(vendorValue: string | null | undefined): CatalogHiddenReason | null {
    const vendor = normalizeName(vendorValue);
    if (!vendor || vendor === 'unknown') return 'unknown_vendor';
    if (isContextualVendor(vendor)) return 'contextual_vendor';
    if (/\b(cert|jpcert|incibe|csirt)\b/i.test(vendor)) return 'cert_org';
    if (/\b(patchstack|vuldb|mitre|nvd|cve|ghsa|advisory|security)\b/i.test(vendor)) {
      return 'advisory_emitter';
    }
    return null;
  }
}
