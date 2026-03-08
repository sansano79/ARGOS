import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { normalizeName, normalizeProduct } from '../../shared/vendor-normalization';

@Injectable()
export class ManufacturersService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll() {
    const [manufacturers, catalogRows] = await Promise.all([
      (this.prisma as any).manufacturer.findMany({
        where: { isActive: true },
        orderBy: { name: 'asc' },
      }),
      this.prisma.softwareCatalog.findMany({
        orderBy: [{ vendor: 'asc' }, { product: 'asc' }],
      }),
    ]);

    const map = new Map<
      string,
      { name: string; products: Array<{ id: number; product: string; versions: string[] }> }
    >();

    for (const m of manufacturers) {
      map.set(m.name, { name: m.name, products: [] });
    }

    for (const row of catalogRows) {
      const name = row.vendor;
      if (!map.has(name)) {
        map.set(name, { name, products: [] });
      }
      map.get(name)?.products.push({
        id: row.id,
        product: row.product,
        versions: this.parseJsonArray(row.versions),
      });
    }

    return Array.from(map.values())
      .map((m) => ({
        ...m,
        products: m.products.sort((a, b) => a.product.localeCompare(b.product)),
        productsCount: m.products.length,
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
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

  // normalizeName and normalizeProduct imported from shared/vendor-normalization

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
}
