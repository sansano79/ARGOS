import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, ProductAsset } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

export interface CreateProductAssetInput {
  name: string;
  slug?: string;
  owner?: string | null;
  environment?: string | null;
  criticality?: string | null;
  productType?: string | null;
  source?: string | null;
  version?: string | null;
  repositoryUrl?: string | null;
  isActive?: boolean;
  lastSeenAt?: Date | string | null;
  metadata?: Prisma.JsonValue | string | null;
}

export interface ListProductAssetsOptions {
  isActive?: boolean;
  environment?: string;
  criticality?: string;
  productType?: string;
  take?: number;
  skip?: number;
}

@Injectable()
export class ProductAssetsService {
  constructor(private readonly prisma: PrismaService) {}

  async createProductAsset(input: CreateProductAssetInput): Promise<ProductAsset> {
    const name = String(input?.name || '').trim();
    if (!name) {
      throw new BadRequestException('Product asset name is required');
    }

    const slug = this.buildSlug(input?.slug || name);
    if (!slug) {
      throw new BadRequestException('A valid slug could not be derived for the product asset');
    }

    return this.prisma.productAsset.create({
      data: {
        name,
        slug,
        owner: this.toOptionalString(input?.owner),
        environment: this.toOptionalString(input?.environment),
        criticality: this.toOptionalString(input?.criticality),
        productType: this.toOptionalString(input?.productType) || 'unknown',
        source: this.toOptionalString(input?.source) || 'manual',
        version: this.toOptionalString(input?.version),
        repositoryUrl: this.toOptionalString(input?.repositoryUrl),
        isActive: input?.isActive ?? true,
        lastSeenAt: this.toOptionalDate(input?.lastSeenAt),
        metadata: this.serializeMetadata(input?.metadata),
      },
    });
  }

  async listProductAssets(options: ListProductAssetsOptions = {}): Promise<ProductAsset[]> {
    const environment = this.toOptionalString(options.environment);
    const criticality = this.toOptionalString(options.criticality);
    const productType = this.toOptionalString(options.productType);
    const where: Prisma.ProductAssetWhereInput = {
      ...(typeof options.isActive === 'boolean' ? { isActive: options.isActive } : {}),
      ...(environment ? { environment } : {}),
      ...(criticality ? { criticality } : {}),
      ...(productType ? { productType } : {}),
    };

    return this.prisma.productAsset.findMany({
      where,
      orderBy: [{ isActive: 'desc' }, { criticality: 'asc' }, { name: 'asc' }],
      take: options.take,
      skip: options.skip,
    });
  }

  async getProductAssetById(id: number): Promise<ProductAsset> {
    const normalizedId = Number(id);
    if (!Number.isInteger(normalizedId) || normalizedId <= 0) {
      throw new BadRequestException('A valid product asset id is required');
    }

    const productAsset = await this.prisma.productAsset.findUnique({
      where: { id: normalizedId },
    });
    if (!productAsset) {
      throw new NotFoundException(`Product asset ${normalizedId} not found`);
    }

    return productAsset;
  }

  async getProductAssetBySlug(slug: string): Promise<ProductAsset> {
    const normalizedSlug = this.buildSlug(slug);
    if (!normalizedSlug) {
      throw new BadRequestException('A valid product asset slug is required');
    }

    const productAsset = await this.prisma.productAsset.findUnique({
      where: { slug: normalizedSlug },
    });
    if (!productAsset) {
      throw new NotFoundException(`Product asset ${normalizedSlug} not found`);
    }

    return productAsset;
  }

  private buildSlug(value: string): string {
    return String(value || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
  }

  private toOptionalString(value: unknown): string | null {
    const normalized = String(value ?? '').trim();
    return normalized ? normalized : null;
  }

  private toOptionalDate(value: Date | string | null | undefined): Date | null {
    if (!value) return null;
    const date = value instanceof Date ? value : new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  private serializeMetadata(value: Prisma.JsonValue | string | null | undefined): string | null {
    if (value == null) return null;
    if (typeof value === 'string') {
      const trimmed = value.trim();
      return trimmed ? trimmed : null;
    }

    try {
      return JSON.stringify(value);
    } catch {
      throw new BadRequestException('Product asset metadata must be serializable');
    }
  }
}
