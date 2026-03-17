import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { ProductAssetsService } from '../product-assets/product-assets.service';

export interface ImportCycloneDxJsonOptions {
  sourceName?: string | null;
  sourcePath?: string | null;
}

export interface ImportCycloneDxJsonResult {
  importId: number;
  productAssetId: number;
  status: 'completed';
  importedComponents: number;
  summary: {
    totalComponents: number;
    ecosystems: string[];
    componentTypes: string[];
    hasMetadataComponent: boolean;
  };
}

type CycloneDxComponentCandidate = {
  name: string;
  version: string | null;
  vendor: string | null;
  componentType: string;
  ecosystem: string;
  purl: string | null;
  cpe: string | null;
  evidencePath: string;
  rawEvidence: string;
  confidence: number;
};

@Injectable()
export class DependencyEvidenceImportsService {
  private readonly logger = new Logger(DependencyEvidenceImportsService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly productAssetsService: ProductAssetsService,
  ) {}

  async importCycloneDxJson(
    productAssetId: number,
    payload: unknown,
    options: ImportCycloneDxJsonOptions = {},
  ): Promise<ImportCycloneDxJsonResult> {
    const productAsset = await this.productAssetsService.getProductAssetById(productAssetId);
    const rawPayload = this.serializePayload(payload);

    const importRow = await this.prisma.dependencyEvidenceImport.create({
      data: {
        productAssetId: productAsset.id,
        importType: 'sbom-cyclonedx',
        importStatus: 'pending',
        sourceName: this.toOptionalString(options.sourceName),
        sourcePath: this.toOptionalString(options.sourcePath),
        rawPayload,
      },
    });

    try {
      const document = this.parseCycloneDxPayload(payload);
      const parsed = this.extractCycloneDxCandidates(document);
      const summary = this.buildSummary(parsed);

      await this.prisma.$transaction(async (tx) => {
        if (parsed.length > 0) {
          // Current phase stores an inventory snapshot attached to each import.
          // A later phase will decide how to reconcile this historical inventory
          // into a single "current effective snapshot" per ProductAsset.
          await tx.productDependencyInventory.createMany({
            data: parsed.map((component) => ({
              productAssetId: productAsset.id,
              dependencyEvidenceImportId: importRow.id,
              componentName: component.name,
              componentVendor: component.vendor,
              componentVersion: component.version,
              componentType: component.componentType,
              ecosystem: component.ecosystem,
              purl: component.purl,
              cpe: component.cpe,
              evidenceSource: 'sbom',
              evidencePath: component.evidencePath,
              directDependency: null,
              devDependency: null,
              reachable: null,
              confidence: component.confidence,
              rawEvidence: component.rawEvidence,
            })),
          });
        }

        await tx.dependencyEvidenceImport.update({
          where: { id: importRow.id },
          data: {
            importStatus: 'completed',
            normalizedSummary: JSON.stringify(summary),
          },
        });
      });

      return {
        importId: importRow.id,
        productAssetId: productAsset.id,
        status: 'completed',
        importedComponents: parsed.length,
        summary,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(
        `CycloneDX import failed for productAsset=${productAssetId} importId=${importRow.id}: ${message}`,
      );
      try {
        await this.prisma.dependencyEvidenceImport.update({
          where: { id: importRow.id },
          data: {
            importStatus: 'failed',
            errorMessage: message.slice(0, 65535),
          },
        });
      } catch (updateError) {
        const updateMessage = updateError instanceof Error ? updateError.message : String(updateError);
        this.logger.error(
          `CycloneDX import failure state could not be persisted for productAsset=${productAssetId} importId=${importRow.id}: ${updateMessage}`,
        );
      }
      throw error;
    }
  }

  private parseCycloneDxPayload(payload: unknown): Record<string, any> {
    const parsed = this.ensureJsonObject(payload);
    const bomFormat = String(parsed?.bomFormat || '').trim().toLowerCase();
    if (bomFormat && bomFormat !== 'cyclonedx') {
      throw new BadRequestException('Payload is not a CycloneDX JSON document');
    }

    if (!Array.isArray(parsed.components) && !parsed?.metadata?.component) {
      throw new BadRequestException(
        'CycloneDX JSON must include metadata.component or components[]',
      );
    }

    return parsed;
  }

  private extractCycloneDxCandidates(document: Record<string, any>): CycloneDxComponentCandidate[] {
    const candidates: CycloneDxComponentCandidate[] = [];
    const pushCandidate = (rawComponent: unknown, evidencePath: string) => {
      const candidate = this.normalizeComponent(rawComponent, evidencePath);
      if (candidate) {
        candidates.push(candidate);
      }
    };

    if (document?.metadata?.component) {
      pushCandidate(document.metadata.component, 'metadata.component');
    }

    const components = Array.isArray(document?.components) ? document.components : [];
    components.forEach((component, index) => {
      pushCandidate(component, `components[${index}]`);
    });

    const deduped = new Map<string, CycloneDxComponentCandidate>();
    for (const candidate of candidates) {
      const key = this.buildDedupKey(candidate);
      if (!deduped.has(key)) {
        deduped.set(key, candidate);
      }
    }

    return Array.from(deduped.values());
  }

  private normalizeComponent(
    rawComponent: unknown,
    evidencePath: string,
  ): CycloneDxComponentCandidate | null {
    const component = this.ensureJsonObject(rawComponent);
    const name = this.toOptionalString(component.name);
    if (!name) return null;

    const purl = this.toOptionalString(component.purl);
    const cpe = this.toOptionalString(component.cpe);
    const version = this.toOptionalString(component.version);
    const vendor =
      this.toOptionalString(component.publisher) ||
      this.toOptionalString(component?.author) ||
      this.toOptionalString(component?.supplier?.name) ||
      this.toOptionalString(component?.manufacturer?.name);
    const componentType = this.mapCycloneDxType(component.type);
    const ecosystem = this.detectEcosystemFromPurl(purl);

    return {
      name,
      version,
      vendor,
      componentType,
      ecosystem,
      purl,
      cpe,
      evidencePath,
      rawEvidence: JSON.stringify(component),
      confidence: this.calculateSbomConfidence({ purl, cpe }),
    };
  }

  private buildSummary(components: CycloneDxComponentCandidate[]) {
    const ecosystems = [...new Set(components.map((component) => component.ecosystem).filter(Boolean))].sort();
    const componentTypes = [...new Set(components.map((component) => component.componentType).filter(Boolean))].sort();
    const hasMetadataComponent = components.some((component) => component.evidencePath === 'metadata.component');

    return {
      totalComponents: components.length,
      ecosystems,
      componentTypes,
      hasMetadataComponent,
    };
  }

  private ensureJsonObject(value: unknown): Record<string, any> {
    if (typeof value === 'string') {
      try {
        const parsed = JSON.parse(value);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          return parsed as Record<string, any>;
        }
      } catch {
        throw new BadRequestException('CycloneDX payload is not valid JSON');
      }
      throw new BadRequestException('CycloneDX payload must be a JSON object');
    }

    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return value as Record<string, any>;
    }

    throw new BadRequestException('CycloneDX payload must be a JSON object');
  }

  private serializePayload(payload: unknown): string {
    if (typeof payload === 'string') {
      const trimmed = payload.trim();
      if (!trimmed) {
        throw new BadRequestException('CycloneDX payload is empty');
      }
      return trimmed;
    }

    try {
      return JSON.stringify(payload);
    } catch {
      throw new BadRequestException('CycloneDX payload must be serializable');
    }
  }

  private buildDedupKey(component: CycloneDxComponentCandidate): string {
    return [
      this.normalizeDedupField(component.name),
      this.normalizeDedupField(component.version),
      this.normalizeDedupField(component.purl),
      this.normalizeDedupField(component.cpe),
    ].join('::');
  }

  private calculateSbomConfidence(input: {
    purl: string | null;
    cpe: string | null;
  }): number {
    // CycloneDX records with a PURL or CPE are treated as highly reliable because
    // they provide a stronger package identity than name/version alone.
    if (input.purl || input.cpe) {
      return 0.98;
    }

    // Otherwise we still trust a well-formed SBOM entry, but slightly less.
    return 0.9;
  }

  private mapCycloneDxType(value: unknown): string {
    switch (String(value || '').trim().toLowerCase()) {
      case 'library':
        return 'library';
      case 'framework':
        return 'framework';
      case 'container':
        return 'container-layer-component';
      case 'application':
        return 'unknown';
      default:
        return 'unknown';
    }
  }

  private detectEcosystemFromPurl(purl: string | null): string {
    if (!purl) return 'unknown';
    const match = purl.match(/^pkg:([^/]+)/i);
    const type = String(match?.[1] || '').trim().toLowerCase();
    if (!type) return 'unknown';

    const supported = new Set([
      'npm',
      'pypi',
      'maven',
      'nuget',
      'golang',
      'cargo',
      'composer',
      'apk',
      'deb',
      'rpm',
    ]);

    return supported.has(type) ? type : 'unknown';
  }

  private toOptionalString(value: unknown): string | null {
    const normalized = String(value ?? '').trim();
    return normalized ? normalized : null;
  }

  private normalizeDedupField(value: string | null | undefined): string {
    return String(value || '')
      .trim()
      .toLowerCase();
  }
}
