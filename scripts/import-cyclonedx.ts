/**
 * Importa un SBOM CycloneDX JSON hacia DependencyEvidenceImport y ProductDependencyInventory.
 *
 * Uso:
 *   npx ts-node scripts/import-cyclonedx.ts \
 *     --product-asset-id=42 \
 *     --file=/ruta/al/bom.json \
 *     --source-name=manual-upload \
 *     --source-path=tmp/bom.json
 *
 * Flags opcionales:
 *   --debug    Muestra stacktrace en caso de error.
 */
import * as fs from 'fs';
import * as path from 'path';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { DependencyEvidenceImportsService } from '../src/modules/dependency-evidence-imports/dependency-evidence-imports.service';

type CliOptions = {
  productAssetId: number;
  file: string;
  sourceName?: string;
  sourcePath?: string;
  debug: boolean;
};

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const resolvedFile = path.resolve(options.file);

  if (!fs.existsSync(resolvedFile)) {
    throw new Error(`CycloneDX file not found: ${resolvedFile}`);
  }

  const raw = await fs.promises.readFile(resolvedFile, 'utf-8');
  let payload: unknown;
  try {
    payload = JSON.parse(raw);
  } catch {
    throw new Error(`CycloneDX file is not valid JSON: ${resolvedFile}`);
  }

  const app = await NestFactory.createApplicationContext(AppModule, {
    logger: ['error', 'warn', 'log'],
  });

  try {
    const importsService = app.get(DependencyEvidenceImportsService);
    const result = await importsService.importCycloneDxJson(
      options.productAssetId,
      payload,
      {
        sourceName: options.sourceName || 'manual-upload',
        sourcePath: options.sourcePath || resolvedFile,
      },
    );

    console.log('CycloneDX import completed');
    console.log(`  productAssetId: ${result.productAssetId}`);
    console.log(`  importId: ${result.importId}`);
    console.log(`  status: ${result.status}`);
    console.log(`  importedComponents: ${result.importedComponents}`);
    console.log(`  ecosystems: ${result.summary.ecosystems.join(', ') || 'none'}`);
    console.log(`  componentTypes: ${result.summary.componentTypes.join(', ') || 'none'}`);
    console.log(`  hasMetadataComponent: ${result.summary.hasMetadataComponent ? 'yes' : 'no'}`);
  } finally {
    await app.close();
  }
}

function parseArgs(args: string[]): CliOptions {
  const values: Record<string, string | boolean> = {};

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (!arg.startsWith('--')) {
      throw new Error(`Unknown argument: ${arg}`);
    }

    if (arg === '--debug') {
      values.debug = true;
      continue;
    }

    const [rawKey, inlineValue] = arg.slice(2).split('=', 2);
    const key = rawKey.trim();
    const nextValue = inlineValue ?? args[i + 1];

    if (!key) {
      throw new Error(`Invalid argument: ${arg}`);
    }
    if (inlineValue == null) {
      if (!nextValue || String(nextValue).startsWith('--')) {
        throw new Error(`Missing value for --${key}`);
      }
      values[key] = String(nextValue);
      i += 1;
      continue;
    }

    values[key] = String(inlineValue);
  }

  const productAssetId = Number(values['product-asset-id']);
  if (!Number.isInteger(productAssetId) || productAssetId <= 0) {
    throw new Error('You must provide a valid --product-asset-id');
  }

  const file = String(values.file || '').trim();
  if (!file) {
    throw new Error('You must provide --file=/path/to/bom.json');
  }

  return {
    productAssetId,
    file,
    sourceName: optionalString(values['source-name']),
    sourcePath: optionalString(values['source-path']),
    debug: values.debug === true,
  };
}

function optionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized ? normalized : undefined;
}

main().catch((error) => {
  const args = process.argv.slice(2);
  const debug = args.includes('--debug');
  const message = error instanceof Error ? error.message : String(error);
  console.error(`CycloneDX import failed: ${message}`);
  if (debug && error instanceof Error && error.stack) {
    console.error(error.stack);
  }
  process.exitCode = 1;
});
