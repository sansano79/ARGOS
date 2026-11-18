/**
 * Recomputes remediation / patch availability for stored vulnerabilities from the raw source
 * payload already saved in `raw_data`, using the evidence-based rules in
 * src/modules/vulnerability-collector/utils/remediation-intelligence.util.ts.
 *
 * Needed once after deploying those rules: older rows hold `patch_available = false` whenever
 * NVD simply had no "Patch"-tagged reference (e.g. SAP Security Notes).
 *
 *   ts-node scripts/backfill-remediation-intelligence.ts                 # dry run (no writes)
 *   ts-node scripts/backfill-remediation-intelligence.ts --apply
 *   ts-node scripts/backfill-remediation-intelligence.ts --cve=CVE-2025-31324 --apply
 *   Options: --from-id=N  --limit=N  --batch-size=N
 */
import { PrismaClient } from '@prisma/client';
import { ConfigService } from '@nestjs/config';
import { NvdCollector } from '../src/modules/vulnerability-collector/collectors/nvd.collector';
import { CveOrgCollector } from '../src/modules/vulnerability-collector/collectors/cveorg.collector';
import {
  mergeRemediationInfo,
  readStoredRemediation,
  RemediationInfo,
} from '../src/modules/vulnerability-collector/utils/remediation-intelligence.util';
import { toJsonString } from '../src/modules/vulnerability-collector/utils/vulnerability-intelligence.util';

const prisma = new PrismaClient();
const nvdCollector = new NvdCollector({} as any, new ConfigService());
const cveOrgCollector = new CveOrgCollector({} as any, new ConfigService());

function arg(name: string): string | undefined {
  const raw = process.argv.find((item) => item.startsWith(`--${name}=`));
  return raw ? raw.slice(name.length + 3) : undefined;
}

function contributionFromRaw(rawData: string | null): RemediationInfo | null {
  if (!rawData) return null;
  try {
    const raw = JSON.parse(rawData);
    if (raw?.cveMetadata || raw?.containers) return cveOrgCollector.parseItem(raw)?.remediationInfo ?? null;
    if (raw?.cve?.id) return nvdCollector.parseItem(raw).remediationInfo;
    if (raw?.id && (raw.references || raw.configurations)) return nvdCollector.parseItem({ cve: raw }).remediationInfo;
  } catch {
    // Unparseable payload: fall through and only upgrade what is stored.
  }
  return null;
}

async function main() {
  const apply = process.argv.includes('--apply');
  const cve = arg('cve');
  const limit = Number(arg('limit') || 0);
  const batchSize = Number(arg('batch-size') || 200);
  let lastId = Number(arg('from-id') || 0);

  console.log(`Remediation backfill (${apply ? 'APPLY' : 'dry run'})${cve ? ` for ${cve}` : ''}`);

  let scanned = 0;
  let changed = 0;
  const transitions = new Map<string, number>();

  while (true) {
    const batch = await prisma.vulnerability.findMany({
      where: cve ? { cveId: cve, id: { gt: lastId } } : { id: { gt: lastId } },
      orderBy: { id: 'asc' },
      take: batchSize,
      select: {
        id: true,
        cveId: true,
        rawData: true,
        remediationInfo: true,
        patchAvailable: true,
        fixedVersions: true,
        workarounds: true,
        affectedProductsDetailed: true,
      },
    });
    if (batch.length === 0) break;

    for (const row of batch) {
      lastId = row.id;
      scanned++;

      const stored = readStoredRemediation(row);
      const contribution = contributionFromRaw(row.rawData);
      const merged = contribution ? mergeRemediationInfo(stored, contribution) : stored;

      const remediationInfo = toJsonString(merged);
      const fixedVersions = merged.fixedVersions.length > 0 ? JSON.stringify(merged.fixedVersions) : null;
      const workarounds = merged.workarounds.length > 0 ? JSON.stringify(merged.workarounds) : row.workarounds;

      if (
        remediationInfo === row.remediationInfo &&
        merged.patchAvailable === row.patchAvailable &&
        fixedVersions === row.fixedVersions &&
        workarounds === row.workarounds
      ) {
        continue;
      }

      changed++;
      const transition = `${row.patchAvailable} -> ${merged.patchAvailable}`;
      transitions.set(transition, (transitions.get(transition) || 0) + 1);
      if (cve || changed <= 20) {
        console.log(`  ${row.cveId}: patch ${transition} (${merged.patchStatus}, ${merged.evidence.length} evidencias)`);
      }

      if (apply) {
        await prisma.vulnerability.update({
          where: { id: row.id },
          data: { remediationInfo, patchAvailable: merged.patchAvailable, fixedVersions, workarounds },
        });
      }
    }

    if (scanned % 5000 < batchSize) console.log(`  ... ${scanned} revisadas, ${changed} con cambios`);
    if (limit > 0 && scanned >= limit) break;
  }

  console.log(`\nRevisadas: ${scanned} · Con cambios: ${changed}${apply ? ' (aplicados)' : ' (dry run, usa --apply para escribir)'}`);
  for (const [transition, count] of [...transitions.entries()].sort((a, b) => b[1] - a[1])) {
    console.log(`  patch_available ${transition}: ${count}`);
  }
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
