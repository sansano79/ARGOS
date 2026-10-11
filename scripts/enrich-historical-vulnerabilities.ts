#!/usr/bin/env ts-node
import mysql, { Pool, PoolConnection, RowDataPacket } from 'mysql2/promise';
import * as dotenv from 'dotenv';
dotenv.config();

import {
  HistoricalEnrichmentProcessor,
  EnrichmentItemResult,
} from '../src/modules/vulnerability-collector/processors/historical-enrichment.processor';

interface CliArgs {
  apply: boolean;
  batchSize: number;
  limit: number | null;
  fromId: number;
  sampleLogLimit: number;
  catalogPreview: boolean;
}

function parseCliArgs(argv: string[]): CliArgs {
  const getNumericFlag = (prefix: string, fallback: number | null): number | null => {
    const raw = argv.find((arg) => arg.startsWith(`${prefix}=`));
    if (!raw) return fallback;
    const parsed = Number.parseInt(raw.slice(prefix.length + 1), 10);
    return Number.isFinite(parsed) ? parsed : fallback;
  };

  return {
    apply: argv.includes('--apply'),
    batchSize: getNumericFlag('--batch-size', 100) || 100,
    limit: getNumericFlag('--limit', null),
    fromId: getNumericFlag('--from-id', 0) || 0,
    sampleLogLimit: getNumericFlag('--sample-log-limit', 25) || 25,
    catalogPreview: argv.includes('--catalog-preview') || !argv.includes('--apply'),
  };
}

async function main() {
  const args = parseCliArgs(process.argv.slice(2));

  console.log('================================================================');
  console.log(' ARGOS - ENRIQUECIMIENTO HISTÓRICO SEGURO DE VULNERABILIDADES NVD');
  console.log('================================================================');
  console.log(`Modo:              ${args.apply ? 'APPLY (Escritura en BD)' : 'DRY-RUN (Solo Lectura, sin cambios)'}`);
  console.log(`Tamaño de lote:    ${args.batchSize}`);
  console.log(`Límite total:      ${args.limit != null ? args.limit : 'Sin límite (todos los candidatos)'}`);
  console.log(`Desde ID:          ${args.fromId}`);
  console.log(`Muestra en log:    ${args.sampleLogLimit}`);
  console.log('----------------------------------------------------------------');

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error('ERROR: DATABASE_URL no está definida en las variables de entorno.');
    process.exit(1);
  }

  const pool: Pool = mysql.createPool({
    uri: databaseUrl,
    waitForConnections: true,
    connectionLimit: 4,
    queueLimit: 0,
  });

  // Handle graceful interruption (SIGINT / SIGTERM)
  let isStopping = false;
  let lastCommittedId = args.fromId;

  process.on('SIGINT', () => {
    console.log('\n[AVISO] Señal de interrupción recibida (Ctrl+C). Finalizando lote en curso...');
    isStopping = true;
  });

  process.on('SIGTERM', () => {
    console.log('\n[AVISO] Señal SIGTERM recibida. Finalizando lote en curso...');
    isStopping = true;
  });

  const conn: PoolConnection = await pool.getConnection();

  try {
    // 1. Contar candidatos globales
    const [candidateCountRows] = await conn.query<RowDataPacket[]>(
      `SELECT COUNT(*) AS total
       FROM vulnerabilities
       WHERE needs_enrichment = 1 AND processing_status = 'new'`,
    );
    const totalCandidates = Number(candidateCountRows[0]?.total || 0);
    console.log(`Total de filas candidatas en base de datos (needs_enrichment=1, status='new'): ${totalCandidates.toLocaleString()}`);

    if (totalCandidates === 0) {
      console.log('No existen vulnerabilidades pendientes de enriquecimiento.');
      return;
    }

    // Use fromId - 1 so that --from-id=X starts at ID X inclusive
    let cursorId = args.fromId > 0 ? args.fromId - 1 : 0;
    let totalProcessed = 0;
    let totalEnriched = 0;
    let totalRejected = 0;
    let totalUnresolved = 0;
    let totalError = 0;
    let loggedSamplesCount = 0;
    let batchCount = 0;

    const vendorStats = new Map<string, number>();
    const productStats = new Map<string, number>();

    const startTime = Date.now();

    while (!isStopping) {
      const remainingLimit = args.limit != null ? Math.max(args.limit - totalProcessed, 0) : args.batchSize;
      if (args.limit != null && remainingLimit === 0) {
        console.log(`Límite configurado (--limit=${args.limit}) alcanzado.`);
        break;
      }

      const takeCount = Math.min(args.batchSize, remainingLimit);

      // Fetch batch of candidate rows
      const [rows] = await conn.query<RowDataPacket[]>(
        `SELECT id, cve_id, description, raw_data, published_at, last_modified_at, first_seen_at
         FROM vulnerabilities
         WHERE id > ?
           AND needs_enrichment = 1
           AND processing_status = 'new'
         ORDER BY id ASC
         LIMIT ?`,
        [cursorId, takeCount],
      );

      if (rows.length === 0) {
        console.log('No quedan más filas candidatas que cumplan el criterio.');
        break;
      }

      const batchResults: EnrichmentItemResult[] = [];

      for (const row of rows) {
        const itemResult = HistoricalEnrichmentProcessor.processVulnerability({
          id: Number(row.id),
          cveId: String(row.cve_id),
          description: row.description ? String(row.description) : null,
          rawData: row.raw_data ? String(row.raw_data) : null,
          publishedAt: row.published_at ? new Date(row.published_at) : null,
          lastModifiedAt: row.last_modified_at ? new Date(row.last_modified_at) : null,
          firstSeenAt: row.first_seen_at ? new Date(row.first_seen_at) : null,
        });

        batchResults.push(itemResult);
        cursorId = Number(row.id);

        if (itemResult.status === 'enriched') {
          totalEnriched++;
          if (itemResult.primaryVendor) {
            vendorStats.set(itemResult.primaryVendor, (vendorStats.get(itemResult.primaryVendor) || 0) + 1);
          }
          if (itemResult.primaryVendor && itemResult.primaryProduct) {
            const vpKey = `${itemResult.primaryVendor}/${itemResult.primaryProduct}`;
            productStats.set(vpKey, (productStats.get(vpKey) || 0) + 1);
          }
        } else if (itemResult.status === 'rejected') {
          totalRejected++;
        } else if (itemResult.status === 'unresolved') {
          totalUnresolved++;
        } else {
          totalError++;
        }

        // Print sample to stdout
        if (loggedSamplesCount < args.sampleLogLimit) {
          const detail = itemResult.status === 'enriched'
            ? `vendor=${itemResult.primaryVendor} | product=${itemResult.primaryProduct} | cpes=${itemResult.affectedCpes.length}`
            : `motivo=${itemResult.reason}${itemResult.errorMessage ? ` (${itemResult.errorMessage})` : ''}`;

          console.log(`  [Muestra ${loggedSamplesCount + 1}] ${itemResult.cveId} (ID: ${itemResult.vulnerabilityId}) -> ${itemResult.status.toUpperCase()} | ${detail}`);
          loggedSamplesCount++;
        }
      }

      totalProcessed += batchResults.length;

      // In APPLY mode, persist with database transaction
      if (args.apply) {
        await conn.beginTransaction();
        try {
          await HistoricalEnrichmentProcessor.applyBatch(conn, batchResults);
          await conn.commit();
          lastCommittedId = cursorId;
        } catch (batchErr: any) {
          await conn.rollback();
          console.error(`\n[ERROR CRÍTICO] Error al persistir el lote (IDs ${rows[0].id}..${cursorId}): ${batchErr.message}`);
          console.error(`Transacción revertida. Último ID confirmado: ${lastCommittedId}`);
          throw batchErr;
        }
      }

      batchCount++;
      const elapsedSec = ((Date.now() - startTime) / 1000).toFixed(1);
      const rate = totalProcessed > 0 ? (totalProcessed / Math.max(Number(elapsedSec), 0.1)).toFixed(0) : '0';

      console.log(
        `[Lote ${batchCount}] Procesadas: ${totalProcessed.toLocaleString()} | Enriquecidas: ${totalEnriched.toLocaleString()} | Rechazadas: ${totalRejected.toLocaleString()} | Errores: ${totalError} | Último ID confirmado: ${lastCommittedId} | Velocidad: ${rate} filas/s | Tiempo: ${elapsedSec}s`,
      );
    }

    console.log('\n\n----------------------------------------------------------------');
    console.log(' RESUMEN DE EJECUCIÓN');
    console.log('----------------------------------------------------------------');
    console.log(`Modo:                       ${args.apply ? 'APPLY (Cambios confirmados)' : 'DRY-RUN (Sin mutaciones en BD)'}`);
    console.log(`Filas analizadas:           ${totalProcessed.toLocaleString()}`);
    console.log(`Enriquecidas con éxito:     ${totalEnriched.toLocaleString()} (${((totalEnriched / Math.max(totalProcessed, 1)) * 100).toFixed(1)}%)`);
    console.log(`CVEs Rechazados (MITRE):    ${totalRejected.toLocaleString()} (${((totalRejected / Math.max(totalProcessed, 1)) * 100).toFixed(1)}%)`);
    console.log(`Sin CPE/Producto resuelto:  ${totalUnresolved.toLocaleString()} (${((totalUnresolved / Math.max(totalProcessed, 1)) * 100).toFixed(1)}%)`);
    console.log(`Errores (rawData inválido): ${totalError.toLocaleString()} (${((totalError / Math.max(totalProcessed, 1)) * 100).toFixed(1)}%)`);
    console.log(`Último ID procesado:        ${cursorId}`);

    if (args.apply) {
      console.log(`Último ID confirmado en BD: ${lastCommittedId}`);
      if (isStopping) {
        console.log(`\nPara reanudar la ejecución use:`);
        console.log(`  npx ts-node scripts/enrich-historical-vulnerabilities.ts --apply --from-id=${lastCommittedId}`);
      }
    }

    if (args.catalogPreview && vendorStats.size > 0) {
      console.log('\n----------------------------------------------------------------');
      console.log(' TOP FABRICANTES IDENTIFICADOS EN LA MUESTRA:');
      console.log('----------------------------------------------------------------');
      const topVendors = Array.from(vendorStats.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 15);
      for (const [v, c] of topVendors) {
        console.log(`  - ${v.padEnd(25)} : ${c} CVEs`);
      }

      console.log('\n TOP PRODUCTOS IDENTIFICADOS EN LA MUESTRA:');
      console.log('----------------------------------------------------------------');
      const topProducts = Array.from(productStats.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 15);
      for (const [vp, c] of topProducts) {
        console.log(`  - ${vp.padEnd(35)} : ${c} CVEs`);
      }
    }

    console.log('================================================================\n');
  } finally {
    conn.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error('\nFallo fatal durante la ejecución:', err);
  process.exit(1);
});
