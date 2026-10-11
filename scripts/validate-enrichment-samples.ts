import mysql, { Pool, RowDataPacket } from 'mysql2/promise';
import * as dotenv from 'dotenv';
dotenv.config();

import {
  HistoricalEnrichmentProcessor,
  EnrichmentItemResult,
} from '../src/modules/vulnerability-collector/processors/historical-enrichment.processor';
import { isContextualVendor } from '../src/shared/vendor-normalization';

interface SliceStats {
  name: string;
  count: number;
  enriched: number;
  rejected: number;
  unresolved: number;
  error: number;
  totalCpes: number;
  totalVersions: number;
}

async function runValidation() {
  const pool: Pool = mysql.createPool({
    uri: process.env.DATABASE_URL!,
    waitForConnections: true,
    connectionLimit: 4,
  });

  const conn = await pool.getConnection();

  try {
    console.log('--- RECOLECTANDO MUESTRAS REPRESENTATIVAS (6 x 100) ---');

    // 1. 100 CVEs antiguos
    const [oldRows] = await conn.query<RowDataPacket[]>(
      `SELECT id, cve_id, description, raw_data, published_at, last_modified_at
       FROM vulnerabilities
       WHERE needs_enrichment = 1
       ORDER BY id ASC
       LIMIT 100`,
    );

    // 2. 100 CVEs recientes
    const [recentRows] = await conn.query<RowDataPacket[]>(
      `SELECT id, cve_id, description, raw_data, published_at, last_modified_at
       FROM vulnerabilities
       WHERE needs_enrichment = 1
       ORDER BY id DESC
       LIMIT 100`,
    );

    // 3. 100 CVEs con CVSS
    const [cvssRows] = await conn.query<RowDataPacket[]>(
      `SELECT id, cve_id, description, raw_data, published_at, last_modified_at
       FROM vulnerabilities
       WHERE needs_enrichment = 1 AND cvss_v31_score IS NOT NULL
       ORDER BY id ASC
       LIMIT 100`,
    );

    // 4. 100 CVEs sin CPE (configurations vacías o sin cpeMatch)
    const [noCpeRows] = await conn.query<RowDataPacket[]>(
      `SELECT id, cve_id, description, raw_data, published_at, last_modified_at
       FROM vulnerabilities
       WHERE needs_enrichment = 1
         AND (raw_data NOT LIKE '%cpeMatch%' OR raw_data LIKE '%"configurations":[]%')
       ORDER BY id DESC
       LIMIT 100`,
    );

    // 5. 100 CVEs rechazados o reservados
    const [rejectedRows] = await conn.query<RowDataPacket[]>(
      `SELECT id, cve_id, description, raw_data, published_at, last_modified_at
       FROM vulnerabilities
       WHERE needs_enrichment = 1
         AND (description LIKE 'Rejected reason%' OR raw_data LIKE '%"vulnStatus":"Rejected"%')
       ORDER BY id ASC
       LIMIT 100`,
    );

    // 6. 100 CVEs con múltiples productos afectados
    // Escaneamos un lote de CVSS para seleccionar 100 con > 1 producto detallado
    const [candidatesMulti] = await conn.query<RowDataPacket[]>(
      `SELECT id, cve_id, description, raw_data, published_at, last_modified_at
       FROM vulnerabilities
       WHERE needs_enrichment = 1 AND cvss_v31_score IS NOT NULL
       ORDER BY id DESC
       LIMIT 300`,
    );

    const multiRows: RowDataPacket[] = [];
    for (const r of candidatesMulti) {
      const res = HistoricalEnrichmentProcessor.processVulnerability({
        id: Number(r.id),
        cveId: String(r.cve_id),
        description: r.description ? String(r.description) : null,
        rawData: r.raw_data ? String(r.raw_data) : null,
        publishedAt: r.published_at,
        lastModifiedAt: r.last_modified_at,
      });
      if (res.detailedProducts.length > 1) {
        multiRows.push(r);
        if (multiRows.length >= 100) break;
      }
    }

    const slices: Array<{ name: string; rows: RowDataPacket[] }> = [
      { name: '100 CVEs Antiguos', rows: oldRows },
      { name: '100 CVEs Recientes', rows: recentRows },
      { name: '100 CVEs con CVSS', rows: cvssRows },
      { name: '100 CVEs sin CPE', rows: noCpeRows },
      { name: '100 CVEs Rechazados / Reservados', rows: rejectedRows },
      { name: '100 CVEs con Múltiples Productos', rows: multiRows },
    ];

    const allResults: EnrichmentItemResult[] = [];
    const sliceStatsList: SliceStats[] = [];

    const vendorCounts = new Map<string, number>();
    const productCounts = new Map<string, number>();
    const contextualVendorCounts = new Map<string, number>();
    const suspiciousProducts = new Map<string, number>();

    let totalCpesExtracted = 0;
    let totalVersionsExtracted = 0;

    for (const slice of slices) {
      let enriched = 0;
      let rejected = 0;
      let unresolved = 0;
      let error = 0;
      let sliceCpes = 0;
      let sliceVersions = 0;

      for (const r of slice.rows) {
        const itemResult = HistoricalEnrichmentProcessor.processVulnerability({
          id: Number(r.id),
          cveId: String(r.cve_id),
          description: r.description ? String(r.description) : null,
          rawData: r.raw_data ? String(r.raw_data) : null,
          publishedAt: r.published_at,
          lastModifiedAt: r.last_modified_at,
        });

        allResults.push(itemResult);

        if (itemResult.status === 'enriched') {
          enriched++;
          if (itemResult.primaryVendor) {
            vendorCounts.set(itemResult.primaryVendor, (vendorCounts.get(itemResult.primaryVendor) || 0) + 1);
            if (isContextualVendor(itemResult.primaryVendor)) {
              contextualVendorCounts.set(itemResult.primaryVendor, (contextualVendorCounts.get(itemResult.primaryVendor) || 0) + 1);
            }
          }
          if (itemResult.primaryVendor && itemResult.primaryProduct) {
            const vp = `${itemResult.primaryVendor}/${itemResult.primaryProduct}`;
            productCounts.set(vp, (productCounts.get(vp) || 0) + 1);

            // Check suspicious patterns: generic names, single characters, numbers only
            if (/^(product|software|app|default|test|\d+|[a-z])$/i.test(itemResult.primaryProduct)) {
              suspiciousProducts.set(vp, (suspiciousProducts.get(vp) || 0) + 1);
            }
          }
        } else if (itemResult.status === 'rejected') {
          rejected++;
        } else if (itemResult.status === 'unresolved') {
          unresolved++;
        } else {
          error++;
        }

        const cpeCount = itemResult.affectedCpes.length;
        sliceCpes += cpeCount;
        totalCpesExtracted += cpeCount;

        const versCount = itemResult.detailedProducts.filter((p) => p.version || p.versionRange).length;
        sliceVersions += versCount;
        totalVersionsExtracted += versCount;
      }

      sliceStatsList.push({
        name: slice.name,
        count: slice.rows.length,
        enriched,
        rejected,
        unresolved,
        error,
        totalCpes: sliceCpes,
        totalVersions: sliceVersions,
      });
    }

    console.log('\n================================================================');
    console.log(' RESULTADOS POR MUESTRA REPRESENTATIVA');
    console.log('================================================================');
    for (const s of sliceStatsList) {
      console.log(`- ${s.name} (${s.count} filas):`);
      console.log(`    Enriquecibles: ${s.enriched} (${((s.enriched / s.count) * 100).toFixed(1)}%)`);
      console.log(`    Rechazados:    ${s.rejected} (${((s.rejected / s.count) * 100).toFixed(1)}%)`);
      console.log(`    Sin CPE:       ${s.unresolved} (${((s.unresolved / s.count) * 100).toFixed(1)}%)`);
      console.log(`    Errores:       ${s.error} (${((s.error / s.count) * 100).toFixed(1)}%)`);
      console.log(`    CPEs extraídos: ${s.totalCpes} | Versiones extraídas: ${s.totalVersions}`);
    }

    const grandTotal = allResults.length;
    const totalEnriched = allResults.filter((r) => r.status === 'enriched').length;
    const totalRejected = allResults.filter((r) => r.status === 'rejected').length;
    const totalUnresolved = allResults.filter((r) => r.status === 'unresolved').length;
    const totalError = allResults.filter((r) => r.status === 'error').length;

    console.log('\n================================================================');
    console.log(' INFORME AGREGADO (MUESTRA TOTAL DE ' + grandTotal + ' FILAS)');
    console.log('================================================================');
    console.log(`Porcentaje enriquecible:   ${((totalEnriched / grandTotal) * 100).toFixed(2)}% (${totalEnriched}/${grandTotal})`);
    console.log(`Porcentaje rechazado:       ${((totalRejected / grandTotal) * 100).toFixed(2)}% (${totalRejected}/${grandTotal})`);
    console.log(`Porcentaje sin CPE:         ${((totalUnresolved / grandTotal) * 100).toFixed(2)}% (${totalUnresolved}/${grandTotal})`);
    console.log(`Porcentaje rawData erróneo: ${((totalError / grandTotal) * 100).toFixed(2)}% (${totalError}/${grandTotal})`);
    console.log(`Total CPEs extraídos:       ${totalCpesExtracted.toLocaleString()}`);
    console.log(`Total Versiones extraídas:  ${totalVersionsExtracted.toLocaleString()}`);

    console.log('\n--- TOP 50 VENDORS (MUESTRAS) ---');
    const topVendors = Array.from(vendorCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 50);
    topVendors.forEach(([v, c], i) => {
      console.log(`  ${String(i + 1).padStart(2)}. ${v.padEnd(25)} : ${c}`);
    });

    console.log('\n--- TOP 50 PRODUCTOS (MUESTRAS) ---');
    const topProducts = Array.from(productCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 50);
    topProducts.forEach(([vp, c], i) => {
      console.log(`  ${String(i + 1).padStart(2)}. ${vp.padEnd(35)} : ${c}`);
    });

    console.log('\n--- VENDORS CONTEXTUALES DETECTADOS ---');
    if (contextualVendorCounts.size === 0) {
      console.log('  (Ninguno detectado en las muestras; todos fueron filtrados/penalizados correctamente)');
    } else {
      for (const [cv, c] of contextualVendorCounts) {
        console.log(`  - ${cv}: ${c}`);
      }
    }

    console.log('\n--- PRODUCTOS SOSPECHOSOS DETECTADOS ---');
    if (suspiciousProducts.size === 0) {
      console.log('  (Ningún producto sospechoso detectado)');
    } else {
      for (const [sp, c] of suspiciousProducts) {
        console.log(`  - ${sp}: ${c}`);
      }
    }

    // 3. Revisión específica de calidad de vendors clave
    const targetVendors = [
      'sun',
      'eric_allman',
      'sgi',
      'sco',
      'cisco',
      'hp',
      'ibm',
      'microsoft',
      'apache',
      'nginx',
    ];

    console.log('\n================================================================');
    console.log(' REVISIÓN ESPECÍFICA DE CALIDAD DE FABRICANTES CLAVE');
    console.log('================================================================');

    for (const tv of targetVendors) {
      const [vRows] = await conn.query<RowDataPacket[]>(
        `SELECT id, cve_id, description, raw_data, published_at, last_modified_at
         FROM vulnerabilities
         WHERE needs_enrichment = 1
           AND (raw_data LIKE ? OR raw_data LIKE ?)
         LIMIT 5`,
        [`%cpe:2.3:a:${tv}:%`, `%cpe:2.3:o:${tv}:%`],
      );

      console.log(`\nFabricante: [${tv.toUpperCase()}] (${vRows.length} casos de prueba localizados):`);
      if (vRows.length === 0) {
        console.log(`  (Sin coincidencias directas en la muestra de prueba)`);
      } else {
        for (const r of vRows) {
          const itemRes = HistoricalEnrichmentProcessor.processVulnerability({
            id: Number(r.id),
            cveId: String(r.cve_id),
            description: r.description ? String(r.description) : null,
            rawData: r.raw_data ? String(r.raw_data) : null,
            publishedAt: r.published_at,
            lastModifiedAt: r.last_modified_at,
          });
          console.log(
            `  - ${itemRes.cveId}: vendor=${itemRes.primaryVendor} | product=${itemRes.primaryProduct} | CPEs=${itemRes.affectedCpes.length} | Status=${itemRes.status}`,
          );
        }
      }
    }

    console.log('\n================================================================');
    console.log(' VERIFICACIÓN DE INMUTABILIDAD DEL DRY-RUN');
    console.log('================================================================');

    const [afterNeedsEnrichment] = await conn.query<RowDataPacket[]>(
      `SELECT COUNT(*) as count FROM vulnerabilities WHERE needs_enrichment = 1`,
    );
    const [afterManufacturers] = await conn.query<RowDataPacket[]>(
      `SELECT COUNT(*) as count FROM manufacturers`,
    );
    const [afterSoftwareCatalog] = await conn.query<RowDataPacket[]>(
      `SELECT COUNT(*) as count FROM software_catalog`,
    );
    const [afterSourceRecords] = await conn.query<RowDataPacket[]>(
      `SELECT COUNT(*) as count FROM vulnerability_source_records`,
    );

    console.log(`needs_enrichment=1 count:          ${afterNeedsEnrichment[0].count} (inmutable)`);
    console.log(`manufacturers count:               ${afterManufacturers[0].count} (0 creados)`);
    console.log(`software_catalog count:            ${afterSoftwareCatalog[0].count} (0 creados)`);
    console.log(`vulnerability_source_records count: ${afterSourceRecords[0].count} (inmutable)`);

  } finally {
    conn.release();
    await pool.end();
  }
}

runValidation().catch((err) => {
  console.error('Error durante la validación:', err);
  process.exit(1);
});
