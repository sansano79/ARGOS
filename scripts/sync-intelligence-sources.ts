#!/usr/bin/env ts-node
import mysql, { Pool, PoolConnection, RowDataPacket } from 'mysql2/promise';
import * as dotenv from 'dotenv';
import https from 'https';
dotenv.config();

interface CliArgs {
  apply: boolean;
  cisaKev: boolean;
  exploitdb: boolean;
  epssKev: boolean;
  batchSize: number;
}

function parseCliArgs(argv: string[]): CliArgs {
  const getNumericFlag = (prefix: string, fallback: number): number => {
    const raw = argv.find((arg) => arg.startsWith(`${prefix}=`));
    if (!raw) return fallback;
    const parsed = Number.parseInt(raw.slice(prefix.length + 1), 10);
    return Number.isFinite(parsed) ? parsed : fallback;
  };

  const hasCisa = argv.includes('--cisa-kev');
  const hasEdb = argv.includes('--exploitdb');
  const hasEpss = argv.includes('--epss-kev');
  const all = argv.includes('--all') || (!hasCisa && !hasEdb && !hasEpss);

  return {
    apply: argv.includes('--apply'),
    cisaKev: all || hasCisa,
    exploitdb: all || hasEdb,
    epssKev: all || hasEpss,
    batchSize: getNumericFlag('--batch-size', 200),
  };
}

function fetchHttps(url: string, timeoutMs = 60000): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'ARGOS-ThreatIntelligence/1.0' } }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return resolve(fetchHttps(res.headers.location, timeoutMs));
      }
      if (res.statusCode && res.statusCode >= 400) {
        return reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
      }
      const chunks: Buffer[] = [];
      res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    });

    req.setTimeout(timeoutMs, () => {
      req.destroy();
      reject(new Error(`Timeout (${timeoutMs}ms) fetching ${url}`));
    });

    req.on('error', reject);
  });
}

function parseCsvLine(line: string): string[] {
  const fields: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      fields.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  fields.push(current);
  return fields;
}

async function main() {
  const args = parseCliArgs(process.argv.slice(2));

  console.log('================================================================');
  console.log(' ARGOS - SINCRONIZACIÓN DE FUENTES DE INTELIGENCIA (KEV / EXPLOIT)');
  console.log('================================================================');
  console.log(`Modo:              ${args.apply ? 'APPLY (Escritura en BD)' : 'DRY-RUN (Solo Lectura, sin cambios)'}`);
  console.log(`CISA KEV:          ${args.cisaKev ? 'SÍ' : 'NO'}`);
  console.log(`ExploitDB:         ${args.exploitdb ? 'SÍ' : 'NO'}`);
  console.log(`Tamaño de lote:    ${args.batchSize}`);
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
  });

  const conn: PoolConnection = await pool.getConnection();

  try {
    // ══════════════════════════════════════════════════════════════
    // 1. CISA KEV
    // ══════════════════════════════════════════════════════════════
    if (args.cisaKev) {
      console.log('\n[1/2] Sincronizando catálogo oficial CISA KEV...');
      const kevUrl = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
      const startTime = Date.now();

      try {
        const rawJson = await fetchHttps(kevUrl, 25000);
        const parsed = JSON.parse(rawJson);
        const vulnerabilities = parsed.vulnerabilities || [];
        console.log(`✓ CISA KEV descargado: ${vulnerabilities.length.toLocaleString()} entradas en el feed oficial`);

        const kevMap = new Map<string, any>();
        for (const item of vulnerabilities) {
          if (item?.cveID) {
            kevMap.set(String(item.cveID).trim().toUpperCase(), item);
          }
        }

        const cveIds = Array.from(kevMap.keys());
        let matchedCount = 0;
        let updatedCount = 0;

        for (let i = 0; i < cveIds.length; i += args.batchSize) {
          const chunk = cveIds.slice(i, i + args.batchSize);
          const placeholders = chunk.map(() => '?').join(',');

          const [rows] = await conn.query<RowDataPacket[]>(
            `SELECT id, cve_id, is_known_exploited, exploit_status, sources_present
             FROM vulnerabilities
             WHERE cve_id IN (${placeholders})`,
            chunk,
          );

          matchedCount += rows.length;

          if (args.apply && rows.length > 0) {
            await conn.beginTransaction();
            try {
              for (const row of rows) {
                const cveId = String(row.cve_id);
                const kev = kevMap.get(cveId);
                const dateAdded = kev?.dateAdded ? new Date(kev.dateAdded) : null;
                const dueDate = kev?.dueDate ? new Date(kev.dueDate) : null;

                let sources: string[] = [];
                try {
                  sources = typeof row.sources_present === 'string'
                    ? JSON.parse(row.sources_present)
                    : (Array.isArray(row.sources_present) ? row.sources_present : []);
                } catch {
                  sources = [];
                }
                if (!sources.includes('cisa_kev')) sources.push('cisa_kev');

                // Update vulnerability row
                await conn.query(
                  `UPDATE vulnerabilities
                   SET is_known_exploited = 1,
                       kev_date_added = ?,
                       kev_due_date = ?,
                       exploit_status = 'active_exploitation',
                       sources_present = ?,
                       updated_at = NOW()
                   WHERE id = ?`,
                  [dateAdded, dueDate, JSON.stringify(sources), row.id],
                );

                // Upsert vulnerability_source_records
                const normalizedData = JSON.stringify({
                  source: 'cisa_kev',
                  cveId,
                  vendorProject: kev?.vendorProject,
                  product: kev?.product,
                  dateAdded: kev?.dateAdded,
                  dueDate: kev?.dueDate,
                  requiredAction: kev?.requiredAction,
                  knownRansomwareCampaignUse: kev?.knownRansomwareCampaignUse,
                });

                await conn.query(
                  `INSERT INTO vulnerability_source_records
                     (vulnerability_id, cve_id, source_name, source_record_id, source_url,
                      confidence, raw_payload, normalized_data, first_seen_at, last_seen_at, is_canonical)
                   VALUES (?, ?, 'cisa_kev', ?, ?, 1.0, ?, ?, NOW(), NOW(), 0)
                   ON DUPLICATE KEY UPDATE
                     normalized_data = VALUES(normalized_data),
                     last_seen_at = NOW()`,
                  [
                    row.id,
                    cveId,
                    cveId,
                    `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cveId}`,
                    JSON.stringify(kev),
                    normalizedData,
                  ],
                );

                updatedCount++;
              }
              await conn.commit();
            } catch (batchErr) {
              await conn.rollback();
              throw batchErr;
            }
          }
        }

        const durationMs = Date.now() - startTime;
        console.log(`  - Entradas KEV en feed:        ${vulnerabilities.length.toLocaleString()}`);
        console.log(`  - CVEs coincidentes en base:   ${matchedCount.toLocaleString()}`);
        console.log(`  - CVEs actualizados en BD:     ${updatedCount.toLocaleString()} (${args.apply ? 'APPLIED' : 'DRY-RUN'})`);
        console.log(`  - Duración:                    ${(durationMs / 1000).toFixed(2)}s`);

        if (args.apply) {
          await conn.query(
            `INSERT INTO collector_source_health
               (source, run_date, fetch_status, items_fetched, items_processed, items_errored, duration_ms)
             VALUES ('cisa_kev', NOW(), 'success', ?, ?, 0, ?)`,
            [vulnerabilities.length, matchedCount, durationMs],
          );
        }
      } catch (err: any) {
        console.error(`✕ Error al sincronizar CISA KEV: ${err.message}`);
        if (args.apply) {
          await conn.query(
            `INSERT INTO collector_source_health
               (source, run_date, fetch_status, items_fetched, items_processed, items_errored, duration_ms, error_message)
             VALUES ('cisa_kev', NOW(), 'error', 0, 0, 1, 0, ?)`,
            [err.message],
          );
        }
      }
    }

    // ══════════════════════════════════════════════════════════════
    // 2. EXPLOITDB
    // ══════════════════════════════════════════════════════════════
    if (args.exploitdb) {
      console.log('\n[2/2] Sincronizando catálogo oficial ExploitDB...');
      const edbUrl = process.env.EXPLOITDB_CSV_URL || 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv';
      const startTime = Date.now();

      try {
        const rawCsv = await fetchHttps(edbUrl, 60000);
        const lines = rawCsv.split('\n');
        console.log(`✓ ExploitDB CSV descargado: ${lines.length.toLocaleString()} líneas`);

        const edbMap = new Map<string, any[]>();
        let totalExploitsWithCve = 0;

        for (let i = 1; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line) continue;

          try {
            const fields = parseCsvLine(line);
            if (fields.length < 12) continue;

            const id = fields[0]?.trim();
            const description = fields[2]?.trim() || '';
            const datePublished = fields[3]?.trim() || '';
            const author = fields[4]?.trim() || '';
            const platform = fields[5]?.trim() || '';
            const type = fields[6]?.trim() || '';
            const codes = fields[11]?.trim() || '';

            if (!id || !codes) continue;

            const cveIds = codes
              .split(';')
              .map((c) => c.trim().toUpperCase())
              .filter((c) => c.startsWith('CVE-'));

            if (cveIds.length === 0) continue;
            totalExploitsWithCve++;

            const entry = {
              source: 'exploitdb',
              id,
              url: `https://www.exploit-db.com/exploits/${id}`,
              description,
              platform,
              type,
              author,
              datePublished,
            };

            for (const cveId of cveIds) {
              const existing = edbMap.get(cveId) || [];
              existing.push(entry);
              edbMap.set(cveId, existing);
            }
          } catch {
            // Skip malformed line
          }
        }

        console.log(`✓ ExploitDB indexado: ${edbMap.size.toLocaleString()} CVEs únicos con exploit (${totalExploitsWithCve.toLocaleString()} exploits vinculados)`);

        const cveIds = Array.from(edbMap.keys());
        let matchedCount = 0;
        let updatedCount = 0;

        for (let i = 0; i < cveIds.length; i += args.batchSize) {
          const chunk = cveIds.slice(i, i + args.batchSize);
          const placeholders = chunk.map(() => '?').join(',');

          const [rows] = await conn.query<RowDataPacket[]>(
            `SELECT id, cve_id, has_public_exploit, exploit_status, sources_present, exploit_references
             FROM vulnerabilities
             WHERE cve_id IN (${placeholders})`,
            chunk,
          );

          matchedCount += rows.length;

          if (args.apply && rows.length > 0) {
            await conn.beginTransaction();
            try {
              for (const row of rows) {
                const cveId = String(row.cve_id);
                const edbEntries = edbMap.get(cveId) || [];

                let sources: string[] = [];
                try {
                  sources = typeof row.sources_present === 'string'
                    ? JSON.parse(row.sources_present)
                    : (Array.isArray(row.sources_present) ? row.sources_present : []);
                } catch {
                  sources = [];
                }
                if (!sources.includes('exploitdb')) sources.push('exploitdb');

                const newStatus = row.exploit_status === 'active_exploitation' ? 'active_exploitation' : 'poc';

                await conn.query(
                  `UPDATE vulnerabilities
                   SET has_public_exploit = 1,
                       exploit_status = ?,
                       exploit_references = ?,
                       sources_present = ?,
                       updated_at = NOW()
                   WHERE id = ?`,
                  [newStatus, JSON.stringify(edbEntries), JSON.stringify(sources), row.id],
                );

                const normalizedData = JSON.stringify({
                  source: 'exploitdb',
                  cveId,
                  exploitsCount: edbEntries.length,
                  exploits: edbEntries,
                });

                await conn.query(
                  `INSERT INTO vulnerability_source_records
                     (vulnerability_id, cve_id, source_name, source_record_id, source_url,
                      confidence, raw_payload, normalized_data, first_seen_at, last_seen_at, is_canonical)
                   VALUES (?, ?, 'exploitdb', ?, ?, 1.0, ?, ?, NOW(), NOW(), 0)
                   ON DUPLICATE KEY UPDATE
                     normalized_data = VALUES(normalized_data),
                     last_seen_at = NOW()`,
                  [
                    row.id,
                    cveId,
                    cveId,
                    `https://www.exploit-db.com/search?cve=${cveId.replace('CVE-', '')}`,
                    JSON.stringify(edbEntries),
                    normalizedData,
                  ],
                );

                updatedCount++;
              }
              await conn.commit();
            } catch (batchErr) {
              await conn.rollback();
              throw batchErr;
            }
          }
        }

        const durationMs = Date.now() - startTime;
        console.log(`  - CVEs en catálogo ExploitDB:  ${edbMap.size.toLocaleString()}`);
        console.log(`  - CVEs coincidentes en base:   ${matchedCount.toLocaleString()}`);
        console.log(`  - CVEs actualizados en BD:     ${updatedCount.toLocaleString()} (${args.apply ? 'APPLIED' : 'DRY-RUN'})`);
        console.log(`  - Duración:                    ${(durationMs / 1000).toFixed(2)}s`);

        if (args.apply) {
          await conn.query(
            `INSERT INTO collector_source_health
               (source, run_date, fetch_status, items_fetched, items_processed, items_errored, duration_ms)
             VALUES ('exploitdb', NOW(), 'success', ?, ?, 0, ?)`,
            [edbMap.size, matchedCount, durationMs],
          );
        }
      } catch (err: any) {
        console.error(`✕ Error al sincronizar ExploitDB: ${err.message}`);
        if (args.apply) {
          await conn.query(
            `INSERT INTO collector_source_health
               (source, run_date, fetch_status, items_fetched, items_processed, items_errored, duration_ms, error_message)
             VALUES ('exploitdb', NOW(), 'error', 0, 0, 1, 0, ?)`,
            [err.message],
          );
        }
      }
    }

    // ══════════════════════════════════════════════════════════════
    // 3. EPSS (para CVEs KEV)
    // ══════════════════════════════════════════════════════════════
    if (args.epssKev) {
      console.log('\n[3/3] Sincronizando EPSS para CVEs KEV...');
      const [kevRows] = await conn.query<RowDataPacket[]>(
        `SELECT id, cve_id FROM vulnerabilities WHERE is_known_exploited = 1 AND epss_score IS NULL`,
      );
      console.log(`✓ Encontrados ${kevRows.length.toLocaleString()} CVEs KEV sin puntaje EPSS`);

      if (kevRows.length > 0) {
        const cveIds = kevRows.map((r) => String(r.cve_id));
        const epssBatchSize = 30;
        let epssUpdated = 0;
        const epssStart = Date.now();

        for (let i = 0; i < cveIds.length; i += epssBatchSize) {
          const chunk = cveIds.slice(i, i + epssBatchSize);
          try {
            const url = `https://api.first.org/data/v1/epss?cve=${chunk.join(',')}`;
            const resText = await fetchHttps(url, 15000);
            const resJson = JSON.parse(resText);
            const epssItems = resJson.data || [];

            if (args.apply && epssItems.length > 0) {
              await conn.beginTransaction();
              for (const item of epssItems) {
                const score = parseFloat(item.epss);
                const percentile = parseFloat(item.percentile);
                if (Number.isFinite(score)) {
                  await conn.query(
                    `UPDATE vulnerabilities SET epss_score = ?, epss_percentile = ?, updated_at = NOW() WHERE cve_id = ?`,
                    [score, percentile, item.cve],
                  );
                  epssUpdated++;
                }
              }
              await conn.commit();
            } else if (!args.apply) {
              epssUpdated += epssItems.length;
            }
            await new Promise((r) => setTimeout(r, 200));
          } catch (e: any) {
            console.warn(`Aviso en lote EPSS: ${e.message}`);
          }
        }
        console.log(`✓ EPSS sincronizado para ${epssUpdated.toLocaleString()} CVEs KEV (${((Date.now() - epssStart) / 1000).toFixed(1)}s)`);
      }
    }

    console.log('\n================================================================');
    console.log(' SINCRONIZACIÓN FINALIZADA');
    console.log('================================================================\n');
  } finally {
    conn.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error('[FATAL]', err);
  process.exit(1);
});
