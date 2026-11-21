import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../../prisma/prisma.service';
import { DefenderClient } from './defender.client';
import { DefenderConfigService } from './defender-config.service';
import {
  dedupeFindings,
  enrichmentUpdate,
  findingKey,
  machineToSystemData,
  normalizeMachineVulnerability,
  reduceChanges,
  selectActiveServers,
} from './defender-sync.logic';
import { DEFENDER_SOURCE, NormalizedFinding, ResolvedDefenderConfig, SyncMode } from './defender.types';

/** Microsoft conserva deltas 14 días; se deja un día de margen. */
const MAX_DELTA_AGE_MS = 13 * 24 * 3600 * 1000;
const STALE_RUN_MS = 4 * 3600 * 1000;
const MAX_FAILURES_STORED = 200;

interface RunCounters {
  devicesSeen: number;
  devicesUpserted: number;
  devicesDeactivated: number;
  devicesFailed: number;
  findingsUpserted: number;
  findingsFixed: number;
  unknownCves: Set<string>;
  failures: Array<{ deviceId?: string; device?: string; error: string }>;
}

const newCounters = (): RunCounters => ({
  devicesSeen: 0,
  devicesUpserted: 0,
  devicesDeactivated: 0,
  devicesFailed: 0,
  findingsUpserted: 0,
  findingsFixed: 0,
  unknownCves: new Set(),
  failures: [],
});

const errorText = (error: unknown) => String((error as any)?.message || error || 'error desconocido').slice(0, 500);

@Injectable()
export class DefenderSyncService {
  private readonly logger = new Logger(DefenderSyncService.name);
  private processing = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly client: DefenderClient,
    private readonly config: DefenderConfigService,
  ) {}

  // ── Cola ──────────────────────────────────────────────────────

  /** Encola una sincronización. Si ya hay una pendiente o en curso, devuelve esa. */
  async requestSync(mode: SyncMode, triggeredBy?: number | null) {
    if (mode !== 'full' && mode !== 'delta') throw new BadRequestException('mode debe ser full o delta');
    const cfg = await this.config.getResolved();
    const errors = this.config.readinessErrors(cfg);
    if (errors.length) throw new BadRequestException(errors);

    const pending = await this.prisma.defenderSyncRun.findFirst({
      where: { status: { in: ['queued', 'running'] } },
      orderBy: { createdAt: 'desc' },
    });
    if (pending) return { run: pending, alreadyPending: true };

    const run = await this.prisma.defenderSyncRun.create({
      data: { mode, status: 'queued', triggeredBy: triggeredBy ?? null },
    });
    void this.processQueue();
    return { run, alreadyPending: false };
  }

  @Cron(CronExpression.EVERY_MINUTE, { name: 'defender-sync-queue' })
  async processQueue() {
    if (this.processing) return;
    this.processing = true;
    try {
      await this.failStaleRuns();
      for (;;) {
        const next = await this.prisma.defenderSyncRun.findFirst({
          where: { status: 'queued' },
          orderBy: { createdAt: 'asc' },
        });
        if (!next) break;
        // Toma atómica: solo una instancia pasa el run a "running".
        const claimed = await this.prisma.defenderSyncRun.updateMany({
          where: { id: next.id, status: 'queued' },
          data: { status: 'running', startedAt: new Date() },
        });
        if (claimed.count === 1) await this.executeRun(next.id, next.mode as SyncMode);
      }
    } catch (error) {
      this.logger.error(`Error procesando la cola de Defender: ${errorText(error)}`);
    } finally {
      this.processing = false;
    }
  }

  private async failStaleRuns() {
    await this.prisma.defenderSyncRun.updateMany({
      where: { status: 'running', startedAt: { lt: new Date(Date.now() - STALE_RUN_MS) } },
      data: { status: 'error', finishedAt: new Date(), errorMessage: 'Ejecución abandonada (proceso reiniciado o bloqueado)' },
    });
  }

  /** Programa syncs automáticos según los intervalos configurados. */
  @Cron(CronExpression.EVERY_10_MINUTES, { name: 'defender-sync-scheduler' })
  async scheduleAutomaticSync() {
    try {
      const cfg = await this.config.getResolved();
      if (!cfg.autoSyncEnabled || this.config.readinessErrors(cfg).length) return;
      const mode = await this.dueMode(cfg);
      if (mode) await this.requestSync(mode, null);
    } catch (error) {
      this.logger.warn(`No se pudo programar el sync de Defender: ${errorText(error)}`);
    }
  }

  async dueMode(cfg: ResolvedDefenderConfig, now = Date.now()): Promise<SyncMode | null> {
    const ok = { status: { in: ['success', 'partial'] } };
    const [lastFull, lastAny] = await Promise.all([
      this.prisma.defenderSyncRun.findFirst({ where: { ...ok, mode: 'full' }, orderBy: { startedAt: 'desc' } }),
      this.prisma.defenderSyncRun.findFirst({ where: ok, orderBy: { startedAt: 'desc' } }),
    ]);
    const age = (d?: Date | null) => (d ? now - d.getTime() : Infinity);
    if (age(lastFull?.startedAt) >= cfg.fullSyncIntervalHours * 3600_000) return 'full';
    if (age(lastAny?.startedAt) >= cfg.deltaSyncIntervalHours * 3600_000) return 'delta';
    return null;
  }

  // ── Ejecución ─────────────────────────────────────────────────

  private async executeRun(runId: number, requestedMode: SyncMode) {
    const started = Date.now();
    const counters = newCounters();
    let mode = requestedMode;
    let sinceTime: Date | null = null;
    let status: 'success' | 'partial' | 'error' = 'success';
    let errorMessage: string | null = null;

    try {
      const cfg = await this.config.getResolved();
      const errors = this.config.readinessErrors(cfg);
      if (errors.length) throw new Error(errors.join('; '));

      if (mode === 'delta') {
        const lastOk = await this.prisma.defenderSyncRun.findFirst({
          where: { status: { in: ['success', 'partial'] }, id: { not: runId } },
          orderBy: { startedAt: 'desc' },
        });
        const since = lastOk?.startedAt ?? null;
        if (!since || Date.now() - since.getTime() > MAX_DELTA_AGE_MS) {
          this.logger.log('Sin sync reciente (<13 días): el delta se convierte en sync completo');
          mode = 'full';
        } else {
          sinceTime = since;
        }
      }

      if (mode === 'full') await this.runFullSync(cfg, counters);
      else await this.runDeltaSync(cfg, sinceTime!, counters);

      await this.relinkUnknownCves();
      if (counters.devicesFailed > 0) status = 'partial';
    } catch (error) {
      status = 'error';
      errorMessage = errorText(error);
      this.logger.error(`Sync de Defender #${runId} falló: ${errorMessage}`);
    }

    const durationMs = Date.now() - started;
    await this.prisma.defenderSyncRun.update({
      where: { id: runId },
      data: {
        mode,
        status,
        sinceTime,
        finishedAt: new Date(),
        durationMs,
        devicesSeen: counters.devicesSeen,
        devicesUpserted: counters.devicesUpserted,
        devicesDeactivated: counters.devicesDeactivated,
        devicesFailed: counters.devicesFailed,
        findingsUpserted: counters.findingsUpserted,
        findingsFixed: counters.findingsFixed,
        unknownCves: counters.unknownCves.size,
        failures: counters.failures.length ? JSON.stringify(counters.failures.slice(0, MAX_FAILURES_STORED)) : null,
        errorMessage,
      },
    });

    await this.prisma.collectorSourceHealth
      .create({
        data: {
          source: DEFENDER_SOURCE,
          fetchStatus: status,
          itemsFetched: counters.devicesSeen,
          itemsProcessed: counters.findingsUpserted + counters.findingsFixed,
          itemsErrored: counters.devicesFailed,
          durationMs,
          errorMessage,
        },
      })
      .catch((e) => this.logger.warn(`No se pudo registrar la salud de Defender: ${errorText(e)}`));

    this.logger.log(
      `Sync Defender #${runId} (${mode}) ${status}: ${counters.devicesSeen} servidores, ` +
        `${counters.findingsUpserted} hallazgos, ${counters.findingsFixed} corregidos, ${counters.devicesFailed} fallidos`,
    );
  }

  private async runFullSync(cfg: ResolvedDefenderConfig, c: RunCounters) {
    const machines = selectActiveServers(await this.client.listServers(cfg), cfg.staleDeviceDays);
    c.devicesSeen = machines.length;

    const systems: Array<{ id: number; machineId: string; name: string }> = [];
    for (const m of machines) {
      const system = await this.upsertSystem(m, cfg.teamId!);
      systems.push({ id: system.id, machineId: m.id, name: system.name });
      c.devicesUpserted++;
    }

    // El listado de equipos fue completo: los servidores ausentes dejan de estar activos.
    // Un listado vacío casi siempre es un filtro mal configurado: no se desactiva nada.
    if (machines.length > 0) {
      const deactivated = await this.prisma.teamSystem.updateMany({
        where: { source: DEFENDER_SOURCE, isActive: true, externalId: { notIn: machines.map((m) => m.id) } },
        data: { isActive: false },
      });
      c.devicesDeactivated = deactivated.count;
    } else {
      c.failures.push({ error: 'Defender no devolvió ningún servidor con los filtros configurados; no se desactiva ningún equipo' });
    }

    const toScan = systems.slice(0, cfg.maxDevicesPerRun);
    if (systems.length > toScan.length) {
      c.failures.push({ error: `Límite maxDevicesPerRun=${cfg.maxDevicesPerRun}: ${systems.length - toScan.length} servidores sin escanear en esta ejecución` });
    }

    for (const s of toScan) {
      try {
        const raw = await this.client.listMachineVulnerabilities(cfg, s.machineId);
        const findings = dedupeFindings(raw.map(normalizeMachineVulnerability));
        const res = await this.applySnapshot(s.id, s.machineId, findings);
        c.findingsUpserted += res.upserted;
        c.findingsFixed += res.fixed;
        res.unknownCves.forEach((cve) => c.unknownCves.add(cve));
      } catch (error) {
        // Sin datos de este servidor: no se marcan sus hallazgos como corregidos.
        c.devicesFailed++;
        c.failures.push({ deviceId: s.machineId, device: s.name, error: errorText(error) });
      }
    }
  }

  private async runDeltaSync(cfg: ResolvedDefenderConfig, since: Date, c: RunCounters) {
    const systems = await this.prisma.teamSystem.findMany({
      where: { source: DEFENDER_SOURCE, isActive: true, externalId: { not: null } },
      select: { id: true, externalId: true },
    });
    const systemByMachine = new Map(systems.map((s) => [s.externalId as string, s.id]));

    const events = reduceChanges(await this.client.listVulnerabilityChanges(cfg, since)).filter((e) =>
      systemByMachine.has(e.deviceId),
    );
    c.devicesSeen = new Set(events.map((e) => e.deviceId)).size;

    const cveMap = await this.vulnerabilityIdsFor(events.map((e) => e.finding.cveId));
    const now = new Date();
    const failedDevices = new Set<string>();

    for (const e of events) {
      const teamSystemId = systemByMachine.get(e.deviceId)!;
      const where = {
        teamSystemId_cveId_productVendor_productName_productVersion: {
          teamSystemId,
          cveId: e.finding.cveId,
          productVendor: e.finding.productVendor,
          productName: e.finding.productName,
          productVersion: e.finding.productVersion,
        },
      };
      try {
        if (e.status === 'fixed') {
          const res = await this.prisma.deviceVulnerabilityFinding.updateMany({
            where: { ...where.teamSystemId_cveId_productVendor_productName_productVersion, status: 'open' },
            data: { status: 'fixed', fixedAt: new Date(e.eventAt || now.getTime()) },
          });
          c.findingsFixed += res.count;
        } else {
          const vulnerabilityId = cveMap.get(e.finding.cveId) ?? null;
          if (!vulnerabilityId) c.unknownCves.add(e.finding.cveId);
          await this.prisma.deviceVulnerabilityFinding.upsert({
            where,
            create: this.createData(teamSystemId, e.deviceId, e.finding, vulnerabilityId, now),
            update: { ...enrichmentUpdate(e.finding), vulnerabilityId, status: 'open', fixedAt: null, lastSeenAt: now },
          });
          c.findingsUpserted++;
        }
      } catch (error) {
        failedDevices.add(e.deviceId);
        c.failures.push({ deviceId: e.deviceId, error: `${e.finding.cveId}: ${errorText(error)}` });
      }
    }
    c.devicesFailed = failedDevices.size;
  }

  // ── Persistencia ──────────────────────────────────────────────

  private async upsertSystem(machine: Parameters<typeof machineToSystemData>[0], defaultTeamId: number) {
    const data = { ...machineToSystemData(machine), isActive: true };
    // Si el servidor ya está en algún equipo de ARGOS, se respeta esa asignación.
    const existing = await this.prisma.teamSystem.findFirst({
      where: { source: DEFENDER_SOURCE, externalId: machine.id },
      orderBy: { id: 'asc' },
    });
    if (existing) {
      return this.prisma.teamSystem.update({ where: { id: existing.id }, data });
    }
    return this.prisma.teamSystem.create({
      data: { ...data, teamId: defaultTeamId, externalId: machine.id, source: DEFENDER_SOURCE },
    });
  }

  private createData(
    teamSystemId: number,
    deviceExternalId: string,
    f: NormalizedFinding,
    vulnerabilityId: number | null,
    now: Date,
  ) {
    return {
      teamSystemId,
      deviceExternalId,
      cveId: f.cveId,
      vulnerabilityId,
      productVendor: f.productVendor,
      productName: f.productName,
      productVersion: f.productVersion,
      defenderSeverity: f.defenderSeverity,
      defenderCvss: f.defenderCvss,
      exploitabilityLevel: f.exploitabilityLevel,
      fixingKbId: f.fixingKbId,
      recommendedUpdate: f.recommendedUpdate,
      diskPaths: f.diskPaths,
      registryPaths: f.registryPaths,
      status: 'open',
      firstSeenAt: f.firstSeenAt ?? now,
      lastSeenAt: now,
    };
  }

  private async vulnerabilityIdsFor(cveIds: string[]) {
    const unique = [...new Set(cveIds)];
    const map = new Map<string, number>();
    for (let i = 0; i < unique.length; i += 1000) {
      const rows = await this.prisma.vulnerability.findMany({
        where: { cveId: { in: unique.slice(i, i + 1000) } },
        select: { id: true, cveId: true },
      });
      rows.forEach((r) => map.set(r.cveId, r.id));
    }
    return map;
  }

  /**
   * Aplica la foto completa de un servidor: crea lo nuevo, refresca lo existente
   * y marca como corregido lo abierto que ya no aparece.
   */
  async applySnapshot(teamSystemId: number, deviceExternalId: string, findings: NormalizedFinding[], now = new Date()) {
    const cveMap = await this.vulnerabilityIdsFor(findings.map((f) => f.cveId));
    const existing = await this.prisma.deviceVulnerabilityFinding.findMany({
      where: { teamSystemId },
      select: {
        id: true,
        cveId: true,
        productVendor: true,
        productName: true,
        productVersion: true,
        status: true,
        defenderSeverity: true,
        fixingKbId: true,
        vulnerabilityId: true,
      },
    });
    const existingByKey = new Map(existing.map((e) => [findingKey(e), e]));
    const incomingKeys = new Set<string>();
    const toCreate: ReturnType<DefenderSyncService['createData']>[] = [];
    const toTouch: number[] = [];
    const toUpdate: Array<{ id: number; data: Record<string, unknown> }> = [];
    const unknownCves = new Set<string>();

    for (const f of findings) {
      const key = findingKey(f);
      incomingKeys.add(key);
      const vulnerabilityId = cveMap.get(f.cveId) ?? null;
      if (!vulnerabilityId) unknownCves.add(f.cveId);
      const prev = existingByKey.get(key);
      if (!prev) {
        toCreate.push(this.createData(teamSystemId, deviceExternalId, f, vulnerabilityId, now));
        continue;
      }
      const changed =
        prev.status !== 'open' ||
        prev.vulnerabilityId !== vulnerabilityId ||
        (f.defenderSeverity !== null && prev.defenderSeverity !== f.defenderSeverity) ||
        (f.fixingKbId !== null && prev.fixingKbId !== f.fixingKbId);
      if (changed) {
        toUpdate.push({
          id: prev.id,
          data: { ...enrichmentUpdate(f), vulnerabilityId, status: 'open', fixedAt: null, lastSeenAt: now },
        });
      } else {
        toTouch.push(prev.id);
      }
    }

    const toFix = existing.filter((e) => e.status === 'open' && !incomingKeys.has(findingKey(e))).map((e) => e.id);

    await this.prisma.$transaction([
      ...(toCreate.length ? [this.prisma.deviceVulnerabilityFinding.createMany({ data: toCreate, skipDuplicates: true })] : []),
      ...toUpdate.map((u) => this.prisma.deviceVulnerabilityFinding.update({ where: { id: u.id }, data: u.data })),
      ...(toTouch.length
        ? [this.prisma.deviceVulnerabilityFinding.updateMany({ where: { id: { in: toTouch } }, data: { lastSeenAt: now } })]
        : []),
      ...(toFix.length
        ? [this.prisma.deviceVulnerabilityFinding.updateMany({ where: { id: { in: toFix } }, data: { status: 'fixed', fixedAt: now } })]
        : []),
    ]);

    return { upserted: findings.length, fixed: toFix.length, unknownCves };
  }

  /** Enlaza hallazgos con CVEs que ARGOS ha incorporado después de la ingesta. */
  async relinkUnknownCves() {
    const pending = await this.prisma.deviceVulnerabilityFinding.findMany({
      where: { vulnerabilityId: null },
      select: { cveId: true },
      distinct: ['cveId'],
      take: 5000,
    });
    if (!pending.length) return 0;
    const map = await this.vulnerabilityIdsFor(pending.map((p) => p.cveId));
    let linked = 0;
    for (const [cveId, id] of map) {
      const res = await this.prisma.deviceVulnerabilityFinding.updateMany({
        where: { cveId, vulnerabilityId: null },
        data: { vulnerabilityId: id },
      });
      linked += res.count;
    }
    return linked;
  }

  // ── Consulta ──────────────────────────────────────────────────

  async listRuns(limit = 20) {
    const runs = await this.prisma.defenderSyncRun.findMany({
      orderBy: { createdAt: 'desc' },
      take: Math.min(Math.max(1, limit), 100),
    });
    return runs.map((r) => ({ ...r, failures: r.failures ? JSON.parse(r.failures) : [] }));
  }
}
