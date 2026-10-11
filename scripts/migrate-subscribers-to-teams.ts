/**
 * Script de análisis y simulación de migración de suscriptores a SubscriberTeam.
 *
 * FASE 1: MODO LECTURA ESTRICTO (--dry-run)
 *
 * Este script NO realiza modificaciones (INSERT, UPDATE, DELETE ni migraciones).
 * Analiza la consistencia de los datos, detecta conflictos y genera un informe
 * determinista en consola y en formato JSON.
 *
 * Uso:
 *   npx ts-node scripts/migrate-subscribers-to-teams.ts --dry-run
 *   npx ts-node scripts/migrate-subscribers-to-teams.ts --dry-run --mapping-file=mappings.json --output=report.json
 */
import * as fs from 'fs';
import * as path from 'path';
import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import {
  analyzeMigration,
  ExplicitMappingConfig,
} from '../src/modules/subscriber-teams/migration/subscriber-migration-engine';

interface CliArgs {
  isDryRun: boolean;
  mappingFilePath?: string;
  outputFilePath: string;
  showHelp: boolean;
}

function parseCliArgs(argv: string[]): CliArgs {
  let isDryRun = false;
  let mappingFilePath: string | undefined;
  let outputFilePath = 'migration-dry-run-report.json';
  let showHelp = false;

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--dry-run') {
      isDryRun = true;
    } else if (arg.startsWith('--mapping-file=')) {
      mappingFilePath = arg.split('=')[1];
    } else if (arg === '--mapping-file' && argv[i + 1]) {
      mappingFilePath = argv[++i];
    } else if (arg.startsWith('--output=')) {
      outputFilePath = arg.split('=')[1];
    } else if (arg === '--output' && argv[i + 1]) {
      outputFilePath = argv[++i];
    } else if (arg === '--help' || arg === '-h') {
      showHelp = true;
    }
  }

  return { isDryRun, mappingFilePath, outputFilePath, showHelp };
}

function printUsage(): void {
  console.log(`
Uso de migrate-subscribers-to-teams.ts:
  npx ts-node scripts/migrate-subscribers-to-teams.ts --dry-run [opciones]

Opciones obligatorias:
  --dry-run                 Ejecuta el análisis en modo solo lectura (obligatorio en esta fase).

Opciones adicionales:
  --mapping-file=<path>     Ruta a archivo JSON con resoluciones de usuarios multi-equipo.
  --output=<path>           Ruta del informe JSON de salida (por defecto: migration-dry-run-report.json).
  --help, -h                Muestra este mensaje de ayuda.
`);
}

async function run(): Promise<void> {
  const args = parseCliArgs(process.argv);

  if (args.showHelp) {
    printUsage();
    process.exit(0);
  }

  if (!args.isDryRun) {
    console.error('======================================================================');
    console.error('ERROR: En esta fase solo se permite la ejecución con el flag --dry-run.');
    console.error('No se permite ejecución de mutaciones sobre la base de datos.');
    console.error('======================================================================');
    printUsage();
    process.exit(1);
  }

  if (!process.env.DATABASE_URL) {
    console.error('======================================================================');
    console.error('ERROR: La variable de entorno DATABASE_URL no está definida.');
    console.error('Ejemplo: DATABASE_URL="mysql://usuario:clave@localhost:3306/argos"');
    console.error('======================================================================');
    process.exit(1);
  }

  let explicitMappings: ExplicitMappingConfig | undefined;
  if (args.mappingFilePath) {
    const resolvedPath = path.resolve(process.cwd(), args.mappingFilePath);
    if (!fs.existsSync(resolvedPath)) {
      console.error(`ERROR: El archivo de mapeo no existe: ${resolvedPath}`);
      process.exit(1);
    }
    try {
      const rawContent = fs.readFileSync(resolvedPath, 'utf8');
      explicitMappings = JSON.parse(rawContent);
      console.log(`[OK] Archivo de mapeos cargado correctamente: ${resolvedPath}`);
    } catch (err: any) {
      console.error(`ERROR: No se pudo parsear el archivo de mapeo JSON: ${err.message}`);
      process.exit(1);
    }
  }

  const prisma = new PrismaClient();

  try {
    console.log('──────────────────────────────────────────────────────────────────────');
    console.log('ARGOS: Iniciando análisis de migración de suscriptores a equipos (DRY-RUN)');
    console.log('Conectando a base de datos...');

    const [users, userSubscriptions, teams, teamMembers, legacyNotifications] = await Promise.all([
      prisma.user.findMany({
        select: {
          id: true,
          email: true,
          name: true,
          isSubscriber: true,
          isActive: true,
          role: true,
        },
      }),
      prisma.userSubscription.findMany({
        where: { isActive: true },
        select: {
          id: true,
          userId: true,
          vendor: true,
          product: true,
          versions: true,
          isActive: true,
        },
      }),
      prisma.subscriberTeam.findMany({
        select: {
          id: true,
          name: true,
          code: true,
          isActive: true,
        },
      }),
      prisma.teamMember.findMany({
        select: {
          id: true,
          teamId: true,
          userId: true,
          role: true,
          isActive: true,
        },
      }),
      prisma.vulnerabilityNotification.findMany({
        select: {
          id: true,
          vulnerabilityId: true,
          subscriberUserId: true,
          recipientEmail: true,
          sentAt: true,
          status: true,
          notificationLogId: true,
        },
      }),
    ]);

    console.log('[OK] Datos consultados con éxito:');
    console.log(`     - Usuarios totales: ${users.length}`);
    console.log(`     - Suscripciones activas: ${userSubscriptions.length}`);
    console.log(`     - Equipos existentes: ${teams.length}`);
    console.log(`     - Membresías existentes: ${teamMembers.length}`);
    console.log(`     - Notificaciones históricas: ${legacyNotifications.length}`);
    console.log('──────────────────────────────────────────────────────────────────────');

    const report = analyzeMigration({
      users,
      userSubscriptions,
      teams,
      teamMembers,
      legacyNotifications,
      explicitMappings,
    });

    console.log('\nRESUMEN DE RESULTADOS DEL ANÁLISIS:');
    console.log('----------------------------------------------------------------------');
    console.log(`[HECHO OBSERVADO] Usuarios evaluados (suscriptores o con reglas): ${report.summary.totalUsersEvaluated}`);
    console.log(`[HECHO OBSERVADO] Usuarios con flag isSubscriber = true:          ${report.summary.totalSubscribers}`);
    console.log(`[HECHO OBSERVADO] Suscripciones activas en user_subscriptions:    ${report.summary.totalLegacySubscriptions}`);
    console.log(`[HECHO OBSERVADO] Notificaciones registradas en histórico:       ${report.summary.totalLegacyNotifications}`);
    console.log('----------------------------------------------------------------------');
    console.log(`[PROPUESTA MIGRACIÓN] Usuarios con 1 equipo (Mapeo directo):      ${report.summary.usersWithSingleTeam}`);
    console.log(`[PROPUESTA MIGRACIÓN] Usuarios sin equipo (Requieren equipo ind): ${report.summary.usersWithNoTeam}`);
    console.log(`[PROPUESTA MIGRACIÓN] Usuarios con varios equipos:                 ${report.summary.usersWithMultipleTeams}`);
    console.log(`[PROPUESTA MIGRACIÓN] - Resueltos vía mappings.json:              ${report.summary.resolvedViaExplicitMappingUsers}`);
    console.log(`[PROPUESTA MIGRACIÓN] - CONFLICTOS pendientes de resolución:      ${report.summary.unresolvedConflictUsers}`);
    console.log('----------------------------------------------------------------------');
    console.log(`[PROPUESTA MIGRACIÓN] Suscripciones migrables a equipos:          ${report.summary.migratableSubscriptionsCount}`);
    console.log(`[PROPUESTA MIGRACIÓN] Grupos con suscripciones duplicadas:       ${report.summary.duplicateSubscriptionGroupsCount}`);
    console.log(`[PROPUESTA MIGRACIÓN] Alertas históricas aptas para backfill:     ${report.summary.backfillableNotificationsCount}`);
    console.log(`[PROPUESTA MIGRACIÓN] Alertas históricas huérfanas (sin usuario): ${report.summary.orphanNotificationsCount}`);
    console.log('----------------------------------------------------------------------');

    if (report.unresolvedConflicts.length > 0) {
      console.warn('\n[ATENCIÓN] CONFLICTOS MULTI-EQUIPO DETECTADOS:');
      for (const conflict of report.unresolvedConflicts) {
        console.warn(`  * Usuario ID ${conflict.userId} (${conflict.email}) pertenece a ${conflict.candidateTeams.length} equipos:`);
        for (const t of conflict.candidateTeams) {
          console.warn(`      -> Equipo ${t.teamId}: "${t.teamName}" (${t.teamCode}) [Rol: ${t.roleInTeam}]`);
        }
        console.warn(`     Tiene ${conflict.activeSubscriptionsCount} suscripción(es) que requieren asignación en mappings.json.`);
      }
    }

    if (report.duplicateSubscriptions.length > 0) {
      console.log('\n[INFO] DUPLICADOS DETECTADOS ENTRE MIEMBROS DEL MISMO EQUIPO:');
      for (const dupe of report.duplicateSubscriptions) {
        console.log(`  * Equipo ${dupe.targetTeamId} -> ${dupe.vendor}/${dupe.product} presente en ${dupe.occurrences.length} usuarios.`);
        console.log(`    Versiones consolidadas: [${dupe.mergedVersions.join(', ')}]`);
      }
    }

    // Write full report JSON
    const outputPath = path.resolve(process.cwd(), args.outputFilePath);
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf8');
    console.log(`\n[OK] Informe JSON completo generado en: ${outputPath}`);
    console.log('Análisis finalizado con éxito sin mutaciones en base de datos.');

    process.exit(0);
  } catch (error: any) {
    console.error('\n[ERROR FATAL] Ocurrió un error durante la ejecución del análisis:');
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

// Execute if run directly from CLI
if (require.main === module) {
  run();
}
