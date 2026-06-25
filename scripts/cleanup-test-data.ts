import { PrismaClient } from '@prisma/client';
import { runCleanupTestData } from '../src/modules/test-data/test-data.executor';

const prisma = new PrismaClient();

async function main() {
  await runCleanupTestData(prisma, {
    enabled: process.env.TEST_DATA_SEED_ENABLED,
    occEnv: process.env.OCC_ENV,
    confirm: process.argv.includes('--confirm'),
    dryRun: process.argv.includes('--dry-run'),
  });
}

main()
  .catch((error) => {
    console.error('[cleanup:test-data] Failed:', error instanceof Error ? error.message : error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
