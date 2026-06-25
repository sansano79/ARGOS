import { PrismaClient } from '@prisma/client';
import { runSeedTestData } from '../src/modules/test-data/test-data.executor';

const prisma = new PrismaClient();

async function main() {
  await runSeedTestData(prisma, {
    enabled: process.env.TEST_DATA_SEED_ENABLED,
    occEnv: process.env.OCC_ENV,
    password: process.env.TEST_USERS_PASSWORD,
    dryRun: process.argv.includes('--dry-run'),
  });
}

main()
  .catch((error) => {
    console.error('[seed:test-data] Failed:', error instanceof Error ? error.message : error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
