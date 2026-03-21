import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  const seedEnabled = process.env.SEED_DATA === 'true';
  const isProduction = process.env.NODE_ENV === 'production';
  if (!seedEnabled || isProduction) {
    console.log('🌱 Seeding disabled');
    return;
  }

  console.log('🌱 Seeding database...');

  const adminEmail = (process.env.SEED_ADMIN_EMAIL || '').trim().toLowerCase();
  const adminPassword = process.env.SEED_ADMIN_PASSWORD || '';
  const viewerEmail = (process.env.SEED_VIEWER_EMAIL || '').trim().toLowerCase();
  const viewerPassword = process.env.SEED_VIEWER_PASSWORD || '';

  if (!adminEmail || !adminPassword) throw new Error('Missing SEED_ADMIN_EMAIL/SEED_ADMIN_PASSWORD');
  if (!viewerEmail || !viewerPassword) throw new Error('Missing SEED_VIEWER_EMAIL/SEED_VIEWER_PASSWORD');

  const adminHash = await bcrypt.hash(adminPassword, 12);
  const admin = await prisma.user.upsert({
    where: { email: adminEmail },
    update: {
      name: 'Administrador OCC',
      role: 'ADMIN',
      isActive: true,
      canLogin: true,
      authProvider: 'LOCAL',
      passwordHash: adminHash,
    },
    create: {
      email: adminEmail,
      passwordHash: adminHash,
      name: 'Administrador OCC',
      role: 'ADMIN',
      isActive: true,
      canLogin: true,
      authProvider: 'LOCAL',
    },
  });
  console.log(`  ✔ Admin user: ${admin.email}`);

  const viewerHash = await bcrypt.hash(viewerPassword, 12);
  const viewer = await prisma.user.upsert({
    where: { email: viewerEmail },
    update: {
      name: 'Viewer OCC',
      role: 'VIEWER',
      isActive: true,
      canLogin: true,
      authProvider: 'LOCAL',
      passwordHash: viewerHash,
    },
    create: {
      email: viewerEmail,
      passwordHash: viewerHash,
      name: 'Viewer OCC',
      role: 'VIEWER',
      isActive: true,
      canLogin: true,
      authProvider: 'LOCAL',
    },
  });
  console.log(`  ✔ Viewer user: ${viewer.email}`);

  // API configurations
  await prisma.apiConfiguration.upsert({
    where: { slug: 'nvd-nist' },
    update: {},
    create: {
      name: 'NVD - National Vulnerability Database',
      slug: 'nvd-nist',
      provider: 'nvd',
      endpointUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
      settings: JSON.stringify({ rateLimit: 50, ratePeriodSeconds: 30 }),
      isActive: true,
      createdBy: admin.id,
    },
  });

  await prisma.apiConfiguration.upsert({
    where: { slug: 'cisa-kev' },
    update: {},
    create: {
      name: 'CISA Known Exploited Vulnerabilities',
      slug: 'cisa-kev',
      provider: 'cisa',
      endpointUrl: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      isActive: true,
      createdBy: admin.id,
    },
  });

  await prisma.apiConfiguration.upsert({
    where: { slug: 'first-epss' },
    update: {},
    create: {
      name: 'FIRST EPSS - Exploit Prediction Scoring System',
      slug: 'first-epss',
      provider: 'first',
      endpointUrl: 'https://api.first.org/data/v1/epss',
      isActive: true,
      createdBy: admin.id,
    },
  });

  console.log('  ✔ API configurations created');

  const seedTestSubscriber = process.env.SEED_TEST_SUBSCRIBER === 'true';
  if (seedTestSubscriber) {
    console.log('\n🧪 Creating test subscriber for AI testing...');
    const testSubscriberEmail = (process.env.SEED_TEST_SUBSCRIBER_EMAIL || '').trim().toLowerCase();
    if (!testSubscriberEmail) throw new Error('Missing SEED_TEST_SUBSCRIBER_EMAIL');

    const catalogRows = await prisma.softwareCatalog.findMany({
      select: { vendor: true, product: true, versions: true },
    });

    if (catalogRows.length > 0) {
      const testSubscriber = await prisma.user.upsert({
        where: { email: testSubscriberEmail },
        update: {
          name: 'Test Subscriber (ALL Products)',
          isSubscriber: true,
          isActive: true,
          notificationEmail: testSubscriberEmail,
          role: 'SUBSCRIBER',
          canLogin: false,
        },
        create: {
          email: testSubscriberEmail,
          name: 'Test Subscriber (ALL Products)',
          role: 'SUBSCRIBER',
          canLogin: false,
          isSubscriber: true,
          isActive: true,
          notificationEmail: testSubscriberEmail,
          notes: 'Test subscriber auto-generated. Subscribed to ALL products in the catalog for AI smart notification testing.',
        },
      });

      await prisma.userSubscription.deleteMany({ where: { userId: testSubscriber.id } });
      await prisma.userSubscription.createMany({
        data: catalogRows.map((row) => ({
          userId: testSubscriber.id,
          vendor: row.vendor,
          product: row.product,
          versions: row.versions,
          isActive: true,
        })),
        skipDuplicates: true,
      });

      console.log(`  ✔ Test subscriber: ${testSubscriber.name} (${catalogRows.length} subscriptions)`);
    }
  }

  console.log('🌱 Seed completed!');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
