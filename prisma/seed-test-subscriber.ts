import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

/**
 * Creates a test subscriber user subscribed to ALL products in the software catalog.
 * This is useful for testing the AI smart notifications system with full coverage.
 */
async function main() {
  console.log('🧪 Creating test subscriber with ALL product subscriptions...\n');

  const TEST_EMAIL = 'test-subscriber@servicios-occ.local';
  const TEST_NAME = 'Test Subscriber (ALL Products)';

  // 1. Get ALL products from the software catalog
  const catalogRows = await prisma.softwareCatalog.findMany({
    orderBy: [{ vendor: 'asc' }, { product: 'asc' }],
    select: { vendor: true, product: true, versions: true },
  });

  if (catalogRows.length === 0) {
    console.log('⚠️  No products found in software_catalog. Run the collector first.');
    return;
  }

  console.log(`📦 Found ${catalogRows.length} products in the software catalog.\n`);

  // 2. Create or update the test subscriber user
  const user = await prisma.user.upsert({
    where: { email: TEST_EMAIL },
    update: {
      name: TEST_NAME,
      isSubscriber: true,
      isActive: true,
      canLogin: false,
      role: 'SUBSCRIBER',
      notificationEmail: TEST_EMAIL,
    },
    create: {
      email: TEST_EMAIL,
      name: TEST_NAME,
      role: 'SUBSCRIBER',
      canLogin: false,
      isSubscriber: true,
      isActive: true,
      notificationEmail: TEST_EMAIL,
      notes: 'Test subscriber auto-generated. Subscribed to ALL products in the catalog for AI smart notification testing.',
    },
  });

  console.log(`👤 User: ${user.name} (ID: ${user.id}, email: ${user.email})`);

  // 3. Delete existing subscriptions for this user (to re-create fresh)
  const deleted = await prisma.userSubscription.deleteMany({
    where: { userId: user.id },
  });
  console.log(`🗑️  Deleted ${deleted.count} old subscriptions.`);

  // 4. Create subscriptions for ALL products
  const subscriptionData = catalogRows.map((row) => ({
    userId: user.id,
    vendor: row.vendor,
    product: row.product,
    versions: row.versions, // Keep all versions from catalog
    isActive: true,
  }));

  const created = await prisma.userSubscription.createMany({
    data: subscriptionData,
    skipDuplicates: true,
  });

  console.log(`✅ Created ${created.count} subscriptions.\n`);

  // 5. Summary
  const vendors = [...new Set(catalogRows.map((r) => r.vendor))];
  console.log('📊 Subscription summary:');
  console.log(`   Total vendors: ${vendors.length}`);
  console.log(`   Total products: ${catalogRows.length}`);
  console.log(`   Vendors: ${vendors.slice(0, 15).join(', ')}${vendors.length > 15 ? ` ... (+${vendors.length - 15} more)` : ''}`);
  console.log('');
  console.log('🧪 Test subscriber ready! You can now:');
  console.log('   1. Go to "Notif. Inteligentes" → "Suscriptores"');
  console.log(`   2. Find "${TEST_NAME}" with ${created.count} subscriptions`);
  console.log('   3. Click "Preview" to test AI analysis');
  console.log('   4. Click "Ejecutar" to send a real notification');
}

main()
  .catch((e) => {
    console.error('❌ Error:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
