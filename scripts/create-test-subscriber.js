const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function main() {
  const userEmail = 'test.subscriber@servicios-occ.local';
  const now = new Date();
  const since = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  const vulnerabilities = await prisma.vulnerability.findMany({
    where: { publishedAt: { gte: since } },
    select: { affectedProducts: true },
    orderBy: { publishedAt: 'desc' },
    take: 1200,
  });

  const frequency = new Map();

  for (const vuln of vulnerabilities) {
    let products = [];
    try {
      products = JSON.parse(vuln.affectedProducts || '[]');
    } catch {
      products = [];
    }

    if (!Array.isArray(products)) continue;

    for (const item of products) {
      const vendor = String(item?.vendor || '').trim().toLowerCase();
      const product = String(item?.product || '').trim().toLowerCase();
      if (!vendor || !product) continue;

      const key = `${vendor}||${product}`;
      frequency.set(key, (frequency.get(key) || 0) + 1);
    }
  }

  const topProducts = [...frequency.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([key, count]) => {
      const [vendor, product] = key.split('||');
      return { vendor, product, count };
    });

  if (topProducts.length === 0) {
    console.log('No se encontraron productos afectados recientes para crear suscripción de prueba.');
    return;
  }

  const topVendors = [...new Set(topProducts.map((x) => x.vendor))].slice(0, 3);
  const selected = topProducts.filter((x) => topVendors.includes(x.vendor)).slice(0, 6);

  const user = await prisma.user.upsert({
    where: { email: userEmail },
    update: {
      name: 'Suscriptor Test Inteligente',
      role: 'SUBSCRIBER',
      canLogin: false,
      isSubscriber: true,
      isActive: true,
      notificationEmail: userEmail,
      contactPerson: 'QA Security',
      department: 'Cyber Test',
      notes: 'Usuario de prueba para validar notificaciones inteligentes',
    },
    create: {
      email: userEmail,
      name: 'Suscriptor Test Inteligente',
      role: 'SUBSCRIBER',
      canLogin: false,
      isSubscriber: true,
      isActive: true,
      notificationEmail: userEmail,
      contactPerson: 'QA Security',
      department: 'Cyber Test',
      notes: 'Usuario de prueba para validar notificaciones inteligentes',
    },
  });

  for (const item of selected) {
    await prisma.userSubscription.upsert({
      where: {
        userId_vendor_product: {
          userId: user.id,
          vendor: item.vendor,
          product: item.product,
        },
      },
      update: { isActive: true },
      create: {
        userId: user.id,
        vendor: item.vendor,
        product: item.product,
        isActive: true,
      },
    });
  }

  const subscriptions = await prisma.userSubscription.findMany({
    where: { userId: user.id, isActive: true },
    select: { vendor: true, product: true },
    orderBy: [{ vendor: 'asc' }, { product: 'asc' }],
  });

  console.log(
    JSON.stringify(
      {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          isSubscriber: user.isSubscriber,
        },
        selectedVendors: topVendors,
        selectedProductsBasis: selected,
        subscriptions,
      },
      null,
      2,
    ),
  );
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
