/**
 * Script para crear un usuario suscriptor de prueba que esté suscrito
 * a TODOS los vendor/product del catálogo de software.
 *
 * Uso: npx ts-node scripts/add-test-subscriber.ts
 */
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const TEST_EMAIL = 'samante.barra.libre@proton.me';
const TEST_NAME = 'Test Subscriber';

async function main() {
    console.log('🧪 Creando usuario suscriptor de prueba...');

    // 1. Upsert del usuario
    const user = await prisma.user.upsert({
        where: { email: TEST_EMAIL },
        update: {
            isSubscriber: true,
            isActive: true,
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
        },
    });

    console.log(`  ✔ Usuario: ${user.email} (id=${user.id})`);

    // 2. Obtener todos los vendor/product del catálogo
    const catalog = await prisma.softwareCatalog.findMany({
        select: { vendor: true, product: true },
        orderBy: [{ vendor: 'asc' }, { product: 'asc' }],
    });

    console.log(`  📦 Productos en catálogo: ${catalog.length}`);

    if (catalog.length === 0) {
        console.log('  ⚠ No hay productos en el catálogo. El usuario se creó pero sin suscripciones.');
        console.log('  ⚠ Las suscripciones se crearán automáticamente tras la primera recolección.');
        return;
    }

    // 3. Eliminar suscripciones existentes y crear nuevas para TODO el catálogo
    await prisma.userSubscription.deleteMany({
        where: { userId: user.id },
    });

    const subscriptions = catalog.map((item) => ({
        userId: user.id,
        vendor: item.vendor.toLowerCase().trim(),
        product: item.product.toLowerCase().trim(),
        versions: '[]', // sin filtro de versión = todas
        isActive: true,
    }));

    // Prisma createMany no soporta duplicados, deduplicar por vendor+product
    const seen = new Set<string>();
    const uniqueSubs = subscriptions.filter((s) => {
        const key = `${s.vendor}::${s.product}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });

    await prisma.userSubscription.createMany({
        data: uniqueSubs,
    });

    console.log(`  ✔ Suscripciones creadas: ${uniqueSubs.length}`);
    console.log('');
    console.log('  Primeros 10 productos suscritos:');
    uniqueSubs.slice(0, 10).forEach((s) => {
        console.log(`    - ${s.vendor} / ${s.product}`);
    });
    if (uniqueSubs.length > 10) {
        console.log(`    ... y ${uniqueSubs.length - 10} más`);
    }

    console.log('');
    console.log('🧪 ¡Usuario de prueba listo! Las notificaciones automáticas se enviarán a:');
    console.log(`   ${TEST_EMAIL}`);
}

main()
    .catch((e) => {
        console.error('❌ Error:', e.message);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
