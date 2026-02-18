/**
 * Migra los it_contacts existentes como usuarios suscriptores en la tabla users.
 * 
 * - Cada it_contact se convierte en un User con isSubscriber=true, canLogin=false
 * - Sus products se convierten en UserSubscription records
 * - Los VulnerabilityNotification existentes se migran de contactId → subscriberUserId
 *
 * Uso: DATABASE_URL="mysql://..." npx ts-node scripts/migrate-contacts-to-users.ts
 */
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

function parseContactProducts(products: string | any): Array<{ vendor: string; product: string }> {
    try {
        const parsed = typeof products === 'string' ? JSON.parse(products) : products;
        if (!Array.isArray(parsed)) return [];

        return parsed
            .map((item: any) => {
                if (typeof item === 'string') {
                    const parts = item.split('/');
                    if (parts.length >= 2) {
                        return {
                            vendor: parts[0].trim().toLowerCase(),
                            product: parts.slice(1).join('/').trim().toLowerCase(),
                        };
                    }
                    // Single string without "/" → treat as product with unknown vendor
                    return null;
                }
                if (item && typeof item === 'object') {
                    return {
                        vendor: String(item.vendor || '').trim().toLowerCase(),
                        product: String(item.product || '').trim().toLowerCase(),
                    };
                }
                return null;
            })
            .filter((p: any): p is { vendor: string; product: string } =>
                p !== null && !!p.vendor && !!p.product,
            );
    } catch {
        return [];
    }
}

async function main() {
    console.log('🔄 Migrando it_contacts → users...\n');

    const contacts = await prisma.itContact.findMany({
        where: { isActive: true },
    });

    console.log(`  Contactos IT encontrados: ${contacts.length}`);
    if (contacts.length === 0) {
        console.log('  No hay contactos que migrar.');
        return;
    }

    let migrated = 0;
    let skipped = 0;
    let subsCreated = 0;
    let notifsUpdated = 0;

    for (const contact of contacts) {
        const existingUser = await prisma.user.findUnique({
            where: { email: contact.email },
        });

        if (existingUser) {
            // If user already exists, just make sure they're a subscriber
            // and add the contact info fields
            await prisma.user.update({
                where: { id: existingUser.id },
                data: {
                    isSubscriber: true,
                    notificationEmail: existingUser.notificationEmail || contact.email,
                    contactPerson: existingUser.contactPerson || contact.contactPerson,
                    department: existingUser.department || contact.department,
                    phone: existingUser.phone || contact.phone,
                    notes: existingUser.notes || contact.notes,
                },
            });

            // Migrate subscriptions from contact products
            const products = parseContactProducts(contact.products);
            for (const p of products) {
                try {
                    await prisma.userSubscription.upsert({
                        where: {
                            userId_vendor_product: {
                                userId: existingUser.id,
                                vendor: p.vendor,
                                product: p.product,
                            },
                        },
                        update: {},
                        create: {
                            userId: existingUser.id,
                            vendor: p.vendor,
                            product: p.product,
                            versions: '[]',
                            isActive: true,
                        },
                    });
                    subsCreated++;
                } catch (e) {
                    // skip duplicates
                }
            }

            // Migrate notifications
            const updated = await prisma.vulnerabilityNotification.updateMany({
                where: {
                    contactId: contact.id,
                    subscriberUserId: null,
                },
                data: {
                    subscriberUserId: existingUser.id,
                },
            });
            notifsUpdated += updated.count;

            console.log(`  ↗ ${contact.name} (${contact.email}): merged into existing user id=${existingUser.id}, ${products.length} subs`);
            skipped++;
            continue;
        }

        // Create new user from contact
        const newUser = await prisma.user.create({
            data: {
                email: contact.email,
                name: contact.name,
                role: 'SUBSCRIBER',
                canLogin: false,
                isSubscriber: true,
                isActive: true,
                notificationEmail: contact.email,
                contactPerson: contact.contactPerson,
                department: contact.department,
                phone: contact.phone,
                notes: contact.notes,
            },
        });

        // Create subscriptions from products
        const products = parseContactProducts(contact.products);
        if (products.length > 0) {
            const seen = new Set<string>();
            const uniqueProducts = products.filter((p) => {
                const key = `${p.vendor}::${p.product}`;
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
            });

            await prisma.userSubscription.createMany({
                data: uniqueProducts.map((p) => ({
                    userId: newUser.id,
                    vendor: p.vendor,
                    product: p.product,
                    versions: '[]',
                    isActive: true,
                })),
            });
            subsCreated += uniqueProducts.length;
        }

        // Migrate existing notifications from contact to new user
        const updated = await prisma.vulnerabilityNotification.updateMany({
            where: {
                contactId: contact.id,
                subscriberUserId: null,
            },
            data: {
                subscriberUserId: newUser.id,
            },
        });
        notifsUpdated += updated.count;

        console.log(`  ✔ ${contact.name} (${contact.email}) → user id=${newUser.id}, ${products.length} subs`);
        migrated++;
    }

    console.log(`\n📊 Resumen:`);
    console.log(`  Contactos migrados como nuevos usuarios: ${migrated}`);
    console.log(`  Contactos fusionados con usuarios existentes: ${skipped}`);
    console.log(`  Suscripciones creadas: ${subsCreated}`);
    console.log(`  Notificaciones migradas: ${notifsUpdated}`);
    console.log('\n✅ Migración completada.');
}

main()
    .catch((e) => {
        console.error('❌ Error:', e.message);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
