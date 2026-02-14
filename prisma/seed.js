/**
 * Production-compatible seed (pure JS, no ts-node required).
 * Creates admin/viewer users, API configs, and default tags.
 */
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

async function main() {
    console.log('🌱 Seeding database...');

    // ── Users ──
    try {
        const adminHash = await bcrypt.hash('Admin.OCC.2026!', 12);
        const admin = await prisma.user.upsert({
            where: { email: 'admin@servicios-occ.local' },
            update: {},
            create: {
                email: 'admin@servicios-occ.local',
                passwordHash: adminHash,
                name: 'Administrador OCC',
                role: 'ADMIN',
                isActive: true,
            },
        });
        console.log(`  ✔ Admin user: ${admin.email}`);

        const viewerHash = await bcrypt.hash('Viewer.OCC.2026!', 12);
        await prisma.user.upsert({
            where: { email: 'viewer@servicios-occ.local' },
            update: {},
            create: {
                email: 'viewer@servicios-occ.local',
                passwordHash: viewerHash,
                name: 'Viewer OCC',
                role: 'VIEWER',
                isActive: true,
            },
        });
        console.log('  ✔ Viewer user created');

        // ── API Configurations ──
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
    } catch (e) {
        console.error('  ⚠️ Users/API config seed error (non-fatal):', e.message);
    }

    // ── Default Tags ──
    try {
        const defaultTags = [
            { name: 'Crítica', color: '#DC2626' },
            { name: 'En seguimiento', color: '#F59E0B' },
            { name: 'Parcheada', color: '#10B981' },
            { name: 'Falso positivo', color: '#6B7280' },
            { name: 'Pendiente revisión', color: '#3B82F6' },
        ];
        for (const tag of defaultTags) {
            await prisma.vulnerabilityTag.upsert({
                where: { name: tag.name },
                update: {},
                create: tag,
            });
        }
        console.log('  ✔ Default tags created');
    } catch (e) {
        console.error('  ⚠️ Tags seed error (non-fatal):', e.message);
    }

    console.log('🌱 Seed completed!');
}

main()
    .catch((e) => {
        console.error('Seed failed:', e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
