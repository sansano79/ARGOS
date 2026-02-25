const { PrismaClient } = require("./node_modules/@prisma/client");
const bcrypt = require("bcrypt");

const prisma = new PrismaClient();

async function main() {
    const email = 'admin@servicios-occ.local';
    const newPassword = 'Admin.OCC.2026!';
    const passwordHash = await bcrypt.hash(newPassword, 12);

    const user = await prisma.user.upsert({
        where: { email },
        update: {
            passwordHash,
            isActive: true,
        },
        create: {
            email,
            passwordHash,
            name: 'Administrador OCC',
            role: 'ADMIN',
            isActive: true,
        }
    });

    console.log('Password reset successfully for:', user.email);
}

main()
    .catch(console.error)
    .finally(() => prisma.$disconnect());
