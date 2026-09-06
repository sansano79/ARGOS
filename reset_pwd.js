const { PrismaClient } = require("./node_modules/@prisma/client");
const bcrypt = require("bcrypt");

const prisma = new PrismaClient();

async function main() {
    const email = String(process.env.RESET_EMAIL || '').trim().toLowerCase();
    const newPassword = String(process.env.RESET_PASSWORD || '');
    if (!email || !newPassword) {
        throw new Error('Missing RESET_EMAIL or RESET_PASSWORD');
    }
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
            name: 'Administrador ARGOS',
            role: 'ADMIN',
            isActive: true,
        }
    });

    console.log('Password reset successfully for:', user.email);
}

main()
    .catch(console.error)
    .finally(() => prisma.$disconnect());
