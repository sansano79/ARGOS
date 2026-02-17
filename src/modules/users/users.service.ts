import { Injectable, NotFoundException, ConflictException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
    constructor(private readonly prisma: PrismaService) { }

    async findAll() {
        const users = await this.prisma.user.findMany({
            orderBy: { createdAt: 'desc' },
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                canLogin: true,
                isSubscriber: true,
                notificationEmail: true,
                isActive: true,
                lastLoginAt: true,
                createdAt: true,
                updatedAt: true,
                subscriptions: {
                    where: { isActive: true },
                    select: {
                        id: true,
                        vendor: true,
                        product: true,
                        versions: true,
                    },
                    orderBy: [{ vendor: 'asc' }, { product: 'asc' }],
                },
            },
        });
        return users.map((u) => this.mapUserResponse(u));
    }

    async findOne(id: number) {
        const user = await this.prisma.user.findUnique({
            where: { id },
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                canLogin: true,
                isSubscriber: true,
                notificationEmail: true,
                isActive: true,
                lastLoginAt: true,
                createdAt: true,
                updatedAt: true,
                subscriptions: {
                    where: { isActive: true },
                    select: {
                        id: true,
                        vendor: true,
                        product: true,
                        versions: true,
                    },
                    orderBy: [{ vendor: 'asc' }, { product: 'asc' }],
                },
            },
        });
        if (!user) throw new NotFoundException('User not found');
        return this.mapUserResponse(user);
    }

    async getSubscriptionCatalog() {
        const [rows, manufacturers] = await Promise.all([
            this.prisma.softwareCatalog.findMany({
                orderBy: [{ vendor: 'asc' }, { product: 'asc' }],
                select: { vendor: true, product: true, versions: true },
            }),
            (this.prisma as any).manufacturer.findMany({
                where: { isActive: true },
                orderBy: { name: 'asc' },
                select: { name: true },
            }),
        ]);

        const grouped = new Map<string, Array<{ product: string; versions: string[] }>>();
        for (const m of manufacturers || []) {
            if (!grouped.has(m.name)) grouped.set(m.name, []);
        }
        for (const row of rows) {
            if (!grouped.has(row.vendor)) grouped.set(row.vendor, []);
            grouped.get(row.vendor)?.push({
                product: row.product,
                versions: this.parseJsonArray(row.versions),
            });
        }

        return Array.from(grouped.entries()).map(([vendor, products]) => ({
            vendor,
            products,
        }));
    }

    async create(data: {
        email: string;
        password?: string;
        name: string;
        role?: string;
        canLogin?: boolean;
        isSubscriber?: boolean;
        notificationEmail?: string;
        subscriptions?: Array<{ vendor: string; product: string; versions?: string[] }>;
    }) {
        const existing = await this.prisma.user.findUnique({
            where: { email: data.email },
        });
        if (existing) throw new ConflictException('Email already in use');

        const canLogin = data.canLogin !== false;
        const isSubscriber = data.isSubscriber === true;
        const role = canLogin ? (data.role || 'USER') : 'SUBSCRIBER';
        const subscriptionItems = this.normalizeSubscriptions(data.subscriptions || []);
        const notificationEmail = isSubscriber ? (data.notificationEmail || data.email) : null;

        let passwordHash: string | null = null;
        if (canLogin) {
            if (!data.password || data.password.length < 8) {
                throw new BadRequestException('Password is required (min 8 chars) for login-enabled users');
            }
            passwordHash = await bcrypt.hash(data.password, 12);
        }

        const created = await this.prisma.user.create({
            data: {
                email: data.email,
                passwordHash,
                name: data.name,
                role,
                canLogin,
                isSubscriber,
                notificationEmail,
                subscriptions: isSubscriber ? {
                    create: subscriptionItems.map((s) => ({
                        vendor: s.vendor,
                        product: s.product,
                        versions: JSON.stringify(s.versions || []),
                        isActive: true,
                    })),
                } : undefined,
            },
            include: {
                subscriptions: {
                    where: { isActive: true },
                    select: { id: true, vendor: true, product: true, versions: true },
                    orderBy: [{ vendor: 'asc' }, { product: 'asc' }],
                },
            },
        });

        return this.mapUserResponse(created);
    }

    async update(id: number, data: {
        email?: string;
        name?: string;
        role?: string;
        password?: string;
        isActive?: boolean;
        canLogin?: boolean;
        isSubscriber?: boolean;
        notificationEmail?: string;
        subscriptions?: Array<{ vendor: string; product: string; versions?: string[] }>;
    }) {
        const existing = await this.prisma.user.findUnique({
            where: { id },
            include: { subscriptions: true },
        });
        if (!existing) throw new NotFoundException('User not found');

        if (data.email && data.email !== existing.email) {
            const withEmail = await this.prisma.user.findUnique({ where: { email: data.email } });
            if (withEmail && withEmail.id !== id) {
                throw new ConflictException('Email already in use');
            }
        }

        const canLogin = data.canLogin ?? existing.canLogin;
        const isSubscriber = data.isSubscriber ?? existing.isSubscriber;
        const role = data.role ?? (canLogin ? existing.role : 'SUBSCRIBER');
        const userEmail = data.email ?? existing.email;
        const notificationEmail = isSubscriber
            ? (data.notificationEmail || existing.notificationEmail || userEmail)
            : null;
        const subscriptionItems = this.normalizeSubscriptions(data.subscriptions || []);

        const updateData: any = {};
        if (data.email) updateData.email = data.email;
        if (data.name) updateData.name = data.name;
        updateData.role = canLogin ? role : 'SUBSCRIBER';
        updateData.canLogin = canLogin;
        updateData.isSubscriber = isSubscriber;
        updateData.notificationEmail = notificationEmail;
        if (data.isActive !== undefined) updateData.isActive = data.isActive;

        if (data.password) {
            updateData.passwordHash = await bcrypt.hash(data.password, 12);
            updateData.canLogin = true;
        } else if (!canLogin) {
            updateData.passwordHash = null;
        } else if (canLogin && !existing.passwordHash) {
            throw new BadRequestException('Password is required to enable login for this user');
        }

        await this.prisma.$transaction(async (tx) => {
            await tx.user.update({
                where: { id },
                data: updateData,
            });

            if (!isSubscriber) {
                await tx.userSubscription.deleteMany({ where: { userId: id } });
            } else if (data.subscriptions) {
                await tx.userSubscription.deleteMany({ where: { userId: id } });
                if (subscriptionItems.length > 0) {
                    await tx.userSubscription.createMany({
                        data: subscriptionItems.map((s) => ({
                            userId: id,
                            vendor: s.vendor,
                            product: s.product,
                            versions: JSON.stringify(s.versions || []),
                            isActive: true,
                        })),
                    });
                }
            }
        });

        return this.findOne(id);
    }

    async remove(id: number) {
        await this.findOne(id);
        return this.prisma.user.update({
            where: { id },
            data: { isActive: false },
        });
    }

    private normalizeSubscriptions(
        items: Array<{ vendor: string; product: string; versions?: string[] }>,
    ): Array<{ vendor: string; product: string; versions: string[] }> {
        const seen = new Set<string>();
        const out: Array<{ vendor: string; product: string; versions: string[] }> = [];

        for (const item of items || []) {
            const vendor = String(item?.vendor || '').trim().toLowerCase();
            const product = String(item?.product || '').trim().toLowerCase();
            if (!vendor || !product) continue;

            const key = `${vendor}::${product}`;
            if (seen.has(key)) continue;
            seen.add(key);

            const versions = [...new Set((item?.versions || [])
                .map((v) => String(v || '').trim())
                .filter((v) => !!v))];

            out.push({ vendor, product, versions });
        }

        return out;
    }

    private parseJsonArray(value: any): string[] {
        try {
            if (Array.isArray(value)) return value.map((v) => String(v));
            const parsed = JSON.parse(value || '[]');
            return Array.isArray(parsed) ? parsed.map((v) => String(v)) : [];
        } catch {
            return [];
        }
    }

    private mapUserResponse(user: any) {
        const { passwordHash: _, ...rest } = user;
        return {
            ...rest,
            subscriptions: (user.subscriptions || []).map((s: any) => ({
                ...s,
                versions: this.parseJsonArray(s.versions),
            })),
        };
    }
}
