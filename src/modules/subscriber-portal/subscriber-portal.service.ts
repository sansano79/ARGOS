import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class SubscriberPortalService {
    constructor(private readonly prisma: PrismaService) {}

    // ── Profile ──────────────────────────────────────────────────

    async getProfile(userId: number) {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                isSubscriber: true,
                notificationEmail: true,
                contactPerson: true,
                department: true,
                phone: true,
                isActive: true,
                createdAt: true,
                subscriptions: {
                    where: { isActive: true },
                    select: { id: true, vendor: true, product: true, versions: true },
                    orderBy: [{ vendor: 'asc' }, { product: 'asc' }],
                },
            },
        });
        if (!user) throw new NotFoundException('User not found');

        return {
            ...user,
            subscriptions: (user.subscriptions || []).map((s) => ({
                ...s,
                versions: this.parseJsonArray(s.versions),
            })),
        };
    }

    // ── Subscriptions ────────────────────────────────────────────

    async updateSubscriptions(
        userId: number,
        subscriptions: Array<{ vendor: string; product: string; versions?: string[] }>,
    ) {
        const user = await this.prisma.user.findFirst({
            where: {
                id: userId,
                isActive: true,
                OR: [
                    { isSubscriber: true },
                    { role: 'SUBSCRIBER' },
                ],
            },
            select: {
                id: true,
                role: true,
                isSubscriber: true,
                notificationEmail: true,
                email: true,
            },
        });
        if (!user) throw new NotFoundException('Subscriber not found');

        const normalized = this.normalizeSubscriptions(subscriptions);

        await this.prisma.$transaction(async (tx) => {
            if (!user.isSubscriber) {
                await tx.user.update({
                    where: { id: userId },
                    data: {
                        isSubscriber: true,
                        role: user.role === 'SUBSCRIBER' ? 'SUBSCRIBER' : user.role,
                        notificationEmail: user.notificationEmail || user.email,
                    },
                });
            }
            await tx.userSubscription.deleteMany({ where: { userId } });
            if (normalized.length > 0) {
                await tx.userSubscription.createMany({
                    data: normalized.map((s) => ({
                        userId,
                        vendor: s.vendor,
                        product: s.product,
                        versions: JSON.stringify(s.versions || []),
                        isActive: true,
                    })),
                });
            }
        });

        return this.getProfile(userId);
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

    // ── Notifications history ────────────────────────────────────

    async getNotifications(userId: number) {
        const [smartReports, regularNotifications] = await Promise.all([
            (this.prisma as any).smartNotificationReport.findMany({
                where: { subscriberUserId: userId },
                orderBy: { createdAt: 'desc' },
                take: 50,
                select: {
                    id: true,
                    subject: true,
                    status: true,
                    sentAt: true,
                    periodStart: true,
                    periodEnd: true,
                    aiProvider: true,
                    aiModel: true,
                    createdAt: true,
                },
            }),
            this.prisma.vulnerabilityNotification.findMany({
                where: { subscriberUserId: userId },
                orderBy: { sentAt: 'desc' },
                take: 50,
                select: {
                    id: true,
                    recipientEmail: true,
                    status: true,
                    sentAt: true,
                    vulnerability: {
                        select: { cveId: true, cvssV31Severity: true },
                    },
                },
            }),
        ]);

        const smart = smartReports.map((r: any) => ({
            id: r.id,
            type: 'smart' as const,
            subject: r.subject || 'Informe Inteligente',
            status: r.status,
            date: r.sentAt || r.createdAt,
            periodStart: r.periodStart,
            periodEnd: r.periodEnd,
        }));

        const regular = regularNotifications.map((n: any) => ({
            id: n.id,
            type: 'regular' as const,
            subject: n.vulnerability?.cveId || 'Notificación CVE',
            status: n.status,
            date: n.sentAt,
            severity: n.vulnerability?.cvssV31Severity,
        }));

        return [...smart, ...regular].sort(
            (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime(),
        );
    }

    // ── Vulnerabilities + patched status ─────────────────────────

    async getVulnerabilities(userId: number) {
        // Get all CVE IDs from smart notification reports for this subscriber
        const reports = await (this.prisma as any).smartNotificationReport.findMany({
            where: {
                subscriberUserId: userId,
                status: { in: ['sent', 'no_correlations'] },
            },
            select: { inputSnapshot: true, analysisJson: true },
        });

        const cveIdSet = new Set<string>();
        for (const report of reports) {
            // Extract from inputSnapshot (has the vulnerability list)
            try {
                const snapshot = JSON.parse(report.inputSnapshot || '{}');
                for (const v of snapshot.vulnerabilities || []) {
                    if (v.cveId) cveIdSet.add(v.cveId);
                }
            } catch { /* ignore parse errors */ }
            // Extract from analysisJson (top risk, correlations)
            try {
                const analysis = JSON.parse(report.analysisJson || '{}');
                for (const item of analysis.top3RealRisk || []) {
                    if (item.cveId) cveIdSet.add(item.cveId);
                }
                for (const corr of analysis.detectedCorrelations || []) {
                    for (const cveId of corr.involvedCves || []) {
                        cveIdSet.add(cveId);
                    }
                }
            } catch { /* ignore parse errors */ }
        }

        if (cveIdSet.size === 0) return [];

        const cveIds = [...cveIdSet];

        // Get vulnerability details
        const vulnerabilities = await this.prisma.vulnerability.findMany({
            where: { cveId: { in: cveIds } },
            select: {
                id: true,
                cveId: true,
                description: true,
                cvssV31Score: true,
                cvssV31Severity: true,
                epssScore: true,
                hasPublicExploit: true,
                isKnownExploited: true,
                publishedAt: true,
                affectedProducts: true,
            },
            orderBy: { cvssV31Score: 'desc' },
        });

        // Get patched status for this subscriber
        const patched = await (this.prisma as any).subscriberPatchedCve.findMany({
            where: { userId },
            select: { cveId: true, patchedAt: true, notes: true },
        });
        const patchedMap = new Map<string, { patchedAt: Date; notes: string | null }>();
        for (const p of patched) {
            patchedMap.set(p.cveId, { patchedAt: p.patchedAt, notes: p.notes });
        }

        return vulnerabilities.map((v) => {
            const patchInfo = patchedMap.get(v.cveId);
            return {
                ...v,
                affectedProducts: this.parseJson(v.affectedProducts),
                isPatched: !!patchInfo,
                patchedAt: patchInfo?.patchedAt || null,
                patchNotes: patchInfo?.notes || null,
            };
        });
    }

    // ── Mark/Unmark as patched ───────────────────────────────────

    async markAsPatched(userId: number, cveId: string, notes?: string) {
        if (!cveId || !cveId.startsWith('CVE-')) {
            throw new BadRequestException('Invalid CVE ID format');
        }

        await (this.prisma as any).subscriberPatchedCve.upsert({
            where: {
                userId_cveId: { userId, cveId },
            },
            update: {
                notes: notes || null,
                patchedAt: new Date(),
            },
            create: {
                userId,
                cveId,
                notes: notes || null,
            },
        });

        return { cveId, patched: true };
    }

    async unmarkAsPatched(userId: number, cveId: string) {
        try {
            await (this.prisma as any).subscriberPatchedCve.delete({
                where: {
                    userId_cveId: { userId, cveId },
                },
            });
        } catch {
            // Ignore if not found
        }

        return { cveId, patched: false };
    }

    // ── Helpers ──────────────────────────────────────────────────

    private parseJsonArray(value: any): string[] {
        try {
            if (Array.isArray(value)) return value.map((v) => String(v));
            const parsed = JSON.parse(value || '[]');
            return Array.isArray(parsed) ? parsed.map((v) => String(v)) : [];
        } catch {
            return [];
        }
    }

    private parseJson(value: any): any {
        try {
            if (typeof value === 'object' && value !== null) return value;
            return JSON.parse(value || '[]');
        } catch {
            return [];
        }
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
}
