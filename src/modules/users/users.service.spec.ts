import { BadRequestException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { UsersService } from './users.service';

jest.mock('bcrypt', () => ({
    hash: jest.fn(),
}));

const makeUserRecord = (overrides: Record<string, any> = {}) => ({
    id: 1,
    email: 'ana@example.local',
    name: 'Ana',
    role: 'USER',
    canLogin: true,
    passwordHash: 'hashed-password',
    isSubscriber: false,
    notificationEmail: null,
    canReceiveNotifications: false,
    notificationsPaused: false,
    notificationsPausedUntil: null,
    communicationLanguage: 'es',
    isActive: true,
    subscriptions: [],
    teamMemberships: [],
    ...overrides,
});

describe('UsersService', () => {
    const prisma = {
        user: {
            findUnique: jest.fn(),
            create: jest.fn(),
            update: jest.fn(),
        },
        userSubscription: {
            deleteMany: jest.fn(),
            createMany: jest.fn(),
        },
        subscriberTeam: {
            findMany: jest.fn(),
        },
        teamMember: {
            findMany: jest.fn(),
            create: jest.fn(),
            update: jest.fn(),
            updateMany: jest.fn(),
        },
        $transaction: jest.fn(),
    } as any;

    let service: UsersService;

    beforeEach(() => {
        jest.clearAllMocks();
        service = new UsersService(prisma);
        (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');
        prisma.$transaction.mockImplementation(async (callback: any) => callback({
            user: prisma.user,
            userSubscription: prisma.userSubscription,
            subscriberTeam: prisma.subscriberTeam,
            teamMember: prisma.teamMember,
        }));
    });

    afterEach(() => {
        (bcrypt.hash as jest.Mock).mockReset();
    });

    it('creates an ordinary user with neutral legacy notification defaults when frontend omits legacy fields', async () => {
        prisma.user.findUnique
            .mockResolvedValueOnce(null)
            .mockResolvedValueOnce(makeUserRecord({ id: 1, role: 'ADMIN' }));
        prisma.user.create.mockResolvedValueOnce({ id: 1 });

        await service.create({
            email: 'ana@example.local',
            name: 'Ana',
            role: 'ADMIN',
            password: 'ChangeMeNow!123',
        });

        expect(prisma.user.create).toHaveBeenCalledWith(expect.objectContaining({
            data: expect.objectContaining({
                role: 'ADMIN',
                canLogin: true,
                isSubscriber: false,
                notificationEmail: null,
                canReceiveNotifications: false,
                notificationsPaused: false,
                notificationsPausedUntil: null,
                communicationLanguage: 'es',
                subscriptions: undefined,
            }),
            select: { id: true },
        }));
    });

    it('does not force SUBSCRIBER role when creating a login-disabled ordinary user', async () => {
        prisma.user.findUnique
            .mockResolvedValueOnce(null)
            .mockResolvedValueOnce(makeUserRecord({ id: 2, role: 'VIEWER', canLogin: false, passwordHash: null }));
        prisma.user.create.mockResolvedValueOnce({ id: 2 });

        await service.create({
            email: 'viewer@example.local',
            name: 'Viewer',
            role: 'VIEWER',
            canLogin: false,
        });

        expect(prisma.user.create).toHaveBeenCalledWith(expect.objectContaining({
            data: expect.objectContaining({
                role: 'VIEWER',
                canLogin: false,
                passwordHash: null,
                isSubscriber: false,
            }),
        }));
    });

    it('creates initial team assignments transactionally for ADMIN and TEAM_MANAGER users', async () => {
        prisma.user.findUnique
            .mockResolvedValueOnce(null)
            .mockResolvedValueOnce(makeUserRecord({
                id: 3,
                role: 'TEAM_MANAGER',
                teamMemberships: [
                    { id: 11, role: 'TEAM_MANAGER', isActive: true, team: { id: 7, name: 'IT Global', code: 'it-global', isActive: true } },
                    { id: 12, role: 'TEAM_VIEWER', isActive: true, team: { id: 8, name: 'Infraestructura', code: 'infra', isActive: true } },
                ],
            }));
        prisma.user.create.mockResolvedValueOnce({ id: 3 });
        prisma.subscriberTeam.findMany.mockResolvedValueOnce([{ id: 7 }, { id: 8 }]);
        prisma.teamMember.findMany.mockResolvedValueOnce([]);

        await service.create({
            email: 'luis@example.local',
            name: 'Luis',
            role: 'TEAM_MANAGER',
            password: 'ChangeMeNow!123',
            teamAssignments: [
                { teamId: 7, role: 'TEAM_MANAGER' },
                { teamId: 8, role: 'TEAM_VIEWER' },
            ],
        });

        expect(prisma.teamMember.create).toHaveBeenCalledTimes(2);
        expect(prisma.teamMember.create).toHaveBeenNthCalledWith(1, {
            data: { userId: 3, teamId: 7, role: 'TEAM_MANAGER', isActive: true },
        });
        expect(prisma.teamMember.create).toHaveBeenNthCalledWith(2, {
            data: { userId: 3, teamId: 8, role: 'TEAM_VIEWER', isActive: true },
        });
    });

    it('rejects TEAM_MANAGER internal assignment for a USER global role', async () => {
        prisma.user.findUnique.mockResolvedValueOnce(null);
        prisma.user.create.mockResolvedValueOnce({ id: 4 });
        prisma.subscriberTeam.findMany.mockResolvedValueOnce([{ id: 9 }]);

        await expect(service.create({
            email: 'user@example.local',
            name: 'User',
            role: 'USER',
            password: 'ChangeMeNow!123',
            teamAssignments: [{ teamId: 9, role: 'TEAM_MANAGER' }],
        })).rejects.toThrow(BadRequestException);
    });

    it('preserves legacy subscriber settings and subscriptions when editing only ordinary user fields', async () => {
        prisma.user.findUnique
            .mockResolvedValueOnce(makeUserRecord({
                id: 7,
                email: 'legacy@example.local',
                name: 'Legacy',
                role: 'SUBSCRIBER',
                canLogin: false,
                passwordHash: null,
                isSubscriber: true,
                notificationEmail: 'legacy-notify@example.local',
                canReceiveNotifications: true,
                notificationsPaused: true,
                notificationsPausedUntil: new Date('2026-06-30T10:00:00.000Z'),
                communicationLanguage: 'en',
                subscriptions: [{ id: 11, vendor: 'microsoft', product: 'windows', versions: '[]' }],
            }))
            .mockResolvedValueOnce(makeUserRecord({
                id: 7,
                email: 'legacy@example.local',
                name: 'Legacy Admin',
                role: 'ADMIN',
                canLogin: true,
                isSubscriber: true,
                notificationEmail: 'legacy-notify@example.local',
                canReceiveNotifications: true,
                notificationsPaused: true,
                notificationsPausedUntil: new Date('2026-06-30T10:00:00.000Z'),
                communicationLanguage: 'en',
                subscriptions: [{ id: 11, vendor: 'microsoft', product: 'windows', versions: '[]' }],
            }));
        prisma.user.update.mockResolvedValueOnce({});

        const result = await service.update(7, {
            name: 'Legacy Admin',
            canLogin: true,
            role: 'ADMIN',
            password: 'ChangeMeNow!123',
        });

        expect(prisma.user.update).toHaveBeenCalledWith({
            where: { id: 7 },
            data: expect.objectContaining({
                name: 'Legacy Admin',
                role: 'ADMIN',
                canLogin: true,
                isSubscriber: true,
                notificationEmail: 'legacy-notify@example.local',
                canReceiveNotifications: true,
                notificationsPaused: true,
                notificationsPausedUntil: new Date('2026-06-30T10:00:00.000Z'),
                communicationLanguage: 'en',
                passwordHash: 'hashed-password',
            }),
        });
        expect(prisma.userSubscription.deleteMany).not.toHaveBeenCalled();
        expect(prisma.userSubscription.createMany).not.toHaveBeenCalled();
        expect(result).toEqual(expect.objectContaining({
            id: 7,
            role: 'ADMIN',
            isSubscriber: true,
            canReceiveNotifications: true,
        }));
    });

    it('keeps legacy notification email untouched when editing access email only', async () => {
        prisma.user.findUnique
            .mockResolvedValueOnce(makeUserRecord({
                id: 8,
                email: 'old@example.local',
                role: 'USER',
                isSubscriber: true,
                notificationEmail: 'notify@example.local',
                canReceiveNotifications: true,
            }))
            .mockResolvedValueOnce(null)
            .mockResolvedValueOnce(makeUserRecord({
                id: 8,
                email: 'new@example.local',
                role: 'USER',
                isSubscriber: true,
                notificationEmail: 'notify@example.local',
                canReceiveNotifications: true,
            }));
        prisma.user.update.mockResolvedValueOnce({});

        await service.update(8, {
            email: 'new@example.local',
            name: 'Old',
            role: 'USER',
        });

        expect(prisma.user.update).toHaveBeenCalledWith({
            where: { id: 8 },
            data: expect.objectContaining({
                email: 'new@example.local',
                notificationEmail: 'notify@example.local',
            }),
        });
    });

    it('syncs team assignments in update by reactivating included memberships and deactivating omitted ones', async () => {
        prisma.user.findUnique
            .mockResolvedValueOnce(makeUserRecord({
                id: 12,
                role: 'TEAM_MANAGER',
                teamMemberships: [
                    { id: 31, role: 'TEAM_MANAGER', isActive: true, team: { id: 7, name: 'IT Global', code: 'it-global', isActive: true } },
                    { id: 32, role: 'TEAM_VIEWER', isActive: true, team: { id: 8, name: 'Infra', code: 'infra', isActive: true } },
                ],
            }))
            .mockResolvedValueOnce(makeUserRecord({
                id: 12,
                role: 'TEAM_MANAGER',
                teamMemberships: [
                    { id: 31, role: 'TEAM_MANAGER', isActive: true, team: { id: 7, name: 'IT Global', code: 'it-global', isActive: true } },
                    { id: 32, role: 'TEAM_VIEWER', isActive: false, team: { id: 8, name: 'Infra', code: 'infra', isActive: true } },
                    { id: 33, role: 'TEAM_VIEWER', isActive: true, team: { id: 9, name: 'ERP', code: 'erp', isActive: true } },
                ],
            }));
        prisma.user.update.mockResolvedValueOnce({});
        prisma.subscriberTeam.findMany.mockResolvedValueOnce([{ id: 7 }, { id: 9 }]);
        prisma.teamMember.findMany.mockResolvedValueOnce([
            { id: 31, teamId: 7 },
            { id: 32, teamId: 8 },
        ]);

        await service.update(12, {
            role: 'TEAM_MANAGER',
            teamAssignments: [
                { teamId: 7, role: 'TEAM_MANAGER' },
                { teamId: 9, role: 'TEAM_VIEWER' },
            ],
        });

        expect(prisma.teamMember.update).toHaveBeenCalledWith({
            where: { id: 31 },
            data: { role: 'TEAM_MANAGER', isActive: true },
        });
        expect(prisma.teamMember.create).toHaveBeenCalledWith({
            data: { userId: 12, teamId: 9, role: 'TEAM_VIEWER', isActive: true },
        });
        expect(prisma.teamMember.updateMany).toHaveBeenCalledWith({
            where: { userId: 12, teamId: { in: [8] } },
            data: { isActive: false },
        });
    });

    // Test cases for bug fix: canLogin existing + role change without password
    describe('Role changes without password on existing canLogin users', () => {
        it('A: allows role change from VIEWER to USER when canLogin was already true, without password', async () => {
            const existingUser = makeUserRecord({
                id: 13,
                role: 'VIEWER',
                canLogin: true,
                passwordHash: 'existing-hash',
            });
            const updatedUser = makeUserRecord({
                id: 13,
                role: 'USER',
                canLogin: true,
                passwordHash: 'existing-hash',
            });

            prisma.user.findUnique
                .mockResolvedValueOnce(existingUser)
                .mockResolvedValueOnce(updatedUser);
            prisma.user.update.mockResolvedValueOnce({});

            const result = await service.update(13, {
                role: 'USER',
                canLogin: true,
            });

            expect(prisma.user.update).toHaveBeenCalledWith({
                where: { id: 13 },
                data: expect.objectContaining({
                    role: 'USER',
                    canLogin: true,
                }),
            });
            expect(result.role).toBe('USER');
        });

        it('B: allows role change between permitted roles when canLogin was already true, without password', async () => {
            const existingUser = makeUserRecord({
                id: 14,
                role: 'USER',
                canLogin: true,
                passwordHash: 'existing-hash',
            });
            const updatedUser = makeUserRecord({
                id: 14,
                role: 'TEAM_MANAGER',
                canLogin: true,
                passwordHash: 'existing-hash',
            });

            prisma.user.findUnique
                .mockResolvedValueOnce(existingUser)
                .mockResolvedValueOnce(updatedUser);
            prisma.user.update.mockResolvedValueOnce({});
            prisma.subscriberTeam.findMany.mockResolvedValueOnce([]);
            prisma.teamMember.findMany.mockResolvedValueOnce([]);

            const result = await service.update(14, {
                role: 'TEAM_MANAGER',
                canLogin: true,
            });

            expect(prisma.user.update).toHaveBeenCalled();
            expect(result.role).toBe('TEAM_MANAGER');
        });

        it('C: rejects enabling login (canLogin false->true) for local user without password', async () => {
            const existingUser = makeUserRecord({
                id: 15,
                role: 'VIEWER',
                canLogin: false,
                passwordHash: null,
            });

            prisma.user.findUnique.mockResolvedValueOnce(existingUser);

            try {
                await service.update(15, {
                    canLogin: true,
                });
                fail('Expected BadRequestException to be thrown');
            } catch (error) {
                expect(error).toBeInstanceOf(BadRequestException);
                expect((error as BadRequestException).message).toBe('Password is required to enable login for this user');
            }
        });

        it('D: allows enabling login (canLogin false->true) when password is provided', async () => {
            const existingUser = makeUserRecord({
                id: 16,
                role: 'VIEWER',
                canLogin: false,
                passwordHash: null,
            });
            const updatedUser = makeUserRecord({
                id: 16,
                role: 'VIEWER',
                canLogin: true,
                passwordHash: 'new-hash',
            });

            prisma.user.findUnique
                .mockResolvedValueOnce(existingUser)
                .mockResolvedValueOnce(updatedUser);
            prisma.user.update.mockResolvedValueOnce({});

            const result = await service.update(16, {
                canLogin: true,
                password: 'NewPassword123',
            });

            expect(prisma.user.update).toHaveBeenCalledWith({
                where: { id: 16 },
                data: expect.objectContaining({
                    canLogin: true,
                    passwordHash: 'hashed-password',
                }),
            });
            expect(result.canLogin).toBe(true);
        });
    });

    describe('SSO/Entra ID user handling', () => {
        it('F: allows role change for SSO user without password (canLogin already true, no passwordHash required)', async () => {
            const ssoUser = makeUserRecord({
                id: 17,
                role: 'VIEWER',
                canLogin: true,
                passwordHash: null,
            });
            const updatedUser = makeUserRecord({
                id: 17,
                role: 'USER',
                canLogin: true,
                passwordHash: null,
            });

            prisma.user.findUnique
                .mockResolvedValueOnce(ssoUser)
                .mockResolvedValueOnce(updatedUser);
            prisma.user.update.mockResolvedValueOnce({});

            const result = await service.update(17, {
                role: 'USER',
                canLogin: true,
            });

            expect(prisma.user.update).toHaveBeenCalledWith({
                where: { id: 17 },
                data: expect.objectContaining({
                    role: 'USER',
                    canLogin: true,
                }),
            });
            expect(result.role).toBe('USER');
        });
    });
});
