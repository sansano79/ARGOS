import {
    Injectable,
    Logger,
    BadRequestException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import { NotificationService } from '../notification/notification.service';
import * as crypto from 'crypto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class PasswordResetService {
    private readonly logger = new Logger(PasswordResetService.name);

    /** Max reset requests per email within the rate-limit window */
    private readonly MAX_REQUESTS = 3;
    /** Rate-limit window in minutes */
    private readonly RATE_LIMIT_WINDOW_MINUTES = 15;
    /** Token expiry in minutes (default 20) */
    private readonly TOKEN_EXPIRY_MINUTES: number;
    /** Frontend base URL for building the reset link */
    private readonly FRONTEND_URL: string;
    /** Bcrypt salt rounds */
    private readonly BCRYPT_ROUNDS = 12;

    constructor(
        private readonly prisma: PrismaService,
        private readonly configService: ConfigService,
        private readonly notificationService: NotificationService,
    ) {
        this.TOKEN_EXPIRY_MINUTES = parseInt(
            this.configService.get<string>('PASSWORD_RESET_EXPIRY_MINUTES', '20'),
            10,
        );
        this.FRONTEND_URL = this.configService.get<string>(
            'FRONTEND_URL',
            'http://localhost:5173',
        );
    }

    // ──────────────────────────────────────────────────────────────
    // PUBLIC API
    // ──────────────────────────────────────────────────────────────

    /**
     * Request a password reset.
     * ALWAYS returns the same generic message to prevent email enumeration.
     */
    async requestReset(email: string): Promise<{ message: string }> {
        const normalizedEmail = email.toLowerCase().trim();
        const genericResponse = {
            message:
                'Si el correo está registrado, recibirás un enlace de recuperación en breve.',
        };

        // ── Rate limiting ───────────────────────────────────────────
        const isRateLimited = await this.checkRateLimit(normalizedEmail);
        if (isRateLimited) {
            this.logger.warn(
                `Rate limit exceeded for password reset: ${normalizedEmail}`,
            );
            // Return the same generic message so attackers can't distinguish
            return genericResponse;
        }

        // ── Check if user exists and can login ──────────────────────
        const user = await this.prisma.user.findUnique({
            where: { email: normalizedEmail },
        });

        if (!user || !user.isActive || !user.canLogin) {
            this.logger.log(
                `Password reset requested for unknown/inactive email: ${normalizedEmail}`,
            );
            return genericResponse;
        }

        // ── Generate cryptographic token ────────────────────────────
        const rawToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = this.hashToken(rawToken);

        const now = new Date();
        const expiresAt = new Date(
            now.getTime() + this.TOKEN_EXPIRY_MINUTES * 60 * 1000,
        );

        // ── Invalidate any existing unused tokens for this email ────
        await this.prisma.passwordReset.updateMany({
            where: {
                email: normalizedEmail,
                usedAt: null,
            },
            data: {
                usedAt: now, // mark as consumed so they can't be reused
            },
        });

        // ── Persist hashed token ────────────────────────────────────
        await this.prisma.passwordReset.create({
            data: {
                email: normalizedEmail,
                tokenHash,
                expiresAt,
            },
        });

        // ── Send reset email ────────────────────────────────────────
        const resetUrl = `${this.FRONTEND_URL}/reset-password/${rawToken}`;
        try {
            await this.notificationService.sendEmail(
                user.notificationEmail || user.email,
                'Recuperación de contraseña — Servicios OCC',
                'password-reset',
                {
                    recipientName: user.name,
                    resetUrl,
                    expiryMinutes: this.TOKEN_EXPIRY_MINUTES,
                },
            );
            this.logger.log(`Password reset email sent to ${normalizedEmail}`);
        } catch (error) {
            this.logger.error(
                `Failed to send password reset email to ${normalizedEmail}`,
                error,
            );
            // Don't leak errors to the client
        }

        return genericResponse;
    }

    /**
     * Validate a raw token (from the URL) without consuming it.
     * Returns the associated email if valid.
     */
    async validateToken(
        rawToken: string,
    ): Promise<{ valid: boolean; email?: string }> {
        const tokenHash = this.hashToken(rawToken);

        const record = await this.prisma.passwordReset.findFirst({
            where: {
                tokenHash,
                usedAt: null,
                expiresAt: { gt: new Date() },
            },
        });

        if (!record) {
            return { valid: false };
        }

        return { valid: true, email: record.email };
    }

    /**
     * Consume the token and update the user's password.
     */
    async resetPassword(
        rawToken: string,
        newPassword: string,
    ): Promise<{ message: string }> {
        const tokenHash = this.hashToken(rawToken);

        const record = await this.prisma.passwordReset.findFirst({
            where: {
                tokenHash,
                usedAt: null,
                expiresAt: { gt: new Date() },
            },
        });

        if (!record) {
            throw new BadRequestException(
                'El enlace de recuperación es inválido o ha expirado.',
            );
        }

        // ── Hash the new password ───────────────────────────────────
        const passwordHash = await bcrypt.hash(newPassword, this.BCRYPT_ROUNDS);

        // ── Update in a transaction ─────────────────────────────────
        await this.prisma.$transaction(async (tx) => {
            // Update user's password
            await tx.user.updateMany({
                where: { email: record.email },
                data: { passwordHash },
            });

            // Mark ALL tokens for this email as used (single-use + invalidate siblings)
            await tx.passwordReset.updateMany({
                where: {
                    email: record.email,
                    usedAt: null,
                },
                data: { usedAt: new Date() },
            });
        });

        this.logger.log(
            `Password successfully reset for user: ${record.email}`,
        );

        return { message: 'La contraseña ha sido actualizada correctamente.' };
    }

    // ──────────────────────────────────────────────────────────────
    // PRIVATE HELPERS
    // ──────────────────────────────────────────────────────────────

    /**
     * SHA-256 hash of a raw token string.
     */
    private hashToken(rawToken: string): string {
        return crypto.createHash('sha256').update(rawToken).digest('hex');
    }

    /**
     * Returns true if the email has exceeded the rate limit.
     */
    private async checkRateLimit(email: string): Promise<boolean> {
        const windowStart = new Date(
            Date.now() - this.RATE_LIMIT_WINDOW_MINUTES * 60 * 1000,
        );

        const recentRequests = await this.prisma.passwordReset.count({
            where: {
                email,
                createdAt: { gte: windowStart },
            },
        });

        return recentRequests >= this.MAX_REQUESTS;
    }
}
