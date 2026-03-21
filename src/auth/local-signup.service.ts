import { Injectable, Logger, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { NotificationService } from '../modules/notification/notification.service';
import { PasswordResetService } from '../modules/password-reset/password-reset.service';
import * as crypto from 'crypto';

@Injectable()
export class LocalSignupService {
  private readonly logger = new Logger(LocalSignupService.name);

  private readonly MAX_REQUESTS = 3;
  private readonly RATE_LIMIT_WINDOW_MINUTES = 30;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly notification: NotificationService,
    private readonly passwordReset: PasswordResetService,
  ) {}

  isEnabled() {
    return this.config.get<string>('LOCAL_SIGNUP_ENABLED') === 'true';
  }

  private getApproverEmail() {
    const email = (this.config.get<string>('LOCAL_SIGNUP_APPROVER_EMAIL') || '').trim().toLowerCase();
    if (!email) throw new Error('LOCAL_SIGNUP_APPROVER_EMAIL missing');
    return email;
  }

  private getExpiryMinutes() {
    const v = parseInt(this.config.get<string>('LOCAL_SIGNUP_EXPIRY_MINUTES', '60'), 10);
    return Number.isFinite(v) && v > 0 ? v : 60;
  }

  private getPublicBaseUrl() {
    const fromEnv = (this.config.get<string>('PUBLIC_BASE_URL') || '').trim();
    if (fromEnv) return fromEnv.replace(/\/+$/, '');
    const frontendBase = (this.config.get<string>('FRONTEND_BASE_URL') || this.config.get<string>('FRONTEND_URL') || '').trim();
    if (frontendBase) return frontendBase.replace(/\/+$/, '');
    return 'http://localhost:3000';
  }

  private hashToken(raw: string) {
    return crypto.createHash('sha256').update(raw).digest('hex');
  }

  private async checkRateLimit(email: string) {
    const windowStart = new Date(Date.now() - this.RATE_LIMIT_WINDOW_MINUTES * 60 * 1000);
    const count = await this.prisma.localSignupRequest.count({
      where: {
        requesterEmail: email,
        createdAt: { gt: windowStart },
      },
    });
    return count >= this.MAX_REQUESTS;
  }

  async createRequest(params: { email: string; name: string; requestIp?: string; userAgent?: string }) {
    if (!this.isEnabled()) throw new NotFoundException();

    const requesterEmail = String(params.email || '').trim().toLowerCase();
    const requesterName = String(params.name || '').trim();
    if (!requesterEmail || !requesterName) throw new UnauthorizedException();

    const rateLimited = await this.checkRateLimit(requesterEmail);
    if (rateLimited) {
      return { message: 'Si procede, se enviará una solicitud de aprobación.' };
    }

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = this.hashToken(rawToken);
    const expiresAt = new Date(Date.now() + this.getExpiryMinutes() * 60 * 1000);

    await this.prisma.localSignupRequest.create({
      data: {
        requesterEmail,
        requesterName,
        tokenHash,
        expiresAt,
        requestIp: params.requestIp || null,
        userAgent: params.userAgent || null,
      },
    });

    const base = this.getPublicBaseUrl();
    const approveUrl = `${base}/api/auth/local-signup/approve/${rawToken}`;
    const denyUrl = `${base}/api/auth/local-signup/deny/${rawToken}`;

    try {
      await this.notification.sendEmail(
        this.getApproverEmail(),
        'Aprobación de alta local — Servicios OCC',
        'local-signup-approval',
        {
          requesterEmail,
          requesterName,
          approveUrl,
          denyUrl,
          expiryMinutes: this.getExpiryMinutes(),
        },
      );
    } catch (e: any) {
      this.logger.error(`Failed to send local signup approval email: ${String(e?.message || e)}`);
    }

    return { message: 'Si procede, se enviará una solicitud de aprobación.' };
  }

  private async findPendingByRawToken(rawToken: string) {
    const tokenHash = this.hashToken(rawToken);
    const record = await this.prisma.localSignupRequest.findFirst({
      where: {
        tokenHash,
        status: 'PENDING',
        expiresAt: { gt: new Date() },
      },
    });
    if (!record) throw new NotFoundException();
    return record;
  }

  async approve(rawToken: string) {
    if (!this.isEnabled()) throw new NotFoundException();
    const record = await this.findPendingByRawToken(rawToken);
    const email = record.requesterEmail;

    await this.prisma.$transaction(async (tx) => {
      const existing = await tx.user.findUnique({ where: { email } });
      if (existing && existing.authProvider !== 'LOCAL') {
        throw new UnauthorizedException('User already exists with different auth');
      }
      if (existing) {
        await tx.user.update({
          where: { email },
          data: { name: record.requesterName, canLogin: true, isActive: true, authProvider: 'LOCAL' },
        });
      } else {
        await tx.user.create({
          data: {
            email,
            name: record.requesterName,
            role: 'USER',
            canLogin: true,
            isActive: true,
            authProvider: 'LOCAL',
          },
        });
      }

      await tx.localSignupRequest.update({
        where: { id: record.id },
        data: {
          status: 'APPROVED',
          decidedAt: new Date(),
          decidedBy: this.getApproverEmail(),
        },
      });
    });

    await this.passwordReset.requestReset(email);
    return { message: 'Aprobado. Se ha enviado un correo al usuario para establecer contraseña.' };
  }

  async deny(rawToken: string) {
    if (!this.isEnabled()) throw new NotFoundException();
    const record = await this.findPendingByRawToken(rawToken);

    await this.prisma.localSignupRequest.update({
      where: { id: record.id },
      data: {
        status: 'REJECTED',
        decidedAt: new Date(),
        decidedBy: this.getApproverEmail(),
      },
    });

    try {
      await this.notification.sendEmail(
        record.requesterEmail,
        'Solicitud de alta local — Servicios OCC',
        'local-signup-denied',
        { requesterName: record.requesterName },
      );
    } catch (e: any) {
      this.logger.error(`Failed to send local signup denied email: ${String(e?.message || e)}`);
    }

    return { message: 'Denegado.' };
  }
}

