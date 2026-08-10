import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import crypto from 'crypto';
import { getTestMfaBypassStartupStatus, shouldBypassMfaForUser } from './test-mfa-bypass.util';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  private getMfaKey(): Buffer {
    const raw = process.env.MFA_ENCRYPTION_KEY || '';
    let key: Buffer;
    try {
      key = Buffer.from(raw, 'base64');
    } catch {
      throw new UnauthorizedException('MFA encryption key invalid');
    }
    if (key.length !== 32) throw new UnauthorizedException('MFA encryption key invalid');
    return key;
  }

  private encryptMfaSecret(secret: string) {
    const key = this.getMfaKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      enc: enc.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
    };
  }

  private decryptMfaSecret(enc: string, iv: string, tag: string) {
    const key = this.getMfaKey();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
    decipher.setAuthTag(Buffer.from(tag, 'base64'));
    const dec = Buffer.concat([decipher.update(Buffer.from(enc, 'base64')), decipher.final()]);
    return dec.toString('utf8');
  }

  private signMfaToken(user: { id: number; email: string }) {
    const payload = { sub: user.id, email: user.email, purpose: 'mfa' };
    return this.jwtService.sign(payload, { expiresIn: process.env.MFA_TOKEN_EXPIRATION || '10m' });
  }

  private verifyMfaToken(token: string) {
    const payload: any = this.jwtService.verify(token);
    if (!payload || payload.purpose !== 'mfa' || !payload.sub) {
      throw new UnauthorizedException('Invalid MFA token');
    }
    return payload;
  }

  async validateUser(email: string, password: string): Promise<any> {
    // Rate limiting check
    const recentAttempts = await this.prisma.loginAttempt.count({
      where: {
        email,
        attemptedAt: { gte: new Date(Date.now() - 15 * 60 * 1000) },
        success: false,
      },
    });

    if (recentAttempts >= 5) {
      throw new UnauthorizedException('Too many login attempts. Try again in 15 minutes.');
    }

    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user || !user.isActive || !user.canLogin || user.authProvider !== 'LOCAL' || !user.passwordHash) {
      await this.recordAttempt(email, false);
      return null;
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      await this.recordAttempt(email, false);
      return null;
    }

    await this.recordAttempt(email, true);
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    const { passwordHash, ...result } = user;
    return result;
  }

  async issueAccessToken(user: any) {
    const payload = { sub: user.id, email: user.email, role: user.role };
    return {
      access_token: this.jwtService.sign(payload),
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        isSubscriber: !!user.isSubscriber,
      },
    };
  }

  async loginLocal(user: any) {
    if (!user || user.authProvider !== 'LOCAL') {
      throw new UnauthorizedException('Invalid credentials');
    }
    if (shouldBypassMfaForUser(user, {
      occEnv: process.env.OCC_ENV,
      enabled: process.env.MFA_TEST_BYPASS_ENABLED,
      emails: process.env.MFA_TEST_BYPASS_EMAILS,
    })) {
      const ipAddress = String(user?.loginContext?.ipAddress || '0.0.0.0');
      this.logger.warn(`TEST_MFA_BYPASS_USED email=${String(user.email || '').toLowerCase()} ip=${ipAddress} timestamp=${new Date().toISOString()}`);
      return this.issueAccessToken(user);
    }

    if (!user.mfaEnabled) {
      return {
        mfaEnrollRequired: true,
        mfaToken: this.signMfaToken(user),
        user: { email: user.email, name: user.name },
      };
    }
    return {
      mfaRequired: true,
      mfaToken: this.signMfaToken(user),
      user: { email: user.email, name: user.name },
    };
  }

  async mfaSetup(req: any) {
    const token = String(req?.body?.mfaToken || '').trim();
    if (!token) throw new UnauthorizedException('Missing MFA token');
    const payload = this.verifyMfaToken(token);
    const userId = Number(payload.sub);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, authProvider: true, isActive: true, canLogin: true },
    });
    if (!user || !user.isActive || !user.canLogin || user.authProvider !== 'LOCAL') {
      throw new UnauthorizedException('User not allowed');
    }

    const secret = authenticator.generateSecret();
    const issuer = process.env.MFA_ISSUER || 'OCC-TVM';
    const otpauthUrl = authenticator.keyuri(user.email, issuer, secret);
    const qrDataUrl = await QRCode.toDataURL(otpauthUrl);

    const enc = this.encryptMfaSecret(secret);
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        mfaSecretEnc: enc.enc,
        mfaSecretIv: enc.iv,
        mfaSecretTag: enc.tag,
      },
    });

    return { issuer, otpauthUrl, qrDataUrl };
  }

  async mfaEnroll(req: any) {
    const token = String(req?.body?.mfaToken || '').trim();
    const code = String(req?.body?.code || '').trim().replace(/\s+/g, '');
    if (!token || !code) throw new UnauthorizedException('Missing MFA data');
    const payload = this.verifyMfaToken(token);
    const userId = Number(payload.sub);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, name: true, role: true, isSubscriber: true, isActive: true, canLogin: true, authProvider: true, mfaSecretEnc: true, mfaSecretIv: true, mfaSecretTag: true },
    });
    if (!user || !user.isActive || !user.canLogin || user.authProvider !== 'LOCAL') throw new UnauthorizedException('User not allowed');
    if (!user.mfaSecretEnc || !user.mfaSecretIv || !user.mfaSecretTag) throw new UnauthorizedException('MFA not initialized');

    const secret = this.decryptMfaSecret(user.mfaSecretEnc, user.mfaSecretIv, user.mfaSecretTag);
    const ok = authenticator.check(code, secret);
    if (!ok) throw new UnauthorizedException('Invalid MFA code');

    await this.prisma.user.update({
      where: { id: userId },
      data: { mfaEnabled: true, lastLoginAt: new Date() },
    });

    return this.issueAccessToken(user);
  }

  async mfaVerify(req: any) {
    const token = String(req?.body?.mfaToken || '').trim();
    const code = String(req?.body?.code || '').trim().replace(/\s+/g, '');
    if (!token || !code) throw new UnauthorizedException('Missing MFA data');
    const payload = this.verifyMfaToken(token);
    const userId = Number(payload.sub);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, name: true, role: true, isSubscriber: true, isActive: true, canLogin: true, authProvider: true, mfaEnabled: true, mfaSecretEnc: true, mfaSecretIv: true, mfaSecretTag: true },
    });
    if (!user || !user.isActive || !user.canLogin || user.authProvider !== 'LOCAL') throw new UnauthorizedException('User not allowed');
    if (!user.mfaEnabled) throw new UnauthorizedException('MFA not enabled');
    if (!user.mfaSecretEnc || !user.mfaSecretIv || !user.mfaSecretTag) throw new UnauthorizedException('MFA secret missing');

    const secret = this.decryptMfaSecret(user.mfaSecretEnc, user.mfaSecretIv, user.mfaSecretTag);
    const ok = authenticator.check(code, secret);
    if (!ok) throw new UnauthorizedException('Invalid MFA code');

    await this.prisma.user.update({
      where: { id: userId },
      data: { lastLoginAt: new Date() },
    });

    return this.issueAccessToken(user);
  }

  private async recordAttempt(email: string, success: boolean) {
    await this.prisma.loginAttempt.create({
      data: { email, ipAddress: '0.0.0.0', success },
    });
  }

  getTestMfaBypassStatus() {
    return getTestMfaBypassStartupStatus({
      occEnv: process.env.OCC_ENV,
      enabled: process.env.MFA_TEST_BYPASS_ENABLED,
      emails: process.env.MFA_TEST_BYPASS_EMAILS,
    });
  }
}
