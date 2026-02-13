import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

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

    if (!user || !user.isActive) {
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

  async login(user: any) {
    const payload = { sub: user.id, email: user.email, role: user.role };
    return {
      access_token: this.jwtService.sign(payload),
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
    };
  }

  private async recordAttempt(email: string, success: boolean) {
    await this.prisma.loginAttempt.create({
      data: { email, ipAddress: '0.0.0.0', success },
    });
  }
}
