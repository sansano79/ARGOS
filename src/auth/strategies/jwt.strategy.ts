import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private prisma: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET'),
    });
  }

  async validate(payload: any) {
    const userId = Number(payload?.sub);
    if (!Number.isInteger(userId) || userId <= 0) throw new UnauthorizedException('Invalid token');
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, name: true, role: true, isSubscriber: true, isActive: true, canLogin: true, authProvider: true },
    });
    if (!user || !user.isActive || !user.canLogin) throw new UnauthorizedException('User disabled');
    return { id: user.id, email: user.email, name: user.name, role: user.role, isSubscriber: !!user.isSubscriber, authProvider: user.authProvider };
  }
}
