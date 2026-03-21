import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { SamlStrategy } from './strategies/saml.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { SamlAuthGuard } from './guards/saml-auth.guard';
import { AzureOidcService } from './azure-oidc.service';
import { LocalSignupService } from './local-signup.service';
import { NotificationModule } from '../modules/notification/notification.module';
import { PasswordResetModule } from '../modules/password-reset/password-reset.module';

@Module({
  imports: [
    PassportModule,
    ConfigModule,
    NotificationModule,
    PasswordResetModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: config.get<string>('JWT_EXPIRATION', '24h') },
      }),
    }),
  ],
  providers: [AuthService, JwtStrategy, LocalStrategy, SamlStrategy, JwtAuthGuard, RolesGuard, SamlAuthGuard, AzureOidcService, LocalSignupService],
  controllers: [AuthController],
  exports: [AuthService, JwtAuthGuard, RolesGuard],
})
export class AuthModule { }
