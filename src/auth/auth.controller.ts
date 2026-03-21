import { Controller, Post, UseGuards, Request, Get, Res } from '@nestjs/common';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { SamlAuthGuard } from './guards/saml-auth.guard';
import { SamlStrategy } from './strategies/saml.strategy';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
    private readonly samlStrategy: SamlStrategy,
  ) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req) {
    return this.authService.loginLocal(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @Get('profile')
  getProfile(@Request() req) {
    return req.user;
  }

  @UseGuards(SamlAuthGuard)
  @Get('saml/login')
  async samlLogin() {
    return;
  }

  @UseGuards(SamlAuthGuard)
  @Post('saml/acs')
  async samlAcs(@Request() req, @Res() res: Response) {
    const auth = await this.authService.issueAccessToken(req.user);
    const frontendBase = this.config.get<string>('FRONTEND_BASE_URL') || '/';
    const safeBase = frontendBase.endsWith('/') ? frontendBase : `${frontendBase}/`;
    return res.redirect(`${safeBase}#token=${encodeURIComponent(auth.access_token)}`);
  }

  @Get('saml/metadata')
  async samlMetadata(@Res() res: Response) {
    const signingCert = this.config.get<string>('AZURE_SAML_SIGNING_CERT') || undefined;
    const xml = (this.samlStrategy as any).generateServiceProviderMetadata(undefined, signingCert);
    res.setHeader('Content-Type', 'application/xml');
    return res.send(xml);
  }

  @Post('mfa/setup')
  async mfaSetup(@Request() req) {
    return this.authService.mfaSetup(req);
  }

  @Post('mfa/enroll')
  async mfaEnroll(@Request() req) {
    return this.authService.mfaEnroll(req);
  }

  @Post('mfa/verify')
  async mfaVerify(@Request() req) {
    return this.authService.mfaVerify(req);
  }
}
