import { Controller, Post, UseGuards, Request, Get, Res, NotFoundException, UnauthorizedException, Logger } from '@nestjs/common';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { SamlAuthGuard } from './guards/saml-auth.guard';
import { SamlStrategy } from './strategies/saml.strategy';
import { AzureOidcService } from './azure-oidc.service';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
    private readonly samlStrategy: SamlStrategy,
    private readonly azureOidc: AzureOidcService,
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
    const enabled = this.config.get<string>('AZURE_SAML_ENABLED') === 'true';
    if (!enabled) throw new NotFoundException();
    const signingCertRaw = this.config.get<string>('AZURE_SAML_SIGNING_CERT') || undefined;
    const signingCert = signingCertRaw ? String(signingCertRaw).replace(/\\n/g, '\n').trim() : undefined;
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

  @Get('azure/login')
  async azureLogin(@Res() res: Response) {
    if (!this.azureOidc.isEnabled()) throw new NotFoundException();
    let url = '';
    let codeVerifier = '';
    let state = '';
    let nonce = '';
    try {
      const req = await this.azureOidc.createLoginRequest();
      codeVerifier = req.codeVerifier;
      state = req.state;
      nonce = req.nonce;
      url = await this.azureOidc.buildAuthorizationUrl({ codeChallenge: req.codeChallenge, state, nonce });
    } catch (e: any) {
      this.logger.error(`Azure OIDC login init failed: ${String(e?.message || e)}`);
      throw new UnauthorizedException('Azure login no disponible');
    }

    const cookieSecure = this.config.get<string>('AZURE_OIDC_COOKIE_SECURE') !== 'false';
    const domain = (this.config.get<string>('AZURE_OIDC_COOKIE_DOMAIN') || '').trim() || undefined;

    res.cookie('occ_oidc_state', state, { httpOnly: true, secure: cookieSecure, sameSite: 'lax', path: '/api/auth/azure', domain });
    res.cookie('occ_oidc_verifier', codeVerifier, { httpOnly: true, secure: cookieSecure, sameSite: 'lax', path: '/api/auth/azure', domain });
    res.cookie('occ_oidc_nonce', nonce, { httpOnly: true, secure: cookieSecure, sameSite: 'lax', path: '/api/auth/azure', domain });
    return res.redirect(url);
  }

  @Get('azure/callback')
  async azureCallback(@Request() req, @Res() res: Response) {
    if (!this.azureOidc.isEnabled()) throw new NotFoundException();
    const code = String(req?.query?.code || '').trim();
    const state = String(req?.query?.state || '').trim();
    const expectedState = String(req?.cookies?.occ_oidc_state || '').trim();
    const codeVerifier = String(req?.cookies?.occ_oidc_verifier || '').trim();
    const nonce = String(req?.cookies?.occ_oidc_nonce || '').trim();

    if (!code || !state || !expectedState || !codeVerifier || !nonce) {
      throw new UnauthorizedException('Missing OIDC callback data');
    }

    let auth: any;
    try {
      const user = await this.azureOidc.handleCallback({ code, state, expectedState, codeVerifier, nonce });
      auth = await this.authService.issueAccessToken(user);
    } catch (e: any) {
      this.logger.error(`Azure OIDC callback failed: ${String(e?.message || e)}`);
      throw new UnauthorizedException('Azure login falló');
    }
    const frontendBase = this.config.get<string>('FRONTEND_BASE_URL') || '/';
    const safeBase = frontendBase.endsWith('/') ? frontendBase : `${frontendBase}/`;

    const cookieSecure = this.config.get<string>('AZURE_OIDC_COOKIE_SECURE') !== 'false';
    const domain = (this.config.get<string>('AZURE_OIDC_COOKIE_DOMAIN') || '').trim() || undefined;
    res.clearCookie('occ_oidc_state', { path: '/api/auth/azure', domain, secure: cookieSecure, sameSite: 'lax' });
    res.clearCookie('occ_oidc_verifier', { path: '/api/auth/azure', domain, secure: cookieSecure, sameSite: 'lax' });
    res.clearCookie('occ_oidc_nonce', { path: '/api/auth/azure', domain, secure: cookieSecure, sameSite: 'lax' });

    return res.redirect(`${safeBase}#token=${encodeURIComponent(auth.access_token)}`);
  }
}
