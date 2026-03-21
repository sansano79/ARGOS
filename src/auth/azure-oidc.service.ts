import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as oidc from 'openid-client';
import { PrismaService } from '../prisma/prisma.service';

const parseJsonObject = (raw: string | undefined) => {
  if (!raw) return {};
  try {
    const obj = JSON.parse(raw);
    if (obj && typeof obj === 'object') return obj;
    return {};
  } catch {
    return {};
  }
};

const normalizeRole = (role: string) => String(role || '').trim().toUpperCase();
const roleRank = (role: string) => ({ ADMIN: 4, VIEWER: 3, USER: 2, SUBSCRIBER: 1 }[normalizeRole(role)] || 0);

const toArray = (v: any) => {
  if (!v) return [];
  if (Array.isArray(v)) return v.map(String);
  return [String(v)];
};

const firstTruthy = (...vals: Array<any>) => vals.find((v) => v != null && String(v).trim().length > 0);

@Injectable()
export class AzureOidcService {
  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  isEnabled() {
    return this.config.get<string>('AZURE_OIDC_ENABLED') === 'true';
  }

  private getTenantId() {
    const tenantId = (this.config.get<string>('AZURE_TENANT_ID') || '').trim();
    if (!tenantId) throw new Error('AZURE_TENANT_ID missing');
    return tenantId;
  }

  private getRedirectUri() {
    const redirectUri = (this.config.get<string>('AZURE_OIDC_REDIRECT_URI') || '').trim();
    if (!redirectUri) throw new Error('AZURE_OIDC_REDIRECT_URI missing');
    return redirectUri;
  }

  private getClientId() {
    const clientId = (this.config.get<string>('AZURE_OIDC_CLIENT_ID') || '').trim();
    if (!clientId) throw new Error('AZURE_OIDC_CLIENT_ID missing');
    return clientId;
  }

  private getClientSecret() {
    const clientSecret = (this.config.get<string>('AZURE_OIDC_CLIENT_SECRET') || '').trim();
    if (!clientSecret) throw new Error('AZURE_OIDC_CLIENT_SECRET missing');
    return clientSecret;
  }

  private async getConfig() {
    const tenantId = this.getTenantId();
    const server = new URL(`https://login.microsoftonline.com/${tenantId}/v2.0`);
    const clientId = this.getClientId();
    const clientSecret = this.getClientSecret();
    return oidc.discovery(server, clientId, undefined, oidc.ClientSecretPost(clientSecret));
  }

  async createLoginRequest() {
    const codeVerifier = oidc.randomPKCECodeVerifier();
    const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    return { codeVerifier, codeChallenge, state, nonce };
  }

  async buildAuthorizationUrl(params: { codeChallenge: string; state: string; nonce: string }) {
    const config = await this.getConfig();
    const url = oidc.buildAuthorizationUrl(config, {
      redirect_uri: this.getRedirectUri(),
      scope: 'openid profile email',
      response_type: 'code',
      response_mode: 'query',
      code_challenge: params.codeChallenge,
      code_challenge_method: 'S256',
      state: params.state,
      nonce: params.nonce,
    });
    return url.toString();
  }

  async handleCallback(params: {
    code: string;
    state: string;
    expectedState: string;
    codeVerifier: string;
    nonce: string;
  }) {
    if (params.state !== params.expectedState) throw new UnauthorizedException('Invalid state');

    const redirectUri = this.getRedirectUri();
    const config = await this.getConfig();
    const currentUrl = new URL(redirectUri);
    currentUrl.searchParams.set('code', params.code);
    currentUrl.searchParams.set('state', params.state);
    const tokenSet = await oidc.authorizationCodeGrant(
      config,
      currentUrl,
      {
        expectedState: params.expectedState,
        expectedNonce: params.nonce,
        pkceCodeVerifier: params.codeVerifier,
      },
      { redirect_uri: redirectUri },
    );
    const claims: any = tokenSet.claims() || {};

    const azureAppRoles = toArray(claims?.roles).map((r) => normalizeRole(r)).filter(Boolean);
    const email = firstTruthy(
      claims?.email,
      claims?.preferred_username,
      claims?.upn,
      claims?.unique_name,
    );
    if (!email) throw new UnauthorizedException('Missing email claim');

    const name = firstTruthy(claims?.name, claims?.given_name, email);
    const oid = firstTruthy(claims?.oid, claims?.sub);
    const groups = toArray(claims?.groups).map((g) => String(g).trim()).filter(Boolean);

    const roleFromAppRoles = azureAppRoles
      .filter((r) => ['ADMIN', 'VIEWER', 'USER', 'SUBSCRIBER'].includes(r))
      .sort((a, b) => roleRank(b) - roleRank(a))[0];

    const groupRoleMap = parseJsonObject(this.config.get<string>('AZURE_OIDC_GROUP_ROLE_MAP'));
    const rolesFromGroups = groups.map((g) => normalizeRole(groupRoleMap[g] || '')).filter(Boolean);

    const role =
      roleFromAppRoles ||
      rolesFromGroups.sort((a, b) => roleRank(b) - roleRank(a))[0] ||
      normalizeRole(this.config.get<string>('AZURE_OIDC_DEFAULT_ROLE') || 'USER');

    if (!['ADMIN', 'VIEWER', 'USER', 'SUBSCRIBER'].includes(role)) {
      throw new UnauthorizedException('Invalid role mapping');
    }

    const isSubscriber = role === 'SUBSCRIBER';

    const user = await this.prisma.user.upsert({
      where: { email: String(email).toLowerCase() },
      update: {
        name: String(name),
        role,
        authProvider: 'AZURE_OIDC',
        externalId: oid ? String(oid) : null,
        isSubscriber,
        canLogin: true,
        isActive: true,
        lastLoginAt: new Date(),
      },
      create: {
        email: String(email).toLowerCase(),
        name: String(name),
        role,
        authProvider: 'AZURE_OIDC',
        externalId: oid ? String(oid) : null,
        isSubscriber,
        canLogin: true,
        isActive: true,
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isSubscriber: true,
        canLogin: true,
        isActive: true,
        authProvider: true,
      },
    });

    if (!user.isActive || !user.canLogin) throw new UnauthorizedException('User is disabled');
    return user;
  }
}
