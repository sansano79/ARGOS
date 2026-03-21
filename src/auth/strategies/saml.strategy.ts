import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Strategy, Profile } from 'passport-saml';
import { PrismaService } from '../../prisma/prisma.service';

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

const firstTruthy = (...vals: Array<any>) => vals.find((v) => v != null && String(v).trim().length > 0);

const toArray = (v: any) => {
  if (!v) return [];
  if (Array.isArray(v)) return v.map(String);
  return [String(v)];
};

const pickFromClaims = (profile: any, keys: string[]) => {
  for (const k of keys) {
    const v = profile?.[k];
    if (v == null) continue;
    const arr = toArray(v).filter(Boolean);
    if (arr.length > 0) return arr.length === 1 ? arr[0] : arr;
  }
  return undefined;
};

const normalizePem = (v: string | undefined) => (v ? String(v).replace(/\\n/g, '\n').trim() : '');
const dummyCert = '-----BEGIN CERTIFICATE-----\nDUMMY\n-----END CERTIFICATE-----';

@Injectable()
export class SamlStrategy extends PassportStrategy(Strategy, 'saml') {
  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    const enabled = config.get<string>('AZURE_SAML_ENABLED') === 'true';
    const entryPoint = config.get<string>('AZURE_SAML_ENTRY_POINT') || '';
    const issuer = config.get<string>('AZURE_SAML_ISSUER') || '';
    const callbackUrl = config.get<string>('AZURE_SAML_CALLBACK_URL') || '';
    const cert = enabled ? normalizePem(config.get<string>('AZURE_SAML_CERT')) : dummyCert;
    if (enabled && (!entryPoint || !issuer || !callbackUrl || !cert)) {
      throw new Error('Azure SAML enabled but config is incomplete');
    }
    super({
      entryPoint: entryPoint || 'https://invalid.local/saml',
      issuer: issuer || 'invalid-issuer',
      callbackUrl: callbackUrl || 'https://invalid.local/api/auth/saml/acs',
      cert,
      wantAuthnResponseSigned: true,
      wantAssertionsSigned: true,
      signatureAlgorithm: 'sha256',
      identifierFormat: undefined,
      disableRequestedAuthnContext: true,
    });
  }

  async validate(profile: Profile) {
    const raw: any = profile as any;

    const email = firstTruthy(
      pickFromClaims(raw, [
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        'email',
        'mail',
        'upn',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
      ]),
      raw?.nameID,
    );
    if (!email) throw new UnauthorizedException('SAML profile missing email');

    const displayName = firstTruthy(
      pickFromClaims(raw, [
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        'displayName',
        'name',
      ]),
      email,
    );

    const groups = toArray(pickFromClaims(raw, [
      'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
      'groups',
    ])).map((g) => String(g).trim()).filter(Boolean);

    const groupRoleMap = parseJsonObject(this.config.get<string>('AZURE_SAML_GROUP_ROLE_MAP'));
    const mappedRoles = groups.map((g) => normalizeRole(groupRoleMap[g] || '')).filter(Boolean);
    const role = mappedRoles.sort((a, b) => roleRank(b) - roleRank(a))[0] || normalizeRole(this.config.get<string>('AZURE_SAML_DEFAULT_ROLE') || 'USER');

    if (!['ADMIN', 'VIEWER', 'USER', 'SUBSCRIBER'].includes(role)) {
      throw new UnauthorizedException('Invalid role mapping');
    }

    const isSubscriber = role === 'SUBSCRIBER';

    const user = await this.prisma.user.upsert({
      where: { email: String(email).toLowerCase() },
      update: {
        name: String(displayName),
        role,
        authProvider: 'AZURE_SAML',
        isSubscriber,
        canLogin: true,
        isActive: true,
        lastLoginAt: new Date(),
      },
      create: {
        email: String(email).toLowerCase(),
        name: String(displayName),
        role,
        authProvider: 'AZURE_SAML',
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
