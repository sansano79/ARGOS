import { Injectable, ExecutionContext, NotFoundException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class SamlAuthGuard extends AuthGuard('saml') {
  constructor(private readonly config: ConfigService) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const enabledFlag = this.config.get<string>('AZURE_SAML_ENABLED') === 'true';
    const entryPoint = (this.config.get<string>('AZURE_SAML_ENTRY_POINT') || '').trim();
    const issuer = (this.config.get<string>('AZURE_SAML_ISSUER') || '').trim();
    const callbackUrl = (this.config.get<string>('AZURE_SAML_CALLBACK_URL') || '').trim();
    const cert = (this.config.get<string>('AZURE_SAML_CERT') || '').trim();
    const enabled = enabledFlag && !!entryPoint && !!issuer && !!callbackUrl && !!cert;
    if (!enabled) throw new NotFoundException();
    return (await super.canActivate(context)) as boolean;
  }
}
