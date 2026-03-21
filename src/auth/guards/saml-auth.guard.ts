import { Injectable, ExecutionContext, NotFoundException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class SamlAuthGuard extends AuthGuard('saml') {
  constructor(private readonly config: ConfigService) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const enabled = this.config.get<string>('AZURE_SAML_ENABLED') === 'true';
    if (!enabled) throw new NotFoundException();
    return (await super.canActivate(context)) as boolean;
  }
}
