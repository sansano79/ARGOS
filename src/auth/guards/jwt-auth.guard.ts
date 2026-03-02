import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
    constructor(private configService: ConfigService) {
        super();
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const bypassAuth = this.configService.get<string>('BYPASS_AUTH') === 'true';
        if (bypassAuth) {
            const request = context.switchToHttp().getRequest();
            request.user = { id: 1, email: 'admin@servicios-occ.local', role: 'ADMIN', name: 'Dev Admin' };
            return true;
        }
        return super.canActivate(context) as boolean;
    }
}
