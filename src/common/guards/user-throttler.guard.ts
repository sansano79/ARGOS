import { Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

/**
 * Throttler por usuario autenticado (req.user.id). Detrás de nginx sin
 * `trust proxy`, req.ip es el del proxy y agruparía a todos los usuarios.
 * Debe ir después de JwtAuthGuard.
 */
@Injectable()
export class UserThrottlerGuard extends ThrottlerGuard {
  protected async getTracker(req: Record<string, any>): Promise<string> {
    const userId = req?.user?.id;
    return userId ? `user:${userId}` : `ip:${req?.ip ?? 'unknown'}`;
  }
}
