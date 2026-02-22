import {
    Controller,
    Post,
    Get,
    Body,
    Param,
    HttpCode,
    HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam } from '@nestjs/swagger';
import { PasswordResetService } from './password-reset.service';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { UpdatePasswordDto } from './dto/update-password.dto';

@ApiTags('Auth — Password Reset')
@Controller('auth')
export class PasswordResetController {
    constructor(private readonly passwordResetService: PasswordResetService) { }

    /**
     * POST /api/auth/forgot-password
     * Solicita un enlace de recuperación de contraseña.
     * Siempre devuelve 200 con un mensaje genérico (sin revelar si el email existe).
     */
    @Post('forgot-password')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({
        summary: 'Solicitar recuperación de contraseña',
        description:
            'Envía un enlace de recuperación al email proporcionado si está registrado. ' +
            'La respuesta siempre es la misma para evitar enumeración de usuarios.',
    })
    @ApiResponse({
        status: 200,
        description: 'Mensaje genérico de éxito (independientemente de si el email existe)',
    })
    async forgotPassword(@Body() dto: ForgotPasswordDto) {
        return this.passwordResetService.requestReset(dto.email);
    }

    /**
     * GET /api/auth/reset-password/:token
     * Valida que el token exista y no haya expirado.
     */
    @Get('reset-password/:token')
    @ApiOperation({
        summary: 'Validar token de recuperación',
        description:
            'Verifica que el token sea válido y no haya expirado ni sido utilizado.',
    })
    @ApiParam({
        name: 'token',
        description: 'Token de recuperación recibido por email',
    })
    @ApiResponse({
        status: 200,
        description: 'Estado de validez del token',
    })
    async validateResetToken(@Param('token') token: string) {
        return this.passwordResetService.validateToken(token);
    }

    /**
     * POST /api/auth/update-password
     * Consume el token y actualiza la contraseña del usuario.
     */
    @Post('update-password')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({
        summary: 'Actualizar contraseña con token de recuperación',
        description:
            'Valida el token, actualiza la contraseña con hash bcrypt y marca el token como utilizado.',
    })
    @ApiResponse({
        status: 200,
        description: 'Contraseña actualizada exitosamente',
    })
    @ApiResponse({
        status: 400,
        description: 'Token inválido o expirado',
    })
    async updatePassword(@Body() dto: UpdatePasswordDto) {
        return this.passwordResetService.resetPassword(dto.token, dto.password);
    }
}
