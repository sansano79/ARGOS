import { IsNotEmpty, IsString, MinLength, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdatePasswordDto {
    @ApiProperty({
        description: 'Token de recuperación recibido por email',
        example: 'a1b2c3d4e5f6...',
    })
    @IsString()
    @IsNotEmpty({ message: 'El token es obligatorio' })
    token: string;

    @ApiProperty({
        description: 'Nueva contraseña (mínimo 8 caracteres, debe incluir mayúscula, minúscula y número)',
        example: 'NuevaPass123',
    })
    @IsString()
    @IsNotEmpty({ message: 'La contraseña es obligatoria' })
    @MinLength(8, { message: 'La contraseña debe tener al menos 8 caracteres' })
    @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
        message: 'La contraseña debe incluir al menos una mayúscula, una minúscula y un número',
    })
    password: string;
}
