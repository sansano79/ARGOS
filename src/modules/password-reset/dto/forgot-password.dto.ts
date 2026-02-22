import { IsEmail, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ForgotPasswordDto {
    @ApiProperty({
        description: 'Email del usuario que solicita la recuperación',
        example: 'admin@occ.local',
    })
    @IsEmail({}, { message: 'Debe ser un correo electrónico válido' })
    @IsNotEmpty({ message: 'El email es obligatorio' })
    email: string;
}
