import { IsEmail, IsString, Length } from 'class-validator';

export class LocalSignupRequestDto {
  @IsEmail()
  email: string;

  @IsString()
  @Length(2, 120)
  name: string;
}

