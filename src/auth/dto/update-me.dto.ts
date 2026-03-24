import { IsBoolean, IsDateString, IsEmail, IsOptional, IsString, Length } from 'class-validator';

export class UpdateMeDto {
  @IsOptional()
  @IsString()
  @Length(2, 120)
  name?: string;

  @IsOptional()
  @IsEmail()
  notificationEmail?: string;

  @IsOptional()
  @IsBoolean()
  canReceiveNotifications?: boolean;

  @IsOptional()
  @IsBoolean()
  notificationsPaused?: boolean;

  @IsOptional()
  @IsDateString()
  notificationsPausedUntil?: string;

  @IsOptional()
  @IsString()
  @Length(0, 120)
  contactPerson?: string;

  @IsOptional()
  @IsString()
  @Length(0, 120)
  department?: string;

  @IsOptional()
  @IsString()
  @Length(0, 60)
  phone?: string;
}
