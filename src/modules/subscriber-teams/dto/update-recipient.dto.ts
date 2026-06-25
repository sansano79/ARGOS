import { IsString, IsEmail, IsOptional, IsBoolean, MaxLength, IsIn } from 'class-validator';

const RECIPIENT_TYPES = ['USER', 'MAILBOX', 'DISTRIBUTION_LIST', 'EXTERNAL_CONTACT'] as const;

export class UpdateRecipientDto {
  @IsEmail()
  @IsOptional()
  email?: string;

  @IsString()
  @IsOptional()
  @MaxLength(191)
  name?: string;

  @IsString()
  @IsIn(RECIPIENT_TYPES)
  @IsOptional()
  type?: string;

  @IsString()
  @IsOptional()
  language?: string;

  @IsString()
  @IsOptional()
  timezone?: string;

  @IsBoolean()
  @IsOptional()
  isActive?: boolean;
}
