import { IsString, IsNotEmpty, IsOptional, IsBoolean, MaxLength } from 'class-validator';

export class CreateSystemDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(191)
  name: string;

  @IsString()
  @IsOptional()
  @MaxLength(191)
  externalId?: string;

  @IsString()
  @IsOptional()
  @MaxLength(191)
  source?: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  @IsOptional()
  @MaxLength(191)
  hostname?: string;

  @IsString()
  @IsOptional()
  @MaxLength(191)
  fqdn?: string;

  @IsString()
  @IsOptional()
  @MaxLength(191)
  platform?: string;

  @IsString()
  @IsOptional()
  @MaxLength(191)
  osVersion?: string;

  @IsString()
  @IsOptional()
  @MaxLength(191)
  riskLevel?: string;

  @IsString()
  @IsOptional()
  @MaxLength(191)
  healthStatus?: string;

  @IsBoolean()
  @IsOptional()
  isSelected?: boolean;

  @IsBoolean()
  @IsOptional()
  isActive?: boolean;

  @IsString()
  @IsOptional()
  tags?: string;
}
