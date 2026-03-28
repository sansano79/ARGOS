import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsOptional, IsArray, IsDateString, MinLength } from 'class-validator';

export class CreateApiKeyDto {
  @ApiProperty({ description: 'Descriptive name for the API key' })
  @IsString()
  @MinLength(1)
  name: string;

  @ApiPropertyOptional({
    description: 'Scopes granted to this key',
    example: ['vulnerabilities:read', 'products:read', 'catalog:read', 'collector:read', 'reports:read'],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  scopes?: string[];

  @ApiPropertyOptional({ description: 'Expiration date (ISO 8601). Null = never expires.' })
  @IsOptional()
  @IsDateString()
  expiresAt?: string;
}

export class UpdateApiKeyDto {
  @ApiPropertyOptional({ description: 'Descriptive name for the API key' })
  @IsOptional()
  @IsString()
  @MinLength(1)
  name?: string;

  @ApiPropertyOptional({ description: 'Scopes granted to this key' })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  scopes?: string[];

  @ApiPropertyOptional({ description: 'Active status' })
  @IsOptional()
  isActive?: boolean;
}
