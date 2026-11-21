import { Type } from 'class-transformer';
import {
  ArrayMaxSize,
  IsArray,
  IsBoolean,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  MaxLength,
  Min,
} from 'class-validator';

export class UpdateDefenderConfigDto {
  @IsOptional() @IsString() @MaxLength(64) tenantId?: string;
  @IsOptional() @IsString() @MaxLength(64) clientId?: string;
  @IsOptional() @IsString() @MaxLength(1024) clientSecret?: string;
  @IsOptional() @IsString() @MaxLength(255) baseUrl?: string;

  @IsOptional() @IsArray() @ArrayMaxSize(20) @IsString({ each: true }) @MaxLength(128, { each: true })
  serverTags?: string[];

  @IsOptional() @IsArray() @ArrayMaxSize(20) @IsString({ each: true }) @MaxLength(64, { each: true })
  serverOsPlatforms?: string[];

  @IsOptional() @Type(() => Number) @IsInt() @Min(1) teamId?: number;
  @IsOptional() @IsBoolean() isActive?: boolean;
  @IsOptional() @IsBoolean() autoSyncEnabled?: boolean;
  @IsOptional() @Type(() => Number) @IsInt() fullSyncIntervalHours?: number;
  @IsOptional() @Type(() => Number) @IsInt() deltaSyncIntervalHours?: number;
  @IsOptional() @Type(() => Number) @IsInt() requestsPerMinute?: number;
  @IsOptional() @Type(() => Number) @IsInt() maxDevicesPerRun?: number;
  @IsOptional() @Type(() => Number) @IsInt() staleDeviceDays?: number;
}

export class RequestDefenderSyncDto {
  @IsIn(['full', 'delta']) mode!: 'full' | 'delta';
}
