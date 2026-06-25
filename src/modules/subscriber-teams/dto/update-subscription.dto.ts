import { IsString, IsOptional, IsBoolean, IsArray, MaxLength } from 'class-validator';

export class UpdateSubscriptionDto {
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  versions?: string[];

  @IsBoolean()
  @IsOptional()
  isActive?: boolean;

  @IsString()
  @IsOptional()
  @MaxLength(191)
  vendor?: string;

  @IsString()
  @IsOptional()
  @MaxLength(191)
  product?: string;
}
