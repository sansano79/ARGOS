import { IsString, IsNotEmpty, IsOptional, IsBoolean, MaxLength, IsArray } from 'class-validator';

export class CreateSubscriptionDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(191)
  vendor: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(191)
  product: string;

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  versions?: string[];

  @IsBoolean()
  @IsOptional()
  isActive?: boolean;
}
