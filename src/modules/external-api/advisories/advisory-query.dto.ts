import { Type } from "class-transformer";
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsIn,
  IsNotEmpty,
  IsString,
  Matches,
  MaxLength,
  ValidateNested,
} from "class-validator";
import { ApiProperty } from "@nestjs/swagger";
import { ECOSYSTEMS } from "./advisory-normalizer";

export class AdvisoryPackageDto {
  @ApiProperty({ enum: [...ECOSYSTEMS] })
  @IsIn(ECOSYSTEMS)
  ecosystem: string;

  @ApiProperty({ example: "requests", maxLength: 256 })
  @IsString()
  @IsNotEmpty()
  @MaxLength(256)
  @Matches(/^\S+$/)
  name: string;

  @ApiProperty({
    example: "2.0.0",
    description: "Exact public package version",
    maxLength: 128,
  })
  @IsString()
  @MaxLength(128)
  @Matches(/^v?\d[0-9A-Za-z.!+_~-]*$/)
  version: string;
}

export class AdvisoryQueryDto {
  @ApiProperty({ type: [AdvisoryPackageDto], minItems: 1, maxItems: 100 })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(100)
  @ValidateNested({ each: true })
  @Type(() => AdvisoryPackageDto)
  packages: AdvisoryPackageDto[];
}
