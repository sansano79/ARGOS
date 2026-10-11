import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class PaginationMeta {
  @ApiProperty() total: number;
  @ApiProperty() page: number;
  @ApiProperty() limit: number;
  @ApiProperty() pages: number;
  @ApiPropertyOptional() hasMore?: boolean;
  @ApiPropertyOptional() nextCursor?: string | null;
  @ApiPropertyOptional() watermark?: string | null;
}

export class PaginatedResponse<T> {
  data: T[];
  @ApiProperty({ type: PaginationMeta })
  meta: PaginationMeta;

  static create<T>(
    data: T[],
    total: number,
    page: number,
    limit: number,
    extraMeta?: { hasMore?: boolean; nextCursor?: string | null; watermark?: string | null },
  ): PaginatedResponse<T> {
    return {
      data,
      meta: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
        hasMore: extraMeta?.hasMore ?? (page * limit < total),
        nextCursor: extraMeta?.nextCursor ?? null,
        watermark: extraMeta?.watermark ?? null,
      },
    };
  }
}
