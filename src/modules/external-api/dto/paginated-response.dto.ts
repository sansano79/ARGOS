import { ApiProperty } from '@nestjs/swagger';

export class PaginationMeta {
  @ApiProperty() total: number;
  @ApiProperty() page: number;
  @ApiProperty() limit: number;
  @ApiProperty() pages: number;
}

export class PaginatedResponse<T> {
  data: T[];
  @ApiProperty({ type: PaginationMeta })
  meta: PaginationMeta;

  static create<T>(data: T[], total: number, page: number, limit: number): PaginatedResponse<T> {
    return {
      data,
      meta: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    };
  }
}
