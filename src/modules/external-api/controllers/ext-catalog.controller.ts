import {
  Controller, Get, Query, UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiSecurity, ApiOperation } from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import { ApiKeyGuard } from '../guards/api-key.guard';
import { ApiKeyScopes } from '../decorators/api-key-scopes.decorator';
import { ExternalApiService } from '../external-api.service';
import { PaginationQueryDto } from '../dto/vulnerability-query.dto';

@ApiTags('External API — Catalog')
@ApiSecurity('api-key')
@Controller('v1')
@UseGuards(ApiKeyGuard, ThrottlerGuard)
@ApiKeyScopes('catalog:read')
export class ExtCatalogController {
  constructor(private readonly service: ExternalApiService) {}

  @Get('manufacturers')
  @ApiOperation({ summary: 'List software manufacturers/vendors' })
  async listManufacturers(@Query() query: PaginationQueryDto) {
    return this.service.listManufacturers(query);
  }

  @Get('tags')
  @ApiOperation({ summary: 'List vulnerability tags' })
  async listTags() {
    return this.service.listTags();
  }

  @Get('kev')
  @ApiOperation({ summary: 'List known exploited vulnerabilities (CISA KEV)' })
  async listKev(@Query() query: PaginationQueryDto) {
    return this.service.listKev(query);
  }

  @Get('exploits')
  @ApiOperation({ summary: 'List vulnerabilities with public exploits' })
  async listExploits(@Query() query: PaginationQueryDto) {
    return this.service.listExploits(query);
  }
}
