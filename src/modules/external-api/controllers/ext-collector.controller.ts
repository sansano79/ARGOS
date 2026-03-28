import {
  Controller, Get, Query, UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiSecurity, ApiOperation } from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import { ApiKeyGuard } from '../guards/api-key.guard';
import { ApiKeyScopes } from '../decorators/api-key-scopes.decorator';
import { ExternalApiService } from '../external-api.service';
import { CollectorRunQueryDto, PaginationQueryDto } from '../dto/vulnerability-query.dto';

@ApiTags('External API — Collector & Reports')
@ApiSecurity('api-key')
@Controller('v1')
@UseGuards(ApiKeyGuard, ThrottlerGuard)
@ApiKeyScopes('collector:read')
export class ExtCollectorController {
  constructor(private readonly service: ExternalApiService) {}

  @Get('collector/runs')
  @ApiOperation({ summary: 'List vulnerability collector run history' })
  async listRuns(@Query() query: CollectorRunQueryDto) {
    return this.service.listCollectorRuns(query);
  }

  @Get('collector/sources-health')
  @ApiOperation({ summary: 'Data source health status' })
  async sourcesHealth() {
    return this.service.listSourcesHealth();
  }

  @Get('reports')
  @ApiKeyScopes('reports:read')
  @ApiOperation({ summary: 'List generated vulnerability reports' })
  async listReports(@Query() query: PaginationQueryDto) {
    return this.service.listReports(query);
  }
}
