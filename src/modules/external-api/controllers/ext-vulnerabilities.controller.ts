import {
  Controller, Get, Param, Query, UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiSecurity, ApiOperation } from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import { ApiKeyGuard } from '../guards/api-key.guard';
import { ApiKeyScopes } from '../decorators/api-key-scopes.decorator';
import { ExternalApiService } from '../external-api.service';
import { VulnerabilityQueryDto, PaginationQueryDto } from '../dto/vulnerability-query.dto';

@ApiTags('External API — Vulnerabilities')
@ApiSecurity('api-key')
@Controller('v1/vulnerabilities')
@UseGuards(ApiKeyGuard, ThrottlerGuard)
@ApiKeyScopes('vulnerabilities:read')
export class ExtVulnerabilitiesController {
  constructor(private readonly service: ExternalApiService) {}

  @Get()
  @ApiOperation({ summary: 'List vulnerabilities with filtering and pagination' })
  async list(@Query() query: VulnerabilityQueryDto) {
    return this.service.listVulnerabilities(query);
  }

  @Get('stats')
  @ApiOperation({ summary: 'Aggregated vulnerability statistics' })
  async stats() {
    return this.service.getVulnerabilityStats();
  }

  @Get(':cveId')
  @ApiOperation({ summary: 'Get vulnerability details by CVE ID' })
  async getByCveId(@Param('cveId') cveId: string) {
    return this.service.getVulnerabilityByCveId(cveId);
  }

  @Get(':cveId/changes')
  @ApiOperation({ summary: 'Get change history for a CVE' })
  async getChanges(
    @Param('cveId') cveId: string,
    @Query() query: PaginationQueryDto,
  ) {
    return this.service.getVulnerabilityChanges(cveId, query);
  }
}
