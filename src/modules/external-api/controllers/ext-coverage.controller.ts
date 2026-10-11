import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiTags, ApiSecurity, ApiOperation } from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import { ApiKeyGuard } from '../guards/api-key.guard';
import { ApiKeyScopes } from '../decorators/api-key-scopes.decorator';
import { ExternalApiService } from '../external-api.service';

@ApiTags('External API — Coverage')
@ApiSecurity('api-key')
@Controller('v1/coverage')
@UseGuards(ApiKeyGuard, ThrottlerGuard)
@ApiKeyScopes('vulnerabilities:read', 'collector:read')
export class ExtCoverageController {
  constructor(private readonly service: ExternalApiService) {}

  @Get()
  @ApiOperation({ summary: 'Get vulnerability intelligence coverage and source health summary' })
  async getCoverage() {
    return this.service.getCoverage();
  }
}
