import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { OsvCollector } from '../vulnerability-collector/collectors/osv.collector';
import { AdvisoriesController, VulnerabilityAssessmentController } from './advisories/advisories.controller';
import { AdvisoriesService } from './advisories/advisories.service';
import { PatchEvidenceService } from './advisories/patch-evidence.service';
import { ThrottlerModule } from '@nestjs/throttler';
import { PrismaModule } from '../../prisma/prisma.module';
import { ExternalApiService } from './external-api.service';
import { ApiKeysService } from './api-keys.service';
import { ApiKeysController } from './api-keys.controller';
import { ApiKeyGuard } from './guards/api-key.guard';
import { ExtVulnerabilitiesController } from './controllers/ext-vulnerabilities.controller';
import { ExtCoverageController } from './controllers/ext-coverage.controller';
import { ExtProductsController } from './controllers/ext-products.controller';
import { ExtCatalogController } from './controllers/ext-catalog.controller';
import { ExtCollectorController } from './controllers/ext-collector.controller';

@Module({
  imports: [
    PrismaModule,
    ConfigModule,
    HttpModule,
    ThrottlerModule.forRoot([{
      ttl: parseInt(process.env.API_RATE_LIMIT_TTL || '60000', 10),
      limit: parseInt(process.env.API_RATE_LIMIT_MAX || '100', 10),
    }]),
  ],
  controllers: [
    ApiKeysController,
    AdvisoriesController,
    VulnerabilityAssessmentController,
    ExtVulnerabilitiesController,
    ExtCoverageController,
    ExtProductsController,
    ExtCatalogController,
    ExtCollectorController,
  ],
  providers: [
    ExternalApiService,
    AdvisoriesService,
    PatchEvidenceService,
    OsvCollector,
    ApiKeysService,
    ApiKeyGuard,
  ],
})
export class ExternalApiModule {}
