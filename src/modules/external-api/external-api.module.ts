import { Module } from '@nestjs/common';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { PrismaModule } from '../../prisma/prisma.module';
import { ExternalApiService } from './external-api.service';
import { ApiKeysService } from './api-keys.service';
import { ApiKeysController } from './api-keys.controller';
import { ApiKeyGuard } from './guards/api-key.guard';
import { ExtVulnerabilitiesController } from './controllers/ext-vulnerabilities.controller';
import { ExtProductsController } from './controllers/ext-products.controller';
import { ExtCatalogController } from './controllers/ext-catalog.controller';
import { ExtCollectorController } from './controllers/ext-collector.controller';

@Module({
  imports: [
    PrismaModule,
    ThrottlerModule.forRoot([{
      ttl: parseInt(process.env.API_RATE_LIMIT_TTL || '60000', 10),
      limit: parseInt(process.env.API_RATE_LIMIT_MAX || '100', 10),
    }]),
  ],
  controllers: [
    ApiKeysController,
    ExtVulnerabilitiesController,
    ExtProductsController,
    ExtCatalogController,
    ExtCollectorController,
  ],
  providers: [
    ExternalApiService,
    ApiKeysService,
    ApiKeyGuard,
  ],
})
export class ExternalApiModule {}
