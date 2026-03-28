import {
  Controller, Get, Param, Query, UseGuards, ParseIntPipe,
} from '@nestjs/common';
import { ApiTags, ApiSecurity, ApiOperation } from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import { ApiKeyGuard } from '../guards/api-key.guard';
import { ApiKeyScopes } from '../decorators/api-key-scopes.decorator';
import { ExternalApiService } from '../external-api.service';
import {
  ProductAssetQueryDto,
  PaginationQueryDto,
  SoftwareCatalogQueryDto,
} from '../dto/vulnerability-query.dto';

@ApiTags('External API — Products & Assets')
@ApiSecurity('api-key')
@Controller('v1')
@UseGuards(ApiKeyGuard, ThrottlerGuard)
@ApiKeyScopes('products:read')
export class ExtProductsController {
  constructor(private readonly service: ExternalApiService) {}

  @Get('product-assets')
  @ApiOperation({ summary: 'List product assets' })
  async listAssets(@Query() query: ProductAssetQueryDto) {
    return this.service.listProductAssets(query);
  }

  @Get('product-assets/:id/dependencies')
  @ApiOperation({ summary: 'List dependencies for a product asset' })
  async getDependencies(
    @Param('id', ParseIntPipe) id: number,
    @Query() query: PaginationQueryDto,
  ) {
    return this.service.getProductAssetDependencies(id, query);
  }

  @Get('product-assets/:id/vulnerabilities')
  @ApiOperation({ summary: 'List vulnerabilities affecting a product asset' })
  async getVulnerabilities(
    @Param('id', ParseIntPipe) id: number,
    @Query() query: PaginationQueryDto,
  ) {
    return this.service.getProductAssetVulnerabilities(id, query);
  }

  @Get('products')
  @ApiOperation({ summary: 'Browse software catalog (vendor/product pairs)' })
  async listCatalog(@Query() query: SoftwareCatalogQueryDto) {
    return this.service.listSoftwareCatalog(query);
  }
}
