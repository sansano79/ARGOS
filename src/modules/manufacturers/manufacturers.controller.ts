import { Body, Controller, Delete, Get, Param, Post, Query, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../auth/decorators/roles.decorator';
import { ManufacturersService } from './manufacturers.service';

@ApiTags('Manufacturers')
@ApiBearerAuth()
@Controller('manufacturers')
@UseGuards(JwtAuthGuard)
export class ManufacturersController {
  constructor(private readonly manufacturersService: ManufacturersService) {}

  @Get()
  async findAll(@Query('includeHidden') includeHidden?: string) {
    return this.manufacturersService.findAll(includeHidden === 'true');
  }

  @Get('catalog-metadata')
  async getCatalogMetadata() {
    return this.manufacturersService.getCatalogMetadata();
  }

  @Post()
  @UseGuards(RolesGuard)
  @Roles('ADMIN')
  async createManufacturer(@Body() body: { name: string }) {
    return this.manufacturersService.createManufacturer(body?.name);
  }

  @Post('products')
  @UseGuards(RolesGuard)
  @Roles('ADMIN')
  async createProduct(
    @Body() body: { vendor: string; product: string; versions?: string[] },
  ) {
    return this.manufacturersService.createProduct(body);
  }

  @Post('merge')
  @UseGuards(RolesGuard)
  @Roles('ADMIN')
  async mergeManufacturers(
    @Body()
    body: {
      targetName: string;
      sourceNames: string[];
    },
  ) {
    return this.manufacturersService.mergeManufacturers(
      body?.targetName,
      body?.sourceNames || [],
    );
  }

  @Get('aliases')
  async getAliasesAndStats() {
    return this.manufacturersService.getAliasesAndStats();
  }

  @Delete('products/:id')
  @UseGuards(RolesGuard)
  @Roles('ADMIN')
  async deleteProduct(@Param('id') id: string) {
    return this.manufacturersService.deleteProduct(Number(id));
  }

  @Delete(':name')
  @UseGuards(RolesGuard)
  @Roles('ADMIN')
  async deleteManufacturer(@Param('name') name: string) {
    return this.manufacturersService.deleteManufacturer(name);
  }
}
