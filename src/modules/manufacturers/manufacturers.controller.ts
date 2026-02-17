import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
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
  async findAll() {
    return this.manufacturersService.findAll();
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
}

