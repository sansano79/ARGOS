import {
  Controller, Get, Post, Patch, Delete,
  Body, Param, Request, UseGuards, ParseIntPipe,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../auth/decorators/roles.decorator';
import { ApiKeysService } from './api-keys.service';
import { CreateApiKeyDto, UpdateApiKeyDto } from './dto/create-api-key.dto';

@ApiTags('API Key Management')
@ApiBearerAuth()
@Controller('api-keys')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('ADMIN')
export class ApiKeysController {
  constructor(private readonly service: ApiKeysService) {}

  @Post()
  async create(@Request() req: any, @Body() dto: CreateApiKeyDto) {
    return this.service.create(req.user.id, dto);
  }

  @Get()
  async findAll() {
    return this.service.findAll();
  }

  @Get('scopes')
  getAvailableScopes() {
    return this.service.getAvailableScopes();
  }

  @Patch(':id')
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: UpdateApiKeyDto,
  ) {
    return this.service.update(id, dto);
  }

  @Delete(':id')
  async revoke(@Param('id', ParseIntPipe) id: number) {
    return this.service.revoke(id);
  }
}
