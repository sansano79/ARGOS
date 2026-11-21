import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Param,
  ParseIntPipe,
  Post,
  Put,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../auth/decorators/roles.decorator';
import { DefenderConfigService } from './defender-config.service';
import { DefenderSyncService } from './defender-sync.service';
import { DefenderDevicesService } from './defender-devices.service';
import { DefenderClient } from './defender.client';
import { RequestDefenderSyncDto, UpdateDefenderConfigDto } from './dto/defender-config.dto';

@Controller('defender')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('ADMIN')
export class DefenderController {
  constructor(
    private readonly config: DefenderConfigService,
    private readonly sync: DefenderSyncService,
    private readonly devices: DefenderDevicesService,
    private readonly client: DefenderClient,
  ) {}

  @Get('config')
  getConfig() {
    return this.config.getView();
  }

  @Put('config')
  saveConfig(@Body() dto: UpdateDefenderConfigDto, @Req() req: any) {
    return this.config.save(dto, req.user?.id);
  }

  @Post('config/test')
  async testConfig() {
    const cfg = await this.config.getResolved();
    const missing = this.config
      // La prueba solo exige credenciales y filtros, no equipo de destino ni activación.
      .readinessErrors({ ...cfg, isActive: true, teamId: cfg.teamId ?? 1 });
    if (missing.length) throw new BadRequestException(missing);
    try {
      return { ok: true, ...(await this.client.testConnection(cfg)) };
    } catch (error: any) {
      return { ok: false, error: String(error?.message || error) };
    }
  }

  @Post('sync')
  async requestSync(@Body() dto: RequestDefenderSyncDto, @Req() req: any) {
    const { run, alreadyPending } = await this.sync.requestSync(dto.mode, req.user?.id);
    return { runId: run.id, status: run.status, mode: run.mode, alreadyPending };
  }

  @Get('sync/runs')
  listRuns(@Query('limit') limit?: string) {
    return this.sync.listRuns(Number(limit) || 20);
  }

  @Get('devices')
  listDevices(@Query('includeInactive') includeInactive?: string, @Query('search') search?: string) {
    return this.devices.listDevices({ includeInactive: includeInactive === 'true', search });
  }

  @Get('devices/:id/findings')
  listFindings(
    @Param('id', ParseIntPipe) id: number,
    @Query('status') status?: string,
    @Query('search') search?: string,
    @Query('page') page?: string,
    @Query('pageSize') pageSize?: string,
  ) {
    return this.devices.listFindings(id, { status, search, page: Number(page), pageSize: Number(pageSize) });
  }
}
