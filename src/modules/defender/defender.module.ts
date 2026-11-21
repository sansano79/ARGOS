import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { HttpModule } from '@nestjs/axios';
import { PrismaModule } from '../../prisma/prisma.module';
import { DefenderClient } from './defender.client';
import { DefenderConfigService } from './defender-config.service';
import { DefenderSyncService } from './defender-sync.service';
import { DefenderDevicesService } from './defender-devices.service';
import { DefenderController } from './defender.controller';

@Module({
  imports: [PrismaModule, ConfigModule, HttpModule],
  providers: [DefenderClient, DefenderConfigService, DefenderSyncService, DefenderDevicesService],
  controllers: [DefenderController],
  exports: [DefenderConfigService, DefenderSyncService, DefenderDevicesService],
})
export class DefenderModule {}
