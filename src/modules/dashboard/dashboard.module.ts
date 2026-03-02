import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DashboardController } from './dashboard.controller';

@Module({
  imports: [ConfigModule],
  controllers: [DashboardController],
})
export class DashboardModule { }
