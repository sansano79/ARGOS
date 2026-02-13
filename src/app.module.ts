import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { VulnerabilityCollectorModule } from './modules/vulnerability-collector/vulnerability-collector.module';
import { DashboardModule } from './modules/dashboard/dashboard.module';
import { NotificationModule } from './modules/notification/notification.module';
import { AiModule } from './modules/ai/ai.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    ScheduleModule.forRoot(),
    PrismaModule,
    AuthModule,
    VulnerabilityCollectorModule,
    DashboardModule,
    NotificationModule,
    AiModule,
  ],
})
export class AppModule { }
