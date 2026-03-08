import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { VulnerabilityCollectorModule } from './modules/vulnerability-collector/vulnerability-collector.module';
import { DashboardModule } from './modules/dashboard/dashboard.module';
import { NotificationModule } from './modules/notification/notification.module';
import { AiModule } from './modules/ai/ai.module';
import { ContactsModule } from './modules/contacts/contacts.module';
import { UsersModule } from './modules/users/users.module';
import { TagsModule } from './modules/tags/tags.module';
import { ManufacturersModule } from './modules/manufacturers/manufacturers.module';
import { PasswordResetModule } from './modules/password-reset/password-reset.module';
import { SmartNotificationsModule } from './modules/smart-notifications/smart-notifications.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env', '.env.prod'],
    }),
    ScheduleModule.forRoot(),
    PrismaModule,
    AuthModule,
    VulnerabilityCollectorModule,
    DashboardModule,
    NotificationModule,
    AiModule,
    ContactsModule,
    UsersModule,
    TagsModule,
    ManufacturersModule,
    PasswordResetModule,
    SmartNotificationsModule,
  ],
})
export class AppModule { }

