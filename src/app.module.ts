import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { VulnerabilityCollectorModule } from './modules/vulnerability-collector/vulnerability-collector.module';
import { DashboardModule } from './modules/dashboard/dashboard.module';
import { NotificationModule } from './modules/notification/notification.module';
import { AiModule } from './modules/ai/ai.module';
// ContactsModule removed — ItContact legacy model eliminated
import { UsersModule } from './modules/users/users.module';
import { TagsModule } from './modules/tags/tags.module';
import { ManufacturersModule } from './modules/manufacturers/manufacturers.module';
import { PasswordResetModule } from './modules/password-reset/password-reset.module';
import { SmartNotificationsModule } from './modules/smart-notifications/smart-notifications.module';
import { SubscriberPortalModule } from './modules/subscriber-portal/subscriber-portal.module';
import { ProductAssetsModule } from './modules/product-assets/product-assets.module';
import { DependencyEvidenceImportsModule } from './modules/dependency-evidence-imports/dependency-evidence-imports.module';
import { VulnerabilityProductImpactsModule } from './modules/vulnerability-product-impacts/vulnerability-product-impacts.module';

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
    UsersModule,
    TagsModule,
    ManufacturersModule,
    PasswordResetModule,
    SmartNotificationsModule,
    SubscriberPortalModule,
    ProductAssetsModule,
    DependencyEvidenceImportsModule,
    VulnerabilityProductImpactsModule,
  ],
})
export class AppModule { }
