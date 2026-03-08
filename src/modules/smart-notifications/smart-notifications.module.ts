import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { AiModule } from '../ai/ai.module';
import { NotificationModule } from '../notification/notification.module';
import { SmartNotificationsController } from './smart-notifications.controller';
import { SmartNotificationsService } from './smart-notifications.service';

@Module({
  imports: [PrismaModule, AiModule, NotificationModule],
  controllers: [SmartNotificationsController],
  providers: [SmartNotificationsService],
  exports: [SmartNotificationsService],
})
export class SmartNotificationsModule {}
