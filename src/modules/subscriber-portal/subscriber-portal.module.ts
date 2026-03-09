import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { SubscriberPortalController } from './subscriber-portal.controller';
import { SubscriberPortalService } from './subscriber-portal.service';

@Module({
    imports: [PrismaModule],
    controllers: [SubscriberPortalController],
    providers: [SubscriberPortalService],
})
export class SubscriberPortalModule {}
