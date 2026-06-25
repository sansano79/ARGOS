import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { SubscriberTeamsController } from './subscriber-teams.controller';
import { TeamPortalController } from './team-portal.controller';
import { SubscriberTeamsService } from './subscriber-teams.service';
import { TeamAccessService } from './team-access.service';

@Module({
  imports: [PrismaModule],
  controllers: [SubscriberTeamsController, TeamPortalController],
  providers: [SubscriberTeamsService, TeamAccessService],
  exports: [TeamAccessService],
})
export class SubscriberTeamsModule {}
