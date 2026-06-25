import {
  Controller, Get, Post, Patch, Delete,
  Body, Param, ParseIntPipe, UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../auth/decorators/roles.decorator';
import { SubscriberTeamsService } from './subscriber-teams.service';
import { TeamAccessService } from './team-access.service';
import { CreateTeamDto } from './dto/create-team.dto';
import { UpdateTeamDto } from './dto/update-team.dto';
import { AddMemberDto } from './dto/add-member.dto';
import { UpdateMemberDto } from './dto/update-member.dto';
import { CreateRecipientDto } from './dto/create-recipient.dto';
import { UpdateRecipientDto } from './dto/update-recipient.dto';
import { CreateSubscriptionDto } from './dto/create-subscription.dto';
import { UpdateSubscriptionDto } from './dto/update-subscription.dto';
import { CreateSystemDto } from './dto/create-system.dto';
import { UpdateSystemDto } from './dto/update-system.dto';

@Controller('subscriber-teams')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('ADMIN')
export class SubscriberTeamsController {
  constructor(
    private readonly service: SubscriberTeamsService,
    private readonly access: TeamAccessService,
  ) {}

  // ── Teams ─────────────────────────────────────────────────────

  @Get()
  findAll() {
    return this.service.findAllTeams();
  }

  @Post()
  create(@Body() dto: CreateTeamDto) {
    return this.service.createTeam(dto);
  }

  @Get(':teamId')
  findOne(@Param('teamId', ParseIntPipe) teamId: number) {
    return this.service.findTeamById(teamId);
  }

  @Patch(':teamId')
  update(
    @Param('teamId', ParseIntPipe) teamId: number,
    @Body() dto: UpdateTeamDto,
  ) {
    return this.service.updateTeam(teamId, dto);
  }

  // ── Members ───────────────────────────────────────────────────

  @Get(':teamId/members')
  findMembers(@Param('teamId', ParseIntPipe) teamId: number) {
    return this.service.findTeamMembers(teamId);
  }

  @Post(':teamId/members')
  addMember(
    @Param('teamId', ParseIntPipe) teamId: number,
    @Body() dto: AddMemberDto,
  ) {
    return this.service.addMember(teamId, dto);
  }

  @Patch(':teamId/members/:memberId')
  updateMember(
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('memberId', ParseIntPipe) memberId: number,
    @Body() dto: UpdateMemberDto,
  ) {
    return this.service.updateMember(teamId, memberId, dto);
  }

  @Delete(':teamId/members/:memberId')
  removeMember(
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('memberId', ParseIntPipe) memberId: number,
  ) {
    return this.service.removeMember(teamId, memberId);
  }

  // ── Recipients ────────────────────────────────────────────────

  @Get(':teamId/recipients')
  findRecipients(@Param('teamId', ParseIntPipe) teamId: number) {
    return this.service.findRecipients(teamId);
  }

  @Post(':teamId/recipients')
  createRecipient(
    @Param('teamId', ParseIntPipe) teamId: number,
    @Body() dto: CreateRecipientDto,
  ) {
    return this.service.createRecipient(teamId, dto);
  }

  @Patch(':teamId/recipients/:recipientId')
  updateRecipient(
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('recipientId', ParseIntPipe) recipientId: number,
    @Body() dto: UpdateRecipientDto,
  ) {
    return this.service.updateRecipient(teamId, recipientId, dto);
  }

  @Delete(':teamId/recipients/:recipientId')
  removeRecipient(
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('recipientId', ParseIntPipe) recipientId: number,
  ) {
    return this.service.removeRecipient(teamId, recipientId);
  }

  // ── Subscriptions ─────────────────────────────────────────────

  @Get(':teamId/subscriptions')
  findSubscriptions(@Param('teamId', ParseIntPipe) teamId: number) {
    return this.service.findSubscriptions(teamId);
  }

  @Post(':teamId/subscriptions')
  createSubscription(
    @Param('teamId', ParseIntPipe) teamId: number,
    @Body() dto: CreateSubscriptionDto,
  ) {
    return this.service.createSubscription(teamId, dto);
  }

  @Patch(':teamId/subscriptions/:subscriptionId')
  updateSubscription(
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('subscriptionId', ParseIntPipe) subscriptionId: number,
    @Body() dto: UpdateSubscriptionDto,
  ) {
    return this.service.updateSubscription(teamId, subscriptionId, dto);
  }

  @Delete(':teamId/subscriptions/:subscriptionId')
  removeSubscription(
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('subscriptionId', ParseIntPipe) subscriptionId: number,
  ) {
    return this.service.removeSubscription(teamId, subscriptionId);
  }

  // ── Systems ───────────────────────────────────────────────────

  @Get(':teamId/systems')
  findSystems(@Param('teamId', ParseIntPipe) teamId: number) {
    return this.service.findSystems(teamId);
  }

  @Post(':teamId/systems')
  createSystem(
    @Param('teamId', ParseIntPipe) teamId: number,
    @Body() dto: CreateSystemDto,
  ) {
    return this.service.createSystem(teamId, dto);
  }

  @Patch(':teamId/systems/:systemId')
  updateSystem(
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('systemId', ParseIntPipe) systemId: number,
    @Body() dto: UpdateSystemDto,
  ) {
    return this.service.updateSystem(teamId, systemId, dto);
  }

  @Delete(':teamId/systems/:systemId')
  removeSystem(
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('systemId', ParseIntPipe) systemId: number,
  ) {
    return this.service.removeSystem(teamId, systemId);
  }
}
