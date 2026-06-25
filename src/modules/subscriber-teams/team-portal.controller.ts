import {
  Controller, Get, Post, Patch, Delete,
  Body, Param, Request, ParseIntPipe, UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { SubscriberTeamsService } from './subscriber-teams.service';
import { TeamAccessService } from './team-access.service';
import { CreateSubscriptionDto } from './dto/create-subscription.dto';
import { UpdateSubscriptionDto } from './dto/update-subscription.dto';
import { CreateSystemDto } from './dto/create-system.dto';
import { UpdateSystemDto } from './dto/update-system.dto';
import { CreateRecipientDto } from './dto/create-recipient.dto';
import { UpdateRecipientDto } from './dto/update-recipient.dto';
import { AddMemberDto } from './dto/add-member.dto';
import { UpdateMemberDto } from './dto/update-member.dto';

@Controller()
@UseGuards(JwtAuthGuard)
export class TeamPortalController {
  constructor(
    private readonly service: SubscriberTeamsService,
    private readonly access: TeamAccessService,
  ) {}

  // ── My teams ──────────────────────────────────────────────────

  @Get('me/teams')
  async getMyTeams(@Request() req: any) {
    return this.access.getAccessibleTeams(req.user);
  }

  // ── Team detail ───────────────────────────────────────────────

  @Get('teams/:teamId')
  async getTeam(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
  ) {
    if (String(req?.user?.role || '').toUpperCase() === 'ADMIN') {
      return this.service.findTeamById(teamId);
    }
    return this.access.getTeamForMember(req.user, teamId);
  }

  // ── Members ───────────────────────────────────────────────────

  @Get('teams/:teamId/members')
  async getMembers(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
  ) {
    await this.access.assertTeamReadable(req.user, teamId);
    return this.service.findTeamMembers(teamId);
  }

  @Get('teams/:teamId/users')
  async getAssignableUsers(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
  ) {
    await this.access.assertTeamWritable(req.user, teamId);
    await this.service.findTeamById(teamId);
    return this.service.findAssignableUsers();
  }

  @Post('teams/:teamId/members')
  async addMember(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
    @Body() dto: AddMemberDto,
  ) {
    await this.access.assertTeamWritable(req.user, teamId);
    return this.service.addMember(teamId, dto);
  }

  @Patch('teams/:teamId/members/:memberId')
  async updateMember(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('memberId', ParseIntPipe) memberId: number,
    @Body() dto: UpdateMemberDto,
  ) {
    await this.access.assertTeamWritable(req.user, teamId);
    return this.service.updateMember(teamId, memberId, dto);
  }

  @Delete('teams/:teamId/members/:memberId')
  async removeMember(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('memberId', ParseIntPipe) memberId: number,
  ) {
    await this.access.assertTeamWritable(req.user, teamId);
    return this.service.removeMember(teamId, memberId);
  }

  // ── Subscriptions ─────────────────────────────────────────────

  @Get('teams/:teamId/subscriptions')
  async getSubscriptions(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
  ) {
    await this.access.assertTeamReadable(req.user, teamId);
    return this.service.findSubscriptions(teamId);
  }

  @Post('teams/:teamId/subscriptions')
  async createSubscription(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
    @Body() dto: CreateSubscriptionDto,
  ) {
    await this.access.assertTeamWritable(req.user, teamId);
    return this.service.createSubscription(teamId, dto);
  }

  @Patch('teams/:teamId/subscriptions/:subscriptionId')
  async updateSubscription(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('subscriptionId', ParseIntPipe) subscriptionId: number,
    @Body() dto: UpdateSubscriptionDto,
  ) {
    await this.access.assertTeamWritable(req.user, teamId);
    return this.service.updateSubscription(teamId, subscriptionId, dto);
  }

  @Delete('teams/:teamId/subscriptions/:subscriptionId')
  async removeSubscription(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('subscriptionId', ParseIntPipe) subscriptionId: number,
  ) {
    await this.access.assertTeamWritable(req.user, teamId);
    return this.service.removeSubscription(teamId, subscriptionId);
  }

  // ── Systems ───────────────────────────────────────────────────

  @Get('teams/:teamId/systems')
  async getSystems(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
  ) {
    await this.access.assertTeamReadable(req.user, teamId);
    return this.service.findSystems(teamId);
  }

  @Post('teams/:teamId/systems')
  async createSystem(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
    @Body() dto: CreateSystemDto,
  ) {
    await this.access.assertTeamWritable(req.user, teamId);
    return this.service.createSystem(teamId, dto);
  }

  @Patch('teams/:teamId/systems/:systemId')
  async updateSystem(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('systemId', ParseIntPipe) systemId: number,
    @Body() dto: UpdateSystemDto,
  ) {
    await this.access.assertTeamWritable(req.user, teamId);
    return this.service.updateSystem(teamId, systemId, dto);
  }

  @Delete('teams/:teamId/systems/:systemId')
  async removeSystem(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('systemId', ParseIntPipe) systemId: number,
  ) {
    await this.access.assertTeamWritable(req.user, teamId);
    return this.service.removeSystem(teamId, systemId);
  }

  // ── Recipients ────────────────────────────────────────────────

  @Get('teams/:teamId/recipients')
  async getRecipients(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
  ) {
    await this.access.assertTeamReadable(req.user, teamId);
    return this.service.findRecipients(teamId);
  }

  @Post('teams/:teamId/recipients')
  async createRecipient(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
    @Body() dto: CreateRecipientDto,
  ) {
    await this.access.assertTeamWritable(req.user, teamId);
    return this.service.createRecipient(teamId, dto);
  }

  @Patch('teams/:teamId/recipients/:recipientId')
  async updateRecipient(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('recipientId', ParseIntPipe) recipientId: number,
    @Body() dto: UpdateRecipientDto,
  ) {
    await this.access.assertTeamWritable(req.user, teamId);
    return this.service.updateRecipient(teamId, recipientId, dto);
  }

  @Delete('teams/:teamId/recipients/:recipientId')
  async removeRecipient(
    @Request() req: any,
    @Param('teamId', ParseIntPipe) teamId: number,
    @Param('recipientId', ParseIntPipe) recipientId: number,
  ) {
    await this.access.assertTeamWritable(req.user, teamId);
    return this.service.removeRecipient(teamId, recipientId);
  }
}
