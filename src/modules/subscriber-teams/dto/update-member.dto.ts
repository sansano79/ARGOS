import { IsString, IsIn, IsOptional, IsBoolean } from 'class-validator';
import { ALL_TEAM_ROLES, TeamRole } from '../constants/team-roles';

export class UpdateMemberDto {
  @IsString()
  @IsIn(ALL_TEAM_ROLES)
  @IsOptional()
  role?: TeamRole;

  @IsBoolean()
  @IsOptional()
  isActive?: boolean;
}
