import { IsInt, IsString, IsIn, IsPositive } from 'class-validator';
import { ALL_TEAM_ROLES, TeamRole } from '../constants/team-roles';

export class AddMemberDto {
  @IsInt()
  @IsPositive()
  userId: number;

  @IsString()
  @IsIn(ALL_TEAM_ROLES)
  role: TeamRole;
}
