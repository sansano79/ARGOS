import { validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { AddMemberDto } from './add-member.dto';
import { UpdateMemberDto } from './update-member.dto';
import { CreateRecipientDto } from './create-recipient.dto';
import { UpdateRecipientDto } from './update-recipient.dto';
import { CreateTeamDto } from './create-team.dto';
import { UpdateTeamDto } from './update-team.dto';
import { CreateSubscriptionDto } from './create-subscription.dto';
import { UpdateSubscriptionDto } from './update-subscription.dto';
import { CreateSystemDto } from './create-system.dto';

// ── Helpers ───────────────────────────────────────────────────────

// Mirror NestJS ValidationPipe(whitelist:true, forbidNonWhitelisted:true) options
const PIPE_OPTS = { whitelist: true, forbidNonWhitelisted: true };

async function hasErrors(cls: any, plain: object): Promise<boolean> {
  const instance = plainToInstance(cls, plain) as object;
  const errors = await validate(instance, PIPE_OPTS);
  return errors.length > 0;
}

async function isValid(cls: any, plain: object): Promise<boolean> {
  return !(await hasErrors(cls, plain));
}

// ── AddMemberDto ──────────────────────────────────────────────────

describe('AddMemberDto', () => {
  it('accepts TEAM_MANAGER role', async () => {
    expect(await isValid(AddMemberDto, { userId: 1, role: 'TEAM_MANAGER' })).toBe(true);
  });

  it('accepts TEAM_VIEWER role', async () => {
    expect(await isValid(AddMemberDto, { userId: 1, role: 'TEAM_VIEWER' })).toBe(true);
  });

  it('rejects invalid role (e.g. ADMIN) → validation error', async () => {
    expect(await hasErrors(AddMemberDto, { userId: 1, role: 'ADMIN' })).toBe(true);
  });

  it('rejects arbitrary role string → validation error', async () => {
    expect(await hasErrors(AddMemberDto, { userId: 1, role: 'SUPER_USER' })).toBe(true);
  });

  it('rejects missing userId', async () => {
    expect(await hasErrors(AddMemberDto, { role: 'TEAM_MANAGER' })).toBe(true);
  });

  it('rejects negative userId', async () => {
    expect(await hasErrors(AddMemberDto, { userId: -1, role: 'TEAM_MANAGER' })).toBe(true);
  });

  it('rejects zero userId', async () => {
    expect(await hasErrors(AddMemberDto, { userId: 0, role: 'TEAM_MANAGER' })).toBe(true);
  });

  it('rejects string userId', async () => {
    expect(await hasErrors(AddMemberDto, { userId: 'abc', role: 'TEAM_MANAGER' })).toBe(true);
  });
});

// ── UpdateMemberDto ───────────────────────────────────────────────

describe('UpdateMemberDto', () => {
  it('accepts empty body (all optional)', async () => {
    expect(await isValid(UpdateMemberDto, {})).toBe(true);
  });

  it('rejects invalid role string', async () => {
    expect(await hasErrors(UpdateMemberDto, { role: 'OWNER' })).toBe(true);
  });

  it('accepts isActive:false (deactivation)', async () => {
    expect(await isValid(UpdateMemberDto, { isActive: false })).toBe(true);
  });
});

// ── CreateRecipientDto ────────────────────────────────────────────

describe('CreateRecipientDto', () => {
  it('accepts valid email', async () => {
    expect(await isValid(CreateRecipientDto, { email: 'user@example.com' })).toBe(true);
  });

  it('rejects invalid email format → 400', async () => {
    expect(await hasErrors(CreateRecipientDto, { email: 'not-an-email' })).toBe(true);
  });

  it('rejects missing email', async () => {
    expect(await hasErrors(CreateRecipientDto, {})).toBe(true);
  });

  it('accepts valid type USER', async () => {
    expect(await isValid(CreateRecipientDto, { email: 'u@x.com', type: 'USER' })).toBe(true);
  });

  it('accepts valid type MAILBOX', async () => {
    expect(await isValid(CreateRecipientDto, { email: 'u@x.com', type: 'MAILBOX' })).toBe(true);
  });

  it('accepts valid type DISTRIBUTION_LIST', async () => {
    expect(await isValid(CreateRecipientDto, { email: 'u@x.com', type: 'DISTRIBUTION_LIST' })).toBe(true);
  });

  it('accepts valid type EXTERNAL_CONTACT', async () => {
    expect(await isValid(CreateRecipientDto, { email: 'u@x.com', type: 'EXTERNAL_CONTACT' })).toBe(true);
  });

  it('rejects invalid recipient type → 400', async () => {
    expect(await hasErrors(CreateRecipientDto, { email: 'u@x.com', type: 'WEBHOOK' })).toBe(true);
  });

  it('rejects arbitrary type string', async () => {
    expect(await hasErrors(CreateRecipientDto, { email: 'u@x.com', type: 'SLACK' })).toBe(true);
  });

  it('rejects verifiedAt (unknown field → forbidNonWhitelisted rejects with 400)', async () => {
    expect(await hasErrors(CreateRecipientDto, { email: 'u@x.com', verifiedAt: '2026-01-01' })).toBe(true);
  });

  it('rejects teamId in body (unknown field → forbidNonWhitelisted rejects with 400)', async () => {
    expect(await hasErrors(CreateRecipientDto, { email: 'u@x.com', teamId: 99 })).toBe(true);
  });
});

// ── UpdateRecipientDto ────────────────────────────────────────────

describe('UpdateRecipientDto', () => {
  it('accepts empty body (all optional)', async () => {
    expect(await isValid(UpdateRecipientDto, {})).toBe(true);
  });

  it('rejects invalid email on update', async () => {
    expect(await hasErrors(UpdateRecipientDto, { email: 'bad-email' })).toBe(true);
  });

  it('rejects invalid type on update → 400', async () => {
    expect(await hasErrors(UpdateRecipientDto, { type: 'INVALID_TYPE' })).toBe(true);
  });
});

// ── CreateTeamDto ─────────────────────────────────────────────────

describe('CreateTeamDto', () => {
  it('accepts minimal valid input', async () => {
    expect(await isValid(CreateTeamDto, { name: 'Alpha', code: 'alpha' })).toBe(true);
  });

  it('rejects missing name', async () => {
    expect(await hasErrors(CreateTeamDto, { code: 'alpha' })).toBe(true);
  });

  it('rejects missing code', async () => {
    expect(await hasErrors(CreateTeamDto, { name: 'Alpha' })).toBe(true);
  });

  it('rejects name longer than 191 chars', async () => {
    expect(await hasErrors(CreateTeamDto, { name: 'x'.repeat(192), code: 'a' })).toBe(true);
  });

  it('rejects teamId in body (unknown field → 400)', async () => {
    expect(await hasErrors(CreateTeamDto, { name: 'X', code: 'x', teamId: 99 })).toBe(true);
  });
});

// ── UpdateTeamDto ─────────────────────────────────────────────────

describe('UpdateTeamDto', () => {
  it('accepts empty body (all optional)', async () => {
    expect(await isValid(UpdateTeamDto, {})).toBe(true);
  });

  it('rejects code longer than 191 chars', async () => {
    expect(await hasErrors(UpdateTeamDto, { code: 'x'.repeat(192) })).toBe(true);
  });
});

// ── CreateSubscriptionDto ─────────────────────────────────────────

describe('CreateSubscriptionDto', () => {
  it('accepts minimal valid input', async () => {
    expect(await isValid(CreateSubscriptionDto, { vendor: 'ms', product: 'edge' })).toBe(true);
  });

  it('rejects missing vendor', async () => {
    expect(await hasErrors(CreateSubscriptionDto, { product: 'edge' })).toBe(true);
  });

  it('rejects empty vendor string', async () => {
    expect(await hasErrors(CreateSubscriptionDto, { vendor: '', product: 'edge' })).toBe(true);
  });

  it('accepts versions array', async () => {
    expect(await isValid(CreateSubscriptionDto, { vendor: 'ms', product: 'edge', versions: ['1.0', '2.0'] })).toBe(true);
  });

  it('rejects teamId in body (unknown field → 400)', async () => {
    expect(await hasErrors(CreateSubscriptionDto, { vendor: 'ms', product: 'edge', teamId: 99 })).toBe(true);
  });
});

// ── UpdateSubscriptionDto ─────────────────────────────────────────

describe('UpdateSubscriptionDto', () => {
  it('accepts empty body (all optional)', async () => {
    expect(await isValid(UpdateSubscriptionDto, {})).toBe(true);
  });

  it('accepts partial update of versions', async () => {
    expect(await isValid(UpdateSubscriptionDto, { versions: ['3.0'] })).toBe(true);
  });

  it('rejects vendor longer than 191 chars', async () => {
    expect(await hasErrors(UpdateSubscriptionDto, { vendor: 'v'.repeat(192) })).toBe(true);
  });
});

// ── CreateSystemDto ───────────────────────────────────────────────

describe('CreateSystemDto', () => {
  it('accepts minimal valid input (name only)', async () => {
    expect(await isValid(CreateSystemDto, { name: 'Server 1' })).toBe(true);
  });

  it('rejects missing name', async () => {
    expect(await hasErrors(CreateSystemDto, {})).toBe(true);
  });

  it('rejects hostname longer than 191 chars', async () => {
    expect(await hasErrors(CreateSystemDto, { name: 'X', hostname: 'h'.repeat(192) })).toBe(true);
  });

  it('rejects rawData (unknown field → forbidNonWhitelisted rejects with 400)', async () => {
    expect(await hasErrors(CreateSystemDto, { name: 'X', rawData: 'big json blob' })).toBe(true);
  });

  it('rejects teamId in body (unknown field → 400)', async () => {
    expect(await hasErrors(CreateSystemDto, { name: 'X', teamId: 99 })).toBe(true);
  });
});
