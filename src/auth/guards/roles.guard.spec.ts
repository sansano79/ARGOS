import { Reflector } from '@nestjs/core';
import { ExecutionContext } from '@nestjs/common';
import { RolesGuard } from './roles.guard';

const makeContext = (userRole: string) =>
  ({
    getHandler: () => function handler() { },
    getClass: () => class TestController { },
    switchToHttp: () => ({
      getRequest: () => ({ user: { role: userRole } }),
    }),
  } as unknown as ExecutionContext);

describe('RolesGuard', () => {
  it('denies when only class roles exist and user role mismatches', () => {
    const reflector = new Reflector();
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['ADMIN']);
    const guard = new RolesGuard(reflector);
    expect(guard.canActivate(makeContext('SUBSCRIBER'))).toBe(false);
  });

  it('allows when class roles exist and user role matches', () => {
    const reflector = new Reflector();
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['ADMIN', 'SUBSCRIBER']);
    const guard = new RolesGuard(reflector);
    expect(guard.canActivate(makeContext('SUBSCRIBER'))).toBe(true);
  });

  it('allows when no roles metadata exists', () => {
    const reflector = new Reflector();
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);
    const guard = new RolesGuard(reflector);
    expect(guard.canActivate(makeContext('ANY'))).toBe(true);
  });
});

