import { SetMetadata } from '@nestjs/common';

export const API_KEY_SCOPES_KEY = 'api-key-scopes';
export const ApiKeyScopes = (...scopes: string[]) =>
  SetMetadata(API_KEY_SCOPES_KEY, scopes);
