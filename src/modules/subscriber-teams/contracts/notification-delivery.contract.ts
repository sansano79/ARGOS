import * as crypto from 'crypto';

export type DeliveryChannel = 'EMAIL';

export type DispatchPriority = 'IMMEDIATE' | 'DIGEST';

export type DeliveryStatus =
  | 'PREPARED'
  | 'PROCESSING'
  | 'SENT'
  | 'PARTIALLY_DELIVERED'
  | 'FAILED'
  | 'CANCELLED'
  | 'SKIPPED_NO_RECIPIENTS';

export interface RecipientDispatchResult {
  recipientId: number;
  email: string;
  name: string | null;
  status: 'sent' | 'failed' | 'skipped';
  smtpMessageId?: string;
  errorMessage?: string;
  sentAt?: Date;
}

export interface NotificationDeliveryContract {
  deliveryId: number;
  alertId: number;
  teamId: number;
  vulnerabilityId: number;
  cveId: string;
  revision: number;
  idempotencyKey: string;
  deliveryChannel: DeliveryChannel;
  dispatchPriority: DispatchPriority;
  status: DeliveryStatus;

  retryCount: number;
  maxRetries: number;
  nextRetryAt: Date | null;

  recipients: Array<{
    recipientId: number;
    email: string;
    name: string | null;
    language: string;
  }>;

  results: RecipientDispatchResult[];

  createdAt: Date;
  sentAt: Date | null;
}

/**
 * Calculates a unique, deterministic idempotency key for a specific delivery attempt.
 *
 * Formula:
 * SHA256(teamId:vulnerabilityId:revision:deliveryChannel:dispatchPriority)
 */
export function calculateDeliveryIdempotencyKey(params: {
  teamId: number;
  vulnerabilityId: number;
  revision: number;
  deliveryChannel: DeliveryChannel;
  dispatchPriority: DispatchPriority;
}): string {
  const rawKey = `${params.teamId}:${params.vulnerabilityId}:${params.revision}:${params.deliveryChannel}:${params.dispatchPriority}`;
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

/**
 * Filters the active recipients for an attempt, omitting recipients who have
 * already received a successful delivery in a previous attempt (for partial delivery retries).
 */
export function resolvePendingRecipients(
  allActiveRecipients: Array<{ recipientId: number; email: string; name: string | null; language?: string }>,
  alreadySentEmails: Set<string>,
): Array<{ recipientId: number; email: string; name: string | null; language?: string }> {
  return allActiveRecipients.filter((r) => !alreadySentEmails.has(r.email.toLowerCase().trim()));
}
