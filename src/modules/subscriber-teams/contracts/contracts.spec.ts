import {
  computeEvidenceFingerprint,
  evaluateEvidenceEscalation,
} from './team-vulnerability-assessment.contract';
import {
  calculateDeliveryIdempotencyKey,
  resolvePendingRecipients,
} from './notification-delivery.contract';

describe('Contracts Unit Tests (Pure Logic, No Database)', () => {
  describe('computeEvidenceFingerprint', () => {
    it('generates a deterministic SHA-256 hash', () => {
      const input = {
        cvssScore: 8.5,
        isKnownExploited: false,
        hasPublicExploit: false,
        confirmedAssets: [
          { assetId: 1, matchedComponentName: 'nginx', installedVersion: '1.18.0', fixedVersion: '1.24.0' },
          { assetId: 2, matchedComponentName: 'openssl', installedVersion: '1.1.1', fixedVersion: '1.1.1t' },
        ],
        subscriptionRules: [
          { subscriptionId: 10, vendor: 'nginx', product: 'nginx' },
        ],
      };

      const hash1 = computeEvidenceFingerprint(input);
      const hash2 = computeEvidenceFingerprint(input);

      expect(hash1).toHaveLength(64);
      expect(hash1).toBe(hash2);
    });

    it('is order-independent for assets and subscription rules', () => {
      const inputA = {
        cvssScore: 8.5,
        isKnownExploited: false,
        hasPublicExploit: false,
        confirmedAssets: [
          { assetId: 2, matchedComponentName: 'openssl', installedVersion: '1.1.1', fixedVersion: '1.1.1t' },
          { assetId: 1, matchedComponentName: 'nginx', installedVersion: '1.18.0', fixedVersion: '1.24.0' },
        ],
        subscriptionRules: [
          { subscriptionId: 20, vendor: 'openssl', product: 'openssl' },
          { subscriptionId: 10, vendor: 'nginx', product: 'nginx' },
        ],
      };

      const inputB = {
        cvssScore: 8.5,
        isKnownExploited: false,
        hasPublicExploit: false,
        confirmedAssets: [
          { assetId: 1, matchedComponentName: 'nginx', installedVersion: '1.18.0', fixedVersion: '1.24.0' },
          { assetId: 2, matchedComponentName: 'openssl', installedVersion: '1.1.1', fixedVersion: '1.1.1t' },
        ],
        subscriptionRules: [
          { subscriptionId: 10, vendor: 'nginx', product: 'nginx' },
          { subscriptionId: 20, vendor: 'openssl', product: 'openssl' },
        ],
      };

      expect(computeEvidenceFingerprint(inputA)).toBe(computeEvidenceFingerprint(inputB));
    });

    it('changes when critical attributes change', () => {
      const base = {
        cvssScore: 8.5,
        isKnownExploited: false,
        hasPublicExploit: false,
        confirmedAssets: [{ assetId: 1, matchedComponentName: 'nginx', installedVersion: '1.18.0', fixedVersion: null }],
        subscriptionRules: [],
      };

      const baseHash = computeEvidenceFingerprint(base);

      expect(computeEvidenceFingerprint({ ...base, cvssScore: 9.8 })).not.toBe(baseHash);
      expect(computeEvidenceFingerprint({ ...base, isKnownExploited: true })).not.toBe(baseHash);
      expect(computeEvidenceFingerprint({
        ...base,
        confirmedAssets: [{ assetId: 1, matchedComponentName: 'nginx', installedVersion: '1.18.0', fixedVersion: '1.24.0' }],
      })).not.toBe(baseHash);
    });
  });

  describe('evaluateEvidenceEscalation', () => {
    it('returns shouldEscalate = false when fingerprints match', () => {
      const state = {
        cvssScore: 7.5,
        isKnownExploited: false,
        hasPublicExploit: false,
        evidenceFingerprint: 'abc123hash',
        confirmedAssets: [{ assetId: 1, criticality: 'HIGH', fixedVersion: null }],
      };

      const result = evaluateEvidenceEscalation(state, { ...state });
      expect(result).toEqual({ shouldEscalate: false, reason: 'NONE' });
    });

    it('escalates immediately when added to CISA KEV', () => {
      const prev = {
        cvssScore: 7.5,
        isKnownExploited: false,
        hasPublicExploit: false,
        evidenceFingerprint: 'hash1',
        confirmedAssets: [],
      };
      const curr = {
        cvssScore: 7.5,
        isKnownExploited: true,
        hasPublicExploit: false,
        evidenceFingerprint: 'hash2',
        confirmedAssets: [],
      };

      const result = evaluateEvidenceEscalation(prev, curr);
      expect(result.shouldEscalate).toBe(true);
      expect(result.reason).toBe('SEVERITY_ESCALATION');
    });

    it('escalates when CVSS jumps by >= 1.0 or enters CRITICAL tier', () => {
      const prev = {
        cvssScore: 7.2,
        isKnownExploited: false,
        hasPublicExploit: false,
        evidenceFingerprint: 'hash1',
        confirmedAssets: [],
      };
      const curr = {
        cvssScore: 8.5,
        isKnownExploited: false,
        hasPublicExploit: false,
        evidenceFingerprint: 'hash2',
        confirmedAssets: [],
      };

      const result = evaluateEvidenceEscalation(prev, curr);
      expect(result.shouldEscalate).toBe(true);
      expect(result.reason).toBe('SEVERITY_ESCALATION');
    });

    it('escalates when a new CRITICAL or HIGH asset is confirmed', () => {
      const prev = {
        cvssScore: 7.5,
        isKnownExploited: false,
        hasPublicExploit: false,
        evidenceFingerprint: 'hash1',
        confirmedAssets: [{ assetId: 1, criticality: 'LOW', fixedVersion: null }],
      };
      const curr = {
        cvssScore: 7.5,
        isKnownExploited: false,
        hasPublicExploit: false,
        evidenceFingerprint: 'hash2',
        confirmedAssets: [
          { assetId: 1, criticality: 'LOW', fixedVersion: null },
          { assetId: 2, criticality: 'CRITICAL', fixedVersion: null },
        ],
      };

      const result = evaluateEvidenceEscalation(prev, curr);
      expect(result.shouldEscalate).toBe(true);
      expect(result.reason).toBe('NEW_CRITICAL_ASSET');
    });

    it('escalates when a fixed version becomes available for a previously unpatched issue', () => {
      const prev = {
        cvssScore: 7.5,
        isKnownExploited: false,
        hasPublicExploit: false,
        evidenceFingerprint: 'hash1',
        confirmedAssets: [{ assetId: 1, criticality: 'LOW', fixedVersion: null }],
      };
      const curr = {
        cvssScore: 7.5,
        isKnownExploited: false,
        hasPublicExploit: false,
        evidenceFingerprint: 'hash2',
        confirmedAssets: [{ assetId: 1, criticality: 'LOW', fixedVersion: '2.0.1' }],
      };

      const result = evaluateEvidenceEscalation(prev, curr);
      expect(result.shouldEscalate).toBe(true);
      expect(result.reason).toBe('REMEDIATION_AVAILABLE');
    });

    it('does not escalate for minor non-critical changes', () => {
      const prev = {
        cvssScore: 7.2,
        isKnownExploited: false,
        hasPublicExploit: false,
        evidenceFingerprint: 'hash1',
        confirmedAssets: [{ assetId: 1, criticality: 'LOW', fixedVersion: null }],
      };
      const curr = {
        cvssScore: 7.4, // delta = 0.2, neither >= 1.0 nor >= 9.0
        isKnownExploited: false,
        hasPublicExploit: false,
        evidenceFingerprint: 'hash2',
        confirmedAssets: [{ assetId: 1, criticality: 'LOW', fixedVersion: null }],
      };

      const result = evaluateEvidenceEscalation(prev, curr);
      expect(result.shouldEscalate).toBe(false);
      expect(result.reason).toBe('NONE');
    });
  });

  describe('calculateDeliveryIdempotencyKey', () => {
    it('produces a 64-character SHA-256 hex string', () => {
      const key = calculateDeliveryIdempotencyKey({
        teamId: 5,
        vulnerabilityId: 120,
        revision: 1,
        deliveryChannel: 'EMAIL',
        dispatchPriority: 'IMMEDIATE',
      });

      expect(key).toHaveLength(64);
    });

    it('distinguishes between IMMEDIATE and DIGEST dispatches for the same vulnerability', () => {
      const immediateKey = calculateDeliveryIdempotencyKey({
        teamId: 5,
        vulnerabilityId: 120,
        revision: 1,
        deliveryChannel: 'EMAIL',
        dispatchPriority: 'IMMEDIATE',
      });

      const digestKey = calculateDeliveryIdempotencyKey({
        teamId: 5,
        vulnerabilityId: 120,
        revision: 1,
        deliveryChannel: 'EMAIL',
        dispatchPriority: 'DIGEST',
      });

      expect(immediateKey).not.toBe(digestKey);
    });

    it('distinguishes between revision 1 and revision 2 for escalation delivery', () => {
      const rev1Key = calculateDeliveryIdempotencyKey({
        teamId: 5,
        vulnerabilityId: 120,
        revision: 1,
        deliveryChannel: 'EMAIL',
        dispatchPriority: 'IMMEDIATE',
      });

      const rev2Key = calculateDeliveryIdempotencyKey({
        teamId: 5,
        vulnerabilityId: 120,
        revision: 2,
        deliveryChannel: 'EMAIL',
        dispatchPriority: 'IMMEDIATE',
      });

      expect(rev1Key).not.toBe(rev2Key);
    });
  });

  describe('resolvePendingRecipients', () => {
    it('filters out recipients that already succeeded in previous attempts', () => {
      const recipients = [
        { recipientId: 1, email: 'alice@example.com', name: 'Alice' },
        { recipientId: 2, email: 'bob@example.com', name: 'Bob' },
        { recipientId: 3, email: 'charlie@example.com', name: 'Charlie' },
      ];

      const alreadySent = new Set(['alice@example.com']);
      const pending = resolvePendingRecipients(recipients, alreadySent);

      expect(pending).toHaveLength(2);
      expect(pending.map((p) => p.email)).toEqual(['bob@example.com', 'charlie@example.com']);
    });
  });
});
