import test from "node:test";
import assert from "node:assert/strict";

import {
  createDefaultNotificationCenterState,
  normalizeNotificationCenterSettings,
} from "./notificationCenter.js";

test("notification center defaults provide the expected structure", () => {
  const defaults = createDefaultNotificationCenterState();
  assert.equal(defaults.general.processEnabled, true);
  assert.equal(defaults.immediate.enabled, true);
  assert.equal(defaults.digest.intervalHours, 12);
  assert.equal(defaults.intelligent.onlyWhenFinding, true);
  assert.equal(defaults.intelligent.historicalContextDays, 60);
  assert.equal(defaults.intelligent.maxNotificationsPerSubscriberPerDay, 2);
});

test("normalizeNotificationCenterSettings coerces arrays, CSV strings and preserves nested intelligent flags", () => {
  const result = normalizeNotificationCenterSettings({
    general: { retryBackoffMinutes: ["5", "15", "bad"] },
    immediate: { vendorFilters: "microsoft, adobe" },
    digest: { exclusions: "[\"noise-a\",\"noise-b\"]" },
    intelligent: {
      minRelevanceScore: "0.72",
      historicalContextDays: "45",
      scenarioFlags: { attackPath: false },
    },
  });

  assert.deepEqual(result.general.retryBackoffMinutes, [5, 15]);
  assert.deepEqual(result.immediate.vendorFilters, ["microsoft", "adobe"]);
  assert.deepEqual(result.digest.exclusions, ["noise-a", "noise-b"]);
  assert.equal(result.intelligent.minRelevanceScore, 0.72);
  assert.equal(result.intelligent.historicalContextDays, 45);
  assert.equal(result.intelligent.scenarioFlags.attackPath, false);
  assert.equal(result.intelligent.scenarioFlags.compoundRisk, true);
});
