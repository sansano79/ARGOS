import test from "node:test";
import assert from "node:assert/strict";

import {
  ACCOUNT_PATH,
  DETAIL_VIEW,
  KEV_LIST_PATH,
  PORTAL_PATH,
  SUBSCRIBER_TEAMS_PATH,
  VULN_LIST_PATH,
  getDetailPathForView,
  getSubscriberTeamDetailPath,
  getListPathForView,
  isViewAllowedForRole,
  parseAppRoute,
} from "./appNavigation.js";

test("subscriber can access account view", () => {
  assert.equal(isViewAllowedForRole("SUBSCRIBER", "account"), true);
  assert.equal(isViewAllowedForRole("SUBSCRIBER", "settings"), false);
});

test("viewer can access account but not portal", () => {
  assert.equal(isViewAllowedForRole("VIEWER", "account"), true);
  assert.equal(isViewAllowedForRole("VIEWER", "portal"), false);
  assert.equal(isViewAllowedForRole("VIEWER", "subscriber-teams"), false);
});

test("admin can access subscriber teams admin view", () => {
  assert.equal(isViewAllowedForRole("ADMIN", "subscriber-teams"), true);
});

test("parseAppRoute resolves top-level account and portal routes", () => {
  assert.deepEqual(parseAppRoute(ACCOUNT_PATH), { view: "account" });
  assert.deepEqual(parseAppRoute(PORTAL_PATH), { view: "portal" });
  assert.deepEqual(parseAppRoute(SUBSCRIBER_TEAMS_PATH), { view: "subscriber-teams", teamId: null });
});

test("parseAppRoute resolves detail routes preserving module context", () => {
  assert.deepEqual(parseAppRoute("/kev/CVE-2026-1234"), {
    view: DETAIL_VIEW,
    sourceView: "exploited",
    cveId: "CVE-2026-1234",
  });
  assert.deepEqual(parseAppRoute("/vulnerabilities/CVE-2026-1234"), {
    view: DETAIL_VIEW,
    sourceView: "vulns",
    cveId: "CVE-2026-1234",
  });
});

test("path helpers map module routes correctly", () => {
  assert.equal(getListPathForView("vulns"), VULN_LIST_PATH);
  assert.equal(getListPathForView("exploited"), KEV_LIST_PATH);
  assert.equal(getListPathForView("account"), ACCOUNT_PATH);
  assert.equal(getDetailPathForView("exploited", "CVE-2026-1234"), "/kev/CVE-2026-1234");
  assert.equal(getSubscriberTeamDetailPath(7), "/admin/subscriber-teams/7");
});

test("parseAppRoute resolves subscriber team detail route", () => {
  assert.deepEqual(parseAppRoute("/admin/subscriber-teams/7"), {
    view: "subscriber-teams",
    teamId: 7,
  });
});
