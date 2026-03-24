import test from "node:test";
import assert from "node:assert/strict";

import {
  ACCOUNT_PATH,
  DETAIL_VIEW,
  KEV_LIST_PATH,
  PORTAL_PATH,
  VULN_LIST_PATH,
  getDetailPathForView,
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
});

test("parseAppRoute resolves top-level account and portal routes", () => {
  assert.deepEqual(parseAppRoute(ACCOUNT_PATH), { view: "account" });
  assert.deepEqual(parseAppRoute(PORTAL_PATH), { view: "portal" });
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
});
