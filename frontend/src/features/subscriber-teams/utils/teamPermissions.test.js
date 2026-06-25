import test from "node:test";
import assert from "node:assert/strict";

import {
  canAccessSubscriberTeamsAdmin,
  canManageMembers,
  canManageRecipients,
  canManageSubscriptions,
  canManageSystems,
  canViewTeam,
} from "./teamPermissions.js";

test("ADMIN can access subscriber teams admin navigation", () => {
  assert.equal(canAccessSubscriberTeamsAdmin("ADMIN"), true);
  assert.equal(canAccessSubscriberTeamsAdmin("VIEWER"), false);
  assert.equal(canAccessSubscriberTeamsAdmin("SUBSCRIBER"), false);
});

test("team permission helpers allow admin and manager flows only where expected", () => {
  const managerTeam = {
    role: "TEAM_MANAGER",
    canRead: true,
    canManageRecipients: true,
    canManageSubscriptions: true,
    canManageSystems: true,
  };

  assert.equal(canViewTeam({ globalRole: "ADMIN" }), true);
  assert.equal(canViewTeam({ globalRole: "USER", team: managerTeam }), true);
  assert.equal(canManageMembers({ globalRole: "ADMIN" }), true);
  assert.equal(canManageMembers({ globalRole: "USER" }), false);
  assert.equal(canManageRecipients({ globalRole: "USER", team: managerTeam }), true);
  assert.equal(canManageSubscriptions({ globalRole: "USER", team: managerTeam }), true);
  assert.equal(canManageSystems({ globalRole: "USER", team: managerTeam }), true);
  assert.equal(canManageRecipients({ globalRole: "USER", team: { role: "TEAM_VIEWER", canRead: true } }), false);
});

