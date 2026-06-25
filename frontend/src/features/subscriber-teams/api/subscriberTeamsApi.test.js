import test from "node:test";
import assert from "node:assert/strict";

import { createSubscriberTeamsApi } from "./subscriberTeamsApi.js";

test("subscriber teams api uses expected admin endpoints", async () => {
  const calls = [];
  const api = createSubscriberTeamsApi(async (path, options = {}) => {
    calls.push({ path, options });
    return new Response(JSON.stringify([{ id: 1 }]), { status: 200 });
  });

  const result = await api.listTeams();
  assert.deepEqual(result, [{ id: 1 }]);
  assert.equal(calls[0].path, "/subscriber-teams");
  await api.listMyTeams();
  await api.listAssignableUsers(7);
  assert.equal(calls[1].path, "/me/teams");
  assert.equal(calls[2].path, "/teams/7/users");
});

test("subscriber teams api maps network and conflict errors", async () => {
  const networkApi = createSubscriberTeamsApi(async () => {
    throw new Error("fetch failed");
  });

  await assert.rejects(() => networkApi.listTeams(), (error) => error.statusCode === 0);

  const conflictApi = createSubscriberTeamsApi(async () => new Response(JSON.stringify({ message: "Código duplicado" }), { status: 409 }));
  await assert.rejects(() => conflictApi.createTeam({}), (error) => error.statusCode === 409 && error.message === "Código duplicado");
});
