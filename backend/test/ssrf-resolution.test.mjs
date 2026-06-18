import test, { mock } from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns";

import { resolvePublicUrlState } from "../src/ssrf.js";

test("resolvePublicUrlState fails fast for unresolvable hosts", async () => {
  const lookupMock = mock.method(dns.promises, "lookup", () => new Promise(() => {}));

  try {
    const started = Date.now();
    const state = await resolvePublicUrlState("http://dead-host.example", {
      lookupTimeoutMs: 5,
    });
    const elapsed = Date.now() - started;

    assert.equal(state.blocked, true);
    assert.equal(state.reason, "unresolvable");
    assert.ok(elapsed < 500);
  } finally {
    lookupMock.mock.restore();
  }
});

test("resolvePublicUrlState allows a public host", async () => {
  const lookupMock = mock.method(dns.promises, "lookup", async () => [{ address: "93.184.216.34" }]);

  try {
    const state = await resolvePublicUrlState("http://example.com", { lookupTimeoutMs: 50 });

    assert.equal(state.blocked, false);
    assert.equal(state.reason, "public");
  } finally {
    lookupMock.mock.restore();
  }
});