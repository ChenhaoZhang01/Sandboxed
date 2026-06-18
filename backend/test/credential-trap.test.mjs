import test from "node:test";
import assert from "node:assert/strict";

import { makeCanary, matchCanaryHit } from "../src/credentialTrap.js";

// matchCanaryHit is the heart of the trap: it decides whether an intercepted
// request is the canary credential submission and whether the password is being
// shipped off-domain. Cross-domain = hard proof of credential theft, which is WHY
// the trap exists — these tests pin that distinction.

function fakeReq({ url, postData = null, method = "POST" }) {
  return { url: () => url, postData: () => postData, method: () => method };
}

test("makeCanary builds a fake identity with a unique, recognisable token", () => {
  const c = makeCanary();
  assert.equal(c.email, "canary@sandbox.invalid");
  assert.ok(c.password.startsWith("SANDBOX-DECOY-"));
  assert.equal(c.password, c.token);
  assert.notEqual(makeCanary().token, c.token); // unique per detonation
});

test("flags a cross-domain credential POST carrying the canary", () => {
  const c = makeCanary();
  const req = fakeReq({
    url: "https://evil-collector.xyz/save.php",
    postData: `user=canary@sandbox.invalid&pass=${c.password}`,
  });
  const hit = matchCanaryHit(req, c.token, "login-paypa1.test");
  assert.ok(hit);
  assert.equal(hit.host, "evil-collector.xyz");
  assert.equal(hit.crossDomain, true);
  assert.equal(hit.sentPassword, true);
});

test("same-host submission is captured but not cross-domain", () => {
  const c = makeCanary();
  const req = fakeReq({
    url: "https://example.test/login",
    postData: `pw=${c.password}`,
  });
  const hit = matchCanaryHit(req, c.token, "example.test");
  assert.ok(hit);
  assert.equal(hit.crossDomain, false);
});

test("ignores unrelated requests that don't carry the canary token", () => {
  const c = makeCanary();
  const req = fakeReq({ url: "https://cdn.example.test/app.js", method: "GET" });
  assert.equal(matchCanaryHit(req, c.token, "example.test"), null);
});

test("catches GET forms that smuggle the canary into the URL", () => {
  const c = makeCanary();
  const req = fakeReq({
    url: `https://evil.test/collect?pw=${c.password}`,
    method: "GET",
  });
  const hit = matchCanaryHit(req, c.token, "bank.test");
  assert.ok(hit);
  assert.equal(hit.crossDomain, true);
});
