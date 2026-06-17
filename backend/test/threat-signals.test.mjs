import test from "node:test";
import assert from "node:assert/strict";
import { mock } from "node:test";

import { scoreRisk } from "../src/risk.js";
import { classifySignalThreats, detectTyposquat, inspectTlsSecurity } from "../src/threatSignals.js";

test("detectTyposquat flags paypa1 lookalikes", () => {
  assert.deepEqual(detectTyposquat("paypa1.com"), {
    hostname: "paypa1.com",
    brand: "paypal",
    distance: 1,
  });
});

test("inspectTlsSecurity flags weak or mismatched certificates", () => {
  const findings = inspectTlsSecurity("https://evil.example", {
    protocol: "TLSv1.0",
    subjectName: "example.com",
    issuer: "Self-Signed",
    validFrom: Math.floor(Date.now() / 1000) - 60,
    validTo: Math.floor(Date.now() / 1000) - 10,
  });

  assert.equal(findings.hostnameMismatch, true);
  assert.equal(findings.expired, true);
  assert.equal(findings.weakProtocol, true);
  assert.equal(findings.selfSigned, true);
  assert.ok(findings.issues.length >= 4);
});

test("classifySignalThreats penalizes wallet-drainer, clipboard, and typosquat patterns", () => {
  const summary = classifySignalThreats({
    runtime: {
      clipboardWrites: 2,
      evalCalls: 1,
      keystrokeHooks: 1,
      popunderAttempts: 1,
      walletCalls: 1,
      walletProviders: ["ethereum"],
      clipboardSamples: ["0xabc..."],
    },
    tls: {
      insecure: true,
      hostnameMismatch: true,
      expired: true,
      weakProtocol: true,
      selfSigned: true,
    },
    typosquat: { hostname: "paypa1.com", brand: "paypal", distance: 1 },
  });

  assert.ok(summary.score >= 60);
  assert.ok(summary.reasons.some((item) => /wallet provider/i.test(item.reason)));
  assert.ok(summary.reasons.some((item) => /clipboard/i.test(item.reason)));
  assert.ok(summary.reasons.some((item) => /typosquat/i.test(item.reason)));
});

test("scoreRisk incorporates the new runtime and TLS threat signals", async () => {
  const originalFetch = global.fetch;
  const fetchMock = mock.method(globalThis, "fetch", async (input) => {
    const url = String(input || "");
    if (url.includes("rdap.org")) {
      return new Response(JSON.stringify({ events: [{ eventAction: "registration", eventDate: "2024-01-01T00:00:00Z" }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ matches: [] }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });

  try {
    const result = await scoreRisk({
      requestedUrl: "https://paypa1.example.test",
      finalUrl: "https://paypa1.example.test",
      signals: {
        finalHost: "paypa1.example.test",
        runtime: {
          clipboardWrites: 2,
          evalCalls: 1,
          walletCalls: 1,
          walletProviders: ["ethereum"],
        },
        tls: {
          insecure: false,
          hostnameMismatch: false,
          expired: false,
          weakProtocol: false,
          selfSigned: false,
        },
        typosquat: { hostname: "paypa1.example.test", brand: "paypal", distance: 1 },
      },
    });

    assert.ok(result.score >= 40);
    assert.ok(result.reasons.some((item) => /typosquat/i.test(item.reason)) || result.reasons.some((item) => /wallet provider/i.test(item.reason)));
  } finally {
    fetchMock.mock.restore();
    global.fetch = originalFetch;
  }
});
