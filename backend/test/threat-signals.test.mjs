import test from "node:test";
import assert from "node:assert/strict";
import { mock } from "node:test";

import { scoreRisk } from "../src/risk.js";
import {
  auditThirdPartyTrackers,
  classifySignalThreats,
  detectSurveyGiveawayScam,
  detectTechSupportScam,
  detectTyposquat,
  inspectTlsSecurity,
} from "../src/threatSignals.js";

test("detectSurveyGiveawayScam catches giveaway language", () => {
  assert.deepEqual(detectSurveyGiveawayScam("You won a free gift card — claim now!"), {
    suspicious: true,
    matchedTerms: ["you won", "free gift card", "claim now"],
  });
});

test("detectTechSupportScam catches fake virus support-lock patterns", () => {
  const findings = detectTechSupportScam({
    text: "Critical security alert. Virus detected. Do not close this window. Call Microsoft Support at 800-555-1212.",
    runtime: {
      fullscreenRequests: 1,
      dialogCalls: 2,
      exitLockHooks: 1,
    },
  });

  assert.equal(findings.suspicious, true);
  assert.ok(findings.matchedTerms.includes("virus detected"));
  assert.deepEqual(findings.phoneNumbers, ["800-555-1212"]);
  assert.equal(findings.fullscreenRequests, 1);
});

test("auditThirdPartyTrackers counts third-party trackers and cookies", () => {
  const audit = auditThirdPartyTrackers(
    ["https://www.google-analytics.com/ga.js", "https://cdn.example.test/app.js"],
    "https://safe.example.test/",
    ["session", "uid", "token", "lang", "theme"],
    ["a", "b", "c", "d", "e", "f", "g"]
  );

  assert.equal(audit.thirdPartyCount, 2);
  assert.equal(audit.trackerCount, 1);
  assert.equal(audit.cookieCount, 5);
  assert.equal(audit.storageKeyCount, 7);
});

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

test("classifySignalThreats penalizes tech-support scams and webdriver sandbox probes", () => {
  const summary = classifySignalThreats({
    techSupportScam: {
      suspicious: true,
      matchedTerms: ["security alert", "call support", "do not close"],
      phoneNumbers: ["800-555-1212"],
      fullscreenRequests: 1,
      dialogCalls: 3,
      exitLockHooks: 1,
    },
    runtime: {
      fullscreenRequests: 1,
      dialogCalls: 3,
      exitLockHooks: 1,
      sandboxProbes: 2,
      sandboxProbeProperties: ["navigator.webdriver"],
    },
  });

  assert.ok(summary.score >= 60);
  assert.ok(summary.reasons.some((item) => /tech-support scam/i.test(item.reason)));
  assert.ok(summary.reasons.some((item) => /navigator\.webdriver/i.test(item.reason)));
  assert.ok(summary.reasons.some((item) => /fullscreen/i.test(item.reason)));
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
