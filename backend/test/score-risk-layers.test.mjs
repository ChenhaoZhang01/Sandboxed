import test from "node:test";
import assert from "node:assert/strict";
import { mock } from "node:test";

import { scoreRisk } from "../src/risk.js";

test("scoreRisk skips optional intelligence layers when disabled", async () => {
  const originalFetch = global.fetch;
  const fetchMock = mock.method(globalThis, "fetch", async () => {
    throw new Error("fetch should not be called when optional layers are disabled");
  });

  try {
    const result = await scoreRisk(
      {
        requestedUrl: "https://example.com",
        finalUrl: "https://example.com",
        signals: {
          finalHost: "example.com",
        },
      },
      {
        analysisLayers: {
          domainAge: false,
          safeBrowsing: false,
        },
      }
    );

    assert.equal(result.intel.domainAge.skipped, true);
    assert.equal(result.intel.safeBrowsing.skipped, true);
  } finally {
    fetchMock.mock.restore();
    global.fetch = originalFetch;
  }
});

test("scoreRisk does not let trusted hosts suppress impersonation evidence", async () => {
  const originalFetch = global.fetch;
  const fetchMock = mock.method(globalThis, "fetch", async () => {
    throw new Error("fetch should not be called when optional layers are disabled");
  });

  try {
    const result = await scoreRisk(
      {
        requestedUrl: "https://google.com.fake.example",
        finalUrl: "https://google.com.fake.example",
        signals: {
          finalHost: "google.com",
          brandImpersonation: ["IRS"],
        },
        phishing: {
          phishing: true,
          spoofedBrand: "IRS",
        },
      },
      {
        analysisLayers: {
          domainAge: false,
          safeBrowsing: false,
        },
      }
    );

    assert.equal(result.verdict, "dangerous");
    assert.ok(result.score >= 60);
    assert.ok(result.reasons.some((item) => /impersonation/i.test(item.reason)));
    assert.ok(result.reasons.some((item) => /phishing detector matched/i.test(item.reason)));
  } finally {
    fetchMock.mock.restore();
    global.fetch = originalFetch;
  }
});
