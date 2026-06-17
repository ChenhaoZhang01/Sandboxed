import test from "node:test";
import assert from "node:assert/strict";

import { runWithTimeout } from "../src/timeouts.js";

test("runWithTimeout falls back when work exceeds the limit", async () => {
  const result = await runWithTimeout(
    new Promise((resolve) => setTimeout(() => resolve("late"), 100)),
    10,
    "fallback"
  );

  assert.equal(result, "fallback");
});

test("runWithTimeout returns the real value when work finishes in time", async () => {
  const result = await runWithTimeout(
    Promise.resolve("ok"),
    100,
    "fallback"
  );

  assert.equal(result, "ok");
});
