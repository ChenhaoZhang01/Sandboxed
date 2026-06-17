import test from "node:test";
import assert from "node:assert/strict";

import { normalizeDomain } from "../tools/phishing-detect.js";

test("normalizeDomain strips leading www. and keeps the real hostname canonical", () => {
  assert.equal(normalizeDomain("www.codecademy.com"), "codecademy.com");
  assert.equal(normalizeDomain("CODECADEMY.COM"), "codecademy.com");
});
