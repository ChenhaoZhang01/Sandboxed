import test from "node:test";
import assert from "node:assert/strict";

import { extractSearchQuery } from "../tools/phishing-detect.js";

test("extractSearchQuery strips noisy title fragments and keeps the meaningful brand term", () => {
  assert.equal(extractSearchQuery("| Codecademy"), "Codecademy");
  assert.equal(extractSearchQuery("Codecademy | Learn to code"), "Learn to code");
});
