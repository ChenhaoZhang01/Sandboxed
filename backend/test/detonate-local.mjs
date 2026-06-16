// Self-contained detonation test: serves the phishing fixture on a local port
// and detonates it directly (bypassing the server's SSRF guard, which is fine
// for a controlled test). Proves the credential-harvesting detection path.
// The fixture is served on 127.0.0.1, which the SSRF guard blocks by default.
// This flag (test-only) allows private targets for this controlled local run.
process.env.ALLOW_PRIVATE_TARGETS = "1";

import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { detonate, closeBrowser } from "../src/detonate.js";
import { scoreRisk } from "../src/risk.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(__dirname, "fixtures", "fake-paypal.html"), "utf8");

const PORT = 3999;
const server = http.createServer((_req, res) => {
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(html);
});

await new Promise((r) => server.listen(PORT, "127.0.0.1", r));

try {
  const report = await detonate(`http://127.0.0.1:${PORT}/`);
  const risk = await scoreRisk(report);

  console.log("=== FAKE PAYPAL FIXTURE ===");
  console.log("verdict :", risk.verdict, "| score:", risk.score);
  console.log("title   :", report.title);
  console.log("signals :", JSON.stringify(report.signals, null, 2));
  console.log("reasons :");
  for (const r of risk.reasons) console.log(`  +${r.points}  ${r.reason}`);
} finally {
  await closeBrowser();
  server.close();
}
