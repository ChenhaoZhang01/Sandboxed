import "dotenv/config";
import express from "express";
import cors from "cors";
import { detonate, closeBrowser } from "./detonate.js";
import { scoreRisk } from "./risk.js";
import { isBlockedUrl } from "./ssrf.js";
import { checkForPhishing } from "../tools/phishing-detect.js";

const app = express();
const PORT = Number(process.env.PORT || 8787);

app.use(cors());
app.use(express.json({ limit: "256kb" }));

app.get("/health", (_req, res) => res.json({ ok: true, service: "sandboxed" }));

/**
 * POST /detonate  { "url": "https://..." }
 * Opens the URL in a sandboxed headless browser, follows redirects,
 * screenshots the landing page, and returns a risk verdict.
 */
app.post("/detonate", async (req, res) => {
  const raw = (req.body && req.body.url ? String(req.body.url) : "").trim();
  const url = await resolveTarget(raw);

  if (!url) {
    return res
      .status(400)
      .json({ error: "Provide a valid, public http(s) url in { url }" });
  }

  const started = Date.now();
  try {
    const report = await detonate(url);
    const risk = await scoreRisk(report);
    const phishing = await checkForPhishing(report)
    console.log("phshing check!! ", phishing)

    res.json({
      verdict: risk.verdict,
      score: risk.score,
      reasons: risk.reasons,
      requestedUrl: report.requestedUrl,
      finalUrl: report.finalUrl,
      finalHost: report.signals?.finalHost || null,
      redirectChain: report.redirectChain,
      redirectCount: report.redirectCount,
      title: report.title,
      favicon: report.favicon,
      h1s: report.h1s,
      signals: report.signals,
      intel: risk.intel,
      downloads: report.downloads,
      blockedRequests: report.blockedRequests,
      screenshotBase64: report.screenshotBase64,
      elapsedMs: Date.now() - started,
      phishing,
    });
  } catch (err) {
    console.error("detonation failed:", err);
    res.status(500).json({ error: "Detonation failed", detail: String(err.message || err) });
  }
});

async function resolveTarget(input) {
  if (!input) return null;
  let candidate = input;
  if (!/^https?:\/\//i.test(candidate)) candidate = `http://${candidate}`;
  let u;
  try {
    u = new URL(candidate);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  // Pre-flight SSRF check: resolves DNS + canonicalizes IP forms and rejects
  // anything that isn't a public unicast address. Redirect hops are re-checked
  // inside the detonation engine (see detonate.js).
  if (await isBlockedUrl(u.toString())) return null;
  return u.toString();
}

const server = app.listen(PORT, () => {
  console.log(`Sandboxed detonation engine listening on http://localhost:${PORT}`);
  console.log(`  POST /detonate { "url": "..." }`);
});

async function shutdown() {
  console.log("\nShutting down...");
  server.close();
  await closeBrowser();
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
