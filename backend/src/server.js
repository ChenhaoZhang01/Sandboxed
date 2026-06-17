import "dotenv/config";
import express from "express";
import cors from "cors";
import { detonate, closeBrowser } from "./detonate.js";
import { scoreRisk } from "./risk.js";
import { isBlockedUrl } from "./ssrf.js";
import { runWithTimeout } from "./timeouts.js";
import { scanBuffer } from "./pdfScan.js";
import { checkForPhishing } from "../tools/phishing-detect.js";
import { readFile, writeFile } from 'fs/promises';
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const app = express();
const PORT = Number(process.env.PORT || 8787);
const PHISHING_ENRICHMENT_TIMEOUT_MS = Number(process.env.PHISHING_ENRICHMENT_TIMEOUT_MS || 10000);

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
    // Clone-detection is enrichment — a failure here must not fail the detonation.
    let phishing = null;
    try {
      phishing = await runWithTimeout(
        checkForPhishing(report),
        PHISHING_ENRICHMENT_TIMEOUT_MS,
        null
      );
    } catch (err) {
      console.error("phishing check failed (non-fatal):", err.message || err);
    }
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

app.get("/verified-links", async (_req, res) => {
  try {
    const data = await getVerifiedLinks();
    res.json({ ok: true, data });
  } catch (err) {
    res.status(500).json({ error: "Failed to load verified links" });
  }
});

app.post("/verified-links/add", async (req, res) => {
  try {
    const { url, data } = req.body;

    if (!url) {
      return res.status(400).json({ error: "Missing url" });
    }

    const result = await addVerifiedLink(url, data || null);

    res.json({ ok: true, added: result });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to add verified link" });
  }
});

const PDF_SCAN_LIMIT = `${Number(process.env.PDF_SCAN_MAX_MB || 20)}mb`;

/**
 * POST /scan-pdf
 * Body: raw PDF bytes, Content-Type: application/pdf
 * ClamAV being unreachable is not a request error — always responds 200
 * with a status field in that case; only bad input is a 4xx.
 */
app.post(
  "/scan-pdf",
  express.raw({ type: "application/pdf", limit: PDF_SCAN_LIMIT }),
  async (req, res) => {
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(400).json({ error: "Provide raw PDF bytes with Content-Type: application/pdf" });
    }
    if (req.body.subarray(0, 5).toString("latin1") !== "%PDF-") {
      return res.status(400).json({ error: "Payload is not a valid PDF (missing %PDF- header)" });
    }

    try {
      res.json(await scanBuffer(req.body));
    } catch (err) {
      console.error("scan-pdf failed:", err);
      res.status(500).json({ status: "error", message: String(err.message || err) });
    }
  }
);


async function getVerifiedLinks() {
  try {
    const filePath = path.join(__dirname, "../verifiedLinks.json");
    const rawData = await readFile(filePath, "utf8");
    return JSON.parse(rawData);
  } catch (error) {
    console.error("Error reading file:", error);
    return {};
  }
}

async function addVerifiedLink(url, data) {
  const filePath = path.join(__dirname, "../verifiedLinks.json");

  let existing = [];

  try {
    const raw = await readFile(filePath, "utf8");
    existing = JSON.parse(raw);
  } catch {
    existing = [];
  }

  const entry = {
    url,
    data,
    timestamp: Date.now(),
  };

  existing.push(entry);

  await writeFile(filePath, JSON.stringify(existing, null, 2), "utf8");

  return entry;
}

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
  console.log(`  POST /scan-pdf  (raw PDF bytes, Content-Type: application/pdf)`);
});

async function shutdown() {
  console.log("\nShutting down...");
  server.close();
  await closeBrowser();
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
