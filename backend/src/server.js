import "dotenv/config";
import express from "express";
import cors from "cors";
import { detonate, closeBrowser } from "./detonate.js";
import { scoreRisk } from "./risk.js";
import { isBlockedUrl } from "./ssrf.js";
import { runWithTimeout } from "./timeouts.js";
import { scanBuffer } from "./pdfScan.js";
import { checkForPhishing } from "../tools/phishing-detect.js";
import { explainThreat } from "./threatNarrative.js";
import { closeSearchBrowser } from "../tools/brand-search.js";
import { attachLiveServer, closeLiveSessions } from "./live.js";
import { readFile, writeFile } from 'fs/promises';
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const app = express();
const PORT = Number(process.env.PORT || 8787);
const PHISHING_ENRICHMENT_TIMEOUT_MS = Number(process.env.PHISHING_ENRICHMENT_TIMEOUT_MS || 10000);
const NARRATIVE_TIMEOUT_MS = Number(process.env.NARRATIVE_TIMEOUT_MS || 20000);

function resolveAnalysisLayers(input = {}) {
  return {
    domainAge: input.domainAge !== false,
    safeBrowsing: input.safeBrowsing !== false,
    phishingEnrichment: input.phishingEnrichment === true,
    // Cautious default: an auto-download still flags even a trusted domain.
    // Send false to trust downloads from allowlisted/verified hosts.
    downloadsAsHardDanger: input.downloadsAsHardDanger !== false,
    // Record a screencast timeline of the detonation (default on).
    recordReplay: input.recordReplay !== false,
    // Auto-fill canary creds + trap the credential POST (opt-in: it submits forms).
    credentialTrap: input.credentialTrap === true,
    // AI plain-English threat narrative (opt-in: needs ANTHROPIC_API_KEY + costs tokens).
    aiNarrative: input.aiNarrative === true,
  };
}

app.use(cors());
app.use(express.json({ limit: "256kb" }));

app.get("/health", (_req, res) => res.json({ ok: true, service: "sandboxed" }));

app.get("/detonate/stream", async (req, res) => {
  writeSseHeaders(res);

  let closed = false;
  const heartbeat = setInterval(() => {
    if (!closed) res.write(": keepalive\n\n");
  }, 15000);

  req.on("close", () => {
    closed = true;
    clearInterval(heartbeat);
  });

  const send = (event, data) => {
    if (closed) return;
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  try {
    const raw = String(req.query?.url || "").trim();
    const analysisLayers = parseAnalysisLayersQuery(req.query || {});
    const result = await runDetonation(raw, analysisLayers, (progress) => {
      send("progress", progress);
    });
    send("result", result);
    send("done", { ok: true });
  } catch (err) {
    console.error("streamed detonation failed:", err);
    send("scan-error", {
      error: err.publicMessage || "Detonation failed",
      detail: String(err.message || err),
    });
  } finally {
    closed = true;
    clearInterval(heartbeat);
    res.end();
  }
});

/**
 * POST /detonate  { "url": "https://..." }
 * Opens the URL in a sandboxed headless browser, follows redirects,
 * screenshots the landing page, and returns a risk verdict.
 */
app.post("/detonate", async (req, res) => {
  const raw = (req.body && req.body.url ? String(req.body.url) : "").trim();
  try {
    res.json(await runDetonation(raw, req.body?.analysisLayers));
  } catch (err) {
    console.error("detonation failed:", err);
    res
      .status(err.statusCode || 500)
      .json({ error: err.publicMessage || "Detonation failed", detail: String(err.message || err) });
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
app.get("/dangerous-links", async (_req, res) => {
  try {
    const data = await getDangerousLinks();
    res.json({ ok: true, data });
  } catch (err) {
    res.status(500).json({ error: "Failed to load dangerous links" });
  }
});
app.post("/dangerous-links/add", async (req, res) => {
  try {
    const newCount = await addDangerousLinkCount();

    res.json({
      ok: true,
      dangerousLinks: newCount
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update dangerous link count" });
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

// --- Spot-the-Phish leaderboard ---
// Same JSON-file pattern as verified-links. Ephemeral demo data (gitignored).
const LEADERBOARD_PATH = path.join(__dirname, "../leaderboard.json");
const LEADERBOARD_TOP = 50;
const LEADERBOARD_KEEP = 1000;

function startOfTodayMs() {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

async function readLeaderboard() {
  try {
    const raw = await readFile(LEADERBOARD_PATH, "utf8");
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

app.get("/leaderboard", async (req, res) => {
  try {
    const entries = await readLeaderboard();
    const since = req.query.period === "all" ? 0 : startOfTodayMs();
    const data = entries
      .filter((e) => e && typeof e.score === "number" && e.ts >= since)
      .sort((a, b) => b.score - a.score)
      .slice(0, LEADERBOARD_TOP);
    res.json({ ok: true, data });
  } catch (err) {
    res.status(500).json({ error: "Failed to load leaderboard" });
  }
});

app.post("/leaderboard", async (req, res) => {
  try {
    const rawScore = Number(req.body?.score);
    if (!Number.isFinite(rawScore)) {
      return res.status(400).json({ error: "score must be a number" });
    }
    const score = Math.max(0, Math.min(9999, Math.floor(rawScore)));
    const name =
      String(req.body?.name ?? "")
        .trim()
        .replace(/[^\w \-]/g, "")
        .slice(0, 12) || "ANON";

    const entries = await readLeaderboard();
    const entry = { name, score, ts: Date.now() };
    entries.push(entry);
    // Cap file growth — keep the most recent submissions only.
    const trimmed = entries.slice(-LEADERBOARD_KEEP);
    await writeFile(LEADERBOARD_PATH, JSON.stringify(trimmed, null, 2), "utf8");

    res.json({ ok: true, entry });
  } catch (err) {
    console.error("leaderboard add failed:", err);
    res.status(500).json({ error: "Failed to record score" });
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
      res.json(await scanBuffer(req.body, ".pdf"));
    } catch (err) {
      console.error("scan-pdf failed:", err);
      res.status(500).json({ status: "error", message: String(err.message || err) });
    }
  }
);

const FILE_SCAN_LIMIT = `${Number(process.env.FILE_SCAN_MAX_MB || 50)}mb`;

/**
 * POST /scan-file
 * Body: raw file bytes, any Content-Type. The download-guard / file-checker path —
 * no format check (unlike /scan-pdf), just a real ClamAV scan of the bytes.
 * ClamAV being unreachable is not a request error (responds 200 with a status field);
 * only empty input is a 4xx.
 */
app.post(
  "/scan-file",
  express.raw({ type: () => true, limit: FILE_SCAN_LIMIT }),
  async (req, res) => {
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(400).json({ error: "Provide raw file bytes in the request body" });
    }

    try {
      res.json(await scanBuffer(req.body));
    } catch (err) {
      console.error("scan-file failed:", err);
      res.status(500).json({ status: "error", message: String(err.message || err) });
    }
  }
);

function writeSseHeaders(res) {
  res.status(200);
  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  if (typeof res.flushHeaders === "function") res.flushHeaders();
}

function parseBoolean(value) {
  if (value == null) return undefined;
  const normalized = String(Array.isArray(value) ? value[0] : value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return undefined;
}

function parseAnalysisLayersQuery(query) {
  let parsed = {};
  if (typeof query.analysisLayers === "string") {
    try {
      const value = JSON.parse(query.analysisLayers);
      if (value && typeof value === "object") parsed = value;
    } catch {
      parsed = {};
    }
  }

  for (const key of [
    "domainAge",
    "safeBrowsing",
    "phishingEnrichment",
    "downloadsAsHardDanger",
    "recordReplay",
    "credentialTrap",
    "aiNarrative",
  ]) {
    const value = parseBoolean(query[key]);
    if (typeof value === "boolean") parsed[key] = value;
  }

  return parsed;
}

function requestError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  err.publicMessage = message;
  return err;
}

function emitProgress(onProgress, stage, message, extra = {}) {
  if (typeof onProgress !== "function") return;
  onProgress({ stage, message, ...extra, ts: Date.now() });
}

async function runDetonation(raw, analysisLayerInput, onProgress) {
  emitProgress(onProgress, "resolving", "resolving target");
  const url = await resolveTarget(raw);
  const analysisLayers = resolveAnalysisLayers(analysisLayerInput);

  if (!url) {
    throw requestError("Provide a valid, public http(s) url in { url }");
  }

  const started = Date.now();
  const report = await detonate(url, {
    recordReplay: analysisLayers.recordReplay,
    credentialTrap: analysisLayers.credentialTrap,
    onProgress,
  });

  // Risk scoring (core) and brand-detection (enrichment) both derive only from
  // `report`, so run them CONCURRENTLY instead of back-to-back to cut latency.
  // Brand-detection is best-effort: it's time-bounded and a failure or timeout
  // resolves to null rather than failing the detonation.
  emitProgress(onProgress, "scoring", "scoring");
  const phishingPromise = analysisLayers.phishingEnrichment
    ? runWithTimeout(checkForPhishing(report), PHISHING_ENRICHMENT_TIMEOUT_MS, null).catch(
        (err) => {
          console.error("phishing check failed (non-fatal):", err.message || err);
          return null;
        }
      )
    : Promise.resolve(null);

  const [risk, phishing] = await Promise.all([
    scoreRisk(report, { analysisLayers }),
    phishingPromise,
  ]);

  const result = {
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
    replayFrames: report.replayFrames,
    credentialTrap: report.credentialTrap,
    elapsedMs: Date.now() - started,
    phishing,
  };

  // AI threat narrative: derives from the assembled result above, so it runs
  // last. Best-effort + time-bounded — a failure leaves `narrative` null and
  // never fails the detonation.
  if (analysisLayers.aiNarrative) {
    emitProgress(onProgress, "narrating", "writing threat narrative");
    result.narrative = await runWithTimeout(explainThreat(result), NARRATIVE_TIMEOUT_MS, null).catch(
      (err) => {
        console.error("narrative failed (non-fatal):", err.message || err);
        return null;
      }
    );
  }

  emitProgress(onProgress, "complete", "complete", {
    verdict: result.verdict,
    score: result.score,
  });
  return result;
}


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
async function addDangerousLinkCount() {
  const filePath = path.join(__dirname, "../dangerousLinks.json")
  let existing = [0]
  try {
    const raw = await readFile(filePath, "utf8");
    existing = JSON.parse(raw);
  } catch {
    existing = [0];
  }
  existing[0] = (existing[0] || 0) + 1;
  await writeFile(filePath,JSON.stringify(existing,null,2), "utf8");
  return existing[0];
}
async function getDangerousLinks(url, data) {
  try{
    const filePath = path.join(__dirname, "../dangerousLinks.json")
    const rawData = await readFile(filePath, "utf8");
    return JSON.parse(rawData);
  } catch (error) {
    console.error("Error reading file:", error);
    return [];
  }
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
  console.log(`  POST /scan-file (raw file bytes, any Content-Type)`);
  console.log(`  WS   /live?url=...  (live interactive sandbox)`);
});

// Live interactive sandbox shares the same HTTP server (WebSocket upgrade on /live).
attachLiveServer(server);

async function shutdown() {
  console.log("\nShutting down...");
  server.close();
  await Promise.all([closeLiveSessions(), closeBrowser(), closeSearchBrowser()]);
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
