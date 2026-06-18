const $ = (id) => document.getElementById(id);
const DEFAULT_API = "https://sandboxed.fly.dev";

// --- API base, persisted ---
const apiInput = $("api");
apiInput.value = localStorage.getItem("sandboxed_api") || DEFAULT_API;
apiInput.addEventListener("change", () =>
  localStorage.setItem("sandboxed_api", apiInput.value.trim())
);
const apiBase = () => (apiInput.value.trim() || DEFAULT_API).replace(/\/$/, "");

// --- elements ---
const urlInput = $("url");
const goBtn = $("go");
const status = $("status");
const statusText = $("status-text");
const consoleState = $("console-state");
const idle = $("idle");
const spinner = $("spinner");
const shot = $("shot");
const glass = $("glass");
const stamp = $("stamp");
const errorBox = $("error");
const readout = $("readout");

// --- pdf scan elements ---
const dropzone = $("dropzone");
const fileInput = $("pdf-file-input");
const browseBtn = $("pdf-browse-btn");
const dropzoneStatus = $("dropzone-status");
const scanResult = $("scan-result");

//Settings
const historySwitch = $("historySwitch")

function setStatus(state, text) {
  status.dataset.state = state;
  statusText.textContent = text;
}

function setDetonationProgress(step) {
  const raw = String((step && (step.message || step.stage)) || "Working");
  const text = raw.charAt(0).toUpperCase() + raw.slice(1);
  setStatus("running", text);
  consoleState.textContent = text;
  const spinnerText = spinner.querySelector("p");
  if (spinnerText) spinnerText.textContent = text + "...";
}

function resetView() {
  errorBox.classList.add("hidden");
  readout.classList.add("hidden");
  shot.classList.add("hidden");
  glass.classList.add("hidden");
  stamp.classList.add("hidden");
  stamp.classList.remove("stamp-in");
  idle.classList.add("hidden");
  teardownExtras();
}

function normalize(u) {
  try {
    const url = new URL(u.includes("://") ? u : "http://" + u);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return u.replace(/^https?:\/\//, "").replace(/\/$/, "");
  }
}
async function detonate(rawUrl) {
  const url = (rawUrl ?? urlInput.value).trim();
  if (!url) {
    urlInput.focus();
    return;
  }
  urlInput.value = url;
  resetView();
  spinner.classList.remove("hidden");
  goBtn.disabled = true;
  setDetonationProgress({ message: "resolving target" });

  try {
    let verifiedLinks = [];
    if (checked("historySwitch", true)) {
      try {
        verifiedLinks = await fetchVerifiedLinks();
      } catch (err) {
        console.warn("failed to load scan history:", err.message);
      }
      const match = verifiedLinks.find(
        (x) => normalize(x.url) === normalize(url)
      );

      if (match) {
        spinner.classList.add("hidden");
        render(match.data);
        return;
      }
    }
    const analysisLayers = currentAnalysisLayers();
    const data = await detonateWithProgress(url, analysisLayers);
    spinner.classList.add("hidden");
    // Don't persist the replay frames in the verified-links cache — they're large
    // base64 JPEGs and would bloat the store. Everything else is kept.
    const { replayFrames, ...cacheable } = data;
    await fetch(apiBase() + "/verified-links/add", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        data: cacheable,
      }),
    });
    render(data);
  } catch (err) {
    spinner.classList.add("hidden");
    showError(
      err.userFacing
        ? err.message
        : "Could not reach the detonation engine at " +
            apiBase() +
            ". Is the backend running? " +
            "(" + err.message + ")"
    );
  } finally {
    goBtn.disabled = false;
  }
}

function currentAnalysisLayers() {
  return {
    domainAge: checked("domainAgeSwitch", true),
    safeBrowsing: checked("safeBrowsingSwitch", true),
    phishingEnrichment: checked("phishingSwitch"),
    recordReplay: checked("replaySwitch", true),
    credentialTrap: checked("trapSwitch"),
  };
}

async function postDetonate(url, analysisLayers) {
  const res = await fetch(apiBase() + "/detonate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, analysisLayers }),
  });

  const data = await res.json();
  if (!res.ok) {
    const err = new Error(data.error || "Detonation failed.");
    err.userFacing = true;
    throw err;
  }
  return data;
}

function streamDetonate(url, analysisLayers) {
  return new Promise((resolve, reject) => {
    const params = new URLSearchParams({
      url,
      analysisLayers: JSON.stringify(analysisLayers),
    });
    const source = new EventSource(apiBase() + "/detonate/stream?" + params.toString());
    let settled = false;

    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      source.close();
      fn(value);
    };

    source.addEventListener("progress", (ev) => {
      try {
        setDetonationProgress(JSON.parse(ev.data));
      } catch {}
    });

    source.addEventListener("result", (ev) => {
      try {
        finish(resolve, JSON.parse(ev.data));
      } catch (err) {
        finish(reject, err);
      }
    });

    source.addEventListener("scan-error", (ev) => {
      let message = "Detonation failed.";
      try {
        const data = JSON.parse(ev.data);
        message = data.error || message;
      } catch {}
      const err = new Error(message);
      err.scanError = true;
      err.userFacing = true;
      finish(reject, err);
    });

    source.onerror = () => {
      if (!settled) finish(reject, new Error("Live progress stream failed."));
    };
  });
}

async function detonateWithProgress(url, analysisLayers) {
  if (!("EventSource" in window)) {
    return postDetonate(url, analysisLayers);
  }

  try {
    return await streamDetonate(url, analysisLayers);
  } catch (err) {
    if (err.scanError) throw err;
    setDetonationProgress({ message: "retrying without live progress" });
    return postDetonate(url, analysisLayers);
  }
}

async function fetchVerifiedLinks() {
  const res = await fetch(apiBase() + '/verified-links');
  const data = await res.json();

  if (!data.ok) throw new Error("Failed to load links");

  return data.data;
}

// Static indicator scan: reads a PDF's raw bytes in-browser and checks for
// keywords associated with active-content/auto-run PDF malware. This is a
// heuristic only — real AV scanning happens server-side via /scan-pdf.
async function scanPDF(file) {
  const buffer = await file.arrayBuffer();
  // latin1 is a byte-safe 1:1 decoding — never throws on binary PDF content,
  // and the ASCII indicator keywords below still match correctly under it.
  const pdfContent = new TextDecoder("latin1").decode(buffer);

  const indicators = ["/JS", "/JavaScript", "/OpenAction", "/AA", "/EmbeddedFile"];
  const foundIndicators = indicators.filter((i) => pdfContent.includes(i));

  return { foundIndicators };
}

// POST the raw PDF bytes to the backend for a real ClamAV scan. Never throws —
// network/backend failures resolve to a result object so the caller can still
// show the local indicator result.
async function scanPdfOnServer(file) {
  try {
    const res = await fetch(apiBase() + "/scan-pdf", {
      method: "POST",
      headers: { "Content-Type": "application/pdf" },
      body: file,
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      return { status: "error", message: (data && data.error) || `Server returned ${res.status}` };
    }
    return data;
  } catch (err) {
    return { status: "error", message: "Could not reach " + apiBase() + " (" + err.message + ")" };
  }
}

async function handlePdfFile(file) {
  if (!file) return;
  if (file.type !== "application/pdf" && !file.name.toLowerCase().endsWith(".pdf")) {
    scanResult.textContent = "Please drop or select a PDF file.";
    scanResult.classList.remove("hidden", "safe", "warn");
    scanResult.classList.add("danger");
    return;
  }

  dropzoneStatus.textContent = "Scanning…";
  dropzone.classList.add("scanning");
  scanResult.classList.add("hidden");

  try {
    const [local, server] = await Promise.all([scanPDF(file), scanPdfOnServer(file)]);
    renderScanResult(file.name, local, server);
  } finally {
    dropzone.classList.remove("scanning");
    dropzoneStatus.textContent = "Drop a PDF here or click to browse";
    fileInput.value = "";
  }
}

function renderScanResult(filename, local, server) {
  const lines = [`PDF scan: ${filename}`, ""];

  lines.push(
    local.foundIndicators.length > 0
      ? `Suspicious indicators found: ${local.foundIndicators.join(", ")}`
      : "No suspicious indicators found (client-side check)."
  );

  if (server.status === "infected") {
    lines.push(`ClamAV: INFECTED — ${(server.viruses || []).join(", ") || "unknown signature"}`);
  } else if (server.status === "clean") {
    lines.push("ClamAV: clean.");
  } else if (server.status === "unavailable") {
    lines.push("ClamAV: scanner unavailable on server.");
  } else {
    lines.push(`ClamAV: could not complete scan (${server.message || "unknown error"}).`);
  }

  const infected = (server.status == "infected") || local.foundIndicators.length > 0;
  const confirmedClean = (server.status == "clean") && local.foundIndicators.length === 0;

  scanResult.textContent = lines.join("\n");
  scanResult.classList.remove("hidden", "safe", "warn", "danger");
  scanResult.classList.add(infected ? "danger" : confirmedClean ? "safe" : "warn");
}

function showError(msg) {
  setStatus("idle", "Idle");
  consoleState.textContent = "Ready";
  idle.classList.remove("hidden");
  errorBox.textContent = msg;
  errorBox.classList.remove("hidden");
}

function render(d) {
  console.log("render: ", d)
  setStatus("armed", "Contained");
  consoleState.textContent = "Done";

  // screenshot behind blast glass
  if (d.screenshotBase64) {
    shot.src = "data:image/jpeg;base64," + d.screenshotBase64;
    shot.classList.remove("hidden");
    glass.classList.remove("hidden");
  }

  // verdict stamp
  const verdict = d.verdict || "safe";
  stamp.dataset.verdict = verdict;
  stamp.innerHTML =
    verdict.toUpperCase() +
    ' <span class="score">· ' +
    (d.score ?? 0) +
    "</span>";
  stamp.classList.remove("hidden");
  void stamp.offsetWidth;
  stamp.classList.add("stamp-in");

  // meta
  $("m-final").textContent = d.finalHost || hostOf(d.finalUrl) || "—";
  $("m-age").textContent = formatAge(d.intel && d.intel.domainAge);
  $("m-redirects").textContent =
    (d.redirectCount ?? 0) + (d.redirectCount === 1 ? " hop" : " hops");
  $("m-title").textContent = d.title || "—";

  // phishing
  renderPhishing(d.phishing);
  renderTrap(d.credentialTrap);
  setupReplay(d.replayFrames || []);
  setupLive(d.finalUrl || d.requestedUrl || urlInput.value);

  renderTrajectory(d.redirectChain || []);
  renderReasons(d.reasons || []);

  readout.classList.remove("hidden");
}

function renderPhishing(p) {
  const el = $("m-phishing");
  if (!el) return;

  if (p && p.phishing) {
    el.innerHTML =
      "⚠️ Spoofing <strong>" + escapeHtml(p.spoofedBrand) + "</strong>" +
      " — real site: <a href=\"" + escapeHtml(p.expectedUrl) + "\" target=\"_blank\" rel=\"noopener\">" +
      escapeHtml(p.expectedUrl) + "</a>";
    el.className = "v phishing-warn";
    return;
  }

  el.textContent = "✓ No spoof detected";
  el.className = "v phishing-ok";
}

function renderTrajectory(chain) {
  const ul = $("traj");
  ul.innerHTML = "";
  if (!chain.length) {
    ul.innerHTML =
      '<li class="final"><span class="host">(no navigation captured)</span></li>';
    return;
  }
  chain.forEach((u, i) => {
    const li = document.createElement("li");
    if (i === chain.length - 1) li.className = "final";
    const host = hostOf(u);
    li.innerHTML =
      '<span class="host">' + escapeHtml(host) + "</span> " +
      '<span style="color:var(--ink-faint)">' +
      escapeHtml(pathOf(u)) +
      "</span>";
    ul.appendChild(li);
  });
}

function renderReasons(reasons) {
  const ul = $("reasons");
  ul.innerHTML = "";
  if (!reasons.length) {
    const li = document.createElement("li");
    li.innerHTML =
      '<div class="empty-reasons">No threat signals detected — nothing suspicious in the chamber.</div>';
    ul.appendChild(li);
    return;
  }
  reasons.forEach((r) => {
    const sev = r.points >= 30 ? "sev-hi" : r.points >= 12 ? "sev-mid" : "sev-lo";
    const li = document.createElement("li");
    li.className = "reason " + sev;
    li.innerHTML =
      '<span class="pts mono">+' + r.points + "</span>" +
      "<span>" + escapeHtml(r.reason) + "</span>";
    ul.appendChild(li);
  });
}

// ---------- password trap ----------
function renderTrap(t) {
  const el = $("m-trap");
  if (!el) return;
  if (!t) {
    el.textContent = "✓ No password trap detected";
    el.className = "v phishing-ok";
    return;
  }
  if (t.blocked) {
    el.innerHTML =
      (t.crossDomain
        ? "⚠️ Password would be sent off-domain to "
        : "Captured submission to ") +
      "<strong>" + escapeHtml(t.host || "?") + "</strong> — blocked, never sent";
    el.className = "v " + (t.crossDomain ? "phishing-warn" : "phishing-ok");
  } else if (t.attempted) {
    el.textContent = "Filled canary creds; no submission captured.";
    el.className = "v";
  } else {
    el.textContent = "✓ No password trap detected";
    el.className = "v phishing-ok";
  }
}

// ---------- replay player ----------
// Scrubs the screencast frames captured during detonation through the chamber's
// existing screenshot <img> (the verdict stamp + blast glass stay overlaid).
let replayFrames = [];
let replayIdx = 0;
let replayTimer = null;
const chamberTools = $("chamber-tools");
const replayControls = $("replay-controls");
const replayPlayBtn = $("replay-play");
const replayScrub = $("replay-scrub");
const replayTime = $("replay-time");

function showFrame(i) {
  if (!replayFrames.length) return;
  replayIdx = Math.max(0, Math.min(replayFrames.length - 1, i));
  shot.src = "data:image/jpeg;base64," + replayFrames[replayIdx].data;
  shot.classList.remove("hidden");
  replayScrub.value = String(replayIdx);
  replayTime.textContent = replayIdx + 1 + " / " + replayFrames.length;
}
function stopReplay() {
  if (replayTimer) {
    clearInterval(replayTimer);
    replayTimer = null;
  }
  replayPlayBtn.textContent = "▶ Replay";
}
function playReplay() {
  if (replayTimer) {
    stopReplay();
    return;
  }
  if (replayIdx >= replayFrames.length - 1) replayIdx = -1;
  replayPlayBtn.textContent = "⏸ Pause";
  replayTimer = setInterval(() => {
    if (replayIdx >= replayFrames.length - 1) {
      stopReplay();
      return;
    }
    showFrame(replayIdx + 1);
  }, 350);
}
function setupReplay(frames) {
  replayFrames = Array.isArray(frames) ? frames : [];
  stopReplay();
  if (!replayFrames.length) {
    replayControls.classList.add("hidden");
    return;
  }
  chamberTools.classList.remove("hidden");
  replayControls.classList.remove("hidden");
  replayScrub.max = String(replayFrames.length - 1);
  replayScrub.value = "0";
  replayIdx = 0;
  replayTime.textContent = "1 / " + replayFrames.length;
}
replayPlayBtn.addEventListener("click", playReplay);
replayScrub.addEventListener("input", () => {
  stopReplay();
  showFrame(Number(replayScrub.value));
});

// ---------- live interactive sandbox ----------
const liveCanvas = $("live-canvas");
const liveStartBtn = $("live-start");
const liveStopBtn = $("live-stop");
const liveNote = $("live-note");
const liveCtx = liveCanvas.getContext("2d");
let liveSocket = null;
let liveUrl = null;
let liveVW = 1280;
let liveVH = 800;
const liveImg = new Image();
liveImg.onload = () => liveCtx.drawImage(liveImg, 0, 0, liveCanvas.width, liveCanvas.height);

function wsBase() {
  return apiBase().replace(/^http/i, "ws");
}
function setupLive(url) {
  liveUrl = url;
  if (checked("liveSwitch") && url) {
    chamberTools.classList.remove("hidden");
    liveStartBtn.classList.remove("hidden");
  } else {
    liveStartBtn.classList.add("hidden");
  }
}
function startLive() {
  if (!liveUrl || liveSocket) return;
  liveNote.textContent = "connecting…";
  liveStartBtn.classList.add("hidden");
  let sock;
  try {
    sock = new WebSocket(wsBase() + "/live?url=" + encodeURIComponent(liveUrl));
  } catch {
    liveNote.textContent = "could not connect";
    liveStartBtn.classList.remove("hidden");
    return;
  }
  liveSocket = sock;
  sock.onmessage = (ev) => {
    let m;
    try {
      m = JSON.parse(ev.data);
    } catch {
      return;
    }
    if (m.type === "ready") {
      liveVW = (m.viewport && m.viewport.width) || 1280;
      liveVH = (m.viewport && m.viewport.height) || 800;
      liveCanvas.width = liveVW;
      liveCanvas.height = liveVH;
      shot.classList.add("hidden");
      liveCanvas.classList.remove("hidden");
      liveStopBtn.classList.remove("hidden");
      liveNote.textContent = "live — click & type in the sandbox";
      liveCanvas.focus();
    } else if (m.type === "frame") {
      liveImg.src = "data:image/jpeg;base64," + m.data;
    } else if (m.type === "error") {
      liveNote.textContent = m.message || "live error";
      stopLive();
    } else if (m.type === "closed") {
      liveNote.textContent = "session ended (" + (m.reason || "closed") + ")";
      stopLive();
    }
  };
  sock.onclose = () => {
    if (liveSocket === sock) stopLive();
  };
  sock.onerror = () => {
    liveNote.textContent = "connection error";
  };
}
function stopLive() {
  if (liveSocket) {
    try {
      liveSocket.close();
    } catch {}
    liveSocket = null;
  }
  liveCanvas.classList.add("hidden");
  liveStopBtn.classList.add("hidden");
  if (checked("liveSwitch") && liveUrl) liveStartBtn.classList.remove("hidden");
}
// Reset all replay/live UI between detonations (called from resetView).
function teardownExtras() {
  stopReplay();
  if (replayControls) replayControls.classList.add("hidden");
  if (liveStartBtn) liveStartBtn.classList.add("hidden");
  if (chamberTools) chamberTools.classList.add("hidden");
  if (liveNote) liveNote.textContent = "";
  stopLive();
}

// live input → control messages (coords scaled to the sandbox viewport)
function liveCoords(e) {
  const r = liveCanvas.getBoundingClientRect();
  return {
    x: (e.clientX - r.left) * (liveVW / r.width),
    y: (e.clientY - r.top) * (liveVH / r.height),
  };
}
function liveSend(obj) {
  if (liveSocket && liveSocket.readyState === WebSocket.OPEN) {
    liveSocket.send(JSON.stringify(obj));
  }
}
let lastLiveMove = 0;
liveCanvas.addEventListener("mousedown", (e) => {
  e.preventDefault();
  liveCanvas.focus();
  liveSend({ type: "mouse", action: "down", button: e.button === 2 ? "right" : "left", ...liveCoords(e) });
});
liveCanvas.addEventListener("mouseup", (e) => {
  liveSend({ type: "mouse", action: "up", button: e.button === 2 ? "right" : "left", ...liveCoords(e) });
});
liveCanvas.addEventListener("mousemove", (e) => {
  const now = Date.now();
  if (now - lastLiveMove < 40) return;
  lastLiveMove = now;
  liveSend({ type: "mouse", action: "move", ...liveCoords(e) });
});
liveCanvas.addEventListener(
  "wheel",
  (e) => {
    e.preventDefault();
    liveSend({ type: "wheel", deltaX: e.deltaX, deltaY: e.deltaY, ...liveCoords(e) });
  },
  { passive: false }
);
liveCanvas.addEventListener("contextmenu", (e) => e.preventDefault());
const LIVE_KEYS = ["Enter", "Backspace", "Tab", "Delete", "Escape", "ArrowLeft", "ArrowUp", "ArrowRight", "ArrowDown", "Home", "End"];
liveCanvas.addEventListener("keydown", (e) => {
  if (!liveSocket) return;
  if (e.key.length === 1 && !e.ctrlKey && !e.metaKey) {
    liveSend({ type: "text", text: e.key });
    e.preventDefault();
  } else if (LIVE_KEYS.includes(e.key)) {
    liveSend({ type: "key", key: e.key });
    e.preventDefault();
  }
});
liveStartBtn.addEventListener("click", startLive);
liveStopBtn.addEventListener("click", stopLive);

// --- helpers ---
function hostOf(u) {
  try {
    return new URL(u).hostname.replace(/^www\./, "");
  } catch {
    return u || "";
  }
}
function pathOf(u) {
  try {
    const x = new URL(u);
    return (x.pathname + x.search).replace(/^\/$/, "");
  } catch {
    return "";
  }
}
function formatAge(age) {
  if (!age || typeof age.ageDays !== "number") return "unknown";
  const d = age.ageDays;
  if (d < 31) return d + " days · NEW";
  if (d < 365) return Math.round(d / 30) + " months";
  return (d / 365).toFixed(1) + " years";
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

// --- events ---
goBtn.addEventListener("click", () => detonate());
urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") detonate();
});
document.getElementById("sample-chips").addEventListener("click", (e) => {
  const chip = e.target.closest(".chip");
  if (chip) detonate(chip.dataset.url);
});

// --- QR scanning ---
let qr = null;
$("scan").addEventListener("click", async () => {
  const region = $("qr-reader");
  if (qr) {
    await qr.stop().catch(() => {});
    qr.clear();
    qr = null;
    region.innerHTML = "";
    return;
  }
  if (!window.Html5Qrcode) {
    showError("QR scanner failed to load (no internet?). Paste the URL instead.");
    return;
  }
  qr = new Html5Qrcode("qr-reader");
  try {
    await qr.start(
      { facingMode: "environment" },
      { fps: 10, qrbox: 220 },
      async (decoded) => {
        await qr.stop().catch(() => {});
        qr.clear();
        qr = null;
        region.innerHTML = "";
        detonate(decoded);
      },
      () => {}
    );
  } catch (err) {
    showError("Couldn't open the camera: " + err.message);
    qr = null;
  }
});

// --- PDF dropzone ---
browseBtn.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("click", (e) => {
  if (e.target !== browseBtn) fileInput.click();
});
dropzone.addEventListener("keydown", (e) => {
  if ((e.key === "Enter" || e.key === " ") && e.target === dropzone) {
    e.preventDefault();
    fileInput.click();
  }
});
fileInput.addEventListener("change", () => handlePdfFile(fileInput.files && fileInput.files[0]));

["dragenter", "dragover"].forEach((evt) =>
  dropzone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  })
);
["dragleave", "dragend"].forEach((evt) =>
  dropzone.addEventListener(evt, () => dropzone.classList.remove("dragover"))
);
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragover");
  handlePdfFile(e.dataTransfer.files && e.dataTransfer.files[0]);
});

// --- PWA: register the service worker (offline app shell + installable) ---
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("sw.js").catch(() => {});
  });
}

// Phone PWA share target: Android can launch this page with ?url= or ?text=.
// Keep this tiny so the phone app stays identical to the main frontend.
(() => {
  const params = new URLSearchParams(location.search);
  const shared = [params.get("url"), params.get("text"), params.get("title")]
    .filter(Boolean)
    .join(" ");
  if (!shared) return;
  const match = shared.match(/https?:\/\/[^\s<>"']+/i) || shared.match(/\b[a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s<>"']*)?/i);
  if (match) detonate(match[0]);
})();
