const $ = (id) => document.getElementById(id);
const DEFAULT_API = "https://sandboxed-backend.onrender.com";

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

function setStatus(state, text) {
  status.dataset.state = state;
  statusText.textContent = text;
}

function resetView() {
  errorBox.classList.add("hidden");
  readout.classList.add("hidden");
  shot.classList.add("hidden");
  glass.classList.add("hidden");
  stamp.classList.add("hidden");
  stamp.classList.remove("stamp-in");
  idle.classList.add("hidden");
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
  setStatus("running", "Detonating");
  consoleState.textContent = "Working";

  try {
    const res = await fetch(apiBase() + "/detonate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    spinner.classList.add("hidden");

    if (!res.ok) {
      showError(data.error || "Detonation failed.");
      return;
    }
    render(data);
  } catch (err) {
    spinner.classList.add("hidden");
    showError(
      "Could not reach the detonation engine at " +
        apiBase() +
        ". Is the backend running? " +
        "(" + err.message + ")"
    );
  } finally {
    goBtn.disabled = false;
  }
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

  renderTrajectory(d.redirectChain || []);
  renderReasons(d.reasons || []);

  readout.classList.remove("hidden");
}

function renderPhishing(p) {
  const el = $("m-phishing");
  if (!el) return;

  if (!p) {
    el.textContent = "—";
    el.className = "v";
    return;
  }

  if (p.phishing) {
    el.innerHTML =
      "⚠️ Spoofing <strong>" + escapeHtml(p.spoofedBrand) + "</strong>" +
      " — real site: <a href=\"" + escapeHtml(p.expectedUrl) + "\" target=\"_blank\" rel=\"noopener\">" +
      escapeHtml(p.expectedUrl) + "</a>";
    el.className = "v phishing-warn";
  } else {
    el.textContent = "✓ No spoof detected";
    el.className = "v phishing-ok";
  }
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

// --- PWA: register the service worker (offline app shell + installable) ---
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("sw.js").catch(() => {});
  });
}