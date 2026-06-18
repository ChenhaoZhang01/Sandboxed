// Shared logic for the popup, result window, options page, AND the background
// service worker (loaded there via importScripts). Exposed as the global SBX.
//
// Only the render* helpers touch the DOM, and only inside function bodies, so
// importScripts into the (DOM-less) service worker is safe.
const SBX = (() => {
  const DEFAULTS = {
    apiBase: "https://sandboxed.fly.dev",
    // How links get checked: "manual" (right-click only),
    // "click" (intercept clicks), or "both".
    checkMode: "manual",
    analysisLayers: {
      domainAge: true,
      safeBrowsing: true,
      phishingEnrichment: false,
      recordReplay: false,
      credentialTrap: false,
    },
    historyEnabled: true,
    // Block script-driven redirects / popunders (e.g. istreameast). Opt-in.
    // action: "scan" = detonate the destination + show verdict window;
    //         "prompt" = just block and show a notification.
    redirectBlock: { enabled: false, action: "scan" },
    // Intercept downloads. Opt-in.
    // scope: "all" = every download; "driveby" = only without a recent user gesture.
    // scan: ClamAV-scan the bytes before letting it through.
    downloadGuard: { enabled: false, scope: "all", scan: true },
  };

  // --- settings (persist across browser restarts via chrome.storage.sync) ---
  function normalizeAnalysisLayers(layers = {}) {
    return {
      domainAge: layers.domainAge !== false,
      safeBrowsing: layers.safeBrowsing !== false,
      phishingEnrichment: layers.phishingEnrichment === true,
      // Recorded replay is opt-in so the default flow stays fast.
      recordReplay: layers.recordReplay === true,
      credentialTrap: layers.credentialTrap === true,
    };
  }

  function normalizeRedirectBlock(rb = {}) {
    return {
      enabled: rb.enabled === true,
      action: rb.action === "prompt" ? "prompt" : "scan",
    };
  }

  function normalizeDownloadGuard(dg = {}) {
    return {
      enabled: dg.enabled === true,
      scope: dg.scope === "driveby" ? "driveby" : "all",
      scan: dg.scan !== false,
    };
  }

  function getSettings() {
    return new Promise((resolve) =>
      chrome.storage.sync.get(DEFAULTS, (o) =>
        resolve({
          apiBase: (o.apiBase || DEFAULTS.apiBase).replace(/\/$/, ""),
          checkMode: o.checkMode || DEFAULTS.checkMode,
          historyEnabled: o.historyEnabled ?? true,
          analysisLayers: normalizeAnalysisLayers(o.analysisLayers),
          redirectBlock: normalizeRedirectBlock(o.redirectBlock),
          downloadGuard: normalizeDownloadGuard(o.downloadGuard),
        })
      )
    );
  }
  function setSettings(patch) {
    return new Promise((resolve) => chrome.storage.sync.set(patch, resolve));
  }
  async function getApiBase() {
    return (await getSettings()).apiBase;
  }

async function detonate(url, opts = {}) {
  const settings = await getSettings();
  const base = settings.apiBase;
  const analysisLayers = normalizeAnalysisLayers(opts.analysisLayers || settings.analysisLayers);
  const timeoutMs = opts.timeoutMs ?? 18000;

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);

    const normalizeHistoryUrl = (u) => {
      try {
        const url = new URL(u.includes("://") ? u : "http://" + u);
        url.hostname = url.hostname.replace(/^www\./, "");
        url.hash = "";
        return url.toString();
      } catch {
        return u
          .replace(/^https?:\/\//, "")
          .replace(/^www\./, "")
          .split(/[/?#]/)[0]
          .replace(/\/$/, "");
      }
    };

  try {
    if (settings.historyEnabled) {
      let verifiedLinks = [];
      try {
        const vres = await fetch(base + "/verified-links");
        const vdata = await vres.json();
        verifiedLinks = Array.isArray(vdata?.data) ? vdata.data : [];
      } catch {}

      const match = verifiedLinks.find(
        (x) => normalizeHistoryUrl(x.url) === normalizeHistoryUrl(url)
      );

      if (match) {
        return match.data;
      }
    }

    const res = await fetch(base + "/detonate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, analysisLayers }),
      signal: controller.signal,
    });

    let data = {};
    try {
      data = await res.json();
    } catch {}

    if (!res.ok) {
      throw new Error(data.error || `Detonation failed (HTTP ${res.status}).`);
    }

    try {
      // Don't persist replay frames in the cache — they're large base64 JPEGs
      // that would bloat verifiedLinks.json. Everything else is kept.
      const { replayFrames, ...cacheable } = data;
      await fetch(base + "/verified-links/add", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: normalizeHistoryUrl(url), data: cacheable }),
      });
    } catch (e) {
      console.warn("failed to store verified link:", e.message);
    }

    return data;

  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("Backend timed out — the page took too long to detonate.");
    }
    throw new Error("Backend unavailable at " + base + ". (" + err.message + ")");
  } finally {
    clearTimeout(t);
  }
}
  // --- small DOM helper (pages only) ---
  function el(tag, opts = {}, kids = []) {
    const n = document.createElement(tag);
    if (opts.class) n.className = opts.class;
    if (opts.text != null) n.textContent = opts.text;
    if (opts.data) for (const k in opts.data) n.dataset[k] = opts.data[k];
    if (opts.attrs) for (const k in opts.attrs) n.setAttribute(k, opts.attrs[k]);
    for (const kid of kids) if (kid) n.appendChild(kid);
    return n;
  }

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

  function renderLoading(root, url) {
    root.replaceChildren(
      el("div", { class: "chamber" }, [
        el("div", { class: "grid-bg" }),
        el("div", { class: "spinner" }, [
          el("p", { text: "Detonating " + hostOf(url) + "…" }),
          el("div", { class: "bar" }, [el("span")]),
        ]),
      ])
    );
  }

  function renderError(root, msg) {
    root.replaceChildren(el("div", { class: "error-box", text: msg }));
  }

  function renderPhishing(p) {
    if (!p) return null;

    if (p.phishing) {
      const wrap = el("div", { class: "sbx-phishing sbx-warn" });
      wrap.innerHTML =
        "⚠️ Spoofed site detected<br/>" +
        "<span>Impersonating: <strong>" + p.spoofedBrand + "</strong></span><br/>" +
        "<span>Real URL: <a href=\"" + p.expectedUrl + "\" target=\"_blank\" rel=\"noopener\">" +
        p.expectedUrl + "</a></span>";
      return wrap;
    }

    return el("div", { class: "sbx-phishing sbx-ok", text: "✓ No spoof detected" });
  }

  function wsBaseFrom(base) {
    return base.replace(/^http/i, "ws");
  }

  function trapText(t) {
    if (!t) return "—";
    if (t.blocked) {
      return (t.crossDomain ? "⚠️ off-domain → " : "captured → ") +
        (t.host || "?") + " (blocked)";
    }
    if (t.attempted) return "filled canary; no submission";
    return "no login form";
  }

  // Replay player: scrubs the screencast frames through the chamber's shot <img>.
  function buildReplay(frames, shotImg) {
    if (!frames || !frames.length || !shotImg) return null;
    let idx = 0;
    let timer = null;
    const playBtn = el("button", { class: "btn btn-ghost btn-sm", text: "▶ Replay" });
    const scrub = el("input", {
      class: "replay-scrub",
      attrs: { type: "range", min: "0", max: String(frames.length - 1), value: "0" },
    });
    const time = el("span", { class: "mono replay-time", text: "1 / " + frames.length });
    const show = (i) => {
      idx = Math.max(0, Math.min(frames.length - 1, i));
      shotImg.src = "data:image/jpeg;base64," + frames[idx].data;
      scrub.value = String(idx);
      time.textContent = idx + 1 + " / " + frames.length;
    };
    const stop = () => {
      if (timer) { clearInterval(timer); timer = null; }
      playBtn.textContent = "▶ Replay";
    };
    playBtn.addEventListener("click", () => {
      if (timer) { stop(); return; }
      if (idx >= frames.length - 1) idx = -1;
      playBtn.textContent = "⏸ Pause";
      timer = setInterval(() => {
        if (idx >= frames.length - 1) { stop(); return; }
        show(idx + 1);
      }, 350);
    });
    scrub.addEventListener("input", () => { stop(); show(Number(scrub.value)); });
    return el("div", { class: "replay-controls" }, [playBtn, scrub, time]);
  }

  // Live interactive sandbox: streams the page over a WebSocket and forwards
  // clicks/keys back. Appends a canvas into the chamber; returns the control bar.
  function buildLive(targetUrl, chamber, shotImg) {
    if (!targetUrl) return null;
    const canvas = el("canvas", { class: "live-canvas hidden", attrs: { tabindex: "0" } });
    chamber.appendChild(canvas);
    const startBtn = el("button", { class: "btn btn-ghost btn-sm", text: "Explore live ▶" });
    const stopBtn = el("button", { class: "btn btn-ghost btn-sm hidden", text: "Stop live ■" });
    const note = el("span", { class: "mono live-note" });

    const ctx = canvas.getContext("2d");
    const img = new Image();
    img.onload = () => ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    let socket = null;
    let vw = 1280;
    let vh = 800;

    const send = (o) => {
      if (socket && socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(o));
    };
    const coords = (e) => {
      const r = canvas.getBoundingClientRect();
      return { x: (e.clientX - r.left) * (vw / r.width), y: (e.clientY - r.top) * (vh / r.height) };
    };
    const stop = () => {
      if (socket) { try { socket.close(); } catch {} socket = null; }
      canvas.classList.add("hidden");
      if (shotImg) shotImg.classList.remove("hidden");
      stopBtn.classList.add("hidden");
      startBtn.classList.remove("hidden");
    };

    const start = async () => {
      // The toolbar popup closes on focus loss, which would kill a live session
      // the instant you click into it — open the persistent result window instead.
      if (typeof document !== "undefined" && document.body.classList.contains("popup")) {
        chrome.runtime.sendMessage({ type: "OPEN_RESULT", url: targetUrl });
        return;
      }
      if (socket) return;
      note.textContent = "connecting…";
      startBtn.classList.add("hidden");
      const base = await getApiBase();
      let sock;
      try {
        sock = new WebSocket(wsBaseFrom(base) + "/live?url=" + encodeURIComponent(targetUrl));
      } catch {
        note.textContent = "could not connect";
        startBtn.classList.remove("hidden");
        return;
      }
      socket = sock;
      sock.onmessage = (ev) => {
        let m;
        try { m = JSON.parse(ev.data); } catch { return; }
        if (m.type === "ready") {
          vw = (m.viewport && m.viewport.width) || 1280;
          vh = (m.viewport && m.viewport.height) || 800;
          canvas.width = vw;
          canvas.height = vh;
          if (shotImg) shotImg.classList.add("hidden");
          canvas.classList.remove("hidden");
          stopBtn.classList.remove("hidden");
          note.textContent = "live — click & type in the sandbox";
          canvas.focus();
        } else if (m.type === "frame") {
          img.src = "data:image/jpeg;base64," + m.data;
        } else if (m.type === "error") {
          note.textContent = m.message || "live error";
          stop();
        } else if (m.type === "closed") {
          note.textContent = "session ended (" + (m.reason || "closed") + ")";
          stop();
        }
      };
      sock.onclose = () => { if (socket === sock) stop(); };
      sock.onerror = () => { note.textContent = "connection error"; };
    };

    let lastMove = 0;
    const LIVE_KEYS = ["Enter", "Backspace", "Tab", "Delete", "Escape", "ArrowLeft", "ArrowUp", "ArrowRight", "ArrowDown", "Home", "End"];
    canvas.addEventListener("mousedown", (e) => { e.preventDefault(); canvas.focus(); send({ type: "mouse", action: "down", button: e.button === 2 ? "right" : "left", ...coords(e) }); });
    canvas.addEventListener("mouseup", (e) => send({ type: "mouse", action: "up", button: e.button === 2 ? "right" : "left", ...coords(e) }));
    canvas.addEventListener("mousemove", (e) => { const n = Date.now(); if (n - lastMove < 40) return; lastMove = n; send({ type: "mouse", action: "move", ...coords(e) }); });
    canvas.addEventListener("wheel", (e) => { e.preventDefault(); send({ type: "wheel", deltaX: e.deltaX, deltaY: e.deltaY, ...coords(e) }); }, { passive: false });
    canvas.addEventListener("contextmenu", (e) => e.preventDefault());
    canvas.addEventListener("keydown", (e) => {
      if (!socket) return;
      if (e.key.length === 1 && !e.ctrlKey && !e.metaKey) { send({ type: "text", text: e.key }); e.preventDefault(); }
      else if (LIVE_KEYS.includes(e.key)) { send({ type: "key", key: e.key }); e.preventDefault(); }
    });
    startBtn.addEventListener("click", start);
    stopBtn.addEventListener("click", stop);
    return el("div", { class: "live-controls" }, [startBtn, stopBtn, note]);
  }

  function renderResult(root, d) {
    const verdict = d.verdict || "safe";

    const chamberKids = [el("div", { class: "grid-bg" })];
    // Need a shot <img> if there's a screenshot OR replay frames to scrub through.
    let shotImg = null;
    if (d.screenshotBase64 || (d.replayFrames && d.replayFrames.length)) {
      shotImg = el("img", {
        class: "shot",
        attrs: {
          src: d.screenshotBase64 ? "data:image/jpeg;base64," + d.screenshotBase64 : "",
          alt: "Detonated page",
        },
      });
      chamberKids.push(shotImg);
      chamberKids.push(el("div", { class: "glass" }));
    }
    const stamp = el("div", { class: "stamp stamp-in", data: { verdict } });
    stamp.appendChild(document.createTextNode(verdict.toUpperCase() + " "));
    stamp.appendChild(el("span", { class: "score", text: "· " + (d.score ?? 0) }));
    chamberKids.push(stamp);
    const chamber = el("div", { class: "chamber" }, chamberKids);

    // Replay + live tools below the chamber.
    const replayNode = buildReplay(d.replayFrames, shotImg);
    const liveNode = buildLive(d.finalUrl || d.requestedUrl, chamber, shotImg);
    const tools = [replayNode, liveNode].filter(Boolean);
    const toolsBar = tools.length ? el("div", { class: "chamber-tools" }, tools) : null;

    const meta = (k, v) =>
      el("div", { class: "meta" }, [
        el("div", { class: "k", text: k }),
        el("div", { class: "v", text: v }),
      ]);
    const grid = el("div", { class: "readout-grid" }, [
      meta("Final destination", d.finalHost || hostOf(d.finalUrl) || "—"),
      meta("Domain age", formatAge(d.intel && d.intel.domainAge)),
      meta("Redirects", (d.redirectCount ?? 0) + (d.redirectCount === 1 ? " hop" : " hops")),
      meta("Page title", d.title || "—"),
      meta("Password trap", trapText(d.credentialTrap)),
    ]);

    const traj = el("ul", { class: "traj" });
    const chain = d.redirectChain || [];
    if (!chain.length) {
      traj.appendChild(el("li", { class: "final", text: "(no navigation captured)" }));
    } else {
      chain.forEach((u, i) => {
        const li = el("li", { class: i === chain.length - 1 ? "final" : "" }, [
          el("span", { class: "host", text: hostOf(u) }),
        ]);
        const p = pathOf(u);
        if (p) li.appendChild(el("span", { text: " " + p, attrs: { style: "color:var(--ink-faint)" } }));
        traj.appendChild(li);
      });
    }

    const reasons = el("ul", { class: "reasons" });
    const list = d.reasons || [];
    if (!list.length) {
      reasons.appendChild(
        el("li", {}, [
          el("div", {
            class: "empty-reasons",
            text: "No threat signals detected — nothing suspicious in the chamber.",
          }),
        ])
      );
    } else {
      list.forEach((r) => {
        const sev = r.points >= 30 ? "sev-hi" : r.points >= 12 ? "sev-mid" : "sev-lo";
        reasons.appendChild(
          el("li", { class: "reason " + sev }, [
            el("span", { class: "pts mono", text: "+" + r.points }),
            el("span", { text: r.reason }),
          ])
        );
      });
    }

    const phishingNode = renderPhishing(d.phishing);

    root.replaceChildren(
      chamber,
      ...(toolsBar ? [toolsBar] : []),
      el("div", { class: "readout" }, [
        grid,
        phishingNode,
        el("div", { class: "section-label", text: "Trajectory" }),
        traj,
        el("div", { class: "section-label", text: "Why" }),
        reasons,
      ])
    );
  }

  return {
    DEFAULTS,
    getSettings,
    setSettings,
    getApiBase,
    detonate,
    hostOf,
    renderLoading,
    renderError,
    renderResult,
  };
})();

// Make available to the service worker global when loaded via importScripts.
if (typeof self !== "undefined") self.SBX = SBX;