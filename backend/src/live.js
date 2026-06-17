// Live interactive sandbox. Streams the real headless browser to the client over a
// WebSocket (CDP screencast) and forwards the user's clicks/keys/scroll back into
// the page (CDP Input). This is the "actually open the sandbox and explore it" mode.
//
// Safety: every navigation is re-checked for SSRF (mirrors detonate.js), downloads
// are denied, and sessions are hard-capped + auto-expired so a long-lived browser
// context can't pile up and OOM the 1GB Fly VM.

import { WebSocketServer } from "ws";
import { getBrowser } from "./detonate.js";
import { isBlockedUrl, isBlockedLiteral } from "./ssrf.js";

const LIVE_MAX_SESSIONS = Number(process.env.LIVE_MAX_SESSIONS || 2);
const LIVE_IDLE_MS = Number(process.env.LIVE_IDLE_MS || 60000);
const LIVE_MAX_MS = Number(process.env.LIVE_MAX_MS || 300000);
const VIEWPORT = { width: 1280, height: 800 };
const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

// Control keys we translate into real CDP key events (printable chars go through
// Input.insertText instead). [code, windowsVirtualKeyCode]
const KEY_MAP = {
  Enter: ["Enter", 13],
  Backspace: ["Backspace", 8],
  Tab: ["Tab", 9],
  Delete: ["Delete", 46],
  Escape: ["Escape", 27],
  ArrowLeft: ["ArrowLeft", 37],
  ArrowUp: ["ArrowUp", 38],
  ArrowRight: ["ArrowRight", 39],
  ArrowDown: ["ArrowDown", 40],
  Home: ["Home", 36],
  End: ["End", 35],
};

const sessions = new Set();

function send(ws, obj) {
  if (ws.readyState === ws.OPEN) {
    try {
      ws.send(JSON.stringify(obj));
    } catch {
      /* socket gone */
    }
  }
}

function normalizeTarget(input) {
  if (!input) return null;
  let candidate = String(input).trim();
  if (!candidate) return null;
  if (!/^https?:\/\//i.test(candidate)) candidate = `http://${candidate}`;
  try {
    const u = new URL(candidate);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.toString();
  } catch {
    return null;
  }
}

const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, Math.round(Number(n) || 0)));

export function attachLiveServer(server) {
  const wss = new WebSocketServer({ server, path: "/live" });
  wss.on("connection", (ws, req) => {
    handleConnection(ws, req).catch((err) => {
      console.error("live session error (non-fatal):", err.message || err);
      send(ws, { type: "error", message: "Live session failed to start" });
      try { ws.close(); } catch {}
    });
  });
  return wss;
}

async function handleConnection(ws, req) {
  if (sessions.size >= LIVE_MAX_SESSIONS) {
    send(ws, { type: "error", message: "Sandbox is busy — too many live sessions. Try again shortly." });
    return ws.close();
  }

  let target;
  try {
    target = new URL(req.url, "http://localhost").searchParams.get("url");
  } catch {
    target = null;
  }
  const url = normalizeTarget(target);
  if (!url) {
    send(ws, { type: "error", message: "Provide a valid http(s) url" });
    return ws.close();
  }
  if (await isBlockedUrl(url)) {
    send(ws, { type: "error", message: "Refused: target resolves to a private/blocked address" });
    return ws.close();
  }

  const browser = await getBrowser();
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  const client = await page.target().createCDPSession();

  const session = { ws, context, client, closed: false, idleTimer: null, maxTimer: null };
  sessions.add(session);

  const closeSession = async () => {
    if (session.closed) return;
    session.closed = true;
    sessions.delete(session);
    clearTimeout(session.idleTimer);
    clearTimeout(session.maxTimer);
    await client.send("Page.stopScreencast").catch(() => {});
    await context.close().catch(() => {});
    try { ws.close(); } catch {}
  };
  const bumpIdle = () => {
    clearTimeout(session.idleTimer);
    session.idleTimer = setTimeout(() => {
      send(ws, { type: "closed", reason: "idle timeout" });
      closeSession();
    }, LIVE_IDLE_MS);
  };
  session.maxTimer = setTimeout(() => {
    send(ws, { type: "closed", reason: "session time limit" });
    closeSession();
  }, LIVE_MAX_MS);
  bumpIdle();

  ws.on("close", closeSession);
  ws.on("error", closeSession);

  try {
    await page.setUserAgent(USER_AGENT);
    await page.setViewport(VIEWPORT);
    await client.send("Page.setDownloadBehavior", { behavior: "deny" }).catch(() => {});

    // SSRF guard on every request — same posture as detonate.js.
    await page.setRequestInterception(true);
    page.on("request", async (r) => {
      try {
        const u = r.url();
        if (/^https?:/i.test(u)) {
          if (isBlockedLiteral(u)) return await r.abort("blockedbyclient");
          const isNav = r.isNavigationRequest() && r.frame() === page.mainFrame();
          if (isNav && (await isBlockedUrl(u))) return await r.abort("blockedbyclient");
        }
        return await r.continue();
      } catch {
        try { await r.abort("failed"); } catch {}
      }
    });

    // Push frames to the client; ack each (CDP requires it to keep frames flowing).
    client.on("Page.screencastFrame", async (frame) => {
      send(ws, { type: "frame", data: frame.data, metadata: frame.metadata });
      client.send("Page.screencastFrameAck", { sessionId: frame.sessionId }).catch(() => {});
    });

    ws.on("message", (raw) => {
      bumpIdle();
      let msg;
      try { msg = JSON.parse(raw.toString()); } catch { return; }
      handleControl(client, msg).catch(() => {});
    });

    send(ws, { type: "ready", viewport: VIEWPORT });
    await client.send("Page.enable").catch(() => {});
    await client.send("Page.startScreencast", {
      format: "jpeg",
      quality: 60,
      maxWidth: VIEWPORT.width,
      maxHeight: VIEWPORT.height,
      everyNthFrame: 1,
    });

    page
      .goto(url, { waitUntil: "domcontentloaded", timeout: 30000 })
      .then(() => send(ws, { type: "nav", url: page.url() }))
      .catch(() => send(ws, { type: "nav", url: page.url() }));
  } catch (err) {
    send(ws, { type: "error", message: "Could not open the page" });
    await closeSession();
  }
}

// Translate a client control message into a CDP Input event.
async function handleControl(client, msg) {
  if (!msg || typeof msg !== "object") return;
  const x = clamp(msg.x, 0, VIEWPORT.width);
  const y = clamp(msg.y, 0, VIEWPORT.height);

  if (msg.type === "mouse") {
    const map = { down: "mousePressed", up: "mouseReleased", move: "mouseMoved" };
    const type = map[msg.action];
    if (!type) return;
    await client.send("Input.dispatchMouseEvent", {
      type,
      x,
      y,
      button: msg.button || "left",
      buttons: msg.action === "down" ? 1 : 0,
      clickCount: msg.action === "move" ? 0 : 1,
    });
  } else if (msg.type === "wheel") {
    await client.send("Input.dispatchMouseEvent", {
      type: "mouseWheel",
      x,
      y,
      deltaX: Number(msg.deltaX) || 0,
      deltaY: Number(msg.deltaY) || 0,
    });
  } else if (msg.type === "text") {
    if (typeof msg.text === "string" && msg.text) {
      await client.send("Input.insertText", { text: msg.text });
    }
  } else if (msg.type === "key") {
    const entry = KEY_MAP[msg.key];
    if (!entry) return;
    const [code, vk] = entry;
    const base = { key: msg.key, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk };
    await client.send("Input.dispatchKeyEvent", { type: "rawKeyDown", ...base });
    await client.send("Input.dispatchKeyEvent", { type: "keyUp", ...base });
  }
}

export async function closeLiveSessions() {
  const all = [...sessions];
  await Promise.all(
    all.map(async (s) => {
      s.closed = true;
      sessions.delete(s);
      clearTimeout(s.idleTimer);
      clearTimeout(s.maxTimer);
      await s.client.send("Page.stopScreencast").catch(() => {});
      await s.context.close().catch(() => {});
      try { s.ws.close(); } catch {}
    })
  );
}
