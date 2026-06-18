// Service worker: context-menu link checking + the central detonation channel
// for the content script (so all backend fetches run here, with the extension's
// host permissions, never under a page's CSP).
importScripts("core.js");

const MENU_LINK = "sbx-check-link";
const MENU_PAGE = "sbx-check-page";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_LINK,
      title: "Check this link with Sandboxed",
      contexts: ["link"],
    });
    chrome.contextMenus.create({
      id: MENU_PAGE,
      title: "Check this page with Sandboxed",
      contexts: ["page"],
    });
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  const url =
    info.menuItemId === MENU_LINK ? info.linkUrl : info.pageUrl || (tab && tab.url);
  if (url && /^https?:/i.test(url)) openResult(url);
});

// Content script asks the worker to detonate (keeps fetch off the page origin).
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || typeof msg !== "object") return;

  if (msg.type === "CHECK_URL") {
    SBX.detonate(msg.url)
      .then((data) => sendResponse({ ok: true, data }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true; // keep the channel open for the async response
  }

  if (msg.type === "OPEN_RESULT" && msg.url) {
    openResult(msg.url);
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === "OPEN_URL" && msg.url) {
    chrome.tabs.create({ url: msg.url, active: true });
    sendResponse({ ok: true });
    return false;
  }

  // Drive-by download heuristic: content scripts report user gestures so the
  // download guard can tell a click-initiated download from an auto-started one.
  if (msg.type === "USER_GESTURE") {
    lastGestureTs = Date.now();
    return false;
  }
});

function openResult(targetUrl) {
  const url =
    chrome.runtime.getURL("result.html") + "?u=" + encodeURIComponent(targetUrl);
  chrome.windows.create({ url, type: "popup", width: 460, height: 760 });
}

// ---------------------------------------------------------------------------
// Settings cache. webNavigation/downloads listeners fire frequently, so we keep
// a live copy refreshed on storage changes rather than awaiting storage each time.
// ---------------------------------------------------------------------------
let settings = null;
function refreshSettings() {
  return SBX.getSettings().then((s) => {
    settings = s;
    return s;
  });
}
refreshSettings();
chrome.storage.onChanged.addListener((_changes, area) => {
  if (area === "sync") refreshSettings();
});
async function ensureSettings() {
  if (!settings) await refreshSettings();
  return settings;
}

const isHttp = (u) => /^https?:/i.test(u || "");
const ICON = chrome.runtime.getURL("icons/icon-192.png");

function notify(id, title, message, buttons, extra = {}) {
  const opts = { type: "basic", iconUrl: ICON, title, message, ...extra };
  if (buttons) opts.buttons = buttons;
  chrome.notifications.create(id, opts, () => {
    if (chrome.runtime.lastError) console.warn("notify failed:", chrome.runtime.lastError.message);
  });
}

async function installWindowOpenHook(tabId, frameId) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId, frameIds: [frameId] },
      world: "MAIN",
      injectImmediately: true,
      func: () => {
        try {
          const guardKey = "__sandboxedWindowOpenHookInstalled";
          if (window[guardKey]) return;
          Object.defineProperty(window, guardKey, {
            value: true,
            configurable: false,
          });

          const blockedOpen = function () {
            return null;
          };

          try {
            Object.defineProperty(window, "open", {
              value: blockedOpen,
              writable: false,
              configurable: false,
            });
          } catch {
            window.open = blockedOpen;
          }

          try {
            const proto = window.Window && window.Window.prototype;
            if (proto) {
              Object.defineProperty(proto, "open", {
                value: blockedOpen,
                writable: false,
                configurable: false,
              });
            }
          } catch {}
        } catch {}
      },
    });
  } catch {}
}

// ---------------------------------------------------------------------------
// Redirect blocker — stops popunders / script redirects (e.g. istreameast).
// ---------------------------------------------------------------------------
const approvedRedirects = new Set(); // urls the user chose to allow
const pendingRedirects = new Map(); // notificationId -> blocked url
const recentRedirects = new Map(); // url -> ts, dedupes rapid repeat popunders
const tabHost = new Map(); // tabId -> last allowed top-frame host
const redirectCooldown = new Map(); // tabId -> ts, breaks same-tab redirect loops

const regDomain = (h) => (h || "").split(".").slice(-2).join(".");
const sameSite = (a, b) => regDomain(a) === regDomain(b);

async function gateRedirect(dest) {
  if (!isHttp(dest) || approvedRedirects.has(dest)) return;
  const now = Date.now();
  if (now - (recentRedirects.get(dest) || 0) < 5000) return; // already handled
  recentRedirects.set(dest, now);

  const s = await ensureSettings();
  if (s.redirectBlock.action === "scan") {
    openResult(dest); // detonates + shows the verdict window
  } else {
    promptRedirect(dest, now);
  }
}

function promptRedirect(dest, now) {
  const id = "sbx-redir-" + now + "-" + Math.random().toString(36).slice(2, 8);
  pendingRedirects.set(id, dest);
  notify(
    id,
    "Sandboxed blocked a redirect",
    "A page tried to send you to " + SBX.hostOf(dest) + ". Choose Go anyway to continue.",
    [{ title: "Go anyway" }],
    { requireInteraction: true }
  );
}

function openPendingRedirect(id) {
  const url = pendingRedirects.get(id);
  if (!url) return false;
  pendingRedirects.delete(id);
  approvedRedirects.add(url);
  chrome.notifications.clear(id);
  chrome.tabs.create({ url, active: true });
  return true;
}

// Popunders / new tabs+windows opened by a page.
chrome.webNavigation.onCreatedNavigationTarget.addListener(async (d) => {
  const s = await ensureSettings();
  if (!s.redirectBlock.enabled) return;
  if (!isHttp(d.url) || approvedRedirects.has(d.url)) return;
  try {
    await chrome.tabs.remove(d.tabId);
  } catch {}
  gateRedirect(d.url);
});

// Same-tab script / meta redirects. onCommitted is the earliest place that
// exposes transitionQualifiers, so this is best-effort (the destination may
// have begun loading); we navigate back off it and inform the user.
chrome.webNavigation.onCommitted.addListener(async (d) => {
  if (!isHttp(d.url)) return;
  const s = await ensureSettings();
  if (s.redirectBlock.enabled) installWindowOpenHook(d.tabId, d.frameId);

  if (d.frameId !== 0) return;
  const host = SBX.hostOf(d.url);
  const isClientRedirect = (d.transitionQualifiers || []).includes("client_redirect");
  const prevHost = tabHost.get(d.tabId);

  if (
    s.redirectBlock.enabled &&
    isClientRedirect &&
    !approvedRedirects.has(d.url) &&
    prevHost &&
    host &&
    !sameSite(host, prevHost)
  ) {
    const now = Date.now();
    // Cooldown: if we just acted on this tab, let it settle instead of looping.
    if (now - (redirectCooldown.get(d.tabId) || 0) >= 4000) {
      redirectCooldown.set(d.tabId, now);
      try {
        await chrome.tabs.goBack(d.tabId);
      } catch {}
      gateRedirect(d.url);
      return; // don't record the blocked host as "current"
    }
  }
  tabHost.set(d.tabId, host);
});

chrome.tabs.onRemoved.addListener((id) => {
  tabHost.delete(id);
  redirectCooldown.delete(id);
});

chrome.notifications.onClicked.addListener((id) => {
  openPendingRedirect(id);
});

chrome.notifications.onButtonClicked.addListener((id, btnIdx) => {
  // Redirect prompt: single "Go anyway" button (index 0).
  if (pendingRedirects.has(id)) {
    if (btnIdx === 0) openPendingRedirect(id);
    else {
      pendingRedirects.delete(id);
      chrome.notifications.clear(id);
    }
    return;
  }

  // Download review: [Allow download, Discard].
  const url = pendingDownloads.get(id);
  if (!url) return;
  pendingDownloads.delete(id);
  chrome.notifications.clear(id);
  if (btnIdx === 0) {
    approvedDownloads.add(url); // let onCreated pass the re-issued download through
    chrome.downloads.download({ url });
  }
});

// ---------------------------------------------------------------------------
// Download guard — holds a download and shows an OS notification with Allow /
// Discard. The notification is shown IMMEDIATELY on interception (not after the
// scan) — re-fetching a just-cancelled URL can stall, and gating the popup on
// that is why it previously never appeared. The ClamAV scan runs async and
// updates the notification's text with the verdict when it's done.
// ---------------------------------------------------------------------------
const approvedDownloads = new Set(); // urls re-issued after the user allowed them
const pendingDownloads = new Map(); // notificationId -> url awaiting Allow/Discard
let dlSeq = 0;
let lastGestureTs = 0;

const fileNameOf = (item, url) =>
  (item && item.filename ? item.filename.split(/[\\/]/).pop() : "") || SBX.hostOf(url);

chrome.downloads.onCreated.addListener(async (item) => {
  const s = await ensureSettings();
  if (!s.downloadGuard.enabled) return;

  const url = item.finalUrl || item.url || "";
  if (!isHttp(url)) return;

  // A download we re-issued after the user clicked Allow — let it through once.
  if (approvedDownloads.has(url)) {
    approvedDownloads.delete(url);
    return;
  }

  // Drive-by scope: a download right after a user gesture is treated as wanted.
  if (s.downloadGuard.scope === "driveby" && Date.now() - lastGestureTs <= 1500) return;

  // Hold it: cancel the browser download.
  try {
    await chrome.downloads.cancel(item.id);
  } catch {}
  try {
    await chrome.downloads.erase({ id: item.id });
  } catch {}

  const name = fileNameOf(item, url);
  const notifId = "sbx-dl-" + Date.now() + "-" + ++dlSeq;
  pendingDownloads.set(notifId, url);

  // Show the review NOW so it always appears; scan result is filled in after.
  notify(
    notifId,
    "Download held for review",
    name + (s.downloadGuard.scan ? " — scanning with ClamAV…" : " — choose Allow or Discard."),
    [{ title: "Allow download" }, { title: "Discard" }],
    { requireInteraction: true }
  );

  if (s.downloadGuard.scan) scanDownloadAndUpdate(notifId, url, name, item.mime || "");
});

// Re-fetch the file's bytes, ClamAV-scan them, and update the held notification's
// message with the verdict. Time-bounded and best-effort: a failure just leaves
// the "review manually" prompt — it never removes the Allow/Discard choice.
async function scanDownloadAndUpdate(notifId, url, name, mime) {
  const base = (await ensureSettings()).apiBase;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 20000);
  let message;
  try {
    const bytes = await (await fetch(url, { signal: ctrl.signal })).arrayBuffer();
    const res = await fetch(base + "/scan-file", {
      method: "POST",
      headers: { "Content-Type": mime || "application/octet-stream" },
      body: bytes,
      signal: ctrl.signal,
    });
    const data = await res.json().catch(() => ({ status: "error" }));
    if (data.status === "infected") {
      message = name + " — ⚠ INFECTED: " + ((data.viruses || []).join(", ") || "malware") + ". Discard recommended.";
    } else if (data.status === "clean") {
      message = name + " — ✓ ClamAV: clean.";
    } else if (data.status === "unavailable") {
      message = name + " — scanner unavailable; review manually.";
    } else {
      message = name + " — couldn't scan; review manually.";
    }
  } catch (e) {
    message = name + " — couldn't scan (" + (e.message || e) + "); review manually.";
  } finally {
    clearTimeout(t);
  }
  // Only update if the user hasn't already acted on / dismissed it.
  if (pendingDownloads.has(notifId)) {
    chrome.notifications.update(notifId, { message }, () => void chrome.runtime.lastError);
  }
}

chrome.notifications.onClosed.addListener((id) => {
  pendingRedirects.delete(id);
  pendingDownloads.delete(id);
});
