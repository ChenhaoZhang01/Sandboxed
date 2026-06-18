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

function notify(id, title, message, buttons) {
  const opts = { type: "basic", iconUrl: ICON, title, message };
  if (buttons) opts.buttons = buttons;
  chrome.notifications.create(id, opts);
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
    notify(
      "sbx-redir-" + now,
      "Sandboxed blocked a redirect",
      "A page tried to send you to " + SBX.hostOf(dest)
    );
  }
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

// ---------------------------------------------------------------------------
// Download guard — holds downloads for review, optionally ClamAV-scanned.
// ---------------------------------------------------------------------------
const approvedDownloads = new Set(); // urls re-issued after the user allowed them
const pendingDownloads = new Map(); // notificationId -> url awaiting Allow/Discard
let lastGestureTs = 0;

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

  try {
    await chrome.downloads.cancel(item.id);
  } catch {}
  try {
    await chrome.downloads.erase({ id: item.id });
  } catch {}

  if (s.downloadGuard.scan) scanDownload(url, item);
  else promptDownload(url, item, null);
});

const fileNameOf = (item, url) =>
  (item && item.filename ? item.filename.split(/[\\/]/).pop() : "") || SBX.hostOf(url);

async function scanDownload(url, item) {
  const s = await ensureSettings();
  const name = fileNameOf(item, url);
  try {
    const bytes = await (await fetch(url)).arrayBuffer();
    const res = await fetch(s.apiBase + "/scan-file", {
      method: "POST",
      headers: { "Content-Type": item.mime || "application/octet-stream" },
      body: bytes,
    });
    const data = await res.json().catch(() => ({ status: "error" }));

    if (data.status === "infected") {
      notify(
        "sbx-dl-" + item.id,
        "Download blocked — malware",
        name + " is infected (" + ((data.viruses || []).join(", ") || "unknown") + "). Discarded."
      );
      return;
    }
    const note =
      data.status === "clean"
        ? "ClamAV: clean."
        : data.status === "unavailable"
        ? "Scanner unavailable."
        : "Scan could not complete.";
    promptDownload(url, item, note);
  } catch (e) {
    promptDownload(url, item, "Couldn't scan (" + (e.message || e) + ").");
  }
}

function promptDownload(url, item, note) {
  const id = "sbx-dlask-" + (item ? item.id : Date.now());
  pendingDownloads.set(id, url);
  notify(
    id,
    "Download held for review",
    fileNameOf(item, url) + (note ? " — " + note : ""),
    [{ title: "Allow download" }, { title: "Discard" }]
  );
}

chrome.notifications.onButtonClicked.addListener((id, btnIdx) => {
  const url = pendingDownloads.get(id);
  if (!url) return;
  pendingDownloads.delete(id);
  chrome.notifications.clear(id);
  if (btnIdx === 0) {
    approvedDownloads.add(url);
    chrome.downloads.download({ url });
  }
});
chrome.notifications.onClosed.addListener((id) => pendingDownloads.delete(id));
