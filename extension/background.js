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
});

function openResult(targetUrl) {
  const url =
    chrome.runtime.getURL("result.html") + "?u=" + encodeURIComponent(targetUrl);
  chrome.windows.create({ url, type: "popup", width: 460, height: 760 });
}
