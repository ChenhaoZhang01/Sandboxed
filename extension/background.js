// Service worker: adds the right-click menu items and opens the detonation
// result window. The detonation itself happens in result.js (so the heavy work
// and rendering live in a real page, not the worker).
const MENU_LINK = "sbx-detonate-link";
const MENU_PAGE = "sbx-detonate-page";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_LINK,
      title: "Detonate link in Sandboxer",
      contexts: ["link"],
    });
    chrome.contextMenus.create({
      id: MENU_PAGE,
      title: "Detonate this page in Sandboxer",
      contexts: ["page"],
    });
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  const url =
    info.menuItemId === MENU_LINK
      ? info.linkUrl
      : info.pageUrl || (tab && tab.url);
  if (url && /^https?:/i.test(url)) openResult(url);
});

function openResult(targetUrl) {
  const url =
    chrome.runtime.getURL("result.html") + "?u=" + encodeURIComponent(targetUrl);
  chrome.windows.create({ url, type: "popup", width: 460, height: 760 });
}
