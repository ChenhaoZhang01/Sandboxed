const root = document.getElementById("result");
const input = document.getElementById("url");
const modeLine = document.getElementById("modeLine");

const MODE_LABEL = {
  manual: "Manual — right-click to check links",
  click: "On click — links auto-checked",
  both: "Both — auto-check + right-click",
};

// Restore the last URL the user checked (persists across reopen/restart).
chrome.storage.local.get({ lastUrl: "" }, (o) => {
  if (o.lastUrl) input.value = o.lastUrl;
});

// Show the current link-checking mode.
SBX.getSettings().then((s) => {
  modeLine.textContent = "Mode: " + (MODE_LABEL[s.checkMode] || s.checkMode);
});

async function run(rawUrl) {
  const url = (rawUrl ?? input.value).trim();
  if (!url) return input.focus();
  input.value = url;
  chrome.storage.local.set({ lastUrl: url });

  SBX.renderLoading(root, url);
  try {
    const data = await SBX.detonate(url);
    SBX.renderResult(root, data);
  } catch (err) {
    SBX.renderError(root, err.message + " — check the backend URL in ⚙ Settings.");
  }
}

document.getElementById("go").addEventListener("click", () => run());
input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") run();
});

document.getElementById("tab").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && tab.url && /^https?:/i.test(tab.url)) run(tab.url);
  else SBX.renderError(root, "This tab has no web page to check.");
});

document.getElementById("opts").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});
