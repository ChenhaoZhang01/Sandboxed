const root = document.getElementById("result");
const input = document.getElementById("url");

async function run(rawUrl) {
  const url = (rawUrl ?? input.value).trim();
  if (!url) return input.focus();
  input.value = url;
  SBX.renderLoading(root, url);
  try {
    const data = await SBX.detonate(url);
    SBX.renderResult(root, data);
  } catch (err) {
    SBX.renderError(
      root,
      err.message + " — check the backend URL in ⚙ Settings."
    );
  }
}

document.getElementById("go").addEventListener("click", () => run());
input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") run();
});

document.getElementById("tab").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && tab.url && /^https?:/i.test(tab.url)) run(tab.url);
  else SBX.renderError(root, "This tab has no web page to detonate.");
});

document.getElementById("opts").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});
