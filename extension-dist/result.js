const root = document.getElementById("result");
const url = new URLSearchParams(location.search).get("u");

document.getElementById("target").textContent = url || "—";
document.getElementById("opts").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

(async () => {
  if (!url) {
    SBX.renderError(root, "No URL provided.");
    return;
  }
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
})();
