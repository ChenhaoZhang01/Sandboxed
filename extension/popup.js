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

// ---- file / download checker (ClamAV via the backend /scan-file) ----
const fileDropzone = document.getElementById("fileDropzone");
const fileInput = document.getElementById("fileInput");
const fileBrowse = document.getElementById("fileBrowse");
const fileStatus = document.getElementById("fileStatus");
const fileScan = document.getElementById("fileScan");

async function scanFile(file) {
  if (!file) return;
  fileStatus.textContent = "Scanning " + file.name + "…";
  fileScan.hidden = true;
  const base = await SBX.getApiBase();
  let data;
  try {
    const res = await fetch(base + "/scan-file", {
      method: "POST",
      headers: { "Content-Type": file.type || "application/octet-stream" },
      body: file,
    });
    data = await res.json().catch(() => null);
    if (!res.ok) data = { status: "error", message: (data && data.error) || `HTTP ${res.status}` };
  } catch (err) {
    data = { status: "error", message: "Could not reach " + base };
  }
  renderFileScan(file.name, data || { status: "error" });
  fileStatus.textContent = "ClamAV download / file checker";
  fileInput.value = "";
}

function renderFileScan(name, data) {
  let line;
  if (data.status === "infected") line = `INFECTED — ${(data.viruses || []).join(", ") || "unknown signature"}`;
  else if (data.status === "clean") line = "Clean.";
  else if (data.status === "unavailable") line = "Scanner unavailable on server.";
  else line = "Could not scan (" + (data.message || "unknown error") + ").";

  fileScan.textContent = `${name}: ${line}`;
  fileScan.classList.remove("safe", "warn", "danger");
  fileScan.classList.add(data.status === "infected" ? "danger" : data.status === "clean" ? "safe" : "warn");
  fileScan.hidden = false;
}

fileBrowse.addEventListener("click", () => fileInput.click());
fileDropzone.addEventListener("click", (e) => {
  if (e.target !== fileBrowse) fileInput.click();
});
fileInput.addEventListener("change", () => scanFile(fileInput.files && fileInput.files[0]));
["dragenter", "dragover"].forEach((evt) =>
  fileDropzone.addEventListener(evt, (e) => {
    e.preventDefault();
    fileDropzone.classList.add("dragover");
  })
);
["dragleave", "dragend"].forEach((evt) =>
  fileDropzone.addEventListener(evt, () => fileDropzone.classList.remove("dragover"))
);
fileDropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  fileDropzone.classList.remove("dragover");
  scanFile(e.dataTransfer.files && e.dataTransfer.files[0]);
});
