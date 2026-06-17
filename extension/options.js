const api = document.getElementById("api");
const saved = document.getElementById("saved");

const modeInputs = document.querySelectorAll('input[name="mode"]');

// layer toggles
const layerDomainAge = document.getElementById("layer-domain-age");
const layerSafeBrowsing = document.getElementById("layer-safe-browsing");
const layerPhishing = document.getElementById("layer-phishing-enrichment");
const historySwitch = document.getElementById("historySwitch");

// ---------------- LOAD ----------------
SBX.getSettings().then((s) => {
  api.value = s.apiBase || SBX.DEFAULTS.apiBase;

  // mode
  const radio = document.querySelector(
    `input[name="mode"][value="${s.checkMode}"]`
  );
  if (radio) radio.checked = true;

  // layers
  layerDomainAge.checked = s.analysisLayers.domainAge;
  layerSafeBrowsing.checked = s.analysisLayers.safeBrowsing;
  layerPhishing.checked = s.analysisLayers.phishingEnrichment;

  // history default (if missing)
  historySwitch.checked = s.historyEnabled ?? true;
});

// ---------------- SAVE ----------------
document.getElementById("save").addEventListener("click", async () => {
  const checkedMode = document.querySelector('input[name="mode"]:checked');

  await SBX.setSettings({
    apiBase: api.value.trim() || SBX.DEFAULTS.apiBase,
    checkMode: checkedMode ? checkedMode.value : "manual",
    historyEnabled: historySwitch.checked,

    analysisLayers: {
      domainAge: layerDomainAge.checked,
      safeBrowsing: layerSafeBrowsing.checked,
      phishingEnrichment: layerPhishing.checked,
    },
  });

  saved.hidden = false;
  setTimeout(() => (saved.hidden = true), 1500);
});