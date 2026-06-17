const api = document.getElementById("api");
const saved = document.getElementById("saved");
const layerDomainAge = document.getElementById("layer-domain-age");
const layerSafeBrowsing = document.getElementById("layer-safe-browsing");
const layerPhishingEnrichment = document.getElementById("layer-phishing-enrichment");

function setLayerToggles(layers = {}) {
  layerDomainAge.checked = layers.domainAge !== false;
  layerSafeBrowsing.checked = layers.safeBrowsing !== false;
  layerPhishingEnrichment.checked = layers.phishingEnrichment === true;
}

SBX.getSettings().then((s) => {
  api.value = s.apiBase || SBX.DEFAULTS.apiBase;
  const radio = document.querySelector(`input[name="mode"][value="${s.checkMode}"]`);
  if (radio) radio.checked = true;
  setLayerToggles(s.analysisLayers || SBX.DEFAULTS.analysisLayers);
});

document.getElementById("save").addEventListener("click", async () => {
  const checked = document.querySelector('input[name="mode"]:checked');
  await SBX.setSettings({
    apiBase: api.value.trim() || SBX.DEFAULTS.apiBase,
    checkMode: checked ? checked.value : "manual",
    analysisLayers: {
      domainAge: layerDomainAge.checked,
      safeBrowsing: layerSafeBrowsing.checked,
      phishingEnrichment: layerPhishingEnrichment.checked,
    },
  });
  saved.hidden = false;
  setTimeout(() => (saved.hidden = true), 1500);
});
