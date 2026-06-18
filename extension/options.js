const api = document.getElementById("api");
const saved = document.getElementById("saved");

const modeInputs = document.querySelectorAll('input[name="mode"]');

// layer toggles
const layerDomainAge = document.getElementById("layer-domain-age");
const layerSafeBrowsing = document.getElementById("layer-safe-browsing");
const layerPhishing = document.getElementById("layer-phishing-enrichment");
const layerRecordReplay = document.getElementById("layer-record-replay");
const layerCredentialTrap = document.getElementById("layer-credential-trap");
const historySwitch = document.getElementById("historySwitch");

// redirect blocker + download guard
const redirectEnabled = document.getElementById("redirect-enabled");
const redirectActionInputs = document.querySelectorAll('input[name="redirectAction"]');
const downloadEnabled = document.getElementById("download-enabled");
const downloadScan = document.getElementById("download-scan");
const downloadScopeInputs = document.querySelectorAll('input[name="downloadScope"]');

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
  layerRecordReplay.checked = s.analysisLayers.recordReplay;
  layerCredentialTrap.checked = s.analysisLayers.credentialTrap;

  // history default (if missing)
  historySwitch.checked = s.historyEnabled ?? true;

  // redirect blocker
  redirectEnabled.checked = s.redirectBlock.enabled;
  const rAction = document.querySelector(
    `input[name="redirectAction"][value="${s.redirectBlock.action}"]`
  );
  if (rAction) rAction.checked = true;

  // download guard
  downloadEnabled.checked = s.downloadGuard.enabled;
  downloadScan.checked = s.downloadGuard.scan;
  const dScope = document.querySelector(
    `input[name="downloadScope"][value="${s.downloadGuard.scope}"]`
  );
  if (dScope) dScope.checked = true;
});

// ---------------- SAVE ----------------
document.getElementById("save").addEventListener("click", async () => {
  const checkedMode = document.querySelector('input[name="mode"]:checked');
  const redirectAction = document.querySelector('input[name="redirectAction"]:checked');
  const downloadScope = document.querySelector('input[name="downloadScope"]:checked');

  await SBX.setSettings({
    apiBase: api.value.trim() || SBX.DEFAULTS.apiBase,
    checkMode: checkedMode ? checkedMode.value : "manual",
    historyEnabled: historySwitch.checked,

    analysisLayers: {
      domainAge: layerDomainAge.checked,
      safeBrowsing: layerSafeBrowsing.checked,
      phishingEnrichment: layerPhishing.checked,
      recordReplay: layerRecordReplay.checked,
      credentialTrap: layerCredentialTrap.checked,
    },

    redirectBlock: {
      enabled: redirectEnabled.checked,
      action: redirectAction ? redirectAction.value : "scan",
    },

    downloadGuard: {
      enabled: downloadEnabled.checked,
      scope: downloadScope ? downloadScope.value : "all",
      scan: downloadScan.checked,
    },
  });

  saved.hidden = false;
  setTimeout(() => (saved.hidden = true), 1500);
});