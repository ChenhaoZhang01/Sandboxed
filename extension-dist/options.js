const api = document.getElementById("api");
const saved = document.getElementById("saved");

SBX.getSettings().then((s) => {
  api.value = s.apiBase || SBX.DEFAULTS.apiBase;
  const radio = document.querySelector(`input[name="mode"][value="${s.checkMode}"]`);
  if (radio) radio.checked = true;
});

document.getElementById("save").addEventListener("click", async () => {
  const checked = document.querySelector('input[name="mode"]:checked');
  await SBX.setSettings({
    apiBase: api.value.trim() || SBX.DEFAULTS.apiBase,
    checkMode: checked ? checked.value : "manual",
  });
  saved.hidden = false;
  setTimeout(() => (saved.hidden = true), 1500);
});
