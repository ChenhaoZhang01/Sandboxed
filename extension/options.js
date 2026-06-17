const api = document.getElementById("api");
const saved = document.getElementById("saved");

SBX.getApiBase().then((v) => {
  api.value = v || SBX.DEFAULT_API;
});

document.getElementById("save").addEventListener("click", async () => {
  await SBX.setApiBase(api.value.trim() || SBX.DEFAULT_API);
  saved.hidden = false;
  setTimeout(() => (saved.hidden = true), 1500);
});
