import {
  DEFAULT_SETTINGS,
  loadSettings,
  saveSettings,
  requestBackendOrigin,
} from "../lib/settings.js";
import { clearCachedToken } from "../lib/gmail_api.js";

const urlInput = document.getElementById("backend-url");
const timeoutInput = document.getElementById("timeout");
const statusSpan = document.getElementById("status");

async function init() {
  const settings = await loadSettings();
  urlInput.value = settings.backendUrl;
  timeoutInput.value = String(settings.requestTimeoutSeconds);
}

document.getElementById("save").addEventListener("click", async () => {
  const next = await saveSettings({
    backendUrl: urlInput.value || DEFAULT_SETTINGS.backendUrl,
    requestTimeoutSeconds: Number(timeoutInput.value) || DEFAULT_SETTINGS.requestTimeoutSeconds,
  });
  // Non-default origins need an explicit MV3 permission grant.
  if (!next.backendUrl.startsWith("http://127.0.0.1:8000") && !next.backendUrl.startsWith("http://localhost:8000")) {
    const granted = await requestBackendOrigin(next.backendUrl);
    show(granted ? "saved; access granted" : "saved; access NOT granted — analysis will fail until granted");
    return;
  }
  show("saved");
});

document.getElementById("signout").addEventListener("click", async () => {
  await clearCachedToken();
  show("Gmail token cleared");
});

function show(text) {
  statusSpan.textContent = text;
  setTimeout(() => (statusSpan.textContent = ""), 4000);
}

init();
