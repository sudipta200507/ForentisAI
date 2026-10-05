/**
 * Settings helper shared by the service worker, side panel and options page.
 * Stored in chrome.storage.sync so they follow the signed-in Chrome profile.
 */

export const DEFAULT_SETTINGS = Object.freeze({
  // Local development backend (docker-compose publishes it on the loopback).
  backendUrl: "http://127.0.0.1:8000",
  // Analysis request timeout in seconds (cold DeBERTa load can take ~20 s).
  requestTimeoutSeconds: 120,
});

export async function loadSettings() {
  try {
    const stored = await chrome.storage.sync.get(DEFAULT_SETTINGS);
    return {
      backendUrl: normalizeBaseUrl(stored.backendUrl),
      requestTimeoutSeconds: clampTimeout(stored.requestTimeoutSeconds),
    };
  } catch (_) {
    return { ...DEFAULT_SETTINGS };
  }
}

export async function saveSettings(partial) {
  const current = await loadSettings();
  const next = { ...current };
  if (partial.backendUrl !== undefined) next.backendUrl = normalizeBaseUrl(partial.backendUrl);
  if (partial.requestTimeoutSeconds !== undefined) {
    next.requestTimeoutSeconds = clampTimeout(partial.requestTimeoutSeconds);
  }
  await chrome.storage.sync.set(next);
  return next;
}

export function normalizeBaseUrl(value) {
  const raw = String(value || "").trim().replace(/\/+$/, "");
  if (!raw) return DEFAULT_SETTINGS.backendUrl;
  if (!/^https?:\/\//i.test(raw)) return DEFAULT_SETTINGS.backendUrl;
  try {
    return new URL(raw).origin; // drop any path/query; backend is at origin root
  } catch (_) {
    return DEFAULT_SETTINGS.backendUrl;
  }
}

function clampTimeout(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return DEFAULT_SETTINGS.requestTimeoutSeconds;
  return Math.min(600, Math.max(10, Math.round(n)));
}

/** True when the backend origin is covered by granted host permissions. */
export async function backendOriginPermitted(backendUrl) {
  try {
    const origin = new URL(backendUrl).origin + "/*";
    const granted = await chrome.permissions.contains({ origins: [origin] });
    if (granted) return true;
    const manifestOrigins = (chrome.runtime.getManifest().host_permissions || []).map(
      (pattern) => pattern.replace(/\/\*$/, "") === new URL(backendUrl).origin,
    );
    return manifestOrigins.some(Boolean);
  } catch (_) {
    return false;
  }
}

/** Ask the user to grant access to a custom backend origin (MV3 flow). */
export async function requestBackendOrigin(backendUrl) {
  try {
    const origin = new URL(backendUrl).origin + "/*";
    return await chrome.permissions.request({ origins: [origin] });
  } catch (_) {
    return false;
  }
}
