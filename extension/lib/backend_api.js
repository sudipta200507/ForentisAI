/**
 * Backend API client (Phase 13).
 *
 * Sends the raw .eml bytes to the ForentisAI backend's /analyze-email
 * endpoint and maps every failure mode to a controlled, user-presentable
 * error state: backend unreachable, HTTP errors, rate limiting, oversized
 * or malformed email, Rspamd unavailable (503) and request timeouts.
 *
 * The email content itself is only ever sent to the user-configured
 * backend origin; nothing else about the message leaves the browser.
 */

import { loadSettings } from "./settings.js";

export class BackendApiError extends Error {
  constructor(kind, message, { status = null, detail = null } = {}) {
    super(message);
    this.name = "BackendApiError";
    this.kind = kind; // network | http | rate_limited | timeout | invalid_response
    this.status = status;
    this.detail = detail;
  }
}

/** Human-facing summary for an error (used by the side panel). */
export function describeError(error) {
  if (!(error instanceof BackendApiError)) {
    return { title: "Unexpected error", detail: String((error && error.message) || error) };
  }
  switch (error.kind) {
    case "network":
      return {
        title: "Backend unreachable",
        detail: `Could not reach the ForentisAI backend at ${error.backendUrl || ""}. Is it running?`,
      };
    case "timeout":
      return { title: "Analysis timed out", detail: "The backend did not answer in time. Try again." };
    case "rate_limited":
      return { title: "Rate limited", detail: "Too many requests; wait a moment and retry." };
    case "http": {
      if (error.status === 503) {
        return {
          title: "Authentication service unavailable",
          detail: "The backend could not reach Rspamd (strict mode). Start the Docker stack and retry.",
        };
      }
      if (error.status === 413 || error.status === 422) {
        return { title: "Message rejected", detail: error.detail || "The email is too large or malformed." };
      }
      if (error.status === 401 || error.status === 403) {
        return { title: "Backend authentication failed", detail: "Configure a valid API key for this backend." };
      }
      return { title: `Backend error ${error.status ?? ""}`.trim(), detail: error.detail || "" };
    }
    default:
      return { title: "Analysis failed", detail: error.message };
  }
}

/**
 * POST the raw email to /analyze-email. Returns the parsed AnalysisResponse.
 * Every failure becomes a BackendApiError; this function never throws
 * anything else.
 */
export async function analyzeRawEmail(emailFile) {
  const settings = await loadSettings();
  const endpoint = `${settings.backendUrl}/analyze-email`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), settings.requestTimeoutSeconds * 1000);

  const form = new FormData();
  form.append("upload", emailFile, "message.eml");

  let response;
  try {
    response = await fetch(endpoint, { method: "POST", body: form, signal: controller.signal });
  } catch (error) {
    if (controller.signal.aborted) {
      const e = new BackendApiError("timeout", "The analysis request timed out.");
      e.backendUrl = settings.backendUrl;
      throw e;
    }
    const e = new BackendApiError("network", "The backend could not be reached.");
    e.backendUrl = settings.backendUrl;
    throw e;
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    let detail = null;
    try {
      const body = await response.json();
      detail = body && (body.detail || body.message || null);
    } catch (_) {
      // Non-JSON error body; keep null.
    }
    const kind = response.status === 429 ? "rate_limited" : "http";
    throw new BackendApiError(kind, `Backend returned HTTP ${response.status}.`, {
      status: response.status,
      detail,
    });
  }

  try {
    return await response.json();
  } catch (error) {
    throw new BackendApiError("invalid_response", "The backend response was not valid JSON.");
  }
}

/** GET /health with a short timeout — used for the panel status line. */
export async function checkBackendHealth() {
  const settings = await loadSettings();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(`${settings.backendUrl}/health`, { signal: controller.signal });
    return response.ok;
  } catch (_) {
    return false;
  } finally {
    clearTimeout(timer);
  }
}
