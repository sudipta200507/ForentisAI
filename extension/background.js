/**
 * ForentisAI service worker (Phase 10/11/13).
 *
 * Wires Gmail detection → Gmail API raw email → backend analysis →
 * side panel. All state lives in chrome.storage.session; the worker itself
 * is stateless so MV3 suspension never loses the last result.
 */

import { fetchRawMessage, GmailApiError } from "./lib/gmail_api.js";
import {
  analyzeRawEmail,
  BackendApiError,
  checkBackendHealth,
  describeError,
} from "./lib/backend_api.js";
import {
  backendOriginPermitted,
  loadSettings,
} from "./lib/settings.js";

const STATE_KEY = "panelState";

/** @type {string | null} currently opened Gmail message id */
let currentMessageId = null;
/** @type {number} monotonically increasing token; stale runs discard results */
let runToken = 0;
/** @type {string | null} message id whose analysis is in flight */
let inFlightMessageId = null;

// ---------------------------------------------------------------------------
// State store (chrome.storage.session — survives worker suspension)
// ---------------------------------------------------------------------------

async function readState() {
  try {
    const stored = await chrome.storage.session.get(STATE_KEY);
    return stored[STATE_KEY] || { status: "idle" };
  } catch (_) {
    return { status: "idle" };
  }
}

async function writeState(state) {
  await chrome.storage.session.set({ [STATE_KEY]: state });
  try {
    await chrome.runtime.sendMessage({ type: "STATE_UPDATED", state }).catch(() => {});
  } catch (_) {
    // No listeners (panel closed) — fine.
  }
}

// ---------------------------------------------------------------------------
// Action click → open the side panel
// ---------------------------------------------------------------------------

chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch(() => {
    // Older Chrome: the panel can still be opened via the menu.
  });

// ---------------------------------------------------------------------------
// Gmail detection → analysis pipeline
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message) => {
  if (!message || typeof message !== "object") return false;

  if (message.type === "GMAIL_MESSAGE_OPENED") {
    currentMessageId = message.messageId || null;
    // Clear stale results immediately; then auto-analyze the new message.
    void handleMessageOpened(currentMessageId);
  }
  if (message.type === "PANEL_REQUEST_STATE") {
    void (async () => {
      const state = await readState();
      try {
        await chrome.runtime.sendMessage({ type: "STATE_UPDATED", state }).catch(() => {});
      } catch (_) {
        // Panel may already be gone.
      }
    })();
  }
  if (message.type === "PANEL_REANALYZE") {
    void handleMessageOpened(currentMessageId, { force: true });
  }
  return false; // all replies happen via STATE_UPDATED broadcasts
});

async function handleMessageOpened(messageId, { force = false } = {}) {
  if (!messageId) {
    inFlightMessageId = null;
    runToken += 1;
    await writeState({ status: "no_message" });
    return;
  }
  // Auto-analysis is skipped when the same message is already analyzed,
  // unless the user explicitly asked for a re-analysis.
  if (!force && inFlightMessageId === messageId) return;
  if (!force) {
    const state = await readState();
    if (state.status === "done" && state.messageId === messageId) return;
  }
  await runAnalysis(messageId);
}

async function runAnalysis(messageId) {
  const token = ++runToken;
  inFlightMessageId = messageId;
  await writeState({ status: "working", messageId, stage: "starting" });

  // Step 0: the backend must be permitted (custom origins) and reachable.
  const settings = await loadSettings();
  const originOk = await backendOriginPermitted(settings.backendUrl);
  if (!originOk) {
    if (token !== runToken) return;
    await writeState({
      status: "error",
      messageId,
      error: {
        title: "Backend access not granted",
        detail: `Grant the extension access to ${settings.backendUrl} on the options page.`,
      },
    });
    inFlightMessageId = null;
    return;
  }

  try {
    // Step 1: raw email via Gmail API (OAuth gmail.readonly).
    await writeState({ status: "working", messageId, stage: "fetching_email" });
    const emailFile = await fetchRawMessage(messageId);
    if (token !== runToken) return;

    // Step 2: backend analysis.
    await writeState({ status: "working", messageId, stage: "analyzing" });
    const analysis = await analyzeRawEmail(emailFile);
    if (token !== runToken) return;

    await writeState({ status: "done", messageId, analysis, analyzedAt: new Date().toISOString() });
  } catch (error) {
    if (token !== runToken) return;
    const failure = mapFailure(error);
    await writeState({ status: "error", messageId, error: failure });
  } finally {
    if (inFlightMessageId === messageId && token === runToken) inFlightMessageId = null;
  }
}

function mapFailure(error) {
  if (error instanceof GmailApiError) {
    if (error.kind === "not_configured") {
      return { title: "Gmail OAuth not configured", detail: error.message };
    }
    if (error.kind === "permission_denied") {
      return { title: "Gmail access needed", detail: error.message };
    }
    if (error.kind === "not_found") {
      return { title: "Message not found", detail: error.message };
    }
    return { title: "Gmail API error", detail: error.message };
  }
  if (error instanceof BackendApiError) {
    return describeError(error);
  }
  return { title: "Unexpected error", detail: String((error && error.message) || error) };
}

// Keep a liveness signal for the panel header (cheap, on demand only).
// The reply is asynchronous, so the listener must return true to keep the
// message channel open until sendResponse is invoked.
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message && message.type === "PANEL_PING_BACKEND") {
    checkBackendHealth()
      .then((reachable) => sendResponse({ reachable }))
      .catch(() => sendResponse({ reachable: false }));
    return true;
  }
  return false;
});
