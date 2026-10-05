/**
 * ForentisAI content script — Gmail opened-message detection (Phase 11).
 *
 * Runs on https://mail.google.com/*. Gmail is a hash-routed SPA: an opened
 * conversation appears as e.g.  #inbox/AbCdEf12345  or  #search/foo/AbCdEf.
 * This script translates hash navigation into a minimal event for the
 * service worker; it never reads message content from the DOM (the raw
 * email is later obtained through the Gmail API, NOT from Gmail markup —
 * DOM scraping cannot be trusted for forensic headers).
 *
 * Privacy: the ONLY data leaving this script is the Gmail message id string
 * from the URL hash. No subject, body, or address is ever read or sent.
 */
(() => {
  "use strict";

  // Gmail's well-known non-message views (a hash segment equal to one of
  // these is a list view, not an opened conversation).
  const VIEW_WORDS = new Set([
    "inbox", "starred", "snoozed", "sent", "drafts", "important",
    "chats", "scheduled", "all", "spam", "trash", "categories",
    "labels", "search", "archive", "imp", "lg",
  ]);

  let lastMessageId = null;

  /** Extract a plausible message id from the URL hash, or null. */
  function extractMessageId(hash) {
    if (!hash || !hash.startsWith("#")) return null;
    const segments = hash.slice(1).split("/");
    const last = segments[segments.length - 1];
    if (!last) return null;
    // Message ids are long, opaque, URL-safe tokens. List views end in a
    // known view word or a label name; a long alphanumeric tail is treated
    // as a conversation id (heuristic — detection only, never forensics).
    if (VIEW_WORDS.has(last.toLowerCase())) return null;
    if (segments.length < 2) return null; // "#inbox" alone is a list view
    if (!/^[A-Za-z0-9_-]{12,}$/.test(last)) return null;
    return last;
  }

  function notify(messageId) {
    if (messageId === lastMessageId) return; // dedupe repeat notifications
    lastMessageId = messageId;
    try {
      chrome.runtime.sendMessage({
        type: "GMAIL_MESSAGE_OPENED",
        messageId,
        url: location.href,
      }).catch(() => {
        // Service worker asleep or extension reloading; nothing to do.
      });
    } catch (_) {
      // Extension context invalidated (reload/update) — ignore.
    }
  }

  function currentMessageId() {
    return extractMessageId(location.hash);
  }

  function evaluate() {
    notify(currentMessageId());
  }

  // Gmail navigates via hash changes (and occasionally pushState to the
  // same hash); hashchange covers both on every observed navigation.
  window.addEventListener("hashchange", evaluate);
  // Initial state when the script runs after the SPA has routed.
  evaluate();

  // Gmail re-renders without hash change in some flows; a slow poll is a
  // cheap safety net (it only compares the URL hash — no DOM reading).
  setInterval(evaluate, 1500);
})();
