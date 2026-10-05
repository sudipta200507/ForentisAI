/**
 * Gmail API client (Phase 12).
 *
 * Uses chrome.identity.getAuthToken (the browser-managed OAuth flow) with
 * the single minimal scope gmail.readonly, then fetches the raw RFC822
 * message via users.messages.get?format=raw.
 *
 * Secrets: the OAuth CLIENT ID lives in manifest.json's oauth2 section
 * (public by design for installed apps). No client secret exists anywhere
 * in this extension; token issuance/caching is handled by Chrome.
 */

const GMAIL_API_ORIGIN = "https://gmail.googleapis.com";
const MANIFEST = chrome.runtime.getManifest();
const OAUTH_SCOPES = MANIFEST.oauth2 ? MANIFEST.oauth2.scopes : [];

export class GmailApiError extends Error {
  constructor(kind, message, { status = null } = {}) {
    super(message);
    this.name = "GmailApiError";
    this.kind = kind; // permission_denied | not_found | api_error | not_configured
    this.status = status;
  }
}

/** True when manifest.json still ships the placeholder client id. */
export function isOAuthConfigured() {
  const clientId = MANIFEST.oauth2 && MANIFEST.oauth2.client_id;
  return Boolean(clientId) && !clientId.startsWith("REPLACE_WITH_");
}

/**
 * Get a cached-or-interactive OAuth token for the declared scope.
 * chrome.identity.getAuthToken handles consent, caching and revocation
 * flows for us; we only surface failures as controlled errors.
 */
export async function getAuthToken() {
  if (!isOAuthConfigured()) {
    throw new GmailApiError(
      "not_configured",
      "Gmail OAuth is not configured: set your OAuth client ID in manifest.json (see extension/README.md).",
    );
  }
  try {
    return await chrome.identity.getAuthToken({ interactive: true, scopes: OAUTH_SCOPES });
  } catch (error) {
    const message = String((error && error.message) || error);
    if (/revoked|user rejected|denied|cancelled/i.test(message)) {
      throw new GmailApiError("permission_denied", "Gmail access was not granted.", error);
    }
    throw new GmailApiError("api_error", `OAuth token error: ${message}`, error);
  }
}

/** Remove the cached token (used by the options page "sign out" action). */
export async function clearCachedToken() {
  if (!isOAuthConfigured()) return;
  try {
    const token = await chrome.identity.getAuthToken({ interactive: false, scopes: OAUTH_SCOPES });
    if (token) await chrome.identity.removeCachedAuthToken({ token });
  } catch (_) {
    // No cached token — nothing to clear.
  }
}

function base64UrlToBytes(input) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Fetch the raw RFC822 bytes of one message.
 * Returns a File named message.eml ready for a multipart upload.
 */
export async function fetchRawMessage(messageId) {
  const token = await getAuthToken();
  const url = `${GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/${encodeURIComponent(messageId)}?format=raw`;
  let response;
  try {
    response = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch (error) {
    throw new GmailApiError("api_error", `Gmail API request failed: ${error}`);
  }

  if (response.status === 401) {
    // Stale cached token: drop it once and retry with a fresh one.
    await clearCachedToken();
    const fresh = await getAuthToken();
    response = await fetch(url, {
      headers: { Authorization: `Bearer ${fresh}` },
    });
  }

  if (response.status === 401 || response.status === 403) {
    throw new GmailApiError(
      "permission_denied",
      "Gmail API refused access to this message (check the granted scope).",
      { status: response.status },
    );
  }
  if (response.status === 404) {
    throw new GmailApiError("not_found", "The message no longer exists in Gmail.", { status: 404 });
  }
  if (!response.ok) {
    throw new GmailApiError("api_error", `Gmail API error ${response.status}.`, { status: response.status });
  }

  const payload = await response.json();
  if (!payload || typeof payload.raw !== "string") {
    throw new GmailApiError("api_error", "Gmail API returned no raw message content.");
  }
  const bytes = base64UrlToBytes(payload.raw);
  // RFC822 content type; a plain .eml filename for the backend validator.
  return new File([bytes], "gmail-message.eml", { type: "message/rfc822" });
}
