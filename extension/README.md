# ForentisAI Chrome Extension

Analyze the currently opened Gmail message with your local ForentisAI backend:
SPF/DKIM/DMARC authentication, model evidence (NLP + Technical ML), a
deterministic risk assessment, forensic transport-path evidence and
explanations — rendered in the Chrome side panel.

**Privacy:** the extension reads ONLY the Gmail message id from the URL hash.
The raw email is fetched through the official Gmail API (`gmail.readonly`
scope) and sent to the backend you configure — nothing is sent anywhere else,
and no message content is stored by the extension (only the analysis result,
in `chrome.storage.session`, which is cleared when the browser closes).

## Components

| File | Purpose |
| --- | --- |
| `manifest.json` | MV3 manifest; permissions, OAuth2 client id, side panel |
| `background.js` | Service worker: detection → Gmail API → backend → panel state |
| `content/gmail.js` | Detects the opened message id from Gmail's URL hash |
| `lib/gmail_api.js` | OAuth (chrome.identity) + `users.messages.get?format=raw` |
| `lib/backend_api.js` | `/analyze-email` client with timeout/error mapping |
| `lib/settings.js` | Backend URL + timeout settings (`chrome.storage.sync`) |
| `sidepanel/` | The side panel UI (real backend data only) |
| `options/` | Backend URL configuration + origin permission grant |

## Setup (local development)

1. **Start the backend** (repo root):

   ```bash
   docker compose up -d
   # API is then at http://127.0.0.1:8000 (docs at /docs)
   ```

2. **Create a Google OAuth client id** (one time):
   - Go to <https://console.cloud.google.com/apis/credentials>.
   - Create a project (or reuse one), enable the **Gmail API**.
   - *Credentials → Create credentials → OAuth client ID →* type
     **Chrome Extension**. Paste your extension ID (see step 3) into
     *Application ID*.
   - Copy the client id (`…apps.googleusercontent.com`).

3. **Load the extension unpacked**:
   - Chrome → `chrome://extensions` → enable *Developer mode*.
   - *Load unpacked* → select this `extension/` directory.
   - Copy the generated **extension ID** shown on the card.
   - Put that extension ID into your OAuth client (step 2), then put the
     client id into `extension/manifest.json` → `oauth2.client_id`
     (replace the `REPLACE_WITH_...` placeholder) and reload the extension.

4. **Add the extension origin to the backend CORS list** (only needed if you
   serve the React dashboard from a different origin — the extension's own
   fetches from the service worker rely on `host_permissions`, which already
   cover `http://127.0.0.1:8000`):

   ```bash
   # .env
   API_CORS_ORIGINS=http://localhost:5173,chrome-extension://<EXTENSION_ID>
   ```

5. **Use it**: open Gmail, open any message, click the ForentisAI icon.
   The side panel shows the analysis. Re-analysis is available in the panel;
   the backend URL can be changed in the extension options.

## Scopes

The extension requests exactly one scope:

- `https://www.googleapis.com/auth/gmail.readonly` — required for
  `users.messages.get(format=raw)`. It cannot modify or send mail.

No OAuth client secret exists in this extension (installed-app flow; token
issuance is managed by Chrome).

## Failure handling

| Situation | Panel shows |
| --- | --- |
| Backend not running / unreachable | "Backend unreachable" + hint |
| Backend request timeout (configurable, default 120 s) | "Analysis timed out" |
| Rspamd down (strict auth mode) | HTTP 503 → "Authentication service unavailable" |
| Oversized/malformed email | HTTP 413/422 → "Message rejected" |
| Gmail OAuth not configured | "Gmail OAuth not configured" + README pointer |
| Gmail permission denied / revoked | "Gmail access needed" |
| Message deleted while analyzing | "Message not found" |
| Custom backend origin without permission | "Backend access not granted" |

## Limitations (V1)

- Message detection uses Gmail's URL hash (`#inbox/<id>`); if Gmail changes
  its URL scheme, detection must be updated. The raw email itself is NEVER
  taken from the DOM — only via the Gmail API.
- The default `host_permissions` cover the local backend at
  `127.0.0.1:8000` / `localhost:8000`; other origins require the options-page
  permission grant.
- The extension never executes attachments, never visits URLs from the
  email, and never stores raw email content.
