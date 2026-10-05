# Dashboard & Chrome Extension (Phases 10–16)

Architecture, setup and limitations for the two ForentisAI clients and the
correlation service added in Phases 10–16.

---

## System overview

```
 Gmail ──► Chrome MV3 Extension ──► Gmail API (gmail.readonly)
                │                        │ raw .eml bytes
                ▼                        ▼
         Side Panel ◄── chrome.storage ◄─ FastAPI /analyze-email
                                          │
                            ┌─────────────┼──────────────────┐
                            ▼             ▼                  ▼
                       Rspamd       DNS/RDAP/GeoIP      AI models
                    (SPF/DKIM/DMARC)  intelligence    (DeBERTa + RF)
                            └─────────────┼──────────────────┘
                                          ▼
                               deterministic risk engine
                                          │
                        PostgreSQL (derived data only) + reports
                                          │
                               React Dashboard ◄── /analyses, /reports,
                                                   /correlation
```

## API endpoints used by the clients

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/analyze-email` | POST | Full pipeline for one .eml upload (multipart `upload`) |
| `/analyses?limit=N` | GET | Recent stored analyses (dashboard list) |
| `/analyses/{analysis_id}` | GET | Full stored derived record |
| `/reports/generate?format=json\|html` | POST | Report from a response the caller holds |
| `/reports/{analysis_id}?format=json\|html` | GET | Report reconstructed from the stored record |
| `/correlation/indicators/{type}?value=` | GET | Analyses sharing one indicator |
| `/correlation/analyses/{analysis_id}` | GET | Analyses sharing indicators with one analysis |
| `/correlation/graph` | GET | Bipartite analysis↔indicator overlap graph |
| `/correlation/similarity?analysis_id_a=&analysis_id_b=` | GET | Jaccard overlap of two analyses |
| `/health`, `/health/rspamd` | GET | Liveness + Rspamd dependency status |

All endpoints except `/health*` are security-scoped (Phase 8): with API keys
configured or a non-local environment they require `Authorization: Bearer`
or `X-API-Key`.

## Chrome extension (Phases 10–14)

See [extension/README.md](../extension/README.md) for full setup (load
unpacked, OAuth client id, CORS). Key properties:

- **Detection** (Phase 11): content script reads ONLY the Gmail URL hash;
  the raw email is obtained exclusively through the Gmail API
  (`users.messages.get?format=raw`), never from Gmail's DOM.
- **OAuth** (Phase 12): `chrome.identity.getAuthToken` with the single
  minimal scope `gmail.readonly`; no client secret exists in the extension.
- **Backend link** (Phase 13): configurable backend URL (options page) with
  explicit failure states for: unreachable backend, timeouts, rate limiting,
  oversized/malformed email, Rspamd-unavailable (strict mode), OAuth denial
  and revoked messages.
- **Side panel** (Phase 14): renders backend data verbatim — risk,
  verdict/severity/confidence, threat types, SPF/DKIM/DMARC, model
  evidence, explanations, indicators, forensic hops, limitations. No
  hard-coded security results.
- The DeBERTa model is NEVER bundled into the extension; inference always
  happens in the backend.

## React dashboard (Phase 15)

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api → 127.0.0.1:8000
npm run build      # production bundle in dist/
```

Pages:

- **Dashboard** — recent stored analyses (`GET /analyses`), verdict chips,
  risk bands; links to detail and report views.
- **Analyze email** — uploads a .eml through the real pipeline and renders
  every response section; surfaces 503 (Rspamd strict mode) and other
  controlled errors.
- **Analysis detail** — the persisted derived record (`GET /analyses/{id}`),
  including the privacy note that raw content is never stored.
- **Report** — full report from a fresh analysis (POST `/reports/generate`)
  or the partial stored report (`GET /reports/{id}`), with JSON download and
  HTML view.

For a production deployment set `VITE_API_BASE` to the backend origin and
add the dashboard origin to `API_CORS_ORIGINS`.

## Correlation V1 (Phase 16)

Implemented in `backend/app/correlation/`:

- `indicator_correlation.py` — normalization (domains lower-cased, URLs
  collapse to host) and lookups: by indicator, and "related analyses" via
  shared indicators plus sender/Reply-To/Message-ID domains.
- `graph_builder.py` — bipartite analysis↔indicator graph for visualization.
- `campaign_similarity.py` — Jaccard similarity between two analyses'
  normalized indicator sets.

**Interpretation boundary (repeated in every API response):** shared
indicators show that analyses observed the same infrastructure or sender
domain. Overlap is NOT proof of common attacker ownership — shared CDNs,
mail providers, or recycled domains produce overlap. No attribution claim
is made anywhere in the product.
