/**
 * ForentisAI API client (Phase 15).
 *
 * All dashboard data comes from the real backend: analyses, reports and
 * email analysis. No data is ever mocked or hard-coded here.
 */

const BASE = import.meta.env.VITE_API_BASE || "/api";

export class ApiError extends Error {
  constructor(message, { status = null, code = null, detail = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${BASE}${path}`, options);
  } catch (error) {
    throw new ApiError(
      "The ForentisAI backend is unreachable. Is `docker compose up -d` running?",
      { code: "network_error" },
    );
  }
  if (!response.ok) {
    let code = null;
    let detail = null;
    try {
      const body = await response.json();
      code = body && body.error && body.error.code;
      detail = body && (body.error && body.error.detail) || body.detail || null;
    } catch (_) {
      // Non-JSON error body.
    }
    throw new ApiError(`Request failed (HTTP ${response.status}).`, {
      status: response.status,
      code,
      detail,
    });
  }
  return response.json();
}

export function listAnalyses(limit = 50) {
  return request(`/analyses?limit=${encodeURIComponent(limit)}`);
}

export function getAnalysis(analysisId) {
  return request(`/analyses/${encodeURIComponent(analysisId)}`);
}

export function getReportJson(analysisId) {
  return request(`/reports/${encodeURIComponent(analysisId)}?format=json`);
}

/** Full report URL (HTML) — used for "open report" links. */
export function reportHtmlUrl(analysisId) {
  return `${BASE}/reports/${encodeURIComponent(analysisId)}?format=html`;
}

/**
 * Analyze one .eml file. Returns the full AnalysisResponse.
 * 503 (Rspamd unavailable in strict mode) is surfaced as a controlled error.
 */
export async function analyzeEmailFile(file) {
  const form = new FormData();
  form.append("upload", file, file.name || "message.eml");
  try {
    return await request("/analyze-email", { method: "POST", body: form });
  } catch (error) {
    if (error instanceof ApiError && error.status === 503) {
      throw new ApiError(
        "Authentication service (Rspamd) is unavailable and the backend runs in strict mode. Start the Docker stack and retry.",
        { status: 503, code: "rspamd_unavailable" },
      );
    }
    throw error;
  }
}

/** Generate a report from an AnalysisResponse the client already holds. */
export async function generateReport(analysisResponse, format = "json") {
  const response = await fetch(
    `${BASE}/reports/generate?format=${encodeURIComponent(format)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(analysisResponse),
    },
  );
  if (!response.ok) {
    throw new ApiError(`Report generation failed (HTTP ${response.status}).`, {
      status: response.status,
    });
  }
  if (format === "html") return response.text();
  return response.json();
}
