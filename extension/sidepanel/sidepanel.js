/**
 * Side panel renderer (Phase 14).
 *
 * Renders EXCLUSIVELY from the backend's AnalysisResponse stored by the
 * service worker. There are no hard-coded security results: every value
 * shown comes from the analysis of the actual message. States rendered:
 * idle, no_message, working, error, done (with all product sections).
 */

const root = document.getElementById("root");
const reanalyzeButton = document.getElementById("reanalyze");
const optionsButton = document.getElementById("open-options");
const backendStatus = document.getElementById("backend-status");

let currentState = { status: "idle" };

// ---------------------------------------------------------------------------
// State plumbing
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message) => {
  if (message && message.type === "STATE_UPDATED" && message.state) {
    currentState = message.state;
    render();
  }
});

async function bootstrap() {
  // Ask the (possibly fresh) service worker for the current state.
  try {
    await chrome.runtime.sendMessage({ type: "PANEL_REQUEST_STATE" });
  } catch (_) {
    currentState = { status: "idle" };
    render();
  }
  void pingBackend();
}

async function pingBackend() {
  let reachable = false;
  try {
    const response = await chrome.runtime.sendMessage({ type: "PANEL_PING_BACKEND" });
    reachable = Boolean(response && response.reachable);
  } catch (_) {
    reachable = false;
  }
  backendStatus.textContent = reachable ? "backend connected" : "backend unreachable";
  backendStatus.className = `backend-status ${reachable ? "ok" : "down"}`;
}

reanalyzeButton.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "PANEL_REANALYZE" });
});
optionsButton.addEventListener("click", () => chrome.runtime.openOptionsPage());

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function esc(value) {
  const div = document.createElement("div");
  div.textContent = value === null || value === undefined ? "" : String(value);
  return div.innerHTML;
}

function render() {
  const { status } = currentState;
  reanalyzeButton.disabled = !currentState.messageId;

  if (status === "idle" || status === "no_message") {
    root.innerHTML = `<div class="empty">${
      status === "idle"
        ? "Open a message in Gmail to analyze it."
        : "Open a specific message in Gmail (a conversation view) to analyze it."
    }</div>`;
    return;
  }

  if (status === "working") {
    const stages = {
      starting: "Preparing…",
      fetching_email: "Fetching message via Gmail API…",
      analyzing: "Analyzing with the backend…",
    };
    root.innerHTML = `
      <div class="section working">
        <h2>Analysis in progress</h2>
        <div><span class="spinner"></span>${esc(stages[currentState.stage] || "Working…")}</div>
        <div class="meta-line" style="margin-top:8px">message ${esc(currentState.messageId || "")}</div>
      </div>`;
    return;
  }

  if (status === "error") {
    const error = currentState.error || {};
    root.innerHTML = `
      <div class="section error-box">
        <h2>Analysis failed</h2>
        <div>${esc(error.title || "Unknown error")}</div>
        <div class="meta-line" style="margin-top:6px">${esc(error.detail || "")}</div>
        <div class="meta-line" style="margin-top:6px">message ${esc(currentState.messageId || "")}</div>
      </div>`;
    return;
  }

  if (status === "done") {
    renderAnalysis(currentState.analysis);
  }
}

function severityColor(score) {
  if (score >= 70) return "var(--malicious)";
  if (score >= 40) return "var(--suspicious)";
  return "var(--benign)";
}

function verdictClass(verdict) {
  const allowed = ["benign", "suspicious", "malicious", "inconclusive"];
  return allowed.includes(verdict) ? `verdict-${verdict}` : "verdict-inconclusive";
}

function authCell(result) {
  if (result === "pass") return `<span class="v pass">pass</span>`;
  if (result === "fail" || result === "softfail") return `<span class="v fail">${esc(result)}</span>`;
  return `<span class="v unknown">${esc(result || "n/a")}</span>`;
}

function renderAnalysis(analysis) {
  if (!analysis) {
    root.innerHTML = `<div class="empty">No analysis data.</div>`;
    return;
  }

  const risk = analysis.risk || {};
  const score = typeof risk.risk_score === "number" ? risk.risk_score : 0;
  const auth = analysis.authentication || {};
  const ai = analysis.ai || {};
  const fusion = ai.fusion || {};
  const explanations = (ai.explainability && ai.explainability.explanations) || [];
  const limitations = risk.limitations || [];
  const indicators = (analysis.intelligence && analysis.intelligence.indicators) || [];
  const threatTypes = risk.threat_types || [];

  const html = [];

  // Risk header.
  html.push(`
    <div class="section">
      <h2>Risk assessment</h2>
      <div>
        <span class="risk-score" style="color:${severityColor(score)}">${score.toFixed(0)}</span>
        <span class="verdict-chip ${verdictClass(risk.verdict)}">${esc(risk.verdict || "inconclusive")}</span>
      </div>
      <div class="risk-bar"><div class="risk-bar-fill" style="width:${Math.min(100, score)}%;background:${severityColor(score)}"></div></div>
      <div class="kv"><span class="k">severity</span><span class="v">${esc(risk.severity || "n/a")}</span></div>
      <div class="kv"><span class="k">confidence</span><span class="v">${
        typeof risk.confidence === "number" ? `${(risk.confidence * 100).toFixed(0)}%` : "n/a"
      }</span></div>
      ${threatTypes.length ? `<div class="kv"><span class="k">threat types</span><span class="v">${esc(threatTypes.join(", "))}</span></div>` : ""}
    </div>`);

  // Reasons.
  if (Array.isArray(risk.reasons) && risk.reasons.length) {
    html.push(`
      <div class="section">
        <h2>Why this verdict</h2>
        ${risk.reasons.map((reason) => `<div class="explanation"><div class="reason">${esc(reason)}</div></div>`).join("")}
      </div>`);
  }

  // Authentication.
  html.push(`
    <div class="section">
      <h2>Authentication (SPF / DKIM / DMARC)</h2>
      <div class="kv"><span class="k">SPF</span>${authCell(auth.spf && auth.spf.result)}</div>
      <div class="kv"><span class="k">DKIM</span>${authCell(auth.dkim && auth.dkim.result)}</div>
      <div class="kv"><span class="k">DMARC</span>${authCell(auth.dmarc && auth.dmarc.result)}</div>
      <div class="meta-line" style="margin-top:6px">A passing protocol is not a safety guarantee; see limitations.</div>
    </div>`);

  // Model evidence.
  html.push(`
    <div class="section">
      <h2>Model evidence</h2>
      ${modelLine("NLP (DeBERTa)", ai.nlp)}
      ${modelLine("Technical ML (RF)", ai.technical_ml)}
      ${modelLine("Fusion", fusion, true)}
    </div>`);

  // Explanations.
  if (explanations.length) {
    html.push(`
      <div class="section">
        <h2>Explanations</h2>
        ${explanations
          .map(
            (explanation) => `
          <div class="explanation">
            <span class="impact impact-${esc(explanation.impact || "low")}">${esc(explanation.impact || "low")}</span>
            <span class="meta-line">${esc(explanation.category || "")}</span>
            <div class="reason">${esc(explanation.reason)}</div>
          </div>`,
          )
          .join("")}
      </div>`);
  }

  // Indicators.
  if (indicators.length) {
    html.push(`
      <div class="section">
        <h2>Indicators (${indicators.length})</h2>
        ${indicators
          .slice(0, 20)
          .map(
            (indicator) =>
              `<div class="indicator"><span class="type">${esc(indicator.type)}</span>${esc(indicator.value)}</div>`,
          )
          .join("")}
        ${indicators.length > 20 ? `<div class="meta-line">…and ${indicators.length - 20} more</div>` : ""}
      </div>`);
  }

  // Forensics.
  const forensics = analysis.forensics || {};
  if (Array.isArray(forensics.received_chain) && forensics.received_chain.length) {
    html.push(`
      <div class="section">
        <h2>Forensic path (${forensics.received_chain.length} hops)</h2>
        ${forensics.received_chain
          .map(
            (hop) =>
              `<div class="kv"><span class="k">hop ${esc(hop.position ?? "?")}</span><span class="v">${
                esc(hop.from_host || hop.from_ip || "unknown")
              } <span class="meta-line">(${esc(hop.ip_classification || "unclassified")})</span></span></div>`,
          )
          .join("")}
      </div>`);
  }

  // Limitations.
  if (limitations.length) {
    html.push(`
      <div class="section">
        <h2>Limitations</h2>
        ${limitations.map((limitation) => `<div class="limitation">${esc(limitation)}</div>`).join("")}
      </div>`);
  }

  root.innerHTML = html.join("");
}

function modelLine(label, model, isFusion = false) {
  if (!model) return `<div class="kv"><span class="k">${esc(label)}</span><span class="v unknown">missing</span></div>`;
  const available = model.available !== false;
  const status = model.status || (available ? "available" : "unavailable");
  const probs = model.probabilities || {};
  const suspicious = typeof probs.suspicious === "number" ? probs.suspicious : model.probability_suspicious;
  const value = available
    ? isFusion || typeof suspicious === "number"
      ? typeof suspicious === "number"
        ? `susp. ${(suspicious * 100).toFixed(0)}%`
        : status
      : status
    : `<span class="fail">${esc(status)}${model.reason ? ` (${esc(model.reason)})` : ""}</span>`;
  return `<div class="kv"><span class="k">${esc(label)}</span><span class="v">${value}</span></div>`;
}

bootstrap();
render();
