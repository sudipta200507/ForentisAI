/**
 * Shared presentational sections used by the Analysis and Analysis Detail
 * pages. All values are rendered verbatim from backend data.
 */

export function RiskCard({ risk, stored = false }) {
  if (!risk) return null;
  const score = typeof risk.risk_score === "number" ? risk.risk_score : 0;
  return (
    <div className="card">
      <h2>{stored ? "Stored risk assessment" : "Risk assessment"}</h2>
      <div className="risk-line">
        <span className={`big-score score-${band(score)}`}>{score.toFixed(0)}</span>
        <span className={`chip chip-${risk.verdict}`}>{risk.verdict}</span>
      </div>
      <div className="risk-bar">
        <div
          className={`risk-bar-fill fill-${band(score)}`}
          style={{ width: `${Math.min(100, score)}%` }}
        />
      </div>
      <Row k="severity" v={risk.severity} />
      <Row k="confidence" v={pct(risk.confidence)} />
      <Row k="primary threat" v={risk.primary_threat_type || "—"} />
      {Array.isArray(risk.threat_types) && risk.threat_types.length > 0 && (
        <Row k="threat types" v={risk.threat_types.join(", ")} />
      )}
      {Array.isArray(risk.reasons) && risk.reasons.length > 0 && (
        <>
          <h3>Why this verdict</h3>
          <ul className="plain">
            {risk.reasons.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

export function AuthCard({ authentication }) {
  if (!authentication) return null;
  return (
    <div className="card">
      <h2>Authentication</h2>
      <Row k="SPF" v={protocolValue(authentication.spf)} cls={protocolClass(authentication.spf)} />
      <Row k="DKIM" v={protocolValue(authentication.dkim)} cls={protocolClass(authentication.dkim)} />
      <Row k="DMARC" v={protocolValue(authentication.dmarc)} cls={protocolClass(authentication.dmarc)} />
      <p className="hint">A passing protocol is not a safety guarantee.</p>
    </div>
  );
}

export function ModelCard({ ai }) {
  if (!ai) return null;
  const fusion = ai.fusion || {};
  return (
    <div className="card">
      <h2>Model evidence</h2>
      <ModelLine label="NLP (DeBERTa)" model={ai.nlp} />
      <ModelLine label="Technical ML (RF)" model={ai.technical_ml} />
      <ModelLine label="Fusion" model={fusion} fusion />
      {fusion.model_status && (
        <Row k="model status" v={Object.entries(fusion.model_status).map(([k, v]) => `${k}: ${v}`).join(", ")} />
      )}
    </div>
  );
}

export function ForensicsCard({ forensics }) {
  if (!forensics || !Array.isArray(forensics.received_chain) || forensics.received_chain.length === 0) {
    return null;
  }
  return (
    <div className="card">
      <h2>Forensic path ({forensics.received_chain.length} hops)</h2>
      <table className="table slim">
        <thead>
          <tr>
            <th>#</th>
            <th>From</th>
            <th>IP class</th>
            <th>By</th>
          </tr>
        </thead>
        <tbody>
          {forensics.received_chain.map((hop, index) => (
            <tr key={index}>
              <td>{hop.position ?? index}</td>
              <td className="mono">{hop.from_host || hop.from_ip || "unknown"}</td>
              <td>{hop.ip_classification || "unclassified"}</td>
              <td className="mono">{hop.by_host || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function IndicatorList({ intelligence, indicators }) {
  const list = indicators || (intelligence && intelligence.indicators) || [];
  if (list.length === 0) return null;
  return (
    <div className="card">
      <h2>Indicators ({list.length})</h2>
      <ul className="plain">
        {list.slice(0, 40).map((indicator, index) => (
          <li key={index}>
            <span className="muted">{indicator.type}</span>{" "}
            <span className="mono">{indicator.value}</span>
          </li>
        ))}
      </ul>
      {list.length > 40 && <p className="hint">…and {list.length - 40} more</p>}
    </div>
  );
}

export function ExplanationList({ ai, explanations }) {
  const list = explanations || (ai && ai.explainability && ai.explainability.explanations) || [];
  if (list.length === 0) return null;
  return (
    <div className="card">
      <h2>Explanations</h2>
      {list.map((explanation, index) => (
        <div key={index} className="explanation">
          <span className={`impact impact-${explanation.impact || "low"}`}>
            {explanation.impact || "low"}
          </span>
          <span className="muted">{explanation.category}</span>
          <p>{explanation.reason}</p>
        </div>
      ))}
    </div>
  );
}

export function LimitationList({ risk, limitations }) {
  const list = limitations || (risk && risk.limitations) || [];
  if (list.length === 0) return null;
  return (
    <div className="card">
      <h2>Limitations</h2>
      <ul className="plain">
        {list.map((limitation, index) => (
          <li key={index} className="muted">
            {limitation}
          </li>
        ))}
      </ul>
    </div>
  );
}

function ModelLine({ label, model, fusion = false }) {
  if (!model) {
    return <Row k={label} v="missing" cls="muted" />;
  }
  const available = model.available !== false;
  if (!available) {
    return <Row k={label} v={`${model.status || "unavailable"}${model.reason ? ` (${model.reason})` : ""}`} cls="fail" />;
  }
  const probs = model.probabilities || {};
  const suspicious =
    typeof probs.suspicious === "number"
      ? probs.suspicious
      : model.probability_suspicious;
  const text =
    typeof suspicious === "number"
      ? `suspicious ${(suspicious * 100).toFixed(0)}%`
      : model.status || "available";
  return <Row k={label} v={text} />;
}

function protocolValue(protocol) {
  if (!protocol) return "n/a";
  if (protocol.result) return String(protocol.result);
  if (protocol.available) return String(protocol.available);
  return "unknown";
}

function protocolClass(protocol) {
  const value = protocol && protocol.result;
  if (value === "pass") return "pass";
  if (value === "fail" || value === "softfail") return "fail";
  return "muted";
}

function band(score) {
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function pct(value) {
  return typeof value === "number" ? `${(value * 100).toFixed(0)}%` : "—";
}

function Row({ k, v, cls }) {
  return (
    <div className="kv">
      <span className="k">{k}</span>
      <span className={`v ${cls || ""}`}>{v === null || v === undefined ? "—" : String(v)}</span>
    </div>
  );
}
