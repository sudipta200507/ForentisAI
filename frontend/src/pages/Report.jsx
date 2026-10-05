import { useEffect, useState } from "react";
import { Link, useParams, useLocation } from "react-router-dom";
import { generateReport, getReportJson, reportHtmlUrl } from "../services/api.js";

/**
 * Report page (Phase 15): renders the forensic report for one analysis.
 * - If the user just ran an analysis, the full report payload is passed via
 *   router state and rendered directly.
 * - Otherwise the PARTIAL report reconstructed from the stored record is
 *   fetched (GET /reports/{id}?format=json) and its explicit
 *   not-retained notices are shown.
 */
export default function Report() {
  const { analysisId } = useParams();
  const location = useLocation();
  const passed = location.state && location.state.analysis;
  const [payload, setPayload] = useState(passed ? null : undefined);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (passed) return;
    let cancelled = false;
    getReportJson(analysisId)
      .then((data) => {
        if (!cancelled) setPayload(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [analysisId, passed]);

  async function downloadJson() {
    let data;
    if (passed) {
      // Generate the FULL report from the response the user already holds.
      data = await generateReport(passed, "json");
    } else {
      data = payload;
    }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `forentisai-report-${analysisId}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  if (error) {
    return (
      <section>
        <h1>Report</h1>
        <div className="empty error-text">{error}</div>
        <Link to="/">← Dashboard</Link>
      </section>
    );
  }
  if (payload === undefined) return <div className="empty">Loading report…</div>;

  const report = payload || {};
  const summary = report.executive_summary || {};
  const threat = report.threat || {};

  return (
    <section>
      <div className="result-head">
        <h1>Forensic report</h1>
        <div className="result-actions">
          <button className="btn" onClick={downloadJson}>Download JSON</button>
          <a className="btn" href={reportHtmlUrl(analysisId)} target="_blank" rel="noreferrer">
            Open HTML version
          </a>
        </div>
      </div>
      <p className="hint mono">{analysisId}</p>

      <div className="grid">
        <div className="card">
          <h2>Executive summary</h2>
          {Object.entries(summary).map(([key, value]) => (
            <div className="kv" key={key}>
              <span className="k">{key.replace(/_/g, " ")}</span>
              <span className="v">{formatValue(value)}</span>
            </div>
          ))}
        </div>

        <div className="card">
          <h2>Threat assessment</h2>
          {Object.entries(threat).map(([key, value]) => (
            <div className="kv" key={key}>
              <span className="k">{key.replace(/_/g, " ")}</span>
              <span className="v">{formatValue(value)}</span>
            </div>
          ))}
        </div>

        {Array.isArray(report.explanations) && report.explanations.length > 0 && (
          <div className="card">
            <h2>Explanations</h2>
            {report.explanations.map((explanation, index) => (
              <div key={index} className="explanation">
                <span className={`impact impact-${explanation.impact || "low"}`}>
                  {explanation.impact || "low"}
                </span>
                <span className="muted">{explanation.category}</span>
                <p>{explanation.reason || explanation}</p>
              </div>
            ))}
          </div>
        )}

        {Array.isArray(report.received_path) && report.received_path.length > 0 && (
          <div className="card">
            <h2>Received path</h2>
            <ul className="plain">
              {report.received_path.map((hop, index) => (
                <li key={index} className="mono">{typeof hop === "string" ? hop : JSON.stringify(hop)}</li>
              ))}
            </ul>
          </div>
        )}

        {Array.isArray(report.limitations) && report.limitations.length > 0 && (
          <div className="card">
            <h2>Limitations</h2>
            <ul className="plain">
              {report.limitations.map((limitation, index) => (
                <li key={index} className="muted">{limitation}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}

function formatValue(value) {
  if (value === null || value === undefined) return "—";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}
