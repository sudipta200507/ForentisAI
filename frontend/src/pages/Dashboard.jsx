import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getHealth, listAnalyses } from "../services/api.js";

/**
 * Dashboard: aggregate view over the PERSISTED derived records only.
 * The database intentionally stores no raw email content, so this page
 * shows counts, verdict distribution and model/service status.
 */
export default function Dashboard() {
  const [rows, setRows] = useState(null);
  const [error, setError] = useState(null);
  const [health, setHealth] = useState(null);

  useEffect(() => {
    let cancelled = false;
    listAnalyses(50)
      .then((data) => {
        if (!cancelled) setRows(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      });
    getHealth()
      .then((data) => {
        if (!cancelled) setHealth(data);
      })
      .catch(() => {
        /* health errors surface as degraded status, not a page error */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) return <div className="empty error-text">{error}</div>;
  if (!rows) return <div className="empty">Loading stored analyses…</div>;

  const stats = summarize(rows);

  return (
    <section>
      <h1>Dashboard</h1>

      <div className="stat-grid">
        <Stat label="Stored analyses" value={stats.total} />
        <Stat label="Malicious" value={stats.malicious} tone="malicious" />
        <Stat label="Suspicious" value={stats.suspicious} tone="suspicious" />
        <Stat label="Benign" value={stats.benign} tone="benign" />
        <Stat label="Inconclusive" value={stats.inconclusive} tone="muted" />
      </div>

      <div className={`health-line ${health && health.api ? "" : "muted"}`}>
        <span
          className={`health-dot health-${health && health.api ? "ok" : "down"}`}
          aria-hidden="true"
        />
        {health && health.api
          ? `Backend online${
              health.rspamd === true
                ? " · Rspamd available"
                : health.rspamd === false
                  ? " · Rspamd unavailable"
                  : ""
            }`
          : "Backend unreachable — is the API running?"}
      </div>

      <h2 className="table-title">Recent analyses</h2>
      {rows.length === 0 ? (
        <div className="empty">
          <p>
            <strong>No stored analyses yet.</strong>
          </p>
          <p>
            Upload a <span className="mono">.eml</span> file on the{" "}
            <Link to="/analysis">Analyze email</Link> page to run the full
            pipeline: extraction, SPF/DKIM/DMARC authentication, DNS/RDAP
            intelligence, AI models and risk scoring. Sample messages live in{" "}
            <span className="mono">samples/</span> in the repository.
          </p>
        </div>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Date</th>
              <th>File</th>
              <th>Sender domain</th>
              <th>Risk</th>
              <th>Verdict</th>
              <th>Severity</th>
              <th>Confidence</th>
              <th>URLs</th>
              <th>Report</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.analysis_id}>
                <td>{formatDate(row.created_at)}</td>
                <td className="mono">{row.filename}</td>
                <td>{row.sender_domain || "—"}</td>
                <td>
                  <span className={`score score-${verdictBand(row.risk_score)}`}>
                    {row.risk_score.toFixed(0)}
                  </span>
                </td>
                <td>
                  <span className={`chip chip-${row.verdict}`}>{row.verdict}</span>
                </td>
                <td>{row.severity}</td>
                <td>{(row.confidence * 100).toFixed(0)}%</td>
                <td>{row.url_count}</td>
                <td>
                  <Link to={`/analyses/${row.analysis_id}`}>detail</Link>
                  {" · "}
                  <Link to={`/reports/${row.analysisId ?? row.analysis_id}`}>report</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function summarize(rows) {
  const counts = { malicious: 0, suspicious: 0, benign: 0, inconclusive: 0 };
  for (const row of rows) {
    if (row.verdict in counts) counts[row.verdict] += 1;
  }
  return { total: rows.length, ...counts };
}

/** Verdict bands mirror the documented risk-engine thresholds (45/75). */
function verdictBand(score) {
  if (score >= 75) return "high";
  if (score >= 45) return "medium";
  return "low";
}

function Stat({ label, value, tone }) {
  return (
    <div className="stat">
      <span className={`stat-value ${tone ? `score-${tone}` : ""}`}>{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}

function formatDate(value) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch (_) {
    return value;
  }
}
