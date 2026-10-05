import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listAnalyses } from "../services/api.js";

export default function Dashboard() {
  const [rows, setRows] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    listAnalyses(50)
      .then((data) => {
        if (!cancelled) setRows(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) return <div className="empty error-text">{error}</div>;
  if (!rows) return <div className="empty">Loading stored analyses…</div>;

  return (
    <section>
      <h1>Recent analyses</h1>
      {rows.length === 0 ? (
        <div className="empty">
          No stored analyses yet. Upload a .eml on the <Link to="/analysis">Analyze
          email</Link> page (persistence enabled) and it will appear here.
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
                  <span className={`score score-${band(row.risk_score)}`}>
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

function band(score) {
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function formatDate(value) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch (_) {
    return value;
  }
}
