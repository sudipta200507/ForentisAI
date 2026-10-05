import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getAnalysis } from "../services/api.js";
import {
  AuthCard,
  ExplanationList,
  ForensicsCard,
  IndicatorList,
  LimitationList,
  RiskCard,
} from "../components/AnalysisSections.jsx";

/**
 * Analysis Detail: renders the PERSISTED derived record (GET /analyses/{id}).
 * The database stores no raw email content, so this page intentionally shows
 * the privacy-safe subset: risk, threat assessment, indicators, evidence,
 * and model status.
 */
export default function AnalysisDetail() {
  const { analysisId } = useParams();
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    getAnalysis(analysisId)
      .then((data) => {
        if (!cancelled) setDetail(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  if (error) {
    return (
      <section>
        <h1>Stored analysis</h1>
        <div className="empty error-text">{error}</div>
        <Link to="/">← Dashboard</Link>
      </section>
    );
  }
  if (!detail) return <div className="empty">Loading stored analysis…</div>;

  const assessment = detail.threat_assessment;

  return (
    <section>
      <div className="result-head">
        <h1>Stored analysis</h1>
        <Link className="btn" to={`/reports/${detail.analysis_id}`}>View report</Link>
      </div>
      <p className="hint mono">{detail.analysis_id}</p>

      <div className="grid">
        {assessment ? (
          <RiskCard
            stored
            risk={{
              risk_score: assessment.risk_score,
              verdict: assessment.verdict,
              severity: assessment.severity,
              confidence: assessment.confidence,
              primary_threat_type: assessment.primary_threat_type,
              threat_types: assessment.threat_types,
              reasons: assessment.reasons,
              limitations: assessment.limitations,
            }}
          />
        ) : (
          <div className="card">
            <h2>Stored risk assessment</h2>
            <Row k="risk score" v={detail.riskFallback ?? "not stored"} />
          </div>
        )}

        <div className="card">
          <h2>Email (derived metadata only)</h2>
          <Row k="filename" v={detail.filename} />
          <Row k="size" v={`${detail.email_size} bytes`} />
          <Row k="sha256" v={detail.email_sha256} mono />
          <Row k="subject length" v={detail.subject_length} />
          <Row k="sender domain" v={detail.sender_domain} />
          <Row k="reply-to domain" v={detail.reply_to_domain} />
          <Row k="return-path domain" v={detail.return_path_domain} />
          <Row k="message-id domain" v={detail.message_id_domain} />
          <Row k="url count" v={detail.url_count} />
          <Row k="attachments" v={detail.attachment_count} />
          <Row k="received hops" v={detail.evidence.filter((item) => item.kind === "forensic").length} />
          <Row k="auth available" v={detail.auth_available ? "yes" : "no"} />
          <Row k="date header missing" v={detail.date_missing ? "yes" : "no"} />
          <Row k="analyzed at" v={detail.created_at} />
          <Row k="engine version" v={detail.engine_version} />
        </div>

        <div className="card">
          <h2>Model status</h2>
          {Object.entries(detail.model_status).map(([key, value]) => (
            <Row key={key} k={key} v={value} />
          ))}
          {Object.keys(detail.model_status).length === 0 && <p className="muted">No model status stored.</p>}
        </div>

        <IndicatorList indicators={detail.indicators} />

        <ExplanationList
          explanations={detail.evidence
            .filter((item) => item.kind === "explanation")
            .map((item) => ({
              category: item.category,
              reason: item.detail,
              impact: (item.payload && item.payload.impact) || "low",
            }))}
        />

        <ForensicsCard
          forensics={{
            received_chain: detail.evidence
              .filter((item) => item.kind === "forensic")
              .map((item, index) => ({
                position: index,
                from_host: item.payload && item.payload.ip ? item.payload.ip : item.name,
                ip_classification: item.payload && item.payload.classification,
                by_host: null,
              })),
          }}
        />

        <LimitationList limitations={assessment ? assessment.limitations : []} />
      </div>

      <p className="hint">
        Note: the persisted record intentionally contains no raw email content,
        addresses, or subjects — only derived, privacy-safe data.
      </p>
    </section>
  );
}

function Row({ k, v, mono }) {
  return (
    <div className="kv">
      <span className="k">{k}</span>
      <span className={`v ${mono ? "mono" : ""}`}>{v === null || v === undefined ? "—" : String(v)}</span>
    </div>
  );
}
