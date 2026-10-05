import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { analyzeEmailFile, reportHtmlUrl } from "../services/api.js";
import { RiskCard, AuthCard, ModelCard, IndicatorList, ExplanationList, LimitationList, ForensicsCard } from "../components/AnalysisSections.jsx";

export default function Analysis() {
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const fileInput = useRef(null);

  async function onSubmit(event) {
    event.preventDefault();
    const file = fileInput.current?.files?.[0];
    if (!file) {
      setError("Choose a .eml file first.");
      return;
    }
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const data = await analyzeEmailFile(file);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h1>Analyze email</h1>
      <form className="upload-form" onSubmit={onSubmit}>
        <input ref={fileInput} type="file" accept=".eml,message/rfc822" />
        <button type="submit" disabled={busy}>
          {busy ? "Analyzing…" : "Analyze"}
        </button>
      </form>
      <p className="hint">
        Upload an original .eml file (max 25 MiB). The email is analyzed
        (extraction → SPF/DKIM/DMARC via Rspamd → DNS/RDAP intelligence → AI
        models → risk) and the derived record is persisted; raw content is
        never stored.
      </p>

      {error && <div className="callout error-text">{error}</div>}

      {result && (
        <>
          <div className="result-head">
            <div>
              Analysis <span className="mono">{result.analysis_id}</span>
            </div>
            <div className="result-actions">
              <Link className="btn" to={`/reports/${result.analysis_id}`} state={{ analysis: result }}>
                View report
              </Link>
              <a className="btn" href={reportHtmlUrl(result.analysis_id)} target="_blank" rel="noreferrer">
                Stored report (HTML)
              </a>
            </div>
          </div>
          <div className="grid">
            <RiskCard risk={result.risk} />
            <AuthCard authentication={result.authentication} />
            <ModelCard ai={result.ai} />
            <ForensicsCard forensics={result.forensics} />
            <IndicatorList intelligence={result.intelligence} />
            <ExplanationList ai={result.ai} />
            <LimitationList risk={result.risk} />
          </div>
        </>
      )}
    </section>
  );
}
