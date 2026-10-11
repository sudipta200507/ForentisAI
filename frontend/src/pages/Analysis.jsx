import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { analyzeEmailFile, reportHtmlUrl } from "../services/api.js";
import {
  RiskCard,
  AuthCard,
  ModelCard,
  IndicatorList,
  ExplanationList,
  LimitationList,
  ForensicsCard,
} from "../components/AnalysisSections.jsx";

/**
 * Analyze email: upload one original .eml message, run the full pipeline
 * (extraction → SPF/DKIM/DMARC via Rspamd → DNS/RDAP intelligence → AI
 * models → risk) and render the real response. Nothing is mocked here.
 */
export default function Analysis() {
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const fileInput = useRef(null);

  function acceptFile(next) {
    if (!next) return;
    const isEml = /\.eml$/i.test(next.name) || next.type === "message/rfc822";
    if (!isEml) {
      setError("Only .eml (message/rfc822) files are supported.");
      return;
    }
    setError(null);
    setFile(next);
  }

  async function onSubmit(event) {
    event.preventDefault();
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

      <form onSubmit={onSubmit}>
        <div
          className={`dropzone ${dragging ? "dragging" : ""}`}
          role="button"
          tabIndex={0}
          aria-label="Choose or drop an .eml file"
          onClick={() => fileInput.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              fileInput.current?.click();
            }
          }}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragging(false);
            acceptFile(event.dataTransfer.files?.[0]);
          }}
        >
          <input
            ref={fileInput}
            type="file"
            accept=".eml,message/rfc822"
            hidden
            onChange={(event) => acceptFile(event.target.files?.[0])}
          />
          <p className="dropzone-title">
            {file ? file.name : "Drop a .eml file here, or click to browse"}
          </p>
          <p className="hint">
            {file
              ? `${(file.size / 1024).toFixed(1)} KiB — the original message is analyzed and never stored.`
              : "Original message file, up to 25 MiB. Raw content is never persisted — only derived, privacy-safe evidence."}
          </p>
        </div>

        <div className="upload-actions">
          <button type="submit" disabled={busy || !file}>
            {busy ? "Analyzing…" : "Analyze"}
          </button>
          {file && !busy && (
            <button type="button" className="btn" onClick={() => setFile(null)}>
              Clear
            </button>
          )}
          {busy && <span className="hint">Running the full analysis pipeline…</span>}
        </div>
      </form>

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
