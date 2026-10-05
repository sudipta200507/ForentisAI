"""Phase 7 report generation (JSON + HTML).

Design rules:

- Reports are DERIVED documents over one analysis response; they never
  introduce conclusions that the underlying evidence does not support.
- No raw email body is ever embedded; only evidence the analysis response
  already exposes (metadata, indicators, authentication outcomes, model
  outputs, risk assessment, forensic structure).
- HTML output is fully escaped, self-contained (no external assets, no
  scripts) and deterministic given the same payload.
- Reports generated from the PERSISTED record (privacy-first storage)
  explicitly state which sections are unavailable because the data was
  never retained.
"""

from __future__ import annotations

import html
import uuid
from datetime import datetime, timezone
from typing import Any

from app.core.constants import APP_VERSION
from app.reports.evidence import (
    build_ai_summary,
    build_authentication_summary,
    build_forensic_summary,
    build_intelligence_summary,
)
from app.schemas.report import (
    ExecutiveSummary,
    ReportMetadata,
    ReportPayload,
    SenderSummary,
)


def _report_id(analysis_id: str, generated_at: str) -> str:
    """Deterministic report id bound to one analysis at one generation time."""

    return str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"forentisai-report:{analysis_id}:{generated_at}")
    )


def _sender_summary(evidence: Any) -> SenderSummary:
    message = evidence.message
    sender = evidence.sender
    return SenderSummary(
        from_address=(sender.address if sender else None),
        from_display_name=(sender.display_name if sender else None),
        reply_to=[
            address.address
            for address in (message.reply_to or [])
            if address.address
        ],
        return_path=message.return_path,
        message_id=message.message_id,
        subject=message.subject,
        date=message.date,
        recipients_to=[
            address.address
            for address in (evidence.recipients.to or [])
            if address.address
        ],
        recipients_cc=[
            address.address
            for address in (evidence.recipients.cc or [])
            if address.address
        ],
        attachments=[
            {
                "filename": attachment.filename,
                "mime_type": attachment.mime_type,
                "size": attachment.size,
                "sha256": attachment.sha256,
            }
            for attachment in (evidence.attachments or [])
        ],
    )


def _executive_summary(response: Any) -> ExecutiveSummary:
    risk = response.risk
    ai = response.fusion_status if hasattr(response, "fusion_status") else None
    model_status = dict(response.ai.fusion.model_status or {})
    models_available = [
        name for name, status in model_status.items() if status == "available"
    ]
    auth_available = any(
        protocol.available == "available"
        for protocol in (
            response.authentication.spf,
            response.authentication.dkim,
            response.authentication.dmarc,
        )
    )
    severity_word = str(risk.severity).replace("_", " ")
    headline = (
        f"Risk score {risk.risk_score:g}/100 - verdict '{risk.verdict}' "
        f"with {severity_word} severity "
        f"(confidence {round(risk.confidence, 2)})."
    )
    if not models_available:
        headline += " No AI models were available for this analysis."
    return ExecutiveSummary(
        headline=headline,
        risk_score=risk.risk_score,
        verdict=str(risk.verdict),
        severity=str(risk.severity),
        confidence=risk.confidence,
        primary_threat_type=risk.primary_threat_type,
        threat_types=list(risk.threat_types),
        models_available=models_available,
        authentication_available=auth_available,
    )


def _evidence_summary(response: Any) -> dict:
    """Structural evidence inventory: files, URLs, defects, model outputs."""

    evidence = response.email
    return {
        "file": {
            "filename": evidence.file.filename,
            "size": evidence.file.size,
            "sha256": evidence.file.sha256,
        },
        "url_count": len(evidence.urls or []),
        "attachment_count": len(evidence.attachments or []),
        "parser_defects": [
            {"source": defect.source, "message": defect.message}
            for defect in (evidence.parser_defects or [])
        ],
        "risk_signals": [
            {
                "name": signal.name,
                "category": signal.category,
                "source": signal.source,
                "points": signal.points,
                "detail": signal.detail,
            }
            for signal in (response.risk.contributing_signals or [])
        ],
        "model_contributions": [
            contribution.model_dump()
            for contribution in (response.risk.model_contributions or [])
        ],
        "caveat": (
            "This inventory lists derived evidence only; the raw email body "
            "is intentionally not part of the report."
        ),
    }


def build_report_payload(
    response: Any,
    *,
    generated_at: str | None = None,
) -> ReportPayload:
    """Build the full Phase 7 report payload from one analysis response."""

    generated = generated_at or datetime.now(timezone.utc).isoformat()
    metadata = response.metadata
    risk = response.risk

    ai_summary = build_ai_summary(response.ai)
    threat = {
        "risk_score": risk.risk_score,
        "verdict": risk.verdict,
        "severity": risk.severity,
        "confidence": risk.confidence,
        "primary_threat_type": risk.primary_threat_type,
        "threat_types": list(risk.threat_types),
        "reasons": list(risk.reasons),
        "thresholds": dict(risk.thresholds),
        "caveat": (
            "The verdict is a policy threshold over documented evidence "
            "weights; it is not a legal or final security determination."
        ),
    }

    limitations = list(risk.limitations)
    limitations.extend(response.forensics.limitations)
    component_status = {
        "nlp": response.ai.nlp.status if response.ai.nlp is not None else None,
        "technical_ml": (
            response.ai.technical_ml.status
            if response.ai.technical_ml is not None
            else None
        ),
    }
    for name, status in component_status.items():
        if status != "available":
            limitations.append(f"AI model '{name}' status: {status or 'unavailable'}.")

    payload = ReportPayload(
        metadata=ReportMetadata(
            report_id=_report_id(response.analysis_id, generated),
            analysis_id=response.analysis_id,
            generated_at=generated,
            engine_version=(metadata.engine_version if metadata else APP_VERSION),
            model_versions=(
                dict(metadata.model_versions) if metadata else {}
            ),
            processing_time_ms=(
                metadata.processing_time_ms if metadata else 0.0
            ),
        ),
        executive_summary=_executive_summary(response),
        threat=threat,
        authentication=build_authentication_summary(response.authentication),
        sender=_sender_summary(response.email),
        received_path=build_forensic_summary(response.forensics),
        intelligence=build_intelligence_summary(response.intelligence),
        ai=ai_summary,
        explanations=list(ai_summary["explanations"]),
        evidence=_evidence_summary(response),
        limitations=limitations,
    )
    return payload


def generate_json_report(response: Any, **kwargs: Any) -> str:
    """Deterministic JSON report string for one analysis response."""

    payload = build_report_payload(response, **kwargs)
    return payload.model_dump_json(indent=2, by_alias=True)


def build_stored_report_payload(analysis: Any, *, generated_at: str | None = None) -> ReportPayload:
    """Build a PARTIAL report from the persisted (privacy-first) record.

    The database never stores raw email content, so this reconstruction
    contains the threat assessment, indicators, forensic rows, and model
    status - and explicitly lists what was not retained.
    """

    generated = generated_at or datetime.now(timezone.utc).isoformat()
    assessment = (
        analysis.threat_assessments[-1] if analysis.threat_assessments else None
    )
    model_versions = {}
    processing_time_ms = 0.0
    if analysis.metadata_json:
        model_versions = dict(analysis.metadata_json.get("model_versions") or {})
        processing_time_ms = float(
            analysis.metadata_json.get("processing_time_ms") or 0.0
        )

    if assessment is not None:
        threat = {
            "risk_score": assessment.risk_score,
            "verdict": assessment.verdict,
            "severity": assessment.severity,
            "confidence": assessment.confidence,
            "primary_threat_type": assessment.primary_threat_type,
            "threat_types": list(assessment.threat_types or []),
            "reasons": list(assessment.reasons or []),
            "contributing_signals": list(assessment.contributing_signals or []),
            "model_contributions": list(assessment.model_contributions or []),
            "thresholds": dict(assessment.thresholds or {}),
        }
        executive = ExecutiveSummary(
            headline=(
                f"Stored analysis: risk score {assessment.risk_score:g}/100, "
                f"verdict '{assessment.verdict}' ({assessment.severity})."
            ),
            risk_score=assessment.risk_score,
            verdict=str(assessment.verdict),
            severity=str(assessment.severity),
            confidence=assessment.confidence,
            primary_threat_type=assessment.primary_threat_type,
            threat_types=list(assessment.threat_types or []),
            models_available=[
                name
                for name, status in dict(analysis.model_status or {}).items()
                if status == "available"
            ],
            authentication_available=bool(analysis.auth_available),
        )
    else:
        threat = {"risk_score": None, "verdict": "unknown", "note": "No threat assessment was persisted."}
        executive = ExecutiveSummary(
            headline="Stored analysis without a persisted threat assessment.",
            risk_score=float(analysis.risk_score or 0.0),
            verdict=str(analysis.verdict or "unknown"),
            severity=str(analysis.severity or "info"),
            confidence=float(analysis.confidence or 0.0),
            models_available=[
                name
                for name, status in dict(analysis.model_status or {}).items()
                if status == "available"
            ],
            authentication_available=bool(analysis.auth_available),
        )

    explanations = [
        {
            "reason": row.detail,
            "category": row.category,
            "impact": (row.payload or {}).get("impact"),
            "evidence": (row.payload or {}).get("evidence"),
        }
        for row in analysis.evidence
        if row.kind == "explanation"
    ]

    payload = ReportPayload(
        metadata=ReportMetadata(
            report_id=_report_id(analysis.analysis_id, generated),
            analysis_id=analysis.analysis_id,
            generated_at=generated,
            engine_version=analysis.engine_version,
            model_versions=model_versions,
            processing_time_ms=processing_time_ms,
        ),
        executive_summary=executive,
        threat=threat,
        authentication={
            "availability": "available" if analysis.auth_available else "unavailable",
            "note": (
                "Per-protocol outcomes are not reconstructed from storage; "
                "only overall availability was retained."
            ),
        },
        sender=SenderSummary(),
        received_path={
            "received_chain": [
                {
                    "position": index,
                    "detail": row.detail,
                    "payload": dict(row.payload or {}),
                }
                for index, row in enumerate(
                    row for row in analysis.evidence if row.kind == "forensic"
                )
            ],
            "note": "Received-chain structure as persisted (derived rows only).",
        },
        intelligence={
            "indicators": [
                {
                    "type": indicator.type,
                    "value": indicator.value,
                    "source_kind": indicator.source_kind,
                    "source_location": indicator.source_location,
                }
                for indicator in analysis.indicators
            ],
            "note": "Stored normalized indicators; enrichment payloads are not retained.",
        },
        ai={
            "model_status": dict(analysis.model_status or {}),
            "note": "Full AI outputs are not reconstructed from storage.",
        },
        explanations=explanations,
        evidence={
            "email_sha256": analysis.email_sha256,
            "email_size": analysis.email_size,
            "filename": analysis.filename,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
            "caveat": "Reconstructed from privacy-first persisted derived data.",
        },
        limitations=[
            *(list(analysis.limitations or [])),
            "This report was reconstructed from the persisted derived record; "
            "raw email content, full headers, and enrichment payloads are "
            "intentionally not stored and therefore not present.",
        ],
    )
    return payload


# ---------------------------------------------------------------------------
# HTML rendering (deterministic, fully escaped, self-contained)
# ---------------------------------------------------------------------------

_STYLE = """<style>
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: "Segoe UI", Arial, sans-serif; margin: 0; background: #f3f5f8; color: #1c2733; }
.wrap { max-width: 960px; margin: 0 auto; padding: 24px; }
header { background: #102a43; color: #fff; padding: 20px 24px; }
header h1 { margin: 0 0 4px 0; font-size: 20px; }
header .sub { color: #b7c6d3; font-size: 12px; }
section { background: #fff; border: 1px solid #d9e2ec; border-radius: 6px; margin: 16px 0; padding: 16px 20px; }
h2 { font-size: 15px; text-transform: uppercase; letter-spacing: .06em; color: #334e68; margin: 0 0 10px 0; border-bottom: 2px solid #f0f4f8; padding-bottom: 6px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #f0f4f8; vertical-align: top; }
th { color: #627d98; font-weight: 600; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 12px; font-weight: 600; }
.b-benign { background: #dff3e9; color: #16794c; }
.b-suspicious { background: #fceecd; color: #a3620a; }
.b-malicious { background: #fadcdb; color: #b3261e; }
.b-inconclusive, .b-unknown { background: #e2e8f0; color: #486581; }
.sev-info, .sev-low { background: #e2e8f0; color: #486581; }
.sev-medium { background: #fceecd; color: #a3620a; }
.sev-high { background: #f9d8d6; color: #b3261e; }
.sev-critical { background: #b3261e; color: #fff; }
.kv { display: grid; grid-template-columns: 220px 1fr; gap: 4px 12px; font-size: 13px; }
.kv div:nth-child(odd) { color: #627d98; }
ul { margin: 4px 0; padding-left: 20px; font-size: 13px; }
li { margin: 3px 0; }
.muted { color: #627d98; font-size: 12px; }
.score { font-size: 26px; font-weight: 700; }
</style>"""


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _render_table(rows: list[dict], columns: list[tuple[str, str]]) -> str:
    if not rows:
        return '<p class="muted">No data.</p>'
    head = "".join(f"<th>{_esc(label)}</th>" for label, _key in columns)
    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{_esc(row.get(key))}</td>" for _label, key in columns)
        body_rows.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"


def _verdict_badge(verdict: str) -> str:
    return f'<span class="badge b-{_esc(verdict)}">{_esc(verdict)}</span>'


def _severity_badge(severity: str) -> str:
    return f'<span class="badge sev-{_esc(severity)}">{_esc(severity)}</span>'


def render_html_report(payload: ReportPayload) -> str:
    """Deterministic, escaped HTML rendering of one report payload."""

    meta = payload.metadata
    summary = payload.executive_summary
    threat = payload.threat

    parts: list[str] = []
    parts.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
    parts.append("<title>ForentisAI Analysis Report</title>")
    parts.append(_STYLE)
    parts.append("</head><body>")

    parts.append("<header><h1>ForentisAI — Email Threat Analysis Report</h1>")
    parts.append(
        f"<div class='sub'>Report {_esc(meta.report_id)} · Analysis {_esc(meta.analysis_id)} · "
        f"Generated {_esc(meta.generated_at)} · Engine {_esc(meta.engine_version)}</div></header>"
    )
    parts.append("<div class='wrap'>")

    # Executive summary
    parts.append("<section><h2>Executive Summary</h2>")
    parts.append(f"<p>{_esc(summary.headline)}</p>")
    parts.append(
        f"<div class='kv'>"
        f"<div>Verdict</div><div>{_verdict_badge(summary.verdict)}</div>"
        f"<div>Severity</div><div>{_severity_badge(summary.severity)}</div>"
        f"<div>Risk score</div><div><span class='score'>{summary.risk_score:g}</span>/100</div>"
        f"<div>Confidence</div><div>{_esc(round(summary.confidence, 2))}</div>"
        f"<div>Primary threat type</div><div>{_esc(summary.primary_threat_type or '—')}</div>"
        f"<div>Models available</div><div>{_esc(', '.join(summary.models_available) or 'none')}</div>"
        f"<div>Authentication available</div><div>{_esc(summary.authentication_available)}</div>"
        f"</div>"
    )
    if summary.threat_types:
        parts.append("<ul>" + "".join(f"<li>{_esc(t)}</li>" for t in summary.threat_types) + "</ul>")
    parts.append("</section>")

    # Threat detail
    parts.append("<section><h2>Threat Assessment</h2>")
    parts.append(_render_table(
        [{"name": k, "value": v} for k, v in threat.items() if k not in {"caveat"} and not isinstance(v, (list, dict))],
        [("Signal", "name"), ("Value", "value")],
    ))
    reasons = threat.get("reasons") or []
    if reasons:
        parts.append("<h2>Reasons</h2><ul>" + "".join(f"<li>{_esc(r)}</li>" for r in reasons) + "</ul>")
    signals = threat.get("contributing_signals") or []
    if signals:
        parts.append("<h2>Contributing Signals</h2>")
        parts.append(_render_table(
            list(signals),
            [("Name", "name"), ("Category", "category"), ("Source", "source"), ("Points", "points"), ("Detail", "detail")],
        ))
    if threat.get("caveat"):
        parts.append(f"<p class='muted'>{_esc(threat['caveat'])}</p>")
    parts.append("</section>")

    # Authentication
    auth = payload.authentication
    parts.append("<section><h2>Authentication</h2>")
    protocols = auth.get("protocols") or {}
    parts.append(_render_table(
        [
            {"protocol": name, "result": proto.get("result"), "available": proto.get("available"), "domain": proto.get("domain")}
            for name, proto in protocols.items()
        ],
        [("Protocol", "protocol"), ("Result", "result"), ("Available", "available"), ("Domain", "domain")],
    ))
    overall = auth.get("overall") or {}
    parts.append(
        f"<p class='muted'>Overall: {_esc(overall.get('status'))} · {_esc(auth.get('availability'))}</p>"
    )
    for note_key in ("note", "caveat"):
        if overall.get(note_key):
            parts.append(f"<p class='muted'>{_esc(overall[note_key])}</p>")
        if auth.get(note_key):
            parts.append(f"<p class='muted'>{_esc(auth[note_key])}</p>")
    parts.append("</section>")

    # Sender
    sender = payload.sender
    parts.append("<section><h2>Sender & Message Identity</h2><div class='kv'>")
    for label, value in (
        ("From", sender.from_address),
        ("Display name", sender.from_display_name),
        ("Reply-To", ", ".join(sender.reply_to) or None),
        ("Return-Path", sender.return_path),
        ("Message-ID", sender.message_id),
        ("Subject", sender.subject),
        ("Date", sender.date),
        ("To", ", ".join(sender.recipients_to) or None),
        ("Cc", ", ".join(sender.recipients_cc) or None),
    ):
        parts.append(f"<div>{_esc(label)}</div><div>{_esc(value or '—')}</div>")
    parts.append("</div>")
    if sender.attachments:
        parts.append("<h2>Attachments</h2>")
        parts.append(_render_table(
            sender.attachments,
            [("Filename", "filename"), ("MIME type", "mime_type"), ("Size", "size"), ("SHA-256", "sha256")],
        ))
    parts.append("</section>")

    # Received path / forensics
    fp = payload.received_path
    parts.append("<section><h2>Received Path (Forensic Transport Evidence)</h2>")
    parts.append(_render_table(
        fp.get("received_chain") or [],
        [("Hop", "position"), ("From host", "from_host"), ("From IP", "from_ip"),
         ("Class", "ip_classification"), ("By", "by_host"), ("Timestamp", "timestamp")],
    ))
    candidate = fp.get("earliest_reliable_candidate")
    if candidate:
        parts.append(f"<h2>Earliest Reliable Candidate</h2>")
        parts.append(
            f"<div class='kv'><div>Status</div><div>{_esc(candidate.get('status'))}</div>"
            f"<div>IP</div><div>{_esc(candidate.get('ip'))}</div>"
            f"<div>Hostname</div><div>{_esc(candidate.get('hostname'))}</div>"
            f"<div>Timestamp</div><div>{_esc(candidate.get('timestamp'))}</div>"
            f"<div>Confidence</div><div>{_esc(candidate.get('confidence'))}</div></div>"
        )
        for reason in (candidate.get("reasoning") or []):
            parts.append(f"<ul><li>{_esc(reason)}</li></ul>")
    for indicator in (fp.get("indicators") or []):
        parts.append(f"<p class='muted'>{_esc(indicator.get('name'))}: {_esc(indicator.get('detail'))}</p>")
    for limitation in (fp.get("limitations") or []):
        parts.append(f"<p class='muted'>Limitation: {_esc(limitation)}</p>")
    parts.append(f"<p class='muted'>{_esc(fp.get('caveat'))}</p>")
    parts.append("</section>")

    # Intelligence
    intel = payload.intelligence
    parts.append("<section><h2>Infrastructure Intelligence</h2>")
    counts = intel.get("counts") or {}
    if counts:
        parts.append("<p class='muted'>Counts: " + _esc(", ".join(f"{k}={v}" for k, v in counts.items())) + "</p>")
    parts.append("<h2>IPs</h2>")
    parts.append(_render_table(
        [
            {**entry, "country": (entry.get("geolocation") or {}).get("country"), "asn": (entry.get("geolocation") or {}).get("asn")}
            for entry in (intel.get("ips") or [])
        ],
        [("IP", "value"), ("Classification", "classification"), ("Global", "is_global"), ("Country", "country"), ("ASN", "asn")],
    ))
    parts.append("<h2>Domains</h2>")
    parts.append(_render_table(
        intel.get("domains") or [],
        [("Domain", "domain"), ("DNS status", "dns_status"), ("RDAP status", "rdap_status"), ("Registrar", "registrar"), ("Registered", "registration_date")],
    ))
    parts.append("<h2>URLs</h2>")
    parts.append(_render_table(
        intel.get("urls") or [],
        [("URL", "url"), ("Scheme", "scheme"), ("Host", "hostname"), ("Registered domain", "registered_domain")],
    ))
    parts.append(f"<p class='muted'>{_esc(intel.get('caveat'))}</p>")
    parts.append("</section>")

    # AI analysis
    ai = payload.ai
    parts.append("<section><h2>AI Model Analysis</h2>")
    parts.append(_render_table(
        [{"model": name, "status": status} for name, status in (ai.get("model_status") or {}).items()],
        [("Model", "model"), ("Status", "status")],
    ))
    for component in ("nlp", "technical_ml", "fusion"):
        comp = ai.get(component) or {}
        if not isinstance(comp, dict) or not comp:
            continue
        parts.append(f"<h2>{_esc(component).title()}</h2>")
        parts.append(_render_table(
            [{"field": k, "value": v} for k, v in comp.items() if not isinstance(v, (list, dict))],
            [("Field", "field"), ("Value", "value")],
        ))
    if ai.get("shap_available") is not None:
        parts.append(f"<p class='muted'>SHAP available: {_esc(ai.get('shap_available'))}</p>")
    parts.append(f"<p class='muted'>{_esc(ai.get('caveat'))}</p>")
    parts.append("</section>")

    # Explanations
    parts.append("<section><h2>Explanations (XAI)</h2>")
    if payload.explanations:
        parts.append(_render_table(
            payload.explanations,
            [("Reason", "reason"), ("Category", "category"), ("Impact", "impact"), ("Evidence", "evidence")],
        ))
    else:
        parts.append("<p class='muted'>No explanations were produced for this analysis.</p>")
    parts.append("</section>")

    # Evidence inventory
    ev = payload.evidence
    parts.append("<section><h2>Evidence Inventory</h2><div class='kv'>")
    file_info = ev.get("file") or {}
    parts.append(
        f"<div>File</div><div>{_esc(file_info.get('filename'))} ({_esc(file_info.get('size'))} bytes)</div>"
        f"<div>SHA-256</div><div>{_esc(file_info.get('sha256'))}</div>"
        f"<div>URL count</div><div>{_esc(ev.get('url_count'))}</div>"
        f"<div>Attachment count</div><div>{_esc(ev.get('attachment_count'))}</div>"
    )
    parts.append("</div>")
    for defect in (ev.get("parser_defects") or []):
        parts.append(f"<p class='muted'>Parser defect ({_esc(defect.get('source'))}): {_esc(defect.get('message'))}</p>")
    parts.append(f"<p class='muted'>{_esc(ev.get('caveat'))}</p>")
    parts.append("</section>")

    # Limitations
    parts.append("<section><h2>Limitations</h2>")
    if payload.limitations:
        parts.append("<ul>" + "".join(f"<li>{_esc(l)}</li>" for l in payload.limitations) + "</ul>")
    else:
        parts.append("<p class='muted'>None recorded.</p>")
    parts.append("</section>")

    parts.append("</div></body></html>")
    return "".join(parts)


def generate_html_report(response: Any, **kwargs: Any) -> str:
    """Deterministic HTML report string for one analysis response."""

    payload = build_report_payload(response, **kwargs)
    return render_html_report(payload)


__all__ = [
    "build_report_payload",
    "build_stored_report_payload",
    "generate_html_report",
    "generate_json_report",
    "render_html_report",
]