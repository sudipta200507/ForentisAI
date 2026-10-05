"""Evidence-section builders for reports (Phase 7).

Each builder turns one section of an analysis response into a plain,
JSON-serializable report section. Everything here is DERIVED evidence:
no raw email body, no raw addresses beyond what the evidence schema already
exposes, and no fabricated forensic conclusions.
"""

from __future__ import annotations

from typing import Any


def build_authentication_summary(authentication: Any) -> dict:
    """SPF/DKIM/DMARC outcomes plus overall availability."""

    protocols = {}
    overall_available = False
    for name in ("spf", "dkim", "dmarc"):
        protocol = getattr(authentication, name)
        available = protocol.available == "available"
        overall_available = overall_available or available
        protocols[name] = {
            "result": protocol.result,
            "available": protocol.available,
            "domain": protocol.domain,
        }

    dmarc = authentication.dmarc
    if dmarc.available == "available":
        overall = {
            "status": dmarc.result,
            "policy": dmarc.policy,
            "note": "Overall status reflects the DMARC evaluation when available.",
        }
    else:
        overall = {
            "status": "unknown",
            "policy": None,
            "note": "Authentication evaluation was unavailable; results are "
            "not 'pass' or 'fail' but 'not evaluated'.",
        }

    return {
        "protocols": protocols,
        "overall": overall,
        "availability": "available" if overall_available else "unavailable",
        "caveat": (
            "SPF/DKIM/DMARC PASS never means an email is safe: legitimate "
            "accounts can be compromised and phishing can be correctly "
            "authenticated."
        ),
    }


def build_forensic_summary(forensics: Any) -> dict:
    """Transport-path summary: received hops + earliest reliable candidate."""

    candidate = forensics.earliest_reliable_candidate
    return {
        "received_chain": [
            {
                "position": hop.position,
                "hop_from_origin": hop.hop_from_origin,
                "from_host": hop.from_host,
                "from_ip": hop.from_ip,
                "ip_classification": hop.ip_classification,
                "by_host": hop.by_host,
                "protocol": hop.protocol,
                "timestamp": hop.timestamp,
            }
            for hop in forensics.received_chain
        ],
        "earliest_reliable_candidate": (
            {
                "status": candidate.status,
                "label": candidate.label,
                "ip": candidate.ip,
                "hostname": candidate.hostname,
                "timestamp": candidate.timestamp,
                "receiving_server": candidate.receiving_server,
                "hop_from_origin": candidate.hop_from_origin,
                "confidence": candidate.confidence,
                "reasoning": list(candidate.reasoning),
                "provenance": dict(candidate.provenance),
            }
            if candidate is not None
            else None
        ),
        "indicators": [
            {"name": indicator.name, "detail": indicator.detail}
            for indicator in forensics.indicators
        ],
        "limitations": list(forensics.limitations),
        "caveat": (
            "Observed infrastructure is NOT automatically the attacker; the "
            "candidate is the earliest observed sending infrastructure only."
        ),
    }


def build_intelligence_summary(intelligence: Any) -> dict:
    """Indicator inventory plus provider availability, no verdicts."""

    def _ip_entry(entry: Any) -> dict:
        geo = entry.geolocation
        return {
            "value": entry.indicator.value,
            "classification": entry.classification,
            "is_global": entry.is_global,
            "geolocation": (
                {
                    "country": geo.country,
                    "region": geo.region,
                    "city": geo.city,
                    "asn": geo.asn,
                    "asn_organization": geo.asn_organization,
                    "available": geo.available,
                }
                if geo is not None
                else None
            ),
        }

    return {
        "counts": dict(intelligence.counts),
        "ips": [_ip_entry(entry) for entry in intelligence.ips],
        "domains": [
            {
                "domain": entry.normalized_domain,
                "dns_status": (entry.dns.status if entry.dns else None),
                "rdap_status": (entry.rdap.status if entry.rdap else None),
                "registrar": (entry.rdap.registrar if entry.rdap else None),
                "registration_date": (
                    entry.rdap.registration_date if entry.rdap else None
                ),
            }
            for entry in intelligence.domains
        ],
        "urls": [
            {
                "url": entry.indicator.value,
                "scheme": entry.scheme,
                "hostname": entry.hostname,
                "registered_domain": entry.registered_domain,
                "ip_in_host": entry.ip_in_host,
            }
            for entry in intelligence.urls
        ],
        "provenance": [
            {
                "type": indicator.type,
                "value": indicator.value,
                "source_kind": indicator.source.kind,
                "source_location": indicator.source.location,
            }
            for indicator in intelligence.indicators
        ],
        "caveat": (
            "Intelligence lookups describe infrastructure only; they never "
            "identify an attacker or confirm malicious intent."
        ),
    }


def build_ai_summary(ai: Any) -> dict:
    """Model evidence summary with explicit model status."""

    return {
        "status": ai.status,
        "model_status": dict(ai.fusion.model_status),
        "nlp": {
            "available": ai.nlp.available,
            "status": ai.nlp.status,
            "model_name": ai.nlp.model_name,
            "predicted_class": ai.nlp.predicted_class,
            "probabilities": dict(ai.nlp.probabilities),
            "confidence": ai.nlp.confidence,
        },
        "technical_ml": {
            "available": ai.technical_ml.available,
            "status": ai.technical_ml.status,
            "model_name": ai.technical_ml.model_name,
            "predicted_class": ai.technical_ml.predicted_class,
            "probabilities": dict(ai.technical_ml.probabilities),
            "confidence": ai.technical_ml.confidence,
            "threshold": ai.technical_ml.threshold,
            "artifact_format_version": ai.technical_ml.artifact_format_version,
            "feature_contract_version": ai.technical_ml.feature_contract_version,
            "dataset_name": ai.technical_ml.dataset_name,
        },
        "fusion": {
            "available": ai.fusion.available,
            "mode": ai.fusion.mode,
            "probability_suspicious": ai.fusion.probability_suspicious,
            "predicted_class": ai.fusion.predicted_class,
            "confidence": ai.fusion.confidence,
            "message": ai.fusion.message,
        },
        "explanations": [
            {
                "reason": entry.reason,
                "category": entry.category,
                "impact": entry.impact,
                "evidence": entry.evidence,
            }
            for entry in ai.explainability.explanations
        ],
        "feature_contributions": [
            {
                "feature": entry.feature,
                "value": entry.value,
                "contribution": entry.contribution,
                "direction": entry.direction,
            }
            for entry in ai.explainability.feature_contributions
        ],
        "shap_available": ai.explainability.shap_available,
        "caveat": (
            "Model outputs are probabilistic assessments on project-internal "
            "datasets; they are not validated real-world detection accuracy."
        ),
    }


__all__ = [
    "build_ai_summary",
    "build_authentication_summary",
    "build_forensic_summary",
    "build_intelligence_summary",
]
