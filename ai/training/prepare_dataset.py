#!/usr/bin/env python
"""Technical ML Phase 1 — raw-email dataset preparation pipeline.

Builds a labeled, split, leakage-safe JSONL dataset of 30 EML-derived
features from a directory of raw .eml files::

    <dataset_root>/
    ├── benign/      → label "benign"
    └── malicious/   → label "suspicious"  (never "malicious")

HONESTY CONTRACT
================
- This script derives features ONLY from the original .eml bytes. It never
  performs DNS, RDAP, GeoIP, or Rspamd lookups and never opens URLs. The
  Step 4 intelligence layer is invoked with ``perform_dns=False`` and
  ``perform_rdap=False`` and no GeoIP database, so ``intelligence.*``
  features come exclusively from the local Received-chain IP
  classification — exactly the two features this phase trains on.
- The folder name ``malicious`` is mapped to the backend label
  ``suspicious`` (model evidence class). The raw folder name never becomes
  a model label.
- Malformed emails are recorded as failures in the quality report; they are
  never silently converted into valid training rows.
- The runtime 48-feature evidence schema is NOT modified. This pipeline
  projects the 30 genuinely EML-derived features for training; the other
  runtime evidence features simply are not training inputs in this phase.

Outputs (written to ``--output-dir``):

- ``dataset_train.jsonl`` / ``dataset_validation.jsonl`` / ``dataset_test.jsonl``
- ``dataset_all.jsonl`` (every accepted row, with its split recorded)
- ``dataset_statistics.csv`` (split × label counts, percentages, parser status)
- ``dataset_quality_report.json`` (counts, leakage checks, overall PASS/FAIL)
- ``dataset_manifest.yaml`` (provenance, feature contract, seed, file hashes)
- ``README_DATASET.txt`` (usage and honesty notes)

Usage (from the ``backend`` directory, venv active):

    python ../ai/training/prepare_dataset.py \
        --input-dir ../datasets/raw/incoming \
        --output-dir ../ai/datasets/processed/raw_eml_v1
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Path bootstrap: allow running as a script from the repository.
# ---------------------------------------------------------------------------
import sys
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

import argparse
import csv
import hashlib
import json
import random
import re
import statistics
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.extractor.email_parser import extract_email_from_bytes
from app.features.feature_fusion import build_feature_vector
from app.intelligence.orchestrator import (
    IntelligenceSettings,
    build_intelligence_evidence,
)
from app.schemas.intelligence import IntelligenceEvidence

# ---------------------------------------------------------------------------
# Constants: the Phase 1 feature contract.
# ---------------------------------------------------------------------------

PREPARATION_VERSION = "1.0"
NORMALIZATION_VERSION = "structural_sig_v1"
SUPPORTED_EXTENSIONS = frozenset({".eml"})

LABEL_BY_SOURCE_CLASS = {"benign": "benign", "malicious": "suspicious"}

TRAIN_RATIO = 0.70
VALIDATION_RATIO = 0.15
# TEST_RATIO = the remainder (0.15), asserted rather than hard-coded.

TEXT_FEATURES: tuple[str, ...] = (
    "text.subject_length",
    "text.subject_exclamation_count",
    "text.subject_urgency_signal",
    "text.subject_money_signal",
    "text.body_plain_length",
    "text.body_html_present",
    "text.body_html_length",
    "text.credential_signal_count",
    "text.payment_signal_count",
    "text.urgency_signal_count",
)

HEADER_FEATURES: tuple[str, ...] = (
    "header.received_hop_count",
    "header.parser_defect_count",
    "header.sender_reply_to_domain_mismatch",
    "header.return_path_sender_mismatch",
    "header.message_id_domain_mismatch",
    "header.message_id_missing",
    "header.date_missing",
    "header.reply_to_present",
    "header.user_agent_present",
    "header.mime_multipart",
)

URL_FEATURES: tuple[str, ...] = (
    "url.url_count",
    "url.unique_url_host_count",
    "url.https_ratio",
    "url.ip_url_count",
    "url.suspicious_port_count",
    "url.max_url_path_length",
    "url.unique_url_registered_domain_count",
    "url.url_registered_domain_mismatch_count",
)

RECEIVED_IP_FEATURES: tuple[str, ...] = (
    "intelligence.public_ip_count",
    "intelligence.non_public_ip_count",
)

TRAINING_FEATURES: tuple[str, ...] = (
    TEXT_FEATURES + HEADER_FEATURES + URL_FEATURES + RECEIVED_IP_FEATURES
)
assert len(TRAINING_FEATURES) == 30, "Phase 1 contract is exactly 30 features"

_BINARY_FEATURES = frozenset(
    {
        "text.subject_urgency_signal",
        "text.subject_money_signal",
        "text.body_html_present",
        "header.sender_reply_to_domain_mismatch",
        "header.return_path_sender_mismatch",
        "header.message_id_domain_mismatch",
        "header.message_id_missing",
        "header.date_missing",
        "header.reply_to_present",
        "header.user_agent_present",
        "header.mime_multipart",
    }
)
_INTEGER_FEATURES = frozenset(
    {
        "text.subject_length",
        "text.subject_exclamation_count",
        "text.body_plain_length",
        "text.body_html_length",
        "text.credential_signal_count",
        "text.payment_signal_count",
        "text.urgency_signal_count",
        "header.received_hop_count",
        "header.parser_defect_count",
        "url.url_count",
        "url.unique_url_host_count",
        "url.ip_url_count",
        "url.suspicious_port_count",
        "url.max_url_path_length",
        "url.unique_url_registered_domain_count",
        "url.url_registered_domain_mismatch_count",
        "intelligence.public_ip_count",
        "intelligence.non_public_ip_count",
    }
)
_RATIO_FEATURES = frozenset({"url.https_ratio"})

# Offline Step 4: no DNS, no RDAP, no GeoIP. Received-chain IPs are still
# parsed and classified locally, which is all this phase trains on.
_OFFLINE_INTELLIGENCE_SETTINGS = IntelligenceSettings(
    perform_dns=False,
    perform_rdap=False,
    geoip=None,
)

# ---------------------------------------------------------------------------
# Structural signature (leakage prevention).
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_DATE_PATTERN = re.compile(
    r"\b\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}\b"  # 2024-05-01, 01/05/2024, 1.5.2024
    r"|\b\d{1,2}:\d{2}(:\d{2})?\b"  # 10:30, 10:30:45
    r"|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2}\b",
    re.IGNORECASE,
)
_NUMBER_PATTERN = re.compile(r"\d+")
_WHITESPACE_PATTERN = re.compile(r"\s+")


def structural_signature(subject: str | None, plain_text: str | None) -> str:
    """Conservative normalized signature of subject + body for leakage checks.

    Normalization (documented, deliberately conservative — content words are
    preserved so genuinely different emails never collide):

    1. concatenate subject and plain body;
    2. casefold;
    3. replace URLs with ``<url>``;
    4. replace email addresses with ``<addr>``;
    5. replace obvious dates/times with ``<date>``;
    6. replace remaining digit runs with ``<num>`` (order numbers, amounts, IDs);
    7. collapse all whitespace runs to a single space.

    What is NOT normalized: wording, phrasing, keyword spelling, punctuation.
    Two emails share a signature only when they are structurally the same
    message (template reuse with different IDs/links), which is exactly the
    near-duplicate case that must not cross splits.
    """

    combined = f"{(subject or '').casefold()}\n{(plain_text or '').casefold()}"
    combined = _URL_PATTERN.sub("<url>", combined)
    combined = _EMAIL_PATTERN.sub("<addr>", combined)
    combined = _DATE_PATTERN.sub("<date>", combined)
    combined = _NUMBER_PATTERN.sub("<num>", combined)
    return _WHITESPACE_PATTERN.sub(" ", combined).strip()


# ---------------------------------------------------------------------------
# Discovery, parsing, feature projection.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class DatasetRow:
    id: str
    source_file: str
    source_class: str
    label: str
    sha256: str
    features: dict[str, float]
    metadata: dict
    signature: str = ""
    split: str = ""


@dataclass(slots=True)
class ParseFailure:
    relative_path: str
    source_class: str
    error: str


@dataclass(slots=True)
class UnsupportedFile:
    relative_path: str
    reason: str


@dataclass(slots=True)
class DiscoveryResult:
    files_by_class: dict[str, list[Path]] = field(default_factory=dict)
    unsupported: list[UnsupportedFile] = field(default_factory=list)

    @property
    def total_files(self) -> int:
        return sum(len(files) for files in self.files_by_class.values()) + len(
            self.unsupported
        )


def discover_emails(input_dir: Path) -> DiscoveryResult:
    """Recursively discover supported email files under benign/ and malicious/.

    Only ``benign/`` and ``malicious/`` class folders are recognized. Files
    with unsupported extensions (or files outside both folders) are reported
    as unsupported — never parsed as emails.
    """

    result = DiscoveryResult()
    if not input_dir.is_dir():
        raise SystemExit(f"Input directory does not exist: {input_dir}")

    for source_class in ("benign", "malicious"):
        class_dir = input_dir / source_class
        files: list[Path] = []
        if class_dir.is_dir():
            for path in sorted(class_dir.rglob("*")):
                if not path.is_file():
                    continue
                if path.suffix.casefold() in SUPPORTED_EXTENSIONS:
                    files.append(path)
                else:
                    result.unsupported.append(
                        UnsupportedFile(
                            relative_path=_relative(path, input_dir),
                            reason=f"unsupported extension {path.suffix!r}",
                        )
                    )
        result.files_by_class[source_class] = files
    return result


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def parse_email_row(
    path: Path,
    source_class: str,
    input_dir: Path,
    source_dataset: str,
    max_size_bytes: int,
) -> DatasetRow | ParseFailure:
    """Parse one EML and build its dataset row + structural signature.

    Uses the Step 1 extractor (``extract_email_from_bytes``), the production
    feature extractors, and the Step 4 orchestrator in its offline
    configuration. Returns a :class:`ParseFailure` for any email that cannot
    be parsed or projected — never a partially valid row.
    """

    raw_bytes = path.read_bytes()
    digest = hashlib.sha256(raw_bytes).hexdigest()
    relative_path = _relative(path, input_dir)

    try:
        evidence = extract_email_from_bytes(
            raw_bytes,
            filename=path.name,
            max_size_bytes=max_size_bytes,
        )
    except Exception as error:  # noqa: BLE001 - recorded, never crashes the run
        return ParseFailure(
            relative_path=relative_path,
            source_class=source_class,
            error=f"parse_failed: {type(error).__name__}: {error}",
        )

    # Offline Step 4: Received-IP classification only (no DNS/RDAP/GeoIP).
    # Total failure degrades to empty IntelligenceEvidence, exactly like the
    # API route does; the projection then reports neutral IP counts.
    try:
        intelligence = build_intelligence_evidence(
            evidence, settings=_OFFLINE_INTELLIGENCE_SETTINGS
        )
    except Exception:  # noqa: BLE001 - isolation by design
        intelligence = IntelligenceEvidence()

    # Same call shape as the production orchestrator (url intelligence from
    # Step 4 decomposition when available) — identical feature semantics.
    vector = build_feature_vector(
        evidence,
        None,
        intelligence,
        url_intelligence=list(intelligence.urls) if intelligence is not None else None,
    )
    projected = project_training_features(vector)

    signature = structural_signature(
        evidence.message.subject, evidence.body.plain_text
    )

    row = DatasetRow(
        id=f"{digest[:16]}",
        source_file=path.name,
        source_class=source_class,
        label=LABEL_BY_SOURCE_CLASS[source_class],
        sha256=digest,
        features=projected,
        metadata={
            "source_dataset": source_dataset,
            "relative_path": relative_path,
            "parser_status": "parsed",
            "parser_defect_count": len(evidence.parser_defects),
        },
        signature=signature,
    )
    return row


def project_training_features(vector) -> dict[str, float]:
    """Project the runtime 48-feature vector onto the 30-feature contract.

    ``vector`` is the FeatureVector built by the production
    ``build_feature_vector`` (Step 1 evidence + offline Step 4 Received-IP
    classification). This projection copies the 30 Phase 1 training features
    out of the already-extracted sections — the runtime 48-feature evidence
    schema itself is untouched, and every value keeps its production
    semantics. The other 18 runtime evidence features (auth.*, DNS/RDAP/
    GeoIP intelligence) are deliberately NOT training inputs in this phase.
    """

    text = vector.text
    header = vector.header
    url = vector.url
    intelligence = vector.intelligence

    features: dict[str, float] = {
        "text.subject_length": float(text.subject_length),
        "text.subject_exclamation_count": float(text.subject_exclamation_count),
        "text.subject_urgency_signal": float(text.subject_urgency_signal),
        "text.subject_money_signal": float(text.subject_money_signal),
        "text.body_plain_length": float(text.body_plain_length),
        "text.body_html_present": float(text.body_html_present),
        "text.body_html_length": float(text.body_html_length),
        "text.credential_signal_count": float(text.credential_signal_count),
        "text.payment_signal_count": float(text.payment_signal_count),
        "text.urgency_signal_count": float(text.urgency_signal_count),
        "header.received_hop_count": float(header.received_hop_count),
        "header.parser_defect_count": float(header.parser_defect_count),
        "header.sender_reply_to_domain_mismatch": float(
            header.sender_reply_to_domain_mismatch
        ),
        "header.return_path_sender_mismatch": float(header.return_path_sender_mismatch),
        "header.message_id_domain_mismatch": float(header.message_id_domain_mismatch),
        "header.message_id_missing": float(header.message_id_missing),
        "header.date_missing": float(header.date_missing),
        "header.reply_to_present": float(header.reply_to_present),
        "header.user_agent_present": float(header.user_agent_present),
        "header.mime_multipart": float(header.mime_multipart),
        "url.url_count": float(url.url_count),
        "url.unique_url_host_count": float(url.unique_url_host_count),
        "url.https_ratio": float(url.https_ratio),
        "url.ip_url_count": float(url.ip_url_count),
        "url.suspicious_port_count": float(url.suspicious_port_count),
        "url.max_url_path_length": float(url.max_url_path_length),
        "url.unique_url_registered_domain_count": float(
            url.unique_url_registered_domain_count
        ),
        "url.url_registered_domain_mismatch_count": float(
            url.url_registered_domain_mismatch_count
        ),
        "intelligence.public_ip_count": float(intelligence.public_ip_count),
        "intelligence.non_public_ip_count": float(intelligence.non_public_ip_count),
    }
    validate_feature_values(features)
    return features


# ---------------------------------------------------------------------------
# Feature integrity validation.
# ---------------------------------------------------------------------------


def validate_feature_values(features: dict[str, float]) -> None:
    """Enforce the Phase 1 feature contract; raise ValueError on violation."""

    if set(features) != set(TRAINING_FEATURES):
        missing = sorted(set(TRAINING_FEATURES) - set(features))
        unexpected = sorted(set(features) - set(TRAINING_FEATURES))
        raise ValueError(
            f"feature contract violation: missing={missing} unexpected={unexpected}"
        )
    for name, value in features.items():
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError(f"feature {name} is not finite: {value!r}")
        if name in _BINARY_FEATURES and value not in (0.0, 1.0):
            raise ValueError(f"binary feature {name} must be 0/1, got {value!r}")
        if name in _INTEGER_FEATURES:
            if value != int(value) or value < 0:
                raise ValueError(
                    f"count feature {name} must be a non-negative integer, got {value!r}"
                )
        if name in _RATIO_FEATURES and not (0.0 <= value <= 1.0):
            raise ValueError(f"ratio feature {name} out of [0,1]: {value!r}")


def validate_rows(rows: list[DatasetRow]) -> list[str]:
    """Row-level contract validation; returns a list of problems (empty = OK)."""

    problems: list[str] = []
    for row in rows:
        if row.label not in {"benign", "suspicious"}:
            problems.append(f"{row.metadata['relative_path']}: invalid label {row.label!r}")
        try:
            validate_feature_values(row.features)
        except ValueError as error:
            problems.append(f"{row.metadata['relative_path']}: {error}")
    return problems


# ---------------------------------------------------------------------------
# Deduplication, grouping, splitting.
# ---------------------------------------------------------------------------


def deduplicate_exact(rows: list[DatasetRow]) -> tuple[list[DatasetRow], int, int]:
    """Drop rows whose full-email SHA-256 was already seen.

    First occurrence wins (benign/ is iterated before malicious/, so a
    byte-identical file present in both class folders is kept once, with the
    first-seen label — the conflict is counted and reported, never duplicated
    into two rows). Returns (kept, dropped_total, dropped_across_classes).
    """

    kept: list[DatasetRow] = []
    class_by_sha: dict[str, str] = {}
    dropped = 0
    dropped_cross_class = 0
    for row in rows:
        if row.sha256 in class_by_sha:
            dropped += 1
            if class_by_sha[row.sha256] != row.source_class:
                dropped_cross_class += 1
            continue
        class_by_sha[row.sha256] = row.source_class
        kept.append(row)
    return kept, dropped, dropped_cross_class


def build_groups(rows: list[DatasetRow]) -> dict[str, list[DatasetRow]]:
    """Group rows by structural signature (same signature = same group)."""

    groups: dict[str, list[DatasetRow]] = {}
    for row in rows:
        groups.setdefault(row.signature, []).append(row)
    return groups


def split_groups(
    groups: dict[str, list[DatasetRow]], seed: int
) -> tuple[list[DatasetRow], list[DatasetRow], list[DatasetRow]]:
    """Deterministic, stratified-by-label group split (70/15/15 by rows).

    For each label independently, groups (structural near-duplicate sets) are
    ordered deterministically, shuffled with a seeded RNG, then assigned one
    group at a time:

    - a label with 1 group is degenerate and goes entirely to train (a group
      may never span splits, so nothing else is possible);
    - a label with 2 groups gets one group in train and one in validation;
    - otherwise each group goes to the split whose row deficit
      (target − filled, targets 70/15/15) is largest, ties broken
      train → validation → test; a reservation guard forces one group each
      into validation and test so those splits can never end up empty.

    A group never spans two splits, which keeps structural near-duplicates —
    and any exact duplicates inside them — inside a single split.
    """

    rng = random.Random(seed)
    train: list[DatasetRow] = []
    validation: list[DatasetRow] = []
    test: list[DatasetRow] = []

    for label in ("benign", "suspicious"):
        label_groups = [
            members
            for _signature, members in sorted(groups.items())
            if members[0].label == label
        ]
        rng.shuffle(label_groups)

        total = sum(len(members) for members in label_groups)
        # Per-label targets: train and validation half-up, test the exact
        # remainder, so targets always sum to the label total. With 10 rows
        # per label this yields 7/2/1; with 20 per label an exact 14/3/3.
        target_train = int(total * TRAIN_RATIO + 0.5)
        target_validation = int(total * VALIDATION_RATIO + 0.5)
        target_test = total - target_train - target_validation
        targets = {
            "train": target_train,
            "validation": target_validation,
            "test": target_test,
        }
        buckets = {"train": train, "validation": validation, "test": test}
        filled = {"train": 0, "validation": 0, "test": 0}

        n = len(label_groups)
        for index, members in enumerate(label_groups):
            if n == 1:
                bucket = "train"
            elif n == 2:
                bucket = "train" if index == 0 else "validation"
            else:
                groups_left_after = n - index - 1
                reserve_needed = (
                    (1 if filled["validation"] == 0 else 0)
                    + (1 if filled["test"] == 0 else 0)
                )
                if groups_left_after < reserve_needed:
                    bucket = "validation" if filled["validation"] == 0 else "test"
                else:
                    deficits = {
                        name: targets[name] - filled[name]
                        for name in ("train", "validation", "test")
                    }
                    # max() keeps the first maximum on ties → train, then
                    # validation, then test — a fixed, deterministic order.
                    bucket = max(
                        ("train", "validation", "test"),
                        key=lambda name: deficits[name],
                    )
            buckets[bucket].extend(members)
            filled[bucket] += len(members)

    return train, validation, test


# ---------------------------------------------------------------------------
# Output writers.
# ---------------------------------------------------------------------------


def row_to_record(row: DatasetRow) -> dict:
    """Serializable record. Never contains body text or raw headers."""

    return {
        "id": row.id,
        "source_file": row.source_file,
        "source_class": row.source_class,
        "label": row.label,
        "sha256": row.sha256,
        "features": {name: row.features[name] for name in TRAINING_FEATURES},
        "metadata": dict(row.metadata),
        "split": row.split,
    }


def write_jsonl(path: Path, rows: list[DatasetRow]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row_to_record(row), ensure_ascii=False) + "\n")


def write_statistics_csv(path: Path, splits: dict[str, list[DatasetRow]]) -> None:
    """Single machine-readable table: split/label summaries + feature stats."""

    all_rows = [row for rows in splits.values() for row in rows]
    grand_total = max(1, len(all_rows))
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "split",
                "label",
                "count",
                "percentage",
                "source_dataset",
                "parser_status",
                "feature",
                "mean",
                "stddev",
                "min",
                "max",
            ]
        )
        for split_name in ("train", "validation", "test", "all"):
            rows = all_rows if split_name == "all" else splits[split_name]
            datasets = ",".join(
                sorted({row.metadata["source_dataset"] for row in rows})
            )
            statuses = (
                ",".join(
                    f"{status}:{count}"
                    for status, count in sorted(
                        Counter(row.metadata["parser_status"] for row in rows).items()
                    )
                )
                or "none"
            )
            by_label = Counter(row.label for row in rows)
            for label in ("benign", "suspicious"):
                count = by_label.get(label, 0)
                writer.writerow(
                    [
                        split_name,
                        label,
                        count,
                        f"{100.0 * count / max(1, len(rows)):.2f}",
                        datasets,
                        statuses,
                        "",
                        "",
                        "",
                        "",
                        "",
                    ]
                )
            writer.writerow(
                [
                    split_name,
                    "total",
                    len(rows),
                    f"{100.0 * len(rows) / grand_total:.2f}",
                    datasets,
                    statuses,
                    "",
                    "",
                    "",
                    "",
                    "",
                ]
            )
            for feature in TRAINING_FEATURES:
                values = [row.features[feature] for row in rows]
                if not values:
                    continue
                writer.writerow(
                    [
                        split_name,
                        "feature",
                        len(values),
                        "",
                        datasets,
                        "",
                        feature,
                        f"{statistics.fmean(values):.6f}",
                        (
                            f"{statistics.pstdev(values):.6f}"
                            if len(values) > 1
                            else "0.000000"
                        ),
                        f"{min(values):.6f}",
                        f"{max(values):.6f}",
                    ]
                )


def _overlaps(
    first: list[DatasetRow], second: list[DatasetRow], key
) -> int:
    first_keys = {key(row) for row in first}
    return sum(1 for row in second if key(row) in first_keys)


def build_quality_report(
    discovery: DiscoveryResult,
    rows: list[DatasetRow],
    failures: list[ParseFailure],
    exact_duplicates_dropped: int,
    exact_duplicates_cross_class: int,
    splits: dict[str, list[DatasetRow]],
    row_problems: list[str],
    seed: int,
) -> dict:
    train, validation, test = splits["train"], splits["validation"], splits["test"]

    exact_train_val = _overlaps(train, validation, lambda r: r.sha256)
    exact_train_test = _overlaps(train, test, lambda r: r.sha256)
    exact_val_test = _overlaps(validation, test, lambda r: r.sha256)
    struct_train_val = _overlaps(train, validation, lambda r: r.signature)
    struct_train_test = _overlaps(train, test, lambda r: r.signature)
    struct_val_test = _overlaps(validation, test, lambda r: r.signature)

    all_rows = train + validation + test
    label_counts = Counter(row.label for row in all_rows)
    group_counts = Counter(row.signature for row in all_rows)
    structural_groups = sum(1 for count in group_counts.values() if count > 1)

    leakage_checks_passed = all(
        overlap == 0
        for overlap in (
            exact_train_val,
            exact_train_test,
            exact_val_test,
            struct_train_val,
            struct_train_test,
            struct_val_test,
        )
    )
    contract_passed = not row_problems
    # Verdict semantics: PASS = no split leakage AND a valid feature contract.
    # Parse failures and duplicates are informational — failed emails are
    # recorded and excluded, never silently converted into training rows.
    overall_pass = leakage_checks_passed and contract_passed

    warnings: list[str] = []
    for split_name, rows_in_split in (
        ("train", train), ("validation", validation), ("test", test)
    ):
        if not rows_in_split:
            warnings.append(
                f"split '{split_name}' is empty (input too small or too "
                "few distinct structural groups)"
            )
    if failures:
        warnings.append(f"{len(failures)} file(s) failed to parse and were excluded")
    if exact_duplicates_dropped:
        warnings.append(
            f"{exact_duplicates_dropped} exact SHA-256 duplicate(s) removed"
        )

    return {
        "preparation_version": PREPARATION_VERSION,
        "seed": seed,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_files_discovered": discovery.total_files,
        "unsupported_files": len(discovery.unsupported),
        "unsupported_file_list": [
            {"path": item.relative_path, "reason": item.reason}
            for item in discovery.unsupported
        ],
        "successfully_parsed": len(rows),
        "failed_parses": len(failures),
        "failed_parse_list": [
            {"path": item.relative_path, "error": item.error} for item in failures
        ],
        "benign_count": label_counts.get("benign", 0),
        "suspicious_count": label_counts.get("suspicious", 0),
        "exact_sha_duplicate_count": exact_duplicates_dropped,
        "exact_duplicates_across_classes": exact_duplicates_cross_class,
        "verdict_definition": (
            "PASS = no split leakage AND valid feature contract; "
            "failed parses and duplicates are informational (excluded rows)."
        ),
        "structural_duplicate_group_count": structural_groups,
        "exact_overlap_train_validation": exact_train_val,
        "exact_overlap_train_test": exact_train_test,
        "exact_overlap_validation_test": exact_val_test,
        "structural_overlap_train_validation": struct_train_val,
        "structural_overlap_train_test": struct_train_test,
        "structural_overlap_validation_test": struct_val_test,
        "missing_required_features": sum(
            1 for row in all_rows if set(row.features) != set(TRAINING_FEATURES)
        ),
        "invalid_labels": sum(1 for row in all_rows if row.label not in {"benign", "suspicious"}),
        "invalid_feature_values": len(row_problems),
        "invalid_feature_detail": row_problems,
        "split_sizes": {
            "train": len(train),
            "validation": len(validation),
            "test": len(test),
        },
        "class_distribution": {
            split: {
                "benign": sum(1 for row in rows if row.label == "benign"),
                "suspicious": sum(1 for row in rows if row.label == "suspicious"),
            }
            for split, rows in (
                ("train", train),
                ("validation", validation),
                ("test", test),
            )
        },
        "leakage_checks_passed": leakage_checks_passed,
        "feature_contract_passed": contract_passed,
        "warnings": warnings,
        "overall_result": "PASS" if overall_pass else "FAIL",
    }


def _file_sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def write_manifest(
    path: Path,
    input_dir: Path,
    output_dir: Path,
    source_dataset: str,
    seed: int,
    quality: dict,
    output_files: dict[str, Path],
) -> None:
    """Write dataset_manifest.yaml as deterministic flat YAML (no deps)."""

    def _yaml_value(value) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        return json.dumps(str(value), ensure_ascii=False)

    lines: list[str] = [
        f"preparation_version: {_yaml_value(PREPARATION_VERSION)}",
        f"random_seed: {_yaml_value(seed)}",
        f"input_directory: {_yaml_value(str(input_dir))}",
        f"output_directory: {_yaml_value(str(output_dir))}",
        f"source_dataset: {_yaml_value(source_dataset)}",
        f"feature_contract_version: {_yaml_value('raw_eml_30_v1')}",
        "training_features:",
        *[
            f"  - {json.dumps(name, ensure_ascii=False)}"
            for name in TRAINING_FEATURES
        ],
        "label_mapping:",
        f"  benign: {_yaml_value('benign')}",
        f"  malicious: {_yaml_value('suspicious')}",
        "split_ratios:",
        f"  train: {TRAIN_RATIO}",
        f"  validation: {VALIDATION_RATIO}",
        f"  test: {round(1.0 - TRAIN_RATIO - VALIDATION_RATIO, 4)}",
        f"parser_used: {_yaml_value('backend/app/extractor/email_parser.py (Step 1 extract_email_from_bytes)')}",
        f"feature_extraction_used: {_yaml_value('backend/app/features/ (production extractors)')}",
        f"ip_classification_used: {_yaml_value('backend/app/intelligence/ (Step 4, offline: perform_dns=false, perform_rdap=false, geoip=none)')}",
        f"normalization_method: {_yaml_value(NORMALIZATION_VERSION + ' urls-><url> emails-><addr> dates-><date> numbers-><num> whitespace-collapsed; content words preserved')}",
        f"generated_at: {_yaml_value(quality['generated_at'])}",
        "counts:",
        f"  discovered: {quality['total_files_discovered']}",
        f"  parsed: {quality['successfully_parsed']}",
        f"  failed: {quality['failed_parses']}",
        f"  exact_duplicates_removed: {quality['exact_sha_duplicate_count']}",
        f"  benign: {quality['benign_count']}",
        f"  suspicious: {quality['suspicious_count']}",
        f"  train: {quality['split_sizes']['train']}",
        f"  validation: {quality['split_sizes']['validation']}",
        f"  test: {quality['split_sizes']['test']}",
        f"overall_result: {_yaml_value(quality['overall_result'])}",
        "file_sha256:",
    ]
    for name, file_path in output_files.items():
        digest = _file_sha256(file_path)
        if digest:
            lines.append(f"  {name}: {digest}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_readme(path: Path, source_dataset: str, quality: dict) -> None:
    content = f"""ForentisAI raw-EML dataset ({source_dataset})
=====================================================

Generated by ai/training/prepare_dataset.py (preparation version {PREPARATION_VERSION})
on {quality['generated_at']}.

WHAT THIS DATASET IS
--------------------
A labeled collection of {quality['successfully_parsed']} raw .eml emails, each reduced to
exactly 30 features derived locally from the original bytes (text shape,
header shape, URL shape, Received-chain IP classification). Rows are split
70/15/15 into train/validation/test, stratified by label, with structural
near-duplicates kept within a single split.

Label mapping: benign/ -> "benign"; malicious/ -> "suspicious".
"suspicious" is the backend's MODEL EVIDENCE class; the raw folder name
"malicious" is never used as a model label.

WHAT THIS DATASET IS NOT
------------------------
- It contains NO DNS, RDAP, WHOIS, GeoIP, or Rspamd-derived values. The
  intelligence features in this dataset are Received-chain IP counts only,
  classified locally.
- Its metrics do not establish real-world model performance. Any accuracy
  measured on it depends entirely on the provenance and labeling quality of
  the source corpus, which must be documented where the corpus was obtained.
- It contains no email bodies, no raw headers, and no unnecessary PII — only
  feature numbers, file names, SHA-256 hashes, and relative paths.

FILES
-----
- dataset_train.jsonl / dataset_validation.jsonl / dataset_test.jsonl
- dataset_all.jsonl  (every accepted row with its split recorded)
- dataset_statistics.csv (split/label counts, percentages, per-feature stats)
- dataset_quality_report.json (counts, leakage checks, overall PASS/FAIL)
- dataset_manifest.yaml (provenance, feature contract, seed, file hashes)

USAGE
-----
Training (future phase) must consume dataset_train.jsonl for fitting,
dataset_validation.jsonl for model selection, and dataset_test.jsonl only
for the final reported evaluation. Never train on the test split.
"""
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Main pipeline.
# ---------------------------------------------------------------------------


def prepare_dataset(
    input_dir: Path,
    output_dir: Path,
    *,
    seed: int = 42,
    source_dataset: str | None = None,
    max_size_bytes: int = 26_214_400,
) -> dict:
    """Run the full Phase 1 preparation; returns the quality report dict."""

    source_dataset = source_dataset or input_dir.resolve().name
    discovery = discover_emails(input_dir)

    rows: list[DatasetRow] = []
    failures: list[ParseFailure] = []
    for source_class in ("benign", "malicious"):
        for path in discovery.files_by_class.get(source_class, []):
            outcome = parse_email_row(
                path,
                source_class,
                input_dir,
                source_dataset,
                max_size_bytes,
            )
            if isinstance(outcome, ParseFailure):
                failures.append(outcome)
            else:
                rows.append(outcome)

    rows, exact_duplicates_dropped, cross_class_dupes = deduplicate_exact(rows)
    row_problems = validate_rows(rows)
    if row_problems:
        raise SystemExit(
            "Feature contract validation failed:\n  " + "\n  ".join(row_problems)
        )

    groups = build_groups(rows)
    train, validation, test = split_groups(groups, seed)
    for row in train:
        row.split = "train"
    for row in validation:
        row.split = "validation"
    for row in test:
        row.split = "test"

    splits = {"train": train, "validation": validation, "test": test}
    quality = build_quality_report(
        discovery,
        rows,
        failures,
        exact_duplicates_dropped,
        cross_class_dupes,
        splits,
        row_problems=[],
        seed=seed,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    output_files = {
        "dataset_train.jsonl": output_dir / "dataset_train.jsonl",
        "dataset_validation.jsonl": output_dir / "dataset_validation.jsonl",
        "dataset_test.jsonl": output_dir / "dataset_test.jsonl",
        "dataset_all.jsonl": output_dir / "dataset_all.jsonl",
        "dataset_statistics.csv": output_dir / "dataset_statistics.csv",
        "dataset_quality_report.json": output_dir / "dataset_quality_report.json",
        "dataset_manifest.yaml": output_dir / "dataset_manifest.yaml",
        "README_DATASET.txt": output_dir / "README_DATASET.txt",
    }
    write_jsonl(output_files["dataset_train.jsonl"], train)
    write_jsonl(output_files["dataset_validation.jsonl"], validation)
    write_jsonl(output_files["dataset_test.jsonl"], test)
    write_jsonl(
        output_files["dataset_all.jsonl"],
        sorted(rows, key=lambda row: row.sha256),
    )
    write_statistics_csv(output_files["dataset_statistics.csv"], splits)
    output_files["dataset_quality_report.json"].write_text(
        json.dumps(quality, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    write_readme(output_files["README_DATASET.txt"], source_dataset, quality)
    # Manifest last: it records SHA-256 of every previously written output.
    write_manifest(
        output_files["dataset_manifest.yaml"],
        input_dir,
        output_dir,
        source_dataset,
        seed,
        quality,
        output_files,
    )
    return quality


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare the Phase 1 raw-EML technical-ML dataset (offline)."
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        required=True,
        help="Dataset root containing benign/ and malicious/ folders of .eml files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory that receives the JSONL splits and reports.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic split seed (default: 42).",
    )
    parser.add_argument(
        "--source-dataset",
        type=str,
        default=None,
        help="Name recorded in row metadata (default: input directory name).",
    )
    args = parser.parse_args(argv)

    input_dir = args.input_dir
    if not input_dir.is_dir():
        raise SystemExit(f"Input directory does not exist: {input_dir}")
    for source_class in ("benign", "malicious"):
        if not (input_dir / source_class).is_dir():
            print(
                f"warning: missing class folder '{source_class}/' under {input_dir}",
                file=sys.stderr,
            )

    quality = prepare_dataset(
        input_dir,
        args.output_dir,
        seed=args.seed,
        source_dataset=args.source_dataset,
    )

    print(f"Discovered files : {quality['total_files_discovered']}")
    print(f"Parsed           : {quality['successfully_parsed']}")
    print(f"Failed parses    : {quality['failed_parses']}")
    print(f"Exact duplicates : {quality['exact_sha_duplicate_count']} "
          f"({quality['exact_duplicates_across_classes']} across classes)")
    print(
        f"Labels           : benign={quality['benign_count']} "
        f"suspicious={quality['suspicious_count']}"
    )
    print(
        f"Split sizes      : train={quality['split_sizes']['train']} "
        f"validation={quality['split_sizes']['validation']} "
        f"test={quality['split_sizes']['test']}"
    )
    print(f"Leakage checks   : {'passed' if quality['leakage_checks_passed'] else 'FAILED'}")
    for warning in quality.get("warnings", []):
        print(f"Warning          : {warning}")
    print(f"Overall result   : {quality['overall_result']}")
    if quality["overall_result"] != "PASS":
        print(
            "ERROR: dataset quality report is FAIL (leakage or contract); "
            "do not train on this dataset.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
