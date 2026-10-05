"""Phase 1 tests for ai/training/prepare_dataset.py.

All fixtures here are synthetic test emails generated in temporary
directories. They are TEST FIXTURES ONLY — never model-training data — and
the pipeline itself is exercised fully offline (no network).
"""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import socket
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Import the pipeline module by file path (it lives outside backend/, and its
# own path bootstrap adds backend/ to sys.path so app.* imports resolve).
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PIPELINE_PATH = _REPO_ROOT / "ai" / "training" / "prepare_dataset.py"
_spec = importlib.util.spec_from_file_location("prepare_dataset", _PIPELINE_PATH)
prepare_dataset = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("prepare_dataset", prepare_dataset)
_spec.loader.exec_module(prepare_dataset)


# ---------------------------------------------------------------------------
# Synthetic EML fixtures (test data only).
# ---------------------------------------------------------------------------

BENIGN_BODIES = [
    "Hi team, the quarterly report is attached for your review this week.",
    "Lunch on Friday at the usual place? Reply yes or no before Thursday.",
    "Your package was delivered to the front desk of building four today.",
    "Here are the meeting minutes and the agreed action items from Monday.",
    "The library due date for the borrowed book was extended by two weeks.",
    "Reminder that the office will be closed on the upcoming public holiday.",
    "Please find the recipe you asked about after last weekend's dinner.",
    "The train tickets for the trip were booked and seats are confirmed.",
    "Thanks for helping me move the furniture into the new flat on Sunday.",
    "The newsletter with the monthly updates went out to all subscribers.",
    "The office coffee machine was repaired and is working again this morning.",
    "Parking permits for the new garage arrive next week at the reception.",
    "Our book club meets on the first Tuesday to discuss the current novel.",
    "The team calendar now shows the correct timezone for all meetings.",
    "Please water the plants on the windowsill while I am on holiday.",
    "The new printer on the third floor accepts mobile print jobs now.",
    "Yesterday's fire drill went smoothly and everyone gathered outside.",
    "The charity bake sale raised funds for the local animal shelter.",
    "The office plant order arrived and pots were distributed to desks.",
    "Car park resurfacing finishes on Friday and spaces reopen on Monday.",
]

MALICIOUS_BODIES = [
    "Your account shows unusual activity and will be suspended unless verified.",
    "Confirm your banking identity immediately or face permanent closure tonight.",
    "Claim your exclusive prize now by entering the code on the linked portal.",
    "Security alert: unauthorized sign-in detected, validate password this hour.",
    "Payment of the outstanding invoice must be made today to avoid penalties.",
    "Final warning: mailbox quota exceeded, revalidate credentials right away.",
    "Act urgently: your package is held at customs and fees must be paid fast.",
    "Your subscription expired and the account will be deleted within the hour.",
    "Warning: suspicious purchase flagged, cancel it via the link immediately.",
    "Lottery winner selected! Send the processing fee to receive your reward.",
    "Your mailbox is full and incoming mail is bouncing until you upgrade.",
    "Unusual sign-in detected from a new device, reset your password quickly.",
    "Your tax refund is approved; submit bank details through the secure form.",
    "Update billing information or the service will be cancelled at midnight.",
    "A file was reported; open the portal link to review the case against you.",
    "Your rewards points expire today, redeem them on the verification page.",
    "Delivery failed: pay the small customs fee to release your parcel fast.",
    "Employee payroll portal migration requires immediate credential validation.",
    "Your insurance policy lapses tonight unless you confirm payment details.",
    "Your cloud storage is full and files will be erased unless upgraded now.",
]


def _make_eml(
    *,
    index: int,
    cls: str,
    subject: str,
    body: str,
    message_id: str | None = None,
    date: str | None = "Mon, 01 Apr 2024 10:30:00 +0000",
    reply_to: str | None = None,
    url: str | None = None,
) -> bytes:
    """Build one deterministic synthetic email as raw bytes."""

    lines = [
        f"From: sender{index}@{cls}.example",
        f"To: recipient{index}@example.org",
        f"Subject: {subject}",
    ]
    if message_id is not None:
        lines.append(f"Message-ID: <{message_id}>")
    if date is not None:
        lines.append(f"Date: {date}")
    if reply_to is not None:
        lines.append(f"Reply-To: {reply_to}")
    if url is not None:
        lines.append("Content-Type: text/plain; charset=utf-8")
    lines.append("")
    text = body
    if url is not None:
        text = f"{body}\nVisit {url}"
    return ("\r\n".join(lines) + "\r\n" + text + "\r\n").encode("utf-8")


@pytest.fixture()
def corpus(tmp_path: Path) -> Path:
    """A small deterministic benign/malicious corpus of unique emails."""

    root = tmp_path / "corpus"
    benign, malicious = root / "benign", root / "malicious"
    benign.mkdir(parents=True)
    malicious.mkdir()
    for i in range(20):
        (benign / f"benign_{i:03d}.eml").write_bytes(
            _make_eml(
                index=i,
                cls="benign",
                subject=f"Weekly update {i}",
                body=BENIGN_BODIES[i],
            )
        )
        (malicious / f"malicious_{i:03d}.eml").write_bytes(
            _make_eml(
                index=i,
                cls="malicious",
                subject=f"URGENT alert {i}!!!",
                body=MALICIOUS_BODIES[i],
                reply_to=f"collector{i}@other.example",
            )
        )
    return root


def _run_pipeline(corpus: Path, out: Path, **kwargs) -> dict:
    return prepare_dataset.prepare_dataset(
        corpus,
        out,
        source_dataset="tests",
        **kwargs,
    )


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# Label mapping.
# ---------------------------------------------------------------------------


class TestLabelMapping:
    def test_benign_maps_to_benign(self, corpus: Path, tmp_path: Path):
        quality = _run_pipeline(corpus, tmp_path / "out")
        assert quality["benign_count"] == 20

    def test_malicious_folder_maps_to_suspicious_label(self, corpus: Path, tmp_path: Path):
        quality = _run_pipeline(corpus, tmp_path / "out")
        assert quality["suspicious_count"] == 20

    def test_no_row_ever_carries_raw_malicious_label(self, corpus: Path, tmp_path: Path):
        _run_pipeline(corpus, tmp_path / "out")
        for row in _read_jsonl(tmp_path / "out" / "dataset_all.jsonl"):
            assert row["label"] in {"benign", "suspicious"}
            assert row["label"] != "malicious"
            assert row["source_class"] in {"benign", "malicious"}


# ---------------------------------------------------------------------------
# EML discovery.
# ---------------------------------------------------------------------------


class TestDiscovery:
    def test_recursive_discovery_of_eml_files(self, corpus: Path, tmp_path: Path):
        (corpus / "benign" / "nested").mkdir()
        (corpus / "benign" / "nested" / "deep.eml").write_bytes(
            _make_eml(index=99, cls="benign", subject="Deep", body="Deep body text.")
        )
        quality = _run_pipeline(corpus, tmp_path / "out")
        assert quality["total_files_discovered"] == 41

    def test_unsupported_files_reported_not_parsed(self, corpus: Path, tmp_path: Path):
        (corpus / "benign" / "readme.txt").write_text("definitely not an email")
        (corpus / "malicious" / "image.png").write_bytes(b"\x89PNG not-an-email")
        quality = _run_pipeline(corpus, tmp_path / "out")
        assert quality["unsupported_files"] == 2
        reported = {item["path"] for item in quality["unsupported_file_list"]}
        assert "benign/readme.txt" in reported
        assert "malicious/image.png" in reported
        # Unsupported files must not become rows.
        paths = {
            row["metadata"]["relative_path"]
            for row in _read_jsonl(tmp_path / "out" / "dataset_all.jsonl")
        }
        assert "benign/readme.txt" not in paths
        assert "malicious/image.png" not in paths

    def test_missing_class_folder_is_warning_not_crash(self, corpus: Path, tmp_path: Path):
        import shutil

        shutil.rmtree(corpus / "malicious")
        quality = _run_pipeline(corpus, tmp_path / "out")
        assert quality["suspicious_count"] == 0
        assert quality["successfully_parsed"] == 20


# ---------------------------------------------------------------------------
# SHA-256 and deduplication.
# ---------------------------------------------------------------------------


class TestSha256AndDedup:
    def test_sha256_over_exact_original_bytes(self, corpus: Path, tmp_path: Path):
        _run_pipeline(corpus, tmp_path / "out")
        rows = _read_jsonl(tmp_path / "out" / "dataset_all.jsonl")
        source = corpus / rows[0]["metadata"]["relative_path"]
        assert rows[0]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()

    def test_exact_duplicates_removed(self, corpus: Path, tmp_path: Path):
        duplicate = (corpus / "benign" / "benign_000.eml").read_bytes()
        (corpus / "benign" / "same_class_dupe.eml").write_bytes(duplicate)
        (corpus / "malicious" / "cross_class_dupe.eml").write_bytes(duplicate)
        quality = _run_pipeline(corpus, tmp_path / "out")
        assert quality["exact_sha_duplicate_count"] == 2
        assert quality["exact_duplicates_across_classes"] == 1
        shas = [
            row["sha256"]
            for row in _read_jsonl(tmp_path / "out" / "dataset_all.jsonl")
        ]
        assert len(shas) == len(set(shas))

    def test_structural_duplicates_share_signature(self):
        wording = "Your account is locked, confirm identity to restore access"
        first = prepare_dataset.structural_signature(
            wording,
            "Verify at https://evil.example/login?id=12345 before the deadline",
        )
        second = prepare_dataset.structural_signature(
            wording,
            "Verify at http://other.example/confirm?id=99999 before the deadline",
        )
        assert first == second

    def test_distinct_content_never_collapses(self):
        first = prepare_dataset.structural_signature(
            "Team offsite planning", "Please book the venue for the workshop."
        )
        second = prepare_dataset.structural_signature(
            "Server maintenance window", "The database upgrade finished early."
        )
        assert first != second


# ---------------------------------------------------------------------------
# Splitting: determinism, ratios, stratification, leakage safety.
# ---------------------------------------------------------------------------


class TestSplit:
    def test_split_is_deterministic(self, corpus: Path, tmp_path: Path):
        out1, out2 = tmp_path / "a", tmp_path / "b"
        _run_pipeline(corpus, out1, seed=7)
        _run_pipeline(corpus, out2, seed=7)
        for name in (
            "dataset_train.jsonl",
            "dataset_validation.jsonl",
            "dataset_test.jsonl",
        ):
            assert (out1 / name).read_bytes() == (out2 / name).read_bytes()

    def test_different_seed_can_change_assignment(self, corpus: Path, tmp_path: Path):
        out1, out2 = tmp_path / "a", tmp_path / "b"
        _run_pipeline(corpus, out1, seed=1)
        _run_pipeline(corpus, out2, seed=2)
        ids_1 = {
            row["id"] for row in _read_jsonl(out1 / "dataset_test.jsonl")
        }
        ids_2 = {
            row["id"] for row in _read_jsonl(out2 / "dataset_test.jsonl")
        }
        # 20 shuffled unique emails: identical test sets across seeds would
        # be an extraordinary coincidence; the assertion guards determinism
        # coming from the seeded RNG, not from input order.
        assert ids_1 != ids_2

    def test_approximately_70_15_15(self, corpus: Path, tmp_path: Path):
        quality = _run_pipeline(corpus, tmp_path / "out")
        sizes = quality["split_sizes"]
        total = sum(sizes.values())
        assert sizes["train"] == round(total * 0.70)
        assert sizes["validation"] == round(total * 0.15)
        assert sizes["test"] == round(total * 0.15)

    def test_split_is_stratified_by_label(self, corpus: Path, tmp_path: Path):
        quality = _run_pipeline(corpus, tmp_path / "out")
        for split, distribution in quality["class_distribution"].items():
            assert distribution["benign"] > 0, split
            assert distribution["suspicious"] > 0, split

    def test_structural_group_never_spans_splits(
        self, corpus: Path, tmp_path: Path
    ):
        # dup_a/dup_b share wording but differ in id/url host -> same signature.
        (corpus / "malicious" / "dup_a.eml").write_bytes(
            _make_eml(
                index=50,
                cls="malicious",
                subject="WINNER selected now",
                body="Send the fee to receive your reward.",
                message_id="da@x.example",
                url="http://a.example/win",
            )
        )
        (corpus / "malicious" / "dup_b.eml").write_bytes(
            _make_eml(
                index=51,
                cls="malicious",
                subject="WINNER selected now",
                body="Send the fee to receive your reward.",
                message_id="db@x.example",
                url="http://b.example/win",
            )
        )
        quality = _run_pipeline(corpus, tmp_path / "out")
        assert quality["structural_duplicate_group_count"] >= 1
        assert quality["structural_overlap_train_validation"] == 0
        assert quality["structural_overlap_train_test"] == 0
        assert quality["structural_overlap_validation_test"] == 0

    def test_groups_respected_on_concatenated_splits(self, corpus: Path, tmp_path: Path):
        (corpus / "benign" / "g1.eml").write_bytes(
            _make_eml(
                index=60,
                cls="benign",
                subject="Standup notes today",
                body="The sprint board was updated after the meeting.",
                message_id="g1@x.example",
            )
        )
        (corpus / "benign" / "g2.eml").write_bytes(
            _make_eml(
                index=61,
                cls="benign",
                subject="Standup notes today",
                body="The sprint board was updated after the meeting.",
                message_id="g2@x.example",
            )
        )
        _run_pipeline(corpus, tmp_path / "out")
        by_split: dict[str, set[str]] = {}
        for name in ("train", "validation", "test"):
            rows = _read_jsonl(tmp_path / "out" / f"dataset_{name}.jsonl")
            by_split[name] = {row["sha256"] for row in rows}
        # The two structurally identical benign emails must land together.
        locations = [
            split
            for split, shas in by_split.items()
            if any(row["source_file"] == "g1.eml" for row in _read_jsonl(
                tmp_path / "out" / f"dataset_{split}.jsonl"
            ))
        ]
        g2_locations = [
            split
            for split, shas in by_split.items()
            if any(row["source_file"] == "g2.eml" for row in _read_jsonl(
                tmp_path / "out" / f"dataset_{split}.jsonl"
            ))
        ]
        assert locations == g2_locations
        assert len(locations) == 1


# ---------------------------------------------------------------------------
# Feature contract.
# ---------------------------------------------------------------------------


class TestFeatureContract:
    def test_exactly_30_features_in_contract_order(self, corpus: Path, tmp_path: Path):
        _run_pipeline(corpus, tmp_path / "out")
        rows = _read_jsonl(tmp_path / "out" / "dataset_all.jsonl")
        expected = list(prepare_dataset.TRAINING_FEATURES)
        assert len(expected) == 30
        for row in rows:
            assert list(row["features"].keys()) == expected

    def test_feature_values_are_valid(self, corpus: Path, tmp_path: Path):
        _run_pipeline(corpus, tmp_path / "out")
        for row in _read_jsonl(tmp_path / "out" / "dataset_all.jsonl"):
            for name, value in row["features"].items():
                assert isinstance(value, float), (name, value)
                assert value == value and abs(value) != float("inf")
                if name in prepare_dataset._BINARY_FEATURES:
                    assert value in (0.0, 1.0), (name, value)
                elif name in prepare_dataset._RATIO_FEATURES:
                    assert 0.0 <= value <= 1.0, (name, value)
                else:
                    assert value >= 0 and value == int(value), (name, value)

    def test_validate_feature_values_rejects_missing_and_extra(self):
        base = dict.fromkeys(prepare_dataset.TRAINING_FEATURES, 0.0)
        base["url.https_ratio"] = 0.5
        base["text.body_html_present"] = 1.0  # binary sanity
        with pytest.raises(ValueError, match="missing"):
            prepare_dataset.validate_feature_values(
                {k: v for k, v in base.items() if k != "text.subject_length"}
            )
        with pytest.raises(ValueError, match="unexpected"):
            prepare_dataset.validate_feature_values({**base, "auth.spf_result": 1.0})

    def test_validate_feature_values_rejects_bad_values(self):
        base = dict.fromkeys(prepare_dataset.TRAINING_FEATURES, 0.0)
        with pytest.raises(ValueError, match="binary"):
            prepare_dataset.validate_feature_values(
                {**base, "text.body_html_present": 2.0}
            )
        with pytest.raises(ValueError, match="non-negative"):
            prepare_dataset.validate_feature_values({**base, "url.url_count": -1.0})
        with pytest.raises(ValueError, match="out of"):
            prepare_dataset.validate_feature_values(
                {**base, "url.https_ratio": 1.5}
            )
        with pytest.raises(ValueError, match="finite"):
            prepare_dataset.validate_feature_values(
                {**base, "url.url_count": float("nan")}
            )

    def test_features_reflect_email_content(self, corpus: Path, tmp_path: Path):
        _run_pipeline(corpus, tmp_path / "out")
        rows = _read_jsonl(tmp_path / "out" / "dataset_all.jsonl")
        by_file = {row["source_file"]: row for row in rows}
        urgent = by_file["malicious_000.eml"]
        assert urgent["features"]["text.subject_urgency_signal"] == 1.0
        assert urgent["features"]["text.subject_exclamation_count"] >= 1.0
        assert urgent["features"]["header.reply_to_present"] == 1.0
        calm = by_file["benign_000.eml"]
        assert calm["features"]["text.subject_urgency_signal"] == 0.0

    def test_row_shape_and_no_body_content_stored(self, corpus: Path, tmp_path: Path):
        _run_pipeline(corpus, tmp_path / "out")
        row = _read_jsonl(tmp_path / "out" / "dataset_all.jsonl")[0]
        assert set(row.keys()) == {
            "id",
            "source_file",
            "source_class",
            "label",
            "sha256",
            "features",
            "metadata",
            "split",
        }
        serialized = json.dumps(row)
        assert "quarterly report is attached" not in serialized
        blob = json.dumps(
            _read_jsonl(tmp_path / "out" / "dataset_all.jsonl")
        )
        for body in BENIGN_BODIES[:3]:
            assert body not in blob


# ---------------------------------------------------------------------------
# Malformed input handling.
# ---------------------------------------------------------------------------


class TestMalformedInput:
    def test_malformed_eml_recorded_and_excluded(self, corpus: Path, tmp_path: Path):
        # Empty bytes make the Step 1 extractor raise (FileValidationError).
        (corpus / "benign" / "broken.eml").write_bytes(b"")
        quality = _run_pipeline(corpus, tmp_path / "out")
        assert quality["failed_parses"] == 1
        assert quality["failed_parse_list"][0]["path"] == "benign/broken.eml"
        assert "parse_failed" in quality["failed_parse_list"][0]["error"]
        assert quality["successfully_parsed"] == 40
        paths = {
            row["metadata"]["relative_path"]
            for row in _read_jsonl(tmp_path / "out" / "dataset_all.jsonl")
        }
        assert "benign/broken.eml" not in paths

    def test_one_bad_email_does_not_stop_the_run(self, corpus: Path, tmp_path: Path):
        for i in range(3):
            (corpus / "benign" / f"junk{i}.eml").write_bytes(b"")
        quality = _run_pipeline(corpus, tmp_path / "out")
        assert quality["failed_parses"] == 3
        assert quality["successfully_parsed"] == 40
        assert quality["overall_result"] == "PASS"  # failures are informational

    def test_tolerated_garbage_keeps_visible_parser_defects(
        self, corpus: Path, tmp_path: Path
    ):
        # NUL bytes do not raise; the Step 1 parser records defects instead.
        # Such an email stays a valid row, but the defect count is exposed so
        # degraded parses are never hidden.
        (corpus / "benign" / "degraded.eml").write_bytes(b"\x00\xff junk body")
        quality = _run_pipeline(corpus, tmp_path / "out")
        assert quality["failed_parses"] == 0
        rows = {
            row["metadata"]["relative_path"]: row
            for row in _read_jsonl(tmp_path / "out" / "dataset_all.jsonl")
        }
        degraded = rows["benign/degraded.eml"]
        assert degraded["metadata"]["parser_defect_count"] >= 1
        assert degraded["metadata"]["parser_status"] == "parsed"


# ---------------------------------------------------------------------------
# Security: the pipeline must stay fully offline.
# ---------------------------------------------------------------------------


class TestOfflineSecurity:
    def test_no_network_calls_during_full_run(
        self, corpus: Path, tmp_path: Path, monkeypatch
    ):
        def _blocked(*args, **kwargs):  # pragma: no cover - must never run
            raise AssertionError(f"network call attempted: {args} {kwargs}")

        monkeypatch.setattr(socket, "socket", _blocked)
        monkeypatch.setattr(socket, "create_connection", _blocked)
        monkeypatch.setattr(
            socket, "getaddrinfo", _blocked
        )
        quality = _run_pipeline(corpus, tmp_path / "out")
        assert quality["successfully_parsed"] == 40

    def test_offline_settings_disable_dns_rdap_geoip(self):
        settings = prepare_dataset._OFFLINE_INTELLIGENCE_SETTINGS
        assert settings.perform_dns is False
        assert settings.perform_rdap is False
        assert settings.geoip is None


# ---------------------------------------------------------------------------
# Output files.
# ---------------------------------------------------------------------------


class TestOutputs:
    EXPECTED_FILES = (
        "dataset_train.jsonl",
        "dataset_validation.jsonl",
        "dataset_test.jsonl",
        "dataset_all.jsonl",
        "dataset_statistics.csv",
        "dataset_quality_report.json",
        "dataset_manifest.yaml",
        "README_DATASET.txt",
    )

    def test_all_eight_output_files_created(self, corpus: Path, tmp_path: Path):
        _run_pipeline(corpus, tmp_path / "out")
        for name in self.EXPECTED_FILES:
            assert (tmp_path / "out" / name).is_file(), name

    def test_split_files_partition_dataset_all(self, corpus: Path, tmp_path: Path):
        _run_pipeline(corpus, tmp_path / "out")
        all_rows = _read_jsonl(tmp_path / "out" / "dataset_all.jsonl")
        pieces = [
            _read_jsonl(tmp_path / "out" / f"dataset_{split}.jsonl")
            for split in ("train", "validation", "test")
        ]
        combined = [row for piece in pieces for row in piece]
        assert {row["sha256"] for row in combined} == {
            row["sha256"] for row in all_rows
        }
        assert len(combined) == len(all_rows)
        for row in all_rows:
            expected = {
                "train": "train",
                "validation": "validation",
                "test": "test",
            }[row["split"]]
            assert row["split"] == expected

    def test_statistics_csv_summary_columns(self, corpus: Path, tmp_path: Path):
        _run_pipeline(corpus, tmp_path / "out")
        with open(tmp_path / "out" / "dataset_statistics.csv", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        summary = [r for r in rows if r["feature"] == ""]
        assert {r["split"] for r in summary} >= {"train", "validation", "test", "all"}
        train_benign = next(
            r
            for r in summary
            if r["split"] == "train" and r["label"] == "benign"
        )
        assert int(train_benign["count"]) > 0
        assert train_benign["source_dataset"] == "tests"
        assert train_benign["parser_status"]
        feature_rows = [r for r in rows if r["feature"]]
        assert {r["feature"] for r in feature_rows} == set(
            prepare_dataset.TRAINING_FEATURES
        )

    def test_readme_documents_label_mapping(self, corpus: Path, tmp_path: Path):
        _run_pipeline(corpus, tmp_path / "out")
        readme = (tmp_path / "out" / "README_DATASET.txt").read_text(encoding="utf-8")
        assert 'malicious/ -> "suspicious"' in readme
        assert "No DNS" in readme or "NO DNS" in readme


# ---------------------------------------------------------------------------
# Quality report.
# ---------------------------------------------------------------------------


class TestQualityReport:
    def test_report_contains_all_required_fields(self, corpus: Path, tmp_path: Path):
        quality = _run_pipeline(corpus, tmp_path / "out")
        for field in (
            "total_files_discovered",
            "successfully_parsed",
            "failed_parses",
            "benign_count",
            "suspicious_count",
            "exact_sha_duplicate_count",
            "structural_duplicate_group_count",
            "exact_overlap_train_validation",
            "exact_overlap_train_test",
            "exact_overlap_validation_test",
            "structural_overlap_train_validation",
            "structural_overlap_train_test",
            "structural_overlap_validation_test",
            "missing_required_features",
            "invalid_labels",
            "invalid_feature_values",
            "split_sizes",
            "class_distribution",
            "leakage_checks_passed",
            "overall_result",
        ):
            assert field in quality, field

    def test_clean_run_passes(self, corpus: Path, tmp_path: Path):
        quality = _run_pipeline(corpus, tmp_path / "out")
        assert quality["leakage_checks_passed"] is True
        assert quality["feature_contract_passed"] is True
        assert quality["overall_result"] == "PASS"
        assert quality["warnings"] == []

    def test_leakage_overlaps_are_zero(self, corpus: Path, tmp_path: Path):
        quality = _run_pipeline(corpus, tmp_path / "out")
        for field in (
            "exact_overlap_train_validation",
            "exact_overlap_train_test",
            "exact_overlap_validation_test",
            "structural_overlap_train_validation",
            "structural_overlap_train_test",
            "structural_overlap_validation_test",
        ):
            assert quality[field] == 0, field

    def test_contract_violation_fails_the_build(self, corpus, tmp_path, monkeypatch):
        def broken_projection(_vector):
            features = dict.fromkeys(prepare_dataset.TRAINING_FEATURES, 0.0)
            features["url.https_ratio"] = 42.0  # invalid ratio
            return features

        monkeypatch.setattr(
            prepare_dataset, "project_training_features", broken_projection
        )
        with pytest.raises(SystemExit, match="contract"):
            _run_pipeline(corpus, tmp_path / "out")


# ---------------------------------------------------------------------------
# Manifest.
# ---------------------------------------------------------------------------


class TestManifest:
    def test_manifest_parses_as_yaml_and_records_provenance(
        self, corpus: Path, tmp_path: Path
    ):
        yaml = pytest.importorskip("yaml")
        _run_pipeline(corpus, tmp_path / "out")
        manifest = yaml.safe_load(
            (tmp_path / "out" / "dataset_manifest.yaml").read_text(encoding="utf-8")
        )
        assert manifest["preparation_version"] == prepare_dataset.PREPARATION_VERSION
        assert manifest["random_seed"] == 42
        assert manifest["feature_contract_version"] == "raw_eml_30_v1"
        assert manifest["training_features"] == list(
            prepare_dataset.TRAINING_FEATURES
        )
        assert manifest["label_mapping"] == {
            "benign": "benign",
            "malicious": "suspicious",
        }
        assert manifest["split_ratios"]["train"] == 0.7
        assert manifest["split_ratios"]["validation"] == 0.15
        assert manifest["split_ratios"]["test"] == 0.15
        assert manifest["counts"]["parsed"] == 40
        assert manifest["counts"]["train"] + manifest["counts"]["validation"] + manifest["counts"]["test"] == 40
        assert manifest["overall_result"] == "PASS"
        # Seven files are hashed; the manifest cannot contain its own hash.
        assert len(manifest["file_sha256"]) == 7

    def test_manifest_file_hashes_match_files(self, corpus: Path, tmp_path: Path):
        yaml = pytest.importorskip("yaml")
        _run_pipeline(corpus, tmp_path / "out")
        manifest = yaml.safe_load(
            (tmp_path / "out" / "dataset_manifest.yaml").read_text(encoding="utf-8")
        )
        for name, digest in manifest["file_sha256"].items():
            assert (
                hashlib.sha256((tmp_path / "out" / name).read_bytes()).hexdigest()
                == digest
            )

    def test_normalization_version_recorded(self, corpus: Path, tmp_path: Path):
        yaml = pytest.importorskip("yaml")
        _run_pipeline(corpus, tmp_path / "out")
        manifest = yaml.safe_load(
            (tmp_path / "out" / "dataset_manifest.yaml").read_text(encoding="utf-8")
        )
        assert prepare_dataset.NORMALIZATION_VERSION in manifest["normalization_method"]
