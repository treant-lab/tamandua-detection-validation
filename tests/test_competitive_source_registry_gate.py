from __future__ import annotations

import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import jsonschema
import pytest

from competitive_source_registry_gate import validate_governed_readiness, validate_registry


TEST_DIR = Path(__file__).resolve().parent
MONOREPO_ROOT = TEST_DIR.parents[2]
ROOT = (
    MONOREPO_ROOT
    if (MONOREPO_ROOT / "tools/detection_validation").is_dir()
    else TEST_DIR.parent
)
DETECTION_ROOT = (
    ROOT / "tools/detection_validation"
    if (ROOT / "tools/detection_validation").is_dir()
    else ROOT
)
FIXTURE = DETECTION_ROOT / "fixtures/competitive_source_registry_v1.json"
SCHEMA = ROOT / "schemas/competitive_source_registry_v1.schema.json"
SCRIPT = DETECTION_ROOT / "scripts/competitive_source_registry_gate.py"
AS_OF = date(2026, 7, 17)


def registry() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def errors_for(payload: dict, *, strict: bool = True) -> list[str]:
    return validate_registry(payload, as_of=AS_OF, strict=strict)


def approve_and_archive(source: dict, digest: str) -> None:
    if not (source["version"] or source["revision"]):
        source["revision"] = "test-pinned-revision"
    source["license_review"] = {
        "state": "approved",
        "reviewed_at": "2026-07-17",
        "notes": "Test-only approved review fixture.",
    }
    source["snapshot"].update(
        status="archived",
        immutable_uri=f"evidence://sha256/{digest}/{source['source_id']}",
        sha256=digest,
    )


def independent_measurement_for(
    vendor: dict,
    index: int,
    *,
    origin: str = "independent",
    covered_source_ids: list[str] | None = None,
) -> dict:
    measurement_id = f"SRC-LAB-MEAS-{index:03d}"
    snapshot_digest = f"{index:064x}"
    artifact_digest = f"{index + 1000:064x}"
    return {
        "source_id": measurement_id,
        "class": "measured",
        "canonical_url": f"https://lab.example.org/evidence/independent-run-{index:03d}",
        "product": f"Independent comparison run {index:03d}",
        "scope": f"Test-only measured evidence for {vendor['source_id']}",
        "retrieved_at": "2026-07-17",
        "version": "1.0.0",
        "revision": f"run-{index:03d}",
        "snapshot": {
            "status": "archived",
            "required_before_governed_comparison": True,
            "immutable_uri": f"evidence://sha256/{snapshot_digest}/{measurement_id}",
            "sha256": snapshot_digest,
        },
        "license_review": {
            "state": "approved",
            "reviewed_at": "2026-07-17",
            "notes": "Test-only approved independent evidence.",
        },
        "permitted_use": "measurement",
        "comparison_category": vendor["comparison_category"],
        "protocol_id": vendor["protocol_id"],
        "measurement_origin": origin,
        "covers_source_ids": covered_source_ids or [vendor["source_id"]],
        "measurement_scope": {
            "category": vendor["comparison_category"],
            "protocol_id": vendor["protocol_id"],
            "artifact_digests": [artifact_digest],
        },
        "independent_measurement_source_ids": [],
        "next_review_at": "2026-10-15",
    }


def test_official_registry_matches_schema_and_strict_gate() -> None:
    payload = registry()
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(payload)

    assert len(payload["sources"]) == 35
    assert errors_for(payload) == []


def test_new_edr_mobile_and_instrumentation_sources_are_explicitly_unready() -> None:
    payload = registry()
    by_id = {source["source_id"]: source for source in payload["sources"]}
    vendor_ids = {
        "SRC-CS-FALCON-001", "SRC-CS-ENDPOINT-001", "SRC-S1-XDR-001",
        "SRC-S1-ENDPOINT-001", "SRC-MS-MDE-001", "SRC-MS-XDR-001",
        "SRC-PAN-XDR-001", "SRC-PAN-XQL-001", "SRC-APPDOME-SUITE-001",
        "SRC-APPDOME-OBF-001", "SRC-VMX-XTD-001",
    }
    normative_ids = {
        "SRC-ANDROID-PROF-001", "SRC-ANDROID-POWER-001",
        "SRC-APPLE-XCT-001", "SRC-APPLE-METRICKIT-001",
    }

    assert vendor_ids | normative_ids <= by_id.keys()
    for source_id in vendor_ids:
        source = by_id[source_id]
        assert source["class"] == "vendor_declared"
        assert source["permitted_use"] == "comparison_dimension"
        assert source["independent_measurement_source_ids"] == []
    for source_id in normative_ids:
        source = by_id[source_id]
        assert source["class"] == "normative"
        assert source["permitted_use"] == "normative_contract"
    for source_id in vendor_ids | normative_ids:
        source = by_id[source_id]
        assert source["retrieved_at"] == "2026-07-17"
        assert source["snapshot"]["status"] == "live"
        assert source["snapshot"]["sha256"] is None
        assert source["license_review"]["state"] == "pending"
        assert source["covers_source_ids"] == []
        assert source["measurement_scope"] is None


def test_current_vendor_ownership_and_primary_pages_are_pinned() -> None:
    by_id = {source["source_id"]: source for source in registry()["sources"]}

    xtd = by_id["SRC-VMX-XTD-001"]
    assert xtd["product"] == "Guardsquare XTD"
    assert xtd["canonical_url"] == "https://www.guardsquare.com/xtd"
    assert "historical compatibility alias" in xtd["scope"]

    appdome = by_id["SRC-APPDOME-SUITE-001"]
    assert appdome["canonical_url"] == (
        "https://www.appdome.com/mobile-app-security/mobile-rasp-and-app-shielding/"
    )

    sentinelone = by_id["SRC-S1-ENDPOINT-001"]
    assert sentinelone["canonical_url"] == (
        "https://www.sentinelone.com/platform/endpoint-protection-platform/"
    )
    assert "platform-specific scope" in sentinelone["scope"]


def test_strict_cli_passes_offline() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(FIXTURE), "--strict", "--as-of", AS_OF.isoformat()],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "STRUCTURAL PASS (35 sources)" in completed.stdout
    assert "not a governed-comparison readiness claim" in completed.stdout


def test_strict_cli_uses_canonical_fixture_by_default() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--strict", "--as-of", AS_OF.isoformat()],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_governed_ready_fails_honest_fixture_with_explicit_blockers() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--governed-ready", "--as-of", AS_OF.isoformat()],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 3
    assert "GOVERNED NOT READY" in completed.stderr
    assert "pinned version or revision required" in completed.stderr
    assert "license/EULA review must be approved" in completed.stderr
    assert "immutable archived snapshot required" in completed.stderr
    assert "immutable snapshot SHA-256 required" in completed.stderr
    assert "independent measured evidence required" in completed.stderr


def test_governed_ready_accepts_approved_archived_sources_and_independent_measurement(
    tmp_path: Path,
) -> None:
    payload = registry()
    measurements = []
    measurement_index = 1
    for source_index, source in enumerate(payload["sources"], start=1):
        approve_and_archive(source, f"{source_index + 100:064x}")
        if source["class"] == "vendor_declared":
            measured = independent_measurement_for(source, measurement_index)
            source["independent_measurement_source_ids"] = [measured["source_id"]]
            measurements.append(measured)
            measurement_index += 1
    payload["sources"].extend(measurements)
    path = tmp_path / "governed-ready.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(path), "--governed-ready", "--as-of", AS_OF.isoformat()],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "GOVERNED READY (65 sources)" in completed.stdout


def test_rejects_duplicate_source_id() -> None:
    payload = registry()
    payload["sources"][1]["source_id"] = payload["sources"][0]["source_id"]

    assert any("duplicate SRC-GSQ-DEX-001" in error for error in errors_for(payload))


@pytest.mark.parametrize("invalid_class", ["standards_declared", "observed", "Vendor"])
def test_rejects_invalid_classes(invalid_class: str) -> None:
    payload = registry()
    payload["sources"][0]["class"] = invalid_class

    assert any("invalid class" in error for error in errors_for(payload, strict=False))


def test_rejects_non_https_url() -> None:
    payload = registry()
    payload["sources"][0]["canonical_url"] = "http://example.test/source"

    assert any("valid HTTPS URL" in error for error in errors_for(payload))


@pytest.mark.parametrize("url", ["https://", "https://localhost/path", "https://example.com"])
def test_rejects_https_without_public_host_and_path(url: str) -> None:
    payload = registry()
    payload["sources"][0]["canonical_url"] = url

    assert any("valid HTTPS URL with public host and path required" in error for error in errors_for(payload))


@pytest.mark.parametrize("field", ["version", "revision"])
def test_rejects_unpinned_latest(field: str) -> None:
    payload = registry()
    payload["sources"][0][field] = "latest"

    assert any("latest is not an immutable pin" in error for error in errors_for(payload))


def test_rejects_latest_url_without_version_or_revision() -> None:
    payload = registry()
    payload["sources"][0]["canonical_url"] = "https://example.test/latest/source"

    assert any("requires pinned version or revision" in error for error in errors_for(payload))


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("retrieved_at", "2026-07-18", "cannot be in the future"),
        ("next_review_at", "2026-07-17", "review is due or expired"),
        ("next_review_at", "16/07/2026", "invalid ISO date"),
    ],
)
def test_rejects_invalid_or_expired_dates(field: str, value: str, expected: str) -> None:
    payload = registry()
    payload["sources"][0][field] = value

    assert any(expected in error for error in errors_for(payload))


def test_rejects_unbounded_review_window() -> None:
    payload = registry()
    payload["sources"][0]["next_review_at"] = "2027-07-17"

    assert any("review window must be 1-92 days" in error for error in errors_for(payload))


def test_archived_source_requires_immutable_uri_and_digest() -> None:
    payload = registry()
    payload["sources"][0]["snapshot"]["status"] = "archived"

    errors = errors_for(payload)
    assert any("digest required for archived/measured" in error for error in errors)
    assert any("required for archived evidence" in error for error in errors)


def test_snapshot_requirement_cannot_be_disabled() -> None:
    payload = registry()
    payload["sources"][0]["snapshot"]["required_before_governed_comparison"] = False

    assert any("immutable snapshot must be required" in error for error in errors_for(payload))


def test_measured_source_requires_digest() -> None:
    payload = registry()
    source = payload["sources"][0]
    source["class"] = "measured"
    source["permitted_use"] = "measurement"

    assert any("digest required for archived/measured" in error for error in errors_for(payload))


def test_vendor_declaration_cannot_be_treated_as_measurement() -> None:
    payload = registry()
    payload["sources"][0]["permitted_use"] = "measurement"

    assert any("vendor_declared source cannot be treated as measured evidence" in error for error in errors_for(payload))


def test_internal_measurement_does_not_satisfy_independent_evidence() -> None:
    payload = registry()
    digest = "b" * 64
    vendor = payload["sources"][0]
    approve_and_archive(vendor, digest)
    measured = independent_measurement_for(vendor, 1, origin="internal")
    vendor["independent_measurement_source_ids"] = [measured["source_id"]]
    payload["sources"] = [vendor, measured]

    blockers = validate_governed_readiness(payload)

    assert any("independent measured evidence required" in blocker for blocker in blockers)


def test_rejects_measured_source_covering_missing_source() -> None:
    payload = registry()
    measured = independent_measurement_for(payload["sources"][0], 1)
    measured["covers_source_ids"] = ["SRC-NOT-FOUND-001"]
    payload["sources"].append(measured)

    assert any("source SRC-NOT-FOUND-001 is missing" in error for error in errors_for(payload))


def test_rejects_measured_source_covering_itself_or_another_measurement() -> None:
    payload = registry()
    vendor = payload["sources"][0]
    first = independent_measurement_for(vendor, 1)
    second = independent_measurement_for(vendor, 2)
    first["covers_source_ids"] = [first["source_id"]]
    second["covers_source_ids"] = [first["source_id"]]
    payload["sources"].extend([first, second])

    errors = errors_for(payload)
    assert any("measured source cannot cover itself" in error for error in errors)
    assert any("must be vendor_declared or normative" in error for error in errors)


def test_rejects_measurement_category_and_protocol_mismatch() -> None:
    payload = registry()
    vendor = next(
        source for source in payload["sources"] if source["source_id"] == "SRC-CS-FALCON-001"
    )
    unrelated = next(
        source for source in payload["sources"] if source["source_id"] == "SRC-GOOG-ING-001"
    )
    measured = independent_measurement_for(vendor, 1, covered_source_ids=[unrelated["source_id"]])
    payload["sources"].append(measured)

    assert any("category/protocol mismatch" in error for error in errors_for(payload))


def test_rejects_unrelated_measurement_reference_even_with_compatible_protocol() -> None:
    payload = registry()
    first = payload["sources"][0]
    second = payload["sources"][1]
    measured = independent_measurement_for(second, 1)
    first["independent_measurement_source_ids"] = [measured["source_id"]]
    payload["sources"].append(measured)

    assert any(
        f"does not cover {first['source_id']}" in error for error in errors_for(payload)
    )


def test_governed_ready_rejects_one_measurement_reused_for_multiple_vendors() -> None:
    payload = registry()
    first = payload["sources"][0]
    second = payload["sources"][1]
    approve_and_archive(first, "1" * 64)
    approve_and_archive(second, "2" * 64)
    measured = independent_measurement_for(
        first, 1, covered_source_ids=[first["source_id"], second["source_id"]]
    )
    first["independent_measurement_source_ids"] = [measured["source_id"]]
    second["independent_measurement_source_ids"] = [measured["source_id"]]
    payload["sources"] = [first, second, measured]

    assert errors_for(payload, strict=False) == []
    blockers = validate_governed_readiness(payload)
    assert sum("reused across vendor sources" in blocker for blocker in blockers) == 2
    assert sum("independent measured evidence required" in blocker for blocker in blockers) == 2


def test_rejects_measurement_without_pinned_artifact_digest() -> None:
    payload = registry()
    measured = independent_measurement_for(payload["sources"][0], 1)
    measured["measurement_scope"]["artifact_digests"] = []
    payload["sources"].append(measured)

    assert any("artifact_digests: non-empty array required" in error for error in errors_for(payload))


def test_completed_license_review_requires_review_date() -> None:
    payload = registry()
    payload["sources"][0]["license_review"]["state"] = "approved"

    assert any("required after review" in error for error in errors_for(payload))


def test_strict_mode_rejects_missing_official_source() -> None:
    payload = registry()
    removed = payload["sources"].pop()

    errors = errors_for(payload)
    assert any("strict official source set mismatch" in error and removed["source_id"] in error for error in errors)


def test_strict_mode_rejects_missing_new_edr_source() -> None:
    payload = registry()
    missing_id = "SRC-CS-FALCON-001"
    payload["sources"] = [source for source in payload["sources"] if source["source_id"] != missing_id]

    errors = errors_for(payload)

    assert any("strict official source set mismatch" in error and missing_id in error for error in errors)


def test_rejects_source_count_over_limit() -> None:
    payload = registry()
    payload["sources"].extend(payload["sources"][0].copy() for _ in range(257 - 35))

    assert any("maximum 256 entries exceeded" in error for error in errors_for(payload, strict=False))


def test_rejects_oversized_source_text() -> None:
    payload = registry()
    payload["sources"][0]["product"] = "x" * 201

    assert any("product: exceeds 200 characters" in error for error in errors_for(payload))


def test_cli_rejects_registry_over_file_size_limit(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_text(" " * 1_048_577, encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(path), "--strict", "--as-of", AS_OF.isoformat()],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 2
    assert "file exceeds 1048576 bytes" in completed.stderr


def test_every_record_exposes_governance_fields_without_implicit_defaults() -> None:
    payload = registry()
    required = {
        "version", "revision", "snapshot", "license_review", "permitted_use",
        "comparison_category", "protocol_id", "measurement_origin", "covers_source_ids",
        "measurement_scope", "independent_measurement_source_ids", "next_review_at"
    }

    assert all(required <= source.keys() for source in payload["sources"])
    assert all(source["license_review"]["state"] == "pending" for source in payload["sources"])
