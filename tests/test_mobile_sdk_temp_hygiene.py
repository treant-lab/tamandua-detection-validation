from pathlib import Path
import sys

import pytest


TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS / "scripts"))

import mobile_sdk_temp_hygiene as hygiene  # noqa: E402
from mobile_sdk_temp_hygiene import find_hygiene_findings, validate_paths  # noqa: E402


REPO_ROOT = Path(__file__).resolve().parents[3]
SDK_MOBILE = REPO_ROOT / "sdk" / "mobile"


def test_mobile_sdk_release_contract_does_not_create_tempdirs_inside_repo() -> None:
    source = (SDK_MOBILE / "scripts" / "validate_sdk_release_contract.py").read_text(encoding="utf-8")

    compact = "".join(source.split())
    assert "TemporaryDirectory(dir=ROOT)" not in compact


def test_mobile_sdk_temp_hygiene_rejects_sdk_mobile_tempdirs() -> None:
    findings = find_hygiene_findings([SDK_MOBILE / ".tmp-mobile-sdk-evidence" / "packet.json"])

    assert findings
    assert "temporary directory" in findings[0].reason


def test_mobile_sdk_temp_hygiene_rejects_evidence_tmp() -> None:
    findings = find_hygiene_findings([REPO_ROOT / "docs" / "benchmarks" / "runs" / "mobile-evidence.tmp"])

    assert findings
    assert "evidence .tmp" in findings[0].reason


def test_mobile_sdk_temp_hygiene_rejects_sensitive_log_filename() -> None:
    findings = find_hygiene_findings([REPO_ROOT / "docs" / "benchmarks" / "runs" / "secret-token.log"])

    assert findings
    assert "sensitive log" in findings[0].reason


def test_mobile_sdk_temp_hygiene_rejects_sensitive_log_content(tmp_path: Path) -> None:
    log = tmp_path / "run.log"
    log.write_text("Authorization: Bearer local-test-token\n", encoding="utf-8")

    findings = find_hygiene_findings([log])

    assert findings
    assert "sensitive values" in findings[0].reason


def test_mobile_sdk_temp_hygiene_rejects_env_backup_without_reading_secret_content() -> None:
    findings = find_hygiene_findings([REPO_ROOT / ".env.before-db-fix"])

    assert findings
    assert "environment/secret backup" in findings[0].reason


def test_mobile_sdk_temp_hygiene_allows_public_env_templates() -> None:
    findings = find_hygiene_findings([REPO_ROOT / ".env.example"])

    assert findings == []


def test_mobile_sdk_temp_hygiene_rejects_root_server_frontend_tmp_artifacts() -> None:
    findings = find_hygiene_findings([REPO_ROOT / ".tmp-server-frontend-publication-audit.json"])

    assert findings
    assert "server frontend temporary audit artifact" in findings[0].reason


def test_mobile_sdk_temp_hygiene_staged_blocks_new_temp_env_and_log(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hygiene,
        "staged_paths",
        lambda: [
            SDK_MOBILE / ".tmp-mobile-sdk-evidence" / "packet.json",
            REPO_ROOT / ".env.before-db-fix",
            REPO_ROOT / "docs" / "benchmarks" / "runs" / "secret-token.log",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        hygiene.main(["--staged"])

    message = str(exc_info.value)
    assert "SDK/mobile temporary directory path must not be committed" in message
    assert "environment/secret backup file must not be committed" in message
    assert "sensitive log filename must not be committed" in message


def test_mobile_sdk_temp_hygiene_tracked_allows_legacy_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hygiene,
        "tracked_paths",
        lambda: [
            REPO_ROOT / "apps" / "tamandua_server" / ".env.example.notifications",
            REPO_ROOT / "deploy" / "docker" / ".env.secrets.example",
            REPO_ROOT / ".tmp-server-frontend-publication-audit.json",
        ],
    )

    assert hygiene.main(["--tracked"]) == 0


def test_mobile_sdk_temp_hygiene_accepts_bounded_evidence_json(tmp_path: Path) -> None:
    report = tmp_path / "mobile-evidence.json"
    report.write_text('{"evidence_class": "synthetic_replay_contract"}\n', encoding="utf-8")

    validate_paths([report])
