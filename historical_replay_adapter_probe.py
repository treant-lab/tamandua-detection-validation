#!/usr/bin/env python3
"""Report-only historical replay adapter probe.

This is not the production TimescaleDB/Postgres replay executor. It uses a
temporary SQLite database to prove the persistence semantics required by
Roadmap P:

- persisted Event Envelope rows are replayed against D&R rules;
- matches are written only to retrospective replay result rows;
- existing live alert rows are byte-for-byte unchanged before and after replay;
- no endpoint action or response execution can occur.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "historical-replay-adapter-report-only"
PROFILE_NAME = "Historical Replay Adapter Report-Only"

DETECTION_RESPONSE = ROOT / "tools" / "detection_response"
sys.path.insert(0, str(DETECTION_RESPONSE))

from replay_report import replay  # noqa: E402


PAIRS = [
    ("suspicious-powershell-dry-run.yaml", "windows-process-create-envelope.json"),
    ("windows-certutil-encode-dry-run.yaml", "windows-certutil-encode-envelope.json"),
    ("windows-registry-run-key-dry-run.yaml", "windows-registry-run-key-envelope.json"),
    ("windows-regsvr32-proxy-dry-run.yaml", "windows-regsvr32-proxy-envelope.json"),
    ("windows-masquerade-outside-system32-dry-run.yaml", "windows-masquerade-envelope.json"),
    ("windows-c2-web-protocol-dry-run.yaml", "windows-c2-web-protocol-envelope.json"),
    ("blocked-lsass-kill-dry-run.yaml", "windows-lsass-process-envelope.json"),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.strip()
        except OSError:
            return ""

    commit = run(["git", "rev-parse", "HEAD"])
    status = run(["git", "status", "--short"]).splitlines()
    return {"commit": commit, "commit_short": commit[:8] if commit else "", "dirty": bool(status), "status_short": status}


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def row_hash(rows: list[sqlite3.Row]) -> str:
    payload = json.dumps([dict(row) for row in rows], sort_keys=True)
    return sha256_text(payload)


def init_db(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        create table event_envelopes (
          id text primary key,
          event_path text not null,
          payload_json text not null,
          observed_at text not null
        );
        create table live_alerts (
          id text primary key,
          title text not null,
          status text not null,
          severity text not null,
          payload_json text not null,
          updated_at text not null
        );
        create table retrospective_replay_runs (
          id text primary key,
          status text not null,
          started_at text not null,
          finished_at text
        );
        create table retrospective_replay_results (
          id text primary key,
          replay_run_id text not null,
          event_id text not null,
          rule_id text not null,
          matched integer not null,
          alert_created integer not null,
          response_executed integer not null,
          result_json text not null,
          foreign key(replay_run_id) references retrospective_replay_runs(id),
          foreign key(event_id) references event_envelopes(id)
        );
        """
    )


def seed_db(db: sqlite3.Connection) -> list[dict[str, Any]]:
    seeded: list[dict[str, Any]] = []
    for idx, (_rule_name, event_name) in enumerate(PAIRS, start=1):
        event_path = ROOT / "examples" / "detection_response" / "events" / event_name
        payload = event_path.read_text(encoding="utf-8")
        event = json.loads(payload)
        event_id = f"event-{idx:02d}-{sha256_text(event_name)[:10]}"
        db.execute(
            "insert into event_envelopes(id, event_path, payload_json, observed_at) values (?, ?, ?, ?)",
            (event_id, str(event_path.relative_to(ROOT)), payload, event["routing"]["observed_at"]),
        )
        seeded.append({"event_id": event_id, "event_name": event_name})

    for idx in range(1, 4):
        payload = {"existing": True, "ordinal": idx}
        db.execute(
            "insert into live_alerts(id, title, status, severity, payload_json, updated_at) values (?, ?, ?, ?, ?, ?)",
            (
                f"live-alert-{idx}",
                f"Existing live alert {idx}",
                "new" if idx < 3 else "closed",
                "medium",
                json.dumps(payload, sort_keys=True),
                "2026-06-01T00:00:00Z",
            ),
        )
    db.commit()
    return seeded


def live_alert_rows(db: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(db.execute("select * from live_alerts order by id"))


def run_replay(db: sqlite3.Connection, seeded: list[dict[str, Any]]) -> list[dict[str, Any]]:
    replay_run_id = "replay-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    db.execute(
        "insert into retrospective_replay_runs(id, status, started_at) values (?, ?, ?)",
        (replay_run_id, "running", utc_now()),
    )
    outputs: list[dict[str, Any]] = []
    for item, (rule_name, event_name) in zip(seeded, PAIRS):
        rule_path = ROOT / "examples" / "detection_response" / "rules" / rule_name
        event_path = ROOT / "examples" / "detection_response" / "events" / event_name
        result = replay(rule_path, event_path)
        result_id = f"result-{sha256_text(rule_name + event_name)[:16]}"
        db.execute(
            """
            insert into retrospective_replay_results(
              id, replay_run_id, event_id, rule_id, matched, alert_created,
              response_executed, result_json
            ) values (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result_id,
                replay_run_id,
                item["event_id"],
                result["rule"]["id"],
                1 if result["matched"] else 0,
                1 if result["alert_created"] else 0,
                1 if result["response_executed"] else 0,
                json.dumps(result, sort_keys=True),
            ),
        )
        outputs.append(
            {
                "result_id": result_id,
                "event_id": item["event_id"],
                "rule_id": result["rule"]["id"],
                "matched": result["matched"],
                "alert_created": result["alert_created"],
                "response_executed": result["response_executed"],
            }
        )
    db.execute("update retrospective_replay_runs set status = ?, finished_at = ? where id = ?", ("complete", utc_now(), replay_run_id))
    db.commit()
    return outputs


def test_result(test_id: str, name: str, covered: bool, evidence: dict[str, Any], gap: str | None = None) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if covered else "missed",
        "gap_category": None if covered else (gap or "historical-replay"),
        "validation_category": "historical_replay_adapter",
        "execution_class": "local_sqlite_report_only",
        "fallback_used": False,
        "claim_level": "historical_replay_report_only",
        "tactics": [],
        "techniques": [],
        "evidence": evidence,
        "missing_expected_fields": [] if covered else [gap or "historical-replay"],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def collect_tests() -> list[dict[str, Any]]:
    with TemporaryDirectory(prefix="tamandua-replay-") as tmp:
        db_path = Path(tmp) / "historical_replay.sqlite"
        db = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
        init_db(db)
        seeded = seed_db(db)
        before_rows = live_alert_rows(db)
        before_hash = row_hash(before_rows)
        outputs = run_replay(db, seeded)
        after_rows = live_alert_rows(db)
        after_hash = row_hash(after_rows)
        result_count = db.execute("select count(*) from retrospective_replay_results").fetchone()[0]
        live_alert_count = db.execute("select count(*) from live_alerts").fetchone()[0]
        replay_runs = db.execute("select count(*) from retrospective_replay_runs where status = 'complete'").fetchone()[0]
        db.close()

    all_matched = all(item["matched"] is True for item in outputs)
    no_alerts_created = all(item["alert_created"] is False for item in outputs)
    no_response = all(item["response_executed"] is False for item in outputs)
    immutable = before_hash == after_hash and len(before_rows) == len(after_rows)

    return [
        test_result(
            "historical-replay-seeds-event-envelopes",
            "Historical replay adapter seeds persisted Event Envelope rows",
            len(seeded) == len(PAIRS),
            {"seeded_events": seeded, "expected_count": len(PAIRS)},
            "event-envelope-seed",
        ),
        test_result(
            "historical-replay-writes-retrospective-results",
            "Historical replay writes one retrospective result per matched fixture",
            result_count == len(PAIRS) and replay_runs == 1 and all_matched,
            {"result_count": result_count, "expected_count": len(PAIRS), "replay_runs_complete": replay_runs, "outputs": outputs},
            "retrospective-result-storage",
        ),
        test_result(
            "historical-replay-does-not-create-live-alerts",
            "Historical replay never creates live alert rows",
            no_alerts_created and live_alert_count == 3,
            {"live_alert_count": live_alert_count, "alert_created_flags": [item["alert_created"] for item in outputs]},
            "live-alert-mutation",
        ),
        test_result(
            "historical-replay-live-alerts-immutable",
            "Historical replay leaves existing live alerts unchanged",
            immutable,
            {"before_hash": before_hash, "after_hash": after_hash, "before_count": len(before_rows), "after_count": len(after_rows)},
            "live-alert-immutability",
        ),
        test_result(
            "historical-replay-no-response-execution",
            "Historical replay never executes endpoint response",
            no_response,
            {"response_executed_flags": [item["response_executed"] for item in outputs]},
            "response-execution",
        ),
    ]


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gap_counts: dict[str, int] = {}
    gaps = []
    for test in tests:
        if test["status"] != "covered":
            gap = test["gap_category"] or "unknown"
            gap_counts[gap] = gap_counts.get(gap, 0) + 1
            gaps.append(test)
    return {
        "tests": len(tests),
        "covered": covered,
        "partial": 0,
        "missed": missed,
        "planned": 0,
        "execution_failed": 0,
        "unknown_source_events": 0,
        "unexpected_high_or_critical_events": 0,
        "unexpected_high_or_critical_alerts": 0,
        "missing_expected_fields": missed,
        "missing_expected_telemetry": 0,
        "missing_expected_driver_raw_events": 0,
        "investigable_alert_gaps": 0,
        "excluded_benchmark_setup_alerts": 0,
        "upstream_backed_tests": 0,
        "deterministic_command_tests": 0,
        "fallback_command_tests": 0,
        "executor_counts": {"historical_replay_adapter_probe": len(tests)},
        "execution_class_counts": {"local_sqlite_report_only": len(tests)},
        "claim_level_counts": {"historical_replay_report_only": len(tests)},
        "category_coverage": {"historical_replay_adapter": {"covered": covered, "missed": missed}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": gap_counts,
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    passed = summary["missed"] == 0
    return {
        "maturity_score": 86 if passed else int(62 * covered_rate),
        "maturity_band": "historical-replay-adapter-report-only-ready" if passed else "historical-replay-adapter-gaps",
        "recommended_claim": (
            "Historical replay persistence semantics are validated in a local report-only adapter; production DB replay still pending"
            if passed
            else "Historical replay adapter gaps exist; do not promote replay persistence claims"
        ),
        "external_claim_allowed": False,
        "covered_rate": covered_rate,
        "telemetry_rate": 1.0 if passed else covered_rate,
        "field_quality": 1.0 if passed else covered_rate,
        "context_quality": 1.0 if passed else covered_rate,
        "analytic_quality": 1.0 if passed else covered_rate,
        "noise_quality": 1.0,
        "driver_quality": 1.0,
        "upstream_rate": 0.0,
        "blocking_gaps": [] if passed else sorted(summary["gap_category_counts"].keys()),
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        f"- Covered: `{report['summary']['covered']}/{report['summary']['tests']}`",
        "- Scope: local SQLite adapter proving historical replay persistence semantics.",
        "- Runtime effect: none; no real DB, endpoint execution, live alert mutation, or response execution.",
        "",
        "| Test | Status | Gap |",
        "|------|--------|-----|",
    ]
    for test in report["tests"]:
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{test['gap_category'] or '-'}` |")
    lines.extend(["", "## Claim Boundary", "", report["claim_boundary"]])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    tests = collect_tests()
    summary = build_summary(tests)
    passed = summary["missed"] == 0
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "execute": True,
        "benchmark_lane": "telemetry-replay",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "multi",
            "quality_bar": {
                "purpose": "historical_replay_adapter_report_only",
                "requires_persisted_events": False,
                "requires_driver_health": False,
                "max_unknown_source_events": 0,
                "max_unexpected_high_critical": 0,
                "max_driver_channel_drops": 0,
                "max_driver_kernel_drops": 0,
            },
        },
        "selected_tests": [test["id"] for test in tests],
        "tests": tests,
        "summary": summary,
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["historical_replay_adapter_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "telemetry-replay",
                "fail_on_missed": True,
                "fail_on_partial": False,
                "max_unknown_source": 0,
                "max_unexpected_high_critical": 0,
                "max_driver_channel_drops": 0,
                "max_driver_kernel_drops": 0,
                "require_upstream": False,
            },
        },
        "scorecard": scorecard(summary),
        "claim_boundary": (
            "Validates historical replay persistence semantics in a local SQLite report-only adapter. It does not "
            "query production TimescaleDB/Postgres, does not prove tenant/RBAC controls, does not prove scheduled "
            "replay jobs, and does not execute endpoint response."
        ),
    }
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": True,
        "benchmark_lane": "telemetry-replay",
        "summary": summary,
        "quality_gate": report["quality_gate"],
        "scorecard": report["scorecard"],
        "tests": tests,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / f"{run_id}.json"
    comparison_path = args.output_dir / f"{run_id}.comparison.json"
    md_path = args.output_dir / f"{run_id}.md"
    write_json(json_path, report)
    write_json(comparison_path, comparison)
    write_markdown(md_path, report)
    print(f"json={json_path} markdown={md_path} comparison_json={comparison_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
