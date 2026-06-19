#!/usr/bin/env python3
"""Read-only CALDERA PAW readiness probe for Roadmap D.

The probe intentionally does not create, stop, or modify CALDERA operations.
It only checks whether the CALDERA API is reachable and whether a fresh target
PAW exists before upstream CALDERA benchmarks are allowed to run.
"""

from __future__ import annotations

import argparse
import email.utils
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "caldera-paw-readiness-probe"
PROFILE_NAME = "CALDERA PAW Readiness Probe"
DEFAULT_CALDERA_URL = "http://192.168.12.146:8888"
DEFAULT_GROUP = "tamandua-lab"
DEFAULT_FRESHNESS_SECONDS = 300


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_http_date(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(str(value))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.strip()
        except OSError:
            return ""

    commit = run(["git", "rev-parse", "HEAD"])
    status = run(["git", "status", "--short"]).splitlines()
    return {
        "commit": commit,
        "commit_short": commit[:8] if commit else "",
        "dirty": bool(status),
        "status_short": status,
    }


def parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp > 10_000_000_000:
            timestamp = timestamp / 1000.0
        try:
            return datetime.fromtimestamp(timestamp, timezone.utc)
        except (OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    for suffix in ("Z", "z"):
        if text.endswith(suffix):
            text = text[:-1] + "+00:00"
            break
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def caldera_request(url: str, api_key: str | None, path: str, timeout: int) -> dict[str, Any]:
    full_url = url.rstrip("/") + path
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["KEY"] = api_key
    request = urllib.request.Request(full_url, headers=headers, method="GET")
    started = time.monotonic()
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=timeout) as response:
            raw = response.read().decode(errors="replace")
            body: Any = json.loads(raw) if raw.strip() else {}
            response_date = response.headers.get("Date")
            return {
                "url": full_url,
                "status": response.status,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "response_date": response_date,
                "server_time": iso(parse_http_date(response_date)) if parse_http_date(response_date) else None,
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        return {
            "url": full_url,
            "status": exc.code,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": raw[:1000],
        }
    except Exception as exc:
        return {
            "url": full_url,
            "status": None,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
        }


def looks_like_agent(candidate: dict[str, Any]) -> bool:
    return any(key in candidate for key in ("paw", "host", "host_name")) and any(
        key in candidate for key in ("group", "last_seen", "platform", "pid", "privilege")
    )


def agents_from_body(body: Any) -> list[dict[str, Any]]:
    """Extract CALDERA agents from common list, wrapper, or paw-keyed shapes."""

    found: list[dict[str, Any]] = []
    seen: set[int] = set()

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(value, list):
            for item in value:
                visit(item, depth + 1)
            return
        if not isinstance(value, dict):
            return
        marker = id(value)
        if marker in seen:
            return
        seen.add(marker)
        if looks_like_agent(value):
            found.append(value)
            return
        for key in ("agents", "data", "results", "objects", "paws"):
            if key in value:
                visit(value.get(key), depth + 1)
        for nested in value.values():
            if isinstance(nested, (dict, list)):
                visit(nested, depth + 1)

    visit(body)
    return found


def agent_snapshot(agent: dict[str, Any], reference_now: datetime | None = None) -> dict[str, Any]:
    keys = (
        "paw",
        "group",
        "host",
        "host_name",
        "platform",
        "last_seen",
        "sleep_min",
        "sleep_max",
        "pid",
        "ppid",
        "privilege",
    )
    snapshot = {key: agent.get(key) for key in keys if key in agent}
    parsed = parse_timestamp(agent.get("last_seen"))
    if parsed is not None:
        now = reference_now or utc_now()
        snapshot["last_seen_age_seconds"] = max(0, int((now - parsed).total_seconds()))
    return snapshot


def make_result(
    test_id: str,
    name: str,
    passed: bool,
    category: str,
    evidence: dict[str, Any],
    missing: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": "none" if passed else category,
        "execution_class": "caldera_read_only_probe",
        "claim_level": "caldera_paw_readiness_claim_boundary",
        "executor_used": PROFILE_ID,
        "fallback_used": False,
        "upstream_backed": False,
        "validation_category": "caldera_paw_readiness",
        "coverage": {
            "telemetry": "not_expected",
            "fields": "ok" if passed else "missing",
            "detection": "not_expected",
            "alert": "not_expected",
            "correlation": "not_expected",
            "driver_raw": "not_expected",
            "timeline": "not_expected",
            "values": "ok" if passed else "missing",
        },
        "evidence": evidence,
        "missing_expected_fields": missing or [],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
        "observed_telemetry_alternative": [],
        "expected_telemetry_any": [],
    }


def next_action_hint(args: argparse.Namespace, tests: list[dict[str, Any]], passed: bool) -> dict[str, Any]:
    missing_readiness: list[str] = []
    required_env: list[str] = []
    blockers: list[str] = []
    target_snapshot: dict[str, Any] | None = None
    known_paws: list[dict[str, Any]] = []

    missing_map = {
        "caldera_api_key_present": "caldera_api_key",
        "caldera_api_agents_http_200": "caldera_agents_api",
        "caldera_agent_inventory_nonempty": "caldera_agent_inventory",
        "caldera_agent_paw_present": "target_paw_present",
        "caldera_agent_group_match": "target_paw_group",
        "caldera_agent_fresh": "target_paw_fresh",
    }
    for test in tests:
        if test.get("status") == "covered":
            continue
        test_id = str(test.get("id") or "")
        if test_id:
            blockers.append(test_id)
        evidence = test.get("evidence") if isinstance(test.get("evidence"), dict) else {}
        if isinstance(evidence.get("required_env"), str):
            required_env.append(str(evidence["required_env"]))
        if isinstance(evidence.get("target"), dict):
            target_snapshot = evidence["target"]
        if isinstance(evidence.get("known_paws"), list):
            known_paws = [
                value for value in evidence.get("known_paws") or [] if isinstance(value, dict)
            ]
        for missing in test.get("missing_expected_fields") or []:
            missing_readiness.append(missing_map.get(str(missing), str(missing)))

    if not args.caldera_agent_paw:
        missing_readiness.append("caldera_agent_paw_configured")
        required_env.append("CALDERA_AGENT_PAW")
    if args.caldera_group == DEFAULT_GROUP:
        required_env.append("CALDERA_GROUP")

    deduped_missing = sorted(dict.fromkeys(missing_readiness))
    deduped_required_env = sorted(dict.fromkeys(required_env or ["CALDERA_API_KEY"]))
    if passed:
        action = "CALDERA PAW readiness is green; run repeatability or enterprise profiles with this PAW before it goes stale."
    else:
        action = (
            "Set CALDERA_API_KEY and CALDERA_AGENT_PAW, start or re-enroll a fresh Sandcat in "
            f"group {args.caldera_group!r}, verify /api/v2/agents is readable, then rerun PAW readiness and repeatability."
        )
    return {
        "caldera_url": args.caldera_url,
        "requested_paw": args.caldera_agent_paw,
        "requested_group": args.caldera_group,
        "freshness_seconds": args.freshness_seconds,
        "missing_readiness": deduped_missing,
        "required_env": deduped_required_env,
        "blockers": blockers,
        "target": target_snapshot,
        "known_paws": known_paws[:10],
        "rerun_commands": [
            "python tools/detection_validation/caldera_paw_readiness_probe.py --output-dir docs/benchmarks/runs",
            "python tools/detection_validation/caldera_repeatability_probe.py --output-dir docs/benchmarks/runs",
        ],
        "action": action,
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now()
    api_key = args.caldera_api_key or os.getenv("CALDERA_API_KEY")
    if api_key:
        request = caldera_request(args.caldera_url, api_key, "/api/v2/agents", args.timeout_seconds)
    else:
        request = {
            "url": args.caldera_url.rstrip("/") + "/api/v2/agents",
            "status": None,
            "duration_ms": 0,
            "error": "missing_caldera_api_key",
            "required_env": "CALDERA_API_KEY",
            "api_key_supplied": False,
        }
    freshness_now = parse_http_date(request.get("response_date")) or utc_now()
    tests: list[dict[str, Any]] = []

    reachable = request.get("status") == 200
    tests.append(
        make_result(
            "caldera-api-agents-readable",
            "CALDERA /api/v2/agents is reachable through a read-only request",
            reachable,
            "infrastructure",
            {
                "url": request.get("url"),
                "status": request.get("status"),
                "duration_ms": request.get("duration_ms"),
                "error": request.get("error"),
                "required_env": request.get("required_env"),
                "api_key_supplied": bool(api_key),
                "server_time": request.get("server_time"),
            },
            [] if reachable else (["caldera_api_key_present", "caldera_api_agents_http_200"] if not api_key else ["caldera_api_agents_http_200"]),
        )
    )

    agents = agents_from_body(request.get("body")) if reachable else []
    known = [agent_snapshot(agent, freshness_now) for agent in agents[:25]]
    tests.append(
        make_result(
            "caldera-paw-inventory-nonempty",
            "CALDERA reports at least one Sandcat PAW",
            bool(agents),
            "infrastructure",
            {"agent_count": len(agents), "known_paws": known},
            [] if agents else ["caldera_agent_inventory_nonempty"],
        )
    )

    target = next((agent for agent in agents if str(agent.get("paw") or "") == str(args.caldera_agent_paw)), None)
    target_snapshot = agent_snapshot(target, freshness_now) if target else None
    target_exists = bool(target)
    tests.append(
        make_result(
            "caldera-target-paw-present",
            "Requested CALDERA PAW exists",
            target_exists,
            "infrastructure",
            {
                "requested_paw": args.caldera_agent_paw,
                "target": target_snapshot,
                "known_paws": known,
            },
            [] if target_exists else ["caldera_agent_paw_present"],
        )
    )

    group_ok = False
    if target:
        group_ok = not args.caldera_group or str(target.get("group") or "") == str(args.caldera_group)
    tests.append(
        make_result(
            "caldera-target-paw-group",
            "Requested CALDERA PAW is in the expected group",
            target_exists and group_ok,
            "infrastructure",
            {
                "requested_group": args.caldera_group,
                "actual_group": target.get("group") if target else None,
                "requested_paw": args.caldera_agent_paw,
            },
            [] if target_exists and group_ok else ["caldera_agent_group_match"],
        )
    )

    fresh = False
    age_seconds: int | None = None
    if target:
        parsed = parse_timestamp(target.get("last_seen"))
        if parsed is not None:
            age_seconds = max(0, int((freshness_now - parsed).total_seconds()))
            fresh = args.freshness_seconds < 0 or age_seconds <= args.freshness_seconds
    tests.append(
        make_result(
            "caldera-target-paw-fresh",
            "Requested CALDERA PAW is fresh enough for upstream operation execution",
            target_exists and fresh,
            "infrastructure",
            {
                "requested_paw": args.caldera_agent_paw,
                "last_seen": target.get("last_seen") if target else None,
                "last_seen_age_seconds": age_seconds,
                "freshness_reference_time": iso(freshness_now),
                "freshness_seconds": args.freshness_seconds,
            },
            [] if target_exists and fresh else ["caldera_agent_fresh"],
        )
    )

    passed = all(test["status"] == "covered" for test in tests)
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    finished = utc_now()
    run_id_value = finished.strftime("%Y%m%dT%H%M%SZ") + f"-{PROFILE_ID}"

    return {
        "schema_version": 1,
        "run_id": run_id_value,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "name": PROFILE_NAME,
        "mode": "execute",
        "benchmark_lane": "claim-boundary",
        "started_at": iso(started),
        "finished_at": iso(finished),
        "git": git_snapshot(),
        "summary": {
            "tests": len(tests),
            "covered": covered,
            "missed": missed,
            "partial": 0,
            "execution_failed": 0,
            "unknown_source_events": 0,
            "unexpected_high_or_critical_events": 0,
            "unexpected_high_or_critical_alerts": 0,
            "missing_expected_fields": sum(len(test.get("missing_expected_fields") or []) for test in tests),
            "gap_category_counts": {
                category: sum(1 for test in tests if test["gap_category"] == category)
                for category in sorted({test["gap_category"] for test in tests if test["gap_category"] != "none"})
            },
            "executor_counts": {PROFILE_ID: len(tests)},
            "claim_level_counts": {"caldera_paw_readiness_claim_boundary": len(tests)},
            "category_coverage": {"caldera_paw_readiness": {"covered": covered, "missed": missed}},
            "roadmap_coverage": {"D": {"covered": covered, "missed": missed}},
        },
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["caldera_paw_readiness_gaps"],
            "actionable_gaps": [
                {
                    "test_id": test["id"],
                    "gap_category": test["gap_category"],
                    "missing": test.get("missing_expected_fields") or [],
                    "evidence": test.get("evidence") or {},
                }
                for test in tests
                if test["status"] != "covered"
            ],
            "gap_category_counts": {
                category: sum(1 for test in tests if test["gap_category"] == category)
                for category in sorted({test["gap_category"] for test in tests if test["gap_category"] != "none"})
            },
            "thresholds": {
                "requires_agents_api_http_200": True,
                "requires_target_paw_present": True,
                "requires_target_group_match": bool(args.caldera_group),
                "freshness_seconds": args.freshness_seconds,
            },
        },
        "caldera_paw_readiness": {
            "ready_for_caldera_execution": passed,
            "next_action": next_action_hint(args, tests, passed),
        },
        "scorecard": {
            "maturity_score": 100 if passed else max(20, int((covered / max(1, len(tests))) * 80)),
            "maturity_band": "caldera-paw-ready" if passed else "caldera-paw-blocked",
            "recommended_claim": (
                "CALDERA PAW is fresh enough for bounded upstream operation execution"
                if passed
                else "CALDERA upstream execution remains infrastructure-blocked until a fresh target PAW is available"
            ),
            "external_claim_allowed": False,
            "blocking_gaps": [] if passed else ["caldera_paw_readiness_missing"],
            "covered_rate": covered / max(1, len(tests)),
            "telemetry_rate": 1.0,
            "field_quality": 1.0 if passed else 0.0,
            "context_quality": 1.0 if passed else 0.0,
            "analytic_quality": 1.0,
            "noise_quality": 1.0,
            "driver_quality": 1.0,
            "upstream_rate": 0.0,
        },
        "tests": tests,
    }


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        f"- Covered: `{report['summary']['covered']}/{report['summary']['tests']}`",
        "",
        "## Results",
        "",
        "| Test | Status | Gap | Evidence | Missing |",
        "|------|--------|-----|----------|---------|",
    ]
    for test in report["tests"]:
        evidence = test.get("evidence") or {}
        summary = []
        for key in ("status", "error", "required_env", "agent_count", "requested_paw", "actual_group", "last_seen_age_seconds"):
            if key in evidence:
                summary.append(f"{key}={evidence.get(key)}")
        missing = ", ".join(test.get("missing_expected_fields") or []) or "-"
        lines.append(
            f"| `{test['id']}` | `{test['status']}` | `{test['gap_category']}` | "
            f"`{'; '.join(summary) or '-'}` | `{missing}` |"
        )
    action = (report.get("caldera_paw_readiness") or {}).get("next_action") or {}
    if action:
        lines.extend(
            [
                "",
                "## Next Action",
                "",
                f"- CALDERA URL: `{action.get('caldera_url') or '-'}`",
                f"- Requested PAW: `{action.get('requested_paw') or '-'}`",
                f"- Requested group: `{action.get('requested_group') or '-'}`",
                f"- Missing readiness: `{', '.join(action.get('missing_readiness') or []) or '-'}`",
                f"- Required env: `{', '.join(action.get('required_env') or []) or '-'}`",
                f"- Action: {action.get('action') or '-'}",
            ]
        )
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "This artifact is a read-only CALDERA readiness gate. It does not create operations, "
            "does not execute abilities, and does not prove endpoint detection.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=PROFILE_NAME)
    parser.add_argument("--caldera-url", default=os.getenv("CALDERA_URL", DEFAULT_CALDERA_URL))
    parser.add_argument("--caldera-api-key", default=os.getenv("CALDERA_API_KEY"))
    parser.add_argument("--caldera-agent-paw", default=os.getenv("CALDERA_AGENT_PAW", ""))
    parser.add_argument("--caldera-group", default=os.getenv("CALDERA_GROUP", DEFAULT_GROUP))
    parser.add_argument(
        "--freshness-seconds",
        type=int,
        default=int(os.getenv("CALDERA_AGENT_FRESHNESS_SECONDS", str(DEFAULT_FRESHNESS_SECONDS))),
    )
    parser.add_argument("--timeout-seconds", type=int, default=int(os.getenv("CALDERA_PROBE_TIMEOUT_SECONDS", "20")))
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id_value = report["run_id"]
    json_path = output_dir / f"{run_id_value}.json"
    comparison_path = output_dir / f"{run_id_value}.comparison.json"
    md_path = output_dir / f"{run_id_value}.md"
    payload = json.dumps(report, indent=2, sort_keys=True)
    json_path.write_text(payload, encoding="utf-8")
    comparison_path.write_text(payload, encoding="utf-8")
    write_markdown(report, md_path)
    print(f"caldera_paw_readiness={'ok' if report['quality_gate']['passed'] else 'gaps'} json={json_path} markdown={md_path}")
    return 0 if report["quality_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
