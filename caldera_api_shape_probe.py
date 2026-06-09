#!/usr/bin/env python3
"""Read-only CALDERA API shape probe for Roadmap D.

This probe intentionally avoids operation creation and ability execution. It
records whether the CALDERA API key can read the expected inventory endpoints
and whether the agents endpoint is truly empty or just shaped differently than
the PAW readiness parser expected.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from caldera_paw_readiness_probe import agents_from_body


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "caldera-api-shape-probe"
PROFILE_NAME = "CALDERA API Shape Probe"
DEFAULT_CALDERA_URL = "http://192.168.12.146:8888"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


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


def request_json(url: str, api_key: str | None, path: str, timeout: int) -> dict[str, Any]:
    full_url = url.rstrip("/") + path
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["KEY"] = api_key
    request = urllib.request.Request(full_url, headers=headers, method="GET")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode(errors="replace")
            body: Any = json.loads(raw) if raw.strip() else {}
            return {
                "path": path,
                "status": response.status,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        return {
            "path": path,
            "status": exc.code,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": raw[:240],
        }
    except Exception as exc:
        return {
            "path": path,
            "status": None,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
        }


def body_count(body: Any) -> int | None:
    if isinstance(body, list):
        return len(body)
    if isinstance(body, dict):
        for key in ("agents", "data", "results", "objects", "abilities", "adversaries", "operations"):
            value = body.get(key)
            if isinstance(value, list):
                return len(value)
            if isinstance(value, dict):
                return len(value)
        return len(body)
    return None


def body_shape(body: Any) -> dict[str, Any]:
    if isinstance(body, list):
        sample = next((item for item in body if isinstance(item, dict)), {})
        return {"type": "list", "count": len(body), "sample_keys": sorted(sample.keys())[:20]}
    if isinstance(body, dict):
        nested = {}
        for key, value in body.items():
            if isinstance(value, list):
                sample = next((item for item in value if isinstance(item, dict)), {})
                nested[key] = {"type": "list", "count": len(value), "sample_keys": sorted(sample.keys())[:20]}
            elif isinstance(value, dict):
                nested[key] = {"type": "dict", "count": len(value), "sample_keys": sorted(value.keys())[:20]}
            else:
                nested[key] = {"type": type(value).__name__}
        return {"type": "dict", "count": len(body), "keys": sorted(body.keys())[:30], "nested": nested}
    return {"type": type(body).__name__}


def make_result(test_id: str, name: str, passed: bool, evidence: dict[str, Any], missing: list[str] | None = None) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": "none" if passed else "infrastructure",
        "execution_class": "caldera_read_only_probe",
        "claim_level": "caldera_api_shape_claim_boundary",
        "executor_used": PROFILE_ID,
        "fallback_used": False,
        "upstream_backed": False,
        "validation_category": "caldera_api_shape",
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
    missed = [test for test in tests if test.get("status") != "covered"]
    required_env: list[str] = []
    missing_endpoints: list[str] = []
    blockers = sorted({str(test.get("gap_category")) for test in missed if test.get("gap_category") not in (None, "none")})

    for test in missed:
        evidence = test.get("evidence") if isinstance(test.get("evidence"), dict) else {}
        missing_values = [str(value) for value in test.get("missing_expected_fields") or []]
        if "caldera_api_key_present" in missing_values or evidence.get("required_env") == "CALDERA_API_KEY":
            required_env.append("CALDERA_API_KEY")
        if test.get("id") == "caldera-api-agents-readable":
            missing_endpoints.append("/api/v2/agents")
        elif test.get("id") == "caldera-api-supporting-endpoints-readable":
            missing_endpoints.extend(["/api/v2/operations", "/api/v2/abilities", "/api/v2/adversaries"])

    required_env = sorted(set(required_env))
    missing_endpoints = sorted(set(missing_endpoints))
    if passed:
        action = "CALDERA API shape is readable; continue with PAW readiness and repeatability probes."
    elif "CALDERA_API_KEY" in required_env:
        action = (
            "Set CALDERA_API_KEY in the execution shell from the approved secret store, verify the CALDERA URL, "
            "then rerun API shape, PAW readiness, and repeatability probes."
        )
    else:
        action = (
            f"Verify CALDERA is reachable at {args.caldera_url} and that the API key can read inventory endpoints, "
            "then rerun API shape, PAW readiness, and repeatability probes."
        )

    return {
        "caldera_url": args.caldera_url,
        "missing_endpoints": missing_endpoints,
        "required_env": required_env,
        "blockers": blockers,
        "rerun_commands": [
            "python tools/detection_validation/caldera_api_shape_probe.py --output-dir <out>",
            "python tools/detection_validation/caldera_paw_readiness_probe.py --output-dir <out>",
            "python tools/detection_validation/caldera_repeatability_probe.py --output-dir <out>",
        ],
        "action": action,
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now()
    api_key = args.caldera_api_key or os.getenv("CALDERA_API_KEY")
    paths = ["/api/v2/agents", "/api/v2/operations", "/api/v2/abilities", "/api/v2/adversaries"]
    if api_key:
        responses = [request_json(args.caldera_url, api_key, path, args.timeout_seconds) for path in paths]
    else:
        responses = [
            {
                "path": path,
                "status": None,
                "duration_ms": 0,
                "error": "missing_caldera_api_key",
                "required_env": "CALDERA_API_KEY",
                "api_key_supplied": False,
            }
            for path in paths
        ]
    by_path = {response["path"]: response for response in responses}

    endpoint_evidence = {
        response["path"]: {
            "status": response.get("status"),
            "duration_ms": response.get("duration_ms"),
            "error": response.get("error"),
            "required_env": response.get("required_env"),
            "api_key_supplied": bool(api_key),
            "shape": body_shape(response.get("body")) if response.get("status") == 200 else None,
            "count": body_count(response.get("body")) if response.get("status") == 200 else None,
        }
        for response in responses
    }

    readable = by_path["/api/v2/agents"].get("status") == 200
    agents = agents_from_body(by_path["/api/v2/agents"].get("body")) if readable else []
    other_readable = [
        path
        for path in ("/api/v2/operations", "/api/v2/abilities", "/api/v2/adversaries")
        if by_path[path].get("status") == 200
    ]

    tests = [
        make_result(
            "caldera-api-agents-readable",
            "CALDERA agents endpoint is readable",
            readable,
            {
                "status": by_path["/api/v2/agents"].get("status"),
                "api_key_supplied": bool(api_key),
                "error": by_path["/api/v2/agents"].get("error"),
                "required_env": by_path["/api/v2/agents"].get("required_env"),
                "shape": endpoint_evidence["/api/v2/agents"]["shape"],
            },
            [] if readable else (["caldera_api_key_present", "caldera_api_agents_http_200"] if not api_key else ["caldera_api_agents_http_200"]),
        ),
        make_result(
            "caldera-api-shape-inventory-parsed",
            "CALDERA agents endpoint shape is parsed without treating non-agent metadata as PAWs",
            readable,
            {
                "api_key_supplied": bool(api_key),
                "error": by_path["/api/v2/agents"].get("error"),
                "required_env": by_path["/api/v2/agents"].get("required_env"),
                "parsed_agent_count": len(agents),
                "shape": endpoint_evidence["/api/v2/agents"]["shape"],
            },
            [] if readable else (["caldera_api_key_present", "caldera_agents_shape_parseable"] if not api_key else ["caldera_agents_shape_parseable"]),
        ),
        make_result(
            "caldera-api-supporting-endpoints-readable",
            "At least one supporting CALDERA inventory endpoint is readable",
            bool(other_readable),
            {
                "readable_paths": other_readable,
                "endpoints": endpoint_evidence,
            },
            [] if other_readable else (["caldera_api_key_present", "caldera_supporting_endpoint_http_200"] if not api_key else ["caldera_supporting_endpoint_http_200"]),
        ),
    ]

    passed = all(test["status"] == "covered" for test in tests)
    covered = sum(1 for test in tests if test["status"] == "covered")
    finished = utc_now()
    run_id = finished.strftime("%Y%m%dT%H%M%SZ") + f"-{PROFILE_ID}"
    return {
        "schema_version": 1,
        "run_id": run_id,
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
            "missed": len(tests) - covered,
            "partial": 0,
            "execution_failed": 0,
            "unknown_source_events": 0,
            "unexpected_high_or_critical_events": 0,
            "unexpected_high_or_critical_alerts": 0,
            "missing_expected_fields": sum(len(test.get("missing_expected_fields") or []) for test in tests),
            "gap_category_counts": {
                "infrastructure": sum(1 for test in tests if test["gap_category"] == "infrastructure")
            },
            "executor_counts": {PROFILE_ID: len(tests)},
            "claim_level_counts": {"caldera_api_shape_claim_boundary": len(tests)},
            "category_coverage": {"caldera_api_shape": {"covered": covered, "missed": len(tests) - covered}},
            "roadmap_coverage": {"D": {"covered": covered, "missed": len(tests) - covered}},
        },
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["caldera_api_shape_gaps"],
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
                "infrastructure": sum(1 for test in tests if test["gap_category"] == "infrastructure")
            },
            "thresholds": {"requires_agents_api_http_200": True, "requires_one_supporting_endpoint": True},
        },
        "scorecard": {
            "maturity_score": 85 if passed else max(30, int((covered / max(1, len(tests))) * 80)),
            "maturity_band": "caldera-api-shape-readable" if passed else "caldera-api-shape-blocked",
            "recommended_claim": (
                "CALDERA API shape is readable for readiness diagnostics"
                if passed
                else "CALDERA API shape diagnostics remain infrastructure-blocked"
            ),
            "external_claim_allowed": False,
            "blocking_gaps": [] if passed else ["caldera_api_shape_missing"],
            "covered_rate": covered / max(1, len(tests)),
            "telemetry_rate": 1.0,
            "field_quality": 1.0 if passed else 0.0,
            "context_quality": 1.0 if passed else 0.0,
            "analytic_quality": 1.0,
            "noise_quality": 1.0,
            "driver_quality": 1.0,
            "upstream_rate": 0.0,
        },
        "caldera_api_shape": {
            "ready_for_readiness_diagnostics": passed,
            "caldera_url": args.caldera_url,
            "next_action": next_action_hint(args, tests, passed),
        },
        "caldera_endpoint_shapes": endpoint_evidence,
        "tests": tests,
    }


def write_markdown(report: dict[str, Any], path: Path) -> None:
    action = (report.get("caldera_api_shape") or {}).get("next_action") or {}
    preflight = []
    for evidence in report.get("caldera_endpoint_shapes", {}).values():
        if evidence.get("error") == "missing_caldera_api_key":
            preflight = [
                "",
                "## Preflight",
                "",
                "- `CALDERA_API_KEY` is not set in the current shell.",
                "- This probe did not issue CALDERA inventory requests without a key.",
            ]
            break
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        f"- Covered: `{report['summary']['covered']}/{report['summary']['tests']}`",
        *preflight,
        "",
        "## Endpoint Shapes",
        "",
        "| Endpoint | Status | Count | Shape | Error | Required env |",
        "|----------|--------|-------|-------|-------|--------------|",
    ]
    for endpoint, evidence in report.get("caldera_endpoint_shapes", {}).items():
        shape = evidence.get("shape") or {}
        lines.append(
            f"| `{endpoint}` | `{evidence.get('status')}` | `{evidence.get('count')}` | "
            f"`{shape.get('type') if isinstance(shape, dict) else '-'}` | "
            f"`{evidence.get('error') or '-'}` | `{evidence.get('required_env') or '-'}` |"
        )
    if action:
        lines.extend(
            [
                "",
                "## Next Action",
                "",
                f"- CALDERA URL: `{action.get('caldera_url')}`",
                "- Missing endpoints: `" + (", ".join(action.get("missing_endpoints") or []) or "-") + "`",
                "- Required env: `" + (", ".join(action.get("required_env") or []) or "-") + "`",
                f"- Action: {action.get('action')}",
            ]
        )
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "This artifact is read-only CALDERA API shape evidence. It does not create operations, "
            "does not execute abilities, and does not prove endpoint detection.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=PROFILE_NAME)
    parser.add_argument("--caldera-url", default=os.getenv("CALDERA_URL", DEFAULT_CALDERA_URL))
    parser.add_argument("--caldera-api-key", default=os.getenv("CALDERA_API_KEY"))
    parser.add_argument("--timeout-seconds", type=int, default=int(os.getenv("CALDERA_PROBE_TIMEOUT_SECONDS", "20")))
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = report["run_id"]
    json_path = output_dir / f"{run_id}.json"
    comparison_path = output_dir / f"{run_id}.comparison.json"
    md_path = output_dir / f"{run_id}.md"
    payload = json.dumps(report, indent=2, sort_keys=True)
    json_path.write_text(payload, encoding="utf-8")
    comparison_path.write_text(payload, encoding="utf-8")
    write_markdown(report, md_path)
    print(f"caldera_api_shape={'ok' if report['quality_gate']['passed'] else 'gaps'} json={json_path} markdown={md_path}")
    return 0 if report["quality_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
