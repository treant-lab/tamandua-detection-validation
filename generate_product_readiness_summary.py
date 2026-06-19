#!/usr/bin/env python3
"""Generate a concise product-readiness blocker summary.

This report is intentionally derived from existing claim-boundary artifacts. It
does not run endpoint commands, contact services, inspect live alerts, or infer
readiness beyond the current closure/preflight/dispatch evidence.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
GENERATED_DIR = ROOT / "docs" / "benchmarks" / "generated"
SCORECARD_JSON = GENERATED_DIR / "validation_roadmap_scorecard.json"
PROFILE_CLOSURE = "roadmap-closure-gate-probe"
PROFILE_PREFLIGHT = "validation-execution-preflight-probe"
PROFILE_DISPATCH = "validation-dispatch-results-probe"
PROFILE_MACOS_BACKEND = "macos-backend-readiness-probe"
PROFILE_MACOS_RELEASE_ARTIFACT_PREFLIGHT = "macos-release-artifact-preflight"
MACOS_LAB_ACCESS_BOUNDARY = (
    "macOS lane is not a Proxmox VMID/QGA flow; use the approved Mac SSH/local access path "
    "and do not attempt qm/VMID remediation for this blocker."
)
MACOS_SIGNED_RELEASE_PREREQUISITE = (
    "Produce and deploy a macOS release app/DMG from the signed/notarized release workflow; "
    "the artifact preflight must pass with a bundled Contents/Library/SystemExtensions/*.systemextension "
    "and the workflow must have Apple signing/notarization secrets configured."
)
MACOS_ENDPOINT_APPROVAL_PREREQUISITE = (
    "On the approved Mac access path, install the signed/notarized app and confirm the Tamandua "
    "System Extension plus Full Disk Access approvals before rerunning backend readiness or P0 smoke."
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} root must be an object")
    return data


def latest_profile_path(scorecard: dict[str, Any], profile_id: str) -> Path | None:
    for profile in scorecard.get("profiles") or []:
        if not isinstance(profile, dict) or profile.get("profile_id") != profile_id:
            continue
        latest = profile.get("latest") if isinstance(profile.get("latest"), dict) else {}
        if latest.get("path"):
            path = Path(str(latest.get("path") or ""))
            return path if path.is_absolute() else ROOT / path
    return None


def compact_quality_gate(artifact: dict[str, Any] | None) -> dict[str, Any]:
    if not artifact:
        return {"run_id": None, "status": "missing", "coverage": None, "passed": False}
    gate = artifact.get("quality_gate") if isinstance(artifact.get("quality_gate"), dict) else {}
    summary = artifact.get("summary") if isinstance(artifact.get("summary"), dict) else {}
    passed = bool(gate.get("passed"))
    total = summary.get("total")
    covered = summary.get("covered")
    coverage = f"{covered}/{total}" if total is not None and covered is not None else None
    return {
        "run_id": artifact.get("run_id"),
        "status": gate.get("status") or ("pass" if passed else "fail"),
        "coverage": coverage,
        "passed": passed,
    }


def dispatch_gate(dispatch: dict[str, Any] | None) -> dict[str, Any]:
    if not dispatch:
        return {
            "run_id": None,
            "status": "missing",
            "coverage": None,
            "missing_count": None,
            "invalid_count": None,
        }
    summary = dispatch.get("summary") if isinstance(dispatch.get("summary"), dict) else {}
    total = summary.get("total") or dispatch.get("package_count")
    passed = summary.get("covered") or dispatch.get("passed_count") or 0
    failed = dispatch.get("failed_count")
    status = "pass" if dispatch.get("quality_gate", {}).get("passed") else "fail"
    return {
        "run_id": dispatch.get("run_id"),
        "status": status,
        "coverage": f"{passed}/{total}" if total is not None else None,
        "missing_count": dispatch.get("missing_count"),
        "invalid_count": dispatch.get("invalid_count"),
        "failed_count": failed,
    }


def load_optional_json(path: Path | None) -> dict[str, Any] | None:
    if not path or not path.exists():
        return None
    return load_json(path)


def preflight_package_dir(preflight_path: Path | None) -> Path | None:
    if not preflight_path:
        return None
    for ancestor in [preflight_path, *preflight_path.parents]:
        if ancestor.name.endswith(".package-artifacts") and ancestor.exists():
            return ancestor
    candidates = [
        preflight_path.with_suffix(".package-artifacts"),
        Path(f"{preflight_path}.package-artifacts"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def dispatch_package_dir(dispatch_path: Path | None) -> Path | None:
    if not dispatch_path:
        return None
    for ancestor in [dispatch_path, *dispatch_path.parents]:
        if ancestor.name.endswith(".package-artifacts") and ancestor.exists():
            return ancestor
    candidates = [
        dispatch_path.with_suffix(".package-artifacts"),
        Path(f"{dispatch_path}.package-artifacts"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def claim_counts(agent_claims: dict[str, Any] | None) -> dict[str, int]:
    if not agent_claims:
        return {
            "claim_count": 0,
            "ready_to_launch_count": 0,
            "blocked_missing_env_count": 0,
            "manual_claim_required_count": 0,
            "not_run_count": 0,
        }
    claims = [claim for claim in agent_claims.get("claims") or [] if isinstance(claim, dict)]
    unresolved_manual_claims = [
        claim
        for claim in claims
        if claim.get("claim_state") == "manual_claim_required"
        and not (
            claim.get("agent_status") == "pass"
            and claim.get("agent_blocker_cleared") is True
            and not claim.get("missing_profiles")
        )
    ]
    return {
        "claim_count": len(claims),
        "ready_to_launch_count": sum(1 for claim in claims if claim.get("ready_to_launch") is True),
        "blocked_missing_env_count": sum(1 for claim in claims if claim.get("claim_state") == "blocked_missing_env"),
        "manual_claim_required_count": len(unresolved_manual_claims),
        "not_run_count": sum(
            1
            for claim in claims
            if (claim.get("agent_status") or claim.get("current_status")) == "not_run"
        ),
    }


def merged_claims_payload(
    agent_claims_snapshot: dict[str, Any] | None,
    claim_status_report: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not agent_claims_snapshot:
        if not claim_status_report:
            return None
        payload = dict(claim_status_report)
        payload["claims"] = [
            normalized_claim_runtime_state(claim)
            for claim in payload.get("claims") or []
            if isinstance(claim, dict)
        ]
        return payload
    if not claim_status_report:
        payload = dict(agent_claims_snapshot)
        payload["claims"] = [
            normalized_claim_runtime_state(claim)
            for claim in payload.get("claims") or []
            if isinstance(claim, dict)
        ]
        return payload

    snapshot_claims = [
        claim for claim in agent_claims_snapshot.get("claims") or [] if isinstance(claim, dict)
    ]
    status_claims = [claim for claim in claim_status_report.get("claims") or [] if isinstance(claim, dict)]
    status_by_id = {str(claim.get("claim_id") or ""): claim for claim in status_claims if claim.get("claim_id")}

    merged_claims: list[dict[str, Any]] = []
    seen: set[str] = set()
    for claim in snapshot_claims:
        claim_id = str(claim.get("claim_id") or "")
        update = status_by_id.get(claim_id, {})
        merged = dict(claim)
        merged.update(update)
        merged_claims.append(merged)
        if claim_id:
            seen.add(claim_id)
    for claim in status_claims:
        claim_id = str(claim.get("claim_id") or "")
        if claim_id and claim_id not in seen:
            merged_claims.append(dict(claim))

    payload = dict(agent_claims_snapshot)
    payload["claims"] = [normalized_claim_runtime_state(claim) for claim in merged_claims]
    return payload


def normalized_claim_runtime_state(claim: dict[str, Any]) -> dict[str, Any]:
    """Prefer current agent_status evidence over the original launch queue state."""
    normalized = dict(claim)
    current_next_action = (
        normalized.get("current_next_action")
        if isinstance(normalized.get("current_next_action"), dict)
        else {}
    )
    missing_readiness = [
        str(value)
        for value in current_next_action.get("missing_readiness") or []
        if str(value)
    ]
    if missing_readiness and normalized.get("ready_to_launch") is True:
        blocked_reasons = [str(value) for value in normalized.get("blocked_reasons") or []]
        if "current_next_action_unresolved" not in blocked_reasons:
            blocked_reasons.append("current_next_action_unresolved")
        normalized["ready_to_launch"] = False
        normalized["claim_state"] = "manual_claim_required"
        normalized["blocked_reasons"] = blocked_reasons
        normalized["missing_readiness"] = missing_readiness

    agent_status = str(
        normalized.get("agent_status") or normalized.get("current_status") or ""
    ).strip()
    if agent_status not in {"pass", "fail", "blocked"}:
        return normalized

    normalized["ready_to_launch"] = False
    blocked_reasons = [str(value) for value in normalized.get("blocked_reasons") or []]
    if agent_status == "pass":
        if normalized.get("agent_blocker_cleared") is True and not normalized.get("missing_profiles"):
            normalized["claim_state"] = "has_current_pass_evidence"
        else:
            normalized["claim_state"] = "has_current_incomplete_pass_evidence"
            if "agent_status_incomplete" not in blocked_reasons:
                blocked_reasons.append("agent_status_incomplete")
    else:
        normalized["claim_state"] = f"has_current_{agent_status}_evidence"
        reason = f"agent_status_{agent_status}"
        if reason not in blocked_reasons:
            blocked_reasons.append(reason)
    normalized["blocked_reasons"] = blocked_reasons
    return normalized


def claim_digest(agent_claims: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not agent_claims:
        return []
    result = []
    for claim in agent_claims.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
        result.append(
            {
                "claim_id": claim.get("claim_id"),
                "package_id": claim.get("package_id"),
                "wave": claim.get("wave"),
                "owner": claim.get("owner"),
                "state": claim.get("claim_state"),
                "agent_status": claim.get("agent_status") or claim.get("current_status") or "",
                "agent_blocker_cleared": bool(claim.get("agent_blocker_cleared")),
                "ready_to_launch": bool(claim.get("ready_to_launch")),
                "missing_effective_env": claim.get("missing_effective_env") or [],
                "missing_profiles": claim.get("missing_profiles") or [],
                "blocked_reasons": claim.get("blocked_reasons") or [],
                "next_action": normalize_macos_smoke_next_action(str(action.get("action") or "")),
                "token_login_command": action.get("token_login_command") or "",
                "command": claim.get("command") or "",
                "script_path": claim.get("script_path") or "",
                "prompt_path": claim.get("prompt_path") or "",
            }
        )
    return sorted(result, key=lambda item: (int(item.get("wave") or 0), str(item.get("package_id") or "")))


def single_env_fast_paths(env_summary: dict[str, Any], claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    claim_by_id = {str(claim.get("claim_id") or ""): claim for claim in claims if claim.get("claim_id")}
    result = []
    for entry in env_summary.get("env_impact") or []:
        if not isinstance(entry, dict):
            continue
        ready_claim_ids = [str(value) for value in entry.get("single_env_ready_claim_ids") or [] if value]
        if not ready_claim_ids:
            continue
        commands = []
        set_command = str(entry.get("powershell_set_command") or "")
        if set_command:
            commands.append(set_command)
        token_login_commands = []
        package_commands = []
        package_ids = []
        for claim_id in ready_claim_ids:
            claim = claim_by_id.get(claim_id)
            if not claim:
                continue
            package_id = str(claim.get("package_id") or "")
            if package_id:
                package_ids.append(package_id)
            token_login_command = str(claim.get("token_login_command") or "")
            if token_login_command:
                token_login_commands.append(token_login_command)
            command = str(claim.get("command") or "")
            if command:
                package_commands.append(command)
        commands.extend(sorted(set(token_login_commands)))
        commands.extend(package_commands)
        result.append(
            {
                "env": entry.get("env"),
                "claim_ids": ready_claim_ids,
                "package_ids": sorted(set(package_ids or [str(value) for value in entry.get("package_ids") or []])),
                "commands": commands,
                "claim_boundary": (
                    "partial env fast path; executes only claims whose remaining blocker is this single env"
                ),
            }
        )
    return result


def env_queue_summary(env_queue: dict[str, Any] | None) -> dict[str, Any]:
    if not env_queue:
        return {
            "current_env_present_count": 0,
            "current_env_missing_count": 0,
            "current_env_missing_names": [],
            "env_impact": [],
            "all_env_powershell_set_commands": [],
            "env_bundle_validation_command": "",
            "post_env_bundle_launcher_commands": [],
            "post_env_bundle_balanced_agent_spawn_commands": [],
            "ready_after_all_env_claim_ids": [],
            "still_blocked_after_all_env_claim_ids": [],
        }
    env_set_commands = {}
    for command in env_queue.get("all_env_powershell_set_commands") or []:
        command_text = str(command)
        prefix = "$env:"
        if not command_text.startswith(prefix) or "=" not in command_text:
            continue
        env_name = command_text[len(prefix) : command_text.index("=")].strip()
        if env_name:
            env_set_commands[env_name] = command_text
    env_impact = []
    for entry in env_queue.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        env_name = str(entry.get("env") or "")
        if not env_name:
            continue
        env_impact.append(
            {
                "env": env_name,
                "claim_count": int(entry.get("claim_count") or 0),
                "immediate_claim_count": int(entry.get("immediate_claim_count") or 0),
                "dependency_claim_count": int(entry.get("dependency_claim_count") or 0),
                "manual_claim_count": int(entry.get("manual_claim_count") or 0),
                "single_env_ready_claim_ids": list(entry.get("single_env_ready_claim_ids") or []),
                "single_env_still_blocked_claim_ids": list(entry.get("single_env_still_blocked_claim_ids") or []),
                "immediate_claim_ids": list(entry.get("immediate_claim_ids") or []),
                "dependency_claim_ids": list(entry.get("dependency_claim_ids") or []),
                "manual_claim_ids": list(entry.get("manual_claim_ids") or []),
                "package_ids": list(entry.get("package_ids") or []),
                "owners": list(entry.get("owners") or []),
                "waves": list(entry.get("waves") or []),
                "powershell_set_command": str(entry.get("powershell_set_command") or env_set_commands.get(env_name) or ""),
            }
        )
    env_impact.sort(
        key=lambda item: (
            -int(item.get("claim_count") or 0),
            str(item.get("env") or ""),
        )
    )
    return {
        "current_env_present_count": int(env_queue.get("current_env_present_count") or 0),
        "current_env_missing_count": int(env_queue.get("current_env_missing_count") or 0),
        "current_env_missing_names": list(env_queue.get("current_env_missing_names") or []),
        "env_impact": env_impact,
        "all_env_powershell_set_commands": list(env_queue.get("all_env_powershell_set_commands") or []),
        "env_bundle_validation_command": str(env_queue.get("env_bundle_validation_command") or ""),
        "post_env_bundle_launcher_commands": list(env_queue.get("post_env_bundle_launcher_commands") or []),
        "post_env_bundle_balanced_agent_spawn_commands": list(
            env_queue.get("post_env_bundle_balanced_agent_spawn_commands") or []
        ),
        "ready_after_all_env_claim_ids": list(env_queue.get("ready_after_all_env_claim_ids") or []),
        "still_blocked_after_all_env_claim_ids": list(env_queue.get("still_blocked_after_all_env_claim_ids") or []),
    }


def run_class_action_fallbacks(claims: list[dict[str, Any]]) -> dict[str, str]:
    actions: dict[str, str] = {}
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        next_action = normalize_macos_smoke_next_action(str(claim.get("next_action") or "").strip())
        if not next_action:
            continue
        for run_class in claim.get("blocked_run_classes") or []:
            run_class_name = str(run_class or "").strip()
            if run_class_name and run_class_name not in actions:
                actions[run_class_name] = next_action
    return actions


def normalize_macos_smoke_next_action(action: str) -> str:
    text = action.strip()
    if (
        "com.apple.developer.endpoint-security.client" in text
        and "com.apple.developer.system-extension.install" not in text
    ):
        text = text.replace(
            "com.apple.developer.endpoint-security.client",
            (
                "com.apple.developer.endpoint-security.client and "
                "com.apple.developer.system-extension.install"
            ),
        )
    if (
        "macos_backend_readiness_probe.py" in text
        and "rerun macos_backend_readiness_probe.py before smoke execution" not in text
    ):
        if "then rerun macos_backend_readiness_probe.py." in text:
            text = text.replace(
                "then rerun macos_backend_readiness_probe.py.",
                "then rerun macos_backend_readiness_probe.py before smoke execution.",
            )
        else:
            text = text.replace(
                "then rerun macos_backend_readiness_probe.py",
                "then rerun macos_backend_readiness_probe.py before smoke execution",
            )
    return text


def latest_macos_backend_runtime_action(macos_backend: dict[str, Any] | None) -> str:
    if not macos_backend:
        return ""
    gate = macos_backend.get("quality_gate") if isinstance(macos_backend.get("quality_gate"), dict) else {}
    for gap in gate.get("actionable_gaps") or []:
        if not isinstance(gap, dict):
            continue
        evidence = gap.get("evidence") if isinstance(gap.get("evidence"), dict) else {}
        next_action = evidence.get("next_action") if isinstance(evidence.get("next_action"), dict) else {}
        action = str(next_action.get("action") or "").strip()
        diagnostics = (
            evidence.get("live_response_diagnostics")
            if isinstance(evidence.get("live_response_diagnostics"), dict)
            else {}
        )
        diagnostic_findings = (
            diagnostics.get("diagnostic_findings")
            if isinstance(diagnostics.get("diagnostic_findings"), dict)
            else {}
        )
        findings = [
            str(value)
            for value in (
                next_action.get("diagnostic_findings")
                if isinstance(next_action.get("diagnostic_findings"), list)
                else diagnostic_findings.get("findings")
                if isinstance(diagnostic_findings.get("findings"), list)
                else []
            )
            if value
        ]
        if not findings:
            continue
        finding_labels = {
            "tamandua_system_extension_missing": "Tamandua system extension is not listed/active",
            "endpoint_security_entitlement_missing": (
                "agent entitlements omit com.apple.developer.endpoint-security.client "
                "and com.apple.developer.system-extension.install"
            ),
            "gatekeeper_rejected_agent_binary": "Gatekeeper rejects /opt/tamandua/tamandua-agent",
        }
        details = [finding_labels.get(finding, finding) for finding in findings]
        if not action:
            action = (
                "Deploy a Developer ID signed/notarized agent binary for macOS that Gatekeeper accepts "
                "and that includes com.apple.developer.endpoint-security.client and "
                "com.apple.developer.system-extension.install, approve the Tamandua system extension "
                "and Full Disk Access, then rerun macos_backend_readiness_probe.py before smoke execution."
            )
        action = normalize_macos_smoke_next_action(action)
        return f"{action} {MACOS_LAB_ACCESS_BOUNDARY} Current read-only diagnostics confirm: {'; '.join(details)}."
    return ""


def apply_macos_runtime_action(claims: list[dict[str, Any]], action: str) -> list[dict[str, Any]]:
    if not action:
        return claims
    enriched = []
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        next_claim = dict(claim)
        blocked_run_classes = [str(value) for value in next_claim.get("blocked_run_classes") or []]
        claim_id = str(next_claim.get("claim_id") or "")
        if "macos-server-backed-smoke" in blocked_run_classes or claim_id == "claim-wave-1-restore-macos-backend-readiness":
            next_claim["next_action"] = action
        enriched.append(next_claim)
    return enriched


def run_class_digest(
    preflight: dict[str, Any] | None,
    claims: list[dict[str, Any]] | None = None,
    macos_runtime_action: str = "",
) -> list[dict[str, Any]]:
    if not preflight:
        return []
    claims = claims or []
    action_fallbacks = run_class_action_fallbacks(claims)
    unique_no_env_claim_actions = sorted(
        {
            normalize_macos_smoke_next_action(str(claim.get("next_action") or "").strip())
            for claim in claims
            if isinstance(claim, dict)
            and str(claim.get("next_action") or "").strip()
            and not claim.get("missing_effective_env")
        }
    )
    blocked_items = [
        item
        for item in preflight.get("run_class_readiness") or []
        if isinstance(item, dict) and not bool(item.get("allowed"))
    ]
    single_class_single_action = (
        len(blocked_items) == 1 and len(unique_no_env_claim_actions) == 1
    )
    result = []
    for item in blocked_items:
        run_class = str(item.get("run_class") or "")
        action = (
            item.get("action")
            or action_fallbacks.get(run_class)
            or (unique_no_env_claim_actions[0] if single_class_single_action else "")
        )
        if run_class == "macos-server-backed-smoke" and macos_runtime_action:
            action = macos_runtime_action
        action = normalize_macos_smoke_next_action(str(action or ""))
        result.append(
            {
                "run_class": item.get("run_class"),
                "allowed": bool(item.get("allowed")),
                "roadmaps": item.get("roadmaps") or [],
                "missing_env": item.get("missing_env") or [],
                "blocking_profiles": item.get("blocking_profiles") or [],
                "action": action,
            }
        )
    return sorted(result, key=lambda item: str(item.get("run_class") or ""))


def next_action_order(env_queue: dict[str, Any], claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = [
        {
            "step": 1,
            "id": "check-current-env",
            "title": "Check current env and print currently launchable fast paths",
            "claim_boundary": "no-execution operator check; prints commands only",
            "commands": [
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_operator_check.ps1 -Json"
            ],
        }
    ]
    if env_queue.get("current_env_missing_names"):
        actions.append(
            {
                "step": len(actions) + 1,
                "id": "fill-env-bundle",
                "title": "Fill the complete redacted env bundle locally",
                "claim_boundary": "operator input only; do not paste secret values into reports",
                "env": list(env_queue.get("current_env_missing_names") or []),
                "commands": list(env_queue.get("all_env_powershell_set_commands") or []),
            }
        )
    if env_queue.get("env_bundle_validation_command"):
        actions.append(
            {
                "step": len(actions) + 1,
                "id": "validate-env-bundle",
                "title": "Validate the local env bundle without launching packages",
                "claim_boundary": "JSON status only; does not import secret values or execute claims",
                "commands": [
                    "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 -Json"
                ],
            }
        )
    ready_after_env = list(env_queue.get("ready_after_all_env_claim_ids") or [])
    if ready_after_env and env_queue.get("post_env_bundle_launcher_commands"):
        actions.append(
            {
                "step": len(actions) + 1,
                "id": "launch-env-bundle-claims",
                "title": "Launch claims that become ready after the full env bundle",
                "claim_boundary": "imports the local env bundle, then executes only generated post-env-bundle package claims",
                "claim_ids": ready_after_env,
                "commands": [
                    "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 "
                    "-Execute -RefreshClaimStatus"
                ],
            }
        )
    if ready_after_env and env_queue.get("post_env_bundle_balanced_agent_spawn_commands"):
        actions.append(
            {
                "step": len(actions) + 1,
                "id": "balanced-agent-fanout",
                "title": "Optionally fan out env-bundle-ready claims across Codex/Claude",
                "claim_boundary": "requires explicit launch guard env vars",
                "claim_ids": ready_after_env,
                "commands": [
                    "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 "
                    "-UseBalancedAgents -Execute -RefreshClaimStatus"
                ],
            }
        )
    manual_claims = [
        claim
        for claim in claims
        if claim.get("state") == "manual_claim_required"
    ]
    if manual_claims:
        actions.append(
            {
                "step": len(actions) + 1,
                "id": "resolve-manual-claims",
                "title": "Resolve manual claims that launchers intentionally skip",
                "claim_boundary": "manual lab/operator decision required before automation can claim progress",
                "claim_ids": [str(claim.get("claim_id") or "") for claim in manual_claims if claim.get("claim_id")],
                "actions": [
                    normalize_macos_smoke_next_action(str(claim.get("next_action") or ""))
                    for claim in manual_claims
                    if claim.get("next_action")
                ],
            }
        )
    still_blocked = list(env_queue.get("still_blocked_after_all_env_claim_ids") or [])
    if still_blocked:
        actions.append(
            {
                "step": len(actions) + 1,
                "id": "resolve-still-blocked-after-env",
                "title": "Resolve dependency-gated claims still blocked after env bundle",
                "claim_boundary": "requires new runtime evidence from prior waves",
                "claim_ids": still_blocked,
            }
        )
    ready_claims = [
        claim
        for claim in claims
        if claim.get("ready_to_launch") is True
        and str(claim.get("state") or "") == "ready_to_claim"
    ]
    if ready_claims:
        actions.append(
            {
                "step": len(actions) + 1,
                "id": "launch-ready-claims",
                "title": "Launch currently ready claims with generated claim guards",
                "claim_boundary": (
                    "executes generated ready-claim wrappers only; product readiness still requires the "
                    "claim status to pass with blocker_cleared=true and no missing profiles"
                ),
                "claim_ids": [str(claim.get("claim_id") or "") for claim in ready_claims if claim.get("claim_id")],
                "actions": [
                    normalize_macos_smoke_next_action(str(claim.get("next_action") or ""))
                    for claim in ready_claims
                    if claim.get("next_action")
                ],
                "commands": [str(claim.get("command") or "") for claim in ready_claims if claim.get("command")],
            }
        )
    failed_claims = [
        claim
        for claim in claims
        if str(claim.get("state") or "").startswith("has_current_")
        and str(claim.get("state") or "") != "has_current_pass_evidence"
    ]
    if failed_claims:
        actions.append(
            {
                "step": len(actions) + 1,
                "id": "resolve-current-failed-claims",
                "title": "Resolve claims with current failed or incomplete agent evidence",
                "claim_boundary": "requires external runtime state to change before rerunning the failed claim",
                "claim_ids": [str(claim.get("claim_id") or "") for claim in failed_claims if claim.get("claim_id")],
                "actions": [
                    normalize_macos_smoke_next_action(str(claim.get("next_action") or ""))
                    for claim in failed_claims
                    if claim.get("next_action")
                ],
                "commands": [str(claim.get("command") or "") for claim in failed_claims if claim.get("command")],
            }
        )
    actions.append(
        {
            "step": len(actions) + 1,
            "id": "refresh-validation-authority",
            "title": "Regenerate closure, preflight, dispatch, scorecard, and product summary",
            "claim_boundary": "sequential local authority refresh; not a product-ready claim by itself",
            "commands": [
                "python tools/detection_validation/refresh_validation_authority.py --dry-run",
                "python tools/detection_validation/refresh_validation_authority.py",
            ],
        }
    )
    return actions


def recommended_next_action(actions: list[dict[str, Any]]) -> dict[str, Any]:
    for action in actions:
        if not isinstance(action, dict):
            continue
        action_id = str(action.get("id") or "")
        if action_id and action_id != "check-current-env":
            return {
                "id": action_id,
                "step": int(action.get("step") or 0),
                "title": str(action.get("title") or ""),
                "claim_boundary": str(action.get("claim_boundary") or ""),
                "commands": list(action.get("commands") or []),
                "claim_ids": list(action.get("claim_ids") or []),
                "env": list(action.get("env") or []),
                "actions": list(action.get("actions") or []),
            }
    return {}


def handoff_artifacts(package_dir: Path | None) -> dict[str, str]:
    if not package_dir:
        return {}
    names = {
        "dispatch_brief": "dispatch_brief.md",
        "env_checklist": "env_checklist.md",
        "env_template": "env_template.ps1",
        "env_unblock_queue": "env_unblock_queue.md",
        "env_unblock_queue_json": "env_unblock_queue.json",
        "agent_claims": "agent_claims.json",
        "agent_spawn_plan": "agent_spawn_plan.json",
        "agent_spawn_launcher": "agent_spawn_launcher.ps1",
        "env_bundle_ready_claims_launcher": "env_bundle_ready_claims_launcher.ps1",
        "dispatch_prelaunch_validation": "dispatch_prelaunch_validation.ps1",
        "dispatch_one_shot_runner": "dispatch_one_shot_runner.ps1",
        "claim_status_report": "claim_status_report.md",
        "claim_status_report_json": "claim_status_report.json",
    }
    artifacts = {}
    for key, name in names.items():
        path = package_dir / name
        if path.exists():
            artifacts[key] = rel(path)
    return artifacts


def post_agent_status_gate(
    package_dir: Path | None,
    post_env_plan: dict[str, Any],
) -> dict[str, Any]:
    report_path = package_dir / "claim_status_report.json" if package_dir else None
    report = load_optional_json(report_path)
    ready_claim_ids = sorted(str(value) for value in post_env_plan.get("ready_claim_ids") or [])
    claims = [claim for claim in (report.get("claims") if isinstance(report, dict) else []) or [] if isinstance(claim, dict)]
    claim_by_id = {str(claim.get("claim_id") or ""): claim for claim in claims if claim.get("claim_id")}
    ready_rows = [claim_by_id.get(claim_id, {}) for claim_id in ready_claim_ids]
    passed_claim_ids = sorted(
        str(row.get("claim_id") or "")
        for row in ready_rows
        if row.get("agent_status") == "pass"
        and row.get("agent_blocker_cleared") is True
        and not row.get("missing_profiles")
    )
    incomplete_claims = []
    for claim_id in ready_claim_ids:
        row = claim_by_id.get(claim_id, {})
        if claim_id in passed_claim_ids:
            continue
        incomplete_claims.append(
            {
                "claim_id": claim_id,
                "agent_status": str(row.get("agent_status") or "missing"),
                "agent_blocker_cleared": bool(row.get("agent_blocker_cleared")),
                "missing_profiles": list(row.get("missing_profiles") or []),
                "status_path": str(row.get("status_path") or ""),
            }
        )
    manifest_path = package_dir / "dispatch_manifest.json" if package_dir else None
    refresh_command = (
        "python tools/detection_validation/run_preflight_work_package.py --refresh-claim-status-report "
        f"'{rel(manifest_path)}'"
        if manifest_path and manifest_path.exists()
        else ""
    )
    return {
        "report": rel(report_path) if report_path and report_path.exists() else "",
        "markdown_report": rel(package_dir / "claim_status_report.md") if package_dir and (package_dir / "claim_status_report.md").exists() else "",
        "refresh_command": refresh_command,
        "claim_count": int(report.get("claim_count") or 0) if isinstance(report, dict) else 0,
        "status_counts": dict(report.get("status_counts") or {}) if isinstance(report, dict) else {},
        "claim_state_counts": dict(report.get("claim_state_counts") or {}) if isinstance(report, dict) else {},
        "locked_claim_count": int(report.get("locked_claim_count") or 0) if isinstance(report, dict) else 0,
        "invalid_lock_count": int(report.get("invalid_lock_count") or 0) if isinstance(report, dict) else 0,
        "ready_after_env_claim_ids": ready_claim_ids,
        "ready_after_env_passed_claim_ids": passed_claim_ids,
        "ready_after_env_passed_count": len(passed_claim_ids),
        "ready_after_env_required_count": len(ready_claim_ids),
        "ready_after_env_all_passed": len(passed_claim_ids) == len(ready_claim_ids),
        "incomplete_ready_after_env_claims": incomplete_claims,
        "required_agent_status_contract": {
            "status": "pass",
            "blocker_cleared": True,
            "missing_profiles": [],
            "required_fields": [
                "package_id",
                "claim_id",
                "agent_id",
                "status",
                "artifacts",
                "blocker_cleared",
                "notes",
                "exit_code",
                "expected_profiles",
                "missing_profiles",
            ],
        },
        "claim_boundary": (
            "refresh this report after agent fanout; do not refresh product authority until env-bundle-ready "
            "claims have pass statuses with blocker_cleared=true and no missing profiles"
        ),
    }


def product_release_gate(
    gates: dict[str, Any],
    env_summary: dict[str, Any],
    claims: dict[str, int],
    manual: list[dict[str, Any]],
    post_agent_gate: dict[str, Any],
    blocked_run_classes: list[dict[str, Any]],
) -> dict[str, Any]:
    requirements = [
        {
            "id": "closure-gate",
            "passed": gates.get("closure", {}).get("passed") is True,
            "current": gates.get("closure", {}).get("coverage") or gates.get("closure", {}).get("status") or "",
            "required": "closure gate pass",
        },
        {
            "id": "preflight-gate",
            "passed": gates.get("preflight", {}).get("passed") is True,
            "current": gates.get("preflight", {}).get("coverage") or gates.get("preflight", {}).get("status") or "",
            "required": "preflight gate pass",
        },
        {
            "id": "dispatch-gate",
            "passed": gates.get("dispatch", {}).get("status") == "pass",
            "current": gates.get("dispatch", {}).get("coverage") or gates.get("dispatch", {}).get("status") or "",
            "required": "dispatch gate pass",
        },
        {
            "id": "required-env",
            "passed": int(env_summary.get("current_env_missing_count") or 0) == 0,
            "current": str(int(env_summary.get("current_env_missing_count") or 0)),
            "required": "0 missing required env values",
        },
        {
            "id": "blocked-env-claims",
            "passed": int(claims.get("blocked_missing_env_count") or 0) == 0,
            "current": str(int(claims.get("blocked_missing_env_count") or 0)),
            "required": "0 claims blocked by missing env",
        },
        {
            "id": "manual-claims",
            "passed": len(manual) == 0,
            "current": str(len(manual)),
            "required": "0 manual claims remaining",
        },
        {
            "id": "post-agent-status",
            "passed": post_agent_gate.get("ready_after_env_all_passed") is True,
            "current": (
                f"{int(post_agent_gate.get('ready_after_env_passed_count') or 0)}/"
                f"{int(post_agent_gate.get('ready_after_env_required_count') or 0)}"
            ),
            "required": "all env-bundle-ready agent statuses pass with blocker_cleared=true and no missing profiles",
        },
        {
            "id": "blocked-run-classes",
            "passed": len(blocked_run_classes) == 0,
            "current": str(len(blocked_run_classes)),
            "required": "0 blocked run classes",
        },
    ]
    failed = [item for item in requirements if item.get("passed") is not True]
    return {
        "passed": not failed,
        "failed_count": len(failed),
        "failed_ids": [str(item.get("id") or "") for item in failed],
        "requirements": requirements,
        "claim_boundary": "product_ready and external_claim_allowed require every release gate requirement to pass",
    }


def env_template_details(package_dir: Path | None, env_summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    details: dict[str, dict[str, Any]] = {}
    for item in env_summary.get("env_impact") or []:
        if not isinstance(item, dict):
            continue
        env_name = str(item.get("env") or "")
        if not env_name:
            continue
        details[env_name] = {
            "env": env_name,
            "class": "",
            "owner": ", ".join(str(owner) for owner in item.get("owners") or []),
            "flag": "",
            "description": "",
            "placeholder": "",
            "powershell_set_command": str(item.get("powershell_set_command") or ""),
            "claim_ids": sorted(
                set(
                    str(value)
                    for key in ("immediate_claim_ids", "dependency_claim_ids", "manual_claim_ids")
                    for value in item.get(key) or []
                    if value
                )
            ),
            "package_ids": list(item.get("package_ids") or []),
        }
    template_path = package_dir / "env_template.ps1" if package_dir else None
    if template_path and template_path.exists():
        metadata: dict[str, str] = {}
        for line in template_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("# Class:"):
                body = stripped[len("# Class:") :].strip()
                if ";" in body:
                    class_value, body = body.split(";", 1)
                else:
                    class_value, body = body, ""
                metadata["class"] = class_value.strip()
                for part in body.split(";"):
                    if ":" not in part:
                        continue
                    key, value = part.split(":", 1)
                    metadata[key.strip().lower()] = value.strip()
            elif stripped.startswith("# Flag:"):
                body = stripped[len("# Flag:") :].strip()
                for part in body.split(";"):
                    if ":" not in part:
                        continue
                    key, value = part.split(":", 1)
                    metadata[key.strip().lower()] = value.strip()
            elif stripped.startswith("$env:") and "=" in stripped:
                env_name = stripped[len("$env:") : stripped.index("=")].strip()
                placeholder = stripped.split("=", 1)[1].strip().strip("'")
                entry = details.setdefault(env_name, {"env": env_name})
                entry.update(
                    {
                        "class": metadata.get("class", ""),
                        "owner": metadata.get("owner", ""),
                        "flag": metadata.get("flag", ""),
                        "description": metadata.get("description", ""),
                        "placeholder": placeholder,
                    }
                )
                metadata = {}
    return dict(sorted(details.items()))


def dispatch_package_metadata(package_dir: Path | None) -> dict[str, dict[str, Any]]:
    try:
        manifest = load_optional_json(package_dir / "dispatch_manifest.json" if package_dir else None)
    except json.JSONDecodeError:
        manifest = {}
    packages = manifest.get("packages") if isinstance(manifest, dict) else []
    if not isinstance(packages, list):
        return {}
    return {
        str(package.get("package_id") or ""): package
        for package in packages
        if isinstance(package, dict) and package.get("package_id")
    }


def manual_claim_prerequisites(summary: dict[str, Any]) -> list[str]:
    prerequisites: list[str] = []
    seen = set()
    for claim in summary.get("manual_claims") or []:
        if not isinstance(claim, dict):
            continue
        for value in claim.get("manual_prerequisites") or []:
            text = str(value).strip()
            if text and text not in seen:
                prerequisites.append(text)
                seen.add(text)
    return prerequisites


def product_readiness_automation_state(
    summary: dict[str, Any],
    env_request: dict[str, Any],
    release_gate_contract: dict[str, Any] | None = None,
    blocked_run_classes_contract: dict[str, Any] | None = None,
) -> str:
    if int(env_request.get("required_env_count") or 0) > 0:
        return "blocked_missing_env"
    manual_claim_count = len(summary.get("manual_claims") or [])
    blocked_run_class_count = int(
        (blocked_run_classes_contract or {}).get("blocked_run_class_count")
        or (release_gate_contract or {}).get("blocked_run_class_count")
        or 0
    )
    if manual_claim_count or blocked_run_class_count:
        return "runtime_evidence_blocked"
    return "ready_for_post_env_runner"


def manual_claims(
    claims: list[dict[str, Any]],
    package_metadata: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    result = []
    package_metadata = package_metadata or {}
    for claim in claims:
        if claim.get("state") != "manual_claim_required":
            continue
        if (
            claim.get("agent_status") == "pass"
            and claim.get("agent_blocker_cleared") is True
            and not claim.get("missing_profiles")
        ):
            continue
        package_id = str(claim.get("package_id") or "")
        package = package_metadata.get(package_id) or {}
        manual_prerequisites = [
            str(value)
            for value in package.get("manual_prerequisites") or claim.get("manual_prerequisites") or []
            if str(value).strip()
        ]
        claim_id = str(claim.get("claim_id") or "")
        if claim_id == "claim-wave-1-restore-macos-backend-readiness":
            for prerequisite in [
                MACOS_SIGNED_RELEASE_PREREQUISITE,
                MACOS_ENDPOINT_APPROVAL_PREREQUISITE,
                MACOS_LAB_ACCESS_BOUNDARY,
            ]:
                if prerequisite not in manual_prerequisites:
                    manual_prerequisites.append(prerequisite)
        result.append(
            {
                "claim_id": claim_id,
                "package_id": package_id,
                "wave": claim.get("wave"),
                "owner": claim.get("owner"),
                "next_action": claim.get("next_action") or "",
                "command": claim.get("command") or "",
                "script_path": claim.get("script_path") or "",
                "prompt_path": claim.get("prompt_path") or "",
                "manual_prerequisites": manual_prerequisites,
                "claim_boundary": "manual operator decision required before automation can claim this blocker",
            }
        )
    return sorted(result, key=lambda item: (int(item.get("wave") or 0), str(item.get("package_id") or "")))


def post_env_bundle_plan(package_dir: Path | None, env_summary: dict[str, Any]) -> dict[str, Any]:
    plan_path = package_dir / "agent_spawn_plan.json" if package_dir else None
    plan = load_optional_json(plan_path)
    ready_batches = plan.get("env_bundle_ready_batches") if isinstance(plan, dict) else []
    if not isinstance(ready_batches, list):
        ready_batches = []
    still_blocked = plan.get("env_bundle_still_blocked_claims") if isinstance(plan, dict) else []
    if not isinstance(still_blocked, list):
        still_blocked = []
    return {
        "actionable": bool(plan.get("post_env_bundle_multi_agent_actionable")) if isinstance(plan, dict) else False,
        "provider_mode": "balanced",
        "phase": "env-bundle",
        "ready_claim_count": int(plan.get("env_bundle_ready_claim_count") or 0) if isinstance(plan, dict) else 0,
        "ready_batch_count": int(plan.get("env_bundle_ready_batch_count") or 0) if isinstance(plan, dict) else 0,
        "still_blocked_claim_count": (
            int(plan.get("env_bundle_still_blocked_claim_count") or 0) if isinstance(plan, dict) else 0
        ),
        "ready_claim_ids": sorted(str(value) for value in env_summary.get("ready_after_all_env_claim_ids") or []),
        "still_blocked_claim_ids": sorted(
            str(value) for value in env_summary.get("still_blocked_after_all_env_claim_ids") or []
        ),
        "ready_batches": [
            {
                "batch": int(batch.get("batch") or 0),
                "claim_count": int(batch.get("claim_count") or 0),
                "claim_ids": sorted(
                    str(claim.get("claim_id") or "")
                    for claim in batch.get("claims") or []
                    if isinstance(claim, dict) and claim.get("claim_id")
                ),
            }
            for batch in ready_batches
            if isinstance(batch, dict)
        ],
        "agent_spawn_plan": rel(plan_path) if plan_path and plan_path.exists() else "",
        "validate_command": str(env_summary.get("env_bundle_validation_command") or ""),
        "package_launcher_commands": list(env_summary.get("post_env_bundle_launcher_commands") or []),
        "balanced_agent_spawn_commands": list(env_summary.get("post_env_bundle_balanced_agent_spawn_commands") or []),
        "claim_boundary": (
            "available only after the full env bundle validates; executes generated env-bundle-ready claims"
        ),
    }


def build_summary(scorecard_path: Path = SCORECARD_JSON) -> dict[str, Any]:
    scorecard = load_json(scorecard_path)
    closure_path = latest_profile_path(scorecard, PROFILE_CLOSURE)
    preflight_path = latest_profile_path(scorecard, PROFILE_PREFLIGHT)
    dispatch_path = latest_profile_path(scorecard, PROFILE_DISPATCH)
    macos_backend_path = latest_profile_path(scorecard, PROFILE_MACOS_BACKEND)
    macos_release_artifact_path = latest_profile_path(scorecard, PROFILE_MACOS_RELEASE_ARTIFACT_PREFLIGHT)
    closure = load_optional_json(closure_path)
    preflight = load_optional_json(preflight_path)
    dispatch = load_optional_json(dispatch_path)
    macos_backend = load_optional_json(macos_backend_path)
    preflight_dir = preflight_package_dir(preflight_path)
    dispatch_dir = dispatch_package_dir(dispatch_path)
    package_dir = dispatch_dir or preflight_dir
    env_queue = load_optional_json(package_dir / "env_unblock_queue.json" if package_dir else None)
    agent_claims_snapshot = load_optional_json(package_dir / "agent_claims.json" if package_dir else None)
    claim_status_report = load_optional_json(package_dir / "claim_status_report.json" if package_dir else None)
    package_metadata = dispatch_package_metadata(package_dir)
    agent_claims = merged_claims_payload(agent_claims_snapshot, claim_status_report)
    env_summary = env_queue_summary(env_queue)
    local_bundle_gate = local_env_bundle_gate(env_summary)
    macos_runtime_action = latest_macos_backend_runtime_action(macos_backend)
    claim_queue = apply_macos_runtime_action(claim_digest(agent_claims), macos_runtime_action)
    gates = {
        "closure": compact_quality_gate(closure),
        "preflight": compact_quality_gate(preflight),
        "dispatch": dispatch_gate(dispatch),
    }
    post_env_plan = post_env_bundle_plan(package_dir, env_summary)
    post_agent_gate = post_agent_status_gate(package_dir, post_env_plan)
    claims = claim_counts(agent_claims)
    manual = manual_claims(claim_queue, package_metadata)
    blocked_classes = run_class_digest(preflight, claim_queue, macos_runtime_action)
    release_gate = product_release_gate(gates, env_summary, claims, manual, post_agent_gate, blocked_classes)
    external_claim_allowed = bool(release_gate.get("passed"))
    actions = next_action_order(env_summary, claim_queue)
    recommended_action = recommended_next_action(actions)
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "scorecard_path": rel(scorecard_path),
        "source_artifacts": {
            "closure": rel(closure_path) if closure_path else None,
            "preflight": rel(preflight_path) if preflight_path else None,
            "dispatch": rel(dispatch_path) if dispatch_path else None,
            "macos_backend": rel(macos_backend_path) if macos_backend_path else None,
            "macos_release_artifact_preflight": (
                rel(macos_release_artifact_path) if macos_release_artifact_path else None
            ),
            "preflight_package_dir": rel(preflight_dir) if preflight_dir else None,
            "dispatch_package_dir": rel(dispatch_dir) if dispatch_dir else None,
            "package_dir": rel(package_dir) if package_dir else None,
        },
        "gates": gates,
        "external_claim_allowed": external_claim_allowed,
        "product_ready": external_claim_allowed,
        "product_release_gate": release_gate,
        "env_queue": env_summary,
        "local_env_bundle_gate": local_bundle_gate,
        "env_details": env_template_details(package_dir, env_summary),
        "handoff_artifacts": handoff_artifacts(package_dir),
        "claims": claims,
        "claim_queue": claim_queue,
        "manual_claims": manual,
        "single_env_fast_paths": single_env_fast_paths(env_summary, claim_queue),
        "post_env_bundle_plan": post_env_plan,
        "post_agent_status_gate": post_agent_gate,
        "recommended_next_action_id": str(recommended_action.get("id") or ""),
        "recommended_next_action": recommended_action,
        "next_action_order": actions,
        "blocked_run_classes": blocked_classes,
        "claim_boundary": (
            "Derived readiness summary only. This report consolidates existing "
            "closure/preflight/dispatch artifacts and does not run product validation."
        ),
    }


def render_markdown(summary: dict[str, Any]) -> str:
    source_artifacts = (
        summary.get("source_artifacts")
        if isinstance(summary.get("source_artifacts"), dict)
        else {}
    )
    lines = [
        "# Product Readiness Summary",
        "",
        "Status: generated from current validation authority",
        "",
        f"- Generated at: `{summary['generated_at']}`",
        f"- Product ready: `{str(summary['product_ready']).lower()}`",
        f"- External claim allowed: `{str(summary['external_claim_allowed']).lower()}`",
        f"- Recommended next action: `{summary.get('recommended_next_action_id') or '-'}`",
        f"- Scorecard: `{summary['scorecard_path']}`",
        "",
        "## Source Artifacts",
        "",
        "| Source | Artifact |",
        "|--------|----------|",
    ]
    for key in sorted(source_artifacts):
        lines.append(f"| `{key}` | `{source_artifacts.get(key) or '-'}` |")
    lines.extend(
        [
        "",
        "## Gates",
        "",
        "| Gate | Run | Status | Coverage |",
        "|------|-----|--------|----------|",
        ]
    )
    for key, gate in summary["gates"].items():
        lines.append(
            f"| `{key}` | `{gate.get('run_id') or '-'}` | `{gate.get('status') or '-'}` | `{gate.get('coverage') or '-'}` |"
        )
    release_gate = (
        summary.get("product_release_gate")
        if isinstance(summary.get("product_release_gate"), dict)
        else {}
    )
    lines.extend(
        [
            "",
            "## Product Release Gate",
            "",
            f"- Passed: `{str(bool(release_gate.get('passed'))).lower()}`",
            f"- Failed requirements: `{release_gate.get('failed_count') or 0}`",
            "",
            "| Requirement | Passed | Current | Required |",
            "|-------------|--------|---------|----------|",
        ]
    )
    release_requirements = (
        release_gate.get("requirements")
        if isinstance(release_gate.get("requirements"), list)
        else []
    )
    if release_requirements:
        for item in release_requirements:
            lines.append(
                f"| `{item.get('id')}` | `{str(bool(item.get('passed'))).lower()}` | "
                f"`{str(item.get('current') or '-').replace('|', '/')}` | "
                f"{str(item.get('required') or '-').replace('|', '/')} |"
            )
    else:
        lines.append("| - | `false` | - | - |")
    lines.extend(
        [
            "",
            "## Next Action Order",
            "",
            "| Step | Action | Boundary | Commands |",
            "|------|--------|----------|----------|",
        ]
    )
    for action in summary.get("next_action_order") or []:
        commands = "<br>".join(str(command).replace("|", "/") for command in action.get("commands") or []) or "-"
        lines.append(
            f"| `{action.get('step')}` | `{action.get('id')}`: {str(action.get('title') or '').replace('|', '/')} | "
            f"{str(action.get('claim_boundary') or '').replace('|', '/')} | {commands} |"
        )
    env_queue = summary["env_queue"]
    lines.extend(
        [
            "",
            "## Env Queue",
            "",
            f"- Current env present: `{env_queue['current_env_present_count']}`",
            f"- Current env missing: `{env_queue['current_env_missing_count']}`",
            f"- Ready after full env bundle: `{', '.join(env_queue['ready_after_all_env_claim_ids']) or '-'}`",
            f"- Still blocked after full env bundle: `{', '.join(env_queue['still_blocked_after_all_env_claim_ids']) or '-'}`",
            "",
            "Missing env:",
            "",
        ]
    )
    for env_name in env_queue["current_env_missing_names"]:
        lines.append(f"- `{env_name}`")
    if not env_queue["current_env_missing_names"]:
        lines.append("- none")
    env_details = summary.get("env_details") if isinstance(summary.get("env_details"), dict) else {}
    lines.extend(
        [
            "",
            "### Missing Env Details",
            "",
            "| Env | Class | Owner | Placeholder | Description |",
            "|-----|-------|-------|-------------|-------------|",
        ]
    )
    if env_queue["current_env_missing_names"]:
        for env_name in env_queue["current_env_missing_names"]:
            detail = env_details.get(env_name, {}) if isinstance(env_details.get(env_name), dict) else {}
            lines.append(
                f"| `{env_name}` | `{detail.get('class') or '-'}` | `{detail.get('owner') or '-'}` | "
                f"`{detail.get('placeholder') or '-'}` | {str(detail.get('description') or '-').replace('|', '/')} |"
            )
    else:
        lines.append("| - | - | - | - | - |")
    lines.extend(
        [
            "",
            "### Env Impact",
            "",
            "| Env | Claims | Ready after only this env | Immediate claims | Dependency-gated claims | Packages |",
            "|-----|--------|---------------------------|------------------|-------------------------|----------|",
        ]
    )
    for item in env_queue.get("env_impact") or []:
        ready = ", ".join(f"`{claim}`" for claim in item.get("single_env_ready_claim_ids") or []) or "-"
        immediate = ", ".join(f"`{claim}`" for claim in item.get("immediate_claim_ids") or []) or "-"
        dependency = ", ".join(f"`{claim}`" for claim in item.get("dependency_claim_ids") or []) or "-"
        packages = ", ".join(f"`{package}`" for package in item.get("package_ids") or []) or "-"
        lines.append(
            f"| `{item.get('env')}` | `{item.get('claim_count')}` | {ready} | "
            f"{immediate} | {dependency} | {packages} |"
        )
    if not env_queue.get("env_impact"):
        lines.append("| - | `0` | - | - | - | - |")
    lines.extend(["", "### Single Env Fast Paths", ""])
    fast_paths = summary.get("single_env_fast_paths") or []
    if fast_paths:
        for item in fast_paths:
            lines.extend(
                [
                    f"- Env `{item.get('env')}` unlocks `{', '.join(item.get('claim_ids') or [])}`",
                    f"  Boundary: {item.get('claim_boundary')}",
                    "",
                    "```powershell",
                ]
            )
            lines.extend(str(command) for command in item.get("commands") or [])
            lines.extend(["```", ""])
    else:
        lines.append("- none")
    lines.extend(["", "### Copy/Paste Env Bundle", ""])
    if env_queue.get("all_env_powershell_set_commands"):
        lines.append("```powershell")
        lines.extend(str(command) for command in env_queue["all_env_powershell_set_commands"])
        lines.append("```")
    else:
        lines.append("- none")
    lines.extend(["", "### Validate And Launch After Env Bundle", ""])
    if env_queue.get("env_bundle_validation_command"):
        lines.extend(
            [
                "Validate first:",
                "",
                "```powershell",
                str(env_queue["env_bundle_validation_command"]),
                "```",
                "",
            ]
        )
    if env_queue.get("post_env_bundle_launcher_commands"):
        lines.extend(["Launch package claims after validation:", "", "```powershell"])
        lines.extend(str(command) for command in env_queue["post_env_bundle_launcher_commands"])
        lines.extend(["```", ""])
    if env_queue.get("post_env_bundle_balanced_agent_spawn_commands"):
        lines.extend(["Balanced Codex/Claude fan-out after validation:", "", "```powershell"])
        lines.extend(str(command) for command in env_queue["post_env_bundle_balanced_agent_spawn_commands"])
        lines.extend(["```", ""])
    lines.extend(
        [
            "Generated local-bundle wrapper:",
            "",
            "```powershell",
            "powershell -NoProfile -ExecutionPolicy Bypass -File "
            "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 -Json",
            "powershell -NoProfile -ExecutionPolicy Bypass -File "
            "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1",
            "powershell -NoProfile -ExecutionPolicy Bypass -File "
            "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 "
            "-UseBalancedAgents -Execute -RefreshClaimStatus",
            "```",
            "",
        ]
    )
    if not (
        env_queue.get("env_bundle_validation_command")
        or env_queue.get("post_env_bundle_launcher_commands")
        or env_queue.get("post_env_bundle_balanced_agent_spawn_commands")
    ):
        lines.append("- none")
    post_env_plan = (
        summary.get("post_env_bundle_plan")
        if isinstance(summary.get("post_env_bundle_plan"), dict)
        else {}
    )
    lines.extend(
        [
            "",
            "### Post Env Bundle Plan",
            "",
            f"- Actionable: `{str(bool(post_env_plan.get('actionable'))).lower()}`",
            f"- Provider mode: `{post_env_plan.get('provider_mode') or '-'}`",
            f"- Phase: `{post_env_plan.get('phase') or '-'}`",
            f"- Ready claims: `{post_env_plan.get('ready_claim_count') or 0}`",
            f"- Ready batches: `{post_env_plan.get('ready_batch_count') or 0}`",
            f"- Still blocked claims: `{post_env_plan.get('still_blocked_claim_count') or 0}`",
            f"- Agent spawn plan: `{post_env_plan.get('agent_spawn_plan') or '-'}`",
            "",
            "| Batch | Claim count | Claim ids |",
            "|-------|-------------|-----------|",
        ]
    )
    ready_batches = post_env_plan.get("ready_batches") if isinstance(post_env_plan.get("ready_batches"), list) else []
    if ready_batches:
        for batch in ready_batches:
            claim_ids = ", ".join(f"`{claim}`" for claim in batch.get("claim_ids") or []) or "-"
            lines.append(f"| `{batch.get('batch')}` | `{batch.get('claim_count')}` | {claim_ids} |")
    else:
        lines.append("| - | `0` | - |")
    post_agent_gate = (
        summary.get("post_agent_status_gate")
        if isinstance(summary.get("post_agent_status_gate"), dict)
        else {}
    )
    local_bundle_gate = (
        summary.get("local_env_bundle_gate")
        if isinstance(summary.get("local_env_bundle_gate"), dict)
        else {}
    )
    recommended_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    lines.extend(
        [
            "",
            "### Post Agent Status Gate",
            "",
            f"- Ready-after-env passed: `{post_agent_gate.get('ready_after_env_passed_count') or 0}/"
            f"{post_agent_gate.get('ready_after_env_required_count') or 0}`",
            f"- All ready-after-env passed: `{str(bool(post_agent_gate.get('ready_after_env_all_passed'))).lower()}`",
            f"- Claim status report: `{post_agent_gate.get('report') or '-'}`",
            f"- Refresh command: `{post_agent_gate.get('refresh_command') or '-'}`",
            "",
            "| Claim | Agent status | Blocker cleared | Missing profiles | Status path |",
            "|-------|--------------|-----------------|------------------|-------------|",
        ]
    )
    incomplete = (
        post_agent_gate.get("incomplete_ready_after_env_claims")
        if isinstance(post_agent_gate.get("incomplete_ready_after_env_claims"), list)
        else []
    )
    if incomplete:
        for claim in incomplete:
            missing_profiles = ", ".join(f"`{value}`" for value in claim.get("missing_profiles") or []) or "-"
            lines.append(
                f"| `{claim.get('claim_id')}` | `{claim.get('agent_status')}` | "
                f"`{str(bool(claim.get('agent_blocker_cleared'))).lower()}` | "
                f"{missing_profiles} | `{claim.get('status_path') or '-'}` |"
            )
    else:
        lines.append("| - | - | - | - | - |")
    handoff = summary.get("handoff_artifacts") if isinstance(summary.get("handoff_artifacts"), dict) else {}
    lines.extend(
        [
            "",
            "## Handoff Artifacts",
            "",
            "| Artifact | Path |",
            "|----------|------|",
        ]
    )
    if handoff:
        for key in sorted(handoff):
            lines.append(f"| `{key}` | `{handoff[key]}` |")
    else:
        lines.append("| - | - |")
    lines.extend(
        [
            "",
            "## Manual Claims",
            "",
            "| Claim | Wave | Owner | Boundary | Next action | Prompt | Command |",
            "|-------|------|-------|----------|-------------|--------|---------|",
        ]
    )
    manual = summary.get("manual_claims") if isinstance(summary.get("manual_claims"), list) else []
    if manual:
        for claim in manual:
            lines.append(
                f"| `{claim.get('package_id')}` | `{claim.get('wave')}` | `{claim.get('owner')}` | "
                f"{str(claim.get('claim_boundary') or '').replace('|', '/')} | "
                f"{str(claim.get('next_action') or '').replace('|', '/')} | "
                f"`{claim.get('prompt_path') or '-'}` | "
                f"{str(claim.get('command') or '-').replace('|', '/')} |"
            )
    else:
        lines.append("| - | - | - | - | - | - | - |")
    claims = summary["claims"]
    lines.extend(
        [
            "",
            "## Claims",
            "",
            f"- Total: `{claims['claim_count']}`",
            f"- Ready now: `{claims['ready_to_launch_count']}`",
            f"- Blocked by env: `{claims['blocked_missing_env_count']}`",
            f"- Manual required: `{claims['manual_claim_required_count']}`",
            f"- Not run: `{claims['not_run_count']}`",
            "",
            "| Claim | Wave | Owner | State | Missing env | Next action |",
            "|-------|------|-------|-------|-------------|-------------|",
        ]
    )
    for claim in summary["claim_queue"]:
        missing_env = ", ".join(f"`{env}`" for env in claim["missing_effective_env"]) or "-"
        lines.append(
            f"| `{claim['package_id']}` | `{claim['wave']}` | `{claim['owner']}` | "
            f"`{claim['state']}` | {missing_env} | {str(claim['next_action']).replace('|', '/')} |"
        )
    lines.extend(
        [
            "",
            "## Blocked Run Classes",
            "",
            "| Run class | Allowed | Roadmaps | Missing env | Blocking profiles | Action |",
            "|-----------|---------|----------|-------------|-------------------|--------|",
        ]
    )
    for item in summary["blocked_run_classes"]:
        lines.append(
            f"| `{item['run_class']}` | `{str(item['allowed']).lower()}` | "
            f"{', '.join(f'`{value}`' for value in item['roadmaps']) or '-'} | "
            f"{', '.join(f'`{value}`' for value in item['missing_env']) or '-'} | "
            f"{', '.join(f'`{value}`' for value in item['blocking_profiles']) or '-'} | "
            f"{str(item.get('action') or '-').replace('|', '/')} |"
        )
    lines.extend(["", "## Claim Boundary", "", summary["claim_boundary"]])
    return "\n".join(lines) + "\n"


def env_request_payload(summary: dict[str, Any]) -> dict[str, Any]:
    env_queue = summary.get("env_queue") if isinstance(summary.get("env_queue"), dict) else {}
    env_details = summary.get("env_details") if isinstance(summary.get("env_details"), dict) else {}
    recommended_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    missing_names = [str(value) for value in env_queue.get("current_env_missing_names") or []]
    entries = []
    for env_name in missing_names:
        detail = env_details.get(env_name) if isinstance(env_details.get(env_name), dict) else {}
        entries.append(
            {
                "env": env_name,
                "class": str(detail.get("class") or ""),
                "owner": str(detail.get("owner") or ""),
                "description": str(detail.get("description") or ""),
                "placeholder": str(detail.get("placeholder") or ""),
                "powershell_set_command": str(detail.get("powershell_set_command") or ""),
                "claim_ids": list(detail.get("claim_ids") or []),
                "package_ids": list(detail.get("package_ids") or []),
            }
        )
    secret_count = sum(1 for entry in entries if entry.get("class") == "secret")
    metadata_count = len(entries) - secret_count
    return {
        "schema_version": 1,
        "artifact": "validation-product-readiness-env-request",
        "generated_at": summary.get("generated_at"),
        "product_ready": bool(summary.get("product_ready")),
        "product_release_gate_passed": bool(
            (summary.get("product_release_gate") if isinstance(summary.get("product_release_gate"), dict) else {}).get(
                "passed"
            )
        ),
        "required_env_count": len(entries),
        "secret_count": secret_count,
        "metadata_count": metadata_count,
        "entries": entries,
        "copy_paste_powershell": [str(entry.get("powershell_set_command") or "") for entry in entries],
        "recommended_next_action_id": str(summary.get("recommended_next_action_id") or ""),
        "recommended_next_action": {
            "id": str(recommended_action.get("id") or ""),
            "step": int(recommended_action.get("step") or 0),
            "title": str(recommended_action.get("title") or ""),
            "claim_boundary": str(recommended_action.get("claim_boundary") or ""),
            "actions": list(recommended_action.get("actions") or []),
            "commands": list(recommended_action.get("commands") or []),
            "claim_ids": list(recommended_action.get("claim_ids") or []),
            "env": list(recommended_action.get("env") or []),
        },
        "claim_boundary": "redacted operator request only; do not paste real secret values into committed artifacts",
    }


def render_env_request_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Product Readiness Env Request",
        "",
        f"- Required env: `{payload.get('required_env_count') or 0}`",
        f"- Secrets: `{payload.get('secret_count') or 0}`",
        f"- Metadata: `{payload.get('metadata_count') or 0}`",
        f"- Recommended next action: `{payload.get('recommended_next_action_id') or '-'}`",
        "",
        "| Env | Class | Owner | Placeholder | Description |",
        "|-----|-------|-------|-------------|-------------|",
    ]
    entries = payload.get("entries") if isinstance(payload.get("entries"), list) else []
    if entries:
        for entry in entries:
            lines.append(
                f"| `{entry.get('env')}` | `{entry.get('class') or '-'}` | `{entry.get('owner') or '-'}` | "
                f"`{entry.get('placeholder') or '-'}` | {str(entry.get('description') or '-').replace('|', '/')} |"
            )
    else:
        lines.append("| - | - | - | - | - |")
    lines.extend(["", "## Copy/Paste PowerShell", ""])
    commands = [str(command) for command in payload.get("copy_paste_powershell") or [] if command]
    if commands:
        lines.append("```powershell")
        lines.extend(commands)
        lines.append("```")
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Local Bundle Check",
            "",
            "Prepare ignored `docs/benchmarks/generated/validation_product_readiness_env_bundle.local.env` from `docs/benchmarks/generated/validation_product_readiness_env_bundle.template.env`, replace placeholders with real local values, then run:",
            "",
            "```powershell",
            "powershell -NoProfile -ExecutionPolicy Bypass -File docs/benchmarks/generated/validation_product_readiness_env_bundle_init.ps1",
            "powershell -NoProfile -ExecutionPolicy Bypass -File docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_init.ps1",
            "powershell -NoProfile -ExecutionPolicy Bypass -File docs/benchmarks/generated/validation_product_readiness_env_bundle_init.ps1 -EnvFile docs/benchmarks/generated/validation_product_readiness_env_bundle.local.env -Force",
            "powershell -NoProfile -ExecutionPolicy Bypass -File docs/benchmarks/generated/validation_product_readiness_env_bundle_init.ps1 -FromProcessEnv -Force",
            "powershell -NoProfile -ExecutionPolicy Bypass -File docs/benchmarks/generated/validation_product_readiness_env_bundle_check.ps1 -Json",
            "```",
            "",
            "The checker reports only env names and counts; it does not print secret values, import env, or launch claims.",
            "The JSON key-list alternative remains `docs/benchmarks/generated/validation_product_readiness_env_bundle.template.json`.",
        ]
    )
    lines.extend(["", "## Claim Boundary", "", str(payload.get("claim_boundary") or "")])
    return "\n".join(lines) + "\n"


def env_request_schema() -> dict[str, Any]:
    entry_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "env",
            "class",
            "owner",
            "description",
            "placeholder",
            "powershell_set_command",
            "claim_ids",
            "package_ids",
        ],
        "properties": {
            "env": {"type": "string"},
            "class": {"enum": ["secret", "claim-metadata", ""]},
            "owner": {"type": "string"},
            "description": {"type": "string"},
            "placeholder": {"type": "string", "pattern": "^<set-.+>$"},
            "powershell_set_command": {"type": "string", "pattern": "^\\$env:[A-Z0-9_]+\\s*="},
            "claim_ids": {"type": "array", "items": {"type": "string"}},
            "package_ids": {"type": "array", "items": {"type": "string"}},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-env-request.schema.json",
        "title": "Tamandua validation product readiness env request",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "generated_at",
            "product_ready",
            "product_release_gate_passed",
            "required_env_count",
            "secret_count",
            "metadata_count",
            "entries",
            "copy_paste_powershell",
            "recommended_next_action_id",
            "recommended_next_action",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-env-request"},
            "generated_at": {"type": ["string", "null"]},
            "product_ready": {"type": "boolean"},
            "product_release_gate_passed": {"type": "boolean"},
            "required_env_count": {"type": "integer", "minimum": 0},
            "secret_count": {"type": "integer", "minimum": 0},
            "metadata_count": {"type": "integer", "minimum": 0},
            "entries": {"type": "array", "items": entry_schema},
            "copy_paste_powershell": {"type": "array", "items": {"type": "string"}},
            "recommended_next_action_id": {"type": "string"},
            "recommended_next_action": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "step", "title", "claim_boundary", "actions", "commands", "claim_ids", "env"],
                "properties": {
                    "id": {"type": "string"},
                    "step": {"type": "integer"},
                    "title": {"type": "string"},
                    "claim_boundary": {"type": "string"},
                    "actions": {"type": "array", "items": {"type": "string"}},
                    "commands": {"type": "array", "items": {"type": "string"}},
                    "claim_ids": {"type": "array", "items": {"type": "string"}},
                    "env": {"type": "array", "items": {"type": "string"}},
                },
            },
            "claim_boundary": {"type": "string"},
        },
    }


def render_env_bundle_check(
    env_request_json_name: str = "validation_product_readiness_env_request.json",
    env_bundle_json_name: str = "validation_product_readiness_env_bundle.local.json",
) -> str:
    return "\n".join(
        [
            "# Product Readiness Env Bundle Check",
            "# Validates a local JSON env bundle without printing secret values.",
            "param(",
            "  [string]$EnvRequestJson = (Join-Path $PSScriptRoot '" + env_request_json_name + "'),",
            "  [string]$EnvBundleJson = (Join-Path $PSScriptRoot '" + env_bundle_json_name + "'),",
            "  [switch]$Json",
            ")",
            "$ErrorActionPreference = 'Stop'",
            "Set-StrictMode -Version Latest",
            "function Read-JsonObject {",
            "  param([string]$Path, [string]$Label)",
            "  if (-not (Test-Path -LiteralPath $Path)) { return $null }",
            "  try { $Payload = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json }",
            "  catch { throw ($Label + ' is not valid JSON: ' + $_.Exception.Message) }",
            "  if (-not $Payload -or $Payload -isnot [pscustomobject]) { throw ($Label + ' must be a JSON object.') }",
            "  return $Payload",
            "}",
            "$Request = Read-JsonObject -Path $EnvRequestJson -Label 'Env request'",
            "if (-not $Request) { throw ('Missing env request JSON: ' + $EnvRequestJson) }",
            "$Entries = @($Request.entries)",
            "$RequiredNames = @($Entries | ForEach-Object { [string]$_.env } | Where-Object { $_ })",
            "$PlaceholderByName = @{}",
            "foreach ($Entry in $Entries) {",
            "  if ($Entry.env) { $PlaceholderByName[[string]$Entry.env] = [string]$Entry.placeholder }",
            "}",
            "$Bundle = Read-JsonObject -Path $EnvBundleJson -Label 'Env bundle'",
            "$BundleExists = [bool]$Bundle",
            "$BundleNames = @()",
            "if ($BundleExists) { $BundleNames = @($Bundle.PSObject.Properties.Name | ForEach-Object { [string]$_ }) }",
            "$Missing = @()",
            "$Empty = @()",
            "$Placeholder = @()",
            "$Present = @()",
            "foreach ($Name in $RequiredNames) {",
            "  $Property = if ($BundleExists) { $Bundle.PSObject.Properties[$Name] } else { $null }",
            "  if (-not $Property) { $Missing += $Name; continue }",
            "  $Value = if ($null -eq $Property.Value) { '' } else { [string]$Property.Value }",
            "  $Trimmed = $Value.Trim()",
            "  if (-not $Trimmed) { $Empty += $Name; continue }",
            "  $ExpectedPlaceholder = if ($PlaceholderByName.ContainsKey($Name)) { [string]$PlaceholderByName[$Name] } else { '' }",
            "  if ($Trimmed -eq $ExpectedPlaceholder -or $Trimmed -match '^<set-.+>$') { $Placeholder += $Name; continue }",
            "  $Present += $Name",
            "}",
            "$RequiredSet = @{}",
            "foreach ($Name in $RequiredNames) { $RequiredSet[$Name] = $true }",
            "$Unexpected = @($BundleNames | Where-Object { -not $RequiredSet.ContainsKey($_) } | Sort-Object)",
            "$UnexpectedBlocks = ($RequiredNames.Count -gt 0 -and $Unexpected.Count -gt 0)",
            "$Complete = ($BundleExists -and $Missing.Count -eq 0 -and $Empty.Count -eq 0 -and $Placeholder.Count -eq 0 -and -not $UnexpectedBlocks)",
            "$CanLaunchAfterImport = [bool]($Complete -and $RequiredNames.Count -gt 0)",
            "$Payload = [ordered]@{",
            "  schema_version = 1",
            "  artifact = 'validation-product-readiness-env-bundle-check'",
            "  env_request_json = $EnvRequestJson",
            "  env_bundle_json = $EnvBundleJson",
            "  bundle_exists = [bool]$BundleExists",
            "  complete = [bool]$Complete",
            "  required_env_count = [int]$RequiredNames.Count",
            "  present_env_count = [int]$Present.Count",
            "  missing_env_names = @($Missing)",
            "  empty_env_names = @($Empty)",
            "  placeholder_env_names = @($Placeholder)",
            "  unexpected_env_names = @($Unexpected)",
            "  can_launch_after_import = [bool]$CanLaunchAfterImport",
            "  claim_boundary = 'local env bundle validation only; output intentionally omits secret values and does not import env or launch claims'",
            "}",
            "if ($Json) {",
            "  $Payload | ConvertTo-Json -Depth 8",
            "} else {",
            "  Write-Host ('Env bundle complete: ' + $Complete)",
            "  Write-Host ('Bundle file: ' + $EnvBundleJson)",
            "  Write-Host ('Required env: ' + $RequiredNames.Count)",
            "  Write-Host ('Present env: ' + $Present.Count)",
            "  if ($Missing.Count) { Write-Host ('Missing env: ' + (($Missing | Sort-Object) -join ', ')) }",
            "  if ($Empty.Count) { Write-Host ('Empty env: ' + (($Empty | Sort-Object) -join ', ')) }",
            "  if ($Placeholder.Count) { Write-Host ('Placeholder env: ' + (($Placeholder | Sort-Object) -join ', ')) }",
            "  if ($Unexpected.Count) { Write-Host ('Unexpected env: ' + (($Unexpected | Sort-Object) -join ', ')) }",
            "  Write-Host 'No secret values were printed.'",
            "}",
            "if ($Complete) { exit 0 }",
            "exit 2",
            "",
        ]
    )


def env_bundle_check_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-env-bundle-check.schema.json",
        "title": "Tamandua validation product readiness env bundle check output",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "env_request_json",
            "env_bundle_json",
            "bundle_exists",
            "complete",
            "required_env_count",
            "present_env_count",
            "missing_env_names",
            "empty_env_names",
            "placeholder_env_names",
            "unexpected_env_names",
            "can_launch_after_import",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-env-bundle-check"},
            "env_request_json": {"type": "string"},
            "env_bundle_json": {"type": "string"},
            "bundle_exists": {"type": "boolean"},
            "complete": {"type": "boolean"},
            "required_env_count": {"type": "integer", "minimum": 0},
            "present_env_count": {"type": "integer", "minimum": 0},
            "missing_env_names": {"type": "array", "items": {"type": "string"}},
            "empty_env_names": {"type": "array", "items": {"type": "string"}},
            "placeholder_env_names": {"type": "array", "items": {"type": "string"}},
            "unexpected_env_names": {"type": "array", "items": {"type": "string"}},
            "can_launch_after_import": {"type": "boolean"},
            "claim_boundary": {"type": "string"},
        },
    }


def env_bundle_local_schema(env_request: dict[str, Any]) -> dict[str, Any]:
    entries = [entry for entry in env_request.get("entries") or [] if isinstance(entry, dict)]
    properties = {}
    required = []
    for entry in entries:
        env_name = str(entry.get("env") or "")
        placeholder = str(entry.get("placeholder") or "")
        if not env_name:
            continue
        required.append(env_name)
        properties[env_name] = {
            "type": "string",
            "minLength": 1,
            "not": {"enum": [placeholder]},
            "description": str(entry.get("description") or ""),
        }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-env-bundle.local.schema.json",
        "title": "Local Tamandua validation env bundle",
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


def env_bundle_template_payload(env_request: dict[str, Any]) -> dict[str, str]:
    return {
        str(entry.get("env") or ""): str(entry.get("placeholder") or "")
        for entry in env_request.get("entries") or []
        if isinstance(entry, dict) and entry.get("env")
    }


def render_env_bundle_dotenv_template(env_request: dict[str, Any]) -> str:
    lines = [
        "# Product readiness env bundle dotenv template",
        "# Replace placeholder values locally. Do not commit real values.",
        "# Copy this file to validation_product_readiness_env_bundle.local.env before editing.",
    ]
    for entry in env_request.get("entries") or []:
        if not isinstance(entry, dict) or not entry.get("env"):
            continue
        env_name = str(entry.get("env") or "")
        placeholder = str(entry.get("placeholder") or "")
        description = str(entry.get("description") or "").replace("\n", " ")
        if description:
            lines.append(f"# {description}")
        lines.append(f"{env_name}='{placeholder}'")
    return "\n".join(lines) + "\n"


def local_env_bundle_gate(
    env_summary: dict[str, Any],
    bundle_path: Path | None = None,
) -> dict[str, Any]:
    bundle_path = bundle_path or (GENERATED_DIR / "validation_product_readiness_env_bundle.local.json")
    required_names = [str(name) for name in env_summary.get("current_env_missing_names") or [] if name]
    placeholders = {
        str(item.get("env") or ""): str(item.get("powershell_set_command") or "")
        for item in env_summary.get("env_impact") or []
        if isinstance(item, dict) and item.get("env")
    }
    exists = bundle_path.exists()
    missing = list(required_names)
    empty: list[str] = []
    placeholder: list[str] = []
    present: list[str] = []
    unexpected: list[str] = []
    parse_error = ""
    if exists:
        try:
            bundle = json.loads(bundle_path.read_text(encoding="utf-8-sig"))
            if not isinstance(bundle, dict):
                parse_error = "local env bundle must be a JSON object"
                bundle = {}
        except Exception as exc:  # pragma: no cover - exact JSON messages vary by runtime
            parse_error = str(exc)
            bundle = {}
        required_set = set(required_names)
        missing = []
        unexpected = sorted(str(name) for name in bundle if str(name) not in required_set)
        for name in required_names:
            if name not in bundle:
                missing.append(name)
                continue
            value = "" if bundle[name] is None else str(bundle[name])
            trimmed = value.strip()
            if not trimmed:
                empty.append(name)
                continue
            command_placeholder = placeholders.get(name, "")
            if trimmed.startswith("<set-") and trimmed.endswith(">"):
                placeholder.append(name)
                continue
            if command_placeholder and trimmed in command_placeholder:
                placeholder.append(name)
                continue
            present.append(name)
    complete = (
        exists
        and not parse_error
        and not missing
        and not empty
        and not placeholder
        and not unexpected
    )
    return {
        "schema_version": 1,
        "artifact": "validation-product-readiness-local-env-bundle-gate",
        "bundle_path": rel(bundle_path),
        "exists": bool(exists),
        "complete": bool(complete),
        "required_env_count": len(required_names),
        "present_env_count": len(present),
        "missing_env_names": missing,
        "empty_env_names": empty,
        "placeholder_env_names": placeholder,
        "unexpected_env_names": unexpected,
        "parse_error": parse_error,
        "claim_boundary": "local ignored env bundle status only; never includes secret values",
    }


def render_env_bundle_local_env_init(
    template_env_name: str = "validation_product_readiness_env_bundle.template.env",
    local_env_name: str = "validation_product_readiness_env_bundle.local.env",
    env_bundle_init_name: str = "validation_product_readiness_env_bundle_init.ps1",
) -> str:
    return "\n".join(
        [
            "# Product Readiness Env Bundle Local Env Init",
            "# Copies the redacted dotenv template to an ignored local dotenv file without printing values.",
            "param(",
            "  [string]$TemplateEnv = (Join-Path $PSScriptRoot '" + template_env_name + "'),",
            "  [string]$LocalEnv = (Join-Path $PSScriptRoot '" + local_env_name + "'),",
            "  [string]$EnvBundleInit = (Join-Path $PSScriptRoot '" + env_bundle_init_name + "'),",
            "  [switch]$Force,",
            "  [switch]$Json",
            ")",
            "$ErrorActionPreference = 'Stop'",
            "Set-StrictMode -Version Latest",
            "if (-not (Test-Path -LiteralPath $TemplateEnv)) {",
            "  $Message = 'Missing dotenv template: ' + $TemplateEnv",
            "  if ($Json) {",
            "    [ordered]@{",
            "      schema_version = 1",
            "      artifact = 'validation-product-readiness-env-bundle-local-env-init'",
            "      template_env = [string]$TemplateEnv",
            "      local_env = [string]$LocalEnv",
            "      created = $false",
            "      overwrote = $false",
            "      force = [bool]$Force",
            "      init_command = 'powershell -NoProfile -ExecutionPolicy Bypass -File ' + $EnvBundleInit + ' -EnvFile ' + $LocalEnv + ' -Force'",
            "      message = $Message",
            "      claim_boundary = 'local dotenv initialization only; output omits secret values and does not validate or launch claims'",
            "    } | ConvertTo-Json -Depth 8",
            "  } else { Write-Error $Message }",
            "  exit 2",
            "}",
            "$Existed = [bool](Test-Path -LiteralPath $LocalEnv)",
            "if ($Existed -and -not $Force) {",
            "  $Message = 'Local dotenv already exists; refusing to overwrite without -Force.'",
            "  $Created = $false",
            "  $Overwrote = $false",
            "} else {",
            "  $Parent = Split-Path -Parent $LocalEnv",
            "  if ($Parent -and -not (Test-Path -LiteralPath $Parent)) { New-Item -ItemType Directory -Force -Path $Parent | Out-Null }",
            "  Copy-Item -LiteralPath $TemplateEnv -Destination $LocalEnv -Force",
            "  $Created = $true",
            "  $Overwrote = $Existed",
            "  $Message = if ($Existed) { 'Local dotenv refreshed from template.' } else { 'Local dotenv created from template.' }",
            "}",
            "$Payload = [ordered]@{",
            "  schema_version = 1",
            "  artifact = 'validation-product-readiness-env-bundle-local-env-init'",
            "  template_env = [string]$TemplateEnv",
            "  local_env = [string]$LocalEnv",
            "  created = [bool]$Created",
            "  overwrote = [bool]$Overwrote",
            "  force = [bool]$Force",
            "  init_command = 'powershell -NoProfile -ExecutionPolicy Bypass -File ' + $EnvBundleInit + ' -EnvFile ' + $LocalEnv + ' -Force'",
            "  message = $Message",
            "  claim_boundary = 'local dotenv initialization only; output omits secret values and does not validate or launch claims'",
            "}",
            "if ($Json) {",
            "  $Payload | ConvertTo-Json -Depth 8",
            "} else {",
            "  Write-Host $Message",
            "  Write-Host ('Local dotenv file: ' + $LocalEnv)",
            "  Write-Host 'No secret values were printed.'",
            "  Write-Host ('Next: edit placeholders locally, then run: ' + $Payload.init_command)",
            "}",
            "if ($Created) { exit 0 }",
            "exit 2",
            "",
        ]
    )


def env_bundle_local_env_init_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-env-bundle-local-env-init.schema.json",
        "title": "Tamandua validation product readiness local dotenv init output",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "template_env",
            "local_env",
            "created",
            "overwrote",
            "force",
            "init_command",
            "message",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-env-bundle-local-env-init"},
            "template_env": {"type": "string"},
            "local_env": {"type": "string"},
            "created": {"type": "boolean"},
            "overwrote": {"type": "boolean"},
            "force": {"type": "boolean"},
            "init_command": {"type": "string"},
            "message": {"type": "string"},
            "claim_boundary": {"type": "string"},
        },
    }


def render_env_bundle_local_env_validate(
    template_env_name: str = "validation_product_readiness_env_bundle.template.env",
    local_env_name: str = "validation_product_readiness_env_bundle.local.env",
    env_bundle_init_name: str = "validation_product_readiness_env_bundle_init.ps1",
    env_bundle_check_name: str = "validation_product_readiness_env_bundle_check.ps1",
    env_bundle_runner_name: str = "validation_product_readiness_env_bundle_runner.ps1",
    doctor_name: str = "validation_product_readiness_doctor.ps1",
) -> str:
    return "\n".join(
        [
            "# Product Readiness Env Bundle Local Env Validate",
            "# Converts the ignored local dotenv into the ignored JSON bundle, then runs no-exec readiness checks.",
            "param(",
            "  [string]$TemplateEnv = (Join-Path $PSScriptRoot '" + template_env_name + "'),",
            "  [string]$LocalEnv = (Join-Path $PSScriptRoot '" + local_env_name + "'),",
            "  [string]$EnvBundleInit = (Join-Path $PSScriptRoot '" + env_bundle_init_name + "'),",
            "  [string]$EnvBundleCheck = (Join-Path $PSScriptRoot '" + env_bundle_check_name + "'),",
            "  [string]$EnvBundleRunner = (Join-Path $PSScriptRoot '" + env_bundle_runner_name + "'),",
            "  [string]$Doctor = (Join-Path $PSScriptRoot '" + doctor_name + "'),",
            "  [switch]$PrepareIfMissing,",
            "  [switch]$Json",
            ")",
            "$ErrorActionPreference = 'Continue'",
            "Set-StrictMode -Version Latest",
            "$PreparedLocalEnv = $false",
            "if ($PrepareIfMissing -and -not (Test-Path -LiteralPath $LocalEnv)) {",
            "  if (Test-Path -LiteralPath $TemplateEnv) {",
            "    $Parent = Split-Path -Parent $LocalEnv",
            "    if ($Parent -and -not (Test-Path -LiteralPath $Parent)) { New-Item -ItemType Directory -Force -Path $Parent | Out-Null }",
            "    Copy-Item -LiteralPath $TemplateEnv -Destination $LocalEnv -Force",
            "    $PreparedLocalEnv = $true",
            "  }",
            "}",
            "function Invoke-JsonCommand {",
            "  param([string[]]$Command)",
            "  $Executable = [string]$Command[0]",
            "  $Arguments = @($Command | Select-Object -Skip 1)",
            "  $Text = & $Executable @Arguments 2>$null",
            "  $Exit = if ($LASTEXITCODE -eq $null) { 0 } else { [int]$LASTEXITCODE }",
            "  $Parsed = $null",
            "  $ParseError = ''",
            "  try { $Parsed = ($Text | Out-String) | ConvertFrom-Json } catch { $ParseError = $_.Exception.Message }",
            "  [ordered]@{ exit_code = $Exit; payload = $Parsed; parse_error = $ParseError }",
            "}",
            "function Read-DotenvAudit {",
            "  param([string]$TemplateEnvPath, [string]$LocalEnvPath)",
            "  $ExpectedNames = @()",
            "  $PlaceholderByName = @{}",
            "  if (Test-Path -LiteralPath $TemplateEnvPath) {",
            "    foreach ($Line in Get-Content -LiteralPath $TemplateEnvPath) {",
            "      if ($Line -match '^\\s*#' -or -not $Line.Trim()) { continue }",
            "      if ($Line -match '^\\s*(?:export\\s+)?([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(.*)\\s*$') {",
            "        $Key = [string]$Matches[1]",
            "        $Value = [string]$Matches[2]",
            "        if (($Value.StartsWith('\"') -and $Value.EndsWith('\"')) -or ($Value.StartsWith(\"'\") -and $Value.EndsWith(\"'\"))) {",
            "          if ($Value.Length -ge 2) { $Value = $Value.Substring(1, $Value.Length - 2) }",
            "        }",
            "        if (-not $PlaceholderByName.ContainsKey($Key)) { $ExpectedNames += $Key }",
            "        $PlaceholderByName[$Key] = $Value",
            "      }",
            "    }",
            "  }",
            "  $ValueByName = @{}",
            "  if (Test-Path -LiteralPath $LocalEnvPath) {",
            "    foreach ($Line in Get-Content -LiteralPath $LocalEnvPath) {",
            "      if ($Line -match '^\\s*#' -or -not $Line.Trim()) { continue }",
            "      if ($Line -match '^\\s*(?:export\\s+)?([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(.*)\\s*$') {",
            "        $Key = [string]$Matches[1]",
            "        $Value = [string]$Matches[2]",
            "        if (($Value.StartsWith('\"') -and $Value.EndsWith('\"')) -or ($Value.StartsWith(\"'\") -and $Value.EndsWith(\"'\"))) {",
            "          if ($Value.Length -ge 2) { $Value = $Value.Substring(1, $Value.Length - 2) }",
            "        }",
            "        $ValueByName[$Key] = $Value",
            "      }",
            "    }",
            "  }",
            "  $Missing = @()",
            "  $Empty = @()",
            "  $Placeholder = @()",
            "  $Present = @()",
            "  foreach ($Name in @($ExpectedNames | Sort-Object -Unique)) {",
            "    if (-not $ValueByName.ContainsKey($Name)) { $Missing += $Name; continue }",
            "    $Value = [string]$ValueByName[$Name]",
            "    $Trimmed = $Value.Trim()",
            "    if (-not $Trimmed) { $Empty += $Name; continue }",
            "    $ExpectedPlaceholder = if ($PlaceholderByName.ContainsKey($Name)) { [string]$PlaceholderByName[$Name] } else { '' }",
            "    if ($Trimmed -eq $ExpectedPlaceholder -or $Trimmed -match '^<set-.+>$') { $Placeholder += $Name; continue }",
            "    $Present += $Name",
            "  }",
            "  [ordered]@{ present_env_names = @($Present); missing_env_names = @($Missing); empty_env_names = @($Empty); placeholder_env_names = @($Placeholder) }",
            "}",
            "$LocalEnvAudit = Read-DotenvAudit -TemplateEnvPath $TemplateEnv -LocalEnvPath $LocalEnv",
            "$Init = Invoke-JsonCommand @('powershell','-NoProfile','-ExecutionPolicy','Bypass','-File',$EnvBundleInit,'-EnvFile',$LocalEnv,'-Force','-Json')",
            "$Check = Invoke-JsonCommand @('powershell','-NoProfile','-ExecutionPolicy','Bypass','-File',$EnvBundleCheck,'-Json')",
            "$DoctorResult = Invoke-JsonCommand @('powershell','-NoProfile','-ExecutionPolicy','Bypass','-File',$Doctor,'-Json')",
            "$CheckPayload = $Check.payload",
            "$DoctorPayload = $DoctorResult.payload",
            "$Complete = [bool]($CheckPayload -and $CheckPayload.complete)",
            "$CanLaunch = [bool]($DoctorPayload -and $DoctorPayload.can_launch_post_env)",
            "$PostEnvLaunchCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File ' + $EnvBundleRunner + ' -UseBalancedAgents -Execute -RefreshClaimStatus'",
            "$PostEnvLaunchRefreshAuthorityCommand = $PostEnvLaunchCommand + ' -RefreshAuthority'",
            "$ValidateCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File ' + $PSCommandPath + ' -PrepareIfMissing -Json'",
            "$NextActionCommand = if ($CanLaunch) { $PostEnvLaunchCommand } else { $ValidateCommand }",
            "$NextActionDescription = if ($CanLaunch) { 'launch post-env claims' } else { 'edit local dotenv placeholders with real values, then rerun validate-only wrapper' }",
            "$Payload = [ordered]@{",
            "  schema_version = 1",
            "  artifact = 'validation-product-readiness-env-bundle-local-env-validate'",
            "  template_env = [string]$TemplateEnv",
            "  local_env = [string]$LocalEnv",
            "  prepare_if_missing = [bool]$PrepareIfMissing",
            "  prepared_local_env = [bool]$PreparedLocalEnv",
            "  local_env_present_names = @($LocalEnvAudit.present_env_names)",
            "  local_env_missing_names = @($LocalEnvAudit.missing_env_names)",
            "  local_env_empty_names = @($LocalEnvAudit.empty_env_names)",
            "  local_env_placeholder_names = @($LocalEnvAudit.placeholder_env_names)",
            "  init_exit_code = [int]$Init.exit_code",
            "  check_exit_code = [int]$Check.exit_code",
            "  doctor_exit_code = [int]$DoctorResult.exit_code",
            "  init_parse_error = [string]$Init.parse_error",
            "  check_parse_error = [string]$Check.parse_error",
            "  doctor_parse_error = [string]$DoctorResult.parse_error",
            "  complete = [bool]$Complete",
            "  can_launch_post_env = [bool]$CanLaunch",
            "  next_action_command = [string]$NextActionCommand",
            "  next_action_description = [string]$NextActionDescription",
            "  post_env_launch_command = [string]$PostEnvLaunchCommand",
            "  post_env_launch_refresh_authority_command = [string]$PostEnvLaunchRefreshAuthorityCommand",
            "  missing_env_names = @($CheckPayload.missing_env_names)",
            "  placeholder_env_names = @($CheckPayload.placeholder_env_names)",
            "  recommended_next_action_id = if ($DoctorPayload) { [string]$DoctorPayload.recommended_next_action_id } else { '' }",
            "  claim_boundary = 'local dotenv validate-only aggregation; output omits secret values and does not launch claims'",
            "}",
            "if ($Json) {",
            "  $Payload | ConvertTo-Json -Depth 10",
            "} else {",
            "  Write-Host ('Env bundle complete: ' + [string]$Payload.complete)",
            "  Write-Host ('Can launch post-env: ' + [string]$Payload.can_launch_post_env)",
            "  Write-Host ('Recommended next action: ' + [string]$Payload.recommended_next_action_id)",
            "  Write-Host ('Next action command: ' + [string]$Payload.next_action_command)",
            "  if ($Payload.can_launch_post_env) { Write-Host ('Post-env launch command: ' + [string]$Payload.post_env_launch_command) }",
            "  if ($Payload.prepared_local_env) { Write-Host ('Prepared local dotenv file: ' + [string]$Payload.local_env) }",
            "  if (@($Payload.local_env_missing_names).Count) { Write-Host ('Local dotenv missing env: ' + (@($Payload.local_env_missing_names) -join ', ')) }",
            "  if (@($Payload.local_env_empty_names).Count) { Write-Host ('Local dotenv empty env: ' + (@($Payload.local_env_empty_names) -join ', ')) }",
            "  if (@($Payload.local_env_placeholder_names).Count) { Write-Host ('Local dotenv placeholder env: ' + (@($Payload.local_env_placeholder_names) -join ', ')) }",
            "  if (@($Payload.missing_env_names).Count) { Write-Host ('Missing env: ' + (@($Payload.missing_env_names) -join ', ')) }",
            "  if (@($Payload.placeholder_env_names).Count) { Write-Host ('Placeholder env: ' + (@($Payload.placeholder_env_names) -join ', ')) }",
            "  Write-Host 'No secret values were printed.'",
            "}",
            "if ($Complete -and $CanLaunch -and -not $Payload.init_parse_error -and -not $Payload.check_parse_error -and -not $Payload.doctor_parse_error) { exit 0 }",
            "exit 2",
            "",
        ]
    )


def env_bundle_local_env_validate_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-env-bundle-local-env-validate.schema.json",
        "title": "Tamandua validation product readiness local dotenv validate output",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "template_env",
            "local_env",
            "prepare_if_missing",
            "prepared_local_env",
            "local_env_present_names",
            "local_env_missing_names",
            "local_env_empty_names",
            "local_env_placeholder_names",
            "init_exit_code",
            "check_exit_code",
            "doctor_exit_code",
            "init_parse_error",
            "check_parse_error",
            "doctor_parse_error",
            "complete",
            "can_launch_post_env",
            "next_action_command",
            "next_action_description",
            "post_env_launch_command",
            "post_env_launch_refresh_authority_command",
            "missing_env_names",
            "placeholder_env_names",
            "recommended_next_action_id",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-env-bundle-local-env-validate"},
            "template_env": {"type": "string"},
            "local_env": {"type": "string"},
            "prepare_if_missing": {"type": "boolean"},
            "prepared_local_env": {"type": "boolean"},
            "local_env_present_names": {"type": "array", "items": {"type": "string"}},
            "local_env_missing_names": {"type": "array", "items": {"type": "string"}},
            "local_env_empty_names": {"type": "array", "items": {"type": "string"}},
            "local_env_placeholder_names": {"type": "array", "items": {"type": "string"}},
            "init_exit_code": {"type": "integer"},
            "check_exit_code": {"type": "integer"},
            "doctor_exit_code": {"type": "integer"},
            "init_parse_error": {"type": "string"},
            "check_parse_error": {"type": "string"},
            "doctor_parse_error": {"type": "string"},
            "complete": {"type": "boolean"},
            "can_launch_post_env": {"type": "boolean"},
            "next_action_command": {"type": "string"},
            "next_action_description": {"type": "string"},
            "post_env_launch_command": {"type": "string"},
            "post_env_launch_refresh_authority_command": {"type": "string"},
            "missing_env_names": {"type": "array", "items": {"type": "string"}},
            "placeholder_env_names": {"type": "array", "items": {"type": "string"}},
            "recommended_next_action_id": {"type": "string"},
            "claim_boundary": {"type": "string"},
        },
    }


def render_env_bundle_init(
    env_bundle_template_name: str = "validation_product_readiness_env_bundle.template.json",
    env_bundle_json_name: str = "validation_product_readiness_env_bundle.local.json",
    env_bundle_check_name: str = "validation_product_readiness_env_bundle_check.ps1",
) -> str:
    return "\n".join(
        [
            "# Product Readiness Env Bundle Init",
            "# Creates the ignored local env bundle from the redacted template without real secret values.",
            "param(",
            "  [string]$TemplateJson = (Join-Path $PSScriptRoot '" + env_bundle_template_name + "'),",
            "  [string]$EnvBundleJson = (Join-Path $PSScriptRoot '" + env_bundle_json_name + "'),",
            "  [string]$EnvBundleCheck = (Join-Path $PSScriptRoot '" + env_bundle_check_name + "'),",
            "  [string]$EnvFile = '',",
            "  [switch]$Force,",
            "  [switch]$FromProcessEnv,",
            "  [switch]$Json",
            ")",
            "$ErrorActionPreference = 'Stop'",
            "Set-StrictMode -Version Latest",
            "if (-not (Test-Path -LiteralPath $TemplateJson)) { Write-Error ('Missing env bundle template: ' + $TemplateJson); exit 2 }",
            "$Created = $false",
            "$Overwrote = $false",
            "$Missing = @()",
            "$Mode = if ($EnvFile) { 'env-file' } elseif ($FromProcessEnv) { 'process-env' } else { 'template' }",
            "if ($EnvFile -and $FromProcessEnv) { Write-Error 'Use either -EnvFile or -FromProcessEnv, not both.'; exit 2 }",
            "if ((Test-Path -LiteralPath $EnvBundleJson) -and -not $Force) {",
            "  $Message = 'Local env bundle already exists; refusing to overwrite without -Force.'",
            "} else {",
            "  $Parent = Split-Path -Parent $EnvBundleJson",
            "  if ($Parent -and -not (Test-Path -LiteralPath $Parent)) { New-Item -ItemType Directory -Force -Path $Parent | Out-Null }",
            "  $ExistingBundle = [bool](Test-Path -LiteralPath $EnvBundleJson)",
            "  if ($FromProcessEnv) {",
            "    try { $Template = Get-Content -Raw -LiteralPath $TemplateJson | ConvertFrom-Json }",
            "    catch { Write-Error ('Unable to parse env bundle template: ' + $_.Exception.Message); exit 2 }",
            "    $Bundle = [ordered]@{}",
            "    foreach ($Name in @($Template.PSObject.Properties.Name | Sort-Object)) {",
            "      $Value = [Environment]::GetEnvironmentVariable([string]$Name, 'Process')",
            "      if ($null -eq $Value -or -not ([string]$Value).Trim()) { $Missing += [string]$Name } else { $Bundle[[string]$Name] = [string]$Value }",
            "    }",
            "    if (-not $Missing.Count) {",
            "      [System.IO.File]::WriteAllText($EnvBundleJson, (($Bundle | ConvertTo-Json -Depth 4) + [Environment]::NewLine), [System.Text.UTF8Encoding]::new($false))",
            "      $Created = $true",
            "      $Overwrote = [bool]$ExistingBundle",
            "      $Message = 'Local env bundle initialized from process env. Secret values were written only to the ignored local bundle.'",
            "    } else {",
            "      $Message = 'Process env is missing required names; local env bundle was not written.'",
            "    }",
            "  } elseif ($EnvFile) {",
            "    if (-not (Test-Path -LiteralPath $EnvFile)) { Write-Error ('Missing env file: ' + $EnvFile); exit 2 }",
            "    try { $Template = Get-Content -Raw -LiteralPath $TemplateJson | ConvertFrom-Json }",
            "    catch { Write-Error ('Unable to parse env bundle template: ' + $_.Exception.Message); exit 2 }",
            "    $FileValues = @{}",
            "    foreach ($Line in Get-Content -LiteralPath $EnvFile) {",
            "      if ($Line -match '^\\s*#' -or -not $Line.Trim()) { continue }",
            "      if ($Line -match '^\\s*(?:export\\s+)?([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(.*)\\s*$') {",
            "        $Key = [string]$Matches[1]",
            "        $Value = [string]$Matches[2]",
            "        if (($Value.StartsWith('\"') -and $Value.EndsWith('\"')) -or ($Value.StartsWith(\"'\") -and $Value.EndsWith(\"'\"))) {",
            "          if ($Value.Length -ge 2) { $Value = $Value.Substring(1, $Value.Length - 2) }",
            "        }",
            "        $FileValues[$Key] = $Value",
            "      }",
            "    }",
            "    $Bundle = [ordered]@{}",
            "    foreach ($Name in @($Template.PSObject.Properties.Name | Sort-Object)) {",
            "      if (-not $FileValues.ContainsKey([string]$Name) -or -not ([string]$FileValues[[string]$Name]).Trim()) {",
            "        $Missing += [string]$Name",
            "      } else {",
            "        $Bundle[[string]$Name] = [string]$FileValues[[string]$Name]",
            "      }",
            "    }",
            "    if (-not $Missing.Count) {",
            "      [System.IO.File]::WriteAllText($EnvBundleJson, (($Bundle | ConvertTo-Json -Depth 4) + [Environment]::NewLine), [System.Text.UTF8Encoding]::new($false))",
            "      $Created = $true",
            "      $Overwrote = [bool]$ExistingBundle",
            "      $Message = 'Local env bundle initialized from env file. Secret values were written only to the ignored local bundle.'",
            "    } else {",
            "      $Message = 'Env file is missing required names; local env bundle was not written.'",
            "    }",
            "  } else {",
            "    Copy-Item -LiteralPath $TemplateJson -Destination $EnvBundleJson -Force",
            "    $Created = $true",
            "    $Overwrote = [bool]$ExistingBundle",
            "    $Message = 'Local env bundle initialized from redacted template. Replace placeholder values before launch.'",
            "  }",
            "}",
            "$Payload = [ordered]@{",
            "  schema_version = 1",
            "  artifact = 'validation-product-readiness-env-bundle-init'",
            "  template_json = $TemplateJson",
            "  env_bundle_json = $EnvBundleJson",
            "  env_file = $EnvFile",
            "  mode = $Mode",
            "  created = [bool]$Created",
            "  overwrote = [bool]$Overwrote",
            "  force = [bool]$Force",
            "  from_process_env = [bool]$FromProcessEnv",
            "  from_env_file = [bool]$EnvFile",
            "  missing_env_names = @($Missing)",
            "  check_command = ('powershell -NoProfile -ExecutionPolicy Bypass -File \"' + $EnvBundleCheck + '\" -EnvBundleJson \"' + $EnvBundleJson + '\" -Json')",
            "  claim_boundary = 'local env bundle initialization only; output omits secret values and does not validate or launch claims'",
            "}",
            "if ($Json) {",
            "  $Payload | ConvertTo-Json -Depth 8",
            "} else {",
            "  Write-Host $Message",
            "  Write-Host ('Bundle file: ' + $EnvBundleJson)",
            "  if ($Missing.Count) { Write-Host ('Missing env: ' + (($Missing | Sort-Object) -join ', ')) }",
            "  Write-Host 'No secret values were printed.'",
            "  Write-Host ('Next: ' + $Payload.check_command)",
            "}",
            "if ($Created) { exit 0 }",
            "exit 2",
            "",
        ]
    )


def env_bundle_init_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-env-bundle-init.schema.json",
        "title": "Tamandua validation product readiness env bundle init output",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "template_json",
            "env_bundle_json",
            "env_file",
            "mode",
            "created",
            "overwrote",
            "force",
            "from_process_env",
            "from_env_file",
            "missing_env_names",
            "check_command",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-env-bundle-init"},
            "template_json": {"type": "string"},
            "env_bundle_json": {"type": "string"},
            "env_file": {"type": "string"},
            "mode": {"enum": ["template", "process-env", "env-file"]},
            "created": {"type": "boolean"},
            "overwrote": {"type": "boolean"},
            "force": {"type": "boolean"},
            "from_process_env": {"type": "boolean"},
            "from_env_file": {"type": "boolean"},
            "missing_env_names": {"type": "array", "items": {"type": "string"}},
            "check_command": {"type": "string"},
            "claim_boundary": {"type": "string"},
        },
    }


def render_env_bundle_runner(
    env_bundle_check_name: str = "validation_product_readiness_env_bundle_check.ps1",
    env_bundle_init_name: str = "validation_product_readiness_env_bundle_init.ps1",
    env_bundle_json_name: str = "validation_product_readiness_env_bundle.local.json",
    post_env_runner_name: str = "validation_product_readiness_post_env_bundle_runner.ps1",
) -> str:
    return "\n".join(
        [
            "# Product Readiness Env Bundle Runner",
            "# Imports a local JSON env bundle into this child process, then delegates to the post-env runner.",
            "param(",
            "  [string]$EnvBundleJson = (Join-Path $PSScriptRoot '" + env_bundle_json_name + "'),",
            "  [string]$EnvBundleCheck = (Join-Path $PSScriptRoot '" + env_bundle_check_name + "'),",
            "  [string]$EnvBundleInit = (Join-Path $PSScriptRoot '" + env_bundle_init_name + "'),",
            "  [string]$PostEnvRunner = (Join-Path $PSScriptRoot '" + post_env_runner_name + "'),",
            "  [string]$RefreshAuthorityScript = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\\..\\..')) 'tools\\detection_validation\\refresh_validation_authority.py'),",
            "  [switch]$InitFromProcessEnv,",
            "  [switch]$UseBalancedAgents,",
            "  [switch]$Execute,",
            "  [switch]$RefreshClaimStatus,",
            "  [switch]$RefreshAuthority,",
            "  [switch]$Json",
            ")",
            "$ErrorActionPreference = 'Stop'",
            "Set-StrictMode -Version Latest",
            "function Write-RunnerJson {",
            "  param($InitPayload, $CheckPayload, [int]$ExitCode, [string]$StatusReason)",
            "  $Complete = $false",
            "  $CanLaunch = $false",
            "  if ($CheckPayload -ne $null) { $Complete = [bool]$CheckPayload.complete }",
            "  if ($CheckPayload -ne $null) { $CanLaunch = [bool]$CheckPayload.can_launch_after_import }",
            "  $Payload = [ordered]@{",
            "    schema_version = 1",
            "    artifact = 'validation-product-readiness-env-bundle-runner'",
            "    env_bundle_json = $EnvBundleJson",
            "    init_from_process_env = [bool]$InitFromProcessEnv",
            "    json_status_only = [bool]$Json",
            "    init = $InitPayload",
            "    check = $CheckPayload",
            "    imported_env_names = @()",
            "    delegated_to_post_env_runner = $false",
            "    post_env_runner_exit_code = $null",
            "    refresh_authority = [bool]$RefreshAuthority",
            "    refresh_authority_exit_code = $null",
            "    complete = $Complete",
            "    can_launch = $CanLaunch",
            "    status_reason = $StatusReason",
            "    exit_code = $ExitCode",
            "    claim_boundary = 'JSON status mode does not import secret values or delegate to the post-env runner.'",
            "  }",
            "  $Payload | ConvertTo-Json -Depth 12",
            "}",
            "if (-not (Test-Path -LiteralPath $EnvBundleCheck)) { Write-Error ('Missing env bundle check script: ' + $EnvBundleCheck); exit 2 }",
            "if ($InitFromProcessEnv -and -not (Test-Path -LiteralPath $EnvBundleInit)) { Write-Error ('Missing env bundle init script: ' + $EnvBundleInit); exit 2 }",
            "if (-not (Test-Path -LiteralPath $PostEnvRunner)) { Write-Error ('Missing post-env runner script: ' + $PostEnvRunner); exit 2 }",
            "if ($Json -and ($UseBalancedAgents -or $Execute -or $RefreshClaimStatus -or $RefreshAuthority)) {",
            "  Write-RunnerJson $null $null 2 'json_status_mode_refuses_launch_flags'",
            "  exit 2",
            "}",
            "$InitPayload = $null",
            "if ($InitFromProcessEnv) {",
            "  $InitJsonText = & powershell -NoProfile -ExecutionPolicy Bypass -File $EnvBundleInit -EnvBundleJson $EnvBundleJson -FromProcessEnv -Force -Json",
            "  $InitExit = if ($LASTEXITCODE -eq $null) { 0 } else { [int]$LASTEXITCODE }",
            "  try { $InitPayload = $InitJsonText | ConvertFrom-Json } catch { Write-Error 'Env bundle init did not return valid JSON.'; exit 2 }",
            "  if ($InitExit -ne 0 -or -not [bool]$InitPayload.created) {",
            "    if ($Json) {",
            "      $JsonExit = if ($InitExit -ne 0) { $InitExit } else { 2 }",
            "      Write-RunnerJson $InitPayload $null $JsonExit 'init_failed'",
            "      exit $JsonExit",
            "    }",
            "    Write-Host ('Env bundle init from process env complete: ' + [string][bool]$InitPayload.created)",
            "    Write-Host ('Bundle file: ' + $EnvBundleJson)",
            "    if (@($InitPayload.missing_env_names).Count) { Write-Host ('Missing env: ' + (@($InitPayload.missing_env_names) -join ', ')) }",
            "    Write-Host 'No secret values were printed or imported.'",
            "    if ($InitExit -ne 0) { exit $InitExit }",
            "    exit 2",
            "  }",
            "  if (-not $Json) { Write-Host 'Env bundle initialized from process env. No secret values were printed.' }",
            "}",
            "$CheckJsonText = & powershell -NoProfile -ExecutionPolicy Bypass -File $EnvBundleCheck -EnvBundleJson $EnvBundleJson -Json",
            "$CheckExit = if ($LASTEXITCODE -eq $null) { 0 } else { [int]$LASTEXITCODE }",
            "try { $CheckPayload = $CheckJsonText | ConvertFrom-Json } catch { Write-Error 'Env bundle check did not return valid JSON.'; exit 2 }",
            "if ($Json) {",
            "  $JsonExit = if ($CheckExit -ne 0) { $CheckExit } elseif (-not [bool]$CheckPayload.complete) { 2 } else { 0 }",
            "  $JsonReason = if (-not [bool]$CheckPayload.complete) { 'env_bundle_incomplete' } elseif ([bool]$CheckPayload.can_launch_after_import) { 'ready_to_launch' } else { 'env_bundle_complete_no_launch' }",
            "  Write-RunnerJson $InitPayload $CheckPayload $JsonExit $JsonReason",
            "  exit $JsonExit",
            "}",
            "if ($CheckExit -ne 0 -or -not [bool]$CheckPayload.complete) {",
            "  Write-Host ('Env bundle complete: ' + [string]$CheckPayload.complete)",
            "  Write-Host ('Bundle file: ' + $EnvBundleJson)",
            "  if (@($CheckPayload.missing_env_names).Count) { Write-Host ('Missing env: ' + (@($CheckPayload.missing_env_names) -join ', ')) }",
            "  if (@($CheckPayload.empty_env_names).Count) { Write-Host ('Empty env: ' + (@($CheckPayload.empty_env_names) -join ', ')) }",
            "  if (@($CheckPayload.placeholder_env_names).Count) { Write-Host ('Placeholder env: ' + (@($CheckPayload.placeholder_env_names) -join ', ')) }",
            "  if (@($CheckPayload.unexpected_env_names).Count) { Write-Host ('Unexpected env: ' + (@($CheckPayload.unexpected_env_names) -join ', ')) }",
            "  Write-Host 'No secret values were printed or imported.'",
            "  if ($CheckExit -ne 0) { exit $CheckExit }",
            "  exit 2",
            "}",
            "try { $Bundle = Get-Content -Raw -LiteralPath $EnvBundleJson | ConvertFrom-Json }",
            "catch { Write-Error ('Unable to parse env bundle JSON after validation: ' + $_.Exception.Message); exit 2 }",
            "foreach ($Property in $Bundle.PSObject.Properties) {",
            "  [Environment]::SetEnvironmentVariable([string]$Property.Name, [string]$Property.Value, 'Process')",
            "}",
            "Write-Host ('Imported env bundle names into child process: ' + (@($Bundle.PSObject.Properties.Name) -join ', '))",
            "Write-Host 'No secret values were printed.'",
            "$RunnerArgs = @('-File', $PostEnvRunner)",
            "if ($UseBalancedAgents) { $RunnerArgs += '-UseBalancedAgents' }",
            "if ($Execute) { $RunnerArgs += '-Execute' }",
            "if ($RefreshClaimStatus) { $RunnerArgs += '-RefreshClaimStatus' }",
            "& powershell -NoProfile -ExecutionPolicy Bypass @RunnerArgs",
            "$RunnerExit = if ($LASTEXITCODE -eq $null) { 0 } else { [int]$LASTEXITCODE }",
            "if ($RunnerExit -ne 0) { exit $RunnerExit }",
            "if ($RefreshAuthority) {",
            "  if (-not (Test-Path -LiteralPath $RefreshAuthorityScript)) { Write-Error ('Missing refresh authority script: ' + $RefreshAuthorityScript); exit 2 }",
            "  Write-Host ('Refreshing validation authority: ' + $RefreshAuthorityScript)",
            "  & python $RefreshAuthorityScript",
            "  $RefreshExit = if ($LASTEXITCODE -eq $null) { 0 } else { [int]$LASTEXITCODE }",
            "  if ($RefreshExit -ne 0) { exit $RefreshExit }",
            "}",
            "exit $RunnerExit",
            "",
        ]
    )


def env_bundle_runner_schema() -> dict[str, Any]:
    nullable_object = {"type": ["object", "null"]}
    nullable_integer = {"type": ["integer", "null"]}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-env-bundle-runner.schema.json",
        "title": "Tamandua validation product readiness env bundle runner JSON status",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "env_bundle_json",
            "init_from_process_env",
            "json_status_only",
            "init",
            "check",
            "imported_env_names",
            "delegated_to_post_env_runner",
            "post_env_runner_exit_code",
            "refresh_authority",
            "refresh_authority_exit_code",
            "complete",
            "can_launch",
            "status_reason",
            "exit_code",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-env-bundle-runner"},
            "env_bundle_json": {"type": "string"},
            "init_from_process_env": {"type": "boolean"},
            "json_status_only": {"type": "boolean"},
            "init": nullable_object,
            "check": nullable_object,
            "imported_env_names": {"type": "array", "items": {"type": "string"}},
            "delegated_to_post_env_runner": {"type": "boolean"},
            "post_env_runner_exit_code": nullable_integer,
            "refresh_authority": {"type": "boolean"},
            "refresh_authority_exit_code": nullable_integer,
            "complete": {"type": "boolean"},
            "can_launch": {"type": "boolean"},
            "status_reason": {
                "enum": [
                    "ready_to_launch",
                    "env_bundle_complete_no_launch",
                    "env_bundle_incomplete",
                    "init_failed",
                    "json_status_mode_refuses_launch_flags",
                ]
            },
            "exit_code": {"type": "integer"},
            "claim_boundary": {"type": "string"},
        },
    }


def render_env_bundle_runner_status_check(
    runner_name: str = "validation_product_readiness_env_bundle_runner.ps1",
    runner_schema_name: str = "validation_product_readiness_env_bundle_runner.schema.json",
) -> str:
    return "\n".join(
        [
            "# Product Readiness Env Bundle Runner Status Check",
            "# Validates runner -Json output shape without importing secret values or launching claims.",
            "param(",
            "  [string]$Runner = (Join-Path $PSScriptRoot '" + runner_name + "'),",
            "  [string]$RunnerSchema = (Join-Path $PSScriptRoot '" + runner_schema_name + "'),",
            "  [switch]$InitFromProcessEnv,",
            "  [switch]$Json",
            ")",
            "$ErrorActionPreference = 'Stop'",
            "Set-StrictMode -Version Latest",
            "if (-not (Test-Path -LiteralPath $Runner)) { Write-Error ('Missing env bundle runner: ' + $Runner); exit 3 }",
            "if (-not (Test-Path -LiteralPath $RunnerSchema)) { Write-Error ('Missing env bundle runner schema: ' + $RunnerSchema); exit 3 }",
            "try { $Schema = Get-Content -Raw -LiteralPath $RunnerSchema | ConvertFrom-Json }",
            "catch { Write-Error ('Unable to parse env bundle runner schema: ' + $_.Exception.Message); exit 3 }",
            "$RunnerArgs = @('-File', $Runner, '-Json')",
            "if ($InitFromProcessEnv) { $RunnerArgs += '-InitFromProcessEnv' }",
            "$RunnerJsonText = & powershell -NoProfile -ExecutionPolicy Bypass @RunnerArgs",
            "$RunnerExit = if ($LASTEXITCODE -eq $null) { 0 } else { [int]$LASTEXITCODE }",
            "$ParseError = ''",
            "$RunnerPayload = $null",
            "try { $RunnerPayload = $RunnerJsonText | ConvertFrom-Json }",
            "catch { $ParseError = $_.Exception.Message }",
            "$MissingFields = @()",
            "$InvalidEnumFields = @()",
            "$ArtifactValid = $false",
            "if ($RunnerPayload -ne $null) {",
            "  $PayloadNames = @($RunnerPayload.PSObject.Properties.Name)",
            "  foreach ($Name in @($Schema.required)) {",
            "    if ($PayloadNames -notcontains [string]$Name) { $MissingFields += [string]$Name }",
            "  }",
            "  $ArtifactValid = ([string]$RunnerPayload.artifact -eq [string]$Schema.properties.artifact.const)",
            "  $AllowedStatusReasons = @($Schema.properties.status_reason.enum | ForEach-Object { [string]$_ })",
            "  if ($AllowedStatusReasons -notcontains [string]$RunnerPayload.status_reason) {",
            "    $InvalidEnumFields += 'status_reason'",
            "  }",
            "}",
            "$RunnerContractValid = ($RunnerPayload -ne $null -and $ParseError -eq '' -and $MissingFields.Count -eq 0 -and $InvalidEnumFields.Count -eq 0 -and $ArtifactValid)",
            "$Payload = [ordered]@{",
            "  schema_version = 1",
            "  artifact = 'validation-product-readiness-env-bundle-runner-status-check'",
            "  runner = $Runner",
            "  runner_schema = $RunnerSchema",
            "  init_from_process_env = [bool]$InitFromProcessEnv",
            "  runner_exit_code = $RunnerExit",
            "  runner_contract_valid = [bool]$RunnerContractValid",
            "  runner_complete = if ($RunnerPayload -ne $null) { [bool]$RunnerPayload.complete } else { $false }",
            "  runner_can_launch = if ($RunnerPayload -ne $null) { [bool]$RunnerPayload.can_launch } else { $false }",
            "  runner_status_reason = if ($RunnerPayload -ne $null) { [string]$RunnerPayload.status_reason } else { '' }",
            "  missing_schema_fields = $MissingFields",
            "  invalid_enum_fields = $InvalidEnumFields",
            "  parse_error = $ParseError",
            "  runner_status = $RunnerPayload",
            "  claim_boundary = 'status check validates runner JSON shape only; it does not import secret values or launch claims'",
            "}",
            "if ($Json) {",
            "  $Payload | ConvertTo-Json -Depth 16",
            "} else {",
            "  Write-Host ('Runner contract valid: ' + [string]$Payload.runner_contract_valid)",
            "  Write-Host ('Runner complete: ' + [string]$Payload.runner_complete)",
            "  Write-Host ('Runner can launch: ' + [string]$Payload.runner_can_launch)",
            "  Write-Host ('Runner status reason: ' + [string]$Payload.runner_status_reason)",
            "}",
            "if (-not $RunnerContractValid) { exit 3 }",
            "if (-not [bool]$Payload.runner_complete) { exit 2 }",
            "exit 0",
            "",
        ]
    )


def env_bundle_runner_status_check_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-env-bundle-runner-status-check.schema.json",
        "title": "Tamandua validation product readiness env bundle runner status check",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "runner",
            "runner_schema",
            "init_from_process_env",
            "runner_exit_code",
            "runner_contract_valid",
            "runner_complete",
            "runner_can_launch",
            "runner_status_reason",
            "missing_schema_fields",
            "invalid_enum_fields",
            "parse_error",
            "runner_status",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-env-bundle-runner-status-check"},
            "runner": {"type": "string"},
            "runner_schema": {"type": "string"},
            "init_from_process_env": {"type": "boolean"},
            "runner_exit_code": {"type": "integer"},
            "runner_contract_valid": {"type": "boolean"},
            "runner_complete": {"type": "boolean"},
            "runner_can_launch": {"type": "boolean"},
            "runner_status_reason": {"type": "string"},
            "missing_schema_fields": {"type": "array", "items": {"type": "string"}},
            "invalid_enum_fields": {"type": "array", "items": {"type": "string"}},
            "parse_error": {"type": "string"},
            "runner_status": {"type": ["object", "null"]},
            "claim_boundary": {"type": "string"},
        },
    }


def render_product_readiness_doctor(
    summary_json_name: str = "validation_product_readiness_summary.json",
    operator_check_name: str = "validation_product_readiness_operator_check.ps1",
    env_bundle_runner_status_check_name: str = "validation_product_readiness_env_bundle_runner_status_check.ps1",
    remaining_work_check_name: str = "validation_product_readiness_remaining_work_check.ps1",
    ready_now_fanout_check_name: str = "validation_product_readiness_ready_now_fanout_check.ps1",
    manual_claim_resolution_check_name: str = "validation_product_readiness_manual_claim_resolution_check.ps1",
    manual_claim_resolution_runner_name: str = "validation_product_readiness_manual_claim_resolution_runner.ps1",
) -> str:
    return "\n".join(
        [
            "# Product Readiness Doctor",
            "# Aggregates no-execution readiness checks for agent/operator decision making.",
            "param(",
            "  [string]$SummaryJson = (Join-Path $PSScriptRoot '" + summary_json_name + "'),",
            "  [string]$OperatorCheck = (Join-Path $PSScriptRoot '" + operator_check_name + "'),",
            "  [string]$EnvBundleRunnerStatusCheck = (Join-Path $PSScriptRoot '" + env_bundle_runner_status_check_name + "'),",
            "  [string]$RemainingWorkCheck = (Join-Path $PSScriptRoot '" + remaining_work_check_name + "'),",
            "  [string]$ReadyNowFanoutCheck = (Join-Path $PSScriptRoot '" + ready_now_fanout_check_name + "'),",
            "  [string]$ManualClaimResolutionCheck = (Join-Path $PSScriptRoot '" + manual_claim_resolution_check_name + "'),",
            "  [string]$ManualClaimResolutionRunner = (Join-Path $PSScriptRoot '" + manual_claim_resolution_runner_name + "'),",
            "  [switch]$InitFromProcessEnv,",
            "  [switch]$Json",
            ")",
            "$ErrorActionPreference = 'Stop'",
            "Set-StrictMode -Version Latest",
            "function Invoke-JsonCheck {",
            "  param([string]$Path, [string[]]$ExtraArgs)",
            "  if (-not (Test-Path -LiteralPath $Path)) {",
            "    return [pscustomobject]@{ payload = $null; exit_code = 3; parse_error = ''; missing = $Path }",
            "  }",
            "  $Args = @('-File', $Path, '-Json')",
            "  foreach ($Arg in @($ExtraArgs)) { if ($Arg) { $Args += $Arg } }",
            "  $Text = & powershell -NoProfile -ExecutionPolicy Bypass @Args",
            "  $Exit = if ($LASTEXITCODE -eq $null) { 0 } else { [int]$LASTEXITCODE }",
            "  try { $Payload = $Text | ConvertFrom-Json; $ParseError = '' }",
            "  catch { $Payload = $null; $ParseError = $_.Exception.Message }",
            "  return [pscustomobject]@{ payload = $Payload; exit_code = $Exit; parse_error = $ParseError; missing = '' }",
            "}",
            "if (-not (Test-Path -LiteralPath $SummaryJson)) { Write-Error ('Missing product readiness summary JSON: ' + $SummaryJson); exit 3 }",
            "try { $Summary = Get-Content -Raw -LiteralPath $SummaryJson | ConvertFrom-Json }",
            "catch { Write-Error ('Unable to parse product readiness summary JSON: ' + $_.Exception.Message); exit 3 }",
            "$Operator = Invoke-JsonCheck -Path $OperatorCheck -ExtraArgs @()",
            "$StatusArgs = @()",
            "if ($InitFromProcessEnv) { $StatusArgs += '-InitFromProcessEnv' }",
            "$EnvStatus = Invoke-JsonCheck -Path $EnvBundleRunnerStatusCheck -ExtraArgs $StatusArgs",
            "$Remaining = Invoke-JsonCheck -Path $RemainingWorkCheck -ExtraArgs @()",
            "$ReadyNowFanout = Invoke-JsonCheck -Path $ReadyNowFanoutCheck -ExtraArgs @()",
            "$ManualClaimResolution = Invoke-JsonCheck -Path $ManualClaimResolutionCheck -ExtraArgs @()",
            "$ManualClaimResolutionRunnerResult = Invoke-JsonCheck -Path $ManualClaimResolutionRunner -ExtraArgs @()",
            "$ReleaseGate = $Summary.product_release_gate",
            "$ReleaseGatePassed = [bool]($ReleaseGate -and [bool]$ReleaseGate.passed)",
            "$ReleaseGateFailedCount = if ($ReleaseGate) { [int]$ReleaseGate.failed_count } else { -1 }",
            "$EnvPayload = $EnvStatus.payload",
            "$RemainingPayload = $Remaining.payload",
            "$ReadyNowFanoutPayload = $ReadyNowFanout.payload",
            "$ManualClaimResolutionPayload = $ManualClaimResolution.payload",
            "$ManualClaimResolutionRunnerPayload = $ManualClaimResolutionRunnerResult.payload",
            "$OperatorPayload = $Operator.payload",
            "$EnvContractValid = [bool]($EnvPayload -ne $null -and [bool]$EnvPayload.runner_contract_valid)",
            "$EnvComplete = [bool]($EnvPayload -ne $null -and [bool]$EnvPayload.runner_complete)",
            "$EnvCanLaunch = [bool]($EnvPayload -ne $null -and [bool]$EnvPayload.runner_can_launch)",
            "$RemainingOpenCount = if ($RemainingPayload -ne $null) { [int]$RemainingPayload.open_count } else { -1 }",
            "$ReadyNowFanoutCount = if ($ReadyNowFanoutPayload -ne $null) { [int]$ReadyNowFanoutPayload.ready_now_count } else { -1 }",
            "$ReadyNowFanoutLaneIds = if ($ReadyNowFanoutPayload -ne $null) { @($ReadyNowFanoutPayload.lane_item_ids) } else { @() }",
            "$ManualClaimResolutionComplete = [bool]($ManualClaimResolutionPayload -ne $null -and [bool]$ManualClaimResolutionPayload.can_claim_manual_resolution)",
            "$ManualClaimResolutionUnresolvedCount = if ($ManualClaimResolutionPayload -ne $null) { [int]$ManualClaimResolutionPayload.unresolved_manual_claim_count } else { -1 }",
            "$ManualClaimResolutionRunnerAllowed = [bool]($ManualClaimResolutionRunnerPayload -ne $null -and [bool]$ManualClaimResolutionRunnerPayload.execute_allowed)",
            "$NextActionId = 'inspect-current-state'",
            "if (-not $EnvContractValid) { $NextActionId = 'repair-env-bundle-runner-contract' }",
            "elseif (-not $EnvComplete) { $NextActionId = 'fill-env-bundle' }",
            "elseif ($EnvCanLaunch -and -not $ReleaseGatePassed) { $NextActionId = 'launch-ready-after-env-claims' }",
            "elseif ($RemainingOpenCount -gt 0) { $NextActionId = [string]$RemainingPayload.next_open_item_id }",
            "elseif ($ReleaseGatePassed) { $NextActionId = 'complete' }",
            "$ParseErrors = @()",
            "foreach ($Pair in @(@('operator_check', $Operator), @('env_bundle_runner_status_check', $EnvStatus), @('remaining_work_check', $Remaining), @('ready_now_fanout_check', $ReadyNowFanout), @('manual_claim_resolution_check', $ManualClaimResolution), @('manual_claim_resolution_runner', $ManualClaimResolutionRunnerResult))) {",
            "  $Name = [string]$Pair[0]",
            "  $Result = $Pair[1]",
            "  if ([string]$Result.missing) { $ParseErrors += ($Name + ': missing ' + [string]$Result.missing) }",
            "  if ([string]$Result.parse_error) { $ParseErrors += ($Name + ': ' + [string]$Result.parse_error) }",
            "}",
            "$DoctorContractValid = ($ParseErrors.Count -eq 0 -and $OperatorPayload -ne $null -and $EnvPayload -ne $null -and $RemainingPayload -ne $null -and $ReadyNowFanoutPayload -ne $null -and $ManualClaimResolutionPayload -ne $null -and $ManualClaimResolutionRunnerPayload -ne $null)",
            "$Payload = [ordered]@{",
            "  schema_version = 1",
            "  artifact = 'validation-product-readiness-doctor'",
            "  product_ready = [bool]$Summary.product_ready",
            "  external_claim_allowed = [bool]$Summary.external_claim_allowed",
            "  release_gate_passed = $ReleaseGatePassed",
            "  release_gate_failed_count = $ReleaseGateFailedCount",
            "  env_bundle_contract_valid = $EnvContractValid",
            "  env_bundle_complete = $EnvComplete",
            "  env_bundle_can_launch = $EnvCanLaunch",
            "  env_bundle_status_reason = if ($EnvPayload -ne $null) { [string]$EnvPayload.runner_status_reason } else { '' }",
            "  remaining_work_open_count = $RemainingOpenCount",
            "  ready_now_fanout_count = $ReadyNowFanoutCount",
            "  ready_now_fanout_lane_item_ids = @($ReadyNowFanoutLaneIds)",
            "  manual_claim_resolution_complete = $ManualClaimResolutionComplete",
            "  manual_claim_resolution_unresolved_count = $ManualClaimResolutionUnresolvedCount",
            "  manual_claim_resolution_runner_execute_allowed = $ManualClaimResolutionRunnerAllowed",
            "  operator_check_exit_code = [int]$Operator.exit_code",
            "  env_bundle_status_check_exit_code = [int]$EnvStatus.exit_code",
            "  remaining_work_check_exit_code = [int]$Remaining.exit_code",
            "  ready_now_fanout_check_exit_code = [int]$ReadyNowFanout.exit_code",
            "  manual_claim_resolution_check_exit_code = [int]$ManualClaimResolution.exit_code",
            "  manual_claim_resolution_runner_exit_code = [int]$ManualClaimResolutionRunnerResult.exit_code",
            "  doctor_contract_valid = [bool]$DoctorContractValid",
            "  can_launch_post_env = [bool]($EnvContractValid -and $EnvCanLaunch)",
            "  recommended_next_action_id = $NextActionId",
            "  parse_errors = $ParseErrors",
            "  operator_check = $OperatorPayload",
            "  env_bundle_status_check = $EnvPayload",
            "  remaining_work_check = $RemainingPayload",
            "  ready_now_fanout_check = $ReadyNowFanoutPayload",
            "  manual_claim_resolution_check = $ManualClaimResolutionPayload",
            "  manual_claim_resolution_runner = $ManualClaimResolutionRunnerPayload",
            "  claim_boundary = 'doctor aggregates no-execution readiness checks only; it does not import secret values or launch claims'",
            "}",
            "if ($Json) {",
            "  $Payload | ConvertTo-Json -Depth 24",
            "} else {",
            "  Write-Host ('Product ready: ' + [string]$Payload.product_ready)",
            "  Write-Host ('Release gate passed: ' + [string]$Payload.release_gate_passed)",
            "  Write-Host ('Env bundle complete: ' + [string]$Payload.env_bundle_complete)",
            "  Write-Host ('Ready-now fanout lanes: ' + [string]$Payload.ready_now_fanout_count)",
            "  Write-Host ('Manual claims resolved: ' + [string]$Payload.manual_claim_resolution_complete)",
            "  Write-Host ('Manual runner execute allowed: ' + [string]$Payload.manual_claim_resolution_runner_execute_allowed)",
            "  Write-Host ('Can launch post-env: ' + [string]$Payload.can_launch_post_env)",
            "  Write-Host ('Recommended next action: ' + [string]$Payload.recommended_next_action_id)",
            "}",
            "if (-not $DoctorContractValid) { exit 3 }",
            "if ($ReleaseGatePassed -and [bool]$Summary.product_ready) { exit 0 }",
            "exit 2",
            "",
        ]
    )


def product_readiness_doctor_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-doctor.schema.json",
        "title": "Tamandua validation product readiness doctor",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "product_ready",
            "external_claim_allowed",
            "release_gate_passed",
            "release_gate_failed_count",
            "env_bundle_contract_valid",
            "env_bundle_complete",
            "env_bundle_can_launch",
            "env_bundle_status_reason",
            "remaining_work_open_count",
            "ready_now_fanout_count",
            "ready_now_fanout_lane_item_ids",
            "manual_claim_resolution_complete",
            "manual_claim_resolution_unresolved_count",
            "manual_claim_resolution_runner_execute_allowed",
            "operator_check_exit_code",
            "env_bundle_status_check_exit_code",
            "remaining_work_check_exit_code",
            "ready_now_fanout_check_exit_code",
            "manual_claim_resolution_check_exit_code",
            "manual_claim_resolution_runner_exit_code",
            "doctor_contract_valid",
            "can_launch_post_env",
            "recommended_next_action_id",
            "parse_errors",
            "operator_check",
            "env_bundle_status_check",
            "remaining_work_check",
            "ready_now_fanout_check",
            "manual_claim_resolution_check",
            "manual_claim_resolution_runner",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-doctor"},
            "product_ready": {"type": "boolean"},
            "external_claim_allowed": {"type": "boolean"},
            "release_gate_passed": {"type": "boolean"},
            "release_gate_failed_count": {"type": "integer"},
            "env_bundle_contract_valid": {"type": "boolean"},
            "env_bundle_complete": {"type": "boolean"},
            "env_bundle_can_launch": {"type": "boolean"},
            "env_bundle_status_reason": {"type": "string"},
            "remaining_work_open_count": {"type": "integer"},
            "ready_now_fanout_count": {"type": "integer"},
            "ready_now_fanout_lane_item_ids": {"type": "array", "items": {"type": "string"}},
            "manual_claim_resolution_complete": {"type": "boolean"},
            "manual_claim_resolution_unresolved_count": {"type": "integer"},
            "manual_claim_resolution_runner_execute_allowed": {"type": "boolean"},
            "operator_check_exit_code": {"type": "integer"},
            "env_bundle_status_check_exit_code": {"type": "integer"},
            "remaining_work_check_exit_code": {"type": "integer"},
            "ready_now_fanout_check_exit_code": {"type": "integer"},
            "manual_claim_resolution_check_exit_code": {"type": "integer"},
            "manual_claim_resolution_runner_exit_code": {"type": "integer"},
            "doctor_contract_valid": {"type": "boolean"},
            "can_launch_post_env": {"type": "boolean"},
            "recommended_next_action_id": {"type": "string"},
            "parse_errors": {"type": "array", "items": {"type": "string"}},
            "operator_check": {"type": ["object", "null"]},
            "env_bundle_status_check": {"type": ["object", "null"]},
            "remaining_work_check": {"type": ["object", "null"]},
            "ready_now_fanout_check": {"type": ["object", "null"]},
            "manual_claim_resolution_check": {"type": ["object", "null"]},
            "manual_claim_resolution_runner": {"type": ["object", "null"]},
            "claim_boundary": {"type": "string"},
        },
    }


def post_env_runner_contract_payload(summary: dict[str, Any]) -> dict[str, Any]:
    env_queue = summary.get("env_queue") if isinstance(summary.get("env_queue"), dict) else {}
    plan = summary.get("post_env_bundle_plan") if isinstance(summary.get("post_env_bundle_plan"), dict) else {}
    recommended_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    post_agent_gate = (
        summary.get("post_agent_status_gate")
        if isinstance(summary.get("post_agent_status_gate"), dict)
        else {}
    )
    return {
        "schema_version": 1,
        "artifact": "validation-product-readiness-post-env-runner-contract",
        "generated_at": summary.get("generated_at"),
        "product_ready": bool(summary.get("product_ready")),
        "runner_path": "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.ps1",
        "runner_schema_path": "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.schema.json",
        "env_bundle_runner_path": "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1",
        "env_bundle_runner_schema_path": (
            "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.schema.json"
        ),
        "env_bundle_runner_status_check_path": (
            "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner_status_check.ps1"
        ),
        "env_bundle_runner_status_check_schema_path": (
            "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner_status_check.schema.json"
        ),
        "env_bundle_check_path": "docs/benchmarks/generated/validation_product_readiness_env_bundle_check.ps1",
        "env_bundle_template_path": "docs/benchmarks/generated/validation_product_readiness_env_bundle.template.json",
        "env_bundle_dotenv_template_path": (
            "docs/benchmarks/generated/validation_product_readiness_env_bundle.template.env"
        ),
        "env_bundle_local_path": "docs/benchmarks/generated/validation_product_readiness_env_bundle.local.json",
        "operator_check_path": "docs/benchmarks/generated/validation_product_readiness_operator_check.ps1",
        "summary_path": "docs/benchmarks/generated/validation_product_readiness_summary.json",
        "env_request_path": "docs/benchmarks/generated/validation_product_readiness_env_request.md",
        "required_env_count": int(env_queue.get("current_env_missing_count") or 0),
        "required_env_names": list(env_queue.get("current_env_missing_names") or []),
        "ready_claim_count": int(plan.get("ready_claim_count") or 0),
        "ready_claim_ids": list(plan.get("ready_claim_ids") or []),
        "still_blocked_claim_count": int(plan.get("still_blocked_claim_count") or 0),
        "still_blocked_claim_ids": list(plan.get("still_blocked_claim_ids") or []),
        "recommended_next_action_id": str(summary.get("recommended_next_action_id") or ""),
        "recommended_next_action": {
            "id": str(recommended_action.get("id") or ""),
            "step": int(recommended_action.get("step") or 0),
            "title": str(recommended_action.get("title") or ""),
            "claim_boundary": str(recommended_action.get("claim_boundary") or ""),
            "actions": list(recommended_action.get("actions") or []),
            "commands": list(recommended_action.get("commands") or []),
            "claim_ids": list(recommended_action.get("claim_ids") or []),
            "env": list(recommended_action.get("env") or []),
        },
        "modes": [
            {
                "id": "dry-run",
                "description": "validate the local env bundle and print launch commands without executing package claims",
                "command": (
                    "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1"
                ),
                "executes_claims": False,
            },
            {
                "id": "process-env-dry-run",
                "description": "initialize the local env bundle from current process env, then validate and print launch commands",
                "command": (
                    "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 "
                    "-InitFromProcessEnv"
                ),
                "executes_claims": False,
            },
            {
                "id": "json-status",
                "description": "return structured env-bundle readiness without importing secrets or launching claims",
                "command": (
                    "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 -Json"
                ),
                "executes_claims": False,
            },
            {
                "id": "process-env-json-status",
                "description": "initialize from current process env, then return structured readiness without launching claims",
                "command": (
                    "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 "
                    "-InitFromProcessEnv -Json"
                ),
                "executes_claims": False,
            },
            {
                "id": "package-launcher",
                "description": "import the local env bundle and execute generated env-bundle-ready package claims",
                "command": (
                    "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 "
                    "-Execute -RefreshClaimStatus"
                ),
                "executes_claims": True,
            },
            {
                "id": "balanced-agent-fanout",
                "description": "import the local env bundle and fan out ready claims across Codex/Claude via claim locks",
                "command": (
                    "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 "
                    "-UseBalancedAgents -Execute -RefreshClaimStatus"
                ),
                "executes_claims": True,
            },
            {
                "id": "process-env-balanced-agent-fanout",
                "description": "initialize the local env bundle from current process env, then fan out ready claims across Codex/Claude",
                "command": (
                    "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 "
                    "-InitFromProcessEnv -UseBalancedAgents -Execute -RefreshClaimStatus"
                ),
                "executes_claims": True,
            },
            {
                "id": "process-env-balanced-agent-fanout-refresh-authority",
                "description": "initialize from current process env, fan out ready claims, refresh claim status, then refresh validation authority",
                "command": (
                    "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 "
                    "-InitFromProcessEnv -UseBalancedAgents -Execute -RefreshClaimStatus -RefreshAuthority"
                ),
                "executes_claims": True,
            },
        ],
        "validation_command": (
            "powershell -NoProfile -ExecutionPolicy Bypass -File "
            "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 -Json"
        ),
        "package_validation_command": str(plan.get("validate_command") or ""),
        "package_launcher_commands": list(plan.get("package_launcher_commands") or []),
        "balanced_agent_spawn_commands": list(plan.get("balanced_agent_spawn_commands") or []),
        "refresh_claim_status_command": str(post_agent_gate.get("refresh_command") or ""),
        "guards": [
            "operator_check_full_env_bundle_ready",
            "env_bundle_validate_only_passes_before_launch",
            "execute_switch_required_for_claim_launch",
            "tamandua_allow_env_bundle_claims_launch_set_before_execution",
            "tamandua_allow_agent_spawn_launch_set_for_balanced_agents",
        ],
        "claim_boundary": (
            "post-env runner contract only; execution requires real operator-provided env values and explicit -Execute"
        ),
    }


def render_post_env_runner_contract_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Product Readiness Post-Env Runner Contract",
        "",
        f"- Product ready: `{str(bool(payload.get('product_ready'))).lower()}`",
        f"- Required env: `{payload.get('required_env_count') or 0}`",
        f"- Ready claims: `{payload.get('ready_claim_count') or 0}`",
        f"- Still blocked claims: `{payload.get('still_blocked_claim_count') or 0}`",
        f"- Recommended next action: `{payload.get('recommended_next_action_id') or '-'}`",
        f"- Runner: `{payload.get('runner_path')}`",
        f"- Local bundle runner: `{payload.get('env_bundle_runner_path')}`",
        f"- Local bundle runner schema: `{payload.get('env_bundle_runner_schema_path')}`",
        f"- Local bundle runner status check: `{payload.get('env_bundle_runner_status_check_path')}`",
        f"- Local bundle check: `{payload.get('env_bundle_check_path')}`",
        f"- Dotenv template: `{payload.get('env_bundle_dotenv_template_path')}`",
        f"- Operator check: `{payload.get('operator_check_path')}`",
        f"- Env request: `{payload.get('env_request_path')}`",
        "",
        "## Modes",
        "",
        "| Mode | Executes claims | Command |",
        "|------|-----------------|---------|",
    ]
    for mode in payload.get("modes") or []:
        lines.append(
            f"| `{mode.get('id')}` | `{str(bool(mode.get('executes_claims'))).lower()}` | "
            f"`{mode.get('command')}` |"
        )
    lines.extend(["", "## Ready Claims", ""])
    ready_claims = payload.get("ready_claim_ids") if isinstance(payload.get("ready_claim_ids"), list) else []
    if ready_claims:
        for claim_id in ready_claims:
            lines.append(f"- `{claim_id}`")
    else:
        lines.append("- none")
    lines.extend(["", "## Guards", ""])
    for guard in payload.get("guards") or []:
        lines.append(f"- `{guard}`")
    lines.extend(
        [
            "",
            "## Commands",
            "",
            "Validation:",
            "",
            "```powershell",
            str(payload.get("validation_command") or ""),
            "```",
            "",
            "Balanced agent fanout:",
            "",
            "```powershell",
        ]
    )
    lines.extend(str(command) for command in payload.get("balanced_agent_spawn_commands") or [])
    lines.extend(
        [
            "```",
            "",
            "Claim status refresh:",
            "",
            "```powershell",
            str(payload.get("refresh_claim_status_command") or ""),
            "```",
            "",
            "## Claim Boundary",
            "",
            str(payload.get("claim_boundary") or ""),
        ]
    )
    return "\n".join(lines) + "\n"


def post_env_runner_contract_schema() -> dict[str, Any]:
    mode_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "description", "command", "executes_claims"],
        "properties": {
            "id": {
                "enum": [
                    "dry-run",
                    "process-env-dry-run",
                    "json-status",
                    "process-env-json-status",
                    "package-launcher",
                    "balanced-agent-fanout",
                    "process-env-balanced-agent-fanout",
                    "process-env-balanced-agent-fanout-refresh-authority",
                ]
            },
            "description": {"type": "string"},
            "command": {"type": "string"},
            "executes_claims": {"type": "boolean"},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-post-env-runner-contract.schema.json",
        "title": "Tamandua validation product readiness post-env runner contract",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "generated_at",
            "product_ready",
            "runner_path",
            "runner_schema_path",
            "env_bundle_runner_path",
            "env_bundle_runner_schema_path",
            "env_bundle_runner_status_check_path",
            "env_bundle_runner_status_check_schema_path",
            "env_bundle_check_path",
            "env_bundle_template_path",
            "env_bundle_dotenv_template_path",
            "env_bundle_local_path",
            "operator_check_path",
            "summary_path",
            "env_request_path",
            "required_env_count",
            "required_env_names",
            "ready_claim_count",
            "ready_claim_ids",
            "still_blocked_claim_count",
            "still_blocked_claim_ids",
            "recommended_next_action_id",
            "recommended_next_action",
            "modes",
            "validation_command",
            "package_validation_command",
            "package_launcher_commands",
            "balanced_agent_spawn_commands",
            "refresh_claim_status_command",
            "guards",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-post-env-runner-contract"},
            "generated_at": {"type": ["string", "null"]},
            "product_ready": {"type": "boolean"},
            "runner_path": {"type": "string"},
            "runner_schema_path": {"type": "string"},
            "env_bundle_runner_path": {"type": "string"},
            "env_bundle_runner_schema_path": {"type": "string"},
            "env_bundle_runner_status_check_path": {"type": "string"},
            "env_bundle_runner_status_check_schema_path": {"type": "string"},
            "env_bundle_check_path": {"type": "string"},
            "env_bundle_template_path": {"type": "string"},
            "env_bundle_dotenv_template_path": {"type": "string"},
            "env_bundle_local_path": {"type": "string"},
            "operator_check_path": {"type": "string"},
            "summary_path": {"type": "string"},
            "env_request_path": {"type": "string"},
            "required_env_count": {"type": "integer", "minimum": 0},
            "required_env_names": {"type": "array", "items": {"type": "string"}},
            "ready_claim_count": {"type": "integer", "minimum": 0},
            "ready_claim_ids": {"type": "array", "items": {"type": "string"}},
            "still_blocked_claim_count": {"type": "integer", "minimum": 0},
            "still_blocked_claim_ids": {"type": "array", "items": {"type": "string"}},
            "recommended_next_action_id": {"type": "string"},
            "recommended_next_action": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "step", "title", "claim_boundary", "actions", "commands", "claim_ids", "env"],
                "properties": {
                    "id": {"type": "string"},
                    "step": {"type": "integer"},
                    "title": {"type": "string"},
                    "claim_boundary": {"type": "string"},
                    "actions": {"type": "array", "items": {"type": "string"}},
                    "commands": {"type": "array", "items": {"type": "string"}},
                    "claim_ids": {"type": "array", "items": {"type": "string"}},
                    "env": {"type": "array", "items": {"type": "string"}},
                },
            },
            "modes": {"type": "array", "items": mode_schema},
            "validation_command": {"type": "string"},
            "package_validation_command": {"type": "string"},
            "package_launcher_commands": {"type": "array", "items": {"type": "string"}},
            "balanced_agent_spawn_commands": {"type": "array", "items": {"type": "string"}},
            "refresh_claim_status_command": {"type": "string"},
            "guards": {"type": "array", "items": {"type": "string"}},
            "claim_boundary": {"type": "string"},
        },
    }


def claim_status_contract_payload(summary: dict[str, Any]) -> dict[str, Any]:
    post_agent_gate = (
        summary.get("post_agent_status_gate")
        if isinstance(summary.get("post_agent_status_gate"), dict)
        else {}
    )
    required_contract = (
        post_agent_gate.get("required_agent_status_contract")
        if isinstance(post_agent_gate.get("required_agent_status_contract"), dict)
        else {}
    )
    recommended_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    incomplete_claims = (
        post_agent_gate.get("incomplete_ready_after_env_claims")
        if isinstance(post_agent_gate.get("incomplete_ready_after_env_claims"), list)
        else []
    )
    incomplete_by_id = {
        str(claim.get("claim_id") or ""): claim
        for claim in incomplete_claims
        if isinstance(claim, dict) and claim.get("claim_id")
    }
    expected_status = str(required_contract.get("status") or "pass")
    expected_blocker_cleared = bool(required_contract.get("blocker_cleared", True))
    expected_missing_profiles = list(required_contract.get("missing_profiles") or [])
    claims = []
    for claim_id in post_agent_gate.get("ready_after_env_claim_ids") or []:
        claim_id_text = str(claim_id)
        current = incomplete_by_id.get(claim_id_text, {})
        claims.append(
            {
                "claim_id": claim_id_text,
                "expected_status": expected_status,
                "required_blocker_cleared": expected_blocker_cleared,
                "required_missing_profiles": expected_missing_profiles,
                "status_path": str(current.get("status_path") or ""),
                "current_agent_status": str(current.get("agent_status") or "pass"),
                "current_blocker_cleared": bool(current.get("agent_blocker_cleared", True)),
                "current_missing_profiles": list(current.get("missing_profiles") or []),
            }
        )
    return {
        "schema_version": 1,
        "artifact": "validation-product-readiness-claim-status-contract",
        "generated_at": summary.get("generated_at"),
        "product_ready": bool(summary.get("product_ready")),
        "ready_after_env_required_count": int(post_agent_gate.get("ready_after_env_required_count") or 0),
        "ready_after_env_passed_count": int(post_agent_gate.get("ready_after_env_passed_count") or 0),
        "ready_after_env_all_passed": bool(post_agent_gate.get("ready_after_env_all_passed")),
        "required_agent_status_contract": dict(required_contract),
        "claims": claims,
        "recommended_next_action_id": str(summary.get("recommended_next_action_id") or ""),
        "recommended_next_action": {
            "id": str(recommended_action.get("id") or ""),
            "step": int(recommended_action.get("step") or 0),
            "title": str(recommended_action.get("title") or ""),
            "claim_boundary": str(recommended_action.get("claim_boundary") or ""),
            "commands": list(recommended_action.get("commands") or []),
            "claim_ids": list(recommended_action.get("claim_ids") or []),
            "env": list(recommended_action.get("env") or []),
        },
        "refresh_command": str(post_agent_gate.get("refresh_command") or ""),
        "claim_boundary": (
            "agent_status.json contract only; product readiness requires refresh plus every ready-after-env "
            "claim status=pass, blocker_cleared=true, and missing_profiles=[]"
        ),
    }


def render_claim_status_contract_markdown(payload: dict[str, Any]) -> str:
    required = (
        payload.get("required_agent_status_contract")
        if isinstance(payload.get("required_agent_status_contract"), dict)
        else {}
    )
    claims = payload.get("claims") if isinstance(payload.get("claims"), list) else []
    lines = [
        "# Product Readiness Claim Status Contract",
        "",
        f"- Product ready: `{str(bool(payload.get('product_ready'))).lower()}`",
        (
            "- Ready-after-env passed: "
            f"`{payload.get('ready_after_env_passed_count') or 0}/"
            f"{payload.get('ready_after_env_required_count') or 0}`"
        ),
        f"- Ready-after-env all passed: `{str(bool(payload.get('ready_after_env_all_passed'))).lower()}`",
        f"- Recommended next action: `{payload.get('recommended_next_action_id') or '-'}`",
        "",
        "## Required Agent Status",
        "",
        f"- `status`: `{required.get('status') or 'pass'}`",
        f"- `blocker_cleared`: `{str(bool(required.get('blocker_cleared', True))).lower()}`",
        f"- `missing_profiles`: `{json.dumps(required.get('missing_profiles') or [])}`",
        "",
        "Required fields:",
        "",
    ]
    for field in required.get("required_fields") or []:
        lines.append(f"- `{field}`")
    lines.extend(["", "## Claims", "", "| Claim | Status path | Current status | Blocker cleared | Missing profiles |"])
    lines.append("|-------|-------------|----------------|-----------------|------------------|")
    if claims:
        for claim in claims:
            lines.append(
                f"| `{claim.get('claim_id')}` | `{claim.get('status_path') or 'agent_status.json'}` | "
                f"`{claim.get('current_agent_status')}` | "
                f"`{str(bool(claim.get('current_blocker_cleared'))).lower()}` | "
                f"`{json.dumps(claim.get('current_missing_profiles') or [])}` |"
            )
    else:
        lines.append("| none | - | - | - | - |")
    lines.extend(
        [
            "",
            "## Refresh",
            "",
            "```powershell",
            str(payload.get("refresh_command") or ""),
            "```",
            "",
            "## Claim Boundary",
            "",
            str(payload.get("claim_boundary") or ""),
        ]
    )
    return "\n".join(lines) + "\n"


def claim_status_contract_schema() -> dict[str, Any]:
    recommended_action_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "step", "title", "claim_boundary", "commands", "claim_ids", "env"],
        "properties": {
            "id": {"type": "string"},
            "step": {"type": "integer", "minimum": 0},
            "title": {"type": "string"},
            "claim_boundary": {"type": "string"},
            "commands": {"type": "array", "items": {"type": "string"}},
            "claim_ids": {"type": "array", "items": {"type": "string"}},
            "env": {"type": "array", "items": {"type": "string"}},
        },
    }
    claim_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "claim_id",
            "expected_status",
            "required_blocker_cleared",
            "required_missing_profiles",
            "status_path",
            "current_agent_status",
            "current_blocker_cleared",
            "current_missing_profiles",
        ],
        "properties": {
            "claim_id": {"type": "string"},
            "expected_status": {"type": "string"},
            "required_blocker_cleared": {"type": "boolean"},
            "required_missing_profiles": {"type": "array", "items": {"type": "string"}},
            "status_path": {"type": "string"},
            "current_agent_status": {"type": "string"},
            "current_blocker_cleared": {"type": "boolean"},
            "current_missing_profiles": {"type": "array", "items": {"type": "string"}},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-claim-status-contract.schema.json",
        "title": "Tamandua validation product readiness claim status contract",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "generated_at",
            "product_ready",
            "ready_after_env_required_count",
            "ready_after_env_passed_count",
            "ready_after_env_all_passed",
            "required_agent_status_contract",
            "claims",
            "recommended_next_action_id",
            "recommended_next_action",
            "refresh_command",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-claim-status-contract"},
            "generated_at": {"type": ["string", "null"]},
            "product_ready": {"type": "boolean"},
            "ready_after_env_required_count": {"type": "integer", "minimum": 0},
            "ready_after_env_passed_count": {"type": "integer", "minimum": 0},
            "ready_after_env_all_passed": {"type": "boolean"},
            "required_agent_status_contract": {"type": "object"},
            "claims": {"type": "array", "items": claim_schema},
            "recommended_next_action_id": {"type": "string"},
            "recommended_next_action": recommended_action_schema,
            "refresh_command": {"type": "string"},
            "claim_boundary": {"type": "string"},
        },
    }


def blocked_run_class_action_fields(
    item: dict[str, Any],
    recommended_action: dict[str, Any],
) -> dict[str, Any]:
    missing_env = [str(value) for value in item.get("missing_env") or []]
    recommended_commands = [str(value) for value in recommended_action.get("commands") or [] if value]
    recommended_claim_ids = [str(value) for value in recommended_action.get("claim_ids") or [] if value]
    recommended_actions = [str(value) for value in recommended_action.get("actions") or [] if value]
    item_action = str(item.get("action") or "").strip()
    action = item_action
    if not action and not missing_env and recommended_actions:
        action = " ".join(recommended_actions)
    if not action:
        action = (
            "provide required env bundle, run post-env claims, then rerun preflight"
            if missing_env
            else "rerun or repair listed blocking profiles with fresh evidence"
        )
    return {
        "action": action,
        "next_action": action,
        "claim_ids": recommended_claim_ids if not missing_env else [],
        "commands": recommended_commands if not missing_env else [],
    }


def release_gate_contract_payload(summary: dict[str, Any]) -> dict[str, Any]:
    release_gate = (
        summary.get("product_release_gate")
        if isinstance(summary.get("product_release_gate"), dict)
        else {}
    )
    env_queue = summary.get("env_queue") if isinstance(summary.get("env_queue"), dict) else {}
    post_agent_gate = (
        summary.get("post_agent_status_gate")
        if isinstance(summary.get("post_agent_status_gate"), dict)
        else {}
    )
    local_bundle_gate = (
        summary.get("local_env_bundle_gate")
        if isinstance(summary.get("local_env_bundle_gate"), dict)
        else {}
    )
    recommended_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    evidence_by_requirement = {
        "closure-gate": [
            "latest roadmap-closure-gate-probe quality_gate.passed=true",
            "coverage equals total roadmap gate requirements",
        ],
        "preflight-gate": [
            "latest validation-execution-preflight-probe quality_gate.passed=true",
            "run_class_readiness has no blocked product run classes",
        ],
        "dispatch-gate": [
            "latest validation-dispatch-results-probe quality_gate.passed=true",
            "dispatch manifest has no missing or invalid packages",
        ],
        "required-env": [
            "operator check reports current_env_missing_names=[]",
            "placeholder_env_names=[]",
        ],
        "blocked-env-claims": [
            "claim_status_report has zero blocked_missing_env claims",
            "env_unblock_queue current_env_missing_count=0",
        ],
        "manual-claims": [
            "claim_status_report has zero manual_claim_required claims",
            "external/runtime preconditions from current_next_action are resolved",
        ],
        "post-agent-status": [
            "ready-after-env claims have status=pass",
            "blocker_cleared=true",
            "missing_profiles=[]",
        ],
        "blocked-run-classes": [
            "preflight run_class_readiness allowed=true for every product run class",
            "blocked_run_classes=[]",
        ],
    }
    next_artifacts = {
        "env_request": "docs/benchmarks/generated/validation_product_readiness_env_request.md",
        "operator_check": "docs/benchmarks/generated/validation_product_readiness_operator_check.ps1",
        "post_env_runner_contract": (
            "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.contract.md"
        ),
        "post_env_runner": "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1",
        "claim_status_report": str(post_agent_gate.get("report") or ""),
        "scorecard": str(summary.get("scorecard_path") or ""),
    }
    requirements = []
    for requirement in release_gate.get("requirements") or []:
        if not isinstance(requirement, dict):
            continue
        requirement_id = str(requirement.get("id") or "")
        requirements.append(
            {
                "id": requirement_id,
                "passed": bool(requirement.get("passed")),
                "current": str(requirement.get("current") or ""),
                "required": str(requirement.get("required") or ""),
                "evidence_required": evidence_by_requirement.get(requirement_id, []),
            }
        )
    blocked_run_classes = []
    for item in summary.get("blocked_run_classes") or []:
        if not isinstance(item, dict):
            continue
        blocked_item = dict(item)
        blocked_item.update(blocked_run_class_action_fields(blocked_item, recommended_action))
        blocked_run_classes.append(blocked_item)
    return {
        "schema_version": 1,
        "artifact": "validation-product-readiness-release-gate-contract",
        "generated_at": summary.get("generated_at"),
        "product_ready": bool(summary.get("product_ready")),
        "external_claim_allowed": bool(summary.get("external_claim_allowed")),
        "passed": bool(release_gate.get("passed")),
        "failed_count": int(release_gate.get("failed_count") or 0),
        "failed_ids": list(release_gate.get("failed_ids") or []),
        "requirements": requirements,
        "required_env_count": int(env_queue.get("current_env_missing_count") or 0),
        "required_env_names": list(env_queue.get("current_env_missing_names") or []),
        "local_env_bundle_gate": local_bundle_gate,
        "manual_claim_ids": [
            str(claim.get("claim_id") or "")
            for claim in summary.get("manual_claims") or []
            if isinstance(claim, dict) and claim.get("claim_id")
        ],
        "ready_after_env_required_count": int(post_agent_gate.get("ready_after_env_required_count") or 0),
        "ready_after_env_passed_count": int(post_agent_gate.get("ready_after_env_passed_count") or 0),
        "blocked_run_class_count": len(blocked_run_classes),
        "blocked_run_classes": blocked_run_classes,
        "next_artifacts": next_artifacts,
        "recommended_next_action_id": str(summary.get("recommended_next_action_id") or ""),
        "recommended_next_action": {
            "id": str(recommended_action.get("id") or ""),
            "step": int(recommended_action.get("step") or 0),
            "title": str(recommended_action.get("title") or ""),
            "claim_boundary": str(recommended_action.get("claim_boundary") or ""),
            "commands": list(recommended_action.get("commands") or []),
            "claim_ids": list(recommended_action.get("claim_ids") or []),
            "env": list(recommended_action.get("env") or []),
        },
        "next_action_order": list(summary.get("next_action_order") or []),
        "claim_boundary": (
            "product readiness and external claims require every release-gate requirement to pass with fresh evidence"
        ),
    }


def render_release_gate_contract_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Product Readiness Release Gate Contract",
        "",
        f"- Product ready: `{str(bool(payload.get('product_ready'))).lower()}`",
        f"- External claim allowed: `{str(bool(payload.get('external_claim_allowed'))).lower()}`",
        f"- Release gate passed: `{str(bool(payload.get('passed'))).lower()}`",
        f"- Failed requirements: `{payload.get('failed_count') or 0}`",
        f"- Required env: `{payload.get('required_env_count') or 0}`",
        f"- Ready-after-env passed: `{payload.get('ready_after_env_passed_count') or 0}/"
        f"{payload.get('ready_after_env_required_count') or 0}`",
        f"- Blocked run classes: `{payload.get('blocked_run_class_count') or 0}`",
        f"- Recommended next action: `{payload.get('recommended_next_action_id') or '-'}`",
        "",
        "## Requirements",
        "",
        "| Requirement | Passed | Current | Required | Evidence required |",
        "|-------------|--------|---------|----------|-------------------|",
    ]
    for requirement in payload.get("requirements") or []:
        evidence = "<br>".join(f"`{value}`" for value in requirement.get("evidence_required") or []) or "-"
        lines.append(
            f"| `{requirement.get('id')}` | `{str(bool(requirement.get('passed'))).lower()}` | "
            f"`{requirement.get('current')}` | {str(requirement.get('required') or '-').replace('|', '/')} | "
            f"{evidence} |"
        )
    lines.extend(["", "## Required Env", ""])
    env_names = payload.get("required_env_names") if isinstance(payload.get("required_env_names"), list) else []
    if env_names:
        for env_name in env_names:
            lines.append(f"- `{env_name}`")
    else:
        lines.append("- none")
    local_bundle_gate = (
        payload.get("local_env_bundle_gate")
        if isinstance(payload.get("local_env_bundle_gate"), dict)
        else {}
    )
    lines.extend(
        [
            "",
            "## Local Env Bundle Gate",
            "",
            f"- Bundle path: `{local_bundle_gate.get('bundle_path') or '-'}`",
            f"- Exists: `{str(bool(local_bundle_gate.get('exists'))).lower()}`",
            f"- Complete: `{str(bool(local_bundle_gate.get('complete'))).lower()}`",
            f"- Present env: `{local_bundle_gate.get('present_env_count') or 0}/"
            f"{local_bundle_gate.get('required_env_count') or 0}`",
            f"- Missing env: `{len(local_bundle_gate.get('missing_env_names') or [])}`",
            f"- Placeholder env: `{len(local_bundle_gate.get('placeholder_env_names') or [])}`",
            f"- Empty env: `{len(local_bundle_gate.get('empty_env_names') or [])}`",
            f"- Unexpected env: `{len(local_bundle_gate.get('unexpected_env_names') or [])}`",
        ]
    )
    if local_bundle_gate.get("parse_error"):
        lines.append(f"- Parse error: `{local_bundle_gate.get('parse_error')}`")
    lines.extend(["", "## Manual Claims", ""])
    manual_claim_ids = (
        payload.get("manual_claim_ids") if isinstance(payload.get("manual_claim_ids"), list) else []
    )
    if manual_claim_ids:
        for claim_id in manual_claim_ids:
            lines.append(f"- `{claim_id}`")
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Next Artifacts",
            "",
            "| Artifact | Path |",
            "|----------|------|",
        ]
    )
    next_artifacts = payload.get("next_artifacts") if isinstance(payload.get("next_artifacts"), dict) else {}
    for key in sorted(next_artifacts):
        lines.append(f"| `{key}` | `{next_artifacts[key] or '-'}` |")
    lines.extend(["", "## Claim Boundary", "", str(payload.get("claim_boundary") or "")])
    return "\n".join(lines) + "\n"


def release_gate_contract_schema() -> dict[str, Any]:
    requirement_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "passed", "current", "required", "evidence_required"],
        "properties": {
            "id": {"type": "string"},
            "passed": {"type": "boolean"},
            "current": {"type": "string"},
            "required": {"type": "string"},
            "evidence_required": {"type": "array", "items": {"type": "string"}},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-release-gate-contract.schema.json",
        "title": "Tamandua validation product readiness release gate contract",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "generated_at",
            "product_ready",
            "external_claim_allowed",
            "passed",
            "failed_count",
            "failed_ids",
            "requirements",
            "required_env_count",
            "required_env_names",
            "local_env_bundle_gate",
            "manual_claim_ids",
            "ready_after_env_required_count",
            "ready_after_env_passed_count",
            "blocked_run_class_count",
            "blocked_run_classes",
            "next_artifacts",
            "recommended_next_action_id",
            "recommended_next_action",
            "next_action_order",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-release-gate-contract"},
            "generated_at": {"type": ["string", "null"]},
            "product_ready": {"type": "boolean"},
            "external_claim_allowed": {"type": "boolean"},
            "passed": {"type": "boolean"},
            "failed_count": {"type": "integer", "minimum": 0},
            "failed_ids": {"type": "array", "items": {"type": "string"}},
            "requirements": {"type": "array", "items": requirement_schema},
            "required_env_count": {"type": "integer", "minimum": 0},
            "required_env_names": {"type": "array", "items": {"type": "string"}},
            "local_env_bundle_gate": {"type": "object"},
            "manual_claim_ids": {"type": "array", "items": {"type": "string"}},
            "ready_after_env_required_count": {"type": "integer", "minimum": 0},
            "ready_after_env_passed_count": {"type": "integer", "minimum": 0},
            "blocked_run_class_count": {"type": "integer", "minimum": 0},
            "blocked_run_classes": {"type": "array", "items": {"type": "object"}},
            "next_artifacts": {"type": "object"},
            "recommended_next_action_id": {"type": "string"},
            "recommended_next_action": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "step", "title", "claim_boundary", "commands", "claim_ids", "env"],
                "properties": {
                    "id": {"type": "string"},
                    "step": {"type": "integer"},
                    "title": {"type": "string"},
                    "claim_boundary": {"type": "string"},
                    "commands": {"type": "array", "items": {"type": "string"}},
                    "claim_ids": {"type": "array", "items": {"type": "string"}},
                    "env": {"type": "array", "items": {"type": "string"}},
                },
            },
            "next_action_order": {"type": "array", "items": {"type": "object"}},
            "claim_boundary": {"type": "string"},
        },
    }


def blocked_run_classes_contract_payload(summary: dict[str, Any]) -> dict[str, Any]:
    blocked_run_classes = [
        item for item in summary.get("blocked_run_classes") or [] if isinstance(item, dict)
    ]
    recommended_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    classes = []
    for item in blocked_run_classes:
        missing_env = [str(value) for value in item.get("missing_env") or []]
        blocking_profiles = [str(value) for value in item.get("blocking_profiles") or []]
        action_fields = blocked_run_class_action_fields(item, recommended_action)
        classes.append(
            {
                "run_class": str(item.get("run_class") or ""),
                "allowed": bool(item.get("allowed")),
                "roadmaps": [str(value) for value in item.get("roadmaps") or []],
                "missing_env": missing_env,
                "blocking_profiles": blocking_profiles,
                "resolution_class": "env_required" if missing_env else "profile_or_lab_required",
                "evidence_required": [
                    "latest validation-execution-preflight-probe run_class_readiness entry allowed=true",
                    "blocking_profiles=[]",
                    "missing_env=[]",
                ],
                "next_action": str(action_fields.get("next_action") or ""),
                "action": str(action_fields.get("action") or ""),
                "claim_ids": list(action_fields.get("claim_ids") or []),
                "commands": list(action_fields.get("commands") or []),
            }
        )
    classes.sort(key=lambda item: str(item.get("run_class") or ""))
    env_blocked_count = sum(1 for item in classes if item.get("missing_env"))
    return {
        "schema_version": 1,
        "artifact": "validation-product-readiness-blocked-run-classes-contract",
        "generated_at": summary.get("generated_at"),
        "product_ready": bool(summary.get("product_ready")),
        "blocked_run_class_count": len(classes),
        "env_blocked_count": env_blocked_count,
        "profile_or_lab_blocked_count": len(classes) - env_blocked_count,
        "classes": classes,
        "recommended_next_action_id": str(summary.get("recommended_next_action_id") or ""),
        "recommended_next_action": {
            "id": str(recommended_action.get("id") or ""),
            "step": int(recommended_action.get("step") or 0),
            "title": str(recommended_action.get("title") or ""),
            "claim_boundary": str(recommended_action.get("claim_boundary") or ""),
            "commands": list(recommended_action.get("commands") or []),
            "claim_ids": list(recommended_action.get("claim_ids") or []),
            "env": list(recommended_action.get("env") or []),
        },
        "preflight_gate_required": "run_class_readiness allowed=true for every product run class",
        "claim_boundary": (
            "blocked run class contract only; product readiness requires blocked_run_classes=[] in fresh preflight"
        ),
    }


def render_blocked_run_classes_contract_markdown(payload: dict[str, Any]) -> str:
    classes = payload.get("classes") if isinstance(payload.get("classes"), list) else []
    lines = [
        "# Product Readiness Blocked Run Classes Contract",
        "",
        f"- Product ready: `{str(bool(payload.get('product_ready'))).lower()}`",
        f"- Blocked run classes: `{payload.get('blocked_run_class_count') or 0}`",
        f"- Env blocked: `{payload.get('env_blocked_count') or 0}`",
        f"- Profile/lab blocked: `{payload.get('profile_or_lab_blocked_count') or 0}`",
        f"- Recommended next action: `{payload.get('recommended_next_action_id') or '-'}`",
        "",
        "## Classes",
        "",
        "| Run class | Resolution class | Roadmaps | Missing env | Blocking profiles | Next action |",
        "|-----------|------------------|----------|-------------|-------------------|-------------|",
    ]
    if classes:
        for item in classes:
            lines.append(
                f"| `{item.get('run_class')}` | `{item.get('resolution_class')}` | "
                f"`{', '.join(item.get('roadmaps') or []) or '-'}` | "
                f"`{', '.join(item.get('missing_env') or []) or '-'}` | "
                f"`{', '.join(item.get('blocking_profiles') or []) or '-'}` | "
                f"{str(item.get('next_action') or '-').replace('|', '/')} |"
            )
    else:
        lines.append("| none | - | - | - | - | - |")
    lines.extend(["", "## Evidence Required", ""])
    lines.append(f"- `{payload.get('preflight_gate_required')}`")
    lines.append("- `blocked_run_classes=[]`")
    lines.extend(["", "## Action Plan", ""])
    if classes:
        for item in classes:
            lines.append(f"### `{item.get('run_class')}`")
            lines.append("")
            lines.append(f"- Action: {str(item.get('action') or item.get('next_action') or '-').replace('|', '/')}")
            claim_ids = ", ".join(item.get("claim_ids") or []) or "-"
            lines.append(f"- Claim ids: `{claim_ids}`")
            commands = [str(value) for value in item.get("commands") or [] if value]
            if commands:
                lines.append("- Commands:")
                for command in commands:
                    lines.append(f"  - `{command}`")
            else:
                lines.append("- Commands: -")
            lines.append("")
    else:
        lines.append("- none")
    lines.extend(["", "## Claim Boundary", "", str(payload.get("claim_boundary") or "")])
    return "\n".join(lines) + "\n"


def blocked_run_classes_contract_schema() -> dict[str, Any]:
    recommended_action_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "step", "title", "claim_boundary", "commands", "claim_ids", "env"],
        "properties": {
            "id": {"type": "string"},
            "step": {"type": "integer", "minimum": 0},
            "title": {"type": "string"},
            "claim_boundary": {"type": "string"},
            "commands": {"type": "array", "items": {"type": "string"}},
            "claim_ids": {"type": "array", "items": {"type": "string"}},
            "env": {"type": "array", "items": {"type": "string"}},
        },
    }
    class_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "run_class",
            "allowed",
            "roadmaps",
            "missing_env",
            "blocking_profiles",
            "resolution_class",
            "evidence_required",
            "next_action",
            "action",
            "claim_ids",
            "commands",
        ],
        "properties": {
            "run_class": {"type": "string"},
            "allowed": {"type": "boolean"},
            "roadmaps": {"type": "array", "items": {"type": "string"}},
            "missing_env": {"type": "array", "items": {"type": "string"}},
            "blocking_profiles": {"type": "array", "items": {"type": "string"}},
            "resolution_class": {"enum": ["env_required", "profile_or_lab_required"]},
            "evidence_required": {"type": "array", "items": {"type": "string"}},
            "next_action": {"type": "string"},
            "action": {"type": "string"},
            "claim_ids": {"type": "array", "items": {"type": "string"}},
            "commands": {"type": "array", "items": {"type": "string"}},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-blocked-run-classes-contract.schema.json",
        "title": "Tamandua validation product readiness blocked run classes contract",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "generated_at",
            "product_ready",
            "blocked_run_class_count",
            "env_blocked_count",
            "profile_or_lab_blocked_count",
            "classes",
            "recommended_next_action_id",
            "recommended_next_action",
            "preflight_gate_required",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-blocked-run-classes-contract"},
            "generated_at": {"type": ["string", "null"]},
            "product_ready": {"type": "boolean"},
            "blocked_run_class_count": {"type": "integer", "minimum": 0},
            "env_blocked_count": {"type": "integer", "minimum": 0},
            "profile_or_lab_blocked_count": {"type": "integer", "minimum": 0},
            "classes": {"type": "array", "items": class_schema},
            "recommended_next_action_id": {"type": "string"},
            "recommended_next_action": recommended_action_schema,
            "preflight_gate_required": {"type": "string"},
            "claim_boundary": {"type": "string"},
        },
    }


def product_readiness_runbook_payload(
    summary: dict[str, Any],
    env_request: dict[str, Any],
    post_env_runner_contract: dict[str, Any],
    claim_status_contract: dict[str, Any],
    blocked_run_classes_contract: dict[str, Any],
) -> dict[str, Any]:
    recommended_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    action_manual_prerequisites = manual_claim_prerequisites(summary)
    modes_by_id = {
        str(mode.get("id") or ""): mode
        for mode in post_env_runner_contract.get("modes") or []
        if isinstance(mode, dict)
    }
    required_env_count = int(env_request.get("required_env_count") or 0)
    ready_after_env_required_count = int(claim_status_contract.get("ready_after_env_required_count") or 0)
    recommended_action_id = str(summary.get("recommended_next_action_id") or "")
    steps = []

    def add_step(step: dict[str, Any]) -> None:
        step = dict(step)
        step["step"] = len(steps) + 1
        steps.append(step)

    add_step(
        {
            "id": "inspect-current-state",
            "actor": "operator-or-agent",
            "execution_class": "no-exec",
            "command": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_operator_check.ps1 -Json"
            ),
            "requires_real_env": False,
            "executes_claims": False,
            "success_evidence": (
                "operator check reports no missing env and identifies the currently launchable claim path"
                if required_env_count == 0
                else "operator check returns full_env_bundle_ready=true before launch"
            ),
        }
    )
    if required_env_count > 0:
        add_step(
            {
                "id": "fill-env-bundle",
                "actor": "operator",
                "execution_class": "secret-input",
                "command": (
                    "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_init.ps1"
                ),
                "requires_real_env": True,
                "executes_claims": False,
                "success_evidence": (
                    "ignored local .env is edited with real values, then env_bundle_init -EnvFile creates "
                    "a local JSON bundle with all required env names present and non-placeholder"
                ),
            }
        )
        add_step(
            {
                "id": "validate-env-bundle",
                "actor": "operator-or-agent",
                "execution_class": "validate-only",
                "command": str(post_env_runner_contract.get("validation_command") or ""),
                "requires_real_env": True,
                "executes_claims": False,
                "success_evidence": "env bundle runner JSON returns complete=true and can_launch=true without launching claims",
            }
        )
    if ready_after_env_required_count > 0:
        add_step(
            {
                "id": "launch-ready-after-env-claims",
                "actor": "operator-or-agent",
                "execution_class": "claim-execution",
                "command": str(modes_by_id.get("balanced-agent-fanout", {}).get("command") or ""),
                "requires_real_env": required_env_count > 0,
                "executes_claims": True,
                "success_evidence": "ready-after-env claim agents write agent_status.json files",
            }
        )
    if recommended_action_id == "launch-ready-claims":
        add_step(
            {
                "id": "launch-ready-claims",
                "actor": "operator-or-agent",
                "execution_class": "claim-execution",
                "command": "<br>".join(str(command) for command in recommended_action.get("commands") or []),
                "requires_real_env": False,
                "executes_claims": True,
                "success_evidence": "ready claim writes agent_status.json with status=pass, blocker_cleared=true, and missing_profiles=[]",
            }
        )
    if recommended_action_id == "resolve-manual-claims":
        add_step(
            {
                "id": "resolve-manual-claims",
                "actor": "operator-or-agent",
                "execution_class": "manual-boundary-resolution",
                "command": "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution.md",
                "requires_real_env": False,
                "executes_claims": False,
                "success_evidence": "manual claims are resolved by satisfying current_next_action preconditions and refreshing claim status",
            }
        )
    for step in [
        {
            "id": "refresh-claim-status",
            "actor": "operator-or-agent",
            "execution_class": "local-refresh",
            "command": str(post_env_runner_contract.get("refresh_claim_status_command") or ""),
            "requires_real_env": False,
            "executes_claims": False,
            "success_evidence": "claim_status_report.json reflects current agent_status.json files",
        },
        {
            "id": "verify-agent-status-contract",
            "actor": "operator-or-agent",
            "execution_class": "contract-check",
            "command": "docs/benchmarks/generated/validation_product_readiness_claim_status_contract.md",
            "requires_real_env": False,
            "executes_claims": False,
            "success_evidence": "ready-after-env passed count equals required count",
        },
        {
            "id": "resolve-profile-or-lab-blockers",
            "actor": "operator-or-agent",
            "execution_class": "profile-or-lab-evidence",
            "command": "docs/benchmarks/generated/validation_product_readiness_blocked_run_classes.contract.md",
            "requires_real_env": False,
            "executes_claims": False,
            "success_evidence": "blocked run classes contract reports profile_or_lab_blocked_count=0",
        },
        {
            "id": "refresh-validation-authority",
            "actor": "operator-or-agent",
            "execution_class": "local-refresh",
            "command": "python tools/detection_validation/refresh_validation_authority.py",
            "requires_real_env": False,
            "executes_claims": False,
            "success_evidence": "release gate contract failed_count=0",
        },
    ]:
        add_step(step)
    return {
        "schema_version": 1,
        "artifact": "validation-product-readiness-runbook",
        "generated_at": summary.get("generated_at"),
        "product_ready": bool(summary.get("product_ready")),
        "automation_state": product_readiness_automation_state(
            summary,
            env_request,
            blocked_run_classes_contract=blocked_run_classes_contract,
        ),
        "required_env_count": required_env_count,
        "ready_after_env_required_count": ready_after_env_required_count,
        "blocked_run_class_count": int(blocked_run_classes_contract.get("blocked_run_class_count") or 0),
        "recommended_next_action_id": str(summary.get("recommended_next_action_id") or ""),
        "recommended_next_action": {
            "id": str(recommended_action.get("id") or ""),
            "step": int(recommended_action.get("step") or 0),
            "title": str(recommended_action.get("title") or ""),
            "claim_boundary": str(recommended_action.get("claim_boundary") or ""),
            "commands": list(recommended_action.get("commands") or []),
            "claim_ids": list(recommended_action.get("claim_ids") or []),
            "manual_prerequisites": action_manual_prerequisites,
            "env": list(recommended_action.get("env") or []),
        },
        "steps": steps,
        "guards": list(post_env_runner_contract.get("guards") or []),
        "contracts": {
            "env_request": "docs/benchmarks/generated/validation_product_readiness_env_request.md",
            "post_env_runner": "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.contract.md",
            "claim_status": "docs/benchmarks/generated/validation_product_readiness_claim_status_contract.md",
            "blocked_run_classes": (
                "docs/benchmarks/generated/validation_product_readiness_blocked_run_classes.contract.md"
            ),
            "release_gate": "docs/benchmarks/generated/validation_product_readiness_release_gate.contract.md",
        },
        "claim_boundary": (
            "ordered runbook only; steps requiring real env or claim execution must not be treated as completed "
            "until their success evidence is present"
        ),
    }


def render_product_readiness_runbook_markdown(payload: dict[str, Any]) -> str:
    steps = payload.get("steps") if isinstance(payload.get("steps"), list) else []
    recommended_action = (
        payload.get("recommended_next_action")
        if isinstance(payload.get("recommended_next_action"), dict)
        else {}
    )
    lines = [
        "# Product Readiness Runbook",
        "",
        f"- Product ready: `{str(bool(payload.get('product_ready'))).lower()}`",
        f"- Automation state: `{payload.get('automation_state') or '-'}`",
        f"- Required env: `{payload.get('required_env_count') or 0}`",
        f"- Ready-after-env required: `{payload.get('ready_after_env_required_count') or 0}`",
        f"- Blocked run classes: `{payload.get('blocked_run_class_count') or 0}`",
        f"- Recommended next action: `{payload.get('recommended_next_action_id') or '-'}`",
        "",
        "## Recommended Next Action",
        "",
        f"- ID: `{recommended_action.get('id') or '-'}`",
        f"- Step: `{recommended_action.get('step') or 0}`",
        f"- Title: {recommended_action.get('title') or '-'}",
        f"- Claim boundary: {recommended_action.get('claim_boundary') or '-'}",
        "",
        "### Manual Prerequisites",
        "",
    ]
    for item in recommended_action.get("manual_prerequisites") or []:
        lines.append(f"- {item}")
    if not recommended_action.get("manual_prerequisites"):
        lines.append("- -")
    lines.extend(
        [
        "",
        "## Ordered Steps",
        "",
        "| Step | ID | Class | Requires env | Executes claims | Command | Success evidence |",
        "|------|----|-------|--------------|-----------------|---------|------------------|",
        ]
    )
    for step in steps:
        lines.append(
            f"| `{step.get('step')}` | `{step.get('id')}` | `{step.get('execution_class')}` | "
            f"`{str(bool(step.get('requires_real_env'))).lower()}` | "
            f"`{str(bool(step.get('executes_claims'))).lower()}` | "
            f"`{step.get('command') or '-'}` | {str(step.get('success_evidence') or '-').replace('|', '/')} |"
        )
    lines.extend(["", "## Guards", ""])
    for guard in payload.get("guards") or []:
        lines.append(f"- `{guard}`")
    lines.extend(["", "## Contracts", "", "| Contract | Path |", "|----------|------|"])
    for key, value in (payload.get("contracts") or {}).items():
        lines.append(f"| `{key}` | `{value}` |")
    lines.extend(["", "## Claim Boundary", "", str(payload.get("claim_boundary") or "")])
    return "\n".join(lines) + "\n"


def product_readiness_runbook_schema() -> dict[str, Any]:
    step_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "step",
            "id",
            "actor",
            "execution_class",
            "command",
            "requires_real_env",
            "executes_claims",
            "success_evidence",
        ],
        "properties": {
            "step": {"type": "integer", "minimum": 1},
            "id": {"type": "string"},
            "actor": {"type": "string"},
            "execution_class": {"type": "string"},
            "command": {"type": "string"},
            "requires_real_env": {"type": "boolean"},
            "executes_claims": {"type": "boolean"},
            "success_evidence": {"type": "string"},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-runbook.schema.json",
        "title": "Tamandua validation product readiness runbook",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "generated_at",
            "product_ready",
            "automation_state",
            "required_env_count",
            "ready_after_env_required_count",
            "blocked_run_class_count",
            "recommended_next_action_id",
            "recommended_next_action",
            "steps",
            "guards",
            "contracts",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-runbook"},
            "generated_at": {"type": ["string", "null"]},
            "product_ready": {"type": "boolean"},
            "automation_state": {
                "enum": [
                    "blocked_missing_env",
                    "ready_for_post_env_runner",
                    "runtime_evidence_blocked",
                ]
            },
            "required_env_count": {"type": "integer", "minimum": 0},
            "ready_after_env_required_count": {"type": "integer", "minimum": 0},
            "blocked_run_class_count": {"type": "integer", "minimum": 0},
            "recommended_next_action_id": {"type": "string"},
            "recommended_next_action": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "id",
                    "step",
                    "title",
                    "claim_boundary",
                    "commands",
                    "claim_ids",
                    "manual_prerequisites",
                    "env",
                ],
                "properties": {
                    "id": {"type": "string"},
                    "step": {"type": "integer"},
                    "title": {"type": "string"},
                    "claim_boundary": {"type": "string"},
                    "commands": {"type": "array", "items": {"type": "string"}},
                    "claim_ids": {"type": "array", "items": {"type": "string"}},
                    "manual_prerequisites": {"type": "array", "items": {"type": "string"}},
                    "env": {"type": "array", "items": {"type": "string"}},
                },
            },
            "steps": {"type": "array", "items": step_schema},
            "guards": {"type": "array", "items": {"type": "string"}},
            "contracts": {"type": "object"},
            "claim_boundary": {"type": "string"},
        },
    }


def remaining_work_payload(
    summary: dict[str, Any],
    release_gate_contract: dict[str, Any],
    env_request: dict[str, Any],
    claim_status_contract: dict[str, Any],
    blocked_run_classes_contract: dict[str, Any],
    runbook: dict[str, Any],
) -> dict[str, Any]:
    recommended_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    requirements = [
        item
        for item in release_gate_contract.get("requirements") or []
        if isinstance(item, dict) and item.get("passed") is not True
    ]
    requirement_by_id = {str(item.get("id") or ""): item for item in requirements}
    manual_claim_ids = list(release_gate_contract.get("manual_claim_ids") or [])
    items = []

    def open_dependency_ids(depends_on: list[str] | None) -> list[str]:
        open_item_ids = {str(item.get("id") or "") for item in items if isinstance(item, dict)}
        return [str(dep) for dep in depends_on or [] if str(dep) in open_item_ids]

    def add_item(
        item_id: str,
        blocker_type: str,
        source_requirement: str,
        owner: str,
        next_artifact: str,
        evidence_required: list[str],
        depends_on: list[str] | None = None,
    ) -> None:
        requirement = requirement_by_id.get(source_requirement, {})
        items.append(
            {
                "id": item_id,
                "status": "open",
                "blocker_type": blocker_type,
                "source_requirement": source_requirement,
                "current": str(requirement.get("current") or ""),
                "required": str(requirement.get("required") or ""),
                "owner": owner,
                "next_artifact": next_artifact,
                "evidence_required": evidence_required,
                "depends_on": open_dependency_ids(depends_on),
            }
        )

    if "required-env" in requirement_by_id:
        add_item(
            "provide-required-env-bundle",
            "env",
            "required-env",
            "operator",
            "docs/benchmarks/generated/validation_product_readiness_env_request.md",
            [
                "operator check reports current_env_missing_names=[]",
                f"required_env_count=0 (currently {int(env_request.get('required_env_count') or 0)})",
            ],
        )
    if "blocked-env-claims" in requirement_by_id:
        add_item(
            "clear-env-blocked-claims",
            "claim-execution",
            "blocked-env-claims",
            "operator-or-agent",
            "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.ps1",
            [
                "claim_status_report has zero blocked_missing_env claims",
                "env_unblock_queue current_env_missing_count=0",
            ],
            ["provide-required-env-bundle"],
        )
    if "manual-claims" in requirement_by_id:
        first_manual_claim = (
            summary.get("manual_claims")[0]
            if isinstance(summary.get("manual_claims"), list) and summary.get("manual_claims")
            else {}
        )
        manual_evidence = [
            "claim_status_report has zero manual_claim_required claims",
            "external/runtime preconditions from current_next_action are resolved",
        ]
        next_action = str(first_manual_claim.get("next_action") or "")
        if next_action:
            manual_evidence.append(next_action)
        for prerequisite in first_manual_claim.get("manual_prerequisites") or []:
            prerequisite_text = str(prerequisite).strip()
            if prerequisite_text:
                manual_evidence.append(f"manual prerequisite satisfied: {prerequisite_text}")
        add_item(
            "resolve-manual-claims",
            "manual",
            "manual-claims",
            "validation-agent",
            str(first_manual_claim.get("prompt_path") or "") if manual_claim_ids else "",
            manual_evidence,
        )
    if "post-agent-status" in requirement_by_id:
        add_item(
            "pass-ready-after-env-agent-status",
            "agent-status",
            "post-agent-status",
            "operator-or-agent",
            "docs/benchmarks/generated/validation_product_readiness_claim_status_contract.md",
            [
                (
                    "ready_after_env_passed_count="
                    f"{int(claim_status_contract.get('ready_after_env_required_count') or 0)} "
                    f"(currently {int(claim_status_contract.get('ready_after_env_passed_count') or 0)})"
                ),
                "every agent_status.json has status=pass, blocker_cleared=true, missing_profiles=[]",
            ],
            ["clear-env-blocked-claims"],
        )
    if "blocked-run-classes" in requirement_by_id:
        add_item(
            "clear-blocked-run-classes",
            "preflight-run-class",
            "blocked-run-classes",
            "operator-or-agent",
            "docs/benchmarks/generated/validation_product_readiness_blocked_run_classes.contract.md",
            [
                "fresh preflight has blocked_run_classes=[]",
                (
                    "profile_or_lab_blocked_count=0 "
                    f"(currently {int(blocked_run_classes_contract.get('profile_or_lab_blocked_count') or 0)})"
                ),
            ],
            ["provide-required-env-bundle", "pass-ready-after-env-agent-status"],
        )
    for requirement_id, item_id, artifact in [
        ("closure-gate", "rerun-closure-gate", "docs/benchmarks/generated/validation_roadmap_scorecard.json"),
        ("preflight-gate", "rerun-preflight-gate", "docs/benchmarks/runs/index.json"),
        ("dispatch-gate", "rerun-dispatch-gate", "docs/benchmarks/runs/index.json"),
    ]:
        if requirement_id in requirement_by_id:
            evidence = [
                str(value)
                for value in requirement_by_id[requirement_id].get("evidence_required") or []
            ]
            add_item(
                item_id,
                "gate-rerun",
                requirement_id,
                "operator-or-agent",
                artifact,
                evidence,
                ["clear-blocked-run-classes", "pass-ready-after-env-agent-status"],
            )
    order = {str(step.get("id") or ""): int(step.get("step") or 0) for step in runbook.get("steps") or [] if isinstance(step, dict)}
    return {
        "schema_version": 1,
        "artifact": "validation-product-readiness-remaining-work",
        "generated_at": summary.get("generated_at"),
        "product_ready": bool(summary.get("product_ready")),
        "open_count": len(items),
        "failed_requirement_count": int(release_gate_contract.get("failed_count") or 0),
        "runbook_step_count": len(runbook.get("steps") or []),
        "runbook_order": order,
        "recommended_next_action_id": str(summary.get("recommended_next_action_id") or ""),
        "recommended_next_action": {
            "id": str(recommended_action.get("id") or ""),
            "step": int(recommended_action.get("step") or 0),
            "title": str(recommended_action.get("title") or ""),
            "claim_boundary": str(recommended_action.get("claim_boundary") or ""),
            "commands": list(recommended_action.get("commands") or []),
            "claim_ids": list(recommended_action.get("claim_ids") or []),
            "env": list(recommended_action.get("env") or []),
        },
        "items": items,
        "claim_boundary": (
            "remaining work queue only; each item closes only with the listed evidence in refreshed artifacts"
        ),
    }


def render_remaining_work_markdown(payload: dict[str, Any]) -> str:
    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    lines = [
        "# Product Readiness Remaining Work",
        "",
        f"- Product ready: `{str(bool(payload.get('product_ready'))).lower()}`",
        f"- Open items: `{payload.get('open_count') or 0}`",
        f"- Failed requirements: `{payload.get('failed_requirement_count') or 0}`",
        f"- Runbook steps: `{payload.get('runbook_step_count') or 0}`",
        f"- Recommended next action: `{payload.get('recommended_next_action_id') or '-'}`",
        "",
        "## Queue",
        "",
        "| ID | Type | Requirement | Owner | Depends on | Evidence required |",
        "|----|------|-------------|-------|------------|-------------------|",
    ]
    for item in items:
        evidence = "<br>".join(f"`{value}`" for value in item.get("evidence_required") or []) or "-"
        depends_on = ", ".join(item.get("depends_on") or []) or "-"
        lines.append(
            f"| `{item.get('id')}` | `{item.get('blocker_type')}` | `{item.get('source_requirement')}` | "
            f"`{item.get('owner')}` | `{depends_on}` | {evidence} |"
        )
    lines.extend(["", "## Next Artifacts", ""])
    for item in items:
        lines.append(f"- `{item.get('id')}`: `{item.get('next_artifact') or '-'}`")
    lines.extend(["", "## Claim Boundary", "", str(payload.get("claim_boundary") or "")])
    return "\n".join(lines) + "\n"


def remaining_work_schema() -> dict[str, Any]:
    item_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "id",
            "status",
            "blocker_type",
            "source_requirement",
            "current",
            "required",
            "owner",
            "next_artifact",
            "evidence_required",
            "depends_on",
        ],
        "properties": {
            "id": {"type": "string"},
            "status": {"const": "open"},
            "blocker_type": {"type": "string"},
            "source_requirement": {"type": "string"},
            "current": {"type": "string"},
            "required": {"type": "string"},
            "owner": {"type": "string"},
            "next_artifact": {"type": "string"},
            "evidence_required": {"type": "array", "items": {"type": "string"}},
            "depends_on": {"type": "array", "items": {"type": "string"}},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-remaining-work.schema.json",
        "title": "Tamandua validation product readiness remaining work",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "generated_at",
            "product_ready",
            "open_count",
            "failed_requirement_count",
            "runbook_step_count",
            "runbook_order",
            "recommended_next_action_id",
            "recommended_next_action",
            "items",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-remaining-work"},
            "generated_at": {"type": ["string", "null"]},
            "product_ready": {"type": "boolean"},
            "open_count": {"type": "integer", "minimum": 0},
            "failed_requirement_count": {"type": "integer", "minimum": 0},
            "runbook_step_count": {"type": "integer", "minimum": 0},
            "runbook_order": {"type": "object"},
            "recommended_next_action_id": {"type": "string"},
            "recommended_next_action": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "step", "title", "claim_boundary", "commands", "claim_ids", "env"],
                "properties": {
                    "id": {"type": "string"},
                    "step": {"type": "integer"},
                    "title": {"type": "string"},
                    "claim_boundary": {"type": "string"},
                    "commands": {"type": "array", "items": {"type": "string"}},
                    "claim_ids": {"type": "array", "items": {"type": "string"}},
                    "env": {"type": "array", "items": {"type": "string"}},
                },
            },
            "items": {"type": "array", "items": item_schema},
            "claim_boundary": {"type": "string"},
        },
    }


def manual_claim_resolution_payload(summary: dict[str, Any]) -> dict[str, Any]:
    manual_claims = [
        claim for claim in summary.get("manual_claims") or [] if isinstance(claim, dict)
    ]
    recommended_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    claims = []
    for claim in manual_claims:
        package_id = str(claim.get("package_id") or "")
        next_action = str(claim.get("next_action") or "")
        manual_prerequisites = [
            str(value)
            for value in claim.get("manual_prerequisites") or []
            if str(value).strip()
        ]
        if package_id == "wave-1-resolve-atomic-extended-preconditions":
            resolution_options = [
                "Use a WMI-capable disposable target and rerun the Atomic extended package.",
                "Narrow the claim boundary for T1047 and refresh the claim-status report.",
            ]
            evidence_required = [
                "claim_status_report has zero manual_claim_required claims",
                "agent_status.json has status=pass, blocker_cleared=true, and missing_profiles=[]",
                "Atomic T1047 manual boundary is resolved by disposable WMI target or narrowed claim",
            ]
        else:
            guarded_resolution_command = ""
            resolution_options = [
                next_action or "Resolve the external/runtime precondition recorded on this claim.",
                "Refresh the claim-status report after the runtime precondition is resolved.",
            ]
            evidence_required = [
                "claim_status_report has zero manual_claim_required claims",
                "agent_status.json has status=pass, blocker_cleared=true, and missing_profiles=[]",
                "external/runtime preconditions from current_next_action are resolved",
            ]
            if next_action:
                evidence_required.append(next_action)
        for prerequisite in manual_prerequisites:
            evidence_required.append(f"manual prerequisite satisfied: {prerequisite}")
        claims.append(
            {
                "claim_id": str(claim.get("claim_id") or ""),
                "package_id": package_id,
                "wave": int(claim.get("wave") or 0),
                "owner": str(claim.get("owner") or ""),
                "prompt_path": str(claim.get("prompt_path") or ""),
                "script_path": str(claim.get("script_path") or ""),
                "command": str(claim.get("command") or ""),
                "check_only_command": (
                    "python tools/detection_validation/atomic_t1047_lab_capability_probe.py --output-dir "
                    f"{str(claim.get('script_path') or '').rsplit('.', 1)[0]}/outputs"
                    if package_id == "wave-1-resolve-atomic-extended-preconditions"
                    else (
                        "powershell -NoProfile -ExecutionPolicy Bypass -File "
                        "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_check.ps1 -Json"
                    )
                ),
                "guarded_resolution_command": (
                    str(claim.get("command") or "")
                    if package_id == "wave-1-resolve-atomic-extended-preconditions"
                    else guarded_resolution_command
                ),
                "guard_env": "TAMANDUA_ALLOW_MANUAL_CLAIM_RESOLUTION",
                "next_action": next_action,
                "manual_prerequisites": manual_prerequisites,
                "resolution_options": resolution_options,
                "evidence_required": evidence_required,
                "claim_boundary": str(claim.get("claim_boundary") or ""),
            }
        )
    return {
        "schema_version": 1,
        "artifact": "validation-product-readiness-manual-claim-resolution",
        "generated_at": summary.get("generated_at"),
        "product_ready": bool(summary.get("product_ready")),
        "unresolved_manual_claim_count": len(claims),
        "can_claim_manual_resolution": len(claims) == 0,
        "claims": claims,
        "source_artifacts": (
            dict(summary.get("source_artifacts"))
            if isinstance(summary.get("source_artifacts"), dict)
            else {}
        ),
        "runner_path": "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_runner.ps1",
        "runner_execute_guard_env": "TAMANDUA_ALLOW_MANUAL_CLAIM_RESOLUTION",
        "runner_execute_guard_value": "1",
        "recommended_next_action_id": str(summary.get("recommended_next_action_id") or ""),
        "recommended_next_action": {
            "id": str(recommended_action.get("id") or ""),
            "step": int(recommended_action.get("step") or 0),
            "title": str(recommended_action.get("title") or ""),
            "claim_boundary": str(recommended_action.get("claim_boundary") or ""),
            "commands": list(recommended_action.get("commands") or []),
            "claim_ids": list(recommended_action.get("claim_ids") or []),
            "env": list(recommended_action.get("env") or []),
        },
        "claim_status_report": str((summary.get("post_agent_status_gate") or {}).get("report") or ""),
        "claim_boundary": (
            "manual-claim resolution contract only; it does not execute packages or close claims"
        ),
    }


def render_manual_claim_resolution_markdown(payload: dict[str, Any]) -> str:
    claims = payload.get("claims") if isinstance(payload.get("claims"), list) else []
    source_artifacts = (
        payload.get("source_artifacts")
        if isinstance(payload.get("source_artifacts"), dict)
        else {}
    )
    lines = [
        "# Product Readiness Manual Claim Resolution",
        "",
        f"- Product ready: `{str(bool(payload.get('product_ready'))).lower()}`",
        f"- Unresolved manual claims: `{payload.get('unresolved_manual_claim_count') or 0}`",
        f"- Can claim manual resolution: `{str(bool(payload.get('can_claim_manual_resolution'))).lower()}`",
        f"- Claim status report: `{payload.get('claim_status_report') or '-'}`",
        f"- Recommended next action: `{payload.get('recommended_next_action_id') or '-'}`",
        "",
        "## Source Artifacts",
        "",
        "| Source | Artifact |",
        "|--------|----------|",
    ]
    for key in sorted(source_artifacts):
        lines.append(f"| `{key}` | `{source_artifacts.get(key) or '-'}` |")
    lines.extend(
        [
        "",
        "## Claims",
        "",
        "| Claim | Package | Owner | Prompt | Guard | Manual prerequisites | Evidence required |",
        "|-------|---------|-------|--------|-------|----------------------|-------------------|",
        ]
    )
    if claims:
        for claim in claims:
            prerequisites = "<br>".join(
                f"`{value}`" for value in claim.get("manual_prerequisites") or []
            ) or "-"
            evidence = "<br>".join(f"`{value}`" for value in claim.get("evidence_required") or []) or "-"
            lines.append(
                f"| `{claim.get('claim_id') or '-'}` | `{claim.get('package_id') or '-'}` | "
                f"`{claim.get('owner') or '-'}` | `{claim.get('prompt_path') or '-'}` | "
                f"`{claim.get('guard_env') or '-'}` | {prerequisites} | {evidence} |"
            )
    else:
        lines.append("| - | - | - | - | - | - | - |")
    lines.extend(
        [
            "",
            "## Runner",
            "",
            f"- Path: `{payload.get('runner_path') or '-'}`",
            (
                "- Execute guard: "
                f"`{payload.get('runner_execute_guard_env') or '-'}="
                f"{payload.get('runner_execute_guard_value') or '-'}`"
            ),
        ]
    )
    lines.extend(["", "## Claim Boundary", "", str(payload.get("claim_boundary") or "")])
    return "\n".join(lines) + "\n"


def manual_claim_resolution_schema() -> dict[str, Any]:
    recommended_action_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "step", "title", "claim_boundary", "commands", "claim_ids", "env"],
        "properties": {
            "id": {"type": "string"},
            "step": {"type": "integer", "minimum": 0},
            "title": {"type": "string"},
            "claim_boundary": {"type": "string"},
            "commands": {"type": "array", "items": {"type": "string"}},
            "claim_ids": {"type": "array", "items": {"type": "string"}},
            "env": {"type": "array", "items": {"type": "string"}},
        },
    }
    claim_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "claim_id",
            "package_id",
            "wave",
            "owner",
            "prompt_path",
            "script_path",
            "command",
            "check_only_command",
            "guarded_resolution_command",
            "guard_env",
            "next_action",
            "manual_prerequisites",
            "resolution_options",
            "evidence_required",
            "claim_boundary",
        ],
        "properties": {
            "claim_id": {"type": "string"},
            "package_id": {"type": "string"},
            "wave": {"type": "integer"},
            "owner": {"type": "string"},
            "prompt_path": {"type": "string"},
            "script_path": {"type": "string"},
            "command": {"type": "string"},
            "check_only_command": {"type": "string"},
            "guarded_resolution_command": {"type": "string"},
            "guard_env": {"type": "string"},
            "next_action": {"type": "string"},
            "manual_prerequisites": {"type": "array", "items": {"type": "string"}},
            "resolution_options": {"type": "array", "items": {"type": "string"}},
            "evidence_required": {"type": "array", "items": {"type": "string"}},
            "claim_boundary": {"type": "string"},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-manual-claim-resolution.schema.json",
        "title": "Tamandua validation product readiness manual claim resolution",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "generated_at",
            "product_ready",
            "unresolved_manual_claim_count",
            "can_claim_manual_resolution",
            "claims",
            "source_artifacts",
            "runner_path",
            "runner_execute_guard_env",
            "runner_execute_guard_value",
            "recommended_next_action_id",
            "recommended_next_action",
            "claim_status_report",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-manual-claim-resolution"},
            "generated_at": {"type": ["string", "null"]},
            "product_ready": {"type": "boolean"},
            "unresolved_manual_claim_count": {"type": "integer", "minimum": 0},
            "can_claim_manual_resolution": {"type": "boolean"},
            "claims": {"type": "array", "items": claim_schema},
            "source_artifacts": {
                "type": "object",
                "additionalProperties": {"type": ["string", "null"]},
            },
            "runner_path": {"type": "string"},
            "runner_execute_guard_env": {"type": "string"},
            "runner_execute_guard_value": {"type": "string"},
            "recommended_next_action_id": {"type": "string"},
            "recommended_next_action": recommended_action_schema,
            "claim_status_report": {"type": "string"},
            "claim_boundary": {"type": "string"},
        },
    }


def render_manual_claim_resolution_check(
    manual_claim_resolution_json_name: str = "validation_product_readiness_manual_claim_resolution.json",
) -> str:
    return "\n".join(
        [
            "# Product Readiness Manual Claim Resolution Check",
            "# Checks manual-claim resolution handoff shape without executing packages.",
            "param(",
            "  [string]$ManualClaimResolutionJson = (Join-Path $PSScriptRoot '" + manual_claim_resolution_json_name + "'),",
            "  [switch]$Json",
            ")",
            "$ErrorActionPreference = 'Stop'",
            "Set-StrictMode -Version Latest",
            "if (-not (Test-Path $ManualClaimResolutionJson)) { Write-Error ('Missing manual claim resolution JSON: ' + $ManualClaimResolutionJson); exit 2 }",
            "$Payload = Get-Content -Raw -Path $ManualClaimResolutionJson | ConvertFrom-Json",
            "$Claims = @($Payload.claims)",
            "$MissingPromptPaths = @()",
            "$MissingScriptPaths = @()",
            "foreach ($Claim in $Claims) {",
            "  if ($Claim.prompt_path) { $PromptPath = Join-Path (Get-Location) ([string]$Claim.prompt_path); if (-not (Test-Path -LiteralPath $PromptPath)) { $MissingPromptPaths += [string]$Claim.prompt_path } } else { $MissingPromptPaths += [string]$Claim.claim_id }",
            "  if ($Claim.script_path) { $ScriptPath = Join-Path (Get-Location) ([string]$Claim.script_path); if (-not (Test-Path -LiteralPath $ScriptPath)) { $MissingScriptPaths += [string]$Claim.script_path } } else { $MissingScriptPaths += [string]$Claim.claim_id }",
            "}",
            "$Result = [pscustomobject]@{",
            "  schema_version = 1",
            "  artifact = 'validation-product-readiness-manual-claim-resolution-check'",
            "  product_ready = [bool]$Payload.product_ready",
            "  can_claim_manual_resolution = [bool]$Payload.can_claim_manual_resolution",
            "  unresolved_manual_claim_count = [int]$Payload.unresolved_manual_claim_count",
            "  claim_ids = @($Claims | ForEach-Object { [string]$_.claim_id })",
            "  missing_prompt_paths = $MissingPromptPaths",
            "  missing_script_paths = $MissingScriptPaths",
            "  recommended_next_action_id = [string]$Payload.recommended_next_action_id",
            "  recommended_next_action = $Payload.recommended_next_action",
            "  manual_claim_resolution = $Payload",
            "  claim_boundary = 'no-execution manual claim check; does not close claims or claim product readiness'",
            "}",
            "if ($Json) {",
            "  $Result | ConvertTo-Json -Depth 16",
            "} else {",
            "  Write-Host ('Can claim manual resolution: ' + [string]$Result.can_claim_manual_resolution)",
            "  Write-Host ('Unresolved manual claims: ' + [string]$Result.unresolved_manual_claim_count)",
            "  Write-Host ('Claims: ' + (@($Result.claim_ids) -join ', '))",
            "}",
            "if ($MissingPromptPaths.Count -gt 0 -or $MissingScriptPaths.Count -gt 0) { exit 3 }",
            "if ($Result.can_claim_manual_resolution) { exit 0 }",
            "exit 2",
            "",
        ]
    )


def render_manual_claim_resolution_runner(
    manual_claim_resolution_json_name: str = "validation_product_readiness_manual_claim_resolution.json",
) -> str:
    return "\n".join(
        [
            "# Product Readiness Manual Claim Resolution Runner",
            "# Prints manual-claim commands by default; execution requires an explicit guard.",
            "param(",
            "  [string]$ManualClaimResolutionJson = (Join-Path $PSScriptRoot '" + manual_claim_resolution_json_name + "'),",
            "  [switch]$Execute,",
            "  [switch]$Json",
            ")",
            "$ErrorActionPreference = 'Stop'",
            "Set-StrictMode -Version Latest",
            "if (-not (Test-Path -LiteralPath $ManualClaimResolutionJson)) { Write-Error ('Missing manual claim resolution JSON: ' + $ManualClaimResolutionJson); exit 2 }",
            "try { $Payload = Get-Content -Raw -LiteralPath $ManualClaimResolutionJson | ConvertFrom-Json }",
            "catch { Write-Error ('Unable to parse manual claim resolution JSON: ' + $_.Exception.Message); exit 2 }",
            "$Claims = @($Payload.claims)",
            "$GuardEnv = [string]$Payload.runner_execute_guard_env",
            "$GuardValue = [string]$Payload.runner_execute_guard_value",
            "$GuardActual = if ($GuardEnv) { [Environment]::GetEnvironmentVariable($GuardEnv) } else { '' }",
            "$CanExecute = [bool]($Execute -and $GuardEnv -and $GuardActual -eq $GuardValue)",
            "$Commands = @($Claims | ForEach-Object { [string]$_.guarded_resolution_command } | Where-Object { $_ })",
            "$CheckOnlyCommands = @($Claims | ForEach-Object { [string]$_.check_only_command } | Where-Object { $_ })",
            "$ManualPrerequisites = @($Claims | ForEach-Object { @($_.manual_prerequisites) } | Where-Object { $_ })",
            "$Result = [ordered]@{",
            "  schema_version = 1",
            "  artifact = 'validation-product-readiness-manual-claim-resolution-runner'",
            "  product_ready = [bool]$Payload.product_ready",
            "  execute_requested = [bool]$Execute",
            "  execute_allowed = [bool]$CanExecute",
            "  unresolved_manual_claim_count = [int]$Payload.unresolved_manual_claim_count",
            "  claim_ids = @($Claims | ForEach-Object { [string]$_.claim_id })",
            "  check_only_commands = @($CheckOnlyCommands)",
            "  guarded_resolution_commands = @($Commands)",
            "  manual_prerequisites = @($ManualPrerequisites)",
            "  guard_env = [string]$GuardEnv",
            "  guard_required_value = [string]$GuardValue",
            "  recommended_next_action_id = [string]$Payload.recommended_next_action_id",
            "  recommended_next_action = $Payload.recommended_next_action",
            "  claim_boundary = 'manual resolution runner; execution requires explicit guard and may close manual claims only after refreshed evidence'",
            "}",
            "if ($Json) { $Result | ConvertTo-Json -Depth 24 }",
            "if ($Claims.Count -eq 0) { exit 0 }",
            "if (-not $Execute) {",
            "  if (-not $Json) {",
            "    Write-Host 'Manual claim resolution commands require explicit execution guard.'",
            "    if ($ManualPrerequisites.Count -gt 0) {",
            "      Write-Host 'Manual prerequisites must be satisfied before using -Execute:'",
            "      foreach ($Prerequisite in $ManualPrerequisites) { Write-Host ('  ' + [string]$Prerequisite) }",
            "    }",
            "    if ($CheckOnlyCommands.Count -gt 0) {",
            "      Write-Host 'Check-only commands:'",
            "      foreach ($Command in $CheckOnlyCommands) { Write-Host ('  ' + [string]$Command) }",
            "    }",
            "    if ($Commands.Count -gt 0) { Write-Host 'Guarded resolution commands:' }",
            "    foreach ($Command in $Commands) { Write-Host ('  ' + [string]$Command) }",
            "  }",
            "  exit 2",
            "}",
            "if ($Commands.Count -eq 0) {",
            "  Write-Error 'No guarded manual resolution commands are generated for these claims; resolve the external/runtime preconditions and refresh claim status.'",
            "  exit 2",
            "}",
            "if (-not $CanExecute) {",
            "  Write-Error ('Execution guard not satisfied. Set ' + $GuardEnv + '=' + $GuardValue + ' before using -Execute.')",
            "  exit 3",
            "}",
            "foreach ($Command in $Commands) {",
            "  Write-Host ('Running guarded manual command: ' + [string]$Command)",
            "  Invoke-Expression ([string]$Command)",
            "  $CommandExit = if ($LASTEXITCODE -eq $null) { 0 } else { [int]$LASTEXITCODE }",
            "  if ($CommandExit -ne 0) { Write-Error ('Manual command failed with exit code ' + $CommandExit); exit $CommandExit }",
            "}",
            "exit 0",
            "",
        ]
    )


def manual_claim_resolution_runner_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-manual-claim-resolution-runner.schema.json",
        "title": "Tamandua validation product readiness manual claim resolution runner",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "product_ready",
            "execute_requested",
            "execute_allowed",
            "unresolved_manual_claim_count",
            "claim_ids",
            "check_only_commands",
            "guarded_resolution_commands",
            "manual_prerequisites",
            "guard_env",
            "guard_required_value",
            "recommended_next_action_id",
            "recommended_next_action",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-manual-claim-resolution-runner"},
            "product_ready": {"type": "boolean"},
            "execute_requested": {"type": "boolean"},
            "execute_allowed": {"type": "boolean"},
            "unresolved_manual_claim_count": {"type": "integer", "minimum": 0},
            "claim_ids": {"type": "array", "items": {"type": "string"}},
            "check_only_commands": {"type": "array", "items": {"type": "string"}},
            "guarded_resolution_commands": {"type": "array", "items": {"type": "string"}},
            "manual_prerequisites": {"type": "array", "items": {"type": "string"}},
            "guard_env": {"type": "string"},
            "guard_required_value": {"type": "string"},
            "recommended_next_action_id": {"type": "string"},
            "recommended_next_action": {"type": ["object", "null"]},
            "claim_boundary": {"type": "string"},
        },
    }


def manual_claim_resolution_check_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-manual-claim-resolution-check.schema.json",
        "title": "Tamandua validation product readiness manual claim resolution check",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "product_ready",
            "can_claim_manual_resolution",
            "unresolved_manual_claim_count",
            "claim_ids",
            "missing_prompt_paths",
            "missing_script_paths",
            "recommended_next_action_id",
            "recommended_next_action",
            "manual_claim_resolution",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-manual-claim-resolution-check"},
            "product_ready": {"type": "boolean"},
            "can_claim_manual_resolution": {"type": "boolean"},
            "unresolved_manual_claim_count": {"type": "integer", "minimum": 0},
            "claim_ids": {"type": "array", "items": {"type": "string"}},
            "missing_prompt_paths": {"type": "array", "items": {"type": "string"}},
            "missing_script_paths": {"type": "array", "items": {"type": "string"}},
            "recommended_next_action_id": {"type": "string"},
            "recommended_next_action": {"type": ["object", "null"]},
            "manual_claim_resolution": {"type": "object"},
            "claim_boundary": {"type": "string"},
        },
    }


def render_remaining_work_check(
    remaining_work_json_name: str = "validation_product_readiness_remaining_work.json",
) -> str:
    return "\n".join(
        [
            "# Product Readiness Remaining Work Check",
            "# Summarizes open product-readiness work without executing claims or validation probes.",
            "param(",
            "  [string]$RemainingWorkJson = (Join-Path $PSScriptRoot '" + remaining_work_json_name + "'),",
            "  [switch]$Json",
            ")",
            "$ErrorActionPreference = 'Stop'",
            "Set-StrictMode -Version Latest",
            "if (-not (Test-Path $RemainingWorkJson)) { Write-Error ('Missing remaining work JSON: ' + $RemainingWorkJson); exit 2 }",
            "$RemainingWork = Get-Content -Raw -Path $RemainingWorkJson | ConvertFrom-Json",
            "$Items = @($RemainingWork.items)",
            "$OpenItems = @($Items | Where-Object { [string]$_.status -eq 'open' })",
            "$OpenIds = @($OpenItems | ForEach-Object { [string]$_.id })",
            "$OpenIdSet = @{}",
            "foreach ($Id in $OpenIds) { if ($Id) { $OpenIdSet[$Id] = $true } }",
            "$ReadyNow = @()",
            "$BlockedByDependency = @()",
            "foreach ($Item in $OpenItems) {",
            "  $Deps = @($Item.depends_on | ForEach-Object { [string]$_ } | Where-Object { $_ })",
            "  $Unmet = @($Deps | Where-Object { $OpenIdSet.ContainsKey($_) })",
            "  if ($Unmet.Count -eq 0) { $ReadyNow += [string]$Item.id } else { $BlockedByDependency += [pscustomobject]@{ id = [string]$Item.id; unmet_dependencies = $Unmet } }",
            "}",
            "$NextOpenItemId = if ($ReadyNow.Count -gt 0) { [string]$ReadyNow[0] } elseif ($OpenIds.Count -gt 0) { [string]$OpenIds[0] } else { '' }",
            "$Payload = [pscustomobject]@{",
            "  schema_version = 1",
            "  artifact = 'validation-product-readiness-remaining-work-check'",
            "  product_ready = [bool]$RemainingWork.product_ready",
            "  can_claim_product_ready = ($OpenItems.Count -eq 0 -and [bool]$RemainingWork.product_ready)",
            "  open_count = [int]$OpenItems.Count",
            "  failed_requirement_count = [int]$RemainingWork.failed_requirement_count",
            "  ready_now_ids = $ReadyNow",
            "  blocked_by_dependency = $BlockedByDependency",
            "  next_open_item_id = $NextOpenItemId",
            "  remaining_work = $RemainingWork",
            "  claim_boundary = 'no-execution remaining work check; does not close items or claim product readiness'",
            "}",
            "if ($Json) {",
            "  $Payload | ConvertTo-Json -Depth 16",
            "} else {",
            "  Write-Host ('Product ready: ' + [string]$Payload.product_ready)",
            "  Write-Host ('Can claim product ready: ' + [string]$Payload.can_claim_product_ready)",
            "  Write-Host ('Open items: ' + [string]$Payload.open_count)",
            "  Write-Host ('Ready now: ' + (@($Payload.ready_now_ids) -join ', '))",
            "  Write-Host ('Next open item: ' + [string]$Payload.next_open_item_id)",
            "  if ($BlockedByDependency.Count -gt 0) {",
            "    Write-Host 'Blocked by dependency:'",
            "    foreach ($Item in $BlockedByDependency) { Write-Host ('  ' + [string]$Item.id + ' <- ' + (@($Item.unmet_dependencies) -join ', ')) }",
            "  }",
            "}",
            "if ($OpenItems.Count -eq 0) { exit 0 }",
            "exit 2",
            "",
        ]
    )


def remaining_work_check_schema() -> dict[str, Any]:
    blocked_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "unmet_dependencies"],
        "properties": {
            "id": {"type": "string"},
            "unmet_dependencies": {"type": "array", "items": {"type": "string"}},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-remaining-work-check.schema.json",
        "title": "Tamandua validation product readiness remaining work check",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "product_ready",
            "can_claim_product_ready",
            "open_count",
            "failed_requirement_count",
            "ready_now_ids",
            "blocked_by_dependency",
            "next_open_item_id",
            "remaining_work",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-remaining-work-check"},
            "product_ready": {"type": "boolean"},
            "can_claim_product_ready": {"type": "boolean"},
            "open_count": {"type": "integer", "minimum": 0},
            "failed_requirement_count": {"type": "integer", "minimum": 0},
            "ready_now_ids": {"type": "array", "items": {"type": "string"}},
            "blocked_by_dependency": {"type": "array", "items": blocked_schema},
            "next_open_item_id": {"type": "string"},
            "remaining_work": {"type": "object"},
            "claim_boundary": {"type": "string"},
        },
    }


def ready_now_fanout_payload(remaining_work: dict[str, Any]) -> dict[str, Any]:
    items = remaining_work.get("items") if isinstance(remaining_work.get("items"), list) else []
    recommended_action = (
        remaining_work.get("recommended_next_action")
        if isinstance(remaining_work.get("recommended_next_action"), dict)
        else {}
    )
    open_items = [item for item in items if isinstance(item, dict) and item.get("status") == "open"]
    open_id_set = {str(item.get("id") or "") for item in open_items if item.get("id")}
    ready_now = []
    blocked = []
    for item in open_items:
        depends_on = [str(value) for value in item.get("depends_on") or [] if value]
        unmet = [dep for dep in depends_on if dep in open_id_set]
        row = {
            "id": str(item.get("id") or ""),
            "blocker_type": str(item.get("blocker_type") or ""),
            "owner": str(item.get("owner") or ""),
            "source_requirement": str(item.get("source_requirement") or ""),
            "next_artifact": str(item.get("next_artifact") or ""),
            "evidence_required": list(item.get("evidence_required") or []),
            "unmet_dependencies": unmet,
        }
        if unmet:
            blocked.append(row)
        else:
            ready_now.append(row)
    lanes = []
    for row in ready_now:
        owner = row.get("owner") or "operator-or-agent"
        blocker_type = str(row.get("blocker_type") or "")
        if blocker_type == "env":
            lane_id = "operator-input"
            execution_class = "operator-secret-input"
        elif blocker_type == "preflight-run-class":
            lane_id = "operator-or-agent"
            execution_class = "runtime-evidence-resolution"
        elif blocker_type == "gate-rerun":
            lane_id = "validation-authority"
            execution_class = "gate-rerun"
        else:
            lane_id = "validation-agent"
            execution_class = "manual-boundary-resolution"
        lanes.append(
            {
                "lane_id": lane_id,
                "item_id": row["id"],
                "owner": owner,
                "execution_class": execution_class,
                "next_artifact": row.get("next_artifact") or "",
                "evidence_required": list(row.get("evidence_required") or []),
            }
        )
    return {
        "schema_version": 1,
        "artifact": "validation-product-readiness-ready-now-fanout",
        "generated_at": remaining_work.get("generated_at"),
        "product_ready": bool(remaining_work.get("product_ready")),
        "open_count": int(remaining_work.get("open_count") or 0),
        "ready_now_count": len(ready_now),
        "blocked_by_dependency_count": len(blocked),
        "ready_now_items": ready_now,
        "blocked_by_dependency": blocked,
        "lanes": lanes,
        "recommended_next_action_id": str(remaining_work.get("recommended_next_action_id") or ""),
        "recommended_next_action": {
            "id": str(recommended_action.get("id") or ""),
            "step": int(recommended_action.get("step") or 0),
            "title": str(recommended_action.get("title") or ""),
            "claim_boundary": str(recommended_action.get("claim_boundary") or ""),
            "commands": list(recommended_action.get("commands") or []),
            "claim_ids": list(recommended_action.get("claim_ids") or []),
            "env": list(recommended_action.get("env") or []),
        },
        "claim_boundary": (
            "ready-now fanout plan only; lanes identify work that can start now and do not execute commands"
        ),
    }


def render_ready_now_fanout_markdown(payload: dict[str, Any]) -> str:
    ready_now = payload.get("ready_now_items") if isinstance(payload.get("ready_now_items"), list) else []
    blocked = (
        payload.get("blocked_by_dependency")
        if isinstance(payload.get("blocked_by_dependency"), list)
        else []
    )
    lanes = payload.get("lanes") if isinstance(payload.get("lanes"), list) else []
    lines = [
        "# Product Readiness Ready-Now Fanout",
        "",
        f"- Product ready: `{str(bool(payload.get('product_ready'))).lower()}`",
        f"- Open items: `{payload.get('open_count') or 0}`",
        f"- Ready now: `{payload.get('ready_now_count') or 0}`",
        f"- Blocked by dependency: `{payload.get('blocked_by_dependency_count') or 0}`",
        f"- Recommended next action: `{payload.get('recommended_next_action_id') or '-'}`",
        "",
        "## Ready Now",
        "",
        "| Item | Type | Owner | Next artifact | Evidence required |",
        "|------|------|-------|---------------|-------------------|",
    ]
    if ready_now:
        for item in ready_now:
            evidence = "<br>".join(f"`{value}`" for value in item.get("evidence_required") or []) or "-"
            lines.append(
                f"| `{item.get('id')}` | `{item.get('blocker_type')}` | `{item.get('owner')}` | "
                f"`{item.get('next_artifact') or '-'}` | {evidence} |"
            )
    else:
        lines.append("| none | - | - | - | - |")
    lines.extend(["", "## Suggested Lanes", "", "| Lane | Item | Class | Owner |"])
    lines.append("|------|------|-------|-------|")
    if lanes:
        for lane in lanes:
            lines.append(
                f"| `{lane.get('lane_id')}` | `{lane.get('item_id')}` | "
                f"`{lane.get('execution_class')}` | `{lane.get('owner')}` |"
            )
    else:
        lines.append("| none | - | - | - |")
    lines.extend(["", "## Blocked By Dependency", "", "| Item | Unmet dependencies |"])
    lines.append("|------|--------------------|")
    if blocked:
        for item in blocked:
            lines.append(
                f"| `{item.get('id')}` | `{', '.join(item.get('unmet_dependencies') or []) or '-'}` |"
            )
    else:
        lines.append("| none | - |")
    lines.extend(["", "## Claim Boundary", "", str(payload.get("claim_boundary") or "")])
    return "\n".join(lines) + "\n"


def ready_now_fanout_schema() -> dict[str, Any]:
    recommended_action_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "step", "title", "claim_boundary", "commands", "claim_ids", "env"],
        "properties": {
            "id": {"type": "string"},
            "step": {"type": "integer", "minimum": 0},
            "title": {"type": "string"},
            "claim_boundary": {"type": "string"},
            "commands": {"type": "array", "items": {"type": "string"}},
            "claim_ids": {"type": "array", "items": {"type": "string"}},
            "env": {"type": "array", "items": {"type": "string"}},
        },
    }
    item_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "id",
            "blocker_type",
            "owner",
            "source_requirement",
            "next_artifact",
            "evidence_required",
            "unmet_dependencies",
        ],
        "properties": {
            "id": {"type": "string"},
            "blocker_type": {"type": "string"},
            "owner": {"type": "string"},
            "source_requirement": {"type": "string"},
            "next_artifact": {"type": "string"},
            "evidence_required": {"type": "array", "items": {"type": "string"}},
            "unmet_dependencies": {"type": "array", "items": {"type": "string"}},
        },
    }
    lane_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["lane_id", "item_id", "owner", "execution_class", "next_artifact", "evidence_required"],
        "properties": {
            "lane_id": {"type": "string"},
            "item_id": {"type": "string"},
            "owner": {"type": "string"},
            "execution_class": {"type": "string"},
            "next_artifact": {"type": "string"},
            "evidence_required": {"type": "array", "items": {"type": "string"}},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-ready-now-fanout.schema.json",
        "title": "Tamandua validation product readiness ready-now fanout",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "generated_at",
            "product_ready",
            "open_count",
            "ready_now_count",
            "blocked_by_dependency_count",
            "ready_now_items",
            "blocked_by_dependency",
            "lanes",
            "recommended_next_action_id",
            "recommended_next_action",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-ready-now-fanout"},
            "generated_at": {"type": ["string", "null"]},
            "product_ready": {"type": "boolean"},
            "open_count": {"type": "integer", "minimum": 0},
            "ready_now_count": {"type": "integer", "minimum": 0},
            "blocked_by_dependency_count": {"type": "integer", "minimum": 0},
            "ready_now_items": {"type": "array", "items": item_schema},
            "blocked_by_dependency": {"type": "array", "items": item_schema},
            "lanes": {"type": "array", "items": lane_schema},
            "recommended_next_action_id": {"type": "string"},
            "recommended_next_action": recommended_action_schema,
            "claim_boundary": {"type": "string"},
        },
    }


def render_ready_now_fanout_check(
    ready_now_fanout_json_name: str = "validation_product_readiness_ready_now_fanout.json",
) -> str:
    return "\n".join(
        [
            "# Product Readiness Ready-Now Fanout Check",
            "# Validates the no-execution fanout queue for immediately actionable readiness lanes.",
            "param(",
            "  [string]$ReadyNowFanoutJson = (Join-Path $PSScriptRoot '" + ready_now_fanout_json_name + "'),",
            "  [switch]$Json",
            ")",
            "$ErrorActionPreference = 'Stop'",
            "Set-StrictMode -Version Latest",
            "if (-not (Test-Path -LiteralPath $ReadyNowFanoutJson)) { Write-Error ('Missing ready-now fanout JSON: ' + $ReadyNowFanoutJson); exit 3 }",
            "try { $Fanout = Get-Content -Raw -LiteralPath $ReadyNowFanoutJson | ConvertFrom-Json }",
            "catch { Write-Error ('Unable to parse ready-now fanout JSON: ' + $_.Exception.Message); exit 3 }",
            "$Lanes = @($Fanout.lanes)",
            "$ReadyNowItems = @($Fanout.ready_now_items)",
            "$BlockedItems = @($Fanout.blocked_by_dependency)",
            "$LaneIds = @($Lanes | ForEach-Object { [string]$_.item_id })",
            "$ReadyIds = @($ReadyNowItems | ForEach-Object { [string]$_.id })",
            "$MissingLaneIds = @($ReadyIds | Where-Object { $LaneIds -notcontains $_ })",
            "$UnexpectedLaneIds = @($LaneIds | Where-Object { $ReadyIds -notcontains $_ })",
            "$ReadyCountMatches = ([int]$Fanout.ready_now_count -eq $ReadyNowItems.Count)",
            "$BlockedCountMatches = ([int]$Fanout.blocked_by_dependency_count -eq $BlockedItems.Count)",
            "$FanoutContractValid = (",
            "  [int]$Fanout.schema_version -eq 1 -and",
            "  [string]$Fanout.artifact -eq 'validation-product-readiness-ready-now-fanout' -and",
            "  $ReadyCountMatches -and",
            "  $BlockedCountMatches -and",
            "  $MissingLaneIds.Count -eq 0 -and",
            "  $UnexpectedLaneIds.Count -eq 0",
            ")",
            "$Payload = [ordered]@{",
            "  schema_version = 1",
            "  artifact = 'validation-product-readiness-ready-now-fanout-check'",
            "  product_ready = [bool]$Fanout.product_ready",
            "  can_claim_ready_now_fanout_complete = [bool]([int]$Fanout.ready_now_count -eq 0)",
            "  ready_now_count = [int]$Fanout.ready_now_count",
            "  blocked_by_dependency_count = [int]$Fanout.blocked_by_dependency_count",
            "  lane_count = $Lanes.Count",
            "  lane_item_ids = @($LaneIds)",
            "  missing_lane_item_ids = @($MissingLaneIds)",
            "  unexpected_lane_item_ids = @($UnexpectedLaneIds)",
            "  fanout_contract_valid = [bool]$FanoutContractValid",
            "  recommended_next_action_id = [string]$Fanout.recommended_next_action_id",
            "  recommended_next_action = $Fanout.recommended_next_action",
            "  ready_now_fanout = $Fanout",
            "  claim_boundary = 'no-execution ready-now fanout check; it validates lanes only and does not execute commands or close work items'",
            "}",
            "if ($Json) {",
            "  $Payload | ConvertTo-Json -Depth 24",
            "} else {",
            "  Write-Host ('Ready-now fanout contract valid: ' + [string]$Payload.fanout_contract_valid)",
            "  Write-Host ('Ready-now lanes: ' + [string]$Payload.ready_now_count)",
            "  foreach ($ItemId in $Payload.lane_item_ids) { Write-Host ('  ' + [string]$ItemId) }",
            "}",
            "if (-not $FanoutContractValid) { exit 3 }",
            "if ([int]$Fanout.ready_now_count -eq 0) { exit 0 }",
            "exit 2",
            "",
        ]
    )


def ready_now_fanout_check_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-ready-now-fanout-check.schema.json",
        "title": "Tamandua validation product readiness ready-now fanout check",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "product_ready",
            "can_claim_ready_now_fanout_complete",
            "ready_now_count",
            "blocked_by_dependency_count",
            "lane_count",
            "lane_item_ids",
            "missing_lane_item_ids",
            "unexpected_lane_item_ids",
            "fanout_contract_valid",
            "recommended_next_action_id",
            "recommended_next_action",
            "ready_now_fanout",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-ready-now-fanout-check"},
            "product_ready": {"type": "boolean"},
            "can_claim_ready_now_fanout_complete": {"type": "boolean"},
            "ready_now_count": {"type": "integer", "minimum": 0},
            "blocked_by_dependency_count": {"type": "integer", "minimum": 0},
            "lane_count": {"type": "integer", "minimum": 0},
            "lane_item_ids": {"type": "array", "items": {"type": "string"}},
            "missing_lane_item_ids": {"type": "array", "items": {"type": "string"}},
            "unexpected_lane_item_ids": {"type": "array", "items": {"type": "string"}},
            "fanout_contract_valid": {"type": "boolean"},
            "recommended_next_action_id": {"type": "string"},
            "recommended_next_action": {"type": ["object", "null"]},
            "ready_now_fanout": {"type": "object"},
            "claim_boundary": {"type": "string"},
        },
    }


def agent_handoff_manifest_payload(
    summary: dict[str, Any],
    env_request: dict[str, Any],
    post_env_runner_contract: dict[str, Any],
    release_gate_contract: dict[str, Any],
    claim_status_contract: dict[str, Any],
    blocked_run_classes_contract: dict[str, Any],
    runbook: dict[str, Any],
    remaining_work: dict[str, Any],
    ready_now_fanout: dict[str, Any],
    manual_claim_resolution: dict[str, Any],
) -> dict[str, Any]:
    operator_command = (
        "powershell -NoProfile -ExecutionPolicy Bypass -File "
        "docs/benchmarks/generated/validation_product_readiness_operator_check.ps1 -Json"
    )
    recommended_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    action_manual_prerequisites = manual_claim_prerequisites(summary)
    return {
        "schema_version": 1,
        "artifact": "validation-product-readiness-agent-handoff",
        "generated_at": summary.get("generated_at"),
        "product_ready": bool(summary.get("product_ready")),
        "external_claim_allowed": bool(summary.get("external_claim_allowed")),
        "automation_state": product_readiness_automation_state(
            summary,
            env_request,
            release_gate_contract=release_gate_contract,
            blocked_run_classes_contract=blocked_run_classes_contract,
        ),
        "source_summary": "docs/benchmarks/generated/validation_product_readiness_summary.json",
        "source_artifacts": (
            dict(summary.get("source_artifacts"))
            if isinstance(summary.get("source_artifacts"), dict)
            else {}
        ),
        "contracts": {
            "env_request": "docs/benchmarks/generated/validation_product_readiness_env_request.json",
            "env_request_markdown": "docs/benchmarks/generated/validation_product_readiness_env_request.md",
            "env_bundle_local_schema": (
                "docs/benchmarks/generated/validation_product_readiness_env_bundle.local.schema.json"
            ),
            "env_bundle_template": (
                "docs/benchmarks/generated/validation_product_readiness_env_bundle.template.json"
            ),
            "env_bundle_dotenv_template": (
                "docs/benchmarks/generated/validation_product_readiness_env_bundle.template.env"
            ),
            "env_bundle_dotenv_local": (
                "docs/benchmarks/generated/validation_product_readiness_env_bundle.local.env"
            ),
            "env_bundle_local_env_init_schema": (
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_init.schema.json"
            ),
            "env_bundle_local_env_validate_schema": (
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_validate.schema.json"
            ),
            "env_bundle_init_schema": (
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_init.schema.json"
            ),
            "env_bundle_check_schema": (
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_check.schema.json"
            ),
            "env_bundle_runner_schema": (
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.schema.json"
            ),
            "env_bundle_runner_status_check_schema": (
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner_status_check.schema.json"
            ),
            "doctor_schema": "docs/benchmarks/generated/validation_product_readiness_doctor.schema.json",
            "release_gate": "docs/benchmarks/generated/validation_product_readiness_release_gate.contract.json",
            "release_gate_markdown": "docs/benchmarks/generated/validation_product_readiness_release_gate.contract.md",
            "post_env_runner": "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.contract.json",
            "post_env_runner_markdown": (
                "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.contract.md"
            ),
            "post_env_bundle_runner_schema": (
                "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.schema.json"
            ),
            "claim_status": "docs/benchmarks/generated/validation_product_readiness_claim_status_contract.json",
            "claim_status_markdown": "docs/benchmarks/generated/validation_product_readiness_claim_status_contract.md",
            "blocked_run_classes": (
                "docs/benchmarks/generated/validation_product_readiness_blocked_run_classes.contract.json"
            ),
            "blocked_run_classes_markdown": (
                "docs/benchmarks/generated/validation_product_readiness_blocked_run_classes.contract.md"
            ),
            "runbook": "docs/benchmarks/generated/validation_product_readiness_runbook.json",
            "runbook_markdown": "docs/benchmarks/generated/validation_product_readiness_runbook.md",
            "remaining_work": "docs/benchmarks/generated/validation_product_readiness_remaining_work.json",
            "remaining_work_markdown": "docs/benchmarks/generated/validation_product_readiness_remaining_work.md",
            "ready_now_fanout": "docs/benchmarks/generated/validation_product_readiness_ready_now_fanout.json",
            "ready_now_fanout_markdown": "docs/benchmarks/generated/validation_product_readiness_ready_now_fanout.md",
            "ready_now_fanout_check_schema": (
                "docs/benchmarks/generated/validation_product_readiness_ready_now_fanout_check.schema.json"
            ),
            "manual_claim_resolution": (
                "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution.json"
            ),
            "manual_claim_resolution_markdown": (
                "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution.md"
            ),
            "manual_claim_resolution_check_schema": (
                "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_check.schema.json"
            ),
            "manual_claim_resolution_runner": (
                "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_runner.ps1"
            ),
            "manual_claim_resolution_runner_schema": (
                "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_runner.schema.json"
            ),
        },
        "scripts": {
            "operator_check": "docs/benchmarks/generated/validation_product_readiness_operator_check.ps1",
            "env_bundle_local_env_init": (
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_init.ps1"
            ),
            "env_bundle_local_env_validate": (
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_validate.ps1"
            ),
            "env_bundle_init": "docs/benchmarks/generated/validation_product_readiness_env_bundle_init.ps1",
            "env_bundle_check": "docs/benchmarks/generated/validation_product_readiness_env_bundle_check.ps1",
            "env_bundle_runner": "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1",
            "env_bundle_runner_status_check": (
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner_status_check.ps1"
            ),
            "doctor": "docs/benchmarks/generated/validation_product_readiness_doctor.ps1",
            "post_env_runner": "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.ps1",
            "remaining_work_check": "docs/benchmarks/generated/validation_product_readiness_remaining_work_check.ps1",
            "ready_now_fanout_check": (
                "docs/benchmarks/generated/validation_product_readiness_ready_now_fanout_check.ps1"
            ),
            "manual_claim_resolution_check": (
                "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_check.ps1"
            ),
            "manual_claim_resolution_runner": (
                "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_runner.ps1"
            ),
        },
        "commands": {
            "operator_check_json": operator_command,
            "env_bundle_init": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_init.ps1"
            ),
            "env_bundle_init_from_process_env": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_init.ps1 -FromProcessEnv -Force"
            ),
            "env_bundle_local_env_init": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_init.ps1"
            ),
            "env_bundle_local_env_init_force": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_init.ps1 -Force"
            ),
            "env_bundle_local_env_validate_json": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_validate.ps1 "
                "-PrepareIfMissing -Json"
            ),
            "env_bundle_init_from_env_file": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_init.ps1 "
                "-EnvFile docs/benchmarks/generated/validation_product_readiness_env_bundle.local.env -Force"
            ),
            "env_bundle_check_json": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_check.ps1 -Json"
            ),
            "env_bundle_runner_dry_run": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1"
            ),
            "env_bundle_runner_from_process_env_dry_run": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 -InitFromProcessEnv"
            ),
            "env_bundle_runner_json_status": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 -Json"
            ),
            "env_bundle_runner_from_process_env_json_status": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 -InitFromProcessEnv -Json"
            ),
            "env_bundle_runner_status_check_json": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner_status_check.ps1 -Json"
            ),
            "env_bundle_runner_status_check_from_process_env_json": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner_status_check.ps1 "
                "-InitFromProcessEnv -Json"
            ),
            "doctor_json": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_doctor.ps1 -Json"
            ),
            "doctor_from_process_env_json": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_doctor.ps1 -InitFromProcessEnv -Json"
            ),
            "remaining_work_check_json": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_remaining_work_check.ps1 -Json"
            ),
            "ready_now_fanout_check_json": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_ready_now_fanout_check.ps1 -Json"
            ),
            "manual_claim_resolution_check_json": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_check.ps1 -Json"
            ),
            "manual_claim_resolution_runner_json": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_runner.ps1 -Json"
            ),
            "post_env_runner_dry_run": next(
                (
                    str(mode.get("command") or "")
                    for mode in post_env_runner_contract.get("modes") or []
                    if isinstance(mode, dict) and mode.get("id") == "dry-run"
                ),
                "",
            ),
            "post_env_runner_balanced_execute": next(
                (
                    str(mode.get("command") or "")
                    for mode in post_env_runner_contract.get("modes") or []
                    if isinstance(mode, dict) and mode.get("id") == "balanced-agent-fanout"
                ),
                "",
            ),
            "post_env_runner_json_status": (
                "powershell -NoProfile -ExecutionPolicy Bypass -File "
                "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.ps1 -Json"
            ),
            "post_env_runner_process_env_balanced_execute": next(
                (
                    str(mode.get("command") or "")
                    for mode in post_env_runner_contract.get("modes") or []
                    if isinstance(mode, dict) and mode.get("id") == "process-env-balanced-agent-fanout"
                ),
                "",
            ),
            "post_env_runner_process_env_balanced_execute_refresh_authority": next(
                (
                    str(mode.get("command") or "")
                    for mode in post_env_runner_contract.get("modes") or []
                    if isinstance(mode, dict)
                    and mode.get("id") == "process-env-balanced-agent-fanout-refresh-authority"
                ),
                "",
            ),
            "refresh_claim_status": str(post_env_runner_contract.get("refresh_claim_status_command") or ""),
            "refresh_authority": "python tools/detection_validation/refresh_validation_authority.py",
        },
        "counts": {
            "release_gate_failed": int(release_gate_contract.get("failed_count") or 0),
            "required_env": int(env_request.get("required_env_count") or 0),
            "secret_env": int(env_request.get("secret_count") or 0),
            "metadata_env": int(env_request.get("metadata_count") or 0),
            "ready_after_env_claims": int(post_env_runner_contract.get("ready_claim_count") or 0),
            "still_blocked_after_env_claims": int(post_env_runner_contract.get("still_blocked_claim_count") or 0),
            "manual_claims": len(release_gate_contract.get("manual_claim_ids") or []),
            "blocked_run_classes": int(release_gate_contract.get("blocked_run_class_count") or 0),
        },
        "blocked_requirements": list(release_gate_contract.get("failed_ids") or []),
        "required_env_names": list(env_request.get("entries") and [entry.get("env") for entry in env_request["entries"]] or []),
        "ready_after_env_claim_ids": list(post_env_runner_contract.get("ready_claim_ids") or []),
        "claim_status_required_fields": list(
            (claim_status_contract.get("required_agent_status_contract") or {}).get("required_fields") or []
        ),
        "blocked_run_class_resolution_counts": {
            "env_required": int(blocked_run_classes_contract.get("env_blocked_count") or 0),
            "profile_or_lab_required": int(blocked_run_classes_contract.get("profile_or_lab_blocked_count") or 0),
        },
        "runbook_step_count": len(runbook.get("steps") or []),
        "remaining_work_open_count": int(remaining_work.get("open_count") or 0),
        "ready_now_fanout_count": int(ready_now_fanout.get("ready_now_count") or 0),
        "manual_claim_ids": list(release_gate_contract.get("manual_claim_ids") or []),
        "manual_claim_resolution_open_count": int(
            manual_claim_resolution.get("unresolved_manual_claim_count") or 0
        ),
        "recommended_next_action_id": str(summary.get("recommended_next_action_id") or ""),
        "recommended_next_action": {
            "id": str(recommended_action.get("id") or ""),
            "step": int(recommended_action.get("step") or 0),
            "title": str(recommended_action.get("title") or ""),
            "claim_boundary": str(recommended_action.get("claim_boundary") or ""),
            "actions": list(recommended_action.get("actions") or []),
            "commands": list(recommended_action.get("commands") or []),
            "claim_ids": list(recommended_action.get("claim_ids") or []),
            "manual_prerequisites": action_manual_prerequisites,
            "env": list(recommended_action.get("env") or []),
        },
        "claim_boundary": (
            "agent handoff index only; does not contain real secrets and does not claim product readiness"
        ),
    }


def render_agent_handoff_manifest_markdown(payload: dict[str, Any]) -> str:
    recommended_action = (
        payload.get("recommended_next_action")
        if isinstance(payload.get("recommended_next_action"), dict)
        else {}
    )
    source_artifacts = (
        payload.get("source_artifacts")
        if isinstance(payload.get("source_artifacts"), dict)
        else {}
    )
    lines = [
        "# Product Readiness Agent Handoff",
        "",
        f"- Product ready: `{str(bool(payload.get('product_ready'))).lower()}`",
        f"- External claim allowed: `{str(bool(payload.get('external_claim_allowed'))).lower()}`",
        f"- Automation state: `{payload.get('automation_state') or '-'}`",
        f"- Release gate failed: `{(payload.get('counts') or {}).get('release_gate_failed') or 0}`",
        f"- Required env: `{(payload.get('counts') or {}).get('required_env') or 0}`",
        f"- Ready-after-env claims: `{(payload.get('counts') or {}).get('ready_after_env_claims') or 0}`",
        f"- Recommended next action: `{payload.get('recommended_next_action_id') or '-'}`",
        "",
        "## Source Artifacts",
        "",
        "| Source | Artifact |",
        "|--------|----------|",
    ]
    for key in sorted(source_artifacts):
        lines.append(f"| `{key}` | `{source_artifacts.get(key) or '-'}` |")
    lines.extend(
        [
        "",
        "## Recommended Next Action",
        "",
        f"- ID: `{recommended_action.get('id') or '-'}`",
        f"- Step: `{recommended_action.get('step') or 0}`",
        f"- Title: {recommended_action.get('title') or '-'}",
        f"- Claim boundary: {recommended_action.get('claim_boundary') or '-'}",
        "",
        "### Actions",
        "",
        ]
    )
    for item in recommended_action.get("actions") or []:
        lines.append(f"- {item}")
    if not recommended_action.get("actions"):
        lines.append("- -")
    lines.extend(["", "### Commands", ""])
    for item in recommended_action.get("commands") or []:
        lines.append(f"- `{item}`")
    if not recommended_action.get("commands"):
        lines.append("- -")
    lines.extend(["", "### Claims", ""])
    for item in recommended_action.get("claim_ids") or []:
        lines.append(f"- `{item}`")
    if not recommended_action.get("claim_ids"):
        lines.append("- -")
    lines.extend(["", "### Manual Prerequisites", ""])
    for item in recommended_action.get("manual_prerequisites") or []:
        lines.append(f"- {item}")
    if not recommended_action.get("manual_prerequisites"):
        lines.append("- -")
    lines.extend(["", "### Env", ""])
    for item in recommended_action.get("env") or []:
        lines.append(f"- `{item}`")
    if not recommended_action.get("env"):
        lines.append("- -")
    lines.extend([
        "",
        "## Commands",
        "",
        "| Command | Value |",
        "|---------|-------|",
    ])
    for key, value in (payload.get("commands") or {}).items():
        lines.append(f"| `{key}` | `{value or '-'}` |")
    lines.extend(["", "## Contracts", "", "| Contract | Path |", "|----------|------|"])
    for key, value in (payload.get("contracts") or {}).items():
        lines.append(f"| `{key}` | `{value}` |")
    lines.extend(["", "## Blocked Requirements", ""])
    for item in payload.get("blocked_requirements") or []:
        lines.append(f"- `{item}`")
    lines.extend(["", "## Required Env", ""])
    for item in payload.get("required_env_names") or []:
        lines.append(f"- `{item}`")
    lines.extend(["", "## Claim Boundary", "", str(payload.get("claim_boundary") or "")])
    return "\n".join(lines) + "\n"


def agent_handoff_manifest_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-agent-handoff.schema.json",
        "title": "Tamandua validation product readiness agent handoff",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "generated_at",
            "product_ready",
            "external_claim_allowed",
            "automation_state",
            "source_summary",
            "source_artifacts",
            "contracts",
            "scripts",
            "commands",
            "counts",
            "blocked_requirements",
            "required_env_names",
            "ready_after_env_claim_ids",
            "claim_status_required_fields",
            "blocked_run_class_resolution_counts",
            "runbook_step_count",
            "remaining_work_open_count",
            "ready_now_fanout_count",
            "manual_claim_ids",
            "manual_claim_resolution_open_count",
            "recommended_next_action_id",
            "recommended_next_action",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-agent-handoff"},
            "generated_at": {"type": ["string", "null"]},
            "product_ready": {"type": "boolean"},
            "external_claim_allowed": {"type": "boolean"},
            "automation_state": {
                "enum": [
                    "blocked_missing_env",
                    "ready_for_post_env_runner",
                    "runtime_evidence_blocked",
                ]
            },
            "source_summary": {"type": "string"},
            "source_artifacts": {
                "type": "object",
                "additionalProperties": {"type": ["string", "null"]},
            },
            "contracts": {"type": "object"},
            "scripts": {"type": "object"},
            "commands": {"type": "object"},
            "counts": {"type": "object"},
            "blocked_requirements": {"type": "array", "items": {"type": "string"}},
            "required_env_names": {"type": "array", "items": {"type": "string"}},
            "ready_after_env_claim_ids": {"type": "array", "items": {"type": "string"}},
            "claim_status_required_fields": {"type": "array", "items": {"type": "string"}},
            "blocked_run_class_resolution_counts": {"type": "object"},
            "runbook_step_count": {"type": "integer", "minimum": 0},
            "remaining_work_open_count": {"type": "integer", "minimum": 0},
            "ready_now_fanout_count": {"type": "integer", "minimum": 0},
            "manual_claim_ids": {"type": "array", "items": {"type": "string"}},
            "manual_claim_resolution_open_count": {"type": "integer", "minimum": 0},
            "recommended_next_action_id": {"type": "string"},
            "recommended_next_action": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "id",
                    "step",
                    "title",
                    "claim_boundary",
                    "actions",
                    "commands",
                    "claim_ids",
                    "manual_prerequisites",
                    "env",
                ],
                "properties": {
                    "id": {"type": "string"},
                    "step": {"type": "integer"},
                    "title": {"type": "string"},
                    "claim_boundary": {"type": "string"},
                    "actions": {"type": "array", "items": {"type": "string"}},
                    "commands": {"type": "array", "items": {"type": "string"}},
                    "claim_ids": {"type": "array", "items": {"type": "string"}},
                    "manual_prerequisites": {"type": "array", "items": {"type": "string"}},
                    "env": {"type": "array", "items": {"type": "string"}},
                },
            },
            "claim_boundary": {"type": "string"},
        },
    }


def render_operator_check(summary_json_name: str = "validation_product_readiness_summary.json") -> str:
    return "\n".join(
        [
            "# Product Readiness Operator Check",
            "# Prints no-execution next steps from validation_product_readiness_summary.json.",
            "param(",
            "  [string]$SummaryJson = (Join-Path $PSScriptRoot '" + summary_json_name + "'),",
            "  [switch]$Json",
            ")",
            "$ErrorActionPreference = 'Stop'",
            "Set-StrictMode -Version Latest",
            "if (-not (Test-Path $SummaryJson)) {",
            "  Write-Error ('Missing product readiness summary JSON: ' + $SummaryJson)",
            "  exit 2",
            "}",
            "try {",
            "  $Summary = Get-Content -Raw -Path $SummaryJson | ConvertFrom-Json",
            "} catch {",
            "  Write-Error ('Unable to parse product readiness summary JSON: ' + [string]$_.Exception.Message)",
            "  exit 2",
            "}",
            "$EnvQueue = $Summary.env_queue",
            "if (-not $EnvQueue) { Write-Error 'Summary missing env_queue.'; exit 2 }",
            "$HandoffArtifacts = if ($Summary.PSObject.Properties.Name -contains 'handoff_artifacts') { $Summary.handoff_artifacts } else { [pscustomobject]@{} }",
            "$ProductReleaseGate = if ($Summary.PSObject.Properties.Name -contains 'product_release_gate') { $Summary.product_release_gate } else { [pscustomobject]@{} }",
            "$PostEnvBundlePlan = if ($Summary.PSObject.Properties.Name -contains 'post_env_bundle_plan') { $Summary.post_env_bundle_plan } else { [pscustomobject]@{} }",
            "$PostAgentStatusGate = if ($Summary.PSObject.Properties.Name -contains 'post_agent_status_gate') { $Summary.post_agent_status_gate } else { [pscustomobject]@{} }",
            "$EnvDetails = if ($Summary.PSObject.Properties.Name -contains 'env_details') { $Summary.env_details } else { [pscustomobject]@{} }",
            "$MissingEnv = @()",
            "$PlaceholderEnv = @()",
            "foreach ($EnvName in @($EnvQueue.current_env_missing_names)) {",
            "  $Name = [string]$EnvName",
            "  if (-not $Name) { continue }",
            "  $Value = [Environment]::GetEnvironmentVariable($Name)",
            "  if (-not $Value) { $MissingEnv += $Name; continue }",
            "  $Impact = @($EnvQueue.env_impact | Where-Object { [string]$_.env -eq $Name } | Select-Object -First 1)",
            "  $Placeholder = if ($Impact.Count -gt 0 -and $Impact[0].PSObject.Properties.Name -contains 'powershell_set_command') { [string]$Impact[0].powershell_set_command } else { '' }",
            "  if ($Value -match '^<set-.+>$') { $PlaceholderEnv += $Name }",
            "}",
            "$ReadyFastPaths = @()",
            "foreach ($Path in @($Summary.single_env_fast_paths)) {",
            "  $EnvName = [string]$Path.env",
            "  if ($EnvName -and [Environment]::GetEnvironmentVariable($EnvName) -and -not ([Environment]::GetEnvironmentVariable($EnvName) -match '^<set-.+>$')) {",
            "    $ReadyFastPaths += $Path",
            "  }",
            "}",
            "$AllRequiredEnv = @($EnvQueue.current_env_missing_names)",
            "$FullBundleReady = ($AllRequiredEnv.Count -gt 0 -and $MissingEnv.Count -eq 0 -and $PlaceholderEnv.Count -eq 0)",
            "$MissingSetCommands = @()",
            "foreach ($Command in @($EnvQueue.all_env_powershell_set_commands)) {",
            "  foreach ($EnvName in $MissingEnv) {",
            "    if ([string]$Command -match ('^\\$env:' + [regex]::Escape([string]$EnvName) + '\\s*=')) { $MissingSetCommands += [string]$Command }",
            "  }",
            "}",
            "$MissingEnvDetails = @()",
            "foreach ($EnvName in ($MissingEnv | Sort-Object)) {",
            "  $DetailProperty = $EnvDetails.PSObject.Properties[[string]$EnvName]",
            "  $Detail = if ($DetailProperty) { $DetailProperty.Value } else { [pscustomobject]@{ env = [string]$EnvName } }",
            "  $MissingEnvDetails += $Detail",
            "}",
            "$LaunchableClaimIds = @()",
            "$FastPathCommands = @()",
            "foreach ($Path in $ReadyFastPaths) {",
            "  foreach ($ClaimId in @($Path.claim_ids)) { if ($ClaimId) { $LaunchableClaimIds += [string]$ClaimId } }",
            "  foreach ($Command in @($Path.commands)) { if ($Command) { $FastPathCommands += [string]$Command } }",
            "}",
            "$RecommendedNextActionId = 'fill-env-bundle'",
            "$RecommendedCommands = @(",
            "  'powershell -NoProfile -ExecutionPolicy Bypass -File docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_validate.ps1 -PrepareIfMissing -Json'",
            ")",
            "$PostEnvBundleActionable = if ($PostEnvBundlePlan.PSObject.Properties.Name -contains 'actionable') { [string]$PostEnvBundlePlan.actionable } else { 'false' }",
            "$PostAgentPassed = if ($PostAgentStatusGate.PSObject.Properties.Name -contains 'ready_after_env_passed_count') { [string]$PostAgentStatusGate.ready_after_env_passed_count } else { '0' }",
            "$PostAgentRequired = if ($PostAgentStatusGate.PSObject.Properties.Name -contains 'ready_after_env_required_count') { [string]$PostAgentStatusGate.ready_after_env_required_count } else { '0' }",
            "if ($FullBundleReady) {",
            "  $RecommendedNextActionId = 'validate-env-bundle'",
            "  $RecommendedCommands = @([string]$EnvQueue.env_bundle_validation_command)",
            "} elseif ($AllRequiredEnv.Count -eq 0) {",
            "  $RecommendedNextActionId = [string]$Summary.recommended_next_action_id",
            "  $RecommendedCommands = @($Summary.recommended_next_action.commands)",
            "} elseif ($ReadyFastPaths.Count -gt 0) {",
            "  $RecommendedNextActionId = 'launch-single-env-fast-paths'",
            "  $RecommendedCommands = @($FastPathCommands)",
            "}",
            "$AutomationState = 'blocked_missing_env'",
            "if ($FullBundleReady) {",
            "  $AutomationState = 'full_env_bundle_ready'",
            "} elseif ($AllRequiredEnv.Count -eq 0) {",
            "  $AutomationState = 'runtime_evidence_blocked'",
            "} elseif ($ReadyFastPaths.Count -gt 0) {",
            "  $AutomationState = 'single_env_fast_path_ready'",
            "}",
            "$Result = [ordered]@{",
            "  schema_version = 1",
            "  artifact = 'validation-product-readiness-operator-check'",
            "  product_ready = [bool]$Summary.product_ready",
            "  product_release_gate = $ProductReleaseGate",
            "  automation_state = [string]$AutomationState",
            "  can_launch_now = [bool]($ReadyFastPaths.Count -gt 0 -or $FullBundleReady)",
            "  needs_env_input = [bool]($MissingEnv.Count -gt 0)",
            "  required_env_count = [int]$AllRequiredEnv.Count",
            "  current_env_present_count = [int]($AllRequiredEnv.Count - $MissingEnv.Count)",
            "  current_env_missing_names = @($MissingEnv | Sort-Object)",
            "  missing_env_details = @($MissingEnvDetails)",
            "  placeholder_env_names = @($PlaceholderEnv | Sort-Object)",
            "  single_env_fast_paths_ready = @($ReadyFastPaths)",
            "  single_env_fast_path_count = [int]$ReadyFastPaths.Count",
            "  full_env_bundle_ready = [bool]$FullBundleReady",
            "  env_bundle_validation_command = [string]$EnvQueue.env_bundle_validation_command",
            "  post_env_bundle_balanced_agent_spawn_commands = @($EnvQueue.post_env_bundle_balanced_agent_spawn_commands)",
            "  post_env_bundle_plan = $PostEnvBundlePlan",
            "  post_agent_status_gate = $PostAgentStatusGate",
            "  handoff_artifacts = $HandoffArtifacts",
            "  manual_claims = @($Summary.manual_claims)",
            "  missing_set_commands = @($MissingSetCommands)",
            "  launchable_claim_ids = @($LaunchableClaimIds | Sort-Object -Unique)",
            "  recommended_next_action_id = [string]$RecommendedNextActionId",
            "  recommended_next_action_commands = @($RecommendedCommands)",
            "}",
            "if ($Json) {",
            "  $Result | ConvertTo-Json -Depth 12",
            "  if ($ReadyFastPaths.Count -gt 0 -or $FullBundleReady) { exit 0 }",
            "  exit 2",
            "}",
            "Write-Host ('Product ready: ' + [string]$Summary.product_ready)",
            "Write-Host ('Product release gate passed: ' + [string]$ProductReleaseGate.passed)",
            "Write-Host ('Recommended next action: ' + [string]$RecommendedNextActionId)",
            "Write-Host ('Post-env bundle actionable: ' + $PostEnvBundleActionable)",
            "Write-Host ('Post-agent status gate: ' + $PostAgentPassed + '/' + $PostAgentRequired)",
            "Write-Host ('Current env present: ' + [string]($AllRequiredEnv.Count - $MissingEnv.Count) + '/' + [string]$AllRequiredEnv.Count)",
            "Write-Host ('Current env missing: ' + (($MissingEnv | Sort-Object) -join ', '))",
            "if ($PlaceholderEnv.Count -gt 0) { Write-Host ('Placeholder env values: ' + (($PlaceholderEnv | Sort-Object) -join ', ')) }",
            "if ($ReadyFastPaths.Count -gt 0) {",
            "  Write-Host 'Single-env fast paths ready now:'",
            "  foreach ($Path in $ReadyFastPaths) {",
            "    Write-Host ('- ' + [string]$Path.env + ': ' + (@($Path.claim_ids) -join ', '))",
            "    foreach ($Command in @($Path.commands)) { Write-Host ('  ' + [string]$Command) }",
            "  }",
            "} else {",
            "  Write-Host 'Single-env fast paths ready now: -'",
            "}",
            "if ($FullBundleReady) {",
            "  Write-Host 'Full env bundle ready now. Validate before launch:'",
            "  Write-Host ('  ' + [string]$EnvQueue.env_bundle_validation_command)",
            "  foreach ($Command in @($EnvQueue.post_env_bundle_balanced_agent_spawn_commands)) { Write-Host ('  ' + [string]$Command) }",
            "} else {",
            "  Write-Host 'Full env bundle ready now: false'",
            "  if ($MissingEnv.Count -gt 0) {",
            "    Write-Host 'Missing set commands:'",
            "    foreach ($Command in $MissingSetCommands) { Write-Host ('  ' + [string]$Command) }",
            "  }",
            "}",
            "if ($ReadyFastPaths.Count -gt 0 -or $FullBundleReady) { exit 0 }",
            "exit 2",
            "",
        ]
    )


def render_post_env_bundle_runner(
    summary_json_name: str = "validation_product_readiness_summary.json",
    operator_check_name: str = "validation_product_readiness_operator_check.ps1",
) -> str:
    return "\n".join(
        [
            "# Product Readiness Post-Env Bundle Runner",
            "# Validates the full env bundle and optionally launches generated post-env claims.",
            "param(",
            "  [string]$SummaryJson = (Join-Path $PSScriptRoot '" + summary_json_name + "'),",
            "  [string]$OperatorCheck = (Join-Path $PSScriptRoot '" + operator_check_name + "'),",
            "  [switch]$UseBalancedAgents,",
            "  [switch]$Execute,",
            "  [switch]$RefreshClaimStatus,",
            "  [switch]$Json",
            ")",
            "$ErrorActionPreference = 'Stop'",
            "Set-StrictMode -Version Latest",
            "if (-not (Test-Path $SummaryJson)) { Write-Error ('Missing product readiness summary JSON: ' + $SummaryJson); exit 2 }",
            "if (-not (Test-Path $OperatorCheck)) { Write-Error ('Missing operator check script: ' + $OperatorCheck); exit 2 }",
            "$Summary = Get-Content -Raw -Path $SummaryJson | ConvertFrom-Json",
            "$OperatorJsonText = & powershell -NoProfile -ExecutionPolicy Bypass -File $OperatorCheck -SummaryJson $SummaryJson -Json",
            "$OperatorExit = if ($LASTEXITCODE -eq $null) { 0 } else { [int]$LASTEXITCODE }",
            "try { $OperatorPayload = $OperatorJsonText | ConvertFrom-Json } catch { Write-Error 'Operator check did not return valid JSON.'; exit 2 }",
            "$Plan = $Summary.post_env_bundle_plan",
            "$LaunchCommands = if ($Plan -and $UseBalancedAgents) { @($Plan.balanced_agent_spawn_commands) } elseif ($Plan) { @($Plan.package_launcher_commands) } else { @() }",
            "$LaunchMode = if ($UseBalancedAgents) { 'balanced-agent-fanout' } else { 'package-launcher' }",
            "$RefreshCommand = if ($Summary.post_agent_status_gate) { [string]$Summary.post_agent_status_gate.refresh_command } else { '' }",
            "$StatusPayload = [ordered]@{",
            "  schema_version = 1",
            "  artifact = 'validation-product-readiness-post-env-bundle-runner'",
            "  product_ready = [bool]$OperatorPayload.product_ready",
            "  execute_requested = [bool]$Execute",
            "  execute_allowed = [bool]([bool]$OperatorPayload.full_env_bundle_ready -and [bool]$Execute)",
            "  use_balanced_agents = [bool]$UseBalancedAgents",
            "  refresh_claim_status_requested = [bool]$RefreshClaimStatus",
            "  full_env_bundle_ready = [bool]$OperatorPayload.full_env_bundle_ready",
            "  automation_state = [string]$OperatorPayload.automation_state",
            "  missing_env_names = @($OperatorPayload.current_env_missing_names)",
            "  ready_claim_ids = if ($Plan) { @($Plan.ready_claim_ids) } else { @() }",
            "  launch_mode = [string]$LaunchMode",
            "  launch_commands = @($LaunchCommands)",
            "  refresh_claim_status_command = [string]$RefreshCommand",
            "  operator_check_exit_code = [int]$OperatorExit",
            "  claim_boundary = 'post-env runner JSON status only; it does not import secret values, validate packages, or launch claims'",
            "}",
            "if ($Json) {",
            "  $StatusPayload | ConvertTo-Json -Depth 16",
            "  if ([bool]$OperatorPayload.full_env_bundle_ready) { exit 0 }",
            "  if ($OperatorExit -ne 0) { exit $OperatorExit }",
            "  exit 2",
            "}",
            "if (-not [bool]$OperatorPayload.full_env_bundle_ready) {",
            "  Write-Host ('Product ready: ' + [string]$OperatorPayload.product_ready)",
            "  Write-Host ('Automation state: ' + [string]$OperatorPayload.automation_state)",
            "  Write-Host ('Full env bundle ready: ' + [string]$OperatorPayload.full_env_bundle_ready)",
            "  Write-Host ('Missing env: ' + (@($OperatorPayload.current_env_missing_names) -join ', '))",
            "  Write-Host 'Recommended commands:'",
            "  foreach ($Command in @($OperatorPayload.recommended_next_action_commands)) { Write-Host ('  ' + [string]$Command) }",
            "  if ($OperatorExit -ne 0) { exit $OperatorExit }",
            "  exit 2",
            "}",
            "if (-not $Plan) { Write-Error 'Summary missing post_env_bundle_plan.'; exit 2 }",
            "$ValidateCommand = [string]$Plan.validate_command",
            "if (-not $ValidateCommand) { Write-Error 'Summary missing post-env validation command.'; exit 2 }",
            "Write-Host 'Validating full env bundle before any launch:'",
            "Write-Host ('  ' + $ValidateCommand)",
            "Invoke-Expression $ValidateCommand",
            "$ValidateExit = if ($LASTEXITCODE -eq $null) { 0 } else { [int]$LASTEXITCODE }",
            "if ($ValidateExit -ne 0) { Write-Error ('Env bundle validation failed with exit code ' + $ValidateExit); exit $ValidateExit }",
            "Write-Host ('Launch mode: ' + $LaunchMode)",
            "Write-Host ('Ready claims: ' + (@($Plan.ready_claim_ids) -join ', '))",
            "if (-not $Execute) {",
            "  Write-Host 'Execute not set; printing launch commands only.'",
            "  foreach ($Command in $LaunchCommands) { Write-Host ('  ' + [string]$Command) }",
            "  exit 0",
            "}",
            "if ($UseBalancedAgents) { $env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1' }",
            "$env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'",
            "foreach ($Command in $LaunchCommands) {",
            "  if (-not [string]$Command) { continue }",
            "  Write-Host ('Running: ' + [string]$Command)",
            "  Invoke-Expression ([string]$Command)",
            "  $CommandExit = if ($LASTEXITCODE -eq $null) { 0 } else { [int]$LASTEXITCODE }",
            "  if ($CommandExit -ne 0) { Write-Error ('Launch command failed with exit code ' + $CommandExit); exit $CommandExit }",
            "}",
            "if ($RefreshClaimStatus -and $RefreshCommand) {",
            "  Write-Host ('Refreshing claim status report: ' + $RefreshCommand)",
            "  Invoke-Expression $RefreshCommand",
            "  $RefreshExit = if ($LASTEXITCODE -eq $null) { 0 } else { [int]$LASTEXITCODE }",
            "  if ($RefreshExit -ne 0) { Write-Error ('Claim status refresh failed with exit code ' + $RefreshExit); exit $RefreshExit }",
            "} elseif ($RefreshCommand) {",
            "  Write-Host 'Refresh command after launch:'",
            "  Write-Host ('  ' + $RefreshCommand)",
            "}",
            "Write-Host 'Post-env bundle runner finished.'",
            "exit 0",
            "",
        ]
    )


def post_env_bundle_runner_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-post-env-bundle-runner.schema.json",
        "title": "Tamandua validation product readiness post-env bundle runner",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "product_ready",
            "execute_requested",
            "execute_allowed",
            "use_balanced_agents",
            "refresh_claim_status_requested",
            "full_env_bundle_ready",
            "automation_state",
            "missing_env_names",
            "ready_claim_ids",
            "launch_mode",
            "launch_commands",
            "refresh_claim_status_command",
            "operator_check_exit_code",
            "claim_boundary",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-post-env-bundle-runner"},
            "product_ready": {"type": "boolean"},
            "execute_requested": {"type": "boolean"},
            "execute_allowed": {"type": "boolean"},
            "use_balanced_agents": {"type": "boolean"},
            "refresh_claim_status_requested": {"type": "boolean"},
            "full_env_bundle_ready": {"type": "boolean"},
            "automation_state": {"type": "string"},
            "missing_env_names": {"type": "array", "items": {"type": "string"}},
            "ready_claim_ids": {"type": "array", "items": {"type": "string"}},
            "launch_mode": {"enum": ["package-launcher", "balanced-agent-fanout"]},
            "launch_commands": {"type": "array", "items": {"type": "string"}},
            "refresh_claim_status_command": {"type": "string"},
            "operator_check_exit_code": {"type": "integer"},
            "claim_boundary": {"type": "string"},
        },
    }


def operator_check_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://tamandua.local/schemas/validation-product-readiness-operator-check.schema.json",
        "title": "Tamandua validation product readiness operator check",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "artifact",
            "product_ready",
            "product_release_gate",
            "automation_state",
            "can_launch_now",
            "needs_env_input",
            "required_env_count",
            "current_env_present_count",
            "current_env_missing_names",
            "missing_env_details",
            "placeholder_env_names",
            "single_env_fast_paths_ready",
            "single_env_fast_path_count",
            "full_env_bundle_ready",
            "env_bundle_validation_command",
            "post_env_bundle_balanced_agent_spawn_commands",
            "post_env_bundle_plan",
            "post_agent_status_gate",
            "handoff_artifacts",
            "manual_claims",
            "missing_set_commands",
            "launchable_claim_ids",
            "recommended_next_action_id",
            "recommended_next_action_commands",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "artifact": {"const": "validation-product-readiness-operator-check"},
            "product_ready": {"type": "boolean"},
            "product_release_gate": {"type": "object"},
            "automation_state": {
                "enum": [
                    "blocked_missing_env",
                    "runtime_evidence_blocked",
                    "single_env_fast_path_ready",
                    "full_env_bundle_ready",
                ]
            },
            "can_launch_now": {"type": "boolean"},
            "needs_env_input": {"type": "boolean"},
            "required_env_count": {"type": "integer", "minimum": 0},
            "current_env_present_count": {"type": "integer", "minimum": 0},
            "current_env_missing_names": {"type": "array", "items": {"type": "string"}},
            "missing_env_details": {"type": "array", "items": {"type": "object"}},
            "placeholder_env_names": {"type": "array", "items": {"type": "string"}},
            "single_env_fast_paths_ready": {"type": "array", "items": {"type": "object"}},
            "single_env_fast_path_count": {"type": "integer", "minimum": 0},
            "full_env_bundle_ready": {"type": "boolean"},
            "env_bundle_validation_command": {"type": "string"},
            "post_env_bundle_balanced_agent_spawn_commands": {"type": "array", "items": {"type": "string"}},
            "post_env_bundle_plan": {"type": "object"},
            "post_agent_status_gate": {"type": "object"},
            "handoff_artifacts": {"type": "object"},
            "manual_claims": {"type": "array", "items": {"type": "object"}},
            "missing_set_commands": {"type": "array", "items": {"type": "string"}},
            "launchable_claim_ids": {"type": "array", "items": {"type": "string"}},
            "recommended_next_action_id": {
                "enum": [
                    "fill-env-bundle",
                    "launch-ready-claims",
                    "launch-single-env-fast-paths",
                    "refresh-validation-authority",
                    "resolve-current-failed-claims",
                    "resolve-manual-claims",
                    "validate-env-bundle",
                ]
            },
            "recommended_next_action_commands": {"type": "array", "items": {"type": "string"}},
        },
    }


def write_outputs(summary: dict[str, Any], output_dir: Path) -> tuple[Path, Path, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "validation_product_readiness_summary.json"
    md_path = output_dir / "validation_product_readiness_summary.md"
    operator_check_path = output_dir / "validation_product_readiness_operator_check.ps1"
    operator_check_schema_path = output_dir / "validation_product_readiness_operator_check.schema.json"
    doctor_path = output_dir / "validation_product_readiness_doctor.ps1"
    doctor_schema_path = output_dir / "validation_product_readiness_doctor.schema.json"
    post_env_runner_path = output_dir / "validation_product_readiness_post_env_bundle_runner.ps1"
    post_env_runner_schema_path = output_dir / "validation_product_readiness_post_env_bundle_runner.schema.json"
    post_env_runner_contract_json_path = output_dir / "validation_product_readiness_post_env_bundle_runner.contract.json"
    post_env_runner_contract_md_path = output_dir / "validation_product_readiness_post_env_bundle_runner.contract.md"
    post_env_runner_contract_schema_path = (
        output_dir / "validation_product_readiness_post_env_bundle_runner.contract.schema.json"
    )
    release_gate_contract_json_path = output_dir / "validation_product_readiness_release_gate.contract.json"
    release_gate_contract_md_path = output_dir / "validation_product_readiness_release_gate.contract.md"
    release_gate_contract_schema_path = output_dir / "validation_product_readiness_release_gate.contract.schema.json"
    claim_status_contract_json_path = output_dir / "validation_product_readiness_claim_status_contract.json"
    claim_status_contract_md_path = output_dir / "validation_product_readiness_claim_status_contract.md"
    claim_status_contract_schema_path = output_dir / "validation_product_readiness_claim_status_contract.schema.json"
    blocked_run_classes_contract_json_path = (
        output_dir / "validation_product_readiness_blocked_run_classes.contract.json"
    )
    blocked_run_classes_contract_md_path = (
        output_dir / "validation_product_readiness_blocked_run_classes.contract.md"
    )
    blocked_run_classes_contract_schema_path = (
        output_dir / "validation_product_readiness_blocked_run_classes.contract.schema.json"
    )
    runbook_json_path = output_dir / "validation_product_readiness_runbook.json"
    runbook_md_path = output_dir / "validation_product_readiness_runbook.md"
    runbook_schema_path = output_dir / "validation_product_readiness_runbook.schema.json"
    remaining_work_json_path = output_dir / "validation_product_readiness_remaining_work.json"
    remaining_work_md_path = output_dir / "validation_product_readiness_remaining_work.md"
    remaining_work_schema_path = output_dir / "validation_product_readiness_remaining_work.schema.json"
    remaining_work_check_path = output_dir / "validation_product_readiness_remaining_work_check.ps1"
    remaining_work_check_schema_path = output_dir / "validation_product_readiness_remaining_work_check.schema.json"
    ready_now_fanout_json_path = output_dir / "validation_product_readiness_ready_now_fanout.json"
    ready_now_fanout_md_path = output_dir / "validation_product_readiness_ready_now_fanout.md"
    ready_now_fanout_schema_path = output_dir / "validation_product_readiness_ready_now_fanout.schema.json"
    ready_now_fanout_check_path = output_dir / "validation_product_readiness_ready_now_fanout_check.ps1"
    ready_now_fanout_check_schema_path = (
        output_dir / "validation_product_readiness_ready_now_fanout_check.schema.json"
    )
    manual_claim_resolution_json_path = output_dir / "validation_product_readiness_manual_claim_resolution.json"
    manual_claim_resolution_md_path = output_dir / "validation_product_readiness_manual_claim_resolution.md"
    manual_claim_resolution_schema_path = (
        output_dir / "validation_product_readiness_manual_claim_resolution.schema.json"
    )
    manual_claim_resolution_check_path = (
        output_dir / "validation_product_readiness_manual_claim_resolution_check.ps1"
    )
    manual_claim_resolution_runner_path = (
        output_dir / "validation_product_readiness_manual_claim_resolution_runner.ps1"
    )
    manual_claim_resolution_runner_schema_path = (
        output_dir / "validation_product_readiness_manual_claim_resolution_runner.schema.json"
    )
    manual_claim_resolution_check_schema_path = (
        output_dir / "validation_product_readiness_manual_claim_resolution_check.schema.json"
    )
    agent_handoff_json_path = output_dir / "validation_product_readiness_agent_handoff.json"
    agent_handoff_md_path = output_dir / "validation_product_readiness_agent_handoff.md"
    agent_handoff_schema_path = output_dir / "validation_product_readiness_agent_handoff.schema.json"
    env_request_json_path = output_dir / "validation_product_readiness_env_request.json"
    env_request_md_path = output_dir / "validation_product_readiness_env_request.md"
    env_request_schema_path = output_dir / "validation_product_readiness_env_request.schema.json"
    env_bundle_local_env_init_path = output_dir / "validation_product_readiness_env_bundle_local_env_init.ps1"
    env_bundle_local_env_init_schema_path = (
        output_dir / "validation_product_readiness_env_bundle_local_env_init.schema.json"
    )
    env_bundle_local_env_validate_path = output_dir / "validation_product_readiness_env_bundle_local_env_validate.ps1"
    env_bundle_local_env_validate_schema_path = (
        output_dir / "validation_product_readiness_env_bundle_local_env_validate.schema.json"
    )
    env_bundle_init_path = output_dir / "validation_product_readiness_env_bundle_init.ps1"
    env_bundle_init_schema_path = output_dir / "validation_product_readiness_env_bundle_init.schema.json"
    env_bundle_check_path = output_dir / "validation_product_readiness_env_bundle_check.ps1"
    env_bundle_runner_path = output_dir / "validation_product_readiness_env_bundle_runner.ps1"
    env_bundle_runner_schema_path = output_dir / "validation_product_readiness_env_bundle_runner.schema.json"
    env_bundle_runner_status_check_path = (
        output_dir / "validation_product_readiness_env_bundle_runner_status_check.ps1"
    )
    env_bundle_runner_status_check_schema_path = (
        output_dir / "validation_product_readiness_env_bundle_runner_status_check.schema.json"
    )
    env_bundle_check_schema_path = output_dir / "validation_product_readiness_env_bundle_check.schema.json"
    env_bundle_local_schema_path = output_dir / "validation_product_readiness_env_bundle.local.schema.json"
    env_bundle_template_path = output_dir / "validation_product_readiness_env_bundle.template.json"
    env_bundle_dotenv_template_path = output_dir / "validation_product_readiness_env_bundle.template.env"
    env_request = env_request_payload(summary)
    post_env_runner_contract = post_env_runner_contract_payload(summary)
    release_gate_contract = release_gate_contract_payload(summary)
    claim_status_contract = claim_status_contract_payload(summary)
    blocked_run_classes_contract = blocked_run_classes_contract_payload(summary)
    runbook = product_readiness_runbook_payload(
        summary,
        env_request,
        post_env_runner_contract,
        claim_status_contract,
        blocked_run_classes_contract,
    )
    remaining_work = remaining_work_payload(
        summary,
        release_gate_contract,
        env_request,
        claim_status_contract,
        blocked_run_classes_contract,
        runbook,
    )
    ready_now_fanout = ready_now_fanout_payload(remaining_work)
    manual_claim_resolution = manual_claim_resolution_payload(summary)
    agent_handoff = agent_handoff_manifest_payload(
        summary,
        env_request,
        post_env_runner_contract,
        release_gate_contract,
        claim_status_contract,
        blocked_run_classes_contract,
        runbook,
        remaining_work,
        ready_now_fanout,
        manual_claim_resolution,
    )
    json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    operator_check_path.write_text(render_operator_check(json_path.name), encoding="utf-8")
    doctor_path.write_text(
        render_product_readiness_doctor(
            json_path.name,
            operator_check_path.name,
            env_bundle_runner_status_check_path.name,
            remaining_work_check_path.name,
            ready_now_fanout_check_path.name,
            manual_claim_resolution_check_path.name,
            manual_claim_resolution_runner_path.name,
        ),
        encoding="utf-8",
    )
    doctor_schema_path.write_text(
        json.dumps(product_readiness_doctor_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    post_env_runner_path.write_text(
        render_post_env_bundle_runner(json_path.name, operator_check_path.name),
        encoding="utf-8",
    )
    post_env_runner_schema_path.write_text(
        json.dumps(post_env_bundle_runner_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    post_env_runner_contract_json_path.write_text(
        json.dumps(post_env_runner_contract, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    post_env_runner_contract_md_path.write_text(
        render_post_env_runner_contract_markdown(post_env_runner_contract),
        encoding="utf-8",
    )
    post_env_runner_contract_schema_path.write_text(
        json.dumps(post_env_runner_contract_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    release_gate_contract_json_path.write_text(
        json.dumps(release_gate_contract, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    release_gate_contract_md_path.write_text(
        render_release_gate_contract_markdown(release_gate_contract),
        encoding="utf-8",
    )
    release_gate_contract_schema_path.write_text(
        json.dumps(release_gate_contract_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    claim_status_contract_json_path.write_text(
        json.dumps(claim_status_contract, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    claim_status_contract_md_path.write_text(
        render_claim_status_contract_markdown(claim_status_contract),
        encoding="utf-8",
    )
    claim_status_contract_schema_path.write_text(
        json.dumps(claim_status_contract_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    blocked_run_classes_contract_json_path.write_text(
        json.dumps(blocked_run_classes_contract, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    blocked_run_classes_contract_md_path.write_text(
        render_blocked_run_classes_contract_markdown(blocked_run_classes_contract),
        encoding="utf-8",
    )
    blocked_run_classes_contract_schema_path.write_text(
        json.dumps(blocked_run_classes_contract_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    runbook_json_path.write_text(json.dumps(runbook, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    runbook_md_path.write_text(render_product_readiness_runbook_markdown(runbook), encoding="utf-8")
    runbook_schema_path.write_text(
        json.dumps(product_readiness_runbook_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    remaining_work_json_path.write_text(
        json.dumps(remaining_work, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    remaining_work_md_path.write_text(render_remaining_work_markdown(remaining_work), encoding="utf-8")
    remaining_work_schema_path.write_text(
        json.dumps(remaining_work_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    remaining_work_check_path.write_text(render_remaining_work_check(remaining_work_json_path.name), encoding="utf-8")
    remaining_work_check_schema_path.write_text(
        json.dumps(remaining_work_check_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    ready_now_fanout_json_path.write_text(
        json.dumps(ready_now_fanout, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    ready_now_fanout_md_path.write_text(render_ready_now_fanout_markdown(ready_now_fanout), encoding="utf-8")
    ready_now_fanout_schema_path.write_text(
        json.dumps(ready_now_fanout_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    ready_now_fanout_check_path.write_text(
        render_ready_now_fanout_check(ready_now_fanout_json_path.name),
        encoding="utf-8",
    )
    ready_now_fanout_check_schema_path.write_text(
        json.dumps(ready_now_fanout_check_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manual_claim_resolution_json_path.write_text(
        json.dumps(manual_claim_resolution, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manual_claim_resolution_md_path.write_text(
        render_manual_claim_resolution_markdown(manual_claim_resolution),
        encoding="utf-8",
    )
    manual_claim_resolution_schema_path.write_text(
        json.dumps(manual_claim_resolution_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manual_claim_resolution_check_path.write_text(
        render_manual_claim_resolution_check(manual_claim_resolution_json_path.name),
        encoding="utf-8",
    )
    manual_claim_resolution_runner_path.write_text(
        render_manual_claim_resolution_runner(manual_claim_resolution_json_path.name),
        encoding="utf-8",
    )
    manual_claim_resolution_runner_schema_path.write_text(
        json.dumps(manual_claim_resolution_runner_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manual_claim_resolution_check_schema_path.write_text(
        json.dumps(manual_claim_resolution_check_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    agent_handoff_json_path.write_text(json.dumps(agent_handoff, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    agent_handoff_md_path.write_text(render_agent_handoff_manifest_markdown(agent_handoff), encoding="utf-8")
    agent_handoff_schema_path.write_text(
        json.dumps(agent_handoff_manifest_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    operator_check_schema_path.write_text(
        json.dumps(operator_check_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    env_request_json_path.write_text(json.dumps(env_request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    env_request_md_path.write_text(render_env_request_markdown(env_request), encoding="utf-8")
    env_request_schema_path.write_text(
        json.dumps(env_request_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    env_bundle_local_env_init_path.write_text(
        render_env_bundle_local_env_init(
            env_bundle_dotenv_template_path.name,
            env_bundle_init_name=env_bundle_init_path.name,
        ),
        encoding="utf-8",
    )
    env_bundle_local_env_init_schema_path.write_text(
        json.dumps(env_bundle_local_env_init_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    env_bundle_local_env_validate_path.write_text(
        render_env_bundle_local_env_validate(
            env_bundle_dotenv_template_path.name,
            env_bundle_init_name=env_bundle_init_path.name,
            env_bundle_check_name=env_bundle_check_path.name,
            env_bundle_runner_name=env_bundle_runner_path.name,
            doctor_name=doctor_path.name,
        ),
        encoding="utf-8",
    )
    env_bundle_local_env_validate_schema_path.write_text(
        json.dumps(env_bundle_local_env_validate_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    env_bundle_init_path.write_text(
        render_env_bundle_init(
            env_bundle_template_path.name,
            env_bundle_check_name=env_bundle_check_path.name,
        ),
        encoding="utf-8",
    )
    env_bundle_init_schema_path.write_text(
        json.dumps(env_bundle_init_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    env_bundle_check_path.write_text(
        render_env_bundle_check(env_request_json_path.name),
        encoding="utf-8",
    )
    env_bundle_runner_path.write_text(
        render_env_bundle_runner(
            env_bundle_check_path.name,
            env_bundle_init_path.name,
            post_env_runner_name=post_env_runner_path.name,
        ),
        encoding="utf-8",
    )
    env_bundle_check_schema_path.write_text(
        json.dumps(env_bundle_check_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    env_bundle_runner_schema_path.write_text(
        json.dumps(env_bundle_runner_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    env_bundle_runner_status_check_path.write_text(
        render_env_bundle_runner_status_check(
            env_bundle_runner_path.name,
            env_bundle_runner_schema_path.name,
        ),
        encoding="utf-8",
    )
    env_bundle_runner_status_check_schema_path.write_text(
        json.dumps(env_bundle_runner_status_check_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    env_bundle_local_schema_path.write_text(
        json.dumps(env_bundle_local_schema(env_request), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    env_bundle_template_path.write_text(
        json.dumps(env_bundle_template_payload(env_request), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    env_bundle_dotenv_template_path.write_text(
        render_env_bundle_dotenv_template(env_request),
        encoding="utf-8",
    )
    return json_path, md_path, operator_check_path, operator_check_schema_path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scorecard-json", type=Path, default=SCORECARD_JSON)
    parser.add_argument("--output-dir", type=Path, default=GENERATED_DIR)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = build_summary(args.scorecard_json)
    json_path, md_path, operator_check_path, operator_check_schema_path = write_outputs(summary, args.output_dir)
    print(
        f"product_ready={str(summary['product_ready']).lower()} "
        f"json={json_path} markdown={md_path} operator_check={operator_check_path} "
        f"doctor={args.output_dir / 'validation_product_readiness_doctor.ps1'} "
        f"doctor_schema={args.output_dir / 'validation_product_readiness_doctor.schema.json'} "
        f"post_env_runner={args.output_dir / 'validation_product_readiness_post_env_bundle_runner.ps1'} "
        f"post_env_runner_schema={args.output_dir / 'validation_product_readiness_post_env_bundle_runner.schema.json'} "
        f"post_env_runner_contract={args.output_dir / 'validation_product_readiness_post_env_bundle_runner.contract.json'} "
        f"release_gate_contract={args.output_dir / 'validation_product_readiness_release_gate.contract.json'} "
        f"claim_status_contract={args.output_dir / 'validation_product_readiness_claim_status_contract.json'} "
        f"blocked_run_classes_contract={args.output_dir / 'validation_product_readiness_blocked_run_classes.contract.json'} "
        f"runbook={args.output_dir / 'validation_product_readiness_runbook.json'} "
        f"remaining_work={args.output_dir / 'validation_product_readiness_remaining_work.json'} "
        f"remaining_work_check={args.output_dir / 'validation_product_readiness_remaining_work_check.ps1'} "
        f"ready_now_fanout={args.output_dir / 'validation_product_readiness_ready_now_fanout.json'} "
        f"ready_now_fanout_check={args.output_dir / 'validation_product_readiness_ready_now_fanout_check.ps1'} "
        f"manual_claim_resolution={args.output_dir / 'validation_product_readiness_manual_claim_resolution.json'} "
        f"manual_claim_resolution_check={args.output_dir / 'validation_product_readiness_manual_claim_resolution_check.ps1'} "
        f"manual_claim_resolution_runner={args.output_dir / 'validation_product_readiness_manual_claim_resolution_runner.ps1'} "
        f"manual_claim_resolution_runner_schema={args.output_dir / 'validation_product_readiness_manual_claim_resolution_runner.schema.json'} "
        f"agent_handoff={args.output_dir / 'validation_product_readiness_agent_handoff.json'} "
        f"env_bundle_local_env_init={args.output_dir / 'validation_product_readiness_env_bundle_local_env_init.ps1'} "
        f"env_bundle_local_env_validate={args.output_dir / 'validation_product_readiness_env_bundle_local_env_validate.ps1'} "
        f"contract_schemas={args.output_dir / 'validation_product_readiness_post_env_bundle_runner.contract.schema.json'},"
        f"{args.output_dir / 'validation_product_readiness_release_gate.contract.schema.json'} "
        f"operator_check_schema={operator_check_schema_path} "
        f"env_request_json={args.output_dir / 'validation_product_readiness_env_request.json'} "
        f"env_request_markdown={args.output_dir / 'validation_product_readiness_env_request.md'} "
        f"env_request_schema={args.output_dir / 'validation_product_readiness_env_request.schema.json'} "
        f"env_bundle_init={args.output_dir / 'validation_product_readiness_env_bundle_init.ps1'} "
        f"env_bundle_init_schema={args.output_dir / 'validation_product_readiness_env_bundle_init.schema.json'} "
        f"env_bundle_check={args.output_dir / 'validation_product_readiness_env_bundle_check.ps1'} "
        f"env_bundle_runner={args.output_dir / 'validation_product_readiness_env_bundle_runner.ps1'} "
        f"env_bundle_runner_schema={args.output_dir / 'validation_product_readiness_env_bundle_runner.schema.json'} "
        f"env_bundle_runner_status_check={args.output_dir / 'validation_product_readiness_env_bundle_runner_status_check.ps1'} "
        f"env_bundle_runner_status_check_schema={args.output_dir / 'validation_product_readiness_env_bundle_runner_status_check.schema.json'} "
        f"env_bundle_check_schema={args.output_dir / 'validation_product_readiness_env_bundle_check.schema.json'} "
        f"env_bundle_local_schema={args.output_dir / 'validation_product_readiness_env_bundle.local.schema.json'} "
        f"env_bundle_template={args.output_dir / 'validation_product_readiness_env_bundle.template.json'} "
        f"env_bundle_dotenv_template={args.output_dir / 'validation_product_readiness_env_bundle.template.env'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
