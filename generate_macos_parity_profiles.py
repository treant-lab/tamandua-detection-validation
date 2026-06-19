#!/usr/bin/env python3
"""Generate macOS parity validation profiles.

These profiles mirror the Windows evidence lanes without overstating maturity:
they are executable/safe where possible, and release/capability lanes stay
report-only until a signed/notarized macOS release and server-backed lab agent
exist.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
PROFILE_DIR = ROOT / "tools" / "detection_validation" / "profiles"

MACOS_FIELDS = ["agent_id", "hostname", "process_name", "command_line", "user"]
MACOS_LIVE_RESPONSE_FIELDS = ["agent_id", "hostname", "command", "session_id"]


def command_test(
    test_id: str,
    name: str,
    command: str,
    tags: list[str],
    *,
    expected_telemetry: list[str] | None = None,
    optional_telemetry: list[str] | None = None,
    expected_fields: list[str] | None = None,
    expected_detections: list[str] | None = None,
    expected_alerts: list[str] | None = None,
    risk: str = "low",
    validation_category: str | None = None,
    claim_boundary: str | None = None,
) -> dict[str, Any]:
    test: dict[str, Any] = {
        "id": test_id,
        "name": name,
        "executor": "command",
        "fallback_command": command,
        "expected_telemetry": expected_telemetry or ["process_create"],
        "expected_detections": expected_detections or [],
        "expected_alerts": expected_alerts or [],
        "expected_fields": expected_fields or MACOS_FIELDS,
        "tags": tags,
        "risk": risk,
    }
    if optional_telemetry:
        test["optional_telemetry"] = optional_telemetry
    if validation_category:
        test["validation_category"] = validation_category
    if claim_boundary:
        test["claim_boundary"] = claim_boundary
    return test


def enterprise_eval_profile() -> dict[str, Any]:
    tests = [
        command_test(
            "eval-macos-T1033-user-discovery",
            "User Discovery",
            "sh -lc 'whoami; id; groups'",
            ["enterprise-eval-safe", "tactic:discovery", "mitre:T1033"],
        ),
        command_test(
            "eval-macos-T1082-system-info",
            "System Information Discovery",
            "sh -lc 'sw_vers 2>/dev/null || uname -a; sysctl kern.ostype kern.osrelease hw.model 2>/dev/null || true'",
            ["enterprise-eval-safe", "tactic:discovery", "mitre:T1082"],
        ),
        command_test(
            "eval-macos-T1057-process-discovery",
            "Process Discovery",
            "sh -lc 'ps -axo pid,ppid,user,comm | head -n 25'",
            ["enterprise-eval-safe", "tactic:discovery", "mitre:T1057"],
        ),
        command_test(
            "eval-macos-T1016-network-config",
            "Network Configuration Discovery",
            "sh -lc 'ifconfig -a; scutil --dns 2>/dev/null | head -n 40 || true'",
            ["enterprise-eval-safe", "tactic:discovery", "mitre:T1016"],
            optional_telemetry=["dns_query", "network_connect"],
        ),
        command_test(
            "eval-macos-T1049-network-connections",
            "Network Connections Discovery",
            "sh -lc 'lsof -n -P -iTCP -iUDP 2>/dev/null | head -n 25 || netstat -an | head -n 25'",
            ["enterprise-eval-safe", "tactic:discovery", "mitre:T1049"],
            optional_telemetry=["network_connect"],
        ),
        command_test(
            "eval-macos-T1083-file-directory-discovery",
            "File and Directory Discovery",
            "sh -lc 'find /Applications /Library/LaunchAgents /Library/LaunchDaemons -maxdepth 1 2>/dev/null | head -n 30'",
            ["enterprise-eval-safe", "tactic:discovery", "mitre:T1083"],
        ),
        command_test(
            "eval-macos-T1543-launchdaemon-discovery",
            "LaunchDaemon Discovery",
            "sh -lc 'launchctl list 2>/dev/null | head -n 25; ls /Library/LaunchDaemons 2>/dev/null | head -n 20'",
            ["enterprise-eval-safe", "tactic:persistence", "mitre:T1543.004"],
        ),
        command_test(
            "eval-macos-T1547-plist-safe",
            "Temporary Plist Creation Safe",
            "sh -lc 'd=$(mktemp -d /tmp/tamandua-plist.XXXXXX); printf \"<?xml version=\\\"1.0\\\"?><plist version=\\\"1.0\\\"><dict><key>Label</key><string>com.tamandua.safe</string></dict></plist>\" > \"$d/com.tamandua.safe.plist\"; plutil -lint \"$d/com.tamandua.safe.plist\" >/dev/null 2>&1 || true; rm -rf \"$d\"'",
            ["enterprise-eval-safe", "tactic:persistence", "mitre:T1547.011"],
            optional_telemetry=["file_create", "file_delete"],
        ),
        command_test(
            "eval-macos-T1036-masquerade-safe",
            "Masquerade Copy Safe",
            "sh -lc 'd=$(mktemp -d /tmp/tamandua-masq.XXXXXX); cp /bin/echo \"$d/com.apple.safeupdate\"; \"$d/com.apple.safeupdate\" tamandua >/dev/null; rm -rf \"$d\"'",
            ["enterprise-eval-safe", "tactic:defense-evasion", "mitre:T1036"],
            optional_telemetry=["file_create", "file_delete"],
            expected_detections=["masquerade"],
            expected_alerts=["masquerade"],
        ),
        command_test(
            "eval-macos-T1564-hidden-file-safe",
            "Hidden File Safe",
            "sh -lc 'p=$(mktemp /tmp/tamandua-visible.XXXXXX); mv \"$p\" \"$(dirname \"$p\")/.tamandua-hidden\"; ls -la \"$(dirname \"$p\")/.tamandua-hidden\" >/dev/null; rm -f \"$(dirname \"$p\")/.tamandua-hidden\"'",
            ["enterprise-eval-safe", "tactic:defense-evasion", "mitre:T1564.001"],
            optional_telemetry=["file_create", "file_delete"],
        ),
        command_test(
            "eval-macos-T1552-private-key-discovery-safe",
            "Private Key Discovery Safe",
            "sh -lc 'find \"$HOME\" -maxdepth 3 \\( -name \"*.pem\" -o -name \"id_rsa\" -o -name \"id_ed25519\" \\) 2>/dev/null | head -n 5 || true'",
            ["enterprise-eval-safe", "tactic:credential-access", "mitre:T1552.004"],
        ),
        command_test(
            "eval-macos-T1071-web-protocols",
            "Web Protocols",
            "sh -lc 'curl -I https://example.com/ >/dev/null 2>&1 || true'",
            ["enterprise-eval-safe", "tactic:command-and-control", "mitre:T1071.001"],
            optional_telemetry=["dns_query", "network_connect"],
        ),
        command_test(
            "eval-macos-T1560-archive-safe",
            "Archive via Utility Safe",
            "sh -lc 'd=$(mktemp -d /tmp/tamandua-archive.XXXXXX); echo sample > \"$d/sample.txt\"; tar -cf \"$d/sample.tar\" -C \"$d\" sample.txt; rm -rf \"$d\"'",
            ["enterprise-eval-safe", "tactic:collection", "mitre:T1560.001"],
            optional_telemetry=["file_create", "file_delete"],
        ),
        command_test(
            "eval-macos-T1486-ransomware-canary-safe",
            "Ransomware Canary Safe Write Pattern",
            "sh -lc 'd=$(mktemp -d /tmp/tamandua-impact.XXXXXX); for i in 1 2 3; do echo before > \"$d/file$i.txt\"; echo after >> \"$d/file$i.txt\"; done; rm -rf \"$d\"'",
            ["enterprise-eval-safe", "tactic:impact", "mitre:T1486"],
            optional_telemetry=["file_create", "file_modify", "file_delete"],
        ),
    ]
    return {
        "schema_version": 1,
        "profile_id": "macos-enterprise-eval-safe-v1",
        "name": "macOS Enterprise Evaluation Safe v1",
        "description": "Safe macOS enterprise-style endpoint evaluation profile: broad tactic coverage, deterministic fallback commands, low-noise guardrails, and clear boundaries around EndpointSecurity/server-backed proof.",
        "platform": "macos",
        "default_observation_seconds": 90,
        "benchmark_lane": "enterprise-eval",
        "quality_bar": {
            "purpose": "macos_enterprise_eval_safe",
            "requires_persisted_events": True,
            "max_unknown_source_events": 0,
            "max_unexpected_high_critical": 0,
            "requires_endpoint_security_health": True,
        },
        "coverage_model": {
            "visibility": "Expected telemetry must be persisted with source attribution.",
            "analytics": "Expected detections/alerts are required only where behavior is unambiguously suspicious.",
            "storyline": "Process, parent, command line, file, DNS, network, launchd and TCC/XPC fields are required when relevant.",
            "noise": "Low-risk tests must not emit unexpected high/critical events.",
        },
        "claim_boundary": "macOS deterministic enterprise evaluation only. Promotion requires server-backed agent evidence, EndpointSecurity and System Extension install entitlement proof, and backend ingestion.",
        "tests": tests,
    }


def response_profile() -> dict[str, Any]:
    response_boundary = "non-destructive macOS response/audit context only"
    tests = [
        command_test(
            "response-macos-shell-audit",
            "Response Shell Audit",
            "sh -lc 'echo tamandua-response-shell; id; pwd'",
            ["response-validation", "tactic:execution", "mitre:T1059.004"],
            expected_telemetry=["live_response_command"],
            optional_telemetry=["process_create"],
            expected_fields=MACOS_LIVE_RESPONSE_FIELDS,
            validation_category="response-audit",
            claim_boundary=response_boundary,
        ),
        command_test(
            "response-macos-launchd-inventory",
            "Response Launchd Inventory",
            "sh -lc 'launchctl list 2>/dev/null | head -n 20; ls /Library/LaunchDaemons 2>/dev/null | head -n 20'",
            ["response-validation", "tactic:persistence", "mitre:T1543.004"],
            expected_telemetry=["live_response_command"],
            optional_telemetry=["process_create"],
            expected_fields=MACOS_LIVE_RESPONSE_FIELDS,
            validation_category="response-audit",
            claim_boundary=response_boundary,
        ),
        command_test(
            "response-macos-network-inventory",
            "Response Network Inventory",
            "sh -lc 'lsof -n -P -iTCP -iUDP 2>/dev/null | head -n 25 || netstat -an | head -n 25'",
            ["response-validation", "tactic:discovery", "mitre:T1049"],
            expected_telemetry=["live_response_command"],
            optional_telemetry=["network_connect"],
            expected_fields=MACOS_LIVE_RESPONSE_FIELDS,
            validation_category="response-audit",
            claim_boundary=response_boundary,
        ),
        command_test(
            "response-macos-process-signature",
            "Response Process Signature Context",
            "sh -lc 'codesign -dv --verbose=2 /bin/ls >/dev/null 2>&1 || true; ps -axo pid,comm | head -n 10'",
            ["response-validation", "tactic:defense-evasion", "mitre:T1553.001"],
            expected_telemetry=["live_response_command"],
            optional_telemetry=["process_create"],
            expected_fields=MACOS_LIVE_RESPONSE_FIELDS,
            validation_category="response-audit",
            claim_boundary=response_boundary,
        ),
        command_test(
            "response-macos-artifact-collection-safe",
            "Response Artifact Collection Safe",
            "sh -lc 'd=$(mktemp -d /tmp/tamandua-response.XXXXXX); echo artifact > \"$d/artifact.txt\"; shasum -a 256 \"$d/artifact.txt\"; rm -rf \"$d\"'",
            ["response-validation", "dfir", "artifact", "mitre:T1005"],
            expected_telemetry=["live_response_command"],
            optional_telemetry=["file_create", "file_delete"],
            expected_fields=MACOS_LIVE_RESPONSE_FIELDS,
            validation_category="response-audit",
            claim_boundary=response_boundary,
        ),
    ]
    return {
        "schema_version": 1,
        "profile_id": "macos-response-validation-safe-v1",
        "name": "macOS Response Validation Safe v1",
        "description": "Safe response-validation lane for macOS analyst-facing outcomes, live-response audit context, and non-destructive inventory/artifact workflows.",
        "platform": "macos",
        "default_observation_seconds": 90,
        "benchmark_lane": "enterprise-eval",
        "claim_boundary": "Selected non-destructive macOS response/audit validation only. This does not prove containment, kill-process, deletion, or broad response parity until server-backed transcript evidence exists.",
        "expected_gap_categories": ["collector", "normalization", "detector", "alert-quality", "response-audit", "runner", "infrastructure", "noise", "claim-boundary"],
        "quality_bar": {
            "purpose": "macos_response_validation_safe",
            "requires_persisted_events": True,
            "max_unknown_source_events": 0,
            "max_unexpected_high_critical": 0,
        },
        "response_contract": {
            "minimum_alert_context": ["event_ids", "contributing_events", "mitre_tactics", "mitre_techniques"],
            "required_response_questions": ["what executed", "who executed it", "where it executed", "why it alerted", "which evidence supports the alert"],
            "write_scope": ["/tmp/tamandua-response-*"],
        },
        "tests": tests,
    }


def benign_noise_profile() -> dict[str, Any]:
    tests = [
        command_test("benign-macos-curl-head-example", "Benign Curl HEAD Example", "sh -lc 'curl -I https://example.com/ >/dev/null 2>&1 || true'", ["benign", "noise", "curl", "network", "mitre:T1071.001"], optional_telemetry=["dns_query", "network_connect"]),
        command_test("benign-macos-curl-download-example", "Benign Curl Download Example", "sh -lc 'p=$(mktemp /tmp/tamandua-benign-download.XXXXXX); curl -L https://example.com/ -o \"$p\" >/dev/null 2>&1 || echo benign > \"$p\"; rm -f \"$p\"'", ["benign", "noise", "curl", "download", "mitre:T1105"], optional_telemetry=["dns_query", "network_connect", "file_create", "file_delete"]),
        command_test("benign-macos-launchctl-query", "Benign Launchctl Query", "sh -lc 'launchctl list 2>/dev/null | head -n 20 || true'", ["benign", "noise", "launchd"], optional_telemetry=[]),
        command_test("benign-macos-softwareupdate-list", "Benign Softwareupdate List", "sh -lc 'softwareupdate --list --no-scan >/dev/null 2>&1 || true'", ["benign", "noise", "softwareupdate", "patch"], optional_telemetry=[]),
        command_test("benign-macos-dev-tools-discovery", "Benign Developer Tools Discovery", "sh -lc 'xcode-select -p >/dev/null 2>&1 || true; clang --version >/dev/null 2>&1 || true; git --version >/dev/null 2>&1 || true'", ["benign", "noise", "developer-tools"], optional_telemetry=[]),
        command_test("benign-macos-tcc-xpc-context", "Benign TCC XPC Context", "sh -lc 'ls ~/Library/Application\\ Support/com.apple.TCC 2>/dev/null || true; ps -axo comm | grep -E \"tccd|cfprefsd\" >/dev/null 2>&1 || true'", ["benign", "noise", "tcc", "xpc"], optional_telemetry=[]),
        command_test("benign-macos-browser-cache-touch", "Benign Browser Cache Touch", "sh -lc 'for d in \"$HOME/Library/Application Support/Google/Chrome\" \"$HOME/Library/Safari\"; do test -d \"$d\" && find \"$d\" -maxdepth 1 2>/dev/null | head -n 3 >/dev/null; done; true'", ["benign", "noise", "browser"], optional_telemetry=[]),
    ]
    return {
        "schema_version": 1,
        "profile_id": "macos-benign-noise-broad-v1",
        "name": "macOS Benign Noise Broad v1",
        "description": "Broader benign workload regression pack for macOS update, browser, developer-tool, launchd, TCC/XPC, and network false-positive controls.",
        "platform": "macos",
        "default_observation_seconds": 75,
        "benchmark_lane": "enterprise-eval",
        "quality_bar": {
            "purpose": "macos_benign_noise_broad",
            "requires_persisted_events": True,
            "max_unknown_source_events": 0,
            "max_unexpected_high_critical": 0,
        },
        "claim_boundary": "Benign/noise regression only. Passing this profile supports false-positive calibration claims, not attack detection coverage claims.",
        "tests": tests,
    }


def release_readiness_profile() -> dict[str, Any]:
    tests = [
        command_test("release-macos-launchdaemon-status-report-only", "LaunchDaemon Status Report Only", "sh -lc 'launchctl print system/com.treant.tamandua 2>/dev/null || launchctl list | grep -i tamandua || true'", ["release-readiness", "launchdaemon", "report-only", "macos"], expected_telemetry=["process_create"]),
        command_test("release-macos-binary-hash-metadata-report-only", "Binary Hash Metadata Report Only", "sh -lc 'for f in /usr/local/bin/tamandua-agent /usr/local/bin/tamandua-watchdog /Applications/Tamandua.app/Contents/MacOS/*; do test -f \"$f\" && shasum -a 256 \"$f\" && codesign -dv \"$f\" >/dev/null 2>&1 || true; done'", ["release-readiness", "binary-metadata", "hash", "signature", "report-only", "macos"], expected_telemetry=["process_create"]),
        command_test("release-macos-plist-metadata-report-only", "LaunchDaemon Plist Metadata Report Only", "sh -lc 'for f in /Library/LaunchDaemons/*tamandua*.plist; do test -f \"$f\" && plutil -lint \"$f\" && ls -l \"$f\"; done; true'", ["release-readiness", "plist", "launchdaemon", "report-only", "macos"], expected_telemetry=["process_create"]),
        command_test("release-macos-manifest-sbom-compatibility-report-only", "Manifest SBOM Compatibility Report Only", "sh -lc 'printf \"manifest=%s\\nsbom=%s\\ncompat=%s\\n\" \"$TAMANDUA_RELEASE_MANIFEST\" \"$TAMANDUA_RELEASE_SBOM\" \"$TAMANDUA_RELEASE_COMPATIBILITY_MATRIX\"; test -n \"$TAMANDUA_RELEASE_MANIFEST\" && test -f \"$TAMANDUA_RELEASE_MANIFEST\" || true'", ["release-readiness", "manifest", "sbom", "compatibility", "report-only", "macos"], expected_telemetry=["process_create"]),
        command_test("release-macos-rollback-uninstall-plan-not-executed", "Rollback Uninstall Plan Not Executed", "sh -lc 'printf \"rollback=planned_not_executed\\nuninstall=planned_not_executed\\nunsafe_actions_blocked=launchctl_bootout,pkgutil_forget,rm_rf_app\\n\"'", ["release-readiness", "rollback", "uninstall", "planned-not-executed", "report-only", "macos"], expected_telemetry=["process_create"]),
    ]
    return {
        "schema_version": 1,
        "profile_id": "macos-release-readiness-dry-run",
        "name": "macOS Release Readiness Dry Run",
        "description": "Report-only macOS release/readiness lane for LaunchDaemon, binary signature/hash, plist, manifest/SBOM, rollback, and uninstall planning.",
        "platform": "macos",
        "default_observation_seconds": 0,
        "benchmark_lane": "release-readiness",
        "quality_bar": {"purpose": "macos_release_readiness_dry_run", "requires_persisted_events": False, "max_unknown_source_events": 0, "max_unexpected_high_critical": 0},
        "release_contract": {
            "evidence_scope": ["LaunchDaemon status report-only", "binary path, version, signature and hash metadata", "plist lint and ownership metadata", "release manifest, SBOM and compatibility matrix presence", "rollback and uninstall command surfaces recorded as planned/not executed"],
            "promotion_requires": ["signed/notarized pkg or app artifact evidence", "generated SBOM attached to the release pack", "successful install/update/rollback/uninstall execution on a clean macOS host", "explicit separation from lab-only or unsigned builds"],
        },
        "claim_boundary": "Dry-run release/readiness contract only. Passing this profile does not prove notarization, installer success, update success, rollback success, clean uninstall, EndpointSecurity/System Extension coverage, or server-backed parity.",
        "tests": tests,
    }


def reliability_profile() -> dict[str, Any]:
    tests = [
        command_test("reliability-macos-process-health-report-only", "Process Health Report Only", "sh -lc 'ps -axo pid,ppid,stat,comm | grep -i tamandua || true'", ["release-reliability", "process-health", "report-only", "macos"], expected_telemetry=["process_create"]),
        command_test("reliability-macos-log-tail-report-only", "Agent Log Tail Report Only", "sh -lc 'log show --style compact --last 5m --predicate \"process CONTAINS[c] \\\"tamandua\\\"\" 2>/dev/null | tail -n 50 || true'", ["release-reliability", "logs", "report-only", "macos"], expected_telemetry=["process_create"]),
        command_test("reliability-macos-resource-snapshot-report-only", "Resource Snapshot Report Only", "sh -lc 'vm_stat | head; top -l 1 -stats pid,cpu,mem,command 2>/dev/null | head -n 20 || true'", ["release-reliability", "resources", "report-only", "macos"], expected_telemetry=["process_create"]),
        command_test("reliability-macos-reconnect-prereq-report-only", "Reconnect Prereq Report Only", "sh -lc 'scutil --dns 2>/dev/null | head -n 20; nc -z agents.tamandua.treantlab.org 8443 >/dev/null 2>&1 || true'", ["release-reliability", "reconnect", "network", "report-only", "macos"], expected_telemetry=["process_create"], optional_telemetry=["dns_query", "network_connect"]),
    ]
    return {
        "schema_version": 1,
        "profile_id": "macos-release-reliability-dry-run",
        "name": "macOS Release Reliability Dry Run",
        "description": "Report-only macOS release reliability lane for process health, logs, resource snapshot, and reconnect prerequisites.",
        "platform": "macos",
        "default_observation_seconds": 0,
        "benchmark_lane": "release-readiness",
        "quality_bar": {"purpose": "macos_release_reliability_dry_run", "requires_persisted_events": False, "max_unknown_source_events": 0, "max_unexpected_high_critical": 0},
        "claim_boundary": "Dry-run reliability contract only. Promotion requires repeated server-backed restart/reconnect/upgrade/rollback runs.",
        "tests": tests,
    }


def capabilities_profile() -> dict[str, Any]:
    tests = [
        command_test("capability-macos-endpoint-security-sdk", "EndpointSecurity SDK Presence", "sh -lc 'xcrun --show-sdk-path 2>/dev/null | xargs -I{} test -e {}/System/Library/Frameworks/EndpointSecurity.framework && echo endpointsecurity=present || echo endpointsecurity=missing'", ["platform-capabilities", "endpointsecurity", "macos"], expected_telemetry=["process_create"]),
        command_test("capability-macos-tcc-full-disk-access-prereq", "TCC Full Disk Access Prereq", "sh -lc 'ls \"$HOME/Library/Application Support/com.apple.TCC\" >/dev/null 2>&1 && echo tcc_user_db_visible || true; test -r /Library/Application\\ Support/com.apple.TCC/TCC.db && echo tcc_system_db_readable || true'", ["platform-capabilities", "tcc", "macos"], expected_telemetry=["process_create"]),
        command_test("capability-macos-pfctl-prereq", "pfctl Prereq", "sh -lc 'pfctl -s info 2>/dev/null | head -n 5 || true; id -u'", ["platform-capabilities", "pfctl", "isolation", "macos"], expected_telemetry=["process_create"]),
        command_test("capability-macos-launchdaemon-prereq", "LaunchDaemon Prereq", "sh -lc 'test -d /Library/LaunchDaemons && ls -ld /Library/LaunchDaemons; launchctl list >/dev/null 2>&1 || true'", ["platform-capabilities", "launchdaemon", "macos"], expected_telemetry=["process_create"]),
        command_test("capability-macos-browser-extension-prereq", "Browser Extension Prereq", "sh -lc 'for d in \"$HOME/Library/Application Support/Google/Chrome\" \"$HOME/Library/Application Support/BraveSoftware/Brave-Browser\" \"$HOME/Library/Safari\"; do test -d \"$d\" && echo browser_dir=$d; done; true'", ["platform-capabilities", "browser", "macos"], expected_telemetry=["process_create"]),
    ]
    return {
        "schema_version": 1,
        "profile_id": "macos-platform-capabilities-dry-run",
        "name": "macOS Platform Capabilities Dry Run",
        "description": "Report-only macOS capability gate for EndpointSecurity SDK, TCC, pfctl, LaunchDaemon, and browser integration prerequisites.",
        "platform": "macos",
        "default_observation_seconds": 0,
        "benchmark_lane": "release-readiness",
        "quality_bar": {"purpose": "macos_platform_capabilities_dry_run", "requires_persisted_events": False, "max_unknown_source_events": 0, "max_unexpected_high_critical": 0},
        "claim_boundary": "Capability reporting only. Passing this profile does not prove entitlements, user approvals, server ingestion, or production installation.",
        "tests": tests,
    }


def profiles() -> list[dict[str, Any]]:
    return [
        enterprise_eval_profile(),
        response_profile(),
        benign_noise_profile(),
        release_readiness_profile(),
        reliability_profile(),
        capabilities_profile(),
    ]


def main() -> int:
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    for profile in profiles():
        path = PROFILE_DIR / f"{profile['profile_id'].replace('-', '_')}.json"
        path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)} tests={len(profile['tests'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
