#!/usr/bin/env python3
"""Static guard for direct Response.Executor call sites.

This guard scans local server source for direct dependencies on
`TamanduaServer.Response.Executor`. It is a static migration guard only; it
does not enforce runtime behavior or prove endpoint response execution safety.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable


try:
    from root_resolver import ROOT
except ImportError:
    ROOT = Path(__file__).resolve().parents[3]


DEFAULT_SCAN_ROOT = ROOT / "apps" / "tamandua_server" / "lib"
ALLOWLIST_DOC = ROOT / "docs" / "operations" / "response-executor-migration-inventory.md"

DOCUMENTED_ALLOWLIST = {
    "apps/tamandua_server/lib/tamandua_server/agentic/agent_runtime.ex",
    "apps/tamandua_server/lib/tamandua_server/agentic/orchestrator.ex",
    "apps/tamandua_server/lib/tamandua_server/agents/registry.ex",
    "apps/tamandua_server/lib/tamandua_server/ai/cost_governor.ex",
    "apps/tamandua_server/lib/tamandua_server/ai_security/agentic_analyst.ex",
    "apps/tamandua_server/lib/tamandua_server/ai_security/predictive_shield.ex",
    "apps/tamandua_server/lib/tamandua_server/automation/hyperautomation.ex",
    "apps/tamandua_server/lib/tamandua_server/deception/breadcrumb_monitor.ex",
    "apps/tamandua_server/lib/tamandua_server/detection/engine_worker.ex",
    "apps/tamandua_server/lib/tamandua_server/integrations/bot_commands.ex",
    "apps/tamandua_server/lib/tamandua_server/integrations/mcp_server.ex",
    "apps/tamandua_server/lib/tamandua_server/playbooks/dag_engine.ex",
    "apps/tamandua_server/lib/tamandua_server/playbooks/executor.ex",
    "apps/tamandua_server/lib/tamandua_server/quarantine/model_quarantine_handler.ex",
    "apps/tamandua_server/lib/tamandua_server/remediation/executor.ex",
    "apps/tamandua_server/lib/tamandua_server/response/advanced_remediation.ex",
    "apps/tamandua_server/lib/tamandua_server/response/autonomous_engine.ex",
    "apps/tamandua_server/lib/tamandua_server/response/decision_engine.ex",
    "apps/tamandua_server/lib/tamandua_server/response/executor.ex",
    "apps/tamandua_server/lib/tamandua_server/response/ml_response.ex",
    "apps/tamandua_server/lib/tamandua_server/response/network_isolation.ex",
    "apps/tamandua_server/lib/tamandua_server/response/playbook.ex",
    "apps/tamandua_server/lib/tamandua_server/response/remediation.ex",
    "apps/tamandua_server/lib/tamandua_server/response/rollback.ex",
    "apps/tamandua_server/lib/tamandua_server/response/rollback_manager.ex",
    "apps/tamandua_server/lib/tamandua_server/response/vss_rollback.ex",
    "apps/tamandua_server/lib/tamandua_server/runtime/kill_switch.ex",
    "apps/tamandua_server/lib/tamandua_server/workers/batch_job_worker.ex",
    "apps/tamandua_server/lib/tamandua_server/workers/quarantine_worker.ex",
    "apps/tamandua_server/lib/tamandua_server/xdr/xdr_playbooks.ex",
    "apps/tamandua_server/lib/tamandua_server_web/controllers/api/v1/agent_controller.ex",
    "apps/tamandua_server/lib/tamandua_server_web/controllers/api/v1/healing_controller.ex",
    "apps/tamandua_server/lib/tamandua_server_web/controllers/api/v1/response_controller.ex",
    "apps/tamandua_server/lib/tamandua_server_web/graphql/resolvers/agent_resolver.ex",
    "apps/tamandua_server/lib/tamandua_server_web/graphql/resolvers/investigation_resolver.ex",
    "apps/tamandua_server/lib/tamandua_server_web/graphql/resolvers/response_resolver.ex",
    "apps/tamandua_server/lib/tamandua_server_web/live/agents_live.ex",
    "apps/tamandua_server/lib/tamandua_server_web/live/agents_live_enhanced.ex",
    "apps/tamandua_server/lib/tamandua_server_web/live/components/remediation_actions.ex",
}

SOURCE_SUFFIXES = {".ex", ".exs"}
DIRECT_ALIAS_RE = re.compile(
    r"\balias\s+TamanduaServer\.Response\.Executor(?:\s*,\s*as:\s*(?P<as>[A-Za-z_][\w]*))?"
)
GROUPED_ALIAS_RE = re.compile(r"\balias\s+TamanduaServer\.Response\.\{(?P<group>[^}]+)\}")
DIRECT_PATTERNS = [
    ("fully_qualified_call", re.compile(r"\bTamanduaServer\.Response\.Executor\.")),
    ("response_namespace_call", re.compile(r"(?<!TamanduaServer\.)\bResponse\.Executor\.")),
]
ALLOWLIST_ENTRY_RE = re.compile(r"`(?P<entry>apps/tamandua_server/lib/[^`]+\.exs?)`")


def rel(path: Path, root: Path = ROOT) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        relative = path.resolve()
    return str(relative).replace("\\", "/")


def source_files(scan_root: Path) -> Iterable[Path]:
    if scan_root.is_file():
        if scan_root.suffix in SOURCE_SUFFIXES:
            yield scan_root
        return

    for path in scan_root.rglob("*"):
        if path.is_file() and path.suffix in SOURCE_SUFFIXES:
            parts = set(path.parts)
            if "deps" not in parts and "_build" not in parts:
                yield path


def strip_comment(line: str) -> str:
    return line.split("#", 1)[0]


def alias_names(lines: list[str]) -> set[str]:
    names: set[str] = set()
    for line in lines:
        code = strip_comment(line)
        match = DIRECT_ALIAS_RE.search(code)
        if not match:
            grouped = GROUPED_ALIAS_RE.search(code)
            if grouped and any(part.strip() == "Executor" for part in grouped.group("group").split(",")):
                names.add("Executor")
            continue
        names.add(match.group("as") or "Executor")
    return names


def finding(path: str, line: int, kind: str, text: str, allowlisted: bool) -> dict[str, Any]:
    return {
        "path": path,
        "line": line,
        "kind": kind,
        "text": text,
        "allowlisted": allowlisted,
    }


def scan_file(path: Path, allowlist: set[str]) -> list[dict[str, Any]]:
    relative = rel(path)
    allowlisted = relative in allowlist
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    aliases = alias_names(lines)
    alias_patterns = [
        (f"alias_call:{name}", re.compile(rf"\b{re.escape(name)}\."))
        for name in aliases
    ]
    findings: list[dict[str, Any]] = []

    for index, raw_line in enumerate(lines, start=1):
        code = strip_comment(raw_line)
        if not code.strip():
            continue

        if alias_names([raw_line]):
            findings.append(finding(relative, index, "executor_alias", raw_line.strip(), allowlisted))

        for kind, pattern in DIRECT_PATTERNS + alias_patterns:
            if pattern.search(code):
                findings.append(finding(relative, index, kind, raw_line.strip(), allowlisted))

    return findings


def documented_allowlist_errors(allowlist_doc: Path, allowlist: set[str]) -> list[str]:
    if not allowlist_doc.exists():
        return [f"allowlist document missing: {rel(allowlist_doc)}"]
    text = allowlist_doc.read_text(encoding="utf-8", errors="replace")
    documented = set(ALLOWLIST_ENTRY_RE.findall(text))
    missing = [
        f"allowlist entry not documented in {rel(allowlist_doc)}: {entry}"
        for entry in sorted(allowlist)
        if entry not in documented
    ]
    stale = [
        f"documented allowlist entry not present in guard allowlist: {entry}"
        for entry in sorted(documented - allowlist)
    ]
    return missing + stale


def scan(scan_root: Path, allowlist_doc: Path = ALLOWLIST_DOC) -> dict[str, Any]:
    allowlist = set(DOCUMENTED_ALLOWLIST)
    findings: list[dict[str, Any]] = []
    for path in source_files(scan_root):
        findings.extend(scan_file(path, allowlist))

    violations = [finding for finding in findings if not finding["allowlisted"]]
    doc_errors = documented_allowlist_errors(allowlist_doc, allowlist)
    passed = not violations and not doc_errors
    return {
        "passed": passed,
        "scan_root": rel(scan_root),
        "guard_type": "local_static_migration_guard",
        "claim_boundary": (
            "Static source scan only. This does not enforce runtime behavior or prove "
            "Response.Executor execution safety."
        ),
        "allowlist_doc": rel(allowlist_doc),
        "allowlist_count": len(allowlist),
        "findings_count": len(findings),
        "allowlisted_findings_count": len(findings) - len(violations),
        "violations_count": len(violations),
        "documented_allowlist_errors": doc_errors,
        "violations": violations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-root", type=Path, default=DEFAULT_SCAN_ROOT)
    parser.add_argument("--allowlist-doc", type=Path, default=ALLOWLIST_DOC)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()

    result = scan(args.scan_root, args.allowlist_doc)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif result["passed"]:
        print(
            "Response.Executor direct-call static guard passed: "
            f"{result['allowlisted_findings_count']} documented allowlisted findings, "
            "0 violations."
        )
    else:
        for error in result["documented_allowlist_errors"]:
            print(error)
        for violation in result["violations"]:
            print(
                f"{violation['path']}:{violation['line']}: "
                f"{violation['kind']}: {violation['text']}"
            )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
