#!/usr/bin/env python3
"""Source audit for mobile identity mutation bridge ownership.

This is a conservative source gate. It does not compile or execute the server;
it checks that known mobile controller bridges either use the identity guard or
remain read-only/closed for identity mutation.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CONTROLLER = (
    ROOT
    / "apps"
    / "tamandua_server"
    / "lib"
    / "tamandua_server_web"
    / "controllers"
    / "api"
    / "v1"
    / "mobile_controller.ex"
)

MUTATION_MARKERS = (
    "Mobile.register_device(",
    "Mobile.update_device(",
    "Repo.insert(",
    "Repo.update(",
    "DeviceRegistry.enroll",
)

IDENTITY_MUTATION_MARKERS = (
    "Mobile.register_device(",
    "Mobile.update_device(",
    "DeviceV2.changeset(",
    "upsert_device_v2_agent(",
    "DeviceRegistry.enroll",
)


def extract_function(source: str, name: str) -> str:
    match = re.search(rf"^\s*def\s+{re.escape(name)}\b.*?(?=^\s*def\s|\Z)", source, re.M | re.S)
    return match.group(0) if match else ""


def marker_line(source: str, marker: str) -> int | None:
    index = source.find(marker)
    if index < 0:
        return None
    return source[:index].count("\n") + 1


def has_any_mutation_marker(source: str) -> bool:
    return any(marker in source for marker in MUTATION_MARKERS)


def has_any_identity_mutation_marker(source: str) -> bool:
    return any(marker in source for marker in IDENTITY_MUTATION_MARKERS)


def check_bridge(source: str, name: str, required_markers: tuple[str, ...]) -> dict[str, object]:
    body = extract_function(source, name)
    missing = [marker for marker in required_markers if marker not in body]
    return {
        "name": name,
        "line": marker_line(source, f"def {name}") or None,
        "present": bool(body),
        "guarded": bool(body) and not missing,
        "missing_markers": missing,
        "mutation_markers_present": [marker for marker in MUTATION_MARKERS if marker in body],
    }


def evaluate(controller_path: Path = CONTROLLER) -> dict[str, object]:
    source = controller_path.read_text(encoding="utf-8")
    bridges = [
        check_bridge(
            source,
            "register",
            ("legacy_identity_mutation(", "Mobile.register_device("),
        ),
        check_bridge(
            source,
            "update",
            ("legacy_identity_mutation(", "Mobile.update_device("),
        ),
        check_bridge(
            source,
            "create_v2",
            ("legacy_identity_mutation(",),
        ),
        check_bridge(
            source,
            "update_v2",
            ("legacy_identity_mutation(",),
        ),
        check_bridge(
            source,
            "enroll_device",
            ("device_identity_proof_required(conn)",),
        ),
    ]

    read_only_bridges = []
    for name in ("ingest_app_guard_event", "ingest_events", "create_command"):
        body = extract_function(source, name)
        read_only_bridges.append(
            {
                "name": name,
                "line": marker_line(source, f"def {name}") or None,
                "present": bool(body),
                "identity_mutation_marker_present": has_any_identity_mutation_marker(body),
                "identity_mutation_markers_present": [
                    marker for marker in IDENTITY_MUTATION_MARKERS if marker in body
                ],
                "write_markers_present": [marker for marker in MUTATION_MARKERS if marker in body],
            }
        )

    helper_markers = [
        "defp legacy_identity_mutation",
        "MobileDeviceIdentity.with_legacy_unbound(",
        ":device_identity_proof_required",
    ]
    helper_missing = [marker for marker in helper_markers if marker not in source]

    reasons: list[str] = []
    for bridge in bridges:
        if not bridge["present"]:
            reasons.append(f"guarded_bridge_missing:{bridge['name']}")
        elif not bridge["guarded"]:
            reasons.append(f"guarded_bridge_incomplete:{bridge['name']}")

    for bridge in read_only_bridges:
        if not bridge["present"]:
            reasons.append(f"read_only_bridge_missing:{bridge['name']}")
        elif bridge["identity_mutation_marker_present"]:
            reasons.append(f"read_only_bridge_mutates_identity:{bridge['name']}")

    for marker in helper_missing:
        reasons.append(f"helper_marker_missing:{marker}")

    return {
        "schema_version": 1,
        "evidence_class": "source_audit",
        "external_claim_allowed": False,
        "ok": not reasons,
        "controller": str(controller_path),
        "guarded_bridges": bridges,
        "read_only_bridges": read_only_bridges,
        "helper_markers": {
            "required": helper_markers,
            "missing": helper_missing,
        },
        "reasons": reasons,
        "claim_boundary": (
            "Source audit only. It proves known mobile controller bridge ownership "
            "markers are present; compile, PostgreSQL, and HTTP regression tests "
            "remain promotion gates."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", type=Path, default=CONTROLLER)
    args = parser.parse_args(argv)
    result = evaluate(args.controller)
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
