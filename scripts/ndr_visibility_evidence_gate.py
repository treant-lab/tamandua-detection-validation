#!/usr/bin/env python3
"""Classify NDR visibility fixtures by evidence completeness.

The gate is intentionally synthetic and contract-focused. It checks whether
network events carry enough persisted evidence to be investigated without
claiming packet-capture fidelity, TLS decryption, payload visibility, or live
production detection efficacy.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CLASSES = ("investigable", "partial", "weak")
DOMAIN_DIRECT_SOURCES = {"dns_query", "tls_sni"}
DOMAIN_DEGRADED_SOURCES = {"reverse_dns", "doh_endpoint_inferred"}
BYTES_DIRECT_SOURCES = {"flow_counter", "conntrack", "pcap_counter"}
TLS_DIRECT_SOURCES = {"handshake_metadata", "sni", "ja3", "certificate_metadata"}
DNS_DIRECT_STATUSES = {"direct", "correlated"}
DNS_DEGRADED_STATUSES = {"inferred"}
LATERAL_PORTS = {445, 3389}


@dataclass(frozen=True)
class Classification:
    event_id: str
    category: str
    classification: str
    expected: str | None
    status: str
    missing_minimum_fields: list[str]
    signals: dict[str, str]
    reasons: list[str]


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def non_empty(value: Any) -> bool:
    return value is not None and value != ""


def source_value(value: Any) -> str:
    return str(value or "missing").strip().lower()


def has_process(process: dict[str, Any]) -> bool:
    source = source_value(process.get("source"))
    return source not in {"missing", "none", "unknown"} and (
        non_empty(process.get("pid")) or non_empty(process.get("name"))
    )


def has_remote_endpoint(remote: dict[str, Any]) -> bool:
    source = source_value(remote.get("source"))
    return (
        source not in {"missing", "none", "unknown"}
        and non_empty(remote.get("ip"))
        and non_empty(remote.get("port"))
        and non_empty(remote.get("protocol"))
    )


def bytes_signal(bytes_block: dict[str, Any]) -> str:
    source = source_value(bytes_block.get("source"))
    sent = int(bytes_block.get("sent") or 0)
    received = int(bytes_block.get("received") or 0)
    if source not in BYTES_DIRECT_SOURCES:
        return "missing"
    if sent + received <= 0:
        return "zero"
    return "direct"


def domain_signal(event: dict[str, Any]) -> str:
    source = source_value(event.get("domain_source"))
    if source in DOMAIN_DIRECT_SOURCES and non_empty(event.get("domain")):
        return "direct"
    if source in DOMAIN_DEGRADED_SOURCES and non_empty(event.get("domain")):
        return "degraded"
    if source.startswith("not_applicable"):
        return "not_applicable"
    return "missing"


def tls_signal(event: dict[str, Any]) -> str:
    tls = event.get("tls") if isinstance(event.get("tls"), dict) else {}
    source = source_value(tls.get("source"))
    remote = event.get("remote_endpoint") if isinstance(event.get("remote_endpoint"), dict) else {}
    port = int(remote.get("port") or 0)

    if source in TLS_DIRECT_SOURCES:
        return "direct"
    if source == "not_applicable" or port not in {443, 8443}:
        return "not_applicable"
    return "missing"


def dns_signal(event: dict[str, Any]) -> str:
    dns = event.get("dns_correlation") if isinstance(event.get("dns_correlation"), dict) else {}
    status = source_value(dns.get("status"))
    if status in DNS_DIRECT_STATUSES:
        return "direct"
    if status in DNS_DEGRADED_STATUSES:
        return "degraded"
    if status == "not_applicable":
        return "not_applicable"
    return "missing"


def is_lateral_service(event: dict[str, Any]) -> bool:
    remote = event.get("remote_endpoint") if isinstance(event.get("remote_endpoint"), dict) else {}
    port = int(remote.get("port") or 0)
    scope = source_value(remote.get("network_scope"))
    service = source_value(remote.get("service"))
    return port in LATERAL_PORTS or scope == "internal" and service in {"smb", "rdp"}


def is_doh_endpoint(scenario: dict[str, Any], event: dict[str, Any]) -> bool:
    remote = event.get("remote_endpoint") if isinstance(event.get("remote_endpoint"), dict) else {}
    category = source_value(scenario.get("category"))
    return category.startswith("doh") or (
        str(remote.get("ip") or "") in {"8.8.8.8", "8.8.4.4"}
        and int(remote.get("port") or 0) == 443
    )


def missing_minimum_fields(event: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    for field in ("process", "remote_endpoint", "bytes", "tls", "dns_correlation"):
        if not isinstance(event.get(field), dict):
            missing.append(field)
    if "domain_source" not in event:
        missing.append("domain_source")
    return missing


def classify_event(scenario: dict[str, Any]) -> Classification:
    event = scenario.get("event") if isinstance(scenario.get("event"), dict) else {}
    process = event.get("process") if isinstance(event.get("process"), dict) else {}
    remote = event.get("remote_endpoint") if isinstance(event.get("remote_endpoint"), dict) else {}
    bytes_block = event.get("bytes") if isinstance(event.get("bytes"), dict) else {}

    missing_fields = missing_minimum_fields(event)
    signals = {
        "process": "direct" if has_process(process) else "missing",
        "remote_endpoint": "direct" if has_remote_endpoint(remote) else "missing",
        "domain": domain_signal(event),
        "bytes": bytes_signal(bytes_block),
        "tls": tls_signal(event),
        "dns_correlation": dns_signal(event),
    }

    reasons: list[str] = []
    if missing_fields:
        reasons.append("minimum field contract is incomplete")
    if signals["remote_endpoint"] == "missing":
        reasons.append("remote endpoint is not observable")
    if signals["bytes"] == "zero":
        reasons.append("byte counters are present but show no transferred data")
    if signals["bytes"] == "missing":
        reasons.append("byte source is missing or unsupported")
    if signals["process"] == "missing":
        reasons.append("process attribution is missing")
    if signals["domain"] == "missing" and signals["dns_correlation"] == "missing":
        reasons.append("no domain or DNS correlation is available")
    if signals["tls"] == "missing":
        reasons.append("TLS metadata is absent for a TLS-like endpoint")

    lateral = is_lateral_service(event)
    doh_without_inner_dns = is_doh_endpoint(scenario, event) and signals["dns_correlation"] == "missing"
    if doh_without_inner_dns:
        reasons.append("DoH endpoint is visible but inner DNS question is not correlated")

    identity_signal = (
        signals["domain"] in {"direct", "degraded"}
        or signals["dns_correlation"] in {"direct", "degraded"}
        or signals["tls"] == "direct"
        or lateral
    )

    if (
        missing_fields
        or signals["remote_endpoint"] == "missing"
        or signals["bytes"] in {"missing", "zero"}
    ):
        classification = "weak"
    elif signals["process"] == "direct" and identity_signal and signals["tls"] != "missing":
        classification = "partial" if doh_without_inner_dns else "investigable"
    elif lateral and signals["process"] == "direct" and signals["bytes"] == "direct":
        classification = "investigable"
    else:
        classification = "partial"

    expected = scenario.get("expected_classification")
    status = "pass" if expected == classification else "fail"
    return Classification(
        event_id=str(scenario.get("id") or "<missing-id>"),
        category=str(scenario.get("category") or "<missing-category>"),
        classification=classification,
        expected=str(expected) if expected is not None else None,
        status=status,
        missing_minimum_fields=missing_fields,
        signals=signals,
        reasons=reasons,
    )


def build_report(path: Path) -> dict[str, Any]:
    payload = load_json(path)
    scenarios = payload.get("scenarios") if isinstance(payload, dict) else None
    if not isinstance(scenarios, list):
        raise ValueError(f"{path} does not contain a scenarios list")

    results = [classify_event(scenario).__dict__ for scenario in scenarios]
    failed = [result for result in results if result["status"] == "fail"]
    return {
        "schema_version": 1,
        "kind": "NdrVisibilityEvidenceGate",
        "fixture": str(path),
        "status": "fail" if failed else "pass",
        "checked_scenarios": len(results),
        "failed_scenarios": len(failed),
        "classes": list(CLASSES),
        "claim_boundary": (
            "Classifies synthetic NDR evidence completeness only. investigable means "
            "the fixture has enough persisted metadata for analyst follow-up; partial "
            "means at least one major attribution or visibility source is degraded; weak "
            "means the event lacks a critical evidence anchor."
        ),
        "results": results,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path, help="NDR visibility evidence fixture JSON")
    parser.add_argument("--output", type=Path, help="Optional JSON report output path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    report = build_report(args.fixture)
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
