#!/usr/bin/env python3
"""Classify mobile network visibility readiness fixtures.

This gate is intentionally contract-focused. It classifies Android/iOS mobile
network visibility by deployment mode and validates that phone-wide visibility
claims are backed by explicit platform capability fields. It does not execute
mobile runtime code or prove physical-device collection.
"""

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MODES = (
    "app_guard_only",
    "sdk_embedded",
    "android_vpnservice",
    "ios_network_extension",
    "mdm_managed",
)
PLATFORMS = {"android", "ios"}
REQUIRED_FIELDS = {
    "platform",
    "app_installed",
    "sdk_embedded",
    "vpnservice_enabled",
    "network_extension_entitled",
    "mdm_profile_installed",
    "per_app_vpn",
    "dns_visibility",
    "flow_visibility",
    "app_process_attribution",
    "packet_visibility",
    "user_consent_required",
}
VISIBILITY_VALUES = {
    "none",
    "app_scope_only",
    "metadata_only",
    "dns_metadata",
    "flow_metadata",
    "per_app_vpn_metadata",
    "packet_metadata",
}
ATTRIBUTION_VALUES = {
    "none",
    "protected_app_only",
    "sdk_process_only",
    "vpn_uid_best_effort",
    "network_extension_app_rule",
    "mdm_per_app_vpn",
}


@dataclass(frozen=True)
class Classification:
    scenario_id: str
    platform: str
    mode: str
    expected_mode: str | None
    status: str
    visibility: str
    missing_fields: list[str]
    signals: dict[str, str]
    reasons: list[str]


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def bool_field(value: Any) -> bool:
    return value is True


def text(value: Any) -> str:
    return str(value or "").strip().lower()


def has_visibility(value: Any) -> bool:
    return text(value) not in {"", "none"}


def derive_mode(capabilities: dict[str, Any]) -> str:
    platform = text(capabilities.get("platform"))
    if bool_field(capabilities.get("mdm_profile_installed")) and bool_field(
        capabilities.get("per_app_vpn")
    ):
        return "mdm_managed"
    if platform == "android" and bool_field(capabilities.get("vpnservice_enabled")):
        return "android_vpnservice"
    if platform == "ios" and bool_field(capabilities.get("network_extension_entitled")):
        return "ios_network_extension"
    if bool_field(capabilities.get("sdk_embedded")):
        return "sdk_embedded"
    if bool_field(capabilities.get("app_installed")):
        return "app_guard_only"
    return "unsupported"


def validate_mode(mode: str, capabilities: dict[str, Any]) -> list[str]:
    platform = text(capabilities.get("platform"))
    dns = capabilities.get("dns_visibility")
    flow = capabilities.get("flow_visibility")
    attribution = text(capabilities.get("app_process_attribution"))
    packet = text(capabilities.get("packet_visibility"))
    reasons: list[str] = []

    if platform not in PLATFORMS:
        reasons.append("platform must be android or ios")
    if mode not in MODES:
        reasons.append("no supported mobile visibility mode is active")
    if text(dns) not in VISIBILITY_VALUES:
        reasons.append("dns_visibility has an unsupported value")
    if text(flow) not in VISIBILITY_VALUES:
        reasons.append("flow_visibility has an unsupported value")
    if attribution not in ATTRIBUTION_VALUES:
        reasons.append("app_process_attribution has an unsupported value")
    if packet not in VISIBILITY_VALUES:
        reasons.append("packet_visibility has an unsupported value")

    if mode == "app_guard_only":
        if not bool_field(capabilities.get("app_installed")):
            reasons.append("app_guard_only requires app_installed")
        if has_visibility(dns) or has_visibility(flow) or has_visibility(packet):
            reasons.append("app_guard_only must not claim phone-wide network visibility")
        if attribution not in {"protected_app_only", "none"}:
            reasons.append("app_guard_only attribution must stay inside the protected app")
    elif mode == "sdk_embedded":
        if not bool_field(capabilities.get("sdk_embedded")):
            reasons.append("sdk_embedded requires sdk_embedded")
        if attribution not in {"sdk_process_only", "protected_app_only"}:
            reasons.append("sdk_embedded attribution must be scoped to embedded SDK processes")
    elif mode == "android_vpnservice":
        if platform != "android":
            reasons.append("android_vpnservice requires platform android")
        if not bool_field(capabilities.get("app_installed")):
            reasons.append("android_vpnservice requires an installed controlling app")
        if not bool_field(capabilities.get("vpnservice_enabled")):
            reasons.append("android_vpnservice requires vpnservice_enabled")
        if not has_visibility(dns) or not has_visibility(flow):
            reasons.append("android_vpnservice requires DNS and flow metadata visibility")
        if attribution != "vpn_uid_best_effort":
            reasons.append("android_vpnservice attribution must be vpn_uid_best_effort")
        if not bool_field(capabilities.get("user_consent_required")):
            reasons.append("android_vpnservice requires explicit user VPN consent unless MDM manages it")
    elif mode == "ios_network_extension":
        if platform != "ios":
            reasons.append("ios_network_extension requires platform ios")
        if not bool_field(capabilities.get("network_extension_entitled")):
            reasons.append("ios_network_extension requires NetworkExtension entitlement")
        if not has_visibility(dns) or not has_visibility(flow):
            reasons.append("ios_network_extension requires DNS and flow metadata visibility")
        if attribution != "network_extension_app_rule":
            reasons.append("ios_network_extension attribution must use app-rule/per-app metadata")
    elif mode == "mdm_managed":
        if not bool_field(capabilities.get("mdm_profile_installed")):
            reasons.append("mdm_managed requires mdm_profile_installed")
        if not bool_field(capabilities.get("per_app_vpn")):
            reasons.append("mdm_managed requires per_app_vpn")
        if not has_visibility(dns) or not has_visibility(flow):
            reasons.append("mdm_managed requires managed DNS and flow metadata visibility")
        if attribution != "mdm_per_app_vpn":
            reasons.append("mdm_managed attribution must use mdm_per_app_vpn")
        if bool_field(capabilities.get("user_consent_required")):
            reasons.append("mdm_managed should model consent through enrollment/profile install")

    return reasons


def visibility_label(mode: str, reasons: list[str], capabilities: dict[str, Any]) -> str:
    if reasons:
        return "invalid"
    if mode in {"android_vpnservice", "ios_network_extension", "mdm_managed"}:
        packet = text(capabilities.get("packet_visibility"))
        if packet == "packet_metadata":
            return "phone_wide_metadata"
        return "phone_wide_dns_flow"
    if mode == "sdk_embedded":
        return "embedded_app_scope"
    return "degraded_app_scope"


def classify_scenario(scenario: dict[str, Any]) -> Classification:
    capabilities = scenario.get("capabilities") if isinstance(scenario.get("capabilities"), dict) else {}
    missing = sorted(REQUIRED_FIELDS - set(capabilities))
    mode = derive_mode(capabilities)
    reasons = validate_mode(mode, capabilities)
    if missing:
        reasons.insert(0, "minimum field contract is incomplete")

    expected = scenario.get("expected_mode")
    if expected is not None and expected != mode:
        reasons.append(f"expected_mode {expected!r} does not match derived mode {mode!r}")

    status = "pass" if not reasons else "fail"
    return Classification(
        scenario_id=str(scenario.get("id") or "<missing-id>"),
        platform=text(capabilities.get("platform")) or "<missing-platform>",
        mode=mode,
        expected_mode=str(expected) if expected is not None else None,
        status=status,
        visibility=visibility_label(mode, reasons, capabilities),
        missing_fields=missing,
        signals={
            "dns_visibility": text(capabilities.get("dns_visibility")) or "missing",
            "flow_visibility": text(capabilities.get("flow_visibility")) or "missing",
            "app_process_attribution": text(capabilities.get("app_process_attribution")) or "missing",
            "packet_visibility": text(capabilities.get("packet_visibility")) or "missing",
            "user_consent_required": str(bool_field(capabilities.get("user_consent_required"))).lower(),
        },
        reasons=reasons,
    )


def build_report(path: Path) -> dict[str, Any]:
    payload = load_json(path)
    scenarios = payload.get("scenarios") if isinstance(payload, dict) else None
    if not isinstance(scenarios, list):
        raise ValueError(f"{path} does not contain a scenarios list")

    results = [classify_scenario(scenario).__dict__ for scenario in scenarios]
    failed = [result for result in results if result["status"] == "fail"]
    mode_counts = {mode: 0 for mode in MODES}
    for result in results:
        if result["mode"] in mode_counts:
            mode_counts[result["mode"]] += 1

    return {
        "schema_version": 1,
        "kind": "MobileNetworkVisibilityReadinessGate",
        "fixture": str(path),
        "status": "fail" if failed else "pass",
        "checked_scenarios": len(results),
        "failed_scenarios": len(failed),
        "modes": list(MODES),
        "mode_counts": mode_counts,
        "required_fields": sorted(REQUIRED_FIELDS),
        "claim_boundary": (
            "Classifies synthetic mobile network visibility readiness only. "
            "Phone-wide Android/iOS claims require VpnService, NetworkExtension, "
            "or MDM/per-app VPN evidence; App Guard and embedded SDK modes are "
            "application-scoped fallbacks, not mature mobile NDR."
        ),
        "results": results,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path, help="Mobile network visibility fixture JSON")
    parser.add_argument("--output", type=Path, help="Optional JSON report output path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    report = build_report(args.fixture)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
