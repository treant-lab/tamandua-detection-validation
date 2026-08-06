#!/usr/bin/env python3
"""Static, non-executing gate for the Windows observe-only driver profile."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


FILES = {
    "driver_h": "apps/tamandua_driver/src/driver.h",
    "protocol_h": "apps/tamandua_driver/src/tamandua.h",
    "user_api_h": "apps/tamandua_driver/src/usermode_api.h",
    "main_c": "apps/tamandua_driver/src/main.c",
    "protection_c": "apps/tamandua_driver/src/protection.c",
    "watchdog_c": "apps/tamandua_driver/src/watchdog.c",
    "makefile": "apps/tamandua_driver/Makefile",
    "vcxproj": "apps/tamandua_driver/tamandua_driver.vcxproj",
}

READ_ONLY_COMMANDS = {
    "TAMANDUA_CMD_GET_VERSION",
    "TAMANDUA_CMD_CONFIG_GET",
    "TAMANDUA_CMD_GET_CAPABILITIES",
    "TAMANDUA_CMD_GET_DRIVER_HEALTH",
    "TAMANDUA_CMD_GET_SAFETY_STATS",
}

CONTROL_MACROS = (
    "TAMANDUA_LAB_ENABLE_CORE_PROTECTION",
    "TAMANDUA_LAB_ENABLE_REGISTRY_CALLBACK",
    "TAMANDUA_LAB_ENABLE_OBJECT_CALLBACKS",
    "TAMANDUA_LAB_ENABLE_ANTITAMPER",
    "TAMANDUA_LAB_ENABLE_RANSOMWARE",
    "TAMANDUA_LAB_ENABLE_ETW_AMSI",
    "TAMANDUA_LAB_ENABLE_NTDLL_GUARD",
    "TAMANDUA_LAB_ENABLE_MINIFILTER_SCAN",
    "TAMANDUA_LAB_ENABLE_WFP",
    "TAMANDUA_LAB_ENABLE_SELF_PROTECTION_BASIC",
    "TAMANDUA_LAB_ENABLE_DRIVER_PROTECTION",
    "TAMANDUA_LAB_ENABLE_CALLBACK_GUARD",
)

CAPABILITY_MACRO_PREFIXES = (
    "TAMANDUA_CAPABILITY_CONTRACT_",
    "TAMANDUA_DRIVER_MODE_",
    "TAMANDUA_OBSERVE_",
    "TAMANDUA_CAP_RESERVED_",
)


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//.*", "", text)


def _macros(text: str) -> dict[str, str]:
    result = {}
    for match in re.finditer(r"^\s*#define\s+(\w+)\s+(.+?)\s*$", text, re.MULTILINE):
        name, value = match.groups()
        result[name] = value.split("//", 1)[0].strip()
    return result


def _capability_macros(text: str) -> dict[str, str]:
    return {
        name: value
        for name, value in _macros(text).items()
        if name.startswith(CAPABILITY_MACRO_PREFIXES)
    }


def _preprocessor_valid(text: str) -> bool:
    stack: list[bool] = []
    for line in _strip_comments(text).splitlines():
        directive = line.strip()
        if re.match(r"^#if(?:n?def)?\b", directive):
            stack.append(False)
        elif re.match(r"^#elif\b", directive):
            if not stack or stack[-1]:
                return False
        elif re.match(r"^#else\b", directive):
            if not stack or stack[-1]:
                return False
            stack[-1] = True
        elif re.match(r"^#endif\b", directive):
            if not stack:
                return False
            stack.pop()
    return not stack


def _function_body(text: str, name: str) -> str:
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", text):
        paren_start = text.find("(", match.start())
        depth = 0
        paren_end = -1
        for index in range(paren_start, len(text)):
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                depth -= 1
                if depth == 0:
                    paren_end = index
                    break
        if paren_end < 0:
            continue
        brace = text.find("{", paren_end)
        semicolon = text.find(";", paren_end)
        if brace < 0 or (semicolon >= 0 and semicolon < brace):
            continue
        depth = 0
        for index in range(brace, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    return text[brace + 1:index]
    raise ValueError(f"function definition not found: {name}")


def _observe_branch(body: str) -> str | None:
    marker = "#if TAMANDUA_DRIVER_OBSERVE_ONLY"
    start = body.find(marker)
    if start < 0:
        return None
    branch_start = start + len(marker)
    ends = [position for token in ("#else", "#endif") if (position := body.find(token, branch_start)) >= 0]
    if not ends:
        return None
    return _strip_comments(body[branch_start:min(ends)])


def _observe_branch_safe(body: str, return_statement: str, forbidden: tuple[str, ...]) -> bool:
    branch = _observe_branch(body)
    marker = body.find("#if TAMANDUA_DRIVER_OBSERVE_ONLY")
    prefix = _strip_comments(body[:marker])
    active = _active_when_observe_only(body)
    before_return, separator, _ = active.partition(return_statement)
    return (
        branch is not None
        and return_statement in branch
        and return_statement not in prefix
        and bool(separator)
        and not any(token in before_return for token in forbidden)
    )


def _active_when_observe_only(text: str) -> str:
    """Return text conservatively active when OBSERVE_ONLY is defined as 1.

    Unknown preprocessor conditions retain every branch; only conditions that
    directly test the immutable profile are reduced.
    """
    output: list[str] = []
    stack: list[dict[str, bool | None]] = []

    def observe_value(expression: str) -> bool | None:
        normalized = re.sub(r"[()\s]", "", expression)
        if normalized == "TAMANDUA_DRIVER_OBSERVE_ONLY":
            return True
        if normalized == "!TAMANDUA_DRIVER_OBSERVE_ONLY":
            return False
        return None

    def active() -> bool:
        return all(frame["active"] is not False for frame in stack)

    for line in _strip_comments(text).splitlines():
        directive = line.strip()
        match = re.match(r"^#if\s+(.+)$", directive)
        if match:
            value = observe_value(match.group(1))
            stack.append({"taken": value, "active": value})
            continue
        if re.match(r"^#ifdef\s+TAMANDUA_DRIVER_OBSERVE_ONLY\b", directive):
            stack.append({"taken": True, "active": True})
            continue
        if re.match(r"^#ifndef\s+TAMANDUA_DRIVER_OBSERVE_ONLY\b", directive):
            stack.append({"taken": False, "active": False})
            continue
        if re.match(r"^#if(?:n?def)?\b", directive):
            stack.append({"taken": None, "active": None})
            continue
        if re.match(r"^#else\b", directive):
            if stack:
                taken = stack[-1]["taken"]
                stack[-1]["active"] = False if taken is True else True if taken is False else None
                stack[-1]["taken"] = True if taken is False else taken
            continue
        elif_match = re.match(r"^#elif\s+(.+)$", directive)
        if elif_match:
            if stack:
                taken = stack[-1]["taken"]
                if taken is True:
                    stack[-1]["active"] = False
                elif taken is False:
                    value = observe_value(elif_match.group(1))
                    stack[-1]["active"] = value
                    stack[-1]["taken"] = value
                else:
                    stack[-1]["active"] = None
            continue
        if re.match(r"^#endif\b", directive):
            if stack:
                stack.pop()
            continue
        if active():
            output.append(line)
    return "\n".join(output)


def _guarded_by(text: str, condition: str, statement: str) -> bool:
    pattern = rf"#if\s+{re.escape(condition)}\b(?P<branch>.*?)#endif\b"
    return any(statement in _strip_comments(match.group("branch")) for match in re.finditer(pattern, text, re.DOTALL))


def _low_core_dispatcher(main: str) -> str:
    start = main.index("#if !TAMANDUA_LAB_ENABLE_CORE_PROTECTION")
    end = main.index("    __try {", start)
    return main[start:end]


def _read_only_dispatcher_is_closed(dispatcher: str) -> bool:
    cases = list(re.finditer(r"case\s+(TAMANDUA_CMD_\w+)\s*:", dispatcher))
    if {match.group(1) for match in cases} != READ_ONLY_COMMANDS:
        return False
    for index, match in enumerate(cases):
        end = cases[index + 1].start() if index + 1 < len(cases) else dispatcher.index("default:", match.end())
        if "return " not in _strip_comments(dispatcher[match.end():end]):
            return False
    default = dispatcher[dispatcher.index("default:"):]
    names = [match.group(1) for match in cases]
    return len(names) == len(set(names)) and "return STATUS_NOT_SUPPORTED;" in _strip_comments(default)


def _struct_fields(text: str, tag: str) -> list[tuple[str, str]]:
    match = re.search(rf"typedef\s+struct\s+_{tag}\s*\{{(?P<body>.*?)\}}\s*{tag}\b", _strip_comments(text), re.DOTALL)
    if not match:
        return []
    return re.findall(r"^\s*(TAMANDUA_MESSAGE_HEADER|ULONG|USHORT)\s+(\w+(?:\[\d+\])?)\s*;", match.group("body"), re.MULTILINE)


def validate(root: Path) -> dict:
    sources = {name: (root / rel).read_text(encoding="utf-8") for name, rel in FILES.items()}
    driver = sources["driver_h"]
    protocol = sources["protocol_h"]
    user_api = sources["user_api_h"]
    main = sources["main_c"]
    protection = sources["protection_c"]
    watchdog = sources["watchdog_c"]
    driver_macros = _macros(driver)
    protocol_macros = _capability_macros(protocol)
    user_api_macros = _capability_macros(user_api)
    dispatcher = _low_core_dispatcher(main)
    get_cap_start = dispatcher.index("case TAMANDUA_CMD_GET_CAPABILITIES:")
    get_cap_end = dispatcher.index("case TAMANDUA_CMD_GET_DRIVER_HEALTH:", get_cap_start)
    get_cap_case = dispatcher[get_cap_start:get_cap_end]
    get_cap_observe = _observe_branch(get_cap_case) or ""

    expected_control_expressions = {
        "TAMANDUA_LAB_ENABLE_CORE_PROTECTION": "(!TAMANDUA_DRIVER_OBSERVE_ONLY&&(TAMANDUA_DRIVER_LAB_LEVEL>=4))",
        "TAMANDUA_LAB_ENABLE_REGISTRY_CALLBACK": "(!TAMANDUA_DRIVER_OBSERVE_ONLY&&(TAMANDUA_DRIVER_LAB_LEVEL>=13))",
        "TAMANDUA_LAB_ENABLE_OBJECT_CALLBACKS": "(!TAMANDUA_DRIVER_OBSERVE_ONLY&&(TAMANDUA_DRIVER_LAB_LEVEL>=14))",
        "TAMANDUA_LAB_ENABLE_ANTITAMPER": "(!TAMANDUA_DRIVER_OBSERVE_ONLY&&(TAMANDUA_DRIVER_LAB_LEVEL>=151))",
        "TAMANDUA_LAB_ENABLE_RANSOMWARE": "(!TAMANDUA_DRIVER_OBSERVE_ONLY&&(TAMANDUA_DRIVER_LAB_LEVEL>=152))",
        "TAMANDUA_LAB_ENABLE_ETW_AMSI": "(!TAMANDUA_DRIVER_OBSERVE_ONLY&&(TAMANDUA_DRIVER_LAB_LEVEL>=155))",
        "TAMANDUA_LAB_ENABLE_NTDLL_GUARD": "(!TAMANDUA_DRIVER_OBSERVE_ONLY&&(TAMANDUA_DRIVER_LAB_LEVEL>=156))",
        "TAMANDUA_LAB_ENABLE_MINIFILTER_SCAN": "(!TAMANDUA_DRIVER_OBSERVE_ONLY&&(TAMANDUA_DRIVER_LAB_LEVEL>=157))",
        "TAMANDUA_LAB_ENABLE_WFP": "(!TAMANDUA_DRIVER_OBSERVE_ONLY&&(TAMANDUA_DRIVER_LAB_LEVEL>=160))",
        "TAMANDUA_LAB_ENABLE_SELF_PROTECTION_BASIC": "(!TAMANDUA_DRIVER_OBSERVE_ONLY&&(TAMANDUA_DRIVER_LAB_LEVEL>=170))",
        "TAMANDUA_LAB_ENABLE_DRIVER_PROTECTION": "(!TAMANDUA_DRIVER_OBSERVE_ONLY&&(TAMANDUA_DRIVER_LAB_LEVEL>=171))",
        "TAMANDUA_LAB_ENABLE_CALLBACK_GUARD": "(!TAMANDUA_DRIVER_OBSERVE_ONLY&&(TAMANDUA_DRIVER_LAB_LEVEL>=172))",
    }

    capability_indices = {
        protocol_macros.get(f"TAMANDUA_CAP_RESERVED_{suffix}")
        for suffix in (
            "CONTRACT_VERSION", "DRIVER_MODE", "COMPILED_CONTROL_FLAGS",
            "ACTIVE_CONTROL_FLAGS", "INVARIANT_FLAGS", "COMMAND_POLICY_FLAGS",
            "DISABLED_SUBSYSTEM_FLAGS", "READ_ONLY_COMMAND_FLAGS",
        )
    }
    receipt_assignments = (
        "capabilities->CapabilityFlags = 0;",
        "capabilities->ActiveFlags = 0;",
        "capabilities->Reserved[TAMANDUA_CAP_RESERVED_COMPILED_CONTROL_FLAGS] = 0;",
        "capabilities->Reserved[TAMANDUA_CAP_RESERVED_ACTIVE_CONTROL_FLAGS] = 0;",
        "TAMANDUA_CAP_RESERVED_INVARIANT_FLAGS] =\n                    TAMANDUA_OBSERVE_INVARIANTS_ALL;",
        "TAMANDUA_CAP_RESERVED_COMMAND_POLICY_FLAGS] =\n                    TAMANDUA_OBSERVE_COMMAND_POLICY_ALL;",
        "TAMANDUA_CAP_RESERVED_DISABLED_SUBSYSTEM_FLAGS] =\n                    TAMANDUA_OBSERVE_DISABLED_SUBSYSTEMS_ALL;",
        "TAMANDUA_CAP_RESERVED_READ_ONLY_COMMAND_FLAGS] =\n                    TAMANDUA_OBSERVE_READ_ONLY_COMMANDS_ALL;",
    )

    precreate = _function_body(main, "TamanduaPreCreate")
    prewrite = _function_body(main, "TamanduaPreWrite")
    preset = _function_body(main, "TamanduaPreSetInformation")
    process_notify = _function_body(main, "TamanduaProcessNotifyCallback")
    protection_preop = _function_body(protection, "TamanduaProtectionPreCallback")
    process_notify_observe = _active_when_observe_only(process_notify)
    protection_preop_observe = _active_when_observe_only(protection_preop)

    precreate_code = _strip_comments(precreate)
    abi_fields = [
        ("ULONG", "ProtocolVersion"), ("ULONG", "DriverVersionMajor"),
        ("ULONG", "DriverVersionMinor"), ("ULONG", "DriverVersionPatch"),
        ("ULONG", "LabLevel"), ("ULONG", "CapabilityFlags"),
        ("ULONG", "ActiveFlags"), ("ULONG", "HealthFlags"),
        ("ULONG", "Reserved[8]"),
    ]
    guard_code = _strip_comments(driver)
    health_code = re.sub(r"\s+", "", get_cap_observe)
    checks = {
        "preprocessor_structure_valid": all(_preprocessor_valid(text) for text in sources.values()),
        "build_default_is_normal": driver_macros.get("TAMANDUA_DRIVER_OBSERVE_ONLY") == "0"
        and re.search(r"#if\s+\(TAMANDUA_DRIVER_OBSERVE_ONLY\s*!=\s*0\)\s*&&\s*\(TAMANDUA_DRIVER_OBSERVE_ONLY\s*!=\s*1\)\s*#error\s+TAMANDUA_DRIVER_OBSERVE_ONLY", guard_code, re.DOTALL) is not None
        and "TAMANDUA_DRIVER_OBSERVE_ONLY = 0" in sources["makefile"]
        and "/D TAMANDUA_DRIVER_OBSERVE_ONLY=$(TAMANDUA_DRIVER_OBSERVE_ONLY)" in sources["makefile"]
        and "<TamanduaDriverObserveOnly Condition=\"'$(TamanduaDriverObserveOnly)'==''\">0</TamanduaDriverObserveOnly>" in sources["vcxproj"]
        and sources["vcxproj"].count("TAMANDUA_DRIVER_OBSERVE_ONLY=$(TamanduaDriverObserveOnly);") == 2,
        "controls_compile_out": all(
            re.sub(r"\s+", "", driver_macros.get(macro, "")) == expression
            for macro, expression in expected_control_expressions.items()
        ),
        "capability_v2_abi": protocol_macros == user_api_macros
        and protocol_macros.get("TAMANDUA_CAPABILITY_CONTRACT_VERSION_V2") == "2"
        and protocol_macros.get("TAMANDUA_OBSERVE_INVARIANTS_ALL") == "0x000000FF"
        and protocol_macros.get("TAMANDUA_OBSERVE_COMMAND_POLICY_ALL") == "0x00000003"
        and protocol_macros.get("TAMANDUA_OBSERVE_DISABLED_SUBSYSTEMS_ALL") == "0x0000001F"
        and protocol_macros.get("TAMANDUA_OBSERVE_READ_ONLY_COMMANDS_ALL") == "0x0000001F"
        and capability_indices == {str(index) for index in range(8)}
        and _struct_fields(protocol, "TAMANDUA_CAPABILITIES") == abi_fields
        and _struct_fields(user_api, "TAMANDUA_CAPABILITIES_RESPONSE") == [("TAMANDUA_MESSAGE_HEADER", "Header"), *abi_fields],
        "complete_zero_control_receipt": all(assignment in get_cap_observe for assignment in receipt_assignments),
        "observe_receipt_isolated": "#if TAMANDUA_DRIVER_OBSERVE_ONLY" in get_cap_case
        and "#else" in get_cap_case
        and "return STATUS_NOT_SUPPORTED;" in get_cap_case.split("#else", 1)[1]
        and "TAMANDUA_DRIVER_MODE_OBSERVE_ONLY" not in get_cap_case.split("#else", 1)[1],
        "health_flags_bounded": "capabilities->HealthFlags=TAMANDUA_HEALTH_DRIVER_LOADED;" in health_code
        and "if(g_Globals.ServerPort!=NULL){capabilities->HealthFlags|=TAMANDUA_HEALTH_COMM_PORT_READY;}" in health_code
        and "if(TAMANDUA_LAB_ENABLE_TELEMETRY){capabilities->HealthFlags|=TAMANDUA_HEALTH_TELEMETRY_READY;}" in health_code
        and "0xFFFFFFFF" not in health_code,
        "dispatcher_fail_closed": _read_only_dispatcher_is_closed(dispatcher),
        "protection_init_disabled": _guarded_by(
            protection, "TAMANDUA_DRIVER_OBSERVE_ONLY", "return STATUS_NOT_SUPPORTED;"
        ),
        "watchdog_init_disabled": _guarded_by(
            watchdog, "TAMANDUA_DRIVER_OBSERVE_ONLY", "return STATUS_NOT_SUPPORTED;"
        ),
        "callbacks_non_mutating": _observe_branch_safe(precreate, "return FLT_PREOP_SUCCESS_NO_CALLBACK;", ("IoStatus", "FLT_PREOP_COMPLETE", "DesiredAccess", "CreationStatus"))
        and _observe_branch_safe(prewrite, "return FLT_PREOP_SUCCESS_NO_CALLBACK;", ("IoStatus", "FLT_PREOP_COMPLETE", "DesiredAccess", "CreationStatus"))
        and _observe_branch_safe(preset, "return FLT_PREOP_SUCCESS_NO_CALLBACK;", ("IoStatus", "FLT_PREOP_COMPLETE", "DesiredAccess", "CreationStatus"))
        and _observe_branch_safe(protection_preop, "return OB_PREOP_SUCCESS;", ("DesiredAccess =", "IoStatus", "CreationStatus", "STATUS_ACCESS_DENIED"))
        and re.search(r"\bCreateInfo\s*->\s*CreationStatus\s*=", process_notify_observe) is None
        and re.search(r"\bOperationInformation\s*->.*?DesiredAccess\s*=", protection_preop_observe, re.DOTALL) is None
        and _guarded_by(precreate, "TAMANDUA_LAB_ENABLE_MINIFILTER_SCAN", "Data->IoStatus.Status = STATUS_ACCESS_DENIED;")
        and _guarded_by(precreate, "TAMANDUA_LAB_ENABLE_MINIFILTER_SCAN", "return FLT_PREOP_COMPLETE;")
        and _guarded_by(process_notify, "!TAMANDUA_DRIVER_OBSERVE_ONLY", "CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;")
        and precreate_code.count("Data->IoStatus.Status = STATUS_ACCESS_DENIED;") == 1,
        "scan_port_compile_out": re.sub(r"\s+", "", driver_macros.get("TAMANDUA_LAB_ENABLE_MINIFILTER_SCAN", "")) == expected_control_expressions["TAMANDUA_LAB_ENABLE_MINIFILTER_SCAN"]
        and _guarded_by(main, "TAMANDUA_LAB_ENABLE_MINIFILTER_SCAN", "TamanduaMinifilterScanInit(g_Globals.Filter);"),
        "no_runtime_toggle": "TAMANDUA_DRIVER_OBSERVE_ONLY" not in user_api
        and "TAMANDUA_DRIVER_OBSERVE_ONLY" not in protocol,
    }
    failures = [name for name, passed in checks.items() if not passed]
    return {
        "schema_version": 2,
        "profile": "windows_driver_observe_only_static_contract",
        "evidence_class": "local_static_source_contract",
        "execution": {"driver_built": False, "driver_loaded": False, "vm_mutated": False},
        "checks": checks,
        "failures": failures,
        "status": "PASS" if not failures else "HOLD",
        "claims": {"runtime_validated": False, "efficacy_validated": False, "production_ready": False},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    args = parser.parse_args()
    result = validate(args.root.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
