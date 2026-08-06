import importlib.util
import shutil
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/anti_cheat_windows_driver_observe_only_static_gate.py"
SPEC = importlib.util.spec_from_file_location("observe_gate", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_current_source_contract_passes_without_execution():
    result = MODULE.validate(ROOT)
    assert result["status"] == "PASS"
    assert all(result["checks"].values())
    assert result["execution"] == {"driver_built": False, "driver_loaded": False, "vm_mutated": False}
    assert not any(result["claims"].values())


@pytest.mark.parametrize(
    ("relative", "old", "new", "failed_check"),
    [
        ("apps/tamandua_driver/Makefile", "TAMANDUA_DRIVER_OBSERVE_ONLY = 0", "TAMANDUA_DRIVER_OBSERVE_ONLY = 1", "build_default_is_normal"),
        ("apps/tamandua_driver/src/driver.h", "#define TAMANDUA_LAB_ENABLE_WFP                (!TAMANDUA_DRIVER_OBSERVE_ONLY", "#define TAMANDUA_LAB_ENABLE_WFP                (TAMANDUA_DRIVER_OBSERVE_ONLY", "controls_compile_out"),
        ("apps/tamandua_driver/src/tamandua.h", "#define TAMANDUA_CAPABILITY_CONTRACT_VERSION_V2       2", "#define TAMANDUA_CAPABILITY_CONTRACT_VERSION_V2       1", "capability_v2_abi"),
        ("apps/tamandua_driver/src/main.c", "capabilities->ActiveFlags = 0;", "capabilities->ActiveFlags = 1;", "complete_zero_control_receipt"),
        ("apps/tamandua_driver/src/main.c", "TAMANDUA_CAP_RESERVED_COMMAND_POLICY_FLAGS] =\n                    TAMANDUA_OBSERVE_COMMAND_POLICY_ALL;", "TAMANDUA_CAP_RESERVED_COMMAND_POLICY_FLAGS] = 0;", "complete_zero_control_receipt"),
        ("apps/tamandua_driver/src/main.c", "case TAMANDUA_CMD_GET_VERSION:", "case TAMANDUA_CMD_REGISTER_AGENT:\n        case TAMANDUA_CMD_GET_VERSION:", "dispatcher_fail_closed"),
        ("apps/tamandua_driver/src/watchdog.c", "return STATUS_NOT_SUPPORTED;\n#endif", "return STATUS_SUCCESS;\n#endif", "watchdog_init_disabled"),
        ("apps/tamandua_driver/src/protection.c", "return OB_PREOP_SUCCESS;\n#else", "/* observe-only return removed */\n#else", "callbacks_non_mutating"),
        ("apps/tamandua_driver/src/main.c", "#if TAMANDUA_LAB_ENABLE_MINIFILTER_SCAN\n        //", "#if 1\n        //", "callbacks_non_mutating"),
        ("apps/tamandua_driver/src/main.c", "#if !TAMANDUA_DRIVER_OBSERVE_ONLY\n            if (g_Globals.Config.EnableRansomwareProtection)", "#if 1\n            if (g_Globals.Config.EnableRansomwareProtection)", "callbacks_non_mutating"),
        ("apps/tamandua_driver/src/main.c", "#if !TAMANDUA_DRIVER_OBSERVE_ONLY\n            if (g_Globals.Config.EnableRansomwareProtection)", "#if !TAMANDUA_DRIVER_OBSERVE_ONLY\n#elif TAMANDUA_UNKNOWN_POLICY\n            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;\n            if (g_Globals.Config.EnableRansomwareProtection)", "callbacks_non_mutating"),
        ("apps/tamandua_driver/src/main.c", "// Observe-only pre-write callbacks cannot change IoStatus or block I/O.\n    return FLT_PREOP_SUCCESS_NO_CALLBACK;", "Data->IoStatus.Status = STATUS_ACCESS_DENIED;\n    return FLT_PREOP_SUCCESS_NO_CALLBACK;", "callbacks_non_mutating"),
        ("apps/tamandua_driver/src/protection.c", "// Invariant: DesiredAccess is never rewritten in observe-only artifacts.\n    return OB_PREOP_SUCCESS;", "OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;\n    return OB_PREOP_SUCCESS;", "callbacks_non_mutating"),
        ("apps/tamandua_driver/src/driver.h", "#define TAMANDUA_LAB_ENABLE_MINIFILTER_SCAN    (!TAMANDUA_DRIVER_OBSERVE_ONLY && (TAMANDUA_DRIVER_LAB_LEVEL >= 157))", "#define TAMANDUA_LAB_ENABLE_MINIFILTER_SCAN    (!TAMANDUA_DRIVER_OBSERVE_ONLY && (TAMANDUA_DRIVER_LAB_LEVEL >= 157)) || 1", "controls_compile_out"),
        ("apps/tamandua_driver/src/driver.h", "#error TAMANDUA_DRIVER_OBSERVE_ONLY must be exactly 0 or 1", "// #error TAMANDUA_DRIVER_OBSERVE_ONLY must be exactly 0 or 1", "build_default_is_normal"),
        ("apps/tamandua_driver/src/main.c", "capabilities->HealthFlags = TAMANDUA_HEALTH_DRIVER_LOADED;", "capabilities->HealthFlags = 0xFFFFFFFF;", "health_flags_bounded"),
        ("apps/tamandua_driver/src/usermode_api.h", "    ULONG HealthFlags;\n    ULONG Reserved[8];", "    USHORT HealthFlags;\n    ULONG Reserved[8];", "capability_v2_abi"),
        ("apps/tamandua_driver/src/driver.h", "#endif // _TAMANDUA_DRIVER_H_", "#endif // _TAMANDUA_DRIVER_H_\n#else", "preprocessor_structure_valid"),
        ("apps/tamandua_driver/src/main.c", "        case TAMANDUA_CMD_CONFIG_GET:", "        case TAMANDUA_CMD_GET_VERSION:\n        case TAMANDUA_CMD_CONFIG_GET:", "dispatcher_fail_closed"),
        ("apps/tamandua_driver/src/main.c", "        case TAMANDUA_CMD_GET_CAPABILITIES:\n#if TAMANDUA_DRIVER_OBSERVE_ONLY", "        case TAMANDUA_CMD_GET_CAPABILITIES:\n#if 1", "observe_receipt_isolated"),
        ("apps/tamandua_driver/src/main.c", "            }\n#endif\n\n#if TAMANDUA_NTDLL_GUARD", "            }\n\n#if TAMANDUA_NTDLL_GUARD", "preprocessor_structure_valid"),
    ],
)
def test_adversarial_source_mutation_fails_closed(tmp_path, relative, old, new, failed_check):
    for rel in MODULE.FILES.values():
        destination = tmp_path / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, destination)
    target = tmp_path / relative
    text = target.read_text(encoding="utf-8")
    assert old in text
    target.write_text(text.replace(old, new, 1), encoding="utf-8")
    result = MODULE.validate(tmp_path)
    assert result["status"] == "HOLD"
    assert failed_check in result["failures"]
