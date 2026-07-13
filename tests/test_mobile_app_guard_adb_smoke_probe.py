from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "mobile_app_guard_adb_smoke_probe.py"

spec = importlib.util.spec_from_file_location("mobile_app_guard_adb_smoke_probe", SCRIPT)
assert spec is not None
probe = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(probe)


def completed(args: Sequence[str], stdout: str, returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(list(args), returncode, stdout=stdout, stderr="")


def test_adb_smoke_probe_collects_read_only_physical_device_smoke() -> None:
    calls: list[list[str]] = []

    def fake_runner(args: Sequence[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        calls.append(list(args))
        joined = " ".join(args)
        if "dumpsys package com.tamandua.mobile" in joined:
            return completed(
                args,
                """
                Package [com.tamandua.mobile] (abc):
                  codePath=/data/app/~~hash/com.tamandua.mobile/base.apk
                  versionCode=42 minSdk=26 targetSdk=35
                  versionName=1.2.3
                  firstInstallTime=2026-07-07 10:00:00
                  lastUpdateTime=2026-07-07 10:05:00
                """,
            )
        if "pidof com.tamandua.mobile" in joined:
            return completed(args, "12345\n")
        if "dumpsys activity services com.tamandua.mobile" in joined:
            return completed(
                args,
                "ServiceRecord{1 com.tamandua.mobile/.EndpointService}\n  foreground=true\n",
            )
        if "uiautomator dump /sdcard/tamandua_app_guard_smoke.xml" in joined:
            return completed(args, "UI hierarchy dumped to: /sdcard/tamandua_app_guard_smoke.xml\n")
        if "cat /sdcard/tamandua_app_guard_smoke.xml" in joined:
            return completed(args, '<node text="Tamandua App Guard Protected Device"/>')
        if "logcat -d -t 500" in joined:
            return completed(args, "I/Tamandua: App Guard physical smoke ready\n")
        raise AssertionError(f"unexpected adb command: {joined}")

    exit_code, report = probe.collect_smoke_evidence(
        "com.tamandua.mobile",
        adb="adb",
        serial="device-1",
        device_id="lab-device-android-001",
        app_build_id="app-build-20260707.1",
        sdk_build_id="sdk-mobile-20260707.1",
        event_ids=["evt-smoke-001"],
        server_request_ids=["req-smoke-001"],
        ui_strings=["Tamandua", "App Guard", "Missing"],
        logcat_grep=["physical smoke"],
        runner=fake_runner,
    )

    assert exit_code == 0
    assert report["evidence_class"] == "physical_device_smoke"
    assert report["claim_status"] == "physical_device_smoke"
    assert report["read_only_low_impact"] is True
    assert report["device_id"] == "lab-device-android-001"
    assert report["app_build_id"] == "app-build-20260707.1"
    assert report["sdk_build_id"] == "sdk-mobile-20260707.1"
    assert report["event_ids"] == ["evt-smoke-001"]
    assert report["server_request_ids"] == ["req-smoke-001"]
    assert report["package"]["installed"] is True
    assert report["package"]["version_name"] == "1.2.3"
    assert report["package"]["version_code"] == "42"
    assert report["process"]["running"] is True
    assert report["foreground_service_state"]["foreground_service_observed"] is True
    assert report["ui_dump_key_strings"]["matched_strings"] == {"Tamandua": 1, "App Guard": 1}
    assert report["logcat_grep"]["matches"][0]["pattern"] == "physical smoke"
    assert set(report["evidence_buckets"]) == {
        "implemented_contract",
        "physical_device_smoke",
        "roadmap_device_evidence_required",
    }
    assert report["failure_reasons"] == []
    assert report["rollback"]["required"] is False
    assert report["privacy_boundary"]["metadata_only"] is True
    assert report["privacy_boundary"]["contains_pii"] is False
    assert all(call[:3] == ["adb", "-s", "device-1"] for call in calls)
    assert not any("install" in call or "am" in call for call in calls)


def test_adb_smoke_probe_reports_missing_package_as_no_evidence() -> None:
    def fake_runner(args: Sequence[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        return completed(args, "", returncode=0)

    exit_code, report = probe.collect_smoke_evidence(
        "com.tamandua.missing",
        runner=fake_runner,
    )

    assert exit_code == 1
    assert report["package"]["installed"] is False
    assert "package com.tamandua.missing was not observed as installed" in report["errors"]
    assert report["failure_reasons"] == report["errors"]
