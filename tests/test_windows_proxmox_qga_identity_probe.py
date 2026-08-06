import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "detection_validation" / "scripts" / "windows_proxmox_qga_identity_probe.py"
SPEC = importlib.util.spec_from_file_location("windows_proxmox_qga_identity_probe_focused", SCRIPT)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


@pytest.fixture(autouse=True)
def canonical_system_curl(monkeypatch, tmp_path):
    windows_root = tmp_path / "Windows"
    curl_path = windows_root / "System32" / "curl.exe"
    curl_path.parent.mkdir(parents=True)
    curl_path.write_bytes(b"test curl")
    monkeypatch.setattr(probe, "_trusted_windows_root", lambda: windows_root)
    monkeypatch.setenv("SystemRoot", str(windows_root))
    return curl_path.resolve()


def args(password: str = "p@ss word") -> SimpleNamespace:
    return SimpleNamespace(
        proxmox_host="proxmox.test",
        proxmox_user="root@pam",
        proxmox_password=password,
        http_timeout_seconds=3,
    )


class FailingSession:
    verify = True
    trust_env = True

    def post(self, *_args, **_kwargs):
        raise requests.exceptions.SSLError(FileNotFoundError("Windows certificate provider failed"))


def test_windows_transport_failure_falls_back_with_secrets_only_on_stdin(monkeypatch, canonical_system_curl):
    password = 's3cr et"\\value'
    ticket = "PVE:root@pam!secret-ticket"
    csrf = "csrf-secret"
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if len(calls) == 1:
            body = json.dumps({"data": {"ticket": ticket, "CSRFPreventionToken": csrf}})
        else:
            body = json.dumps({"data": {"result": {"host-name": "WIN-TEMPLATE"}}})
        return SimpleNamespace(returncode=0, stdout=f"{body}\n200", stderr="")

    monkeypatch.setattr(probe.requests, "Session", FailingSession)
    monkeypatch.setattr(probe, "_windows_curl_fallback_enabled", lambda: True)
    monkeypatch.setattr(probe.subprocess, "run", fake_run)
    monkeypatch.setenv("TAMANDUA_PROXMOX_PASSWORD", "inherited-password")
    monkeypatch.setenv("TAMANDUA_PROXMOX_TICKET", "inherited-ticket")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy-user:proxy-secret@proxy.test")
    monkeypatch.setenv("ALL_PROXY", "socks5://proxy.test")

    transport, auth = probe.login(args(password))
    assert isinstance(transport, probe.CurlReadOnlyTransport)
    assert auth == {"authenticated": True, "status": 200}
    result = probe.request_json(transport, "https://proxmox.test:8006/api2/json", "/version", 3)

    assert result["ok"] is True
    assert len(calls) == 2
    for argv, kwargs in calls:
        assert argv == [str(canonical_system_curl), "--disable", "--config", "-"]
        assert password not in argv
        assert ticket not in argv
        assert csrf not in argv
        assert kwargs["shell"] is False
        assert kwargs["timeout"] == 5
        assert kwargs["env"] == {
            "SystemRoot": str(canonical_system_curl.parents[1]),
            "WINDIR": str(canonical_system_curl.parents[1]),
        }
        assert not any("TAMANDUA" in key.upper() or "PROXY" in key.upper() for key in kwargs["env"])
    assert f"password={probe._curl_config_value(password)}" in calls[0][1]["input"]
    assert ticket not in calls[0][1]["input"]
    assert ticket in calls[1][1]["input"]
    assert password not in calls[1][1]["input"]
    assert csrf not in calls[1][1]["input"]
    assert password not in repr(auth)
    assert ticket not in repr(auth)
    assert ticket not in repr(transport)


def test_non_windows_preserves_requests_failure_without_curl(monkeypatch):
    monkeypatch.setattr(probe.requests, "Session", FailingSession)
    monkeypatch.setattr(probe, "_windows_curl_fallback_enabled", lambda: False)
    monkeypatch.setattr(
        probe.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("curl fallback must remain Windows-only"),
    )

    transport, auth = probe.login(args())

    assert transport is None
    assert auth["authenticated"] is False
    assert "SSLError" in auth["error"]


@pytest.mark.parametrize(
    "failure",
    [
        requests.ConnectionError("connection failed"),
        requests.exceptions.SSLError("TLS failed"),
        FileNotFoundError("certificate provider failed"),
    ],
)
def test_expected_windows_failures_are_fallback_eligible(failure):
    assert probe._is_windows_transport_failure(failure) is True


def test_curl_timeout_is_bounded_and_does_not_report_secret(monkeypatch, canonical_system_curl):
    password = "timeout-secret"
    captured = {}

    def timeout_run(argv, **kwargs):
        captured.update({"argv": argv, **kwargs})
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(probe.requests, "Session", FailingSession)
    monkeypatch.setattr(probe, "_windows_curl_fallback_enabled", lambda: True)
    monkeypatch.setattr(probe.subprocess, "run", timeout_run)

    transport, auth = probe.login(args(password))

    assert transport is None
    assert auth == {"authenticated": False, "status": None, "error": "curl_transport_timeout"}
    assert captured["argv"] == [str(canonical_system_curl), "--disable", "--config", "-"]
    assert captured["timeout"] == 5
    assert "connect-timeout = 3" in captured["input"]
    assert "max-time = 3" in captured["input"]
    assert password not in json.dumps(auth)


def test_curl_error_redacts_password_and_uses_no_shell_interpolation(monkeypatch, canonical_system_curl):
    password = "diagnostic-secret"
    captured = {}

    def failed_run(argv, **kwargs):
        captured.update({"argv": argv, **kwargs})
        return SimpleNamespace(returncode=35, stdout="", stderr=f"TLS failed near {password}")

    monkeypatch.setattr(probe.requests, "Session", FailingSession)
    monkeypatch.setattr(probe, "_windows_curl_fallback_enabled", lambda: True)
    monkeypatch.setattr(probe.subprocess, "run", failed_run)

    transport, auth = probe.login(args(password))

    assert transport is None
    assert captured["argv"] == [str(canonical_system_curl), "--disable", "--config", "-"]
    assert captured["shell"] is False
    assert password not in json.dumps(auth)
    assert auth["error"] == "curl_transport_error: exit_35"


def test_curl_get_error_does_not_report_ticket(monkeypatch, canonical_system_curl):
    ticket = "private-ticket"

    def failed_run(argv, **kwargs):
        assert argv == [str(canonical_system_curl), "--disable", "--config", "-"]
        assert ticket not in argv
        assert ticket in kwargs["input"]
        return SimpleNamespace(returncode=35, stdout="", stderr=f"header contained {ticket}")

    monkeypatch.setattr(probe.subprocess, "run", failed_run)

    result = probe.CurlReadOnlyTransport(ticket).get_json("https://proxmox.test", "/version", 3)

    assert ticket not in json.dumps(result)
    assert result["error"] == "curl_transport_error: exit_35"


def test_missing_canonical_system_curl_fails_closed(monkeypatch, canonical_system_curl):
    canonical_system_curl.unlink()
    monkeypatch.setattr(
        probe.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("bare PATH curl must not be attempted"),
    )

    result = probe._run_curl("silent\n", 3, ())

    assert result == {
        "ok": False,
        "status": None,
        "error": "curl_transport_unavailable: canonical_system_curl_missing_or_untrusted",
    }


def test_untrusted_system_root_curl_fails_closed(monkeypatch, tmp_path):
    untrusted_root = tmp_path / "UntrustedWindows"
    fake_curl = untrusted_root / "System32" / "curl.exe"
    fake_curl.parent.mkdir(parents=True)
    fake_curl.write_bytes(b"untrusted curl")
    monkeypatch.setenv("SystemRoot", str(untrusted_root))
    monkeypatch.setattr(
        probe.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("untrusted SystemRoot curl must not be executed"),
    )

    result = probe._run_curl("silent\n", 3, ())

    assert result["ok"] is False
    assert result["error"] == "curl_transport_unavailable: canonical_system_curl_missing_or_untrusted"


def test_requests_auth_error_body_is_redacted(monkeypatch):
    password = "body-secret"

    class RejectedSession:
        verify = True
        trust_env = True

        def post(self, *_args, **_kwargs):
            return SimpleNamespace(ok=False, status_code=401, text=f"bad password {password}")

    monkeypatch.setattr(probe.requests, "Session", RejectedSession)

    transport, auth = probe.login(args(password))

    assert transport is None
    assert auth["status"] == 401
    assert password not in json.dumps(auth)
    assert auth["error"] == "proxmox_login_rejected"


def test_fallback_build_report_preserves_schema_and_excludes_auth_material(monkeypatch):
    password = "report-password"
    ticket = "report-ticket"
    csrf = "report-csrf"

    def fake_run(_argv, **kwargs):
        config = kwargs["input"]
        if "/access/ticket" in config:
            body = {"data": {"ticket": ticket, "CSRFPreventionToken": csrf}}
        elif "/status/current" in config:
            body = {"data": {"name": "win-template", "status": "running", "agent": 1}}
        elif "/get-host-name" in config:
            body = {"data": {"result": {"host-name": "WIN-TEMPLATE"}}}
        else:
            body = {"data": {"result": []}}
        return SimpleNamespace(returncode=0, stdout=f"{json.dumps(body)}\n200", stderr="")

    monkeypatch.setattr(probe.requests, "Session", FailingSession)
    monkeypatch.setattr(probe, "_windows_curl_fallback_enabled", lambda: True)
    monkeypatch.setattr(probe.subprocess, "run", fake_run)
    monkeypatch.setattr(probe, "git_snapshot", lambda: {"commit": "abc", "commit_short": "abc", "dirty": False, "status_short": []})
    report_args = args(password)
    report_args.proxmox_node = "node-a"
    report_args.vmids = "1521"
    report_args.expected_hostnames = "WIN-TEMPLATE"

    report = probe.build_report(report_args)
    serialized = json.dumps(report)

    assert report["schema_version"] == 1
    assert report["auth"] == {"authenticated": True, "status": 200}
    assert report["quality_gate"]["passed"] is True
    assert report["vmids"][0]["guest_hostname"] == "WIN-TEMPLATE"
    assert password not in serialized
    assert ticket not in serialized
    assert csrf not in serialized
