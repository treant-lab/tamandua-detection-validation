import importlib.util
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "detection_validation" / "scripts" / "windows_qga_start_foreground_agent.py"
SPEC = importlib.util.spec_from_file_location("windows_qga_start_foreground_agent", SCRIPT)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def test_direct_guest_exec_keeps_token_out_of_process_argv(monkeypatch):
    sentinel = "TOKEN-SENTINEL-DO-NOT-LOG"
    captured = {}
    args = SimpleNamespace(
        proxmox_node="node-a",
        vmid="1521",
        qga_exec_start_attempts=1,
        guest_exec_timeout_seconds=5,
    )

    def fake_start(_session, _args, method, path, **kwargs):
        captured.update({"method": method, "path": path, **kwargs})
        return {"ok": True, "body": {"data": {"pid": 42}}}

    monkeypatch.setattr(probe.qga, "request_json_retry", fake_start)
    monkeypatch.setattr(
        probe.qga,
        "request_json",
        lambda *_args, **_kwargs: {
            "ok": True,
            "body": {
                "data": {
                    "exited": True,
                    "exitcode": 1,
                    "out-data": f"remote reflected {sentinel}",
                    "err-data": sentinel,
                }
            },
        },
    )
    monkeypatch.setattr(probe.qga, "decode_qga", lambda value: value or "")
    monkeypatch.setattr(probe.time, "sleep", lambda _seconds: None)

    result = probe.guest_exec_program(
        object(),
        args,
        r"D:\Tamandua\tamandua-agent.exe",
        ["install", "--token-stdin", "--server", "wss://example.invalid"],
        sentinel + "\n",
        sensitive_values=(sentinel,),
    )

    request_data = captured["data"]
    command_values = [value for key, value in request_data if key == "command"]
    stdin_values = [value for key, value in request_data if key == "input-data"]
    assert all(sentinel not in value for value in command_values)
    assert command_values[1:3] == ["install", "--token-stdin"]
    assert stdin_values == [sentinel + "\n"]
    assert sentinel not in result["stdout"]
    assert sentinel not in result["stderr"]


def test_qga_install_source_has_no_legacy_token_argument():
    source = SCRIPT.read_text(encoding="utf-8")
    assert '"--token-stdin"' in source
    assert "install --token " not in source
    assert 'add_argument("--installation-token")' not in source
