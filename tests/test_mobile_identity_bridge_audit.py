from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "mobile_identity_bridge_audit.py"
)
SPEC = importlib.util.spec_from_file_location("mobile_identity_bridge_audit", SCRIPT)
assert SPEC and SPEC.loader
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def write_controller(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "mobile_controller.ex"
    path.write_text(source, encoding="utf-8")
    return path


def valid_source() -> str:
    return """
defmodule MobileController do
  alias TamanduaServer.Mobile.MobileDeviceIdentity

  def register(conn, params) do
    legacy_identity_mutation(org, [params["device_id"]], fn ->
      Mobile.register_device(params)
    end)
  end

  def update(conn, params) do
    legacy_identity_mutation(org, [params["device_id"]], fn ->
      Mobile.update_device(device, params)
    end)
  end

  def create_v2(conn, params) do
    legacy_identity_mutation(org, [params["device_id"]], fn ->
      {:ok, device}
    end)
  end

  def update_v2(conn, params) do
    legacy_identity_mutation(org, [params["device_id"]], fn ->
      {:ok, device}
    end)
  end

  def enroll_device(conn, _params) do
    device_identity_proof_required(conn)
  end

  def ingest_app_guard_event(conn, _params), do: conn
  def ingest_events(conn, _params), do: conn
  def create_command(conn, _params), do: Repo.insert(command_changeset)

  defp legacy_identity_mutation(org, ids, callback) do
    MobileDeviceIdentity.with_legacy_unbound(org, ids, callback)
  end

  defp device_identity_proof_required(conn), do: {:error, :device_identity_proof_required}
end
"""


def test_valid_controller_marks_known_bridges_owned(tmp_path: Path):
    result = audit.evaluate(write_controller(tmp_path, valid_source()))

    assert result["ok"] is True
    assert result["reasons"] == []
    assert {bridge["name"] for bridge in result["guarded_bridges"]} == {
        "register",
        "update",
        "create_v2",
        "update_v2",
        "enroll_device",
    }


def test_read_only_app_guard_bridge_cannot_mutate_identity(tmp_path: Path):
    source = valid_source().replace(
        "def ingest_app_guard_event(conn, _params), do: conn",
        "def ingest_app_guard_event(conn, params), do: Mobile.register_device(params)",
    )
    result = audit.evaluate(write_controller(tmp_path, source))

    assert result["ok"] is False
    assert "read_only_bridge_mutates_identity:ingest_app_guard_event" in result["reasons"]


def test_guarded_bridge_requires_identity_wrapper(tmp_path: Path):
    source = valid_source().replace("legacy_identity_mutation(org, [params[\"device_id\"]], fn ->", "fn ->", 1)
    result = audit.evaluate(write_controller(tmp_path, source))

    assert result["ok"] is False
    assert "guarded_bridge_incomplete:register" in result["reasons"]
