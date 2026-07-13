from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


from inprocess_gate_cli import run_cli_in_process
from response_executor_direct_call_guard import DOCUMENTED_ALLOWLIST


ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / "tools" / "detection_validation"
SCRIPT = TOOLS / "scripts" / "response_executor_direct_call_guard.py"
SERVER_LIB = ROOT / "apps" / "tamandua_server" / "lib"


def run_guard(*args: str):
    return run_cli_in_process(SCRIPT, list(args))


def write_doc(path: Path, entries: list[str]) -> None:
    path.write_text("\n".join(f"- `{entry}`" for entry in entries), encoding="utf-8")


def test_real_server_tree_passes_static_guard() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--scan-root", str(SERVER_LIB), "--json"],
        cwd=TOOLS,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["guard_type"] == "local_static_migration_guard"
    assert summary["violations_count"] == 0
    assert "does not enforce runtime behavior" in summary["claim_boundary"]


def test_rejects_new_fully_qualified_direct_call_outside_allowlist(tmp_path: Path) -> None:
    source = tmp_path / "apps" / "tamandua_server" / "lib" / "tamandua_server" / "new_direct.ex"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
defmodule TamanduaServer.NewDirect do
  def run(agent_id), do: TamanduaServer.Response.Executor.isolate_host(agent_id)
end
""",
        encoding="utf-8",
    )
    allowlist_doc = tmp_path / "allowlist.md"
    write_doc(allowlist_doc, [])

    completed = run_guard("--scan-root", source.parent, "--allowlist-doc", allowlist_doc)

    assert completed.returncode == 1
    assert "new_direct.ex:3" in completed.stdout
    assert "fully_qualified_call" in completed.stdout


def test_rejects_alias_and_local_executor_call_outside_allowlist(tmp_path: Path) -> None:
    source = tmp_path / "apps" / "tamandua_server" / "lib" / "tamandua_server" / "alias_direct.ex"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
defmodule TamanduaServer.AliasDirect do
  alias TamanduaServer.Response.Executor
  def run(agent_id), do: Executor.kill_process(agent_id, 123)
end
""",
        encoding="utf-8",
    )
    allowlist_doc = tmp_path / "allowlist.md"
    write_doc(allowlist_doc, [])

    completed = run_guard("--scan-root", source.parent, "--allowlist-doc", allowlist_doc, "--json")

    assert completed.returncode == 1
    summary = json.loads(completed.stdout)
    kinds = {violation["kind"] for violation in summary["violations"]}
    assert {"executor_alias", "alias_call:Executor"}.issubset(kinds)


def test_rejects_renamed_alias_call_outside_allowlist(tmp_path: Path) -> None:
    source = tmp_path / "apps" / "tamandua_server" / "lib" / "tamandua_server" / "renamed_alias.ex"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
defmodule TamanduaServer.RenamedAlias do
  alias TamanduaServer.Response.Executor, as: ResponseExecutor
  def run(agent_id), do: ResponseExecutor.quarantine_file(agent_id, "/tmp/a")
end
""",
        encoding="utf-8",
    )
    allowlist_doc = tmp_path / "allowlist.md"
    write_doc(allowlist_doc, [])

    completed = run_guard("--scan-root", source.parent, "--allowlist-doc", allowlist_doc, "--json")

    assert completed.returncode == 1
    summary = json.loads(completed.stdout)
    kinds = {violation["kind"] for violation in summary["violations"]}
    assert {"executor_alias", "alias_call:ResponseExecutor"}.issubset(kinds)


def test_rejects_grouped_executor_alias_call_outside_allowlist(tmp_path: Path) -> None:
    source = tmp_path / "apps" / "tamandua_server" / "lib" / "tamandua_server" / "grouped_alias.ex"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
defmodule TamanduaServer.GroupedAlias do
  alias TamanduaServer.Response.{Executor, Other}
  def run(agent_id), do: Executor.isolate_host(agent_id)
end
""",
        encoding="utf-8",
    )
    allowlist_doc = tmp_path / "allowlist.md"
    write_doc(allowlist_doc, [])

    completed = run_guard("--scan-root", source.parent, "--allowlist-doc", allowlist_doc, "--json")

    assert completed.returncode == 1
    summary = json.loads(completed.stdout)
    kinds = {violation["kind"] for violation in summary["violations"]}
    assert {"executor_alias", "alias_call:Executor"}.issubset(kinds)


def test_ignores_grouped_response_alias_without_executor(tmp_path: Path) -> None:
    source = tmp_path / "apps" / "tamandua_server" / "lib" / "tamandua_server" / "other_alias.ex"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
defmodule TamanduaServer.OtherAlias do
  alias TamanduaServer.Response.{Other, Result}
  def run(value), do: Other.normalize(value)
end
""",
        encoding="utf-8",
    )
    allowlist_doc = tmp_path / "allowlist.md"
    write_doc(allowlist_doc, sorted(DOCUMENTED_ALLOWLIST))

    completed = run_guard("--scan-root", source.parent, "--allowlist-doc", allowlist_doc, "--json")

    assert completed.returncode == 0
    summary = json.loads(completed.stdout)
    assert summary["violations_count"] == 0


def test_allowlisted_file_requires_documented_allowlist_entry(tmp_path: Path) -> None:
    relative = "apps/tamandua_server/lib/tamandua_server/response/executor.ex"
    source = ROOT / relative
    allowlist_doc = tmp_path / "allowlist.md"
    allowlist_doc.write_text("# no entries\n", encoding="utf-8")

    completed = run_guard("--scan-root", source, "--allowlist-doc", allowlist_doc)

    assert completed.returncode == 1
    assert "allowlist entry not documented" in completed.stdout
    assert relative in completed.stdout


def test_documented_allowlist_entry_must_match_guard_allowlist(tmp_path: Path) -> None:
    relative = "apps/tamandua_server/lib/tamandua_server/response/executor.ex"
    stale = "apps/tamandua_server/lib/tamandua_server/response/stale_executor_call.ex"
    source = ROOT / relative
    allowlist_doc = tmp_path / "allowlist.md"
    write_doc(allowlist_doc, sorted([*DOCUMENTED_ALLOWLIST, stale]))

    completed = run_guard("--scan-root", source, "--allowlist-doc", allowlist_doc)

    assert completed.returncode == 1
    assert "documented allowlist entry not present in guard allowlist" in completed.stdout
    assert stale in completed.stdout
