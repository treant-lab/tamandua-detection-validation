import importlib.util
import io
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def assert_no_legacy_token_option(source: str, label: str) -> None:
    legacy = re.compile(r"--token(?=$|[\s\"',])")
    match = legacy.search(source)
    assert match is None, f"{label} still exposes the legacy token argv option"


def load_python(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_active_install_commands_keep_enrollment_secret_out_of_argv():
    active_surfaces = {
        "DeployAgent": read("apps/tamandua_server/assets/src/pages/DeployAgent.tsx"),
        "WinRM rollout": read("deploy/scripts/deploy_lab_agents.py"),
        "PowerShell lab installer": read("deploy/scripts/install_lab_agent.ps1"),
        "PowerShell QGA wrapper": read("deploy/scripts/proxmox/deploy-lab-agent-qga.ps1"),
        "Python QGA probe": read(
            "tools/detection_validation/scripts/windows_qga_start_foreground_agent.py"
        ),
    }

    for label, source in active_surfaces.items():
        assert_no_legacy_token_option(source, label)

    assert "--token-stdin" in active_surfaces["WinRM rollout"]
    assert "--token-stdin" in active_surfaces["PowerShell lab installer"]
    assert "ReadBlock($tokenBuffer, 0, $tokenBuffer.Length)" in active_surfaces[
        "PowerShell lab installer"
    ]
    assert "New-Object char[] 4097" in active_surfaces["PowerShell lab installer"]
    assert "ReadToEnd()" not in active_surfaces["PowerShell lab installer"]
    assert "guest_exec_program" in active_surfaces["Python QGA probe"]
    assert "wrapper deliberately accepts no installation-token argument" in active_surfaces[
        "PowerShell QGA wrapper"
    ]


def test_active_docs_do_not_teach_secret_bearing_agent_or_msi_arguments():
    docs = {
        "install": read("docs/INSTALL.md"),
        "quickstart": read("docs/apps/tamandua_agent/QUICKSTART_SPLIT_PROCESS.md"),
        "architecture": read("docs/apps/tamandua_agent/SPLIT_PROCESS_ARCHITECTURE.md"),
        "website enrollment": read("website/src/content/docs/agent/enrollment.md"),
        "website Windows": read("website/src/content/docs/agent/install-windows.md"),
        "website Linux": read("website/src/content/docs/agent/install-linux.md"),
        "website macOS": read("website/src/content/docs/agent/install-macos.md"),
        "website quick start": read("website/src/content/docs/getting-started/quick-start.md"),
        "website troubleshooting": read(
            "website/src/content/docs/troubleshooting/agent-issues.md"
        ),
        "MSI README": read("apps/tamandua_agent/installer/windows/README.md"),
        "lab rollout": read("deploy/scripts/README-lab-light-deploy.md"),
        "response harness": read("docs/harnesses/RESPONSE_E2E_HARNESS.md"),
    }

    forbidden_msi_properties = re.compile(r"(?:AGENT_TOKEN|ENROLLMENT_TOKEN)\s*=")
    for label, source in docs.items():
        assert_no_legacy_token_option(source, label)
        assert forbidden_msi_properties.search(source) is None, (
            f"{label} still teaches secret-bearing MSI properties"
        )

    assert "--validate-enrollment-token" not in docs["website troubleshooting"]


def test_winrm_launcher_parser_matches_agent_total_input_limit(monkeypatch):
    rollout = load_python("deploy/scripts/deploy_lab_agents.py", "deploy_lab_agents_contract")

    class RedirectedInput:
        def __init__(self, payload: bytes):
            self.buffer = io.BytesIO(payload)

        @staticmethod
        def isatty() -> bool:
            return False

    monkeypatch.setattr(rollout.sys, "stdin", RedirectedInput(b"x" * 4096))
    assert len(rollout.read_token_stdin()) == 4096

    monkeypatch.setattr(rollout.sys, "stdin", RedirectedInput(b"x" * 4095 + b"\n"))
    assert len(rollout.read_token_stdin()) == 4095

    monkeypatch.setattr(rollout.sys, "stdin", RedirectedInput(b"x" * 4096 + b"\n"))
    try:
        rollout.read_token_stdin()
    except ValueError as error:
        assert "4096-byte limit" in str(error)
    else:
        raise AssertionError("launcher accepted input beyond the agent's total byte limit")
