import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional local convenience
    def load_dotenv(*_args, **_kwargs) -> bool:
        return False

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = REPO_ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "validation-execution-preflight-probe"
DISPATCH_RESULTS_PROFILE_ID = "validation-dispatch-results-probe"
DEFAULT_OUTPUT_DIR = Path(tempfile.gettempdir()) / "tamandua-preflight-work-packages"
RESULT_PROFILE_PRIORITY = {
    "validation-execution-preflight-probe": 0,
    "windows-lab-execution-readiness-probe": 0,
    "windows-agent-connection-stability-probe": 1,
    "windows-proxmox-qga-readiness-probe": 2,
    "windows-proxmox-qga-file-diagnostics-probe": 3,
    "macos-backend-readiness-probe": 0,
    "atomic-t1047-lab-capability-probe": 0,
}
ALLOWED_COMMAND_PREFIXES = (
    "$Out = ",
    "python tools/detection_validation/",
    "powershell -File deploy/scripts/proxmox/run-macos-p0-smoke.ps1 ",
)
UNSAFE_COMMAND_TOKENS = (";", "|", "&", "`", "\r", "\n", ">", "<")


@contextmanager
def local_dotenv_environment():
    previous = os.environ.copy()
    load_dotenv(REPO_ROOT / ".env")
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def latest_preflight_path(runs_dir: Path = RUNS_DIR) -> Path:
    candidates = sorted(runs_dir.glob(f"*-{PROFILE_ID}.json"), key=lambda path: path.name)
    if not candidates:
        raise FileNotFoundError(f"no {PROFILE_ID} JSON artifacts found in {runs_dir}")
    return candidates[-1]


def preflight_packages(preflight_artifact: dict) -> list[dict]:
    packages = preflight_artifact.get("parallel_work_packages") or []
    if not isinstance(packages, list):
        raise ValueError("preflight artifact parallel_work_packages must be a list")
    return [package for package in packages if isinstance(package, dict)]


def validate_preflight_artifact(preflight_artifact: dict) -> None:
    if preflight_artifact.get("profile_id") != PROFILE_ID:
        raise ValueError(f"preflight artifact profile_id must be {PROFILE_ID}")
    claim_boundary = str(preflight_artifact.get("claim_boundary") or "")
    if "Local read-only scheduling preflight" not in claim_boundary:
        raise ValueError("preflight artifact claim_boundary is not the expected scheduling preflight boundary")
    packages = preflight_packages(preflight_artifact)
    if not packages:
        raise ValueError("preflight artifact has no parallel_work_packages")


def validate_dispatch_manifest_source(manifest: dict, runs_dir: Path = RUNS_DIR) -> None:
    source_preflight = manifest.get("source_preflight")
    if not source_preflight:
        raise ValueError("dispatch manifest source_preflight is required")
    try:
        latest = latest_preflight_path(runs_dir)
    except FileNotFoundError:
        return
    source_name = Path(str(source_preflight)).name
    if source_name != latest.name:
        raise ValueError(
            "dispatch manifest source_preflight is stale: "
            f"{source_name} != latest {latest.name}"
        )


def find_package(packages: list[dict], package_id: str) -> dict:
    for package in packages:
        if package.get("package_id") == package_id:
            return package
    available = ", ".join(str(package.get("package_id")) for package in packages)
    raise KeyError(f"package_id {package_id!r} not found; available: {available}")


def select_packages(
    packages: list[dict],
    package_id: str | None = None,
    wave: int | None = None,
    include_all: bool = False,
) -> list[dict]:
    selectors = sum(1 for value in (package_id, wave, include_all) if value)
    if selectors != 1:
        raise ValueError("select exactly one of --package-id, --wave, or --all")
    if package_id:
        return [find_package(packages, package_id)]
    if wave is not None:
        selected = [package for package in packages if int(package.get("wave") or 0) == wave]
        if not selected:
            raise KeyError(f"no packages found for wave {wave}")
        return sorted(selected, key=lambda package: str(package.get("package_id") or ""))
    return sorted(packages, key=lambda package: (int(package.get("wave") or 0), str(package.get("package_id") or "")))


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "work-package"


def unique_default_output_dir() -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_OUTPUT_DIR / f"{timestamp}-pid{os.getpid()}"


def ps_single_quoted(value: Path | str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def ps_array(values: list[str]) -> str:
    if not values:
        return "@()"
    return "@(" + ", ".join(ps_single_quoted(value) for value in values) + ")"


def ps_agent_id_guard_lines(variable_name: str, source_name: str) -> list[str]:
    return [
        f"if (-not ${variable_name}) {{",
        f"  Write-Error 'AgentId is required for {source_name}.'",
        "  exit 2",
        "}",
        f"if (${variable_name} -notmatch '^[A-Za-z0-9_.-]+$') {{",
        f"  Write-Error 'AgentId may only contain letters, digits, underscore, dot, or dash. Source: {source_name}.'",
        "  exit 2",
        "}",
    ]


def repo_relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def stable_path(path: Path) -> str:
    return repo_relative(path).replace("\\", "/")


def stable_artifact_ref(value: str | Path | None) -> str:
    if not value:
        return ""
    return repo_relative(Path(str(value))).replace("\\", "/")


def replacement_variants(value: str | Path | None) -> list[str]:
    if not value:
        return []
    text = str(value)
    variants = {text, text.replace("\\", "/"), text.replace("/", "\\")}
    path = Path(text)
    variants.add(stable_path(path))
    variants.add(stable_path(path).replace("/", "\\"))
    relative = repo_relative(path)
    variants.add(relative)
    variants.add(relative.replace("/", "\\"))
    if not path.is_absolute():
        absolute = (REPO_ROOT / path).resolve(strict=False)
        variants.add(str(absolute))
        variants.add(absolute.as_posix())
    return [variant for variant in variants if variant]


def replace_artifact_ref(value: str | Path, replacements: dict[str, str]) -> str:
    text = str(value)
    for variant in replacement_variants(text):
        if variant in replacements:
            return replacements[variant]
    path = Path(text)
    if path.is_absolute() and path_is_within(path, REPO_ROOT):
        return repo_relative(path)
    return text


def rewrite_archived_handoff_file(path: Path, replacements: dict[str, str]) -> None:
    text = path.read_text(encoding="utf-8-sig")
    for old, new in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        if old:
            old_variants = {
                old,
                old.replace("/", "\\"),
                old.replace("\\", "/"),
                json.dumps(old)[1:-1],
                json.dumps(old.replace("/", "\\"))[1:-1],
                json.dumps(old.replace("\\", "/"))[1:-1],
            }
            for old_variant in sorted(old_variants, key=len, reverse=True):
                if old_variant:
                    text = text.replace(old_variant, new)
    text = re.sub(
        r"(?m)^Set-Location\s+['\"][A-Za-z]:[^\r\n'\"]+['\"]\s*$",
        "Set-Location (Resolve-Path '.')",
        text,
    )
    text = text.replace(
        "Keep outputs in the package script's temp output directory",
        "Keep outputs in the package script's output directory",
    )
    path.write_text(text, encoding="utf-8")


def command_is_allowed(command: str) -> bool:
    command_text = command.strip()
    if not command_text:
        return True
    if any(token in command_text for token in UNSAFE_COMMAND_TOKENS):
        return False
    if not command_text.startswith(ALLOWED_COMMAND_PREFIXES):
        return False
    if command_text.startswith("python tools/detection_validation/"):
        return ".py" in command_text.split()[1]
    return True


def validate_safe_commands(package: dict) -> None:
    for command in package.get("safe_commands") or []:
        if not isinstance(command, str) or not command.strip() or not command_is_allowed(command):
            raise ValueError(f"package {package.get('package_id')} has unsupported command: {command}")


def missing_required_env(package: dict, environ: dict[str, str] | None = None) -> list[str]:
    env = environ if environ is not None else os.environ
    return [name for name in package.get("required_env") or [] if not env.get(str(name))]


def missing_effective_env(
    package: dict,
    environ: dict[str, str] | None = None,
    current_next_action: object = None,
) -> list[str]:
    env = environ if environ is not None else os.environ
    return [name for name in package_effective_env_with_current_action(package, current_next_action) if not env.get(str(name))]


def package_launch_blockers(
    package: dict,
    current_next_action: object = None,
    environ: dict[str, str] | None = None,
    include_launcher_selection: bool = False,
) -> list[str]:
    blockers = []
    if missing_effective_env(package, environ, current_next_action=current_next_action):
        blockers.append("missing_effective_env")
    if dependent_waves(package):
        blockers.append("depends_on_prior_waves")
    if include_launcher_selection and package.get("launcher_selected") is False:
        blockers.append("manual_launch_required")
    return blockers


def package_is_launch_ready(
    package: dict,
    current_next_action: object = None,
    environ: dict[str, str] | None = None,
) -> bool:
    return not package_launch_blockers(package, current_next_action=current_next_action, environ=environ)


def package_handoff_notes(
    package: dict,
    launcher_selected: bool | None = None,
    manual_reason: str | None = None,
    staged_stage: int | None = None,
    environ: dict[str, str] | None = None,
    current_next_action: object = None,
) -> list[str]:
    notes = ["parallelizable" if package.get("parallelizable_in_wave") else "serial-only"]
    if launcher_selected is True:
        notes.append("parallel-launcher:auto")
    elif launcher_selected is False:
        reason = manual_reason or "manual"
        if str(reason).startswith("blocked:"):
            notes.append("parallel-launcher:" + str(reason))
        else:
            notes.append(f"parallel-launcher:manual:{reason}")
    if staged_stage is not None:
        notes.append(f"staged-launcher:stage-{staged_stage}")
    dependencies = dependent_waves(package)
    if dependencies:
        notes.append("depends-on-waves:" + ",".join(str(value) for value in dependencies))
    missing_env = missing_effective_env(package, environ, current_next_action=current_next_action)
    if missing_env:
        notes.append("env-blocked:" + ",".join(str(value) for value in missing_env))
    return notes


def package_resource_tags(package: dict) -> list[str]:
    package_id = str(package.get("package_id") or "")
    step_id = str(package.get("step_id") or package_id)
    blocking_profiles = " ".join(str(value) for value in package.get("blocking_profiles") or [])
    commands = " ".join(str(value) for value in package.get("safe_commands") or [])
    tags = set()

    if step_id == "provide-required-preflight-env":
        return ["operator-env"]
    if "windows" in package_id or "windows" in blocking_profiles or "windows" in commands:
        tags.add("windows-lab")
    if "qga" in blocking_profiles or "qga" in commands:
        tags.add("proxmox-qga")
    if "caldera" in package_id or "caldera" in blocking_profiles or "caldera" in commands:
        tags.add("caldera")
    if "macos" in package_id or "macos" in blocking_profiles or "macos" in commands:
        tags.add("macos-agent")
    if "fresh-restore" in package_id or "fresh-restore" in step_id:
        tags.add("fresh-restore-window")
    if "atomic" in package_id or "atomic" in blocking_profiles or "atomic" in commands:
        tags.add("atomic-target")
    if "scorecard" in commands or "closure_gate" in commands or "closure-gate" in package_id:
        tags.add("repo-generated-gates")
    if not tags:
        tags.add("operator-env")
    return sorted(tags)


def package_manifest_resource_tags(package: dict) -> list[str]:
    if "resource_tags" in package:
        return [str(value) for value in package.get("resource_tags") or []]
    return package_resource_tags(package)


def dependent_waves(package: dict) -> list[int]:
    waves = []
    for wave in package.get("depends_on_waves") or []:
        try:
            waves.append(int(wave))
        except (TypeError, ValueError):
            continue
    return sorted(set(waves))


def ordered_unique(values: list[str]) -> list[str]:
    ordered = []
    seen = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def markdown_code_list(values: list[str]) -> str:
    return ", ".join(f"`{str(value)}`" for value in values) if values else "-"


def package_next_action_env(package: dict) -> list[str]:
    values = []
    for action in package.get("roadmap_next_actions") or []:
        if not isinstance(action, dict):
            continue
        values.extend(str(value) for value in action.get("required_env") or [])
    for item in package.get("operator_inputs") or []:
        if isinstance(item, dict) and item.get("env"):
            values.append(str(item.get("env")))
    values.extend(next_action_env_from_action(package.get("current_next_action")))
    return ordered_unique(values)


def next_action_env_from_action(action: object) -> list[str]:
    if not isinstance(action, dict):
        return []
    values = [str(value) for value in action.get("required_env") or [] if str(value)]
    token_env = str(action.get("token_env") or "")
    if token_env:
        values.append(token_env)
    return ordered_unique(values)


def package_effective_env_with_current_action(package: dict, current_next_action: object = None) -> list[str]:
    return ordered_unique(
        [str(value) for value in package.get("required_env") or []]
        + package_next_action_env(package)
        + next_action_env_from_action(current_next_action)
    )


def package_effective_env(package: dict) -> list[str]:
    return ordered_unique(
        [str(value) for value in package.get("required_env") or []] + package_next_action_env(package)
    )


def latest_profile_artifact_ref(profile_id: str, runs_dir: Path = RUNS_DIR) -> str:
    candidates = sorted(runs_dir.glob(f"*-{profile_id}.json"), key=lambda path: path.name)
    return stable_artifact_ref(candidates[-1]) if candidates else ""


def package_latest_current_next_action(package: dict, runs_dir: Path = RUNS_DIR) -> dict[str, object]:
    artifacts = []
    for profile_id in ordered_unique(
        [str(value) for value in package.get("expected_profile_ids") or []]
        + [str(value) for value in package.get("blocking_profiles") or []]
    ):
        artifact_ref = latest_profile_artifact_ref(profile_id, runs_dir)
        if artifact_ref:
            artifacts.append(artifact_ref)
    return current_next_action_from_artifacts(artifacts)


def package_with_latest_current_next_action(package: dict, runs_dir: Path = RUNS_DIR) -> dict:
    action = package_latest_current_next_action(package, runs_dir)
    if not action:
        return dict(package)
    enriched = dict(package)
    enriched["current_next_action"] = action
    return enriched


def package_current_next_action_or_task(package: dict, current_next_action: object = None) -> dict[str, object]:
    action: dict[str, object] = {}
    if isinstance(current_next_action, dict) and current_next_action:
        action = dict(current_next_action)
    elif isinstance(package.get("current_next_action"), dict) and package.get("current_next_action"):
        action = dict(package.get("current_next_action") or {})
    if action.get("action"):
        return action
    action_text = str(package.get("action") or "").strip()
    if action_text:
        action["action"] = action_text
        return action
    for roadmap_action in package.get("roadmap_next_actions") or []:
        if not isinstance(roadmap_action, dict):
            continue
        action_text = str(roadmap_action.get("action") or "").strip()
        if action_text:
            action["action"] = action_text
            return action
    return action


def operator_input_details_by_env(package: dict) -> dict[str, dict[str, str]]:
    details: dict[str, dict[str, str]] = {}
    for item in package.get("operator_inputs") or []:
        if not isinstance(item, dict) or not item.get("env"):
            continue
        env_name = str(item.get("env"))
        details[env_name] = {
            "name": str(item.get("name") or ""),
            "flag": str(item.get("flag") or ""),
            "description": str(item.get("description") or ""),
        }
    return details


def next_action_env_details_by_env(package: dict) -> dict[str, dict[str, str]]:
    action = package.get("current_next_action") if isinstance(package.get("current_next_action"), dict) else {}
    details: dict[str, dict[str, str]] = {}
    token_env = str(action.get("token_env") or "")
    if token_env:
        target_server = str(action.get("target_server") or "")
        suffix = f" for {target_server}" if target_server else ""
        details[token_env] = {
            "name": "tamandua_token",
            "flag": "",
            "description": f"Tamandua API token used for non-interactive tamandua-ctl remote login{suffix}",
        }
    for env_name in [str(value) for value in action.get("required_env") or [] if str(value)]:
        details.setdefault(
            env_name,
            {
                "name": "",
                "flag": "",
                "description": str(action.get("action") or ""),
            },
        )
    return details


def env_details_by_env(package: dict) -> dict[str, dict[str, str]]:
    details = next_action_env_details_by_env(package)
    for env_name, item in operator_input_details_by_env(package).items():
        existing = details.setdefault(env_name, {"name": "", "flag": "", "description": ""})
        if item.get("name"):
            existing["name"] = item["name"]
        if item.get("flag"):
            existing["flag"] = item["flag"]
        if item.get("description"):
            existing["description"] = item["description"]
    return details


def package_impact_score(package: dict) -> int:
    return len(package.get("blocking_profiles") or []) + len(package.get("blocked_run_classes") or [])


def render_package_script(
    package: dict,
    preflight_path: Path,
    package_output_dir: Path | None = None,
) -> str:
    commands = package.get("safe_commands") or []
    if not commands:
        raise ValueError(f"package {package.get('package_id')} has no safe_commands")
    validate_safe_commands(package)

    package_id = str(package.get("package_id") or "")
    output_dir = package_output_dir or DEFAULT_OUTPUT_DIR / safe_filename(package_id) / "outputs"
    expected_profiles = [str(value) for value in package.get("expected_profile_ids") or []]
    lines = [
        "# Generated from validation execution preflight work package.",
        f"# PackageId: {package_id}",
        f"# Title: {package.get('title') or ''}",
        f"# Wave: {package.get('wave') or ''}",
        f"# OwnerRole: {package.get('recommended_owner_role') or ''}",
        f"# SourcePreflight: {preflight_path.as_posix()}",
        "$ErrorActionPreference = 'Stop'",
        "Set-StrictMode -Version Latest",
        "$RepoRoot = $null",
        "$CandidateRoots = @(",
        "  (Split-Path -Parent $MyInvocation.MyCommand.Path),",
        "  (Get-Location).Path,",
        "  [Environment]::GetEnvironmentVariable('TAMANDUA_REPO_ROOT')",
        ")",
        "foreach ($Root in $CandidateRoots) {",
        "  if ($RepoRoot -or -not $Root) { continue }",
        "  $Candidate = Resolve-Path $Root -ErrorAction SilentlyContinue",
        "  while ($Candidate) {",
        "    if (Test-Path (Join-Path $Candidate 'tools/detection_validation')) { $RepoRoot = $Candidate; break }",
        "    $Parent = Split-Path -Parent $Candidate",
        "    if (-not $Parent -or $Parent -eq $Candidate) { break }",
        "    $Candidate = $Parent",
        "  }",
        "}",
        "if (-not $RepoRoot) {",
        "  Write-Error 'Could not locate repo root; run from the repo or set TAMANDUA_REPO_ROOT.'",
        "  exit 2",
        "}",
        "Set-Location $RepoRoot",
        f"$Out = {ps_single_quoted(output_dir)}",
        "New-Item -ItemType Directory -Force -Path $Out | Out-Null",
        "$StatusPath = if ((Split-Path -Leaf $Out) -ieq 'outputs') {",
        "  Join-Path (Split-Path -Parent $Out) 'agent_status.json'",
        "} else {",
        "  Join-Path $Out 'agent_status.json'",
        "}",
        f"$PackageId = {ps_single_quoted(package_id)}",
        "$ClaimId = [Environment]::GetEnvironmentVariable('TAMANDUA_AGENT_CLAIM_ID')",
        "if (-not $ClaimId) { $ClaimId = 'claim-' + $PackageId }",
        "$AgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_AGENT_ID')",
        "if (-not $AgentId) { $AgentId = [Environment]::UserName }",
        *ps_agent_id_guard_lines("AgentId", "TAMANDUA_AGENT_ID"),
        f"$ExpectedProfiles = {ps_array(expected_profiles)}",
        "function Write-AgentStatus {",
        "  param([string]$Status, [int]$ExitCode, [string[]]$Notes)",
        "  $Artifacts = @(",
        "    Get-ChildItem -Path $Out -Filter '*.json' -File -ErrorAction SilentlyContinue |",
        "      Where-Object { $_.Name -notlike '*.comparison.json' } |",
        "      ForEach-Object { $_.FullName }",
        "  )",
        "  $ClearedProfiles = @()",
        "  foreach ($JsonOutput in $Artifacts) {",
        "    try { $Payload = Get-Content -Raw -Path $JsonOutput | ConvertFrom-Json } catch { continue }",
        "    $ProfileIdProperty = $Payload.PSObject.Properties['profile_id']",
        "    $QualityGateProperty = $Payload.PSObject.Properties['quality_gate']",
        "    if ($ProfileIdProperty -and $QualityGateProperty) {",
        "      $PassedProperty = $QualityGateProperty.Value.PSObject.Properties['passed']",
        "      if ($PassedProperty -and $PassedProperty.Value -eq $true) {",
        "        $ClearedProfiles += [string]$ProfileIdProperty.Value",
        "      }",
        "    }",
        "  }",
        "  $MissingProfiles = @($ExpectedProfiles | Where-Object { $ClearedProfiles -notcontains [string]$_ })",
        "  $BlockerCleared = ($Status -eq 'pass' -and $MissingProfiles.Count -eq 0)",
        "  $Payload = [ordered]@{",
        "    package_id = $PackageId",
        "    claim_id = $ClaimId",
        "    agent_id = $AgentId",
        "    status = $Status",
        "    artifacts = @($Artifacts)",
        "    blocker_cleared = [bool]$BlockerCleared",
        "    notes = @($Notes)",
        "    exit_code = $ExitCode",
        "    expected_profiles = @($ExpectedProfiles)",
        "    missing_profiles = @($MissingProfiles)",
        "  }",
        "  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $StatusPath) | Out-Null",
        "  $Payload | ConvertTo-Json -Depth 5 | Set-Content -Path $StatusPath -Encoding UTF8",
        "}",
        "trap { Write-AgentStatus 'fail' 1 @('exception: ' + $_.Exception.Message); exit 1 }",
        "",
    ]
    required_env = package_effective_env(package)
    if required_env:
        lines.extend(
            [
                f"$RequiredEnv = {ps_array(required_env)}",
                "$MissingEnv = @($RequiredEnv | Where-Object { -not [Environment]::GetEnvironmentVariable($_) })",
                "if ($MissingEnv.Count -gt 0) {",
                "  Write-Host ('Missing effective env for package: ' + ($MissingEnv -join ', '))",
                "  Write-AgentStatus 'blocked' 2 @('missing_effective_env: ' + ($MissingEnv -join ', '))",
                "  exit 2",
                "}",
                "",
            ]
        )

    lines.extend(
        [
            "if ([Environment]::GetEnvironmentVariable('TAMANDUA_CLAIM_LOCK_ACQUIRED') -ne '1') {",
            "  $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
            "  $ClaimLockHelperCandidates = @(",
            "    (Join-Path $ScriptDir 'claim_lock_helper.ps1'),",
            "    (Join-Path (Split-Path -Parent $ScriptDir) 'claim_lock_helper.ps1'),",
            "    (Join-Path (Split-Path -Parent (Split-Path -Parent $ScriptDir)) 'claim_lock_helper.ps1')",
            "  )",
            "  $ClaimLockHelperPath = $null",
            "  foreach ($Candidate in $ClaimLockHelperCandidates) {",
            "    if ($Candidate -and (Test-Path $Candidate)) { $ClaimLockHelperPath = $Candidate; break }",
            "  }",
            "  if (-not $ClaimLockHelperPath) {",
            "    Write-Error 'Missing claim lock helper for direct package execution.'",
            "    exit 2",
            "  }",
            "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ClaimLockHelperPath -ClaimId $ClaimId -AgentId $AgentId",
            "  if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
            "  $env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
            "}",
            "",
        ]
    )

    continue_on_failure = bool(package.get("continue_on_failure"))
    if continue_on_failure:
        lines.extend(
            [
                "$PackageExitCode = 0",
                "",
            ]
        )

    for command in commands:
        command_text = str(command).strip()
        if not command_text:
            continue
        if command_text.startswith("$Out = "):
            continue
        lines.append(command_text)
        if not command_text.startswith("$"):
            if continue_on_failure:
                lines.append(
                    "if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0 -and $PackageExitCode -eq 0) { $PackageExitCode = $LASTEXITCODE }"
                )
            else:
                lines.append("if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {")
                lines.append(f"  Write-AgentStatus 'fail' $LASTEXITCODE @({ps_single_quoted('command_failed: ' + command_text)})")
                lines.append("  exit $LASTEXITCODE")
                lines.append("}")

    if continue_on_failure:
        lines.extend(
            [
                "if ($PackageExitCode -ne 0) {",
                "  Write-AgentStatus 'fail' $PackageExitCode @('one_or_more_commands_failed')",
                "  exit $PackageExitCode",
                "}",
            ]
        )

    lines.extend(["Write-AgentStatus 'pass' 0 @()", ""])
    return "\n".join(lines)


def write_package_script(package: dict, preflight_path: Path, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    package_id = str(package.get("package_id") or "work-package")
    script_path = output_dir / f"{safe_filename(package_id)}.ps1"
    package_output_dir = output_dir / safe_filename(package_id) / "outputs"
    package_output_dir.mkdir(parents=True, exist_ok=True)
    script_path.write_text(
        render_package_script(package, preflight_path, package_output_dir=package_output_dir),
        encoding="utf-8",
    )
    return script_path


def package_output_dir_for_script(script_path: Path) -> Path:
    return script_path.parent / script_path.stem / "outputs"


def package_status_path_for_script(script_path: Path) -> Path:
    return script_path.parent / script_path.stem / "agent_status.json"


def package_manifest_output_dir(package: dict, script_path: Path) -> Path:
    output_dir_value = str(package.get("output_dir") or "")
    return Path(output_dir_value) if output_dir_value else package_output_dir_for_script(script_path)


def package_manifest_status_path(package: dict, script_path: Path) -> Path:
    status_path_value = str(package.get("status_path") or "")
    return Path(status_path_value) if status_path_value else package_status_path_for_script(script_path)


def package_claim_output_contract(package: dict) -> dict[str, list[str] | str]:
    expected_profiles = [str(value) for value in package.get("expected_profile_ids") or []]
    return {
        "output_dir": "package output directory",
        "required_json_profile_ids": expected_profiles,
        "status_file": "agent_status.json",
        "status_required_fields": AGENT_STATUS_REQUIRED_FIELDS,
        "status_allowed_values": ["pass", "fail", "blocked"],
    }


def package_references(package: dict) -> list[str]:
    step_id = str(package.get("step_id") or "")
    package_id = str(package.get("package_id") or "")
    profiles = " ".join(str(value) for value in package.get("blocking_profiles") or [])
    commands = " ".join(str(value) for value in package.get("safe_commands") or [])
    text = " ".join([step_id, package_id, profiles, commands]).lower()
    references: list[str] = []

    def add(path: str) -> None:
        if path not in references:
            references.append(path)

    if "fresh-restore" in text:
        add("docs/benchmarks/FRESH_RESTORE_PROVENANCE_RUNBOOK.md")
    if "caldera" in text:
        add("docs/benchmarks/CALDERA_PAW_RECOVERY_RUNBOOK.md")
    if "macos" in text:
        add("docs/benchmarks/macos-roadmap-p0-lab-runbook.md")
        add("docs/benchmarks/macos-backend-parity-runbook.md")
    if "windows" in text:
        add("docs/benchmarks/WIN_TEMPLATE_LAB_RECOVERY_NOTES.md")
    return references


def package_current_status_fields(script_path: Path, package: dict | None = None) -> dict[str, object]:
    status_path = package_manifest_status_path(package, script_path) if package is not None else package_status_path_for_script(script_path)
    if not status_path.exists() or not status_path.is_file():
        return {
            "status": "not_run",
            "exit_code": None,
            "artifacts": [],
            "missing_profiles": [],
            "next_action": {},
        }
    try:
        status_payload = load_json(status_path)
    except json.JSONDecodeError:
        return {
            "status": "status_json_invalid",
            "exit_code": None,
            "artifacts": [],
            "missing_profiles": [],
            "next_action": {},
        }
    artifacts = [stable_artifact_ref(value) for value in status_payload.get("artifacts") or []]
    return {
        "status": str(status_payload.get("status") or "not_run"),
        "exit_code": status_payload.get("exit_code"),
        "artifacts": artifacts,
        "missing_profiles": [str(value) for value in status_payload.get("missing_profiles") or []],
        "next_action": current_next_action_from_artifacts(artifacts),
    }


def resolve_current_artifact_ref(path_value: str) -> Path:
    path = Path(str(path_value))
    return path if path.is_absolute() else REPO_ROOT / path


def compact_next_action(action: dict) -> dict[str, object]:
    compact: dict[str, object] = {}
    for key in (
        "missing_stability",
        "missing_readiness",
        "missing_diagnostics",
        "missing_endpoints",
        "missing_profiles",
        "required_env",
        "blockers",
    ):
        if isinstance(action.get(key), list):
            compact[key] = [str(value) for value in action.get(key) or []]
    for key in (
        "action",
        "login_command",
        "token_env",
        "token_login_command",
        "target_server",
        "saved_server",
        "target_hostname",
        "target_agent_id",
    ):
        if action.get(key) not in (None, "", []):
            compact[key] = str(action.get(key))
    if "server_matches_target" in action:
        compact["server_matches_target"] = bool(action.get("server_matches_target"))
    if (
        compact.get("login_command")
        and compact.get("target_server")
        and not compact.get("token_login_command")
    ):
        compact["token_env"] = "TAMANDUA_TOKEN"
        compact["token_login_command"] = (
            "tamandua-ctl remote login --server "
            f"{compact['target_server']} --token $env:TAMANDUA_TOKEN"
        )
    return compact


def find_first_next_action(value: object) -> dict:
    if isinstance(value, dict):
        action = value.get("next_action")
        if isinstance(action, dict) and action:
            return action
        for nested in value.values():
            found = find_first_next_action(nested)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = find_first_next_action(item)
            if found:
                return found
    return {}


def infer_auth_next_action_from_artifact(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        stderr = str(value.get("stderr") or "")
        stdout = str(value.get("stdout") or "")
        text = f"{stderr}\n{stdout}".lower()
        if int(value.get("exit_code") or 0) != 0 and (
            "401 unauthorized" in text or "invalid or expired token" in text
        ):
            command = str(value.get("command") or "")
            target_server = ""
            parts = command.split()
            if "--server" in parts:
                index = parts.index("--server")
                if index + 1 < len(parts):
                    target_server = parts[index + 1]
            action = {
                "missing_readiness": ["tamandua_ctl_auth"],
                "action": "Refresh tamandua-ctl authentication for the target server, then rerun the readiness probe.",
                "token_env": "TAMANDUA_TOKEN",
            }
            if target_server:
                action["target_server"] = target_server
                action["login_command"] = f"tamandua-ctl remote login --server {target_server} --no-browser"
                action["token_login_command"] = (
                    f"tamandua-ctl remote login --server {target_server} --token $env:TAMANDUA_TOKEN"
                )
            return action
        for nested in value.values():
            found = infer_auth_next_action_from_artifact(nested)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = infer_auth_next_action_from_artifact(item)
            if found:
                return found
    return {}


def current_next_action_from_artifacts(artifacts: list[str]) -> dict[str, object]:
    for artifact in reversed([str(value) for value in artifacts if str(value).endswith(".json")]):
        path = resolve_current_artifact_ref(artifact)
        if not path.exists() or not path.is_file():
            continue
        try:
            data = load_json(path)
        except (json.JSONDecodeError, OSError):
            continue
        inferred_action = infer_auth_next_action_from_artifact(data)
        if inferred_action:
            return compact_next_action(inferred_action)
        action = find_first_next_action(data)
        if action:
            return compact_next_action(action)
    return {}


def render_agent_prompt(package: dict, script_path: Path, preflight_path: Path) -> str:
    package_id = str(package.get("package_id") or "")
    claim_id = f"claim-{package_id}" if package_id else "claim-unassigned"
    declared_required_env = ", ".join(str(value) for value in package.get("required_env") or []) or "-"
    roadmaps = ", ".join(str(value) for value in package.get("roadmaps") or []) or "-"
    blockers = ", ".join(str(value) for value in package.get("blocking_profiles") or []) or "-"
    resources = ", ".join(package_manifest_resource_tags(package))
    dependencies = ", ".join(str(value) for value in dependent_waves(package)) or "-"
    status_path = stable_path(package_manifest_status_path(package, script_path))
    claim_lock_helper_value = str(package.get("claim_lock_helper_path") or "")
    claim_lock_helper_path = (
        stable_artifact_ref(claim_lock_helper_value)
        if claim_lock_helper_value
        else stable_path(script_path.parent / "claim_lock_helper.ps1")
    )
    output_contract = package_claim_output_contract(package)
    expected_profiles = ", ".join(output_contract["required_json_profile_ids"]) or "-"
    required_status_fields = ", ".join(output_contract["status_required_fields"])
    allowed_status_values = ", ".join(output_contract["status_allowed_values"])
    current_status = package_current_status_fields(script_path, package)
    current_status["next_action"] = package_current_next_action_or_task(package, current_status["next_action"])
    current_artifacts = ", ".join(str(value) for value in current_status["artifacts"]) or "-"
    current_missing_profiles = ", ".join(str(value) for value in current_status["missing_profiles"]) or "-"
    current_exit_code = current_status["exit_code"] if current_status["exit_code"] is not None else "-"
    current_next_action = json.dumps(current_status["next_action"], sort_keys=True) if current_status["next_action"] else "-"
    next_action_env = (
        ", ".join(ordered_unique(package_next_action_env(package) + next_action_env_from_action(current_status["next_action"])))
        or "-"
    )
    effective_env = ", ".join(package_effective_env_with_current_action(package, current_status["next_action"])) or "-"
    required_env = effective_env
    lines = [
        f"# {package.get('package_id')}",
        "",
        f"Claim ID: {claim_id}",
        f"Title: {package.get('title') or ''}",
        f"Wave: {package.get('wave') or ''}",
        f"Owner role: {package.get('recommended_owner_role') or ''}",
        f"Roadmaps: {roadmaps}",
        f"Required env: {required_env}",
        f"Declared package env: {declared_required_env}",
        f"Next-action env: {next_action_env}",
        f"Effective env checklist: {effective_env}",
        f"Depends on waves: {dependencies}",
        f"Resource tags: {resources}",
        f"Blocking profiles: {blockers}",
        f"Source preflight: {stable_path(preflight_path)}",
        f"Script: {stable_path(script_path)}",
        f"Status path: {status_path}",
        f"Claim lock helper: {claim_lock_helper_path}",
        f"Claim lock command: powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(claim_lock_helper_path)} -ClaimId {claim_id} -AgentId <agent-id>",
        f"Expected JSON profiles: {expected_profiles}",
        f"Status JSON required fields: {required_status_fields}",
        f"Status JSON allowed status values: {allowed_status_values}",
        f"Current status: {current_status['status']}",
        f"Current exit code: {current_exit_code}",
        f"Current artifacts: {current_artifacts}",
        f"Current missing profiles: {current_missing_profiles}",
        f"Current next action: {current_next_action}",
        "",
        "Task:",
        str(package.get("action") or "Run the materialized package script and report the resulting artifacts."),
        "",
    ]
    references = package_references(package)
    if references:
        lines.extend(["References:", *[f"- {reference}" for reference in references], ""])
    roadmap_actions = [
        item for item in package.get("roadmap_next_actions") or [] if isinstance(item, dict)
    ]
    if roadmap_actions:
        lines.extend(["Roadmap next actions:"])
        for item in roadmap_actions:
            roadmap = str(item.get("roadmap") or "-")
            envs = ", ".join(str(value) for value in item.get("required_env") or []) or "-"
            profiles = ", ".join(str(value) for value in item.get("blocking_profiles") or []) or "-"
            action = str(item.get("action") or "-")
            lines.append(f"- {roadmap}: {action} Required env: `{envs}`. Blocking profiles: `{profiles}`.")
        lines.append("")
    manual_prerequisites = [
        str(value) for value in package.get("manual_prerequisites") or [] if value
    ]
    if manual_prerequisites:
        lines.extend(["Manual prerequisites:", *[f"- {value}" for value in manual_prerequisites], ""])
    operator_inputs = [
        item for item in package.get("operator_inputs") or [] if isinstance(item, dict)
    ]
    if operator_inputs:
        lines.extend(["Operator inputs:"])
        for item in operator_inputs:
            name = str(item.get("name") or "-")
            env = str(item.get("env") or "-")
            flag = str(item.get("flag") or "-")
            description = str(item.get("description") or "")
            lines.append(f"- {name}: env `{env}`, flag `{flag}`; {description}")
        lines.append("")
    lines.extend(
        [
            "Rules:",
            "- Do not edit unrelated files or revert another worker's changes.",
            "- Acquire the claim lock with the claim lock command above before running the package script.",
            "- Do not run the script until all required env vars above are present.",
            "- Keep outputs in the package script's output directory unless explicitly promoting official artifacts.",
            "- Write final package status to the status path above using the required JSON fields and allowed status values above.",
            "- Report command output, generated artifact paths, and whether the package cleared its blocker.",
            "",
            "Command:",
            f"powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(stable_path(script_path))}",
            "",
        ]
    )
    return "\n".join(lines)


def write_agent_prompt(package: dict, script_path: Path, preflight_path: Path, output_dir: Path) -> Path:
    package_id = str(package.get("package_id") or "work-package")
    prompt_path = output_dir / f"{safe_filename(package_id)}.agent.md"
    return write_agent_prompt_to_path(package, script_path, preflight_path, prompt_path)


def write_agent_prompt_to_path(package: dict, script_path: Path, preflight_path: Path, prompt_path: Path) -> Path:
    prompt_path.parent.mkdir(parents=True, exist_ok=True)
    prompt_path.write_text(render_agent_prompt(package, script_path, preflight_path), encoding="utf-8")
    return prompt_path


def render_dependency_evidence_guard(wave: int, depends_on_waves: list[int]) -> list[str]:
    if not depends_on_waves:
        return []
    dependency_text = ", ".join(str(value) for value in depends_on_waves)
    dependency_array = ps_array([str(value) for value in depends_on_waves])
    return [
        f"# DependsOnWaves: {dependency_text}",
        "$AllowDependentWaveLaunch = [Environment]::GetEnvironmentVariable('TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH')",
        "if ($AllowDependentWaveLaunch -ne '1') {",
        (
            "  Write-Error "
            + ps_single_quoted(
                f"Wave {wave} depends on completed waves: {dependency_text}. "
                "Set TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH=1 only after verifying dependencies."
            )
        ),
        "  exit 2",
        "}",
        f"$DependentWaves = {dependency_array}",
        "$LauncherDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
        "$ManifestPath = Join-Path $LauncherDir 'dispatch_manifest.json'",
        "if (-not (Test-Path $ManifestPath)) {",
        "  $ManifestPath = Join-Path (Split-Path -Parent $LauncherDir) 'dispatch_manifest.json'",
        "}",
        "if (Test-Path $ManifestPath) {",
        "  $Manifest = Get-Content -Raw -Path $ManifestPath | ConvertFrom-Json",
        "  $MissingDependencyEvidence = @()",
        "  foreach ($DependencyWave in $DependentWaves) {",
        "    $WaveNumber = [int]$DependencyWave",
        "    $DependencyPackages = @($Manifest.packages | Where-Object { [int]$_.wave -eq $WaveNumber -and ($_.launcher_selected -eq $true -or $_.staged_launcher_selected -eq $true) })",
        "    if ($DependencyPackages.Count -eq 0) {",
        "      $MissingDependencyEvidence += ('wave-' + [string]$WaveNumber + ':missing_dependency_packages')",
        "      continue",
        "    }",
        "    foreach ($DependencyPackage in $DependencyPackages) {",
        "      $OutputDir = [string]$DependencyPackage.output_dir",
        "      if (-not $OutputDir -or -not (Test-Path $OutputDir)) {",
        "        $MissingDependencyEvidence += ([string]$DependencyPackage.package_id + ':missing_output_dir')",
        "        continue",
        "      }",
        "      $JsonOutputs = @(Get-ChildItem -Path $OutputDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*.comparison.json' })",
        "      if ($JsonOutputs.Count -eq 0) {",
        "        $MissingDependencyEvidence += ([string]$DependencyPackage.package_id + ':missing_json_output')",
        "        continue",
        "      }",
        "      foreach ($ExpectedProfile in @($DependencyPackage.expected_profile_ids)) {",
        "        $ProfilePassed = $false",
        "        foreach ($JsonOutput in $JsonOutputs) {",
        "          try { $Payload = Get-Content -Raw -Path $JsonOutput.FullName | ConvertFrom-Json } catch { continue }",
        "          $ProfileIdProperty = $Payload.PSObject.Properties['profile_id']",
        "          $QualityGateProperty = $Payload.PSObject.Properties['quality_gate']",
        "          if ($ProfileIdProperty -and $QualityGateProperty -and [string]$ProfileIdProperty.Value -eq [string]$ExpectedProfile) {",
        "            $PassedProperty = $QualityGateProperty.Value.PSObject.Properties['passed']",
        "            if ($PassedProperty -and $PassedProperty.Value -eq $true) {",
        "              $ProfilePassed = $true",
        "              break",
        "            }",
        "          }",
        "        }",
        "        if (-not $ProfilePassed) {",
        "          $MissingDependencyEvidence += ([string]$DependencyPackage.package_id + ':' + [string]$ExpectedProfile + ':quality_gate_not_passed')",
        "        }",
        "      }",
        "    }",
        "  }",
        "  if ($MissingDependencyEvidence.Count -gt 0) {",
        "    Write-Error ('Dependent wave evidence missing: ' + ($MissingDependencyEvidence -join ', '))",
        "    exit 2",
        "  }",
        "} else {",
        "  Write-Warning ('dispatch_manifest.json not found beside launcher or parent directory; dependency evidence check skipped')",
        "}",
    ]


def render_wave_launcher(
    wave: int,
    launch_items: list[tuple[dict, Path]],
    skipped_items: list[tuple[dict, str]],
    depends_on_waves: list[int] | None = None,
) -> str:
    depends_on_waves = depends_on_waves or []
    lines = [
        "# Generated parallel launcher for validation preflight work packages.",
        f"# Wave: {wave}",
        "# Review resource tags before running; skipped packages were left for manual execution.",
        "$ErrorActionPreference = 'Stop'",
        "Set-StrictMode -Version Latest",
        "$WaveLauncherAgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_WAVE_LAUNCHER_AGENT_ID')",
        "if (-not $WaveLauncherAgentId) { $WaveLauncherAgentId = [Environment]::UserName }",
        *ps_agent_id_guard_lines("WaveLauncherAgentId", "TAMANDUA_WAVE_LAUNCHER_AGENT_ID"),
        "$WaveLauncherDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
    ]
    if depends_on_waves:
        lines.extend(render_dependency_evidence_guard(wave, depends_on_waves))
    lines.extend(
        [
        "$ClaimLockHelperPath = Join-Path $WaveLauncherDir 'claim_lock_helper.ps1'",
        "if (-not (Test-Path $ClaimLockHelperPath)) {",
        "  $ClaimLockHelperPath = Join-Path (Split-Path -Parent $WaveLauncherDir) 'claim_lock_helper.ps1'",
        "}",
        "if (-not (Test-Path $ClaimLockHelperPath)) {",
        "  Write-Error ('Missing claim lock helper: ' + $ClaimLockHelperPath)",
        "  exit 2",
        "}",
        ]
    )
    lines.extend(
        [
        "$jobs = @()",
        "",
        ]
    )
    for package, script_path in launch_items:
        resources = ", ".join(package_resource_tags(package))
        absolute_script_path = stable_path(script_path)
        claim_id = "claim-" + str(package.get("package_id") or "")
        lines.extend(
            [
                f"# Package: {package.get('package_id')} resources={resources}",
                f"$jobs += Start-Job -Name {ps_single_quoted(script_path.stem)} -ArgumentList {ps_single_quoted(absolute_script_path)}, {ps_single_quoted(claim_id)}, $script:ClaimLockHelperPath, $WaveLauncherAgentId -ScriptBlock {{",
                "  param([string]$ScriptPath, [string]$ClaimId, [string]$ClaimLockHelperPath, [string]$AgentId)",
                "  $env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId",
                "  $env:TAMANDUA_AGENT_ID = $AgentId",
                "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ClaimLockHelperPath -ClaimId $ClaimId -AgentId $AgentId",
                "  if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
                "  $env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
                "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath",
                "  if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
                "}",
                "",
            ]
        )
    if skipped_items:
        lines.append("# Skipped due to resource overlap:")
        for package, reason in skipped_items:
            lines.append(f"# - {package.get('package_id')}: {reason}")
        lines.append("")
    lines.extend(
        [
            "$jobs | Wait-Job | Out-Null",
            "$failed = @()",
            "foreach ($job in $jobs) {",
            "  Receive-Job -Job $job",
            "  if ($job.State -ne 'Completed') { $failed += $job.Name }",
            "}",
            "Remove-Job -Job $jobs -Force",
            "if ($failed.Count -gt 0) {",
            "  Write-Error ('Failed package jobs: ' + ($failed -join ', '))",
            "  exit 1",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def write_wave_launchers(packages: list[dict], script_paths: dict[str, Path], output_dir: Path) -> list[Path]:
    launcher_paths = []
    waves = sorted({int(package.get("wave") or 0) for package in packages})
    for wave in waves:
        wave_packages = [
            package
            for package in packages
            if int(package.get("wave") or 0) == wave and package.get("parallelizable_in_wave")
        ]
        launchable_wave_packages = []
        for package in wave_packages:
            if not package_is_launch_ready(package):
                continue
            if missing_effective_env(package):
                continue
            launchable_wave_packages.append(package)
        if len(launchable_wave_packages) < 2:
            continue
        used_resources = set()
        launch_items = []
        skipped_items = []
        ordered_wave_packages = sorted(
            launchable_wave_packages,
            key=lambda package: (-package_impact_score(package), str(package.get("package_id") or "")),
        )
        for package in ordered_wave_packages:
            resources = set(package_resource_tags(package))
            overlap = sorted(used_resources & resources)
            if overlap:
                skipped_items.append((package, f"resource overlap: {', '.join(overlap)}"))
                continue
            used_resources.update(resources)
            launch_items.append((package, script_paths[str(package.get("package_id"))]))
        if len(launch_items) < 2:
            continue
        launcher_path = output_dir / f"wave-{wave}-parallel-launcher.ps1"
        depends_on = sorted(
            {
                dependency
                for package in wave_packages
                for dependency in dependent_waves(package)
            }
        )
        launcher_path.write_text(
            render_wave_launcher(wave, launch_items, skipped_items, depends_on),
            encoding="utf-8",
        )
        launcher_paths.append(launcher_path)
    return launcher_paths


def wave_execution_stages(wave_packages: list[dict]) -> list[list[dict]]:
    stages: list[list[dict]] = []
    stage_resources: list[set[str]] = []
    ordered_packages = sorted(
        [
            package
            for package in wave_packages
            if package.get("parallelizable_in_wave") and package_is_launch_ready(package)
        ],
        key=lambda package: (-package_impact_score(package), str(package.get("package_id") or "")),
    )
    for package in ordered_packages:
        resources = set(package_resource_tags(package))
        placed = False
        for index, used_resources in enumerate(stage_resources):
            if used_resources & resources:
                continue
            stages[index].append(package)
            used_resources.update(resources)
            placed = True
            break
        if not placed:
            stages.append([package])
            stage_resources.append(set(resources))
    return stages


def staged_launcher_membership(packages: list[dict]) -> dict[str, int]:
    staged: dict[str, int] = {}
    for wave in sorted({int(package.get("wave") or 0) for package in packages}):
        wave_packages = [
            package
            for package in packages
            if int(package.get("wave") or 0) == wave and package.get("parallelizable_in_wave")
        ]
        launchable_wave_packages = [
            package for package in wave_packages if package_is_launch_ready(package)
        ]
        if len(launchable_wave_packages) < 2:
            continue
        for stage_number, stage in enumerate(wave_execution_stages(launchable_wave_packages), start=1):
            for package in stage:
                staged[str(package.get("package_id"))] = stage_number
    return staged


def render_staged_wave_launcher(
    wave: int,
    stages: list[list[tuple[dict, Path]]],
    depends_on_waves: list[int] | None = None,
) -> str:
    depends_on_waves = depends_on_waves or []
    lines = [
        "# Generated staged launcher for validation preflight work packages.",
        f"# Wave: {wave}",
        "# Runs resource-independent packages in parallel stages; resource overlaps are serialized automatically.",
        "$ErrorActionPreference = 'Stop'",
        "Set-StrictMode -Version Latest",
        "$StagedLauncherAgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_STAGED_LAUNCHER_AGENT_ID')",
        "if (-not $StagedLauncherAgentId) { $StagedLauncherAgentId = [Environment]::UserName }",
        *ps_agent_id_guard_lines("StagedLauncherAgentId", "TAMANDUA_STAGED_LAUNCHER_AGENT_ID"),
        "$StagedLauncherDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
    ]
    if depends_on_waves:
        lines.extend(render_dependency_evidence_guard(wave, depends_on_waves))
    lines.extend(
        [
        "$ClaimLockHelperPath = Join-Path $StagedLauncherDir 'claim_lock_helper.ps1'",
        "if (-not (Test-Path $ClaimLockHelperPath)) {",
        "  $ClaimLockHelperPath = Join-Path (Split-Path -Parent $StagedLauncherDir) 'claim_lock_helper.ps1'",
        "}",
        "if (-not (Test-Path $ClaimLockHelperPath)) {",
        "  Write-Error ('Missing claim lock helper: ' + $ClaimLockHelperPath)",
        "  exit 2",
        "}",
        ]
    )
    lines.append("$StageFailures = @()")
    for stage_number, stage in enumerate(stages, start=1):
        lines.extend(["", f"# Stage {stage_number}", "$jobs = @()"])
        for package, script_path in stage:
            resources = ", ".join(package_resource_tags(package))
            absolute_script_path = stable_path(script_path)
            claim_id = "claim-" + str(package.get("package_id") or "")
            lines.extend(
                [
                    f"# Package: {package.get('package_id')} resources={resources}",
                    f"$jobs += Start-Job -Name {ps_single_quoted(script_path.stem)} -ArgumentList {ps_single_quoted(absolute_script_path)}, {ps_single_quoted(claim_id)}, $script:ClaimLockHelperPath, $StagedLauncherAgentId -ScriptBlock {{",
                    "  param([string]$ScriptPath, [string]$ClaimId, [string]$ClaimLockHelperPath, [string]$AgentId)",
                    "  $env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId",
                    "  $env:TAMANDUA_AGENT_ID = $AgentId",
                    "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ClaimLockHelperPath -ClaimId $ClaimId -AgentId $AgentId",
                    "  if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
                    "  $env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
                    "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath",
                    "  if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
                    "}",
                ]
            )
        lines.extend(
            [
                "$jobs | Wait-Job | Out-Null",
                "$failed = @()",
                "foreach ($job in $jobs) {",
                "  Receive-Job -Job $job",
                "  if ($job.State -ne 'Completed') { $failed += $job.Name }",
                "}",
                "Remove-Job -Job $jobs -Force",
                "if ($failed.Count -gt 0) {",
                "  $script:StageFailures += ('stage "
                + str(stage_number)
                + ": ' + ($failed -join ', '))",
                "}",
            ]
        )
    lines.extend(
        [
            "",
            "if ($StageFailures.Count -gt 0) {",
            "  Write-Error ('Failed package jobs across staged wave: ' + ($StageFailures -join '; '))",
            "  exit 1",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def write_staged_wave_launchers(packages: list[dict], script_paths: dict[str, Path], output_dir: Path) -> list[Path]:
    launcher_paths = []
    waves = sorted({int(package.get("wave") or 0) for package in packages})
    for wave in waves:
        wave_packages = [
            package
            for package in packages
            if int(package.get("wave") or 0) == wave and package.get("parallelizable_in_wave")
        ]
        launchable_wave_packages = [
            package for package in wave_packages if package_is_launch_ready(package)
        ]
        if len(launchable_wave_packages) < 2:
            continue
        stages = wave_execution_stages(launchable_wave_packages)
        staged_items = [
            [(package, script_paths[str(package.get("package_id"))]) for package in stage]
            for stage in stages
        ]
        depends_on = sorted(
            {
                dependency
                for package in wave_packages
                for dependency in dependent_waves(package)
            }
        )
        launcher_path = output_dir / f"wave-{wave}-staged-launcher.ps1"
        launcher_path.write_text(render_staged_wave_launcher(wave, staged_items, depends_on), encoding="utf-8")
        launcher_paths.append(launcher_path)
    return launcher_paths


def render_agent_roster(
    packages: list[dict],
    script_paths: dict[str, Path],
    prompt_paths: dict[str, Path] | None = None,
) -> str:
    prompt_paths = prompt_paths or {}
    launched, skipped = launcher_membership(packages)
    lines = [
        "# Validation Agent Roster",
        "",
        "Use this roster to hand off independent validation packages to separate agents without sharing output directories.",
        "",
        "| Wave | Package | Owner | Launcher | Resources | Required env | Next-action env | Depends | Script | Prompt | Status | Output contract |",
        "|---:|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for package in sorted(packages, key=lambda item: (int(item.get("wave") or 0), str(item.get("package_id") or ""))):
        package_id = str(package.get("package_id") or "")
        selected = (
            package.get("launcher_selected")
            if "launcher_selected" in package
            else launched.get(package_id)
        )
        manual_reason = (
            package.get("manual_reason")
            if "manual_reason" in package
            else skipped.get(package_id)
        )
        selected_text = "-" if selected is None else ("auto" if selected else f"manual: {manual_reason}")
        script_path = stable_path(script_paths[package_id])
        prompt_path = stable_path(prompt_paths[package_id]) if package_id in prompt_paths else "-"
        status_path = stable_path(package_manifest_status_path(package, script_paths[package_id]))
        next_action_env = (
            [str(value) for value in package.get("next_action_required_env") or []]
            if "next_action_required_env" in package
            else package_next_action_env(package)
        )
        output_contract = markdown_code_list(
            [str(value) for value in package_claim_output_contract(package)["required_json_profile_ids"]]
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    str(int(package.get("wave") or 0)),
                    f"`{package_id}`",
                    str(package.get("recommended_owner_role") or "-"),
                    selected_text,
                    markdown_code_list(package_manifest_resource_tags(package)),
                    markdown_code_list([str(value) for value in package.get("required_env") or []]),
                    markdown_code_list(next_action_env),
                    markdown_code_list([str(value) for value in dependent_waves(package)]),
                    f"`{script_path}`",
                    f"`{prompt_path}`",
                    f"`{status_path}`",
                    output_contract,
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def write_agent_roster(
    packages: list[dict],
    script_paths: dict[str, Path],
    prompt_paths: dict[str, Path] | None,
    output_dir: Path,
) -> Path:
    roster_path = output_dir / "agent_roster.md"
    roster_path.write_text(render_agent_roster(packages, script_paths, prompt_paths), encoding="utf-8")
    return roster_path


def env_is_secret(name: str) -> bool:
    upper = name.upper()
    secret_markers = ("KEY", "PASSWORD", "TOKEN", "SECRET")
    return any(marker in upper for marker in secret_markers)


def render_env_checklist(packages: list[dict], environ: dict[str, str] | None = None) -> str:
    env = environ if environ is not None else os.environ
    rows = []
    seen: set[tuple[int, str, str]] = set()
    for package in sorted(packages, key=lambda item: (int(item.get("wave") or 0), str(item.get("package_id") or ""))):
        package_id = str(package.get("package_id") or "")
        wave = int(package.get("wave") or 0)
        env_sources: dict[str, set[str]] = {}
        input_details = env_details_by_env(package)
        for env_name in package.get("required_env") or []:
            env_sources.setdefault(str(env_name), set()).add("script")
        for env_name in package_next_action_env(package):
            env_sources.setdefault(str(env_name), set()).add("next-action")
        for env_name in package_effective_env(package):
            name = str(env_name)
            key = (wave, package_id, name)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "wave": wave,
                    "package_id": package_id,
                    "env": name,
                    "present": "yes" if env.get(name) else "no",
                    "class": "secret" if env_is_secret(name) else "claim-metadata",
                    "source": "+".join(sorted(env_sources.get(name) or {"script"})),
                    "flag": input_details.get(name, {}).get("flag") or "-",
                    "description": input_details.get(name, {}).get("description") or "-",
                    "owner": str(package.get("recommended_owner_role") or "-"),
                }
            )

    lines = [
        "# Validation Env Checklist",
        "",
        "Use this checklist before launching generated package scripts. It records only whether a variable is present, never its value.",
        "",
    ]
    if not rows:
        lines.extend(["No selected packages declare required env vars.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "| Wave | Package | Env var | Present | Class | Source | Flag | Description | Owner |",
            "|---:|---|---|---|---|---|---|---|---|",
        ]
    )
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                [
                    str(row["wave"]),
                    f"`{row['package_id']}`",
                    f"`{row['env']}`",
                    f"`{row['present']}`",
                    f"`{row['class']}`",
                    f"`{row['source']}`",
                    f"`{row['flag']}`",
                    row["description"],
                    row["owner"],
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def write_env_checklist(packages: list[dict], output_dir: Path) -> Path:
    checklist_path = output_dir / "env_checklist.md"
    checklist_path.write_text(render_env_checklist(packages), encoding="utf-8")
    return checklist_path


def env_template_placeholder(name: str) -> str:
    if env_is_secret(name):
        return f"<set-{name.lower().replace('_', '-')}-secret>"
    return f"<set-{name.lower().replace('_', '-')}>"


def render_env_template(packages: list[dict]) -> str:
    env_details: dict[str, dict[str, str]] = {}
    env_owners: dict[str, set[str]] = {}
    for package in sorted(packages, key=lambda item: (int(item.get("wave") or 0), str(item.get("package_id") or ""))):
        input_details = env_details_by_env(package)
        owner = str(package.get("recommended_owner_role") or "operator-or-secret-holder")
        for env_name in package_effective_env(package):
            name = str(env_name)
            detail = input_details.get(name) or {}
            existing = env_details.setdefault(
                name,
                {
                    "class": "secret" if env_is_secret(name) else "claim-metadata",
                    "flag": str(detail.get("flag") or "-"),
                    "description": str(detail.get("description") or "-"),
                },
            )
            if existing["flag"] == "-" and detail.get("flag"):
                existing["flag"] = str(detail.get("flag"))
            if existing["description"] == "-" and detail.get("description"):
                existing["description"] = str(detail.get("description"))
            env_owners.setdefault(name, set()).add(owner)

    lines = [
        "# Validation env handoff template",
        "# Fill placeholders locally before launching dispatch scripts.",
        "# This file is generated with redacted placeholder values only.",
        "",
    ]
    if not env_details:
        lines.extend(["# No selected packages declare required env vars.", ""])
        return "\n".join(lines)

    for env_name in sorted(env_details):
        detail = env_details[env_name]
        owners = ", ".join(sorted(env_owners.get(env_name) or []))
        lines.append(f"# Class: {detail['class']}; Owner: {owners or '-'}")
        lines.append(f"# Flag: {detail['flag']}; Description: {detail['description']}")
        lines.append(f"$env:{env_name} = '{env_template_placeholder(env_name)}'")
        lines.append("")
    return "\n".join(lines)


def write_env_template(packages: list[dict], output_dir: Path) -> Path:
    template_path = output_dir / "env_template.ps1"
    template_path.write_text(render_env_template(packages), encoding="utf-8")
    return template_path


def render_owner_launch_plan(
    packages: list[dict],
    script_paths: dict[str, Path],
    prompt_paths: dict[str, Path] | None = None,
    env_checklist_path: Path | None = None,
    env_template_path: Path | None = None,
) -> str:
    prompt_paths = prompt_paths or {}
    launched, skipped = launcher_membership(packages)
    staged = staged_launcher_membership(packages)
    packages_by_owner: dict[str, list[dict]] = {}
    for package in packages:
        owner = str(package.get("recommended_owner_role") or "unassigned")
        packages_by_owner.setdefault(owner, []).append(package)

    lines = [
        "# Validation Owner Launch Plan",
        "",
        "Use this plan to assign package execution to separate agents by owner while preserving wave and resource order.",
        "",
    ]
    if env_checklist_path:
        lines.append(f"Env checklist: `{stable_path(env_checklist_path)}`")
    if env_template_path:
        lines.append(f"Env template: `{stable_path(env_template_path)}`")
    if env_checklist_path or env_template_path:
        lines.append("")
    if not packages_by_owner:
        lines.extend(["No selected packages.", ""])
        return "\n".join(lines)

    for owner in sorted(packages_by_owner):
        owner_packages = sorted(
            packages_by_owner[owner],
            key=lambda item: (
                int(item.get("wave") or 0),
                staged.get(str(item.get("package_id") or ""), 999),
                str(item.get("package_id") or ""),
            ),
        )
        owner_package_context: dict[str, dict[str, object]] = {}
        for package in owner_packages:
            package_id = str(package.get("package_id") or "")
            status_path = package_manifest_status_path(package, script_paths[package_id])
            status_payload = None
            if status_path.exists() and status_path.is_file():
                try:
                    status_payload = load_json(status_path)
                except json.JSONDecodeError:
                    status_payload = None
            current_artifacts = (
                [stable_artifact_ref(value) for value in status_payload.get("artifacts") or []]
                if isinstance(status_payload, dict)
                else []
            )
            current_next_action = (
                current_next_action_from_artifacts(current_artifacts)
                if isinstance(status_payload, dict)
                else {}
            )
            current_next_action = package_current_next_action_or_task(package, current_next_action)
            owner_package_context[package_id] = {
                "current_next_action": current_next_action,
                "missing_effective_env": missing_effective_env(
                    package,
                    current_next_action=current_next_action,
                ),
            }
        missing_env = sorted(
            {
                env
                for context in owner_package_context.values()
                for env in context.get("missing_effective_env") or []
            }
        )
        roadmaps = sorted({str(value) for package in owner_packages for value in package.get("roadmaps") or []})
        lines.extend(
            [
                f"## Owner: {owner}",
                "",
                f"Missing effective env: {markdown_code_list(missing_env)}",
                f"Roadmaps: {markdown_code_list(roadmaps)}",
                "",
                "| Wave | Stage | Package | Launch mode | Depends | Missing env | Command | Prompt |",
                "|---:|---:|---|---|---|---|---|---|",
            ]
        )
        for package in owner_packages:
            package_id = str(package.get("package_id") or "")
            selected = (
                package.get("launcher_selected")
                if "launcher_selected" in package
                else launched.get(package_id)
            )
            manual_reason = (
                package.get("manual_reason")
                if "manual_reason" in package
                else skipped.get(package_id)
            )
            launch_mode = "-" if selected is None else ("parallel-auto" if selected else f"manual: {manual_reason}")
            stage = (
                package.get("staged_stage")
                if "staged_stage" in package
                else staged.get(package_id)
            )
            script_ref = stable_path(script_paths[package_id])
            prompt_ref = stable_path(prompt_paths[package_id]) if package_id in prompt_paths else "-"
            command = f"powershell -NoProfile -ExecutionPolicy Bypass -File '{script_ref}'"
            package_missing_env = [
                str(value)
                for value in owner_package_context.get(package_id, {}).get("missing_effective_env") or []
            ]
            lines.append(
                "| "
                + " | ".join(
                    [
                        str(int(package.get("wave") or 0)),
                        str(stage) if stage else "-",
                        f"`{package_id}`",
                        launch_mode,
                        markdown_code_list([str(value) for value in dependent_waves(package)]),
                        markdown_code_list(package_missing_env),
                        f"`{command}`",
                        f"`{prompt_ref}`",
                    ]
                )
                + " |"
            )
        lines.append("")
    return "\n".join(lines)


def build_owner_launch_plan_json(
    packages: list[dict],
    script_paths: dict[str, Path],
    prompt_paths: dict[str, Path] | None = None,
    env_checklist_path: Path | None = None,
    env_template_path: Path | None = None,
) -> dict:
    prompt_paths = prompt_paths or {}
    launched, skipped = launcher_membership(packages)
    staged = staged_launcher_membership(packages)
    packages_by_owner: dict[str, list[dict]] = {}
    for package in packages:
        owner = str(package.get("recommended_owner_role") or "unassigned")
        packages_by_owner.setdefault(owner, []).append(package)

    owner_entries = []
    for owner in sorted(packages_by_owner):
        owner_packages = sorted(
            packages_by_owner[owner],
            key=lambda item: (
                int(item.get("wave") or 0),
                staged.get(str(item.get("package_id") or ""), 999),
                str(item.get("package_id") or ""),
            ),
        )
        missing_env = sorted({env for package in owner_packages for env in missing_effective_env(package)})
        roadmaps = sorted({str(value) for package in owner_packages for value in package.get("roadmaps") or []})
        package_entries = []
        for package in owner_packages:
            package_id = str(package.get("package_id") or "")
            selected = (
                package.get("launcher_selected")
                if "launcher_selected" in package
                else launched.get(package_id)
            )
            manual_reason = (
                package.get("manual_reason")
                if "manual_reason" in package
                else skipped.get(package_id)
            )
            staged_stage = (
                package.get("staged_stage")
                if "staged_stage" in package
                else staged.get(package_id)
            )
            script_ref = stable_path(script_paths[package_id])
            status_path = package_manifest_status_path(package, script_paths[package_id])
            status_payload = None
            if status_path.exists() and status_path.is_file():
                try:
                    status_payload = load_json(status_path)
                except json.JSONDecodeError:
                    status_payload = None
            current_artifacts = (
                [stable_artifact_ref(value) for value in status_payload.get("artifacts") or []]
                if isinstance(status_payload, dict)
                else []
            )
            current_next_action = (
                current_next_action_from_artifacts(current_artifacts)
                if isinstance(status_payload, dict)
                else {}
            )
            current_next_action = package_current_next_action_or_task(package, current_next_action)
            package_next_env = ordered_unique(
                package_next_action_env(package) + next_action_env_from_action(current_next_action)
            )
            package_effective = package_effective_env_with_current_action(package, current_next_action)
            package_missing_env = missing_effective_env(package, current_next_action=current_next_action)
            package_dependencies = dependent_waves(package)
            blocked_reasons = []
            if package_missing_env:
                blocked_reasons.append("missing_effective_env")
            if package_dependencies:
                blocked_reasons.append("depends_on_prior_waves")
            if selected is False and not str(manual_reason or "").startswith("blocked:"):
                blocked_reasons.append("manual_launch_required")
            package_entries.append(
                {
                    "package_id": package_id,
                    "title": str(package.get("title") or ""),
                    "wave": int(package.get("wave") or 0),
                    "stage": staged_stage,
                    "launcher_selected": selected,
                    "manual_reason": manual_reason,
                    "depends_on_waves": dependent_waves(package),
                    "resource_tags": package_manifest_resource_tags(package),
                    "required_env": [str(value) for value in package.get("required_env") or []],
                    "next_action_required_env": package_next_env,
                    "current_next_action_required_env": next_action_env_from_action(current_next_action),
                    "effective_required_env": package_effective,
                    "missing_effective_env": package_missing_env,
                    "ready_to_launch": not blocked_reasons,
                    "blocked_reasons": blocked_reasons,
                    "roadmaps": [str(value) for value in package.get("roadmaps") or []],
                    "script_path": script_ref,
                    "prompt_path": stable_path(prompt_paths[package_id]) if package_id in prompt_paths else None,
                    "status_path": stable_path(status_path),
                    "current_status": str(status_payload.get("status") or "not_run") if isinstance(status_payload, dict) else "not_run",
                    "current_exit_code": status_payload.get("exit_code") if isinstance(status_payload, dict) else None,
                    "current_notes": [str(value) for value in status_payload.get("notes") or []] if isinstance(status_payload, dict) else [],
                    "current_artifacts": current_artifacts,
                    "current_missing_profiles": [str(value) for value in status_payload.get("missing_profiles") or []] if isinstance(status_payload, dict) else [],
                    "current_next_action": current_next_action,
                    "current_blocker_cleared": status_payload.get("blocker_cleared") if isinstance(status_payload, dict) else None,
                    "command": f"powershell -NoProfile -ExecutionPolicy Bypass -File '{script_ref}'",
                    "handoff_notes": package_handoff_notes(
                        package,
                        launcher_selected=selected,
                        manual_reason=manual_reason,
                        staged_stage=staged_stage,
                        current_next_action=current_next_action,
                    ),
                }
            )
        launchable_count = sum(1 for package in package_entries if package.get("ready_to_launch"))
        missing_env = sorted({env for package in package_entries for env in package.get("missing_effective_env") or []})
        owner_entries.append(
            {
                "owner": owner,
                "package_count": len(package_entries),
                "launchable_package_count": launchable_count,
                "blocked_package_count": len(package_entries) - launchable_count,
                "missing_effective_env": missing_env,
                "roadmaps": roadmaps,
                "packages": package_entries,
            }
        )

    launchable_package_count = sum(owner["launchable_package_count"] for owner in owner_entries)
    total_package_count = sum(len(owner["packages"]) for owner in owner_entries)
    return {
        "schema_version": 1,
        "artifact": "validation-owner-launch-plan",
        "env_checklist_path": stable_path(env_checklist_path) if env_checklist_path else None,
        "env_template_path": stable_path(env_template_path) if env_template_path else None,
        "owner_count": len(owner_entries),
        "package_count": total_package_count,
        "launchable_package_count": launchable_package_count,
        "blocked_package_count": total_package_count - launchable_package_count,
        "owners": owner_entries,
    }


def write_owner_launch_plan(
    packages: list[dict],
    output_dir: Path,
    script_paths: dict[str, Path],
    prompt_paths: dict[str, Path] | None = None,
    env_checklist_path: Path | None = None,
    env_template_path: Path | None = None,
) -> Path:
    plan_path = output_dir / "owner_launch_plan.md"
    plan_path.write_text(
        render_owner_launch_plan(packages, script_paths, prompt_paths, env_checklist_path, env_template_path),
        encoding="utf-8",
    )
    return plan_path


def write_owner_launch_plan_json(
    packages: list[dict],
    output_dir: Path,
    script_paths: dict[str, Path],
    prompt_paths: dict[str, Path] | None = None,
    env_checklist_path: Path | None = None,
    env_template_path: Path | None = None,
) -> Path:
    plan_path = output_dir / "owner_launch_plan.json"
    plan = build_owner_launch_plan_json(packages, script_paths, prompt_paths, env_checklist_path, env_template_path)
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return plan_path


def build_execution_matrix_json(owner_launch_plan: dict) -> dict:
    rows = []
    for owner in owner_launch_plan.get("owners") or []:
        if not isinstance(owner, dict):
            continue
        owner_name = str(owner.get("owner") or "unassigned")
        for package in owner.get("packages") or []:
            if not isinstance(package, dict):
                continue
            rows.append(
                {
                    "package_id": str(package.get("package_id") or ""),
                    "owner": owner_name,
                    "wave": int(package.get("wave") or 0),
                    "stage": package.get("stage"),
                    "current_status": str(package.get("current_status") or "not_run"),
                    "current_exit_code": package.get("current_exit_code"),
                    "ready_to_launch": bool(package.get("ready_to_launch")),
                    "blocked_reasons": [str(value) for value in package.get("blocked_reasons") or []],
                    "missing_effective_env": [str(value) for value in package.get("missing_effective_env") or []],
                    "depends_on_waves": [int(value) for value in package.get("depends_on_waves") or []],
                    "resource_tags": [str(value) for value in package.get("resource_tags") or []],
                    "launcher_selected": package.get("launcher_selected"),
                    "manual_reason": package.get("manual_reason"),
                    "current_artifacts": [str(value) for value in package.get("current_artifacts") or []],
                    "current_next_action": package.get("current_next_action") if isinstance(package.get("current_next_action"), dict) else {},
                    "command": str(package.get("command") or ""),
                    "script_path": str(package.get("script_path") or ""),
                    "prompt_path": package.get("prompt_path"),
                    "status_path": str(package.get("status_path") or ""),
                }
            )
    rows.sort(
        key=lambda item: (
            int(item.get("wave") or 0),
            int(item.get("stage") or 999),
            str(item.get("owner") or ""),
            str(item.get("package_id") or ""),
        )
    )
    return {
        "schema_version": 1,
        "artifact": "validation-execution-matrix",
        "source_artifact": str(owner_launch_plan.get("artifact") or ""),
        "package_count": len(rows),
        "ready_to_launch_count": sum(1 for row in rows if row.get("ready_to_launch") is True),
        "blocked_count": sum(1 for row in rows if row.get("ready_to_launch") is not True),
        "rows": rows,
    }


def render_execution_matrix(matrix: dict) -> str:
    def cell(value: object) -> str:
        if isinstance(value, list):
            text = ", ".join(str(item) for item in value) or "-"
        elif value is None or value == "":
            text = "-"
        else:
            text = str(value)
        return text.replace("|", "\\|")

    lines = [
        "# Validation Execution Matrix",
        "",
        f"- Packages: `{matrix.get('package_count')}`",
        f"- Ready to launch: `{matrix.get('ready_to_launch_count')}`",
        f"- Blocked/manual: `{matrix.get('blocked_count')}`",
        "",
        "| Wave | Stage | Owner | Package | Current | Ready | Blockers | Missing env | Artifacts | Next action | Command |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in matrix.get("rows") or []:
        lines.append(
            "| "
            + " | ".join(
                [
                    cell(row.get("wave")),
                    cell(row.get("stage")),
                    cell(row.get("owner")),
                    f"`{cell(row.get('package_id'))}`",
                    cell(row.get("current_status")),
                    cell(row.get("ready_to_launch")),
                    cell(row.get("blocked_reasons")),
                    cell(row.get("missing_effective_env")),
                    cell(row.get("current_artifacts")),
                    cell(render_current_next_action_summary(row.get("current_next_action"))),
                    f"`{cell(row.get('command'))}`",
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def write_execution_matrix(owner_launch_plan_json_path: Path, output_dir: Path) -> tuple[Path, Path]:
    owner_launch_plan = load_json(owner_launch_plan_json_path)
    matrix = build_execution_matrix_json(owner_launch_plan)
    markdown_path = output_dir / "execution_matrix.md"
    json_path = output_dir / "execution_matrix.json"
    markdown_path.write_text(render_execution_matrix(matrix), encoding="utf-8")
    json_path.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return markdown_path, json_path


def claim_state_for_matrix_row(row: dict) -> str:
    if row.get("ready_to_launch") is True:
        return "ready_to_claim"
    blocked_reasons = {str(value) for value in row.get("blocked_reasons") or []}
    current_status = str(row.get("current_status") or "")
    if "missing_effective_env" in blocked_reasons:
        return "blocked_missing_env"
    if "depends_on_prior_waves" in blocked_reasons:
        return "blocked_dependency_wave"
    if "manual_launch_required" in blocked_reasons:
        return "manual_claim_required"
    if current_status in {"pass", "fail", "blocked"}:
        return f"has_current_{current_status}_evidence"
    return "not_ready"


def build_agent_claims_json(matrix: dict) -> dict:
    claims = []
    for row in matrix.get("rows") or []:
        if not isinstance(row, dict):
            continue
        package_id = str(row.get("package_id") or "")
        claim_state = claim_state_for_matrix_row(row)
        claims.append(
            {
                "claim_id": f"claim-{package_id}",
                "package_id": package_id,
                "owner": str(row.get("owner") or "unassigned"),
                "wave": int(row.get("wave") or 0),
                "stage": row.get("stage"),
                "claim_state": claim_state,
                "ready_to_launch": bool(row.get("ready_to_launch")),
                "current_status": str(row.get("current_status") or "not_run"),
                "blocked_reasons": [str(value) for value in row.get("blocked_reasons") or []],
                "missing_effective_env": [str(value) for value in row.get("missing_effective_env") or []],
                "depends_on_waves": [int(value) for value in row.get("depends_on_waves") or []],
                "resource_tags": [str(value) for value in row.get("resource_tags") or []],
                "current_artifacts": [str(value) for value in row.get("current_artifacts") or []],
                "current_next_action": row.get("current_next_action") if isinstance(row.get("current_next_action"), dict) else {},
                "command": str(row.get("command") or ""),
                "script_path": str(row.get("script_path") or ""),
                "prompt_path": row.get("prompt_path"),
                "status_path": str(row.get("status_path") or ""),
                "claim_output": {
                    "status_file": "agent_status.json",
                    "allowed_status": ["pass", "fail", "blocked"],
                    "must_update_current_status": True,
                },
            }
        )
    claims.sort(key=lambda item: (int(item.get("wave") or 0), int(item.get("stage") or 999), str(item.get("claim_id") or "")))
    return {
        "schema_version": 1,
        "artifact": "validation-agent-claims",
        "source_artifact": str(matrix.get("artifact") or ""),
        "claim_count": len(claims),
        "ready_to_claim_count": sum(1 for claim in claims if claim.get("claim_state") == "ready_to_claim"),
        "blocked_claim_count": sum(1 for claim in claims if str(claim.get("claim_state") or "").startswith("blocked_")),
        "manual_claim_count": sum(1 for claim in claims if claim.get("claim_state") == "manual_claim_required"),
        "claims": claims,
    }


def render_current_next_action_summary(action: object) -> str:
    if not isinstance(action, dict) or not action:
        return "-"
    missing_values = (
        action.get("missing_stability")
        or action.get("missing_readiness")
        or action.get("missing_diagnostics")
        or action.get("missing_endpoints")
        or action.get("missing_profiles")
        or []
    )
    parts = []
    if missing_values:
        parts.append("missing=" + ",".join(str(value) for value in missing_values))
    if action.get("login_command"):
        parts.append("login_command=" + str(action.get("login_command")))
    if action.get("token_login_command"):
        parts.append("token_login_command=" + str(action.get("token_login_command")))
    if action.get("action"):
        parts.append("action=" + str(action.get("action")))
    return "; ".join(parts) or "-"


def render_agent_claims(claims_payload: dict) -> str:
    def cell(value: object) -> str:
        if isinstance(value, list):
            text = ", ".join(str(item) for item in value) or "-"
        elif value is None or value == "":
            text = "-"
        else:
            text = str(value)
        return text.replace("|", "\\|")

    lines = [
        "# Validation Agent Claims",
        "",
        f"- Claims: `{claims_payload.get('claim_count')}`",
        f"- Ready to claim: `{claims_payload.get('ready_to_claim_count')}`",
        f"- Blocked: `{claims_payload.get('blocked_claim_count')}`",
        f"- Manual: `{claims_payload.get('manual_claim_count')}`",
        "",
        "| Claim | Wave | Stage | Owner | Package | State | Current | Blockers | Missing env | Next action | Command |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for claim in claims_payload.get("claims") or []:
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{cell(claim.get('claim_id'))}`",
                    cell(claim.get("wave")),
                    cell(claim.get("stage")),
                    cell(claim.get("owner")),
                    f"`{cell(claim.get('package_id'))}`",
                    cell(claim.get("claim_state")),
                    cell(claim.get("current_status")),
                    cell(claim.get("blocked_reasons")),
                    cell(claim.get("missing_effective_env")),
                    cell(render_current_next_action_summary(claim.get("current_next_action"))),
                    f"`{cell(claim.get('command'))}`",
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def write_agent_claims(execution_matrix_json_path: Path, output_dir: Path) -> tuple[Path, Path]:
    matrix = load_json(execution_matrix_json_path)
    claims_payload = build_agent_claims_json(matrix)
    markdown_path = output_dir / "agent_claims.md"
    json_path = output_dir / "agent_claims.json"
    markdown_path.write_text(render_agent_claims(claims_payload), encoding="utf-8")
    json_path.write_text(json.dumps(claims_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return markdown_path, json_path


def build_agent_spawn_plan_json(claims_payload: dict, output_dir: Path) -> dict:
    def output_ref(path: Path) -> str:
        if path.is_absolute():
            return stable_path(path)
        return str(path).replace("\\", "/")

    def prompt_text_for(prompt_ref: str) -> str:
        if not prompt_ref:
            return ""
        candidates = [Path(prompt_ref)]
        if not Path(prompt_ref).is_absolute():
            candidates.append(REPO_ROOT / prompt_ref)
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return candidate.read_text(encoding="utf-8").strip()
        return ""

    lock_helper_ref = output_ref(output_dir / "claim_lock_helper.ps1")
    dispatch_manifest_ref = output_ref(output_dir / "dispatch_manifest.json")

    def spawn_entry_for(claim: dict) -> dict:
        claim_id = str(claim.get("claim_id") or "")
        script_path = str(claim.get("script_path") or "")
        prompt_path = stable_artifact_ref(claim.get("prompt_path"))
        prompt_text = prompt_text_for(prompt_path)
        lock_command = (
            "powershell -NoProfile -ExecutionPolicy Bypass -File "
            f"'{lock_helper_ref}' -ClaimId {claim_id} -AgentId <agent-id>"
        )
        lock_prefix = (
            f"& '{lock_helper_ref}' -ClaimId {claim_id} -AgentId '<agent-id>'; "
            "if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; "
            "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED='1'; "
        )
        run_command = str(claim.get("command") or "")
        codex_spawn_script = (
            f"{lock_prefix}"
            f"$env:TAMANDUA_AGENT_CLAIM_ID='{claim_id}'; "
            "$env:TAMANDUA_AGENT_ID='<agent-id>'; "
            f"Get-Content -Raw '{prompt_path}' | codex exec --cd . -"
        )
        claude_spawn_script = (
            f"{lock_prefix}"
            f"$env:TAMANDUA_AGENT_CLAIM_ID='{claim_id}'; "
            "$env:TAMANDUA_AGENT_ID='<agent-id>'; "
            f"Get-Content -Raw '{prompt_path}' | claude --print"
        )
        command_templates = {
            "codex": (
                "powershell -NoProfile -ExecutionPolicy Bypass -Command "
                f"{ps_single_quoted(codex_spawn_script)}"
            ),
            "claude": (
                "powershell -NoProfile -ExecutionPolicy Bypass -Command "
                f"{ps_single_quoted(claude_spawn_script)}"
            ),
        }
        copy_paste_prompt = "\n".join(
            [
                f"Claim ID: {claim_id}",
                f"Package ID: {str(claim.get('package_id') or '')}",
                f"Prompt path: {prompt_path}",
                "Working directory: .",
                f"Claim env: TAMANDUA_AGENT_CLAIM_ID={claim_id}",
                "Agent env: TAMANDUA_AGENT_ID=<agent-id>",
                f"Claim lock command: {lock_command}",
                f"Run command: {run_command}",
                f"Codex spawn template: {command_templates['codex']}",
                f"Claude spawn template: {command_templates['claude']}",
                "",
                prompt_text,
            ]
        ).strip()
        return {
            "claim_id": claim_id,
            "package_id": str(claim.get("package_id") or ""),
            "owner": str(claim.get("owner") or "unassigned"),
            "prompt_path": prompt_path,
            "script_path": stable_artifact_ref(script_path),
            "status_path": stable_artifact_ref(claim.get("status_path")),
            "resource_tags": [str(value) for value in claim.get("resource_tags") or []],
            "lock_command": lock_command,
            "run_command": run_command,
            "cwd": ".",
            "claim_id_env": f"TAMANDUA_AGENT_CLAIM_ID={claim_id}",
            "agent_id_env": "TAMANDUA_AGENT_ID=<agent-id>",
            "agent_spawn_command_templates": command_templates,
            "prompt_text": prompt_text,
            "copy_paste_prompt": copy_paste_prompt,
            "current_next_action": claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {},
        }

    batches = []
    for wave, batch_index, batch in ready_claim_parallel_batches(claims_payload):
        entries = [spawn_entry_for(claim) for claim in batch]
        batches.append(
            {
                "wave": wave,
                "batch": batch_index,
                "claim_count": len(entries),
                "claims": entries,
            }
        )
    blocked_or_manual = []
    for claim in claims_payload.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        state = str(claim.get("claim_state") or "")
        if state == "ready_to_claim":
            continue
        blocked_or_manual.append(
            {
                "claim_id": str(claim.get("claim_id") or ""),
                "package_id": str(claim.get("package_id") or ""),
                "owner": str(claim.get("owner") or "unassigned"),
                "claim_state": state,
                "missing_effective_env": [str(value) for value in claim.get("missing_effective_env") or []],
                "blocked_reasons": [str(value) for value in claim.get("blocked_reasons") or []],
                "depends_on_waves": [int(value) for value in claim.get("depends_on_waves") or []],
                "prompt_path": stable_artifact_ref(claim.get("prompt_path")),
                "current_next_action": claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {},
            }
        )
    env_bundle_ready_source_claims = []
    env_bundle_still_blocked_claims = []
    for claim in claims_payload.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        missing_env = [str(value) for value in claim.get("missing_effective_env") or []]
        if not missing_env:
            continue
        blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or []}
        if blocked_reasons <= {"missing_effective_env"}:
            env_ready_claim = dict(claim)
            env_ready_claim["claim_state"] = "ready_to_claim"
            env_ready_claim["missing_effective_env"] = []
            env_ready_claim["blocked_reasons"] = []
            env_bundle_ready_source_claims.append(env_ready_claim)
        else:
            remaining_reasons = sorted(blocked_reasons - {"missing_effective_env"})
            post_env_state = str(claim.get("claim_state") or "")
            if "depends_on_prior_waves" in remaining_reasons:
                post_env_state = "blocked_dependency_wave"
            elif "manual_launch_required" in remaining_reasons:
                post_env_state = "manual_claim_required"
            env_bundle_still_blocked_claims.append(
                {
                    "claim_id": str(claim.get("claim_id") or ""),
                    "package_id": str(claim.get("package_id") or ""),
                    "owner": str(claim.get("owner") or "unassigned"),
                    "claim_state": post_env_state,
                    "missing_effective_env": [],
                    "blocked_reasons": remaining_reasons,
                    "depends_on_waves": [int(value) for value in claim.get("depends_on_waves") or []],
                    "prompt_path": stable_artifact_ref(claim.get("prompt_path")),
                    "current_next_action": claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {},
                }
            )
    env_bundle_ready_payload = {"claims": env_bundle_ready_source_claims}
    env_bundle_ready_batches = []
    for wave, batch_index, batch in ready_claim_parallel_batches(env_bundle_ready_payload):
        entries = [spawn_entry_for(claim) for claim in batch]
        env_bundle_ready_batches.append(
            {
                "wave": wave,
                "batch": batch_index,
                "claim_count": len(entries),
                "claims": entries,
            }
        )
    ready_claim_count = sum(int(batch.get("claim_count") or 0) for batch in batches)
    env_bundle_ready_claim_count = sum(int(batch.get("claim_count") or 0) for batch in env_bundle_ready_batches)
    plan = {
        "schema_version": 1,
        "artifact": "validation-agent-spawn-plan",
        "source_artifact": str(claims_payload.get("artifact") or ""),
        "ready_batch_count": len(batches),
        "ready_claim_count": ready_claim_count,
        "current_env_multi_agent_actionable": ready_claim_count >= 2,
        "env_bundle_ready_batch_count": len(env_bundle_ready_batches),
        "env_bundle_ready_claim_count": env_bundle_ready_claim_count,
        "post_env_bundle_multi_agent_actionable": env_bundle_ready_claim_count >= 2,
        "env_bundle_still_blocked_claim_count": len(env_bundle_still_blocked_claims),
        "blocked_or_manual_claim_count": len(blocked_or_manual),
        "execute_policy": {
            "one_provider_per_claim": True,
            "override_switch": "-AllowDuplicateProviderPerClaim",
            "override_env": "TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM",
            "parallel_switch": "-Parallel",
        },
        "claim_lock_helper_path": lock_helper_ref,
        "dispatch_manifest_path": dispatch_manifest_ref,
        "refresh_command": (
            "python tools/detection_validation/run_preflight_work_package.py "
            f"--refresh-claim-status-report '{dispatch_manifest_ref}'"
        ),
        "batches": batches,
        "env_bundle_ready_batches": env_bundle_ready_batches,
        "env_bundle_still_blocked_claims": env_bundle_still_blocked_claims,
        "blocked_or_manual_claims": blocked_or_manual,
    }
    if ready_claim_count < 2:
        plan["not_multi_agent_actionable_reason"] = "fewer than two ready claims"
    if env_bundle_ready_claim_count < 2:
        plan["post_env_bundle_not_multi_agent_actionable_reason"] = (
            "fewer than two env-bundle ready claims"
        )
    return plan


def render_agent_spawn_plan(plan: dict) -> str:
    def cell(value: object) -> str:
        if isinstance(value, list):
            text = ", ".join(str(item) for item in value) or "-"
        elif value is None or value == "":
            text = "-"
        else:
            text = str(value)
        return text.replace("|", "\\|")

    lines = [
        "# Validation Agent Spawn Plan",
        "",
        f"- Ready batches: `{plan.get('ready_batch_count')}`",
        f"- Ready claims: `{plan.get('ready_claim_count')}`",
        f"- Current-env multi-agent actionable: `{str(bool(plan.get('current_env_multi_agent_actionable'))).lower()}`",
        f"- Env-bundle ready batches: `{plan.get('env_bundle_ready_batch_count')}`",
        f"- Env-bundle ready claims: `{plan.get('env_bundle_ready_claim_count')}`",
        f"- Post-env-bundle multi-agent actionable: `{str(bool(plan.get('post_env_bundle_multi_agent_actionable'))).lower()}`",
        f"- Env-bundle still blocked claims: `{plan.get('env_bundle_still_blocked_claim_count')}`",
        f"- Blocked/manual claims: `{plan.get('blocked_or_manual_claim_count')}`",
        "- Execute policy: one provider per claim unless `-AllowDuplicateProviderPerClaim` is passed and `TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM=1` is set.",
        f"- Claim lock helper: `{plan.get('claim_lock_helper_path')}`",
        f"- Refresh command: `{plan.get('refresh_command')}`",
    ]
    if plan.get("not_multi_agent_actionable_reason"):
        lines.append(f"- Not multi-agent actionable reason: `{plan.get('not_multi_agent_actionable_reason')}`")
    if plan.get("post_env_bundle_not_multi_agent_actionable_reason"):
        lines.append(
            "- Post-env-bundle not multi-agent actionable reason: "
            f"`{plan.get('post_env_bundle_not_multi_agent_actionable_reason')}`"
        )
    lines.append("")
    for batch in plan.get("batches") or []:
        lines.extend(
            [
                f"## Wave {batch.get('wave')} Batch {batch.get('batch')}",
                "",
                "| Claim | Owner | Package | Resources | Next action | Prompt | Codex template | Claude template | Lock command | Run command | Status |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for claim in batch.get("claims") or []:
            templates = claim.get("agent_spawn_command_templates") or {}
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{cell(claim.get('claim_id'))}`",
                        cell(claim.get("owner")),
                        f"`{cell(claim.get('package_id'))}`",
                        cell(claim.get("resource_tags")),
                        cell(render_current_next_action_summary(claim.get("current_next_action"))),
                        f"`{cell(claim.get('prompt_path'))}`",
                        f"`{cell(templates.get('codex'))}`",
                        f"`{cell(templates.get('claude'))}`",
                        f"`{cell(claim.get('lock_command'))}`",
                        f"`{cell(claim.get('run_command'))}`",
                        f"`{cell(claim.get('status_path'))}`",
                    ]
                )
                + " |"
            )
        lines.append("")
        lines.extend(["### Copy/Paste Spawn Prompts", ""])
        for claim in batch.get("claims") or []:
            prompt = str(claim.get("copy_paste_prompt") or "").strip()
            if not prompt:
                continue
            lines.extend(
                [
                    f"#### {cell(claim.get('claim_id'))}",
                    "",
                    "```text",
                    prompt,
                    "```",
                    "",
                ]
            )
    for batch in plan.get("env_bundle_ready_batches") or []:
        lines.extend(
            [
                f"## Ready After Env Bundle Wave {batch.get('wave')} Batch {batch.get('batch')}",
                "",
                "Set every value in `env_unblock_queue.md` before spawning these agents.",
                "",
                "| Claim | Owner | Package | Resources | Next action | Prompt | Codex template | Claude template | Lock command | Run command | Status |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for claim in batch.get("claims") or []:
            templates = claim.get("agent_spawn_command_templates") or {}
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{cell(claim.get('claim_id'))}`",
                        cell(claim.get("owner")),
                        f"`{cell(claim.get('package_id'))}`",
                        cell(claim.get("resource_tags")),
                        cell(render_current_next_action_summary(claim.get("current_next_action"))),
                        f"`{cell(claim.get('prompt_path'))}`",
                        f"`{cell(templates.get('codex'))}`",
                        f"`{cell(templates.get('claude'))}`",
                        f"`{cell(claim.get('lock_command'))}`",
                        f"`{cell(claim.get('run_command'))}`",
                        f"`{cell(claim.get('status_path'))}`",
                    ]
                )
                + " |"
            )
        lines.append("")
        lines.extend(["### Copy/Paste Env-Bundle Spawn Prompts", ""])
        for claim in batch.get("claims") or []:
            prompt = str(claim.get("copy_paste_prompt") or "").strip()
            if not prompt:
                continue
            lines.extend(
                [
                    f"#### {cell(claim.get('claim_id'))}",
                    "",
                    "```text",
                    prompt,
                    "```",
                    "",
                ]
            )
    if plan.get("env_bundle_still_blocked_claims"):
        lines.extend(
            [
                "## Still Blocked After Env Bundle",
                "",
                "| Claim | Owner | Package | State | Missing env | Blockers | Depends | Next action | Prompt |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for claim in plan.get("env_bundle_still_blocked_claims") or []:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{cell(claim.get('claim_id'))}`",
                        cell(claim.get("owner")),
                        f"`{cell(claim.get('package_id'))}`",
                        cell(claim.get("claim_state")),
                        cell(claim.get("missing_effective_env")),
                        cell(claim.get("blocked_reasons")),
                        cell(claim.get("depends_on_waves")),
                        cell(render_current_next_action_summary(claim.get("current_next_action"))),
                        f"`{cell(claim.get('prompt_path'))}`",
                    ]
                )
                + " |"
            )
        lines.append("")
    if plan.get("blocked_or_manual_claims"):
        lines.extend(
            [
                "## Blocked Or Manual Claims",
                "",
                "| Claim | Owner | Package | State | Missing env | Blockers | Depends | Next action | Prompt |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for claim in plan.get("blocked_or_manual_claims") or []:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{cell(claim.get('claim_id'))}`",
                        cell(claim.get("owner")),
                        f"`{cell(claim.get('package_id'))}`",
                        cell(claim.get("claim_state")),
                        cell(claim.get("missing_effective_env")),
                        cell(claim.get("blocked_reasons")),
                        cell(claim.get("depends_on_waves")),
                        cell(render_current_next_action_summary(claim.get("current_next_action"))),
                        f"`{cell(claim.get('prompt_path'))}`",
                    ]
                )
                + " |"
            )
        lines.append("")
    return "\n".join(lines)


def write_agent_spawn_plan(agent_claims_json_path: Path, output_dir: Path) -> tuple[Path, Path]:
    claims_payload = load_json(agent_claims_json_path)
    plan = build_agent_spawn_plan_json(claims_payload, output_dir)
    markdown_path = output_dir / "agent_spawn_plan.md"
    json_path = output_dir / "agent_spawn_plan.json"
    markdown_path.write_text(render_agent_spawn_plan(plan), encoding="utf-8")
    json_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return markdown_path, json_path


def render_agent_spawn_launcher(agent_spawn_plan_json_path: Path) -> str:
    plan_ref = stable_path(agent_spawn_plan_json_path)
    return "\n".join(
        [
            "# Validation Agent Spawn Launcher",
            "param(",
            "  [ValidateSet('codex','claude','all','balanced')]",
            "  [string]$Provider = 'all',",
            "  [ValidateSet('ready','env-bundle','all')]",
            "  [string]$Phase = 'ready',",
            "  [string]$ClaimId = '',",
            "  [string]$AgentId = '',",
            "  [switch]$ShowBlocked,",
            "  [switch]$AllowDuplicateProviderPerClaim,",
            "  [switch]$Parallel,",
            "  [switch]$Execute",
            ")",
            "$ErrorActionPreference = 'Stop'",
            f"$PlanPath = {ps_single_quoted(plan_ref)}",
            "if (-not (Test-Path -LiteralPath $PlanPath)) { throw ('agent spawn plan not found: ' + $PlanPath) }",
            "if (-not $AgentId) { $AgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_SPAWN_AGENT_ID') }",
            "if (-not $AgentId) { $AgentId = [Environment]::UserName }",
            "if (-not $AgentId) { throw 'AgentId is required; pass -AgentId or set TAMANDUA_SPAWN_AGENT_ID.' }",
            "if ($AgentId -notmatch '^[A-Za-z0-9_.-]+$') { throw 'AgentId may only contain letters, digits, underscore, dot, or dash.' }",
            "$Plan = Get-Content -Raw -LiteralPath $PlanPath | ConvertFrom-Json",
            "$PlanDir = Split-Path -Parent $PlanPath",
            "$EnvQueuePath = Join-Path $PlanDir 'env_unblock_queue.json'",
            "$Rows = @()",
            "$BlockedRowCount = 0",
            "$BalancedProviderIndex = 0",
            "function Format-NextAction([object]$Action) {",
            "  if ($null -eq $Action) { return '-' }",
            "  $Parts = @()",
            "  foreach ($Name in @('missing_readiness','action','login_command','token_env','token_login_command','target_server','saved_server')) {",
            "    if ($Action.PSObject.Properties.Name -contains $Name) {",
            "      $Value = $Action.$Name",
            "      if ($null -ne $Value -and [string]$Value -ne '') { $Parts += ($Name + '=' + ((@($Value)) -join ',')) }",
            "    }",
            "  }",
            "  if ($Parts.Count -eq 0) { return '-' }",
            "  return ($Parts -join '; ')",
            "}",
            "function Add-SpawnRows([object[]]$Batches, [string]$BatchPhase) {",
            "  foreach ($Batch in @($Batches)) {",
            "    foreach ($Claim in @($Batch.claims)) {",
            "      if ($ClaimId -and ([string]$Claim.claim_id) -ne $ClaimId) { continue }",
            "      if ($Provider -eq 'balanced') {",
            "        $BalancedProvider = if (($script:BalancedProviderIndex % 2) -eq 0) { 'codex' } else { 'claude' }",
            "        $script:BalancedProviderIndex += 1",
            "        $BalancedCommand = ([string]$Claim.agent_spawn_command_templates.$BalancedProvider).Replace('<agent-id>', $AgentId)",
            "        $script:Rows += [pscustomobject]@{ phase = $BatchPhase; provider = $BalancedProvider; claim_id = [string]$Claim.claim_id; next_action = (Format-NextAction $Claim.current_next_action); command = $BalancedCommand }",
            "        continue",
            "      }",
            "      if ($Provider -in @('codex','all')) {",
            "        $script:Rows += [pscustomobject]@{ phase = $BatchPhase; provider = 'codex'; claim_id = [string]$Claim.claim_id; next_action = (Format-NextAction $Claim.current_next_action); command = ([string]$Claim.agent_spawn_command_templates.codex).Replace('<agent-id>', $AgentId) }",
            "      }",
            "      if ($Provider -in @('claude','all')) {",
            "        $script:Rows += [pscustomobject]@{ phase = $BatchPhase; provider = 'claude'; claim_id = [string]$Claim.claim_id; next_action = (Format-NextAction $Claim.current_next_action); command = ([string]$Claim.agent_spawn_command_templates.claude).Replace('<agent-id>', $AgentId) }",
            "      }",
            "    }",
            "  }",
            "}",
            "function Show-BlockedClaims {",
            "  foreach ($Claim in @($Plan.blocked_or_manual_claims)) {",
            "    if ($ClaimId -and ([string]$Claim.claim_id) -ne $ClaimId) { continue }",
            "    $script:BlockedRowCount += 1",
            "    $Missing = @($Claim.missing_effective_env) -join ','",
            "    $Reasons = @($Claim.blocked_reasons) -join ','",
            "    $Prompt = [string]$Claim.prompt_path",
            "    $NextAction = Format-NextAction $Claim.current_next_action",
            "    Write-Host ('[blocked][' + [string]$Claim.claim_state + '][' + [string]$Claim.claim_id + '] missing_env=' + $Missing + '; reasons=' + $Reasons + '; next_action=' + $NextAction + '; prompt=' + $Prompt)",
            "  }",
            "}",
            "function Show-EnvBundleReadiness {",
            "  if (-not (Test-Path -LiteralPath $script:EnvQueuePath)) { Write-Host ('[env-bundle-readiness] missing_queue=' + $script:EnvQueuePath); return }",
            "  try { $Queue = Get-Content -Raw -LiteralPath $script:EnvQueuePath | ConvertFrom-Json } catch { Write-Host ('[env-bundle-readiness] invalid_queue=' + [string]$_.Exception.Message); return }",
            "  try { $RequiredEnv = Get-EnvBundleRequiredEnv $Queue } catch { Write-Host ('[env-bundle-readiness] invalid_queue=' + [string]$_.Exception.Message); return }",
            "  try { Assert-EnvBundleQueueMatchesPlan $Queue } catch { Write-Host ('[env-bundle-readiness] invalid_queue=' + [string]$_.Exception.Message); return }",
            "  $PresentEnv = @($RequiredEnv | Where-Object { [Environment]::GetEnvironmentVariable($_) })",
            "  $MissingEnv = @($RequiredEnv | Where-Object { -not [Environment]::GetEnvironmentVariable($_) })",
            "  Write-Host ('[env-bundle-readiness] present=' + [string]$PresentEnv.Count + '/' + [string]$RequiredEnv.Count + ' missing=' + (($MissingEnv -join ',') -replace '^$', '-'))",
            "}",
            "function Get-EnvBundleReadyClaimIdsFromPlan {",
            "  $PlanClaimIds = @()",
            "  foreach ($Batch in @($script:Plan.env_bundle_ready_batches)) {",
            "    foreach ($Claim in @($Batch.claims)) {",
            "      $ClaimIdText = [string]$Claim.claim_id",
            "      if ($ClaimIdText) { $PlanClaimIds += $ClaimIdText }",
            "    }",
            "  }",
            "  return @($PlanClaimIds | Sort-Object)",
            "}",
            "function Get-EnvBundleStillBlockedClaimIdsFromPlan {",
            "  $PlanClaimIds = @()",
            "  foreach ($Claim in @($script:Plan.env_bundle_still_blocked_claims)) {",
            "    $ClaimIdText = [string]$Claim.claim_id",
            "    if ($ClaimIdText) { $PlanClaimIds += $ClaimIdText }",
            "  }",
            "  return @($PlanClaimIds | Sort-Object)",
            "}",
            "function Assert-EnvBundleQueueMatchesPlan([object]$Queue) {",
            "  if (-not ($Queue.PSObject.Properties.Name -contains 'ready_after_all_env_claim_ids')) { throw 'Env unblock queue missing ready_after_all_env_claim_ids.' }",
            "  if ($Queue.ready_after_all_env_claim_ids -isnot [System.Array]) { throw 'Env unblock queue ready_after_all_env_claim_ids is not a list.' }",
            "  if (-not ($Queue.PSObject.Properties.Name -contains 'still_blocked_after_all_env_claim_ids')) { throw 'Env unblock queue missing still_blocked_after_all_env_claim_ids.' }",
            "  if ($Queue.still_blocked_after_all_env_claim_ids -isnot [System.Array]) { throw 'Env unblock queue still_blocked_after_all_env_claim_ids is not a list.' }",
            "  $QueueClaimIds = @()",
            "  foreach ($ClaimId in @($Queue.ready_after_all_env_claim_ids)) {",
            "    $ClaimIdText = [string]$ClaimId",
            "    if (-not $ClaimIdText) { throw 'Env unblock queue ready_after_all_env_claim_ids contains empty value.' }",
            "    $QueueClaimIds += $ClaimIdText",
            "  }",
            "  $QueueClaimIds = @($QueueClaimIds | Sort-Object)",
            "  $PlanClaimIds = Get-EnvBundleReadyClaimIdsFromPlan",
            "  if (($QueueClaimIds -join '|') -ne ($PlanClaimIds -join '|')) { throw ('Env unblock queue ready_after_all_env_claim_ids mismatch: queue=' + ($QueueClaimIds -join ',') + ' plan=' + ($PlanClaimIds -join ',')) }",
            "  $QueueStillBlockedClaimIds = @()",
            "  foreach ($ClaimId in @($Queue.still_blocked_after_all_env_claim_ids)) {",
            "    $ClaimIdText = [string]$ClaimId",
            "    if (-not $ClaimIdText) { throw 'Env unblock queue still_blocked_after_all_env_claim_ids contains empty value.' }",
            "    $QueueStillBlockedClaimIds += $ClaimIdText",
            "  }",
            "  $QueueStillBlockedClaimIds = @($QueueStillBlockedClaimIds | Sort-Object)",
            "  $PlanStillBlockedClaimIds = Get-EnvBundleStillBlockedClaimIdsFromPlan",
            "  if (($QueueStillBlockedClaimIds -join '|') -ne ($PlanStillBlockedClaimIds -join '|')) { throw ('Env unblock queue still_blocked_after_all_env_claim_ids mismatch: queue=' + ($QueueStillBlockedClaimIds -join ',') + ' plan=' + ($PlanStillBlockedClaimIds -join ',')) }",
            "}",
            "function Get-EnvBundleRequiredEnv([object]$Queue) {",
            "  $RequiredEnv = @()",
            "  foreach ($Entry in @($Queue.entries)) {",
            "    $EnvName = [string]$Entry.env",
            "    if (-not $EnvName) { throw 'Env unblock queue contains an entry without env.' }",
            "    $RequiredEnv += $EnvName",
            "  }",
            "  $DuplicateEnv = @($RequiredEnv | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })",
            "  if ($DuplicateEnv.Count -gt 0) { throw ('Env unblock queue contains duplicate env entries: ' + (($DuplicateEnv | Sort-Object) -join ', ')) }",
            "  if (-not ($Queue.PSObject.Properties.Name -contains 'required_env_names')) { throw 'Env unblock queue missing required_env_names.' }",
            "  if ($Queue.required_env_names -isnot [System.Array]) { throw 'Env unblock queue required_env_names is not a list.' }",
            "  $RequiredEnvNames = @()",
            "  foreach ($RequiredEnvName in @($Queue.required_env_names)) {",
            "    $RequiredEnvNameText = [string]$RequiredEnvName",
            "    if (-not $RequiredEnvNameText) { throw 'Env unblock queue required_env_names contains empty value.' }",
            "    $RequiredEnvNames += $RequiredEnvNameText",
            "  }",
            "  $RequiredEnvNames = @($RequiredEnvNames | Sort-Object)",
            "  $EntryEnvNames = @($RequiredEnv | Sort-Object)",
            "  if (($RequiredEnvNames -join '|') -ne ($EntryEnvNames -join '|')) { throw ('Env unblock queue required_env_names mismatch: required_env_names=' + ($RequiredEnvNames -join ',') + ' entries=' + ($EntryEnvNames -join ',')) }",
            "  if (-not ($Queue.PSObject.Properties.Name -contains 'all_env_powershell_set_commands')) { throw 'Env unblock queue missing all_env_powershell_set_commands.' }",
            "  if ($Queue.all_env_powershell_set_commands -isnot [System.Array]) { throw 'Env unblock queue all_env_powershell_set_commands is not a list.' }",
            "  $CommandEnvNames = @()",
            "  foreach ($Command in @($Queue.all_env_powershell_set_commands)) {",
            "    $CommandText = [string]$Command",
            "    if (-not $CommandText) { throw 'Env unblock queue all_env_powershell_set_commands contains empty value.' }",
            "    $CommandMatch = [regex]::Match($CommandText, '^\\$env:([A-Za-z_][A-Za-z0-9_]*)\\s*=')",
            "    if (-not $CommandMatch.Success) { throw ('Env unblock queue invalid env set command: ' + $CommandText) }",
            "    $CommandEnvNames += $CommandMatch.Groups[1].Value",
            "  }",
            "  $CommandEnvNames = @($CommandEnvNames | Sort-Object)",
            "  if (($CommandEnvNames -join '|') -ne ($EntryEnvNames -join '|')) { throw ('Env unblock queue env set commands mismatch: commands=' + ($CommandEnvNames -join ',') + ' entries=' + ($EntryEnvNames -join ',')) }",
            "  return @($RequiredEnv | Sort-Object)",
            "}",
            "function Assert-EnvBundleReadyForExecution {",
            "  if (-not (Test-Path -LiteralPath $script:EnvQueuePath)) { throw ('env bundle queue not found: ' + $script:EnvQueuePath) }",
            "  try { $Queue = Get-Content -Raw -LiteralPath $script:EnvQueuePath | ConvertFrom-Json } catch { throw ('env bundle queue invalid: ' + [string]$_.Exception.Message) }",
            "  $RequiredEnv = Get-EnvBundleRequiredEnv $Queue",
            "  Assert-EnvBundleQueueMatchesPlan $Queue",
            "  $MissingEnv = @($RequiredEnv | Where-Object { -not [Environment]::GetEnvironmentVariable($_) })",
            "  if ($MissingEnv.Count -gt 0) { throw ('Refusing env-bundle spawn while env values are missing: ' + ($MissingEnv -join ', ')) }",
            "  $PlaceholderEnv = @($RequiredEnv | Where-Object { [Environment]::GetEnvironmentVariable($_) -match '^<set-.+>$' })",
            "  if ($PlaceholderEnv.Count -gt 0) { throw ('Refusing env-bundle spawn while placeholder env values remain: ' + ($PlaceholderEnv -join ', ')) }",
            "}",
            "if ($Phase -in @('ready','all')) { Add-SpawnRows @($Plan.batches) 'ready' }",
            "if ($Phase -in @('env-bundle','all')) { Add-SpawnRows @($Plan.env_bundle_ready_batches) 'env-bundle' }",
            "if ($Phase -in @('env-bundle','all')) { Show-EnvBundleReadiness }",
            "if ($ShowBlocked) { Show-BlockedClaims }",
            "if (-not $Rows -and -not $BlockedRowCount) { Write-Host 'No matching spawn commands or blocked claims.'; exit 0 }",
            "if ($Execute) {",
            "  if ([Environment]::GetEnvironmentVariable('TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH') -ne '1') {",
            "    throw 'Refusing to execute agent spawn commands without TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH=1.'",
            "  }",
            "  if ($Phase -in @('env-bundle','all') -and [Environment]::GetEnvironmentVariable('TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH') -ne '1') {",
            "    throw 'Refusing to execute env-bundle spawn commands without TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH=1.'",
            "  }",
            "  if ($Phase -in @('env-bundle','all')) { Assert-EnvBundleReadyForExecution }",
            "}",
            "if ($Execute) {",
            "if (-not $AllowDuplicateProviderPerClaim) {",
            "  $DuplicateClaims = @($Rows | Group-Object claim_id | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })",
            "  if ($DuplicateClaims.Count -gt 0) {",
            "    throw ('Refusing to execute multiple providers for the same claim without -AllowDuplicateProviderPerClaim: ' + ($DuplicateClaims -join ', '))",
            "  }",
            "} elseif ([Environment]::GetEnvironmentVariable('TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM') -ne '1') {",
            "  $DuplicateClaims = @($Rows | Group-Object claim_id | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })",
            "  if ($DuplicateClaims.Count -gt 0) {",
            "    throw ('Refusing duplicate provider execution without TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM=1: ' + ($DuplicateClaims -join ', '))",
            "  }",
            "} else {",
            "  $DuplicateClaims = @($Rows | Group-Object claim_id | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })",
            "  if ($DuplicateClaims.Count -gt 0) { Write-Host ('[duplicate-provider-override] claims=' + ($DuplicateClaims -join ',')) }",
            "}",
            "}",
            "foreach ($Row in $Rows) {",
            "  Write-Host ('[' + $Row.phase + '][' + $Row.provider + '][' + $Row.claim_id + '] next_action=' + $Row.next_action + '; command=' + $Row.command)",
            "}",
            "if (-not $Execute) {",
            "  Write-Host 'Dry run only. Pass -Execute and set TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH=1 to run commands.'",
            "  exit 0",
            "}",
            "if ($Parallel) {",
            "  $Jobs = @()",
            "  $SpawnWorkingDirectory = (Get-Location).Path",
            "  foreach ($Row in $Rows) {",
            "    $Jobs += Start-Job -Name ($Row.provider + '-' + $Row.claim_id) -ArgumentList $Row.phase, $Row.provider, $Row.claim_id, $Row.command, $SpawnWorkingDirectory -ScriptBlock {",
            "      param([string]$Phase, [string]$Provider, [string]$ClaimId, [string]$Command, [string]$WorkingDirectory)",
            "      Write-Host ('[spawn-execute][' + $Phase + '][' + $Provider + '][' + $ClaimId + ']')",
            "      try {",
            "        if ($WorkingDirectory) { Set-Location -LiteralPath $WorkingDirectory }",
            "        Invoke-Expression $Command",
            "        $ExitCode = if ($LASTEXITCODE -ne $null) { [int]$LASTEXITCODE } else { 0 }",
            "        [pscustomobject]@{ phase = $Phase; provider = $Provider; claim_id = $ClaimId; exit_code = $ExitCode; error = '' }",
            "      } catch {",
            "        [pscustomobject]@{ phase = $Phase; provider = $Provider; claim_id = $ClaimId; exit_code = 1; error = [string]$_.Exception.Message }",
            "      }",
            "    }",
            "  }",
            "  $Jobs | Wait-Job | Out-Null",
            "  $Failures = @()",
            "  foreach ($Job in $Jobs) {",
            "    $JobReceiveErrors = @()",
            "    $Results = @(Receive-Job -Job $Job -ErrorAction SilentlyContinue -ErrorVariable JobReceiveErrors)",
            "    $SawResult = $false",
            "    foreach ($Result in @($Results)) {",
            "      if ($Result.PSObject.Properties.Name -contains 'exit_code') { $SawResult = $true }",
            "      if ($Result.PSObject.Properties.Name -contains 'exit_code' -and [int]$Result.exit_code -ne 0) {",
            "        $Failure = [string]$Result.provider + ':' + [string]$Result.claim_id + '=' + [string]$Result.exit_code",
            "        if ($Result.PSObject.Properties.Name -contains 'error' -and [string]$Result.error) { $Failure += ' ' + [string]$Result.error }",
            "        if ($JobReceiveErrors.Count -gt 0) { $Failure += ' stderr=' + (($JobReceiveErrors | ForEach-Object { [string]$_ }) -join ' | ') }",
            "        $Failures += $Failure",
            "      }",
            "    }",
            "    if (-not $SawResult) {",
            "      $NoResultFailure = $Job.Name + ' produced no result'",
            "      if ($JobReceiveErrors.Count -gt 0) { $NoResultFailure += ' stderr=' + (($JobReceiveErrors | ForEach-Object { [string]$_ }) -join ' | ') }",
            "      $Failures += $NoResultFailure",
            "    }",
            "    if ($Job.State -ne 'Completed') { $Failures += ($Job.Name + ' state ' + [string]$Job.State) }",
            "    if ($Job.ChildJobs.Count -gt 0 -and $Job.ChildJobs[0].JobStateInfo.Reason) { $Failures += ($Job.Name + ' reason ' + [string]$Job.ChildJobs[0].JobStateInfo.Reason) }",
            "    Remove-Job -Job $Job -Force",
            "  }",
            "  if ($Failures.Count -gt 0) { throw ('Agent spawn parallel execution failed: ' + ($Failures -join '; ')) }",
            "  exit 0",
            "}",
            "foreach ($Row in $Rows) {",
            "  Invoke-Expression $Row.command",
            "  $SequentialExitCode = if ($LASTEXITCODE -ne $null) { [int]$LASTEXITCODE } else { 0 }",
            "  if ($SequentialExitCode -ne 0) { throw ('Agent spawn sequential execution failed: ' + [string]$Row.provider + ':' + [string]$Row.claim_id + '=' + [string]$SequentialExitCode) }",
            "}",
            "",
        ]
    )


def write_agent_spawn_launcher(agent_spawn_plan_json_path: Path, output_dir: Path) -> Path:
    launcher_path = output_dir / "agent_spawn_launcher.ps1"
    launcher_path.write_text(render_agent_spawn_launcher(agent_spawn_plan_json_path), encoding="utf-8")
    return launcher_path


def summarize_claim_lock(lock_path: Path | None, claim_id: str) -> dict:
    if lock_path is None:
        return {"lock_state": "unlocked", "lock_path": "", "lock_agent_id": "", "locked_at": ""}
    lock_ref = stable_artifact_ref(lock_path)
    if not lock_path.exists():
        return {"lock_state": "unlocked", "lock_path": lock_ref, "lock_agent_id": "", "locked_at": ""}
    try:
        payload = load_json(lock_path)
    except json.JSONDecodeError:
        return {"lock_state": "invalid", "lock_path": lock_ref, "lock_agent_id": "", "locked_at": ""}
    if str(payload.get("claim_id") or "") != claim_id:
        return {"lock_state": "invalid", "lock_path": lock_ref, "lock_agent_id": "", "locked_at": ""}
    return {
        "lock_state": "locked",
        "lock_path": lock_ref,
        "lock_agent_id": str(payload.get("agent_id") or ""),
        "locked_at": str(payload.get("locked_at") or ""),
    }


def resolve_claim_status_path(status_path_value: str, archive_dir: Path | None = None) -> Path:
    status_path = Path(status_path_value)
    candidates = [status_path]
    if not status_path.is_absolute():
        candidates.append(REPO_ROOT / status_path)
    if archive_dir and status_path_value:
        normalized = status_path_value.replace("\\", "/")
        marker = "/" + archive_dir.name + "/"
        if marker in normalized:
            suffix = normalized.split(marker, 1)[1]
            candidates.append(archive_dir / suffix)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return status_path


def build_claim_status_report_json(claims_payload: dict, lock_dir: Path | None = None) -> dict:
    claim_entries = []
    archive_dir = lock_dir.parent if lock_dir else None
    for claim in claims_payload.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        claim_id = str(claim.get("claim_id") or "")
        lock_path = lock_dir / f"{claim_id}.claim-lock.json" if lock_dir and claim_id else None
        lock_summary = summarize_claim_lock(lock_path, claim_id)
        status_path_value = str(claim.get("status_path") or "")
        status_summary = summarize_agent_status(resolve_claim_status_path(status_path_value, archive_dir)) if status_path_value else {}
        agent_status = str(status_summary.get("agent_status") or claim.get("current_status") or "not_run")
        claim_entries.append(
            {
                "claim_id": claim_id,
                "package_id": str(claim.get("package_id") or ""),
                "owner": str(claim.get("owner") or "unassigned"),
                "wave": int(claim.get("wave") or 0),
                "stage": claim.get("stage"),
                "claim_state": str(claim.get("claim_state") or ""),
                "ready_to_launch": bool(claim.get("ready_to_launch")),
                "agent_status": agent_status,
                "agent_claim_id": str(status_summary.get("agent_claim_id") or ""),
                "agent_id": str(status_summary.get("agent_id") or ""),
                "agent_exit_code": status_summary.get("agent_exit_code", claim.get("current_exit_code")),
                "agent_blocker_cleared": bool(status_summary.get("agent_blocker_cleared")),
                "agent_notes": [str(value) for value in status_summary.get("agent_notes") or []],
                "lock_state": lock_summary["lock_state"],
                "lock_path": lock_summary["lock_path"],
                "lock_agent_id": lock_summary["lock_agent_id"],
                "locked_at": lock_summary["locked_at"],
                "missing_effective_env": [str(value) for value in claim.get("missing_effective_env") or []],
                "blocked_reasons": [str(value) for value in claim.get("blocked_reasons") or []],
                "missing_profiles": [str(value) for value in status_summary.get("agent_missing_profiles") or []],
                "artifacts": [
                    stable_artifact_ref(value)
                    for value in status_summary.get("agent_artifacts") or claim.get("current_artifacts") or []
                ],
                "current_next_action": claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {},
                "resource_tags": [str(value) for value in claim.get("resource_tags") or []],
                "status_path": status_path_value,
                "script_path": str(claim.get("script_path") or ""),
                "prompt_path": claim.get("prompt_path"),
                "command": str(claim.get("command") or ""),
            }
        )
    claim_entries.sort(
        key=lambda item: (
            int(item.get("wave") or 0),
            int(item.get("stage") or 999),
            str(item.get("claim_id") or ""),
        )
    )
    status_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    for entry in claim_entries:
        status = str(entry.get("agent_status") or "unknown")
        state = str(entry.get("claim_state") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        state_counts[state] = state_counts.get(state, 0) + 1
    return {
        "schema_version": 1,
        "artifact": "validation-claim-status-report",
        "source_artifact": str(claims_payload.get("artifact") or ""),
        "claim_count": len(claim_entries),
        "ready_to_claim_count": sum(1 for entry in claim_entries if entry.get("claim_state") == "ready_to_claim"),
        "blocked_claim_count": sum(1 for entry in claim_entries if str(entry.get("claim_state") or "").startswith("blocked_")),
        "manual_claim_count": sum(1 for entry in claim_entries if entry.get("claim_state") == "manual_claim_required"),
        "locked_claim_count": sum(1 for entry in claim_entries if entry.get("lock_state") == "locked"),
        "invalid_lock_count": sum(1 for entry in claim_entries if entry.get("lock_state") == "invalid"),
        "status_counts": dict(sorted(status_counts.items())),
        "claim_state_counts": dict(sorted(state_counts.items())),
        "claims": claim_entries,
    }


def render_claim_status_report(report: dict) -> str:
    def cell(value: object) -> str:
        if isinstance(value, list):
            text = ", ".join(str(item) for item in value) or "-"
        elif value is None or value == "":
            text = "-"
        else:
            text = str(value)
        return text.replace("|", "\\|")

    lines = [
        "# Validation Claim Status Report",
        "",
        f"- Claims: `{report.get('claim_count')}`",
        f"- Ready to claim: `{report.get('ready_to_claim_count')}`",
        f"- Blocked: `{report.get('blocked_claim_count')}`",
        f"- Manual: `{report.get('manual_claim_count')}`",
        f"- Locked claims: `{report.get('locked_claim_count')}`",
        f"- Invalid locks: `{report.get('invalid_lock_count')}`",
        f"- Status counts: `{', '.join(f'{key}={value}' for key, value in (report.get('status_counts') or {}).items()) or '-'}`",
        "",
        "| Claim | Wave | Stage | Owner | Package | State | Agent status | Agent claim | Agent id | Lock | Lock agent | Locked at | Exit | Missing env | Missing profiles | Artifacts | Next action | Command |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for claim in report.get("claims") or []:
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{cell(claim.get('claim_id'))}`",
                    cell(claim.get("wave")),
                    cell(claim.get("stage")),
                    cell(claim.get("owner")),
                    f"`{cell(claim.get('package_id'))}`",
                    cell(claim.get("claim_state")),
                    cell(claim.get("agent_status")),
                    f"`{cell(claim.get('agent_claim_id'))}`",
                    cell(claim.get("agent_id")),
                    cell(claim.get("lock_state")),
                    cell(claim.get("lock_agent_id")),
                    cell(claim.get("locked_at")),
                    cell(claim.get("agent_exit_code")),
                    cell(claim.get("missing_effective_env")),
                    cell(claim.get("missing_profiles")),
                    cell(claim.get("artifacts")),
                    cell(render_current_next_action_summary(claim.get("current_next_action"))),
                    f"`{cell(claim.get('command'))}`",
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def write_claim_status_report(agent_claims_json_path: Path, output_dir: Path) -> tuple[Path, Path]:
    claims_payload = load_json(agent_claims_json_path)
    report = build_claim_status_report_json(claims_payload, output_dir / "claim_locks")
    markdown_path = output_dir / "claim_status_report.md"
    json_path = output_dir / "claim_status_report.json"
    markdown_path.write_text(render_claim_status_report(report), encoding="utf-8")
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return markdown_path, json_path


def resolve_dispatch_manifest_path_ref(path_value: object, manifest_dir: Path) -> Path:
    value = str(path_value or "")
    if not value:
        raise ValueError("dispatch manifest is missing a required path")
    path = Path(value)
    if path.is_absolute():
        return path
    repo_path = REPO_ROOT / path
    if repo_path.exists() or value.startswith("docs/") or value.startswith("docs\\"):
        return repo_path
    return manifest_dir / path


def refresh_claim_status_report_from_manifest(manifest_path: Path) -> tuple[Path, Path]:
    manifest = load_json(manifest_path)
    manifest_dir = manifest_path.parent
    agent_claims_json_path = resolve_dispatch_manifest_path_ref(
        manifest.get("agent_claims_json_path"),
        manifest_dir,
    )
    output_dir_value = manifest.get("output_dir")
    if output_dir_value:
        output_dir = resolve_dispatch_manifest_path_ref(output_dir_value, manifest_dir)
    else:
        report_path_value = manifest.get("claim_status_report_path")
        output_dir = resolve_dispatch_manifest_path_ref(report_path_value, manifest_dir).parent
    return write_claim_status_report(agent_claims_json_path, output_dir)


def refresh_dispatch_handoff_artifacts_from_manifest(manifest_path: Path) -> dict[str, str]:
    manifest = load_json(manifest_path)
    manifest_dir = manifest_path.parent
    packages = [
        package_with_latest_current_next_action(package)
        for package in manifest.get("packages") or []
        if isinstance(package, dict)
    ]
    for package in packages:
        for derived_key in (
            "launcher_selected",
            "manual_reason",
            "staged_launcher_selected",
            "staged_stage",
            "handoff_notes",
        ):
            package.pop(derived_key, None)
    output_dir = resolve_dispatch_manifest_path_ref(manifest.get("output_dir"), manifest_dir)
    preflight_path = resolve_dispatch_manifest_path_ref(manifest.get("source_preflight"), manifest_dir)
    claim_lock_helper_ref = str(manifest.get("claim_lock_helper_path") or "")
    if claim_lock_helper_ref:
        for package in packages:
            package["claim_lock_helper_path"] = claim_lock_helper_ref

    script_paths: dict[str, Path] = {}
    refreshed_package_script_paths: list[Path] = []
    prompt_paths: dict[str, Path] = {}
    for package in packages:
        package_id = str(package.get("package_id") or "")
        if not package_id:
            continue
        script_path = resolve_dispatch_manifest_path_ref(package.get("script_path"), manifest_dir)
        script_paths[package_id] = script_path
        script_path.parent.mkdir(parents=True, exist_ok=True)
        package_output_dir = resolve_dispatch_manifest_path_ref(
            package.get("output_dir") or package_manifest_output_dir(package, script_path),
            manifest_dir,
        )
        script_path.write_text(
            render_package_script(
                package,
                Path(stable_path(preflight_path)),
                package_output_dir=Path(stable_path(package_output_dir)),
            ),
            encoding="utf-8",
        )
        refreshed_package_script_paths.append(script_path)
        prompt_path_value = package.get("prompt_path")
        if prompt_path_value:
            prompt_path = resolve_dispatch_manifest_path_ref(prompt_path_value, manifest_dir)
            prompt_paths[package_id] = write_agent_prompt_to_path(package, script_path, preflight_path, prompt_path)
        else:
            prompt_paths[package_id] = write_agent_prompt(package, script_path, preflight_path, output_dir)

    env_checklist_path = (
        resolve_dispatch_manifest_path_ref(manifest.get("env_checklist_path"), manifest_dir)
        if manifest.get("env_checklist_path")
        else None
    )
    env_template_path = (
        resolve_dispatch_manifest_path_ref(manifest.get("env_template_path"), manifest_dir)
        if manifest.get("env_template_path")
        else None
    )
    existing_launcher_paths = [
        resolve_dispatch_manifest_path_ref(value, manifest_dir)
        for value in manifest.get("launcher_paths") or []
    ]
    existing_staged_launcher_paths = [
        resolve_dispatch_manifest_path_ref(value, manifest_dir)
        for value in manifest.get("staged_launcher_paths") or []
    ]
    launcher_output_dir = existing_launcher_paths[0].parent if existing_launcher_paths else output_dir / "launchers"
    launcher_output_dir.mkdir(parents=True, exist_ok=True)
    launcher_paths = write_wave_launchers(packages, script_paths, launcher_output_dir)
    staged_launcher_output_dir = (
        existing_staged_launcher_paths[0].parent if existing_staged_launcher_paths else launcher_output_dir
    )
    staged_launcher_output_dir.mkdir(parents=True, exist_ok=True)
    staged_launcher_paths = write_staged_wave_launchers(packages, script_paths, staged_launcher_output_dir)
    roster_path = write_agent_roster(packages, script_paths, prompt_paths, output_dir)
    owner_launch_plan_path = write_owner_launch_plan(
        packages,
        output_dir,
        script_paths,
        prompt_paths,
        env_checklist_path,
        env_template_path,
    )
    owner_launch_plan_json_path = write_owner_launch_plan_json(
        packages,
        output_dir,
        script_paths,
        prompt_paths,
        env_checklist_path,
        env_template_path,
    )
    execution_matrix_path, execution_matrix_json_path = write_execution_matrix(owner_launch_plan_json_path, output_dir)
    agent_claims_path, agent_claims_json_path = write_agent_claims(execution_matrix_json_path, output_dir)
    agent_spawn_plan_path, agent_spawn_plan_json_path = write_agent_spawn_plan(agent_claims_json_path, output_dir)
    agent_spawn_launcher_path = write_agent_spawn_launcher(agent_spawn_plan_json_path, output_dir)
    claim_status_report_path, claim_status_report_json_path = write_claim_status_report(agent_claims_json_path, output_dir)
    claim_lock_helper_path = write_claim_lock_helper(agent_claims_json_path, output_dir)
    env_unblock_queue_path, env_unblock_queue_json_path = write_env_unblock_queue(
        agent_claims_json_path,
        output_dir,
        agent_spawn_launcher_path,
    )
    ready_claims_launcher_path = write_ready_claims_launcher(agent_claims_json_path, output_dir)
    ready_claims_parallel_launcher_path = write_ready_claims_parallel_launcher(agent_claims_json_path, output_dir)
    env_bundle_ready_claims_launcher_path = write_env_bundle_ready_claims_launcher(agent_claims_json_path, output_dir)
    dispatch_prelaunch_validation_path = write_dispatch_prelaunch_validation(
        output_dir,
        agent_spawn_launcher_path,
        ready_claims_launcher_path,
        ready_claims_parallel_launcher_path,
        env_bundle_ready_claims_launcher_path,
        claim_lock_helper_path,
        env_unblock_queue_json_path,
        agent_spawn_plan_json_path,
        agent_claims_json_path,
        claim_status_report_json_path,
        manifest_path,
        owner_launch_plan_json_path,
        execution_matrix_json_path,
    )
    dispatch_runner_path = None
    if manifest.get("dispatch_runner_path"):
        dispatch_runner_path = write_dispatch_runner(
            packages,
            output_dir,
            script_paths,
            launcher_paths,
            staged_launcher_paths,
            manifest_path,
        )
    dispatch_brief_path = write_dispatch_brief(
        packages,
        preflight_path,
        output_dir,
        script_paths,
        prompt_paths,
        launcher_paths,
        staged_launcher_paths,
        roster_path,
        env_checklist_path,
        env_template_path,
        owner_launch_plan_path,
        owner_launch_plan_json_path,
        execution_matrix_path,
        execution_matrix_json_path,
        agent_claims_path,
        agent_claims_json_path,
        agent_spawn_plan_path,
        agent_spawn_plan_json_path,
        agent_spawn_launcher_path,
        claim_status_report_path,
        claim_status_report_json_path,
        claim_lock_helper_path,
        env_unblock_queue_path,
        env_unblock_queue_json_path,
        ready_claims_launcher_path,
        ready_claims_parallel_launcher_path,
        env_bundle_ready_claims_launcher_path,
        dispatch_prelaunch_validation_path,
        manifest_path,
        dispatch_runner_path,
    )
    manifest = build_dispatch_manifest(
        packages,
        preflight_path,
        output_dir,
        script_paths,
        prompt_paths,
        launcher_paths,
        staged_launcher_paths,
        roster_path,
        env_checklist_path,
        env_template_path,
        owner_launch_plan_path,
        owner_launch_plan_json_path,
        execution_matrix_path,
        execution_matrix_json_path,
        agent_claims_path,
        agent_claims_json_path,
        agent_spawn_plan_path,
        agent_spawn_plan_json_path,
        agent_spawn_launcher_path,
        claim_status_report_path,
        claim_status_report_json_path,
        claim_lock_helper_path,
        env_unblock_queue_path,
        env_unblock_queue_json_path,
        ready_claims_launcher_path,
        ready_claims_parallel_launcher_path,
        env_bundle_ready_claims_launcher_path,
        dispatch_prelaunch_validation_path,
        dispatch_brief_path,
        dispatch_runner_path,
        manifest.get("selection_mode"),
        manifest.get("selected_wave"),
    )
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "package_scripts": ",".join(stable_path(path) for path in refreshed_package_script_paths),
        "agent_roster": str(roster_path),
        "owner_launch_plan": str(owner_launch_plan_path),
        "owner_launch_plan_json": str(owner_launch_plan_json_path),
        "execution_matrix": str(execution_matrix_path),
        "execution_matrix_json": str(execution_matrix_json_path),
        "agent_claims": str(agent_claims_path),
        "agent_claims_json": str(agent_claims_json_path),
        "agent_spawn_plan": str(agent_spawn_plan_path),
        "agent_spawn_plan_json": str(agent_spawn_plan_json_path),
        "agent_spawn_launcher": str(agent_spawn_launcher_path),
        "claim_status_report": str(claim_status_report_path),
        "claim_status_report_json": str(claim_status_report_json_path),
        "claim_lock_helper": str(claim_lock_helper_path),
        "env_unblock_queue": str(env_unblock_queue_path),
        "env_unblock_queue_json": str(env_unblock_queue_json_path),
        "ready_claims_launcher": str(ready_claims_launcher_path),
        "ready_claims_parallel_launcher": str(ready_claims_parallel_launcher_path),
        "env_bundle_ready_claims_launcher": str(env_bundle_ready_claims_launcher_path),
        "dispatch_prelaunch_validation": str(dispatch_prelaunch_validation_path),
        "dispatch_brief": str(dispatch_brief_path),
        "launcher_paths": ",".join(stable_path(path) for path in launcher_paths),
        "staged_launcher_paths": ",".join(stable_path(path) for path in staged_launcher_paths),
        "dispatch_runner": str(dispatch_runner_path) if dispatch_runner_path else "",
    }


def render_claim_lock_helper(claims_payload: dict) -> str:
    claim_ids = sorted(
        str(claim.get("claim_id") or "")
        for claim in claims_payload.get("claims") or []
        if isinstance(claim, dict) and str(claim.get("claim_id") or "")
    )
    lines = [
        "# Validation Claim Lock Helper",
        "# Creates an atomic local lock file before a validation agent starts a claim.",
        "param(",
        "  [string]$ClaimId = '',",
        "  [string]$AgentId = [Environment]::UserName,",
        "  [switch]$List,",
        "  [string]$ResetClaimId = '',",
        "  [switch]$ResetAll,",
        "  [switch]$Force",
        ")",
        "$ErrorActionPreference = 'Stop'",
        "Set-StrictMode -Version Latest",
        f"$KnownClaims = {ps_array(claim_ids)}",
        "$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
        "$LockDir = Join-Path $ScriptDir 'claim_locks'",
        "New-Item -ItemType Directory -Force -Path $LockDir | Out-Null",
        "function Assert-KnownClaim([string]$KnownClaimId) {",
        "  if ($KnownClaims -notcontains $KnownClaimId) {",
        "    Write-Host ('Unknown validation claim: ' + $KnownClaimId)",
        "    exit 2",
        "  }",
        "}",
        "function Get-ClaimLockPath([string]$KnownClaimId) {",
        "  return (Join-Path $LockDir ($KnownClaimId + '.claim-lock.json'))",
        "}",
        "if ($List) {",
        "  $Locks = @(Get-ChildItem -LiteralPath $LockDir -Filter '*.claim-lock.json' -ErrorAction SilentlyContinue)",
        "  if ($Locks.Count -eq 0) { Write-Host 'No claim locks found.'; exit 0 }",
        "  foreach ($Lock in $Locks) { Get-Content -Raw -LiteralPath $Lock.FullName | Write-Host }",
        "  exit 0",
        "}",
        "if ($ResetAll) {",
        "  if (-not $Force) { Write-Host 'Refusing to reset all claim locks without -Force.'; exit 4 }",
        "  Get-ChildItem -LiteralPath $LockDir -Filter '*.claim-lock.json' -ErrorAction SilentlyContinue | Remove-Item -Force",
        "  Write-Host 'All claim locks reset.'",
        "  exit 0",
        "}",
        "if ($ResetClaimId) {",
        "  if (-not $Force) { Write-Host 'Refusing to reset claim lock without -Force.'; exit 4 }",
        "  Assert-KnownClaim $ResetClaimId",
        "  $ResetLockPath = Get-ClaimLockPath $ResetClaimId",
        "  if (Test-Path -LiteralPath $ResetLockPath) { Remove-Item -LiteralPath $ResetLockPath -Force; Write-Host ('Claim lock reset: ' + $ResetLockPath) } else { Write-Host ('Claim lock not found: ' + $ResetLockPath) }",
        "  exit 0",
        "}",
        "if (-not $ClaimId) {",
        "  Write-Host 'ClaimId is required unless -List, -ResetClaimId, or -ResetAll is used.'",
        "  exit 2",
        "}",
        "if ($KnownClaims -notcontains $ClaimId) {",
        "  Write-Host ('Unknown validation claim: ' + $ClaimId)",
        "  exit 2",
        "}",
        "if (-not $AgentId) {",
        "  Write-Host 'AgentId is required.'",
        "  exit 2",
        "}",
        "if ($AgentId -notmatch '^[A-Za-z0-9_.-]+$') {",
        "  Write-Host 'AgentId may only contain letters, digits, underscore, dot, or dash.'",
        "  exit 2",
        "}",
        "$LockPath = Get-ClaimLockPath $ClaimId",
        "if (Test-Path $LockPath) {",
        "  Write-Host ('Claim already locked: ' + $LockPath)",
        "  Get-Content -Raw -Path $LockPath | Write-Host",
        "  exit 3",
        "}",
        "$Payload = [ordered]@{",
        "  claim_id = $ClaimId",
        "  agent_id = $AgentId",
        "  locked_at = [DateTimeOffset]::UtcNow.ToString('o')",
        "  lock_path = $LockPath",
        "}",
        "$Json = $Payload | ConvertTo-Json -Depth 5",
        "$Bytes = [System.Text.Encoding]::UTF8.GetBytes($Json + [Environment]::NewLine)",
        "$Stream = $null",
        "try {",
        "  $Stream = [System.IO.File]::Open($LockPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)",
        "  $Stream.Write($Bytes, 0, $Bytes.Length)",
        "} catch [System.IO.IOException] {",
        "  Write-Host ('Claim already locked: ' + $LockPath)",
        "  exit 3",
        "} finally {",
        "  if ($Stream) { $Stream.Dispose() }",
        "}",
        "Write-Host ('Claim lock acquired: ' + $LockPath)",
        "exit 0",
        "",
    ]
    return "\n".join(lines)


def write_claim_lock_helper(agent_claims_json_path: Path, output_dir: Path) -> Path:
    claims_payload = load_json(agent_claims_json_path)
    helper_path = output_dir / "claim_lock_helper.ps1"
    helper_path.write_text(render_claim_lock_helper(claims_payload), encoding="utf-8")
    return helper_path


def claim_current_next_action_env(claim: dict) -> list[str]:
    action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
    return next_action_env_from_action(action)


def next_action_summary_direct_for_env(env_name: str, action: object, summary: str) -> bool:
    action_env = next_action_env_from_action(action)
    if action_env:
        return env_name in action_env
    summary_text = str(summary or "")
    if env_name in summary_text:
        return True
    if env_name.startswith("TAMANDUA_FRESH_RESTORE") and (
        "fresh-restore" in summary_text or "restore metadata" in summary_text
    ):
        return True
    if env_name.startswith("CALDERA_") and "CALDERA" in summary_text:
        return True
    if env_name == "TAMANDUA_PROXMOX_PASSWORD" and (
        "Proxmox" in summary_text or "QGA" in summary_text
    ):
        return True
    if env_name == "TAMANDUA_TOKEN" and "tamandua-ctl" in summary_text:
        return True
    return False


def build_env_unblock_queue_json(
    claims_payload: dict,
    env_bundle_launcher_path: Path | None = None,
    agent_spawn_launcher_path: Path | None = None,
    environ: dict[str, str] | None = None,
) -> dict:
    env = environ if environ is not None else os.environ
    env_entries: dict[str, dict] = {}
    next_action_env_entries: dict[str, dict] = {}
    claims = [claim for claim in claims_payload.get("claims") or [] if isinstance(claim, dict)]
    for claim in claims_payload.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        next_action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
        for env_name in claim_current_next_action_env(claim):
            entry = next_action_env_entries.setdefault(
                env_name,
                {
                    "env": env_name,
                    "owners": set(),
                    "claim_ids": [],
                    "package_ids": [],
                    "waves": set(),
                    "token_login_commands": set(),
                    "actions": [],
                },
            )
            entry["owners"].add(str(claim.get("owner") or "unassigned"))
            entry["claim_ids"].append(str(claim.get("claim_id") or ""))
            entry["package_ids"].append(str(claim.get("package_id") or ""))
            entry["waves"].add(int(claim.get("wave") or 0))
            if next_action.get("token_login_command"):
                entry["token_login_commands"].add(str(next_action.get("token_login_command")))
            if next_action.get("action"):
                entry["actions"].append(str(next_action.get("action")))
        missing_env = [str(value) for value in claim.get("missing_effective_env") or []]
        if not missing_env:
            continue
        for env_name in missing_env:
            entry = env_entries.setdefault(
                env_name,
                {
                    "env": env_name,
                    "owners": set(),
                    "claim_ids": [],
                    "package_ids": [],
                    "waves": set(),
                    "immediate_claim_ids": [],
                    "dependency_claim_ids": [],
                    "manual_claim_ids": [],
                    "next_action_summaries": [],
                    "direct_next_action_summaries": [],
                    "indirect_next_action_summaries": [],
                },
            )
            entry["owners"].add(str(claim.get("owner") or "unassigned"))
            claim_id = str(claim.get("claim_id") or "")
            entry["claim_ids"].append(claim_id)
            entry["package_ids"].append(str(claim.get("package_id") or ""))
            entry["waves"].add(int(claim.get("wave") or 0))
            next_action_summary = render_current_next_action_summary(claim.get("current_next_action"))
            if claim_id and next_action_summary != "-":
                entry["next_action_summaries"].append(f"{claim_id}: {next_action_summary}")
                summary = f"{claim_id}: {next_action_summary}"
                current_next_action = claim.get("current_next_action")
                if next_action_summary_direct_for_env(env_name, current_next_action, next_action_summary):
                    entry["direct_next_action_summaries"].append(summary)
                else:
                    entry["indirect_next_action_summaries"].append(summary)
            blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or []}
            if "depends_on_prior_waves" in blocked_reasons:
                entry["dependency_claim_ids"].append(claim_id)
            elif "manual_launch_required" in blocked_reasons:
                entry["manual_claim_ids"].append(claim_id)
            else:
                entry["immediate_claim_ids"].append(claim_id)
    entries = []
    for entry in env_entries.values():
        claim_ids = sorted(set(value for value in entry["claim_ids"] if value))
        immediate_claim_ids = sorted(set(value for value in entry["immediate_claim_ids"] if value))
        dependency_claim_ids = sorted(set(value for value in entry["dependency_claim_ids"] if value))
        manual_claim_ids = sorted(set(value for value in entry["manual_claim_ids"] if value))
        env_name = str(entry["env"])
        single_env_ready_claim_ids = []
        single_env_still_blocked_claim_ids = []
        remaining_env_after_setting: dict[str, list[str]] = {}
        for claim in claims:
            claim_id = str(claim.get("claim_id") or "")
            missing_env = [str(value) for value in claim.get("missing_effective_env") or []]
            if env_name not in missing_env:
                continue
            remaining_env = sorted(value for value in missing_env if value != env_name)
            remaining_env_after_setting[claim_id] = remaining_env
            blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or []}
            if not remaining_env and blocked_reasons <= {"missing_effective_env"}:
                single_env_ready_claim_ids.append(claim_id)
            else:
                single_env_still_blocked_claim_ids.append(claim_id)
        entries.append(
            {
                "env": env_name,
                "owners": sorted(entry["owners"]),
                "claim_ids": claim_ids,
                "package_ids": sorted(set(value for value in entry["package_ids"] if value)),
                "waves": sorted(entry["waves"]),
                "claim_count": len(claim_ids),
                "immediate_claim_count": len(immediate_claim_ids),
                "dependency_claim_count": len(dependency_claim_ids),
                "manual_claim_count": len(manual_claim_ids),
                "immediate_claim_ids": immediate_claim_ids,
                "dependency_claim_ids": dependency_claim_ids,
                "manual_claim_ids": manual_claim_ids,
                "single_env_ready_claim_ids": sorted(single_env_ready_claim_ids),
                "single_env_still_blocked_claim_ids": sorted(single_env_still_blocked_claim_ids),
                "remaining_env_after_setting": remaining_env_after_setting,
                "next_action_summaries": sorted(set(value for value in entry["next_action_summaries"] if value)),
                "direct_next_action_summaries": sorted(
                    set(value for value in entry["direct_next_action_summaries"] if value)
                ),
                "indirect_next_action_summaries": sorted(
                    set(value for value in entry["indirect_next_action_summaries"] if value)
                ),
                "placeholder": env_template_placeholder(env_name),
                "powershell_set_command": f"$env:{env_name} = '{env_template_placeholder(env_name)}'",
                "copy_paste_unblock_prompt": "\n".join(
                    [
                        f"Env: {env_name}",
                        f"Set command: $env:{env_name} = '{env_template_placeholder(env_name)}'",
                        f"Claims ready after setting only this env: {', '.join(sorted(single_env_ready_claim_ids)) or '-'}",
                        f"Claims still blocked after setting only this env: {', '.join(sorted(single_env_still_blocked_claim_ids)) or '-'}",
                        f"Immediate claims unlocked by this env: {', '.join(immediate_claim_ids) or '-'}",
                        f"Dependency-gated claims also needing this env: {', '.join(dependency_claim_ids) or '-'}",
                        f"Manual claims also needing this env: {', '.join(manual_claim_ids) or '-'}",
                        f"All affected packages: {', '.join(sorted(set(value for value in entry['package_ids'] if value))) or '-'}",
                        (
                            "Direct claim next actions: "
                            + (
                                " | ".join(
                                    sorted(set(value for value in entry["direct_next_action_summaries"] if value))
                                )
                                or "-"
                            )
                        ),
                        (
                            "Other affected claim next actions: "
                            + (
                                " | ".join(
                                    sorted(set(value for value in entry["indirect_next_action_summaries"] if value))
                                )
                                or "-"
                            )
                        ),
                        (
                            "Affected claim next actions: "
                            + (
                                " | ".join(sorted(set(value for value in entry["next_action_summaries"] if value)))
                                or "-"
                            )
                        ),
                    ]
                ),
            }
        )
    entries.sort(
        key=lambda item: (
            -int(item.get("immediate_claim_count") or 0),
            -int(item.get("claim_count") or 0),
            str(item.get("env") or ""),
        )
    )
    next_action_entries = []
    for entry in next_action_env_entries.values():
        env_name = str(entry["env"])
        next_action_entries.append(
            {
                "env": env_name,
                "owners": sorted(entry["owners"]),
                "claim_ids": sorted(set(value for value in entry["claim_ids"] if value)),
                "package_ids": sorted(set(value for value in entry["package_ids"] if value)),
                "waves": sorted(entry["waves"]),
                "claim_count": len(set(value for value in entry["claim_ids"] if value)),
                "placeholder": env_template_placeholder(env_name),
                "powershell_set_command": f"$env:{env_name} = '{env_template_placeholder(env_name)}'",
                "token_login_commands": sorted(entry["token_login_commands"]),
                "actions": sorted(set(value for value in entry["actions"] if value)),
            }
        )
    existing_next_action_env = {str(entry.get("env") or "") for entry in next_action_entries}
    for entry in entries:
        env_name = str(entry.get("env") or "")
        if not env_name or env_name in existing_next_action_env:
            continue
        direct_summaries = [str(value) for value in entry.get("direct_next_action_summaries") or [] if value]
        if not direct_summaries:
            continue
        next_action_entries.append(
            {
                "env": env_name,
                "owners": [str(value) for value in entry.get("owners") or []],
                "claim_ids": [str(value) for value in entry.get("claim_ids") or []],
                "package_ids": [str(value) for value in entry.get("package_ids") or []],
                "waves": [int(value) for value in entry.get("waves") or []],
                "claim_count": int(entry.get("claim_count") or 0),
                "placeholder": env_template_placeholder(env_name),
                "powershell_set_command": f"$env:{env_name} = '{env_template_placeholder(env_name)}'",
                "token_login_commands": [],
                "actions": direct_summaries,
            }
        )
        existing_next_action_env.add(env_name)
    next_action_entries.sort(
        key=lambda item: (
            -int(item.get("claim_count") or 0),
            str(item.get("env") or ""),
        )
    )
    all_env_names = {str(entry.get("env") or "") for entry in entries}
    def env_value_is_placeholder(env_name: str) -> bool:
        value = str(env.get(env_name) or "")
        return value == env_template_placeholder(env_name) or bool(re.fullmatch(r"<set-.+>", value))

    currently_present_env_names = sorted(
        name for name in all_env_names if env.get(name) and not env_value_is_placeholder(name)
    )
    currently_placeholder_env_names = sorted(
        name for name in all_env_names if env.get(name) and env_value_is_placeholder(name)
    )
    currently_missing_env_names = sorted(name for name in all_env_names if not env.get(name))
    ready_after_all_env_claim_ids = []
    still_blocked_after_all_env_claim_ids = []
    ready_with_current_env_claim_ids = []
    still_blocked_with_current_env_claim_ids = []
    for claim in claims:
        claim_id = str(claim.get("claim_id") or "")
        missing_env = {str(value) for value in claim.get("missing_effective_env") or []}
        if not missing_env:
            continue
        remaining_env = sorted(missing_env - all_env_names)
        current_remaining_env = sorted(value for value in missing_env if not env.get(value) or env_value_is_placeholder(value))
        blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or []}
        if not remaining_env and blocked_reasons <= {"missing_effective_env"}:
            ready_after_all_env_claim_ids.append(claim_id)
        else:
            still_blocked_after_all_env_claim_ids.append(claim_id)
        if not current_remaining_env and blocked_reasons <= {"missing_effective_env"}:
            ready_with_current_env_claim_ids.append(claim_id)
        else:
            still_blocked_with_current_env_claim_ids.append(claim_id)
    return {
        "schema_version": 1,
        "artifact": "validation-env-unblock-queue",
        "source_artifact": str(claims_payload.get("artifact") or ""),
        "env_count": len(entries),
        "required_env_names": sorted(all_env_names),
        "next_action_env_count": len(next_action_entries),
        "blocked_claim_count": int(claims_payload.get("blocked_claim_count") or 0),
        "current_env_present_count": len(currently_present_env_names),
        "current_env_missing_count": len(currently_missing_env_names),
        "current_env_placeholder_count": len(currently_placeholder_env_names),
        "current_env_present_names": currently_present_env_names,
        "current_env_missing_names": currently_missing_env_names,
        "current_env_placeholder_names": currently_placeholder_env_names,
        "ready_with_current_env_claim_ids": sorted(ready_with_current_env_claim_ids),
        "still_blocked_with_current_env_claim_ids": sorted(still_blocked_with_current_env_claim_ids),
        "all_env_powershell_set_commands": [str(entry.get("powershell_set_command") or "") for entry in entries],
        "next_action_env_powershell_set_commands": [
            str(entry.get("powershell_set_command") or "") for entry in next_action_entries
        ],
        "post_env_bundle_launcher_commands": [
            "$env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'",
            "powershell -NoProfile -ExecutionPolicy Bypass -File "
            f"'{stable_artifact_ref(env_bundle_launcher_path) if env_bundle_launcher_path else 'env_bundle_ready_claims_launcher.ps1'}'",
        ] if ready_after_all_env_claim_ids else [],
        "post_env_bundle_balanced_agent_spawn_commands": [
            "$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'",
            "$env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'",
            "powershell -NoProfile -ExecutionPolicy Bypass -File "
            f"'{stable_artifact_ref(agent_spawn_launcher_path) if agent_spawn_launcher_path else 'agent_spawn_launcher.ps1'}' "
            "-Provider balanced -Phase env-bundle -Execute -Parallel",
        ] if ready_after_all_env_claim_ids else [],
        "env_bundle_validation_command": (
            "powershell -NoProfile -ExecutionPolicy Bypass -File "
            f"'{stable_artifact_ref(env_bundle_launcher_path) if env_bundle_launcher_path else 'env_bundle_ready_claims_launcher.ps1'}' "
            "-ValidateOnly"
        ) if ready_after_all_env_claim_ids else "",
        "ready_after_all_env_claim_ids": sorted(ready_after_all_env_claim_ids),
        "still_blocked_after_all_env_claim_ids": sorted(still_blocked_after_all_env_claim_ids),
        "entries": entries,
        "next_action_entries": next_action_entries,
    }


def render_env_unblock_queue(queue: dict) -> str:
    def cell(value: object) -> str:
        if isinstance(value, list):
            text = ", ".join(str(item) for item in value) or "-"
        elif value is None or value == "":
            text = "-"
        else:
            text = str(value)
        return text.replace("|", "\\|")

    lines = [
        "# Validation Env Unblock Queue",
        "",
        f"- Env vars: `{queue.get('env_count')}`",
        f"- Next-action env vars: `{queue.get('next_action_env_count') or 0}`",
        f"- Blocked claims: `{queue.get('blocked_claim_count')}`",
        f"- Current env present: `{queue.get('current_env_present_count') or 0}`",
        f"- Current env missing: `{queue.get('current_env_missing_count') or 0}`",
        f"- Current env placeholders: `{queue.get('current_env_placeholder_count') or 0}`",
        f"- Claims ready with current env: `{', '.join(str(value) for value in queue.get('ready_with_current_env_claim_ids') or []) or '-'}`",
        f"- Claims still blocked with current env: `{', '.join(str(value) for value in queue.get('still_blocked_with_current_env_claim_ids') or []) or '-'}`",
        f"- Claims ready after all envs: `{', '.join(str(value) for value in queue.get('ready_after_all_env_claim_ids') or []) or '-'}`",
        f"- Claims still blocked after all envs: `{', '.join(str(value) for value in queue.get('still_blocked_after_all_env_claim_ids') or []) or '-'}`",
        "",
        "| Env | Owners | Claims | Single-env ready | Single-env still blocked | Immediate | Dependency | Manual | Set command | Claim IDs |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for entry in queue.get("entries") or []:
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{cell(entry.get('env'))}`",
                    cell(entry.get("owners")),
                    cell(entry.get("claim_count")),
                    cell(entry.get("single_env_ready_claim_ids")),
                    cell(entry.get("single_env_still_blocked_claim_ids")),
                    cell(entry.get("immediate_claim_count")),
                    cell(entry.get("dependency_claim_count")),
                    cell(entry.get("manual_claim_count")),
                    f"`{cell(entry.get('powershell_set_command'))}`",
                    cell(entry.get("claim_ids")),
                ]
            )
            + " |"
        )
    lines.append("")
    if queue.get("entries"):
        lines.extend(["## Copy/Paste Complete Env Bundle", "", "```powershell"])
        for command in queue.get("all_env_powershell_set_commands") or []:
            if command:
                lines.append(str(command))
        lines.extend(["```", ""])
        validation_command = str(queue.get("env_bundle_validation_command") or "")
        if validation_command:
            lines.extend(
                [
                    "## Copy/Paste Env-Bundle Validation",
                    "",
                    "```powershell",
                    validation_command,
                    "```",
                    "",
                ]
            )
        launcher_commands = [str(command) for command in queue.get("post_env_bundle_launcher_commands") or [] if command]
        if launcher_commands:
            lines.extend(
                [
                    "## Copy/Paste Post-Env-Bundle Launcher",
                    "",
                    "```powershell",
                    *launcher_commands,
                    "```",
                    "",
                ]
            )
        balanced_spawn_commands = [
            str(command) for command in queue.get("post_env_bundle_balanced_agent_spawn_commands") or [] if command
        ]
        if balanced_spawn_commands:
            lines.extend(
                [
                    "## Copy/Paste Post-Env-Bundle Balanced Agent Spawn",
                    "",
                    "```powershell",
                    *balanced_spawn_commands,
                    "```",
                    "",
                ]
            )
        next_action_commands = [
            str(command) for command in queue.get("next_action_env_powershell_set_commands") or [] if command
        ]
        token_login_commands = []
        for entry in queue.get("next_action_entries") or []:
            for command in entry.get("token_login_commands") or []:
                command_text = str(command)
                if command_text and command_text not in token_login_commands:
                    token_login_commands.append(command_text)
        if next_action_commands:
            lines.extend(
                [
                    "## Copy/Paste Next-Action Env Commands",
                    "",
                    "```powershell",
                    *next_action_commands,
                    *token_login_commands,
                    "```",
                    "",
                    "## Next-Action Env Follow-Ups",
                    "",
                    "| Env | Owners | Claims | Packages | Waves | Token login commands | Actions |",
                    "| --- | --- | --- | --- | --- | --- | --- |",
                ]
            )
            for entry in queue.get("next_action_entries") or []:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            f"`{cell(entry.get('env'))}`",
                            cell(entry.get("owners")),
                            cell(entry.get("claim_ids")),
                            cell(entry.get("package_ids")),
                            cell(entry.get("waves")),
                            cell(entry.get("token_login_commands")),
                            cell(entry.get("actions")),
                        ]
                    )
                    + " |"
                )
            lines.append("")
        lines.extend(["## Copy/Paste Env Unblock Commands", ""])
        for entry in queue.get("entries") or []:
            prompt = str(entry.get("copy_paste_unblock_prompt") or "").strip()
            if not prompt:
                continue
            lines.extend(
                [
                    f"### {cell(entry.get('env'))}",
                    "",
                    "```text",
                    prompt,
                    "```",
                    "",
                ]
            )
    return "\n".join(lines)


def write_env_unblock_queue(
    agent_claims_json_path: Path,
    output_dir: Path,
    agent_spawn_launcher_path: Path | None = None,
) -> tuple[Path, Path]:
    claims_payload = load_json(agent_claims_json_path)
    queue = build_env_unblock_queue_json(
        claims_payload,
        output_dir / "env_bundle_ready_claims_launcher.ps1",
        agent_spawn_launcher_path=agent_spawn_launcher_path or output_dir / "agent_spawn_launcher.ps1",
    )
    markdown_path = output_dir / "env_unblock_queue.md"
    json_path = output_dir / "env_unblock_queue.json"
    markdown_path.write_text(render_env_unblock_queue(queue), encoding="utf-8")
    json_path.write_text(json.dumps(queue, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return markdown_path, json_path


def render_ready_claims_launcher(claims_payload: dict) -> str:
    ready_claims = [
        claim
        for claim in claims_payload.get("claims") or []
        if isinstance(claim, dict) and claim.get("claim_state") == "ready_to_claim"
    ]
    ready_claims.sort(
        key=lambda item: (
            int(item.get("wave") or 0),
            int(item.get("stage") or 999),
            str(item.get("claim_id") or ""),
        )
    )
    validate_claim_ids = [str(claim.get("claim_id") or "") for claim in ready_claims if str(claim.get("claim_id") or "")]
    lines = [
        "# Validation Ready Claims Launcher",
        "# Runs only claims currently marked ready_to_claim in agent_claims.json.",
        "param(",
        "  [switch]$ValidateOnly",
        ")",
        "$ErrorActionPreference = 'Stop'",
        "Set-StrictMode -Version Latest",
        f"$ReadyClaims = {ps_array(validate_claim_ids)}",
        "if ($ValidateOnly) {",
        "  Write-Host ('Ready claims validation passed. Ready claims: ' + (($ReadyClaims -join ', ') -replace '^$', '-'))",
        "  exit 0",
        "}",
        "$AllowReadyClaims = [Environment]::GetEnvironmentVariable('TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH')",
        "if ($AllowReadyClaims -ne '1') {",
        "  Write-Error 'Set TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH=1 only after reviewing agent_claims.json.'",
        "  exit 2",
        "}",
        "$ReadyClaimFailures = @()",
        "$ReadyClaimAgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_READY_CLAIMS_AGENT_ID')",
        "if (-not $ReadyClaimAgentId) { $ReadyClaimAgentId = [Environment]::UserName }",
        *ps_agent_id_guard_lines("ReadyClaimAgentId", "TAMANDUA_READY_CLAIMS_AGENT_ID"),
        "$ReadyClaimLauncherDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
        "$ClaimLockHelperPath = Join-Path $ReadyClaimLauncherDir 'claim_lock_helper.ps1'",
        "$DispatchManifestPath = Join-Path $ReadyClaimLauncherDir 'dispatch_manifest.json'",
        "if (-not (Test-Path $ClaimLockHelperPath)) {",
        "  Write-Error ('Missing claim lock helper: ' + $ClaimLockHelperPath)",
        "  exit 2",
        "}",
        "function Invoke-ClaimStatusRefresh {",
        "  if (Test-Path $script:DispatchManifestPath) {",
        "    python tools/detection_validation/run_preflight_work_package.py --refresh-claim-status-report $script:DispatchManifestPath",
        "    if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) {",
        "      Write-Warning ('Claim status refresh failed with exit ' + [string]$LASTEXITCODE)",
        "    }",
        "  }",
        "}",
        "function Invoke-ReadyClaim {",
        "  param([string]$ClaimId, [string]$PackageId, [string]$ScriptPath)",
        "  Write-Host ('[ready-claim] ' + $ClaimId + ' (' + $PackageId + ')')",
        "  $env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId",
        "  $env:TAMANDUA_AGENT_ID = $script:ReadyClaimAgentId",
        "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:ClaimLockHelperPath -ClaimId $ClaimId -AgentId $script:ReadyClaimAgentId",
        "  if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {",
        "    $script:ReadyClaimFailures += ($ClaimId + ' lock exit ' + [string]$LASTEXITCODE)",
        "    return",
        "  }",
        "  $env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
        "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath",
        "  if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {",
        "    $script:ReadyClaimFailures += ($ClaimId + ' exit ' + [string]$LASTEXITCODE)",
        "  }",
        "}",
        "",
    ]
    if not ready_claims:
        lines.extend(
            [
                "Write-Host '[ready-claim] no ready_to_claim packages found'",
                "Invoke-ClaimStatusRefresh",
                "exit 0",
                "",
            ]
        )
        return "\n".join(lines)
    for claim in ready_claims:
        claim_id = str(claim.get("claim_id") or "")
        package_id = str(claim.get("package_id") or "")
        script_path = str(claim.get("script_path") or "")
        lines.extend(
            [
                f"# Claim: {claim_id}",
                f"# Package: {package_id}",
                f"Invoke-ReadyClaim {ps_single_quoted(claim_id)} {ps_single_quoted(package_id)} {ps_single_quoted(script_path)}",
                "",
            ]
        )
    lines.extend(
        [
            "Invoke-ClaimStatusRefresh",
            "if ($ReadyClaimFailures.Count -gt 0) {",
            "  Write-Error ('Ready claims launcher completed with failures: ' + ($ReadyClaimFailures -join ', '))",
            "  exit 1",
            "}",
            "exit 0",
            "",
        ]
    )
    return "\n".join(lines)


def write_ready_claims_launcher(agent_claims_json_path: Path, output_dir: Path) -> Path:
    claims_payload = load_json(agent_claims_json_path)
    launcher_path = output_dir / "ready_claims_launcher.ps1"
    launcher_path.write_text(render_ready_claims_launcher(claims_payload), encoding="utf-8")
    return launcher_path


def ready_claim_parallel_batches(claims_payload: dict) -> list[tuple[int, int, list[dict]]]:
    ready_claims = [
        claim
        for claim in claims_payload.get("claims") or []
        if isinstance(claim, dict) and claim.get("claim_state") == "ready_to_claim"
    ]
    by_wave: dict[int, list[dict]] = {}
    for claim in ready_claims:
        by_wave.setdefault(int(claim.get("wave") or 0), []).append(claim)

    batches: list[tuple[int, int, list[dict]]] = []
    for wave in sorted(by_wave):
        wave_claims = sorted(
            by_wave[wave],
            key=lambda item: (
                int(item.get("stage") or 999),
                str(item.get("claim_id") or ""),
            ),
        )
        wave_batches: list[list[dict]] = []
        wave_batch_resources: list[set[str]] = []
        for claim in wave_claims:
            resources = {str(value) for value in claim.get("resource_tags") or [] if str(value)}
            placed = False
            for index, used_resources in enumerate(wave_batch_resources):
                if resources and used_resources & resources:
                    continue
                wave_batches[index].append(claim)
                used_resources.update(resources)
                placed = True
                break
            if not placed:
                wave_batches.append([claim])
                wave_batch_resources.append(set(resources))
        for index, batch in enumerate(wave_batches, start=1):
            batches.append((wave, index, batch))
    return batches


def render_ready_claims_parallel_launcher(claims_payload: dict) -> str:
    batches = ready_claim_parallel_batches(claims_payload)
    validate_claim_ids = [
        str(claim.get("claim_id") or "")
        for _wave, _batch_index, batch in batches
        for claim in batch
        if str(claim.get("claim_id") or "")
    ]
    lines = [
        "# Validation Ready Claims Parallel Launcher",
        "# Runs only claims currently marked ready_to_claim in agent_claims.json.",
        "# Claims are grouped by wave and resource tags to avoid overlapping resource claims in the same batch.",
        "param(",
        "  [switch]$ValidateOnly",
        ")",
        "$ErrorActionPreference = 'Stop'",
        "Set-StrictMode -Version Latest",
        f"$ReadyClaims = {ps_array(validate_claim_ids)}",
        "if ($ValidateOnly) {",
        "  Write-Host ('Ready claims validation passed. Ready claims: ' + (($ReadyClaims -join ', ') -replace '^$', '-'))",
        "  exit 0",
        "}",
        "$AllowReadyClaims = [Environment]::GetEnvironmentVariable('TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH')",
        "if ($AllowReadyClaims -ne '1') {",
        "  Write-Error 'Set TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH=1 only after reviewing agent_claims.json.'",
        "  exit 2",
        "}",
        "$ReadyClaimFailures = @()",
        "$ReadyClaimAgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_READY_CLAIMS_AGENT_ID')",
        "if (-not $ReadyClaimAgentId) { $ReadyClaimAgentId = [Environment]::UserName }",
        *ps_agent_id_guard_lines("ReadyClaimAgentId", "TAMANDUA_READY_CLAIMS_AGENT_ID"),
        "$ReadyClaimLauncherDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
        "$ClaimLockHelperPath = Join-Path $ReadyClaimLauncherDir 'claim_lock_helper.ps1'",
        "$DispatchManifestPath = Join-Path $ReadyClaimLauncherDir 'dispatch_manifest.json'",
        "if (-not (Test-Path $ClaimLockHelperPath)) {",
        "  Write-Error ('Missing claim lock helper: ' + $ClaimLockHelperPath)",
        "  exit 2",
        "}",
        "function Invoke-ClaimStatusRefresh {",
        "  if (Test-Path $script:DispatchManifestPath) {",
        "    python tools/detection_validation/run_preflight_work_package.py --refresh-claim-status-report $script:DispatchManifestPath",
        "    if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) {",
        "      Write-Warning ('Claim status refresh failed with exit ' + [string]$LASTEXITCODE)",
        "    }",
        "  }",
        "}",
        "function Start-ReadyClaimJob {",
        "  param([string]$ClaimId, [string]$PackageId, [string]$ScriptPath, [string]$TokenEnv, [string]$TokenLoginCommand)",
        "  Start-Job -Name $ClaimId -ArgumentList $ClaimId, $PackageId, $ScriptPath, $script:ClaimLockHelperPath, $script:ReadyClaimAgentId, $TokenEnv, $TokenLoginCommand -ScriptBlock {",
        "    param([string]$InnerClaimId, [string]$InnerPackageId, [string]$InnerScriptPath, [string]$InnerClaimLockHelperPath, [string]$InnerAgentId, [string]$InnerTokenEnv, [string]$InnerTokenLoginCommand)",
            "    Write-Host ('[ready-claim] ' + $InnerClaimId + ' (' + $InnerPackageId + ')')",
            "    $env:TAMANDUA_AGENT_CLAIM_ID = $InnerClaimId",
            "    $env:TAMANDUA_AGENT_ID = $InnerAgentId",
            "    if ($InnerTokenEnv) {",
            "      if (-not [Environment]::GetEnvironmentVariable($InnerTokenEnv)) {",
            "        [pscustomobject]@{ ClaimId = $InnerClaimId; PackageId = $InnerPackageId; ExitCode = 2; Phase = 'auth-env'; MissingEnv = $InnerTokenEnv }",
            "        return",
            "      }",
            "      if ($InnerTokenLoginCommand) {",
            "        Invoke-Expression $InnerTokenLoginCommand",
            "        if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) {",
            "          [pscustomobject]@{ ClaimId = $InnerClaimId; PackageId = $InnerPackageId; ExitCode = [int]$LASTEXITCODE; Phase = 'auth-login' }",
            "          return",
            "        }",
            "      }",
            "    }",
            "    powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerClaimLockHelperPath -ClaimId $InnerClaimId -AgentId $InnerAgentId",
        "    if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) {",
        "      [pscustomobject]@{ ClaimId = $InnerClaimId; PackageId = $InnerPackageId; ExitCode = [int]$LASTEXITCODE; Phase = 'lock' }",
        "      return",
        "    }",
        "    $env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
        "    powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerScriptPath",
        "    $InnerExitCode = if ($LASTEXITCODE -ne $null) { [int]$LASTEXITCODE } else { 0 }",
        "    [pscustomobject]@{ ClaimId = $InnerClaimId; PackageId = $InnerPackageId; ExitCode = $InnerExitCode; Phase = 'run' }",
        "  }",
        "}",
        "function Wait-ReadyClaimBatch {",
        "  param([object[]]$Jobs)",
        "  foreach ($Job in $Jobs) {",
        "    Wait-Job -Job $Job | Out-Null",
        "    $Results = @(Receive-Job -Job $Job)",
        "    foreach ($Result in $Results) {",
        "      if ($Result.PSObject.Properties.Name -contains 'ExitCode' -and [int]$Result.ExitCode -ne 0) {",
        "        $script:ReadyClaimFailures += ($Job.Name + ' exit ' + [string]$Result.ExitCode)",
        "      }",
        "    }",
        "    if ($Job.State -ne 'Completed') {",
        "      $script:ReadyClaimFailures += ($Job.Name + ' state ' + [string]$Job.State)",
        "    }",
        "    if ($Job.ChildJobs.Count -gt 0 -and $Job.ChildJobs[0].JobStateInfo.Reason) {",
        "      $script:ReadyClaimFailures += ($Job.Name + ' reason ' + [string]$Job.ChildJobs[0].JobStateInfo.Reason)",
        "    }",
        "    Remove-Job -Job $Job -Force",
        "  }",
        "}",
        "",
    ]
    if not batches:
        lines.extend(
            [
                "Write-Host '[ready-claim] no ready_to_claim packages found'",
                "Invoke-ClaimStatusRefresh",
                "exit 0",
                "",
            ]
        )
        return "\n".join(lines)
    for wave, batch_index, batch in batches:
        lines.extend(
            [
                f"# Wave: {wave}",
                f"# Batch: {batch_index}",
                "$ReadyClaimJobs = @()",
            ]
        )
        for claim in batch:
            claim_id = str(claim.get("claim_id") or "")
            package_id = str(claim.get("package_id") or "")
            script_path = str(claim.get("script_path") or "")
            resources = ", ".join(str(value) for value in claim.get("resource_tags") or []) or "-"
            next_action = render_current_next_action_summary(claim.get("current_next_action"))
            current_next_action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
            token_env = str(current_next_action.get("token_env") or "")
            token_login_command = str(current_next_action.get("token_login_command") or "")
            lines.extend(
                [
                    f"# Claim: {claim_id}",
                    f"# Package: {package_id}",
                    f"# Resources: {resources}",
                    f"# Next action: {next_action}",
                    f"$ReadyClaimJobs += Start-ReadyClaimJob {ps_single_quoted(claim_id)} {ps_single_quoted(package_id)} {ps_single_quoted(script_path)} {ps_single_quoted(token_env)} {ps_single_quoted(token_login_command)}",
                ]
            )
        lines.extend(["Wait-ReadyClaimBatch $ReadyClaimJobs", ""])
    lines.extend(
        [
            "Invoke-ClaimStatusRefresh",
            "if ($ReadyClaimFailures.Count -gt 0) {",
            "  Write-Error ('Ready claims parallel launcher completed with failures: ' + ($ReadyClaimFailures -join ', '))",
            "  exit 1",
            "}",
            "exit 0",
            "",
        ]
    )
    return "\n".join(lines)


def env_bundle_ready_claims_payload(claims_payload: dict) -> dict:
    claims: list[dict] = []
    for claim in claims_payload.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        missing_env = [str(value) for value in claim.get("missing_effective_env") or [] if str(value)]
        blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or [] if str(value)}
        if not missing_env or not blocked_reasons <= {"missing_effective_env"}:
            continue
        ready_claim = dict(claim)
        ready_claim["claim_state"] = "ready_to_claim"
        claims.append(ready_claim)
    payload = dict(claims_payload)
    payload["claims"] = claims
    return payload


def render_env_bundle_ready_claims_launcher(claims_payload: dict) -> str:
    batches = ready_claim_parallel_batches(env_bundle_ready_claims_payload(claims_payload))
    validate_claim_ids = [
        str(claim.get("claim_id") or "")
        for _wave, _batch_index, batch in batches
        for claim in batch
        if str(claim.get("claim_id") or "")
    ]
    all_env_names = {
        str(env_name)
        for claim in claims_payload.get("claims") or []
        if isinstance(claim, dict)
        for env_name in claim.get("missing_effective_env") or []
        if str(env_name)
    }
    still_blocked_after_all_env_claim_ids = []
    for claim in claims_payload.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        claim_id = str(claim.get("claim_id") or "")
        missing_env = {str(value) for value in claim.get("missing_effective_env") or [] if str(value)}
        blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or [] if str(value)}
        if (
            claim_id
            and missing_env
            and (missing_env - all_env_names or not blocked_reasons <= {"missing_effective_env"})
        ):
            still_blocked_after_all_env_claim_ids.append(claim_id)
    lines = [
        "# Validation Env-Bundle Ready Claims Launcher",
        "# Runs claims that become ready only after env_unblock_queue.json values are set.",
        "# Claims are grouped by wave and resource tags to avoid overlapping resource claims in the same batch.",
        "param(",
        "  [switch]$ValidateOnly",
        ")",
        "$ErrorActionPreference = 'Stop'",
        "Set-StrictMode -Version Latest",
        "$EnvBundleFailures = @()",
        "$EnvBundleClaimsAgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_ENV_BUNDLE_CLAIMS_AGENT_ID')",
        "if (-not $EnvBundleClaimsAgentId) { $EnvBundleClaimsAgentId = [Environment]::UserName }",
        *ps_agent_id_guard_lines("EnvBundleClaimsAgentId", "TAMANDUA_ENV_BUNDLE_CLAIMS_AGENT_ID"),
        "$EnvBundleLauncherDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
        "$ClaimLockHelperPath = Join-Path $EnvBundleLauncherDir 'claim_lock_helper.ps1'",
        "$DispatchManifestPath = Join-Path $EnvBundleLauncherDir 'dispatch_manifest.json'",
        "$EnvQueuePath = Join-Path $EnvBundleLauncherDir 'env_unblock_queue.json'",
        "if (-not (Test-Path $ClaimLockHelperPath)) {",
        "  Write-Error ('Missing claim lock helper: ' + $ClaimLockHelperPath)",
        "  exit 2",
        "}",
        "if (-not (Test-Path $EnvQueuePath)) {",
        "  Write-Error ('Missing env unblock queue JSON: ' + $EnvQueuePath)",
        "  exit 2",
        "}",
        "try {",
        "  $EnvQueue = Get-Content -Raw -Path $EnvQueuePath | ConvertFrom-Json",
        "} catch {",
        "  Write-Error ('Unable to parse env unblock queue JSON: ' + [string]$_.Exception.Message)",
        "  exit 2",
        "}",
        "$RequiredEnv = @()",
        "foreach ($Entry in @($EnvQueue.entries)) {",
        "  $EnvName = [string]$Entry.env",
        "  if (-not $EnvName) {",
        "    Write-Error 'Env unblock queue contains an entry without env.'",
        "    exit 2",
        "  }",
        "  $RequiredEnv += $EnvName",
        "}",
        "$DuplicateEnv = @($RequiredEnv | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })",
        "if ($DuplicateEnv.Count -gt 0) {",
        "  Write-Error ('Env unblock queue contains duplicate env entries: ' + (($DuplicateEnv | Sort-Object) -join ', '))",
        "  exit 2",
        "}",
        "$RequiredEnv = @($RequiredEnv | Sort-Object)",
        f"$EnvBundleReadyClaims = {ps_array(validate_claim_ids)}",
        "if (-not ($EnvQueue.PSObject.Properties.Name -contains 'ready_after_all_env_claim_ids')) {",
        "  Write-Error 'Env unblock queue missing ready_after_all_env_claim_ids.'",
        "  exit 2",
        "}",
        "if ($EnvQueue.ready_after_all_env_claim_ids -isnot [System.Array]) {",
        "  Write-Error 'Env unblock queue ready_after_all_env_claim_ids is not a list.'",
        "  exit 2",
        "}",
        "if (-not ($EnvQueue.PSObject.Properties.Name -contains 'still_blocked_after_all_env_claim_ids')) {",
        "  Write-Error 'Env unblock queue missing still_blocked_after_all_env_claim_ids.'",
        "  exit 2",
        "}",
        "if ($EnvQueue.still_blocked_after_all_env_claim_ids -isnot [System.Array]) {",
        "  Write-Error 'Env unblock queue still_blocked_after_all_env_claim_ids is not a list.'",
        "  exit 2",
        "}",
        "$QueueReadyClaimIds = @()",
        "foreach ($ClaimId in @($EnvQueue.ready_after_all_env_claim_ids)) {",
        "  $ClaimIdText = [string]$ClaimId",
        "  if (-not $ClaimIdText) {",
        "    Write-Error 'Env unblock queue ready_after_all_env_claim_ids contains empty value.'",
        "    exit 2",
        "  }",
        "  $QueueReadyClaimIds += $ClaimIdText",
        "}",
        "$QueueReadyClaimIds = @($QueueReadyClaimIds | Sort-Object)",
        "$ExpectedReadyClaimIds = @($EnvBundleReadyClaims | Sort-Object)",
        "if (($QueueReadyClaimIds -join '|') -ne ($ExpectedReadyClaimIds -join '|')) {",
        "  Write-Error ('Env unblock queue ready_after_all_env_claim_ids mismatch: queue=' + ($QueueReadyClaimIds -join ',') + ' launcher=' + ($ExpectedReadyClaimIds -join ','))",
        "  exit 2",
        "}",
        "$QueueStillBlockedClaimIds = @()",
        "foreach ($ClaimId in @($EnvQueue.still_blocked_after_all_env_claim_ids)) {",
        "  $ClaimIdText = [string]$ClaimId",
        "  if (-not $ClaimIdText) {",
        "    Write-Error 'Env unblock queue still_blocked_after_all_env_claim_ids contains empty value.'",
        "    exit 2",
        "  }",
        "  $QueueStillBlockedClaimIds += $ClaimIdText",
        "}",
        "$QueueStillBlockedClaimIds = @($QueueStillBlockedClaimIds | Sort-Object)",
        f"$ExpectedStillBlockedClaimIds = @({ps_array(sorted(still_blocked_after_all_env_claim_ids))} | Sort-Object)",
        "if (($QueueStillBlockedClaimIds -join '|') -ne ($ExpectedStillBlockedClaimIds -join '|')) {",
        "  Write-Error ('Env unblock queue still_blocked_after_all_env_claim_ids mismatch: queue=' + ($QueueStillBlockedClaimIds -join ',') + ' launcher=' + ($ExpectedStillBlockedClaimIds -join ','))",
        "  exit 2",
        "}",
        "if (-not ($EnvQueue.PSObject.Properties.Name -contains 'required_env_names')) {",
        "  Write-Error 'Env unblock queue missing required_env_names.'",
        "  exit 2",
        "}",
        "if ($EnvQueue.required_env_names -isnot [System.Array]) {",
        "  Write-Error 'Env unblock queue required_env_names is not a list.'",
        "  exit 2",
        "}",
        "$RequiredEnvNames = @()",
        "foreach ($RequiredEnvName in @($EnvQueue.required_env_names)) {",
        "  $RequiredEnvNameText = [string]$RequiredEnvName",
        "  if (-not $RequiredEnvNameText) {",
        "    Write-Error 'Env unblock queue required_env_names contains empty value.'",
        "    exit 2",
        "  }",
        "  $RequiredEnvNames += $RequiredEnvNameText",
        "}",
        "$RequiredEnvNames = @($RequiredEnvNames | Sort-Object)",
        "if (($RequiredEnvNames -join '|') -ne ($RequiredEnv -join '|')) {",
        "  Write-Error ('Env unblock queue required_env_names mismatch: required_env_names=' + ($RequiredEnvNames -join ',') + ' entries=' + ($RequiredEnv -join ','))",
        "  exit 2",
        "}",
        "if (-not ($EnvQueue.PSObject.Properties.Name -contains 'all_env_powershell_set_commands')) {",
        "  Write-Error 'Env unblock queue missing all_env_powershell_set_commands.'",
        "  exit 2",
        "}",
        "if ($EnvQueue.all_env_powershell_set_commands -isnot [System.Array]) {",
        "  Write-Error 'Env unblock queue all_env_powershell_set_commands is not a list.'",
        "  exit 2",
        "}",
        "$CommandEnvNames = @()",
        "foreach ($Command in @($EnvQueue.all_env_powershell_set_commands)) {",
        "  $CommandText = [string]$Command",
        "  if (-not $CommandText) {",
        "    Write-Error 'Env unblock queue all_env_powershell_set_commands contains empty value.'",
        "    exit 2",
        "  }",
        "  $CommandMatch = [regex]::Match($CommandText, '^\\$env:([A-Za-z_][A-Za-z0-9_]*)\\s*=')",
        "  if (-not $CommandMatch.Success) {",
        "    Write-Error ('Env unblock queue invalid env set command: ' + $CommandText)",
        "    exit 2",
        "  }",
        "  $CommandEnvNames += $CommandMatch.Groups[1].Value",
        "}",
        "$CommandEnvNames = @($CommandEnvNames | Sort-Object)",
        "if (($CommandEnvNames -join '|') -ne ($RequiredEnv -join '|')) {",
        "  Write-Error ('Env unblock queue env set commands mismatch: commands=' + ($CommandEnvNames -join ',') + ' entries=' + ($RequiredEnv -join ','))",
        "  exit 2",
        "}",
        "$PresentEnv = @($RequiredEnv | Where-Object { [Environment]::GetEnvironmentVariable($_) })",
        "$MissingEnv = @($RequiredEnv | Where-Object { -not [Environment]::GetEnvironmentVariable($_) })",
        "Write-Host ('Env bundle current env present: ' + [string]$PresentEnv.Count + '/' + [string]$RequiredEnv.Count)",
        "Write-Host ('Env bundle current env missing: ' + (($MissingEnv -join ', ') -replace '^$', '-'))",
        "if ($MissingEnv.Count -gt 0) {",
        "  $MissingSetCommands = @()",
        "  foreach ($Command in @($EnvQueue.all_env_powershell_set_commands)) {",
        "    $CommandText = [string]$Command",
        "    $CommandMatch = [regex]::Match($CommandText, '^\\$env:([A-Za-z_][A-Za-z0-9_]*)\\s*=')",
        "    if ($CommandMatch.Success -and $MissingEnv -contains $CommandMatch.Groups[1].Value) {",
        "      $MissingSetCommands += $CommandText",
        "    }",
        "  }",
        "  if ($MissingSetCommands.Count -gt 0) {",
        "    Write-Host 'Env bundle missing set commands:'",
        "    foreach ($CommandText in $MissingSetCommands) { Write-Host ('  ' + $CommandText) }",
        "  }",
        "  Write-Error ('Missing env bundle values: ' + ($MissingEnv -join ', '))",
        "  exit 2",
        "}",
        "$PlaceholderEnv = @()",
        "foreach ($Entry in @($EnvQueue.entries)) {",
        "  $EnvName = [string]$Entry.env",
        "  if (-not $EnvName) { continue }",
        "  $EnvValue = [Environment]::GetEnvironmentVariable($EnvName)",
        "  $Placeholder = [string]$Entry.placeholder",
        "  if ($EnvValue -and (($Placeholder -and $EnvValue -eq $Placeholder) -or $EnvValue -match '^<set-.+>$')) {",
        "    $PlaceholderEnv += $EnvName",
        "  }",
        "}",
        "if ($PlaceholderEnv.Count -gt 0) {",
        "  Write-Error ('Placeholder env bundle values must be replaced before launch: ' + (($PlaceholderEnv | Sort-Object -Unique) -join ', '))",
        "  exit 2",
        "}",
        "if ($ValidateOnly) {",
        "  Write-Host ('Env bundle validation passed. Ready claims after complete env bundle: ' + ($EnvBundleReadyClaims -join ', '))",
        "  exit 0",
        "}",
        "$AllowEnvBundleClaims = [Environment]::GetEnvironmentVariable('TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH')",
        "if ($AllowEnvBundleClaims -ne '1') {",
        "  Write-Error 'Set TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH=1 only after setting env_unblock_queue.md values.'",
        "  exit 2",
        "}",
        "function Invoke-ClaimStatusRefresh {",
        "  if (Test-Path $script:DispatchManifestPath) {",
        "    python tools/detection_validation/run_preflight_work_package.py --refresh-claim-status-report $script:DispatchManifestPath",
        "    if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) {",
        "      Write-Warning ('Claim status refresh failed with exit ' + [string]$LASTEXITCODE)",
        "    }",
        "  }",
        "}",
        "function Start-EnvBundleClaimJob {",
        "  param([string]$ClaimId, [string]$PackageId, [string]$ScriptPath, [string]$TokenEnv, [string]$TokenLoginCommand)",
        "  $ResolvedScriptPath = $ScriptPath",
        "  if (-not [System.IO.Path]::IsPathRooted($ResolvedScriptPath)) {",
        "    $RepoRelativePath = Join-Path (Get-Location) $ResolvedScriptPath",
        "    if (Test-Path $RepoRelativePath) {",
        "      $ResolvedScriptPath = $RepoRelativePath",
        "    } else {",
        "      $PackageRelativePath = Join-Path $script:EnvBundleLauncherDir (Split-Path -Leaf $ResolvedScriptPath)",
        "      $ResolvedScriptPath = $PackageRelativePath",
        "    }",
        "  }",
        "  if (-not (Test-Path $ResolvedScriptPath)) {",
        "    Write-Error ('Missing env-bundle claim script: ' + $ResolvedScriptPath)",
        "    exit 2",
        "  }",
        "  $ResolvedScriptPath = (Resolve-Path -LiteralPath $ResolvedScriptPath).Path",
        "  Start-Job -Name $ClaimId -ArgumentList $ClaimId, $PackageId, $ResolvedScriptPath, $script:ClaimLockHelperPath, $script:EnvBundleClaimsAgentId, $TokenEnv, $TokenLoginCommand -ScriptBlock {",
        "    param([string]$InnerClaimId, [string]$InnerPackageId, [string]$InnerScriptPath, [string]$InnerClaimLockHelperPath, [string]$InnerAgentId, [string]$InnerTokenEnv, [string]$InnerTokenLoginCommand)",
        "    Write-Host ('[env-bundle-claim] ' + $InnerClaimId + ' (' + $InnerPackageId + ')')",
        "    $env:TAMANDUA_AGENT_CLAIM_ID = $InnerClaimId",
        "    $env:TAMANDUA_AGENT_ID = $InnerAgentId",
        "    if ($InnerTokenEnv) {",
        "      if (-not [Environment]::GetEnvironmentVariable($InnerTokenEnv)) {",
        "        [pscustomobject]@{ ClaimId = $InnerClaimId; PackageId = $InnerPackageId; ExitCode = 2; Phase = 'auth-env'; MissingEnv = $InnerTokenEnv }",
        "        return",
        "      }",
        "      if ($InnerTokenLoginCommand) {",
        "        Invoke-Expression $InnerTokenLoginCommand",
        "        if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) {",
        "          [pscustomobject]@{ ClaimId = $InnerClaimId; PackageId = $InnerPackageId; ExitCode = [int]$LASTEXITCODE; Phase = 'auth-login' }",
        "          return",
        "        }",
        "      }",
        "    }",
        "    powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerClaimLockHelperPath -ClaimId $InnerClaimId -AgentId $InnerAgentId",
        "    if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) {",
        "      [pscustomobject]@{ ClaimId = $InnerClaimId; PackageId = $InnerPackageId; ExitCode = [int]$LASTEXITCODE; Phase = 'lock' }",
        "      return",
        "    }",
        "    $env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
        "    powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerScriptPath",
        "    $InnerExitCode = if ($LASTEXITCODE -ne $null) { [int]$LASTEXITCODE } else { 0 }",
        "    [pscustomobject]@{ ClaimId = $InnerClaimId; PackageId = $InnerPackageId; ExitCode = $InnerExitCode; Phase = 'run' }",
        "  }",
        "}",
        "function Wait-EnvBundleClaimBatch {",
        "  param([object[]]$Jobs)",
        "  foreach ($Job in $Jobs) {",
        "    Wait-Job -Job $Job | Out-Null",
        "    $Results = @(Receive-Job -Job $Job)",
        "    foreach ($Result in $Results) {",
        "      if ($Result.PSObject.Properties.Name -contains 'ExitCode' -and [int]$Result.ExitCode -ne 0) {",
        "        $script:EnvBundleFailures += ($Job.Name + ' exit ' + [string]$Result.ExitCode)",
        "      }",
        "    }",
        "    if ($Job.State -ne 'Completed') {",
        "      $script:EnvBundleFailures += ($Job.Name + ' state ' + [string]$Job.State)",
        "    }",
        "    if ($Job.ChildJobs.Count -gt 0 -and $Job.ChildJobs[0].JobStateInfo.Reason) {",
        "      $script:EnvBundleFailures += ($Job.Name + ' reason ' + [string]$Job.ChildJobs[0].JobStateInfo.Reason)",
        "    }",
        "    Remove-Job -Job $Job -Force",
        "  }",
        "}",
        "",
    ]
    if not batches:
        lines.extend(
            [
                "Write-Host '[env-bundle-claim] no env-bundle-ready packages found'",
                "Invoke-ClaimStatusRefresh",
                "exit 0",
                "",
            ]
        )
        return "\n".join(lines)
    for wave, batch_index, batch in batches:
        lines.extend([f"# Wave: {wave}", f"# Batch: {batch_index}", "$EnvBundleClaimJobs = @()"])
        for claim in batch:
            claim_id = str(claim.get("claim_id") or "")
            package_id = str(claim.get("package_id") or "")
            script_path = str(claim.get("script_path") or "")
            resources = ", ".join(str(value) for value in claim.get("resource_tags") or []) or "-"
            next_action = render_current_next_action_summary(claim.get("current_next_action"))
            current_next_action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
            token_env = str(current_next_action.get("token_env") or "")
            token_login_command = str(current_next_action.get("token_login_command") or "")
            lines.extend(
                [
                    f"# Claim: {claim_id}",
                    f"# Package: {package_id}",
                    f"# Resources: {resources}",
                    f"# Next action: {next_action}",
                    f"$EnvBundleClaimJobs += Start-EnvBundleClaimJob {ps_single_quoted(claim_id)} {ps_single_quoted(package_id)} {ps_single_quoted(script_path)} {ps_single_quoted(token_env)} {ps_single_quoted(token_login_command)}",
                ]
            )
        lines.extend(["Wait-EnvBundleClaimBatch $EnvBundleClaimJobs", ""])
    lines.extend(
        [
            "Invoke-ClaimStatusRefresh",
            "if ($EnvBundleFailures.Count -gt 0) {",
            "  Write-Error ('Env-bundle claims launcher completed with failures: ' + ($EnvBundleFailures -join ', '))",
            "  exit 1",
            "}",
            "exit 0",
            "",
        ]
    )
    return "\n".join(lines)


def write_ready_claims_parallel_launcher(agent_claims_json_path: Path, output_dir: Path) -> Path:
    claims_payload = load_json(agent_claims_json_path)
    launcher_path = output_dir / "ready_claims_parallel_launcher.ps1"
    launcher_path.write_text(render_ready_claims_parallel_launcher(claims_payload), encoding="utf-8")
    return launcher_path


def write_env_bundle_ready_claims_launcher(agent_claims_json_path: Path, output_dir: Path) -> Path:
    claims_payload = load_json(agent_claims_json_path)
    launcher_path = output_dir / "env_bundle_ready_claims_launcher.ps1"
    launcher_path.write_text(render_env_bundle_ready_claims_launcher(claims_payload), encoding="utf-8")
    return launcher_path


def render_dispatch_prelaunch_validation(
    agent_spawn_launcher_path: Path | None = None,
    ready_claims_launcher_path: Path | None = None,
    ready_claims_parallel_launcher_path: Path | None = None,
    env_bundle_ready_claims_launcher_path: Path | None = None,
    claim_lock_helper_path: Path | None = None,
    env_unblock_queue_json_path: Path | None = None,
    agent_spawn_plan_json_path: Path | None = None,
    agent_claims_json_path: Path | None = None,
    claim_status_report_json_path: Path | None = None,
    dispatch_manifest_path: Path | None = None,
    owner_launch_plan_json_path: Path | None = None,
    execution_matrix_json_path: Path | None = None,
) -> str:
    lines = [
        "# Validation Dispatch Prelaunch Validation",
        "# Runs no-execution checks before any package launcher opt-in is set.",
        "param(",
        "  [switch]$ValidateEnvBundle",
        ")",
        "$ErrorActionPreference = 'Stop'",
        "Set-StrictMode -Version Latest",
        "$PrelaunchFailures = @()",
        "function Invoke-PrelaunchStep {",
        "  param([string]$Label, [string[]]$Command)",
        "  Write-Host ('[prelaunch] ' + $Label)",
        "  & $Command[0] @($Command[1..($Command.Count - 1)])",
        "  $ExitCode = if ($LASTEXITCODE -ne $null) { [int]$LASTEXITCODE } else { 0 }",
        "  if ($ExitCode -ne 0) {",
        "    $script:PrelaunchFailures += ($Label + ' exit ' + [string]$ExitCode)",
        "  }",
        "}",
        "function Invoke-ClaimLockEmptyValidation {",
        "  param([string]$ClaimLockHelperPath)",
        "  Write-Host '[prelaunch] claim lock empty check'",
        "  if (-not (Test-Path -LiteralPath $ClaimLockHelperPath)) {",
        "    $script:PrelaunchFailures += ('claim lock helper missing for empty check: ' + $ClaimLockHelperPath)",
        "    return",
        "  }",
        "  $ClaimLockDir = Join-Path (Split-Path -Parent $ClaimLockHelperPath) 'claim_locks'",
        "  if (-not (Test-Path -LiteralPath $ClaimLockDir)) {",
        "    Write-Host '[prelaunch] claim lock empty check passed: no claim_locks dir'",
        "    return",
        "  }",
        "  $ExistingLocks = @(Get-ChildItem -LiteralPath $ClaimLockDir -Filter '*.claim-lock.json' -ErrorAction SilentlyContinue)",
        "  if ($ExistingLocks.Count -gt 0) {",
        "    $LockNames = @($ExistingLocks | ForEach-Object { $_.Name } | Sort-Object)",
        "    $script:PrelaunchFailures += ('claim lock prelaunch found existing locks: ' + ($LockNames -join ', '))",
        "    return",
        "  }",
        "  Write-Host '[prelaunch] claim lock empty check passed'",
        "}",
        "function Invoke-OwnerLaunchPlanShapeValidation {",
        "  param([string]$Path)",
        "  Write-Host '[prelaunch] owner launch plan shape'",
        "  if (-not (Test-Path -LiteralPath $Path)) {",
        "    $script:PrelaunchFailures += ('owner launch plan shape missing ' + $Path)",
        "    return",
        "  }",
        "  try { $Plan = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('owner launch plan shape invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  if (-not ($Plan.PSObject.Properties.Name -contains 'artifact')) {",
        "    $script:PrelaunchFailures += 'owner launch plan shape missing artifact'",
        "    return",
        "  }",
        "  if ([string]$Plan.artifact -ne 'validation-owner-launch-plan') {",
        "    $script:PrelaunchFailures += ('owner launch plan shape invalid artifact: ' + [string]$Plan.artifact)",
        "    return",
        "  }",
        "  if (-not ($Plan.PSObject.Properties.Name -contains 'owners')) {",
        "    $script:PrelaunchFailures += 'owner launch plan shape missing owners'",
        "    return",
        "  }",
        "  if ($Plan.owners -isnot [System.Array]) {",
        "    $script:PrelaunchFailures += 'owner launch plan shape owners is not a list'",
        "    return",
        "  }",
        "  foreach ($CountField in @('owner_count','package_count','launchable_package_count','blocked_package_count')) {",
        "    if (-not ($Plan.PSObject.Properties.Name -contains $CountField)) {",
        "      $script:PrelaunchFailures += ('owner launch plan shape missing ' + $CountField)",
        "      return",
        "    }",
        "    $CountRaw = [string]$Plan.PSObject.Properties[$CountField].Value",
        "    $Count = 0",
        "    if (-not [int]::TryParse($CountRaw, [ref]$Count) -or $Count -lt 0) {",
        "      $script:PrelaunchFailures += ('owner launch plan shape invalid ' + $CountField + ': ' + $CountRaw)",
        "      return",
        "    }",
        "  }",
        "  $PackageIds = @()",
        "  $LaunchableCount = 0",
        "  $BlockedCount = 0",
        "  foreach ($Owner in @($Plan.owners)) {",
        "    if (-not ($Owner.PSObject.Properties.Name -contains 'owner') -or -not [string]$Owner.owner) {",
        "      $script:PrelaunchFailures += 'owner launch plan shape owner without owner'",
        "      return",
        "    }",
        "    if (-not ($Owner.PSObject.Properties.Name -contains 'packages')) {",
        "      $script:PrelaunchFailures += ('owner launch plan shape owner missing packages: ' + [string]$Owner.owner)",
        "      return",
        "    }",
        "    if ($Owner.packages -isnot [System.Array]) {",
        "      $script:PrelaunchFailures += ('owner launch plan shape owner packages is not a list: ' + [string]$Owner.owner)",
        "      return",
        "    }",
        "    foreach ($Package in @($Owner.packages)) {",
        "      if (-not ($Package.PSObject.Properties.Name -contains 'package_id') -or -not [string]$Package.package_id) {",
        "        $script:PrelaunchFailures += 'owner launch plan shape package without package_id'",
        "        return",
        "      }",
        "      $PackageIds += [string]$Package.package_id",
        "      if ($Package.PSObject.Properties.Name -contains 'ready_to_launch' -and [bool]$Package.ready_to_launch) {",
        "        $LaunchableCount += 1",
        "      } else {",
        "        $BlockedCount += 1",
        "      }",
        "    }",
        "  }",
        "  $DuplicatePackageIds = @($PackageIds | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name } | Sort-Object)",
        "  if ($DuplicatePackageIds.Count -gt 0) {",
        "    $script:PrelaunchFailures += ('owner launch plan shape duplicate package_id: ' + ($DuplicatePackageIds -join ','))",
        "    return",
        "  }",
        "  if ([int]$Plan.owner_count -ne @($Plan.owners).Count) {",
        "    $script:PrelaunchFailures += ('owner launch plan shape owner_count mismatch: count=' + [string]$Plan.owner_count + ' owners=' + [string]@($Plan.owners).Count)",
        "    return",
        "  }",
        "  if ([int]$Plan.package_count -ne $PackageIds.Count) {",
        "    $script:PrelaunchFailures += ('owner launch plan shape package_count mismatch: count=' + [string]$Plan.package_count + ' packages=' + [string]$PackageIds.Count)",
        "    return",
        "  }",
        "  if ([int]$Plan.launchable_package_count -ne $LaunchableCount) {",
        "    $script:PrelaunchFailures += ('owner launch plan shape launchable_package_count mismatch: count=' + [string]$Plan.launchable_package_count + ' packages=' + [string]$LaunchableCount)",
        "    return",
        "  }",
        "  if ([int]$Plan.blocked_package_count -ne $BlockedCount) {",
        "    $script:PrelaunchFailures += ('owner launch plan shape blocked_package_count mismatch: count=' + [string]$Plan.blocked_package_count + ' packages=' + [string]$BlockedCount)",
        "    return",
        "  }",
        "  Write-Host ('[prelaunch] owner launch plan shape valid: packages=' + [string]$PackageIds.Count)",
        "}",
        "function Invoke-ExecutionMatrixShapeValidation {",
        "  param([string]$Path)",
        "  Write-Host '[prelaunch] execution matrix shape'",
        "  if (-not (Test-Path -LiteralPath $Path)) {",
        "    $script:PrelaunchFailures += ('execution matrix shape missing ' + $Path)",
        "    return",
        "  }",
        "  try { $Matrix = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('execution matrix shape invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  if (-not ($Matrix.PSObject.Properties.Name -contains 'artifact')) {",
        "    $script:PrelaunchFailures += 'execution matrix shape missing artifact'",
        "    return",
        "  }",
        "  if ([string]$Matrix.artifact -ne 'validation-execution-matrix') {",
        "    $script:PrelaunchFailures += ('execution matrix shape invalid artifact: ' + [string]$Matrix.artifact)",
        "    return",
        "  }",
        "  if ($Matrix.PSObject.Properties.Name -contains 'source_artifact' -and [string]$Matrix.source_artifact -ne 'validation-owner-launch-plan') {",
        "    $script:PrelaunchFailures += ('execution matrix shape invalid source_artifact: ' + [string]$Matrix.source_artifact)",
        "    return",
        "  }",
        "  if (-not ($Matrix.PSObject.Properties.Name -contains 'rows')) {",
        "    $script:PrelaunchFailures += 'execution matrix shape missing rows'",
        "    return",
        "  }",
        "  if ($Matrix.rows -isnot [System.Array]) {",
        "    $script:PrelaunchFailures += 'execution matrix shape rows is not a list'",
        "    return",
        "  }",
        "  foreach ($CountField in @('package_count','ready_to_launch_count','blocked_count')) {",
        "    if (-not ($Matrix.PSObject.Properties.Name -contains $CountField)) {",
        "      $script:PrelaunchFailures += ('execution matrix shape missing ' + $CountField)",
        "      return",
        "    }",
        "    $CountRaw = [string]$Matrix.PSObject.Properties[$CountField].Value",
        "    $Count = 0",
        "    if (-not [int]::TryParse($CountRaw, [ref]$Count) -or $Count -lt 0) {",
        "      $script:PrelaunchFailures += ('execution matrix shape invalid ' + $CountField + ': ' + $CountRaw)",
        "      return",
        "    }",
        "  }",
        "  $PackageIds = @()",
        "  $ReadyCount = 0",
        "  $BlockedCount = 0",
        "  foreach ($Row in @($Matrix.rows)) {",
        "    if (-not ($Row.PSObject.Properties.Name -contains 'package_id') -or -not [string]$Row.package_id) {",
        "      $script:PrelaunchFailures += 'execution matrix shape row without package_id'",
        "      return",
        "    }",
        "    $PackageIds += [string]$Row.package_id",
        "    if ($Row.PSObject.Properties.Name -contains 'ready_to_launch' -and [bool]$Row.ready_to_launch) {",
        "      $ReadyCount += 1",
        "    } else {",
        "      $BlockedCount += 1",
        "    }",
        "  }",
        "  $DuplicatePackageIds = @($PackageIds | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name } | Sort-Object)",
        "  if ($DuplicatePackageIds.Count -gt 0) {",
        "    $script:PrelaunchFailures += ('execution matrix shape duplicate package_id: ' + ($DuplicatePackageIds -join ','))",
        "    return",
        "  }",
        "  if ([int]$Matrix.package_count -ne $PackageIds.Count) {",
        "    $script:PrelaunchFailures += ('execution matrix shape package_count mismatch: count=' + [string]$Matrix.package_count + ' rows=' + [string]$PackageIds.Count)",
        "    return",
        "  }",
        "  if ([int]$Matrix.ready_to_launch_count -ne $ReadyCount) {",
        "    $script:PrelaunchFailures += ('execution matrix shape ready_to_launch_count mismatch: count=' + [string]$Matrix.ready_to_launch_count + ' rows=' + [string]$ReadyCount)",
        "    return",
        "  }",
        "  if ([int]$Matrix.blocked_count -ne $BlockedCount) {",
        "    $script:PrelaunchFailures += ('execution matrix shape blocked_count mismatch: count=' + [string]$Matrix.blocked_count + ' rows=' + [string]$BlockedCount)",
        "    return",
        "  }",
        "  Write-Host ('[prelaunch] execution matrix shape valid: rows=' + [string]$PackageIds.Count)",
        "}",
        "function Invoke-OwnerPlanExecutionMatrixAlignmentValidation {",
        "  param([string]$OwnerPlanPath, [string]$ExecutionMatrixPath)",
        "  Write-Host '[prelaunch] owner plan execution matrix alignment'",
        "  if (-not (Test-Path -LiteralPath $OwnerPlanPath)) {",
        "    $script:PrelaunchFailures += ('owner plan execution matrix alignment missing owner plan: ' + $OwnerPlanPath)",
        "    return",
        "  }",
        "  if (-not (Test-Path -LiteralPath $ExecutionMatrixPath)) {",
        "    $script:PrelaunchFailures += ('owner plan execution matrix alignment missing execution matrix: ' + $ExecutionMatrixPath)",
        "    return",
        "  }",
        "  try { $OwnerPlan = Get-Content -Raw -LiteralPath $OwnerPlanPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('owner plan execution matrix alignment owner plan invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  try { $Matrix = Get-Content -Raw -LiteralPath $ExecutionMatrixPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('owner plan execution matrix alignment execution matrix invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  $OwnerPackages = @{}",
        "  foreach ($Owner in @($OwnerPlan.owners)) {",
        "    foreach ($Package in @($Owner.packages)) {",
        "      $PackageId = [string]$Package.package_id",
        "      if ($PackageId) { $OwnerPackages[$PackageId] = [bool]$Package.ready_to_launch }",
        "    }",
        "  }",
        "  $MatrixPackages = @{}",
        "  foreach ($Row in @($Matrix.rows)) {",
        "    $PackageId = [string]$Row.package_id",
        "    if ($PackageId) { $MatrixPackages[$PackageId] = [bool]$Row.ready_to_launch }",
        "  }",
        "  $OwnerPackageIds = @($OwnerPackages.Keys | Sort-Object)",
        "  $MatrixPackageIds = @($MatrixPackages.Keys | Sort-Object)",
        "  if (($OwnerPackageIds -join '|') -ne ($MatrixPackageIds -join '|')) {",
        "    $script:PrelaunchFailures += ('owner plan execution matrix alignment package_ids mismatch: owner=' + ($OwnerPackageIds -join ',') + ' matrix=' + ($MatrixPackageIds -join ','))",
        "    return",
        "  }",
        "  foreach ($PackageId in $OwnerPackageIds) {",
        "    if ([bool]$OwnerPackages[$PackageId] -ne [bool]$MatrixPackages[$PackageId]) {",
        "      $script:PrelaunchFailures += ('owner plan execution matrix alignment ready_to_launch mismatch: ' + $PackageId)",
        "      return",
        "    }",
        "  }",
        "  Write-Host ('[prelaunch] owner plan execution matrix alignment valid: packages=' + [string]$OwnerPackageIds.Count)",
        "}",
        "function Invoke-DispatchManifestPlanAlignmentValidation {",
        "  param([string]$ManifestPath, [string]$OwnerPlanPath, [string]$ExecutionMatrixPath)",
        "  Write-Host '[prelaunch] dispatch manifest plan alignment'",
        "  foreach ($Path in @($ManifestPath,$OwnerPlanPath,$ExecutionMatrixPath)) {",
        "    if (-not (Test-Path -LiteralPath $Path)) {",
        "      $script:PrelaunchFailures += ('dispatch manifest plan alignment missing path: ' + $Path)",
        "      return",
        "    }",
        "  }",
        "  try { $Manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('dispatch manifest plan alignment manifest invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  try { $OwnerPlan = Get-Content -Raw -LiteralPath $OwnerPlanPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('dispatch manifest plan alignment owner plan invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  try { $Matrix = Get-Content -Raw -LiteralPath $ExecutionMatrixPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('dispatch manifest plan alignment execution matrix invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  $ManifestPackageIds = @($Manifest.packages | ForEach-Object { [string]$_.package_id } | Where-Object { $_ } | Sort-Object)",
        "  $OwnerPackageIds = @()",
        "  foreach ($Owner in @($OwnerPlan.owners)) {",
        "    foreach ($Package in @($Owner.packages)) {",
        "      $PackageId = [string]$Package.package_id",
        "      if ($PackageId) { $OwnerPackageIds += $PackageId }",
        "    }",
        "  }",
        "  $OwnerPackageIds = @($OwnerPackageIds | Sort-Object)",
        "  $MatrixPackageIds = @($Matrix.rows | ForEach-Object { [string]$_.package_id } | Where-Object { $_ } | Sort-Object)",
        "  if (($ManifestPackageIds -join '|') -ne ($OwnerPackageIds -join '|')) {",
        "    $script:PrelaunchFailures += ('dispatch manifest plan alignment owner package_ids mismatch: manifest=' + ($ManifestPackageIds -join ',') + ' owner=' + ($OwnerPackageIds -join ','))",
        "    return",
        "  }",
        "  if (($ManifestPackageIds -join '|') -ne ($MatrixPackageIds -join '|')) {",
        "    $script:PrelaunchFailures += ('dispatch manifest plan alignment matrix package_ids mismatch: manifest=' + ($ManifestPackageIds -join ',') + ' matrix=' + ($MatrixPackageIds -join ','))",
        "    return",
        "  }",
        "  Write-Host ('[prelaunch] dispatch manifest plan alignment valid: packages=' + [string]$ManifestPackageIds.Count)",
        "}",
        "function Invoke-DispatchManifestAgentClaimsAlignmentValidation {",
        "  param([string]$ManifestPath, [string]$AgentClaimsPath)",
        "  Write-Host '[prelaunch] dispatch manifest agent claims alignment'",
        "  foreach ($Path in @($ManifestPath,$AgentClaimsPath)) {",
        "    if (-not (Test-Path -LiteralPath $Path)) {",
        "      $script:PrelaunchFailures += ('dispatch manifest agent claims alignment missing path: ' + $Path)",
        "      return",
        "    }",
        "  }",
        "  try { $Manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('dispatch manifest agent claims alignment manifest invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  try { $ClaimsPayload = Get-Content -Raw -LiteralPath $AgentClaimsPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('dispatch manifest agent claims alignment claims invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  $ManifestPackageIds = @($Manifest.packages | ForEach-Object { [string]$_.package_id } | Where-Object { $_ } | Sort-Object)",
        "  $ClaimPackageIds = @($ClaimsPayload.claims | ForEach-Object { [string]$_.package_id } | Where-Object { $_ } | Sort-Object)",
        "  if (($ManifestPackageIds -join '|') -ne ($ClaimPackageIds -join '|')) {",
        "    $script:PrelaunchFailures += ('dispatch manifest agent claims alignment package_ids mismatch: manifest=' + ($ManifestPackageIds -join ',') + ' claims=' + ($ClaimPackageIds -join ','))",
        "    return",
        "  }",
        "  foreach ($Claim in @($ClaimsPayload.claims)) {",
        "    $PackageId = [string]$Claim.package_id",
        "    $ClaimId = [string]$Claim.claim_id",
        "    $ExpectedClaimId = 'claim-' + $PackageId",
        "    if ($PackageId -and $ClaimId -ne $ExpectedClaimId) {",
        "      $script:PrelaunchFailures += ('dispatch manifest agent claims alignment claim_id mismatch: ' + $PackageId + '=' + $ClaimId)",
        "      return",
        "    }",
        "  }",
        "  Write-Host ('[prelaunch] dispatch manifest agent claims alignment valid: packages=' + [string]$ManifestPackageIds.Count)",
        "}",
        "function Invoke-ClaimLockHelperAgentClaimsAlignmentValidation {",
        "  param([string]$ClaimLockHelperPath, [string]$AgentClaimsPath)",
        "  Write-Host '[prelaunch] claim lock helper agent claims alignment'",
        "  foreach ($Path in @($ClaimLockHelperPath,$AgentClaimsPath)) {",
        "    if (-not (Test-Path -LiteralPath $Path)) {",
        "      $script:PrelaunchFailures += ('claim lock helper agent claims alignment missing path: ' + $Path)",
        "      return",
        "    }",
        "  }",
        "  try { $HelperText = Get-Content -Raw -LiteralPath $ClaimLockHelperPath } catch {",
        "    $script:PrelaunchFailures += ('claim lock helper agent claims alignment helper unreadable: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  try { $ClaimsPayload = Get-Content -Raw -LiteralPath $AgentClaimsPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('claim lock helper agent claims alignment claims invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  foreach ($RequiredText in @('# Validation Claim Lock Helper','CreateNew','Unknown validation claim','Claim already locked','AgentId may only contain letters','Refusing to reset claim lock without -Force','Refusing to reset all claim locks without -Force')) {",
        "    if (-not $HelperText.Contains($RequiredText)) {",
        "      $script:PrelaunchFailures += ('claim lock helper agent claims alignment missing helper marker: ' + $RequiredText)",
        "      return",
        "    }",
        "  }",
        "  $KnownClaimsMatch = [regex]::Match($HelperText, '(?s)\\$KnownClaims\\s*=\\s*@\\((.*?)\\)')",
        "  if (-not $KnownClaimsMatch.Success) {",
        "    $script:PrelaunchFailures += 'claim lock helper agent claims alignment missing KnownClaims list'",
        "    return",
        "  }",
        "  $KnownClaims = @()",
        "  foreach ($Match in [regex]::Matches($KnownClaimsMatch.Groups[1].Value, \"'([^']+)'\") ) {",
        "    $KnownClaims += [string]$Match.Groups[1].Value",
        "  }",
        "  $KnownClaims = @($KnownClaims | Where-Object { $_ } | Sort-Object)",
        "  $ClaimIds = @($ClaimsPayload.claims | ForEach-Object { [string]$_.claim_id } | Where-Object { $_ } | Sort-Object)",
        "  if (($KnownClaims -join '|') -ne ($ClaimIds -join '|')) {",
        "    $script:PrelaunchFailures += ('claim lock helper agent claims alignment claim_ids mismatch: helper=' + ($KnownClaims -join ',') + ' claims=' + ($ClaimIds -join ','))",
        "    return",
        "  }",
        "  foreach ($ClaimId in $ClaimIds) {",
        "    $ExpectedLockSuffix = $ClaimId + '.claim-lock.json'",
        "    if (-not $HelperText.Contains($ExpectedLockSuffix) -and -not $HelperText.Contains('$KnownClaimId + ''.claim-lock.json''')) {",
        "      $script:PrelaunchFailures += ('claim lock helper agent claims alignment missing lock suffix handling: ' + $ExpectedLockSuffix)",
        "      return",
        "    }",
        "  }",
        "  Write-Host ('[prelaunch] claim lock helper agent claims alignment valid: claims=' + [string]$ClaimIds.Count)",
        "}",
        "function Invoke-AgentClaimsStatusReportAlignmentValidation {",
        "  param([string]$AgentClaimsPath, [string]$ClaimStatusReportPath)",
        "  Write-Host '[prelaunch] agent claims status report alignment'",
        "  foreach ($Path in @($AgentClaimsPath,$ClaimStatusReportPath)) {",
        "    if (-not (Test-Path -LiteralPath $Path)) {",
        "      $script:PrelaunchFailures += ('agent claims status report alignment missing path: ' + $Path)",
        "      return",
        "    }",
        "  }",
        "  try { $ClaimsPayload = Get-Content -Raw -LiteralPath $AgentClaimsPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('agent claims status report alignment claims invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  try { $Report = Get-Content -Raw -LiteralPath $ClaimStatusReportPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('agent claims status report alignment report invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  $ClaimIds = @($ClaimsPayload.claims | ForEach-Object { [string]$_.claim_id } | Where-Object { $_ } | Sort-Object)",
        "  $ReportClaimIds = @($Report.claims | ForEach-Object { [string]$_.claim_id } | Where-Object { $_ } | Sort-Object)",
        "  if (($ClaimIds -join '|') -ne ($ReportClaimIds -join '|')) {",
        "    $script:PrelaunchFailures += ('agent claims status report alignment claim_ids mismatch: claims=' + ($ClaimIds -join ',') + ' report=' + ($ReportClaimIds -join ','))",
        "    return",
        "  }",
        "  # Static audit markers for dynamic agent-claims/report field checks:",
        "  # agent claims status report alignment package_id mismatch:",
        "  # agent claims status report alignment claim_state mismatch:",
        "  # agent claims status report alignment owner mismatch:",
        "  # agent claims status report alignment wave mismatch:",
        "  # agent claims status report alignment stage mismatch:",
        "  # agent claims status report alignment ready_to_launch mismatch:",
        "  # agent claims status report alignment script_path mismatch:",
        "  # agent claims status report alignment prompt_path mismatch:",
        "  # agent claims status report alignment status_path mismatch:",
        "  # agent claims status report alignment command mismatch:",
        "  # agent claims status report alignment missing_effective_env mismatch:",
        "  # agent claims status report alignment blocked_reasons mismatch:",
        "  # agent claims status report alignment resource_tags mismatch:",
        "  # agent claims status report alignment invalid lock_state:",
        "  # agent claims status report alignment lock_path mismatch:",
        "  $ReportByClaimId = @{}",
        "  foreach ($ReportClaim in @($Report.claims)) {",
        "    $ReportClaimId = [string]$ReportClaim.claim_id",
        "    if ($ReportClaimId) { $ReportByClaimId[$ReportClaimId] = $ReportClaim }",
        "  }",
        "  foreach ($Claim in @($ClaimsPayload.claims)) {",
        "    $ClaimId = [string]$Claim.claim_id",
        "    $ReportClaim = $ReportByClaimId[$ClaimId]",
        "    foreach ($FieldName in @('package_id','claim_state','owner','wave','stage','ready_to_launch','script_path','prompt_path','status_path','command')) {",
        "      $ClaimValue = ''",
        "      $ReportValue = ''",
        "      if ($Claim.PSObject.Properties.Name -contains $FieldName) { $ClaimValue = [string]$Claim.PSObject.Properties[$FieldName].Value }",
        "      if ($ReportClaim.PSObject.Properties.Name -contains $FieldName) { $ReportValue = [string]$ReportClaim.PSObject.Properties[$FieldName].Value }",
        "      if ($ClaimValue -ne $ReportValue) {",
        "        $script:PrelaunchFailures += ('agent claims status report alignment ' + $FieldName + ' mismatch: ' + $ClaimId + ' claims=' + $ClaimValue + ' report=' + $ReportValue)",
        "        return",
        "      }",
        "    }",
        "    foreach ($ListFieldName in @('missing_effective_env','blocked_reasons','resource_tags')) {",
        "      $ClaimValues = @()",
        "      $ReportValues = @()",
        "      if ($Claim.PSObject.Properties.Name -contains $ListFieldName) { $ClaimValues = @($Claim.PSObject.Properties[$ListFieldName].Value | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object) }",
        "      if ($ReportClaim.PSObject.Properties.Name -contains $ListFieldName) { $ReportValues = @($ReportClaim.PSObject.Properties[$ListFieldName].Value | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object) }",
        "      if (($ClaimValues -join '|') -ne ($ReportValues -join '|')) {",
        "        $script:PrelaunchFailures += ('agent claims status report alignment ' + $ListFieldName + ' mismatch: ' + $ClaimId + ' claims=' + ($ClaimValues -join ',') + ' report=' + ($ReportValues -join ','))",
        "        return",
        "      }",
        "    }",
        "    $LockState = [string]$ReportClaim.lock_state",
        "    if ($LockState -and $LockState -notin @('unlocked','locked','invalid')) {",
        "      $script:PrelaunchFailures += ('agent claims status report alignment invalid lock_state: ' + $ClaimId + '=' + $LockState)",
        "      return",
        "    }",
        "    $LockPath = ([string]$ReportClaim.lock_path).Replace('\\','/')",
        "    if ($LockPath -and -not $LockPath.EndsWith('/claim_locks/' + $ClaimId + '.claim-lock.json')) {",
        "      $script:PrelaunchFailures += ('agent claims status report alignment lock_path mismatch: ' + $ClaimId + '=' + $LockPath)",
        "      return",
        "    }",
        "  }",
        "  Write-Host ('[prelaunch] agent claims status report alignment valid: claims=' + [string]$ClaimIds.Count)",
        "}",
        "function Invoke-AgentClaimsSpawnPlanAlignmentValidation {",
        "  param([string]$AgentClaimsPath, [string]$AgentSpawnPlanPath)",
        "  Write-Host '[prelaunch] agent claims spawn plan alignment'",
        "  foreach ($Path in @($AgentClaimsPath,$AgentSpawnPlanPath)) {",
        "    if (-not (Test-Path -LiteralPath $Path)) {",
        "      $script:PrelaunchFailures += ('agent claims spawn plan alignment missing path: ' + $Path)",
        "      return",
        "    }",
        "  }",
        "  try { $ClaimsPayload = Get-Content -Raw -LiteralPath $AgentClaimsPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('agent claims spawn plan alignment claims invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  try { $Plan = Get-Content -Raw -LiteralPath $AgentSpawnPlanPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('agent claims spawn plan alignment spawn plan invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  $ClaimsById = @{}",
        "  foreach ($Claim in @($ClaimsPayload.claims)) {",
        "    $ClaimId = [string]$Claim.claim_id",
        "    if ($ClaimId) { $ClaimsById[$ClaimId] = $Claim }",
        "  }",
        "  $PlanClaimsById = @{}",
        "  foreach ($BatchField in @('batches','env_bundle_ready_batches')) {",
        "    foreach ($Batch in @($Plan.PSObject.Properties[$BatchField].Value)) {",
        "      foreach ($Claim in @($Batch.claims)) {",
        "        $ClaimId = [string]$Claim.claim_id",
        "        if ($ClaimId) { $PlanClaimsById[$ClaimId] = $Claim }",
        "      }",
        "    }",
        "  }",
        "  foreach ($ListField in @('env_bundle_still_blocked_claims','blocked_or_manual_claims')) {",
        "    foreach ($Claim in @($Plan.PSObject.Properties[$ListField].Value)) {",
        "      $ClaimId = [string]$Claim.claim_id",
        "      if ($ClaimId) { $PlanClaimsById[$ClaimId] = $Claim }",
        "    }",
        "  }",
        "  $ClaimIds = @($ClaimsById.Keys | Sort-Object)",
        "  $PlanClaimIds = @($PlanClaimsById.Keys | Sort-Object)",
        "  if (($ClaimIds -join '|') -ne ($PlanClaimIds -join '|')) {",
        "    $script:PrelaunchFailures += ('agent claims spawn plan alignment claim_ids mismatch: claims=' + ($ClaimIds -join ',') + ' spawn=' + ($PlanClaimIds -join ','))",
        "    return",
        "  }",
        "  # Static audit markers for dynamic agent-claims/spawn-plan field checks:",
        "  # agent claims spawn plan alignment package_id mismatch:",
        "  # agent claims spawn plan alignment claim_state mismatch:",
        "  foreach ($ClaimId in $ClaimIds) {",
        "    $Claim = $ClaimsById[$ClaimId]",
        "    $PlanClaim = $PlanClaimsById[$ClaimId]",
        "    foreach ($FieldName in @('package_id','claim_state')) {",
        "      if ($PlanClaim.PSObject.Properties.Name -contains $FieldName) {",
        "        $ClaimValue = [string]$Claim.PSObject.Properties[$FieldName].Value",
        "        $PlanValue = [string]$PlanClaim.PSObject.Properties[$FieldName].Value",
        "        if ($ClaimValue -ne $PlanValue) {",
        "          $script:PrelaunchFailures += ('agent claims spawn plan alignment ' + $FieldName + ' mismatch: ' + $ClaimId + ' claims=' + $ClaimValue + ' spawn=' + $PlanValue)",
        "          return",
        "        }",
        "      }",
        "    }",
        "  }",
        "  Write-Host ('[prelaunch] agent claims spawn plan alignment valid: claims=' + [string]$ClaimIds.Count)",
        "}",
        "function Invoke-EnvQueueAgentClaimsAlignmentValidation {",
        "  param([string]$EnvQueuePath, [string]$AgentClaimsPath)",
        "  Write-Host '[prelaunch] env unblock queue agent claims alignment'",
        "  foreach ($Path in @($EnvQueuePath,$AgentClaimsPath)) {",
        "    if (-not (Test-Path -LiteralPath $Path)) {",
        "      $script:PrelaunchFailures += ('env unblock queue agent claims alignment missing path: ' + $Path)",
        "      return",
        "    }",
        "  }",
        "  try { $Queue = Get-Content -Raw -LiteralPath $EnvQueuePath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('env unblock queue agent claims alignment queue invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  try { $ClaimsPayload = Get-Content -Raw -LiteralPath $AgentClaimsPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('env unblock queue agent claims alignment claims invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  $ClaimsById = @{}",
        "  foreach ($Claim in @($ClaimsPayload.claims)) {",
        "    $ClaimId = [string]$Claim.claim_id",
        "    if ($ClaimId) { $ClaimsById[$ClaimId] = $Claim }",
        "  }",
        "  $RequiredEnvNames = @($Queue.required_env_names | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object)",
        "  $ExpectedEnvNames = @()",
        "  $ExpectedReadyAfterAll = @()",
        "  $ExpectedStillBlockedAfterAll = @()",
        "  foreach ($Claim in @($ClaimsPayload.claims)) {",
        "    $ClaimId = [string]$Claim.claim_id",
        "    $MissingEnv = @($Claim.missing_effective_env | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object)",
        "    if ($MissingEnv.Count -eq 0) { continue }",
        "    $ExpectedEnvNames += $MissingEnv",
        "    $BlockedReasons = @($Claim.blocked_reasons | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object)",
        "    $OtherBlockers = @($BlockedReasons | Where-Object { $_ -ne 'missing_effective_env' })",
        "    $MissingOutsideQueue = @($MissingEnv | Where-Object { $RequiredEnvNames -notcontains $_ })",
        "    if ($MissingOutsideQueue.Count -eq 0 -and $OtherBlockers.Count -eq 0) {",
        "      $ExpectedReadyAfterAll += $ClaimId",
        "    } else {",
        "      $ExpectedStillBlockedAfterAll += $ClaimId",
        "    }",
        "  }",
        "  $ExpectedEnvNames = @($ExpectedEnvNames | Sort-Object -Unique)",
        "  if (($RequiredEnvNames -join '|') -ne ($ExpectedEnvNames -join '|')) {",
        "    $script:PrelaunchFailures += ('env unblock queue agent claims alignment required_env_names mismatch: queue=' + ($RequiredEnvNames -join ',') + ' claims=' + ($ExpectedEnvNames -join ','))",
        "    return",
        "  }",
        "  # Static audit markers for dynamic env-queue/agent-claims checks:",
        "  # env unblock queue agent claims alignment unknown claim_id:",
        "  # env unblock queue agent claims alignment package_ids mismatch:",
        "  # env unblock queue agent claims alignment env not in claim missing_effective_env:",
        "  # env unblock queue agent claims alignment remaining_env_after_setting mismatch:",
        "  # env unblock queue agent claims alignment ready_after_all_env_claim_ids mismatch:",
        "  # env unblock queue agent claims alignment still_blocked_after_all_env_claim_ids mismatch:",
        "  foreach ($Entry in @($Queue.entries)) {",
        "    $EnvName = [string]$Entry.env",
        "    $EntryClaimIds = @($Entry.claim_ids | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object)",
        "    $ExpectedPackageIds = @()",
        "    foreach ($ClaimId in $EntryClaimIds) {",
        "      if (-not $ClaimsById.ContainsKey($ClaimId)) {",
        "        $script:PrelaunchFailures += ('env unblock queue agent claims alignment unknown claim_id: ' + $ClaimId)",
        "        return",
        "      }",
        "      $Claim = $ClaimsById[$ClaimId]",
        "      $ExpectedPackageIds += [string]$Claim.package_id",
        "      $MissingEnv = @($Claim.missing_effective_env | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object)",
        "      if ($MissingEnv -notcontains $EnvName) {",
        "        $script:PrelaunchFailures += ('env unblock queue agent claims alignment env not in claim missing_effective_env: ' + $EnvName + ' claim=' + $ClaimId)",
        "        return",
        "      }",
        "      if ($Entry.PSObject.Properties.Name -contains 'remaining_env_after_setting') {",
        "        $RemainingByClaim = $Entry.remaining_env_after_setting",
        "        if (-not ($RemainingByClaim.PSObject.Properties.Name -contains $ClaimId)) {",
        "          $script:PrelaunchFailures += ('env unblock queue agent claims alignment remaining_env_after_setting mismatch: ' + $EnvName + ' claim=' + $ClaimId)",
        "          return",
        "        }",
        "        $ExpectedRemaining = @($MissingEnv | Where-Object { $_ -ne $EnvName } | Sort-Object)",
        "        $ActualRemaining = @($RemainingByClaim.PSObject.Properties[$ClaimId].Value | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object)",
        "        if (($ExpectedRemaining -join '|') -ne ($ActualRemaining -join '|')) {",
        "          $script:PrelaunchFailures += ('env unblock queue agent claims alignment remaining_env_after_setting mismatch: ' + $EnvName + ' claim=' + $ClaimId + ' queue=' + ($ActualRemaining -join ',') + ' claims=' + ($ExpectedRemaining -join ','))",
        "          return",
        "        }",
        "      }",
        "    }",
        "    $ExpectedPackageIds = @($ExpectedPackageIds | Where-Object { $_ } | Sort-Object -Unique)",
        "    $EntryPackageIds = @($Entry.package_ids | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object -Unique)",
        "    if (($EntryPackageIds -join '|') -ne ($ExpectedPackageIds -join '|')) {",
        "      $script:PrelaunchFailures += ('env unblock queue agent claims alignment package_ids mismatch: ' + $EnvName + ' queue=' + ($EntryPackageIds -join ',') + ' claims=' + ($ExpectedPackageIds -join ','))",
        "      return",
        "    }",
        "  }",
        "  $QueueReadyAfterAll = @($Queue.ready_after_all_env_claim_ids | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object)",
        "  $ExpectedReadyAfterAll = @($ExpectedReadyAfterAll | Where-Object { $_ } | Sort-Object)",
        "  if (($QueueReadyAfterAll -join '|') -ne ($ExpectedReadyAfterAll -join '|')) {",
        "    $script:PrelaunchFailures += ('env unblock queue agent claims alignment ready_after_all_env_claim_ids mismatch: queue=' + ($QueueReadyAfterAll -join ',') + ' claims=' + ($ExpectedReadyAfterAll -join ','))",
        "    return",
        "  }",
        "  $QueueStillBlockedAfterAll = @($Queue.still_blocked_after_all_env_claim_ids | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object)",
        "  $ExpectedStillBlockedAfterAll = @($ExpectedStillBlockedAfterAll | Where-Object { $_ } | Sort-Object)",
        "  if (($QueueStillBlockedAfterAll -join '|') -ne ($ExpectedStillBlockedAfterAll -join '|')) {",
        "    $script:PrelaunchFailures += ('env unblock queue agent claims alignment still_blocked_after_all_env_claim_ids mismatch: queue=' + ($QueueStillBlockedAfterAll -join ',') + ' claims=' + ($ExpectedStillBlockedAfterAll -join ','))",
        "    return",
        "  }",
        "  Write-Host ('[prelaunch] env unblock queue agent claims alignment valid: envs=' + [string]$RequiredEnvNames.Count + ' claims=' + [string]$ClaimsById.Count)",
        "}",
        "function Invoke-ReadyLaunchersAgentClaimsAlignmentValidation {",
        "  param([string]$AgentClaimsPath, [string]$ReadyLauncherPath, [string]$ReadyParallelLauncherPath, [string]$EnvBundleLauncherPath)",
        "  Write-Host '[prelaunch] ready launchers agent claims alignment'",
        "  foreach ($Path in @($AgentClaimsPath,$ReadyLauncherPath,$ReadyParallelLauncherPath,$EnvBundleLauncherPath)) {",
        "    if (-not (Test-Path -LiteralPath $Path)) {",
        "      $script:PrelaunchFailures += ('ready launchers agent claims alignment missing path: ' + $Path)",
        "      return",
        "    }",
        "  }",
        "  try { $ClaimsPayload = Get-Content -Raw -LiteralPath $AgentClaimsPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('ready launchers agent claims alignment claims invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  function Get-LauncherRows([string]$Path, [string]$Pattern) {",
        "    $Text = Get-Content -Raw -LiteralPath $Path",
        "    $Rows = @()",
        "    foreach ($Match in [regex]::Matches($Text, $Pattern)) {",
        "      $Rows += [pscustomobject]@{",
        "        claim_id = [string]$Match.Groups[1].Value",
        "        package_id = [string]$Match.Groups[2].Value",
        "        script_path = [string]$Match.Groups[3].Value",
        "      }",
        "    }",
        "    return $Rows",
        "  }",
        "  function Test-LauncherRows([string]$Name, [object[]]$Rows, [object[]]$ExpectedClaimIds, [hashtable]$ClaimsById) {",
        "    $RowClaimIds = @($Rows | ForEach-Object { [string]$_.claim_id } | Where-Object { $_ } | Sort-Object)",
        "    $ExpectedSorted = @($ExpectedClaimIds | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object)",
        "    if (($RowClaimIds -join '|') -ne ($ExpectedSorted -join '|')) {",
        "      $script:PrelaunchFailures += ('ready launchers agent claims alignment ' + $Name + ' claim_ids mismatch: launcher=' + ($RowClaimIds -join ',') + ' claims=' + ($ExpectedSorted -join ','))",
        "      return $false",
        "    }",
        "    foreach ($Row in $Rows) {",
        "      $ClaimId = [string]$Row.claim_id",
        "      if (-not $ClaimsById.ContainsKey($ClaimId)) {",
        "        $script:PrelaunchFailures += ('ready launchers agent claims alignment ' + $Name + ' unknown claim_id: ' + $ClaimId)",
        "        return $false",
        "      }",
        "      $Claim = $ClaimsById[$ClaimId]",
        "      foreach ($FieldName in @('package_id','script_path')) {",
        "        $ClaimValue = [string]$Claim.PSObject.Properties[$FieldName].Value",
        "        $RowValue = [string]$Row.PSObject.Properties[$FieldName].Value",
        "        if ($ClaimValue -ne $RowValue) {",
        "          $script:PrelaunchFailures += ('ready launchers agent claims alignment ' + $Name + ' ' + $FieldName + ' mismatch: ' + $ClaimId + ' launcher=' + $RowValue + ' claims=' + $ClaimValue)",
        "          return $false",
        "        }",
        "      }",
        "    }",
        "    return $true",
        "  }",
        "  $ClaimsById = @{}",
        "  $ReadyClaimIds = @()",
        "  $EnvBundleClaimIds = @()",
        "  foreach ($Claim in @($ClaimsPayload.claims)) {",
        "    $ClaimId = [string]$Claim.claim_id",
        "    if (-not $ClaimId) { continue }",
        "    $ClaimsById[$ClaimId] = $Claim",
        "    if ([string]$Claim.claim_state -eq 'ready_to_claim') { $ReadyClaimIds += $ClaimId }",
        "    $MissingEnv = @($Claim.missing_effective_env | ForEach-Object { [string]$_ } | Where-Object { $_ })",
        "    $BlockedReasons = @($Claim.blocked_reasons | ForEach-Object { [string]$_ } | Where-Object { $_ })",
        "    $OtherBlockers = @($BlockedReasons | Where-Object { $_ -ne 'missing_effective_env' })",
        "    if ($MissingEnv.Count -gt 0 -and $OtherBlockers.Count -eq 0) { $EnvBundleClaimIds += $ClaimId }",
        "  }",
        "  # Static audit markers for dynamic launcher/agent-claims checks:",
        "  # ready launchers agent claims alignment ready claim_ids mismatch:",
        "  # ready launchers agent claims alignment ready-parallel claim_ids mismatch:",
        "  # ready launchers agent claims alignment env-bundle claim_ids mismatch:",
        "  # ready launchers agent claims alignment ready package_id mismatch:",
        "  # ready launchers agent claims alignment ready script_path mismatch:",
        "  # ready launchers agent claims alignment valid:",
        "  $ReadyRows = @(Get-LauncherRows $ReadyLauncherPath \"Invoke-ReadyClaim\\s+'([^']*)'\\s+'([^']*)'\\s+'([^']*)'\")",
        "  $ReadyParallelRows = @(Get-LauncherRows $ReadyParallelLauncherPath \"Start-ReadyClaimJob\\s+'([^']*)'\\s+'([^']*)'\\s+'([^']*)'\")",
        "  $EnvBundleRows = @(Get-LauncherRows $EnvBundleLauncherPath \"Start-EnvBundleClaimJob\\s+'([^']*)'\\s+'([^']*)'\\s+'([^']*)'\")",
        "  if (-not (Test-LauncherRows 'ready' $ReadyRows $ReadyClaimIds $ClaimsById)) { return }",
        "  if (-not (Test-LauncherRows 'ready-parallel' $ReadyParallelRows $ReadyClaimIds $ClaimsById)) { return }",
        "  if (-not (Test-LauncherRows 'env-bundle' $EnvBundleRows $EnvBundleClaimIds $ClaimsById)) { return }",
        "  Write-Host ('[prelaunch] ready launchers agent claims alignment valid: ready=' + [string]$ReadyClaimIds.Count + ' env_bundle=' + [string]$EnvBundleClaimIds.Count)",
        "}",
        "function Invoke-DispatchRunnerManifestAlignmentValidation {",
        "  param([string]$ManifestPath)",
        "  Write-Host '[prelaunch] dispatch runner manifest alignment'",
        "  if (-not (Test-Path -LiteralPath $ManifestPath)) {",
        "    $script:PrelaunchFailures += ('dispatch runner manifest alignment missing manifest: ' + $ManifestPath)",
        "    return",
        "  }",
        "  try { $Manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('dispatch runner manifest alignment manifest invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  $RunnerPath = ''",
        "  if ($Manifest.PSObject.Properties.Name -contains 'dispatch_runner_path') { $RunnerPath = [string]$Manifest.dispatch_runner_path }",
        "  if (-not $RunnerPath) {",
        "    Write-Host '[prelaunch] dispatch runner manifest alignment skipped: no dispatch_runner_path'",
        "    return",
        "  }",
        "  if (-not (Test-Path -LiteralPath $RunnerPath)) {",
        "    $script:PrelaunchFailures += ('dispatch runner manifest alignment runner missing: ' + $RunnerPath)",
        "    return",
        "  }",
        "  try { $RunnerText = Get-Content -Raw -LiteralPath $RunnerPath } catch {",
        "    $script:PrelaunchFailures += ('dispatch runner manifest alignment runner unreadable: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  foreach ($RequiredText in @('TAMANDUA_ALLOW_ONE_SHOT_DISPATCH','TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH','Missing claim lock helper','claim lock exit','Dispatch one-shot completed with failures')) {",
        "    if (-not $RunnerText.Contains($RequiredText)) {",
        "      $script:PrelaunchFailures += ('dispatch runner manifest alignment missing runner marker: ' + $RequiredText)",
        "      return",
        "    }",
        "  }",
        "  $RunnerTextNormalized = $RunnerText.Replace('\\','/')",
        "  $ManifestPathNormalized = $ManifestPath.Replace('\\','/')",
        "  if (-not $RunnerTextNormalized.Contains($ManifestPathNormalized)) {",
        "    $script:PrelaunchFailures += ('dispatch runner manifest alignment manifest path mismatch: ' + $ManifestPath)",
        "    return",
        "  }",
        "  if (-not ($Manifest.PSObject.Properties.Name -contains 'packages') -or $Manifest.packages -isnot [System.Array]) {",
        "    return",
        "  }",
        "  $StagedLauncherPaths = @()",
        "  if ($Manifest.PSObject.Properties.Name -contains 'staged_launcher_paths' -and $Manifest.staged_launcher_paths -is [System.Array]) {",
        "    $StagedLauncherPaths = @($Manifest.staged_launcher_paths)",
        "  }",
        "  foreach ($LauncherPath in $StagedLauncherPaths) {",
        "    $LauncherPathText = [string]$LauncherPath",
        "    if ($LauncherPathText -and -not $RunnerTextNormalized.Contains($LauncherPathText.Replace('\\','/'))) {",
        "      $script:PrelaunchFailures += ('dispatch runner manifest alignment missing staged launcher: ' + $LauncherPathText)",
        "      return",
        "    }",
        "  }",
        "  foreach ($Package in @($Manifest.packages)) {",
        "    $PackageId = [string]$Package.package_id",
        "    $ScriptPath = [string]$Package.script_path",
        "    $StagedSelected = $false",
        "    $HasStagedSelection = $false",
        "    if ($Package.PSObject.Properties.Name -contains 'staged_launcher_selected') { $HasStagedSelection = $true; $StagedSelected = ($Package.staged_launcher_selected -eq $true) }",
        "    if ($PackageId -and $ScriptPath -and $HasStagedSelection -and -not $StagedSelected) {",
        "      $ClaimId = 'claim-' + $PackageId",
        "      if (-not $RunnerTextNormalized.Contains($ScriptPath.Replace('\\','/'))) {",
        "        $script:PrelaunchFailures += ('dispatch runner manifest alignment missing direct script: ' + $PackageId + '=' + $ScriptPath)",
        "        return",
        "      }",
        "      if (-not $RunnerText.Contains($ClaimId)) {",
        "        $script:PrelaunchFailures += ('dispatch runner manifest alignment missing direct claim: ' + $PackageId + '=' + $ClaimId)",
        "        return",
        "      }",
        "    }",
        "  }",
        "  Write-Host ('[prelaunch] dispatch runner manifest alignment valid: runner=' + $RunnerPath)",
        "}",
        "function Invoke-DispatchManifestShapeValidation {",
        "  param([string]$Path)",
        "  Write-Host '[prelaunch] dispatch manifest shape'",
        "  if (-not (Test-Path -LiteralPath $Path)) {",
        "    $script:PrelaunchFailures += ('dispatch manifest shape missing ' + $Path)",
        "    return",
        "  }",
        "  try { $Manifest = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('dispatch manifest shape invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  foreach ($PathField in @('output_dir','owner_launch_plan_path','owner_launch_plan_json_path','execution_matrix_path','execution_matrix_json_path','agent_claims_json_path','agent_spawn_plan_json_path','agent_spawn_launcher_path','claim_status_report_json_path','claim_lock_helper_path','env_unblock_queue_json_path','ready_claims_launcher_path','ready_claims_parallel_launcher_path','env_bundle_ready_claims_launcher_path','dispatch_prelaunch_validation_path')) {",
        "    if (-not ($Manifest.PSObject.Properties.Name -contains $PathField)) {",
        "      $script:PrelaunchFailures += ('dispatch manifest shape missing ' + $PathField)",
        "      return",
        "    }",
        "    $PathValue = [string]$Manifest.PSObject.Properties[$PathField].Value",
        "    if (-not $PathValue) {",
        "      $script:PrelaunchFailures += ('dispatch manifest shape empty ' + $PathField)",
        "      return",
        "    }",
        "    if (-not (Test-Path -LiteralPath $PathValue)) {",
        "      $script:PrelaunchFailures += ('dispatch manifest shape path missing ' + $PathField + ': ' + $PathValue)",
        "      return",
        "    }",
        "  }",
        "  if (-not ($Manifest.PSObject.Properties.Name -contains 'packages')) {",
        "    $script:PrelaunchFailures += 'dispatch manifest shape missing packages'",
        "    return",
        "  }",
        "  if (-not ($Manifest.PSObject.Properties.Name -contains 'profile_id')) {",
        "    $script:PrelaunchFailures += 'dispatch manifest shape missing profile_id'",
        "    return",
        "  }",
        "  if ([string]$Manifest.profile_id -ne 'validation-execution-preflight-probe') {",
        "    $script:PrelaunchFailures += ('dispatch manifest shape invalid profile_id: ' + [string]$Manifest.profile_id)",
        "    return",
        "  }",
        "  if (-not ($Manifest.PSObject.Properties.Name -contains 'source_preflight')) {",
        "    $script:PrelaunchFailures += 'dispatch manifest shape missing source_preflight'",
        "    return",
        "  }",
        "  $SourcePreflightPath = [string]$Manifest.source_preflight",
        "  if (-not $SourcePreflightPath) {",
        "    $script:PrelaunchFailures += 'dispatch manifest shape empty source_preflight'",
        "    return",
        "  }",
        "  if (-not (Test-Path -LiteralPath $SourcePreflightPath)) {",
        "    $script:PrelaunchFailures += ('dispatch manifest shape source_preflight missing: ' + $SourcePreflightPath)",
        "    return",
        "  }",
        "  try { $SourcePreflight = Get-Content -Raw -LiteralPath $SourcePreflightPath | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('dispatch manifest shape source_preflight invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  $SourceProfileId = ''",
        "  if ($SourcePreflight.PSObject.Properties.Name -contains 'profile_id') {",
        "    $SourceProfileId = [string]$SourcePreflight.profile_id",
        "  } elseif ($SourcePreflight.PSObject.Properties.Name -contains 'profile') {",
        "    $SourceProfileId = [string]$SourcePreflight.profile",
        "  }",
        "  if ($SourceProfileId -ne 'validation-execution-preflight-probe') {",
        "    $script:PrelaunchFailures += ('dispatch manifest shape source_preflight invalid profile_id: ' + $SourceProfileId)",
        "    return",
        "  }",
        "  if ($Manifest.packages -isnot [System.Array]) {",
        "    $script:PrelaunchFailures += 'dispatch manifest shape packages is not a list'",
        "    return",
        "  }",
        "  if (-not ($Manifest.PSObject.Properties.Name -contains 'expected_package_ids')) {",
        "    $script:PrelaunchFailures += 'dispatch manifest shape missing expected_package_ids'",
        "    return",
        "  }",
        "  if ($Manifest.expected_package_ids -isnot [System.Array]) {",
        "    $script:PrelaunchFailures += 'dispatch manifest shape expected_package_ids is not a list'",
        "    return",
        "  }",
        "  if (-not ($Manifest.PSObject.Properties.Name -contains 'expected_waves')) {",
        "    $script:PrelaunchFailures += 'dispatch manifest shape missing expected_waves'",
        "    return",
        "  }",
        "  if ($Manifest.expected_waves -isnot [System.Array]) {",
        "    $script:PrelaunchFailures += 'dispatch manifest shape expected_waves is not a list'",
        "    return",
        "  }",
        "  # Static audit markers for optional manifest launcher fields:",
        "  # dispatch manifest shape launcher_paths is not a list",
        "  # dispatch manifest shape launcher_paths contains empty value",
        "  # dispatch manifest shape launcher path missing launcher_paths:",
        "  # dispatch manifest shape missing staged_launcher_paths",
        "  # dispatch manifest shape staged_launcher_paths is not a list",
        "  # dispatch manifest shape staged_launcher_paths contains empty value",
        "  # dispatch manifest shape launcher path missing staged_launcher_paths:",
        "  # dispatch manifest shape empty agent_roster_path",
        "  # dispatch manifest shape path missing agent_roster_path:",
        "  # dispatch manifest shape empty dispatch_runner_path",
        "  # dispatch manifest shape path missing dispatch_runner_path:",
        "  foreach ($LauncherListField in @('launcher_paths','staged_launcher_paths')) {",
        "    if ($Manifest.PSObject.Properties.Name -contains $LauncherListField) {",
        "      if ($Manifest.PSObject.Properties[$LauncherListField].Value -isnot [System.Array]) {",
        "        $script:PrelaunchFailures += ('dispatch manifest shape ' + $LauncherListField + ' is not a list')",
        "        return",
        "      }",
        "      foreach ($LauncherPath in @($Manifest.PSObject.Properties[$LauncherListField].Value)) {",
        "        $LauncherPathText = [string]$LauncherPath",
        "        if (-not $LauncherPathText) {",
        "          $script:PrelaunchFailures += ('dispatch manifest shape ' + $LauncherListField + ' contains empty value')",
        "          return",
        "        }",
        "        if (-not (Test-Path -LiteralPath $LauncherPathText)) {",
        "          $script:PrelaunchFailures += ('dispatch manifest shape launcher path missing ' + $LauncherListField + ': ' + $LauncherPathText)",
        "          return",
        "        }",
        "      }",
        "    }",
        "  }",
        "  if ($Manifest.PSObject.Properties.Name -contains 'dispatch_runner_path' -and $null -ne $Manifest.PSObject.Properties['dispatch_runner_path'].Value -and -not ($Manifest.PSObject.Properties.Name -contains 'staged_launcher_paths')) {",
        "    $script:PrelaunchFailures += 'dispatch manifest shape missing staged_launcher_paths'",
        "    return",
        "  }",
        "  foreach ($OptionalPathField in @('agent_roster_path','dispatch_runner_path')) {",
        "    if ($Manifest.PSObject.Properties.Name -contains $OptionalPathField -and $null -ne $Manifest.PSObject.Properties[$OptionalPathField].Value) {",
        "      $OptionalPathValue = [string]$Manifest.PSObject.Properties[$OptionalPathField].Value",
        "      if (-not $OptionalPathValue) {",
        "        $script:PrelaunchFailures += ('dispatch manifest shape empty ' + $OptionalPathField)",
        "        return",
        "      }",
        "      if (-not (Test-Path -LiteralPath $OptionalPathValue)) {",
        "        $script:PrelaunchFailures += ('dispatch manifest shape path missing ' + $OptionalPathField + ': ' + $OptionalPathValue)",
        "        return",
        "      }",
        "    }",
        "  }",
        "  $PackageIds = @()",
        "  $PackageWaves = @()",
        "  # Static audit markers for dynamic dispatch-manifest package path fields:",
        "  # dispatch manifest shape package missing output_dir:",
        "  # dispatch manifest shape package missing script_path:",
        "  # dispatch manifest shape package missing prompt_path:",
        "  # dispatch manifest shape package missing status_path:",
        "  # dispatch manifest shape package empty output_dir:",
        "  # dispatch manifest shape package empty script_path:",
        "  # dispatch manifest shape package empty prompt_path:",
        "  # dispatch manifest shape package empty status_path:",
        "  # dispatch manifest shape package path missing output_dir:",
        "  # dispatch manifest shape package path missing script_path:",
        "  # dispatch manifest shape package path missing prompt_path:",
        "  foreach ($Package in @($Manifest.packages)) {",
        "    if (-not ($Package.PSObject.Properties.Name -contains 'package_id')) {",
        "      $script:PrelaunchFailures += 'dispatch manifest shape package without package_id'",
        "      return",
        "    }",
        "    $PackageId = [string]$Package.package_id",
        "    if (-not $PackageId) {",
        "      $script:PrelaunchFailures += 'dispatch manifest shape package without package_id'",
        "      return",
        "    }",
        "    $PackageIds += $PackageId",
        "    foreach ($PackagePathField in @('output_dir','script_path','prompt_path','status_path')) {",
        "      if (-not ($Package.PSObject.Properties.Name -contains $PackagePathField)) {",
        "        $script:PrelaunchFailures += ('dispatch manifest shape package missing ' + $PackagePathField + ': ' + $PackageId)",
        "        return",
        "      }",
        "      $PackagePathValue = [string]$Package.PSObject.Properties[$PackagePathField].Value",
        "      if (-not $PackagePathValue) {",
        "        $script:PrelaunchFailures += ('dispatch manifest shape package empty ' + $PackagePathField + ': ' + $PackageId)",
        "        return",
        "      }",
        "      if ($PackagePathField -in @('output_dir','script_path','prompt_path') -and -not (Test-Path -LiteralPath $PackagePathValue)) {",
        "        $script:PrelaunchFailures += ('dispatch manifest shape package path missing ' + $PackagePathField + ': ' + $PackageId + '=' + $PackagePathValue)",
        "        return",
        "      }",
        "      if ($PackagePathField -eq 'status_path') {",
        "        $StatusParent = Split-Path -Parent $PackagePathValue",
        "        if (-not $StatusParent -or -not (Test-Path -LiteralPath $StatusParent)) {",
        "          $script:PrelaunchFailures += ('dispatch manifest shape package status parent missing: ' + $PackageId + '=' + $PackagePathValue)",
        "          return",
        "        }",
        "      }",
        "    }",
        "    if (-not ($Package.PSObject.Properties.Name -contains 'wave')) {",
        "      $script:PrelaunchFailures += ('dispatch manifest shape package missing wave: ' + $PackageId)",
        "      return",
        "    }",
        "    $WaveRaw = [string]$Package.wave",
        "    $Wave = 0",
        "    if (-not [int]::TryParse($WaveRaw, [ref]$Wave) -or $Wave -lt 1) {",
        "      $script:PrelaunchFailures += ('dispatch manifest shape package invalid wave: ' + $PackageId + '=' + $WaveRaw)",
        "      return",
        "    }",
        "    $PackageWaves += $Wave",
        "  }",
        "  $DuplicatePackageIds = @($PackageIds | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name } | Sort-Object)",
        "  if ($DuplicatePackageIds.Count -gt 0) {",
        "    $script:PrelaunchFailures += ('dispatch manifest shape duplicate package_id: ' + ($DuplicatePackageIds -join ','))",
        "    return",
        "  }",
        "  $ExpectedPackageIds = @($Manifest.expected_package_ids | ForEach-Object { [string]$_ } | Sort-Object)",
        "  if (@($ExpectedPackageIds | Where-Object { -not $_ }).Count -gt 0) {",
        "    $script:PrelaunchFailures += 'dispatch manifest shape expected_package_ids contains empty value'",
        "    return",
        "  }",
        "  $SortedPackageIds = @($PackageIds | Sort-Object)",
        "  if (($ExpectedPackageIds -join '|') -ne ($SortedPackageIds -join '|')) {",
        "    $script:PrelaunchFailures += ('dispatch manifest shape expected_package_ids mismatch: expected=' + ($ExpectedPackageIds -join ',') + ' packages=' + ($SortedPackageIds -join ','))",
        "    return",
        "  }",
        "  $ExpectedWaves = @($Manifest.expected_waves | ForEach-Object { [string]$_ } | Sort-Object)",
        "  if (@($ExpectedWaves | Where-Object { -not $_ }).Count -gt 0) {",
        "    $script:PrelaunchFailures += 'dispatch manifest shape expected_waves contains empty value'",
        "    return",
        "  }",
        "  $PackageWaves = @($PackageWaves | Sort-Object -Unique | ForEach-Object { [string]$_ })",
        "  if (($ExpectedWaves -join '|') -ne ($PackageWaves -join '|')) {",
        "    $script:PrelaunchFailures += ('dispatch manifest shape expected_waves mismatch: expected=' + ($ExpectedWaves -join ',') + ' packages=' + ($PackageWaves -join ','))",
        "    return",
        "  }",
        "  Write-Host ('[prelaunch] dispatch manifest shape valid: packages=' + [string]@($Manifest.packages).Count)",
        "}",
        "function Invoke-AgentSpawnPlanShapeValidation {",
        "  param([string]$Path)",
        "  Write-Host '[prelaunch] agent spawn plan shape'",
        "  if (-not (Test-Path -LiteralPath $Path)) {",
        "    $script:PrelaunchFailures += ('agent spawn plan shape missing ' + $Path)",
        "    return",
        "  }",
        "  try { $Plan = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('agent spawn plan shape invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  if (-not ($Plan.PSObject.Properties.Name -contains 'schema_version')) {",
        "    $script:PrelaunchFailures += 'agent spawn plan shape missing schema_version'",
        "    return",
        "  }",
        "  if (-not ($Plan.PSObject.Properties.Name -contains 'artifact')) {",
        "    $script:PrelaunchFailures += 'agent spawn plan shape missing artifact'",
        "    return",
        "  }",
        "  if ([int]$Plan.schema_version -ne 1) {",
        "    $script:PrelaunchFailures += ('agent spawn plan shape invalid schema_version: ' + [string]$Plan.schema_version)",
        "    return",
        "  }",
        "  if ([string]$Plan.artifact -ne 'validation-agent-spawn-plan') {",
        "    $script:PrelaunchFailures += ('agent spawn plan shape invalid artifact: ' + [string]$Plan.artifact)",
        "    return",
        "  }",
        "  if ($Plan.PSObject.Properties.Name -contains 'source_artifact' -and [string]$Plan.source_artifact -ne 'validation-agent-claims') {",
        "    $script:PrelaunchFailures += ('agent spawn plan shape invalid source_artifact: ' + [string]$Plan.source_artifact)",
        "    return",
        "  }",
        "  # Static audit markers for dynamic agent-spawn-plan count fields:",
        "  # agent spawn plan shape missing ready_batch_count",
        "  # agent spawn plan shape missing ready_claim_count",
        "  # agent spawn plan shape missing env_bundle_ready_batch_count",
        "  # agent spawn plan shape missing env_bundle_ready_claim_count",
        "  # agent spawn plan shape missing env_bundle_still_blocked_claim_count",
        "  # agent spawn plan shape missing blocked_or_manual_claim_count",
        "  # agent spawn plan shape invalid ready_batch_count:",
        "  # agent spawn plan shape invalid ready_claim_count:",
        "  # agent spawn plan shape invalid env_bundle_ready_batch_count:",
        "  # agent spawn plan shape invalid env_bundle_ready_claim_count:",
        "  # agent spawn plan shape invalid env_bundle_still_blocked_claim_count:",
        "  # agent spawn plan shape invalid blocked_or_manual_claim_count:",
        "  # agent spawn plan shape missing batches",
        "  # agent spawn plan shape missing env_bundle_ready_batches",
        "  # agent spawn plan shape missing env_bundle_still_blocked_claims",
        "  # agent spawn plan shape missing blocked_or_manual_claims",
        "  # agent spawn plan shape batches is not a list",
        "  # agent spawn plan shape env_bundle_ready_batches is not a list",
        "  # agent spawn plan shape env_bundle_still_blocked_claims is not a list",
        "  # agent spawn plan shape blocked_or_manual_claims is not a list",
        "  # agent spawn plan shape ready_claim_count mismatch:",
        "  # agent spawn plan shape env_bundle_ready_claim_count mismatch:",
        "  foreach ($CountField in @('ready_batch_count','ready_claim_count','env_bundle_ready_batch_count','env_bundle_ready_claim_count','env_bundle_still_blocked_claim_count','blocked_or_manual_claim_count')) {",
        "    if (-not ($Plan.PSObject.Properties.Name -contains $CountField)) {",
        "      $script:PrelaunchFailures += ('agent spawn plan shape missing ' + $CountField)",
        "      return",
        "    }",
        "    $CountRaw = [string]$Plan.PSObject.Properties[$CountField].Value",
        "    $Count = 0",
        "    if (-not [int]::TryParse($CountRaw, [ref]$Count) -or $Count -lt 0) {",
        "      $script:PrelaunchFailures += ('agent spawn plan shape invalid ' + $CountField + ': ' + $CountRaw)",
        "      return",
        "    }",
        "  }",
        "  foreach ($ListField in @('batches','env_bundle_ready_batches','env_bundle_still_blocked_claims','blocked_or_manual_claims')) {",
        "    if (-not ($Plan.PSObject.Properties.Name -contains $ListField)) {",
        "      $script:PrelaunchFailures += ('agent spawn plan shape missing ' + $ListField)",
        "      return",
        "    }",
        "    if ($Plan.PSObject.Properties[$ListField].Value -isnot [System.Array]) {",
        "      $script:PrelaunchFailures += ('agent spawn plan shape ' + $ListField + ' is not a list')",
        "      return",
        "    }",
        "  }",
        "  function Test-SpawnPlanBatchList([object[]]$Batches, [string]$FieldName, [string]$CountFieldName) {",
        "    $ClaimCount = 0",
        "    foreach ($Batch in @($Batches)) {",
        "      if (-not ($Batch.PSObject.Properties.Name -contains 'claims')) {",
        "        $script:PrelaunchFailures += ('agent spawn plan shape batch missing claims in ' + $FieldName)",
        "        return $null",
        "      }",
        "      if ($Batch.claims -isnot [System.Array]) {",
        "        $script:PrelaunchFailures += ('agent spawn plan shape batch claims is not a list in ' + $FieldName)",
        "        return $null",
        "      }",
        "      if (-not ($Batch.PSObject.Properties.Name -contains 'claim_count')) {",
        "        $script:PrelaunchFailures += ('agent spawn plan shape batch missing claim_count in ' + $FieldName)",
        "        return $null",
        "      }",
        "      $BatchClaimCountRaw = [string]$Batch.claim_count",
        "      $BatchClaimCount = 0",
        "      if (-not [int]::TryParse($BatchClaimCountRaw, [ref]$BatchClaimCount) -or $BatchClaimCount -lt 0) {",
        "        $script:PrelaunchFailures += ('agent spawn plan shape invalid batch claim_count in ' + $FieldName + ': ' + $BatchClaimCountRaw)",
        "        return $null",
        "      }",
        "      if ($BatchClaimCount -ne @($Batch.claims).Count) {",
        "        $script:PrelaunchFailures += ('agent spawn plan shape batch claim_count mismatch in ' + $FieldName + ': count=' + [string]$BatchClaimCount + ' claims=' + [string]@($Batch.claims).Count)",
        "        return $null",
        "      }",
        "      foreach ($Claim in @($Batch.claims)) {",
        "        if (-not ($Claim.PSObject.Properties.Name -contains 'claim_id') -or -not [string]$Claim.claim_id) {",
        "          $script:PrelaunchFailures += ('agent spawn plan shape batch claim without claim_id in ' + $FieldName)",
        "          return $null",
        "        }",
        "      }",
        "      $ClaimCount += $BatchClaimCount",
        "    }",
        "    if ([int]$Plan.PSObject.Properties[$CountFieldName].Value -ne $ClaimCount) {",
        "      $script:PrelaunchFailures += ('agent spawn plan shape ' + $CountFieldName + ' mismatch: count=' + [string]$Plan.PSObject.Properties[$CountFieldName].Value + ' claims=' + [string]$ClaimCount)",
        "      return $null",
        "    }",
        "    return $ClaimCount",
        "  }",
        "  if ([int]$Plan.ready_batch_count -ne @($Plan.batches).Count) {",
        "    $script:PrelaunchFailures += ('agent spawn plan shape ready_batch_count mismatch: count=' + [string]$Plan.ready_batch_count + ' batches=' + [string]@($Plan.batches).Count)",
        "    return",
        "  }",
        "  if ([int]$Plan.env_bundle_ready_batch_count -ne @($Plan.env_bundle_ready_batches).Count) {",
        "    $script:PrelaunchFailures += ('agent spawn plan shape env_bundle_ready_batch_count mismatch: count=' + [string]$Plan.env_bundle_ready_batch_count + ' batches=' + [string]@($Plan.env_bundle_ready_batches).Count)",
        "    return",
        "  }",
        "  if ($null -eq (Test-SpawnPlanBatchList @($Plan.batches) 'batches' 'ready_claim_count')) { return }",
        "  if ($null -eq (Test-SpawnPlanBatchList @($Plan.env_bundle_ready_batches) 'env_bundle_ready_batches' 'env_bundle_ready_claim_count')) { return }",
        "  if ([int]$Plan.env_bundle_still_blocked_claim_count -ne @($Plan.env_bundle_still_blocked_claims).Count) {",
        "    $script:PrelaunchFailures += ('agent spawn plan shape env_bundle_still_blocked_claim_count mismatch: count=' + [string]$Plan.env_bundle_still_blocked_claim_count + ' claims=' + [string]@($Plan.env_bundle_still_blocked_claims).Count)",
        "    return",
        "  }",
        "  if ([int]$Plan.blocked_or_manual_claim_count -ne @($Plan.blocked_or_manual_claims).Count) {",
        "    $script:PrelaunchFailures += ('agent spawn plan shape blocked_or_manual_claim_count mismatch: count=' + [string]$Plan.blocked_or_manual_claim_count + ' claims=' + [string]@($Plan.blocked_or_manual_claims).Count)",
        "    return",
        "  }",
        "  Write-Host ('[prelaunch] agent spawn plan shape valid: ready_claims=' + [string]$Plan.ready_claim_count + ' env_bundle_ready_claims=' + [string]$Plan.env_bundle_ready_claim_count)",
        "}",
        "function Invoke-AgentClaimsShapeValidation {",
        "  param([string]$Path)",
        "  Write-Host '[prelaunch] agent claims shape'",
        "  if (-not (Test-Path -LiteralPath $Path)) {",
        "    $script:PrelaunchFailures += ('agent claims shape missing ' + $Path)",
        "    return",
        "  }",
        "  try { $ClaimsPayload = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('agent claims shape invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  if (-not ($ClaimsPayload.PSObject.Properties.Name -contains 'schema_version')) {",
        "    $script:PrelaunchFailures += 'agent claims shape missing schema_version'",
        "    return",
        "  }",
        "  if (-not ($ClaimsPayload.PSObject.Properties.Name -contains 'artifact')) {",
        "    $script:PrelaunchFailures += 'agent claims shape missing artifact'",
        "    return",
        "  }",
        "  if ([int]$ClaimsPayload.schema_version -ne 1) {",
        "    $script:PrelaunchFailures += ('agent claims shape invalid schema_version: ' + [string]$ClaimsPayload.schema_version)",
        "    return",
        "  }",
        "  if ([string]$ClaimsPayload.artifact -ne 'validation-agent-claims') {",
        "    $script:PrelaunchFailures += ('agent claims shape invalid artifact: ' + [string]$ClaimsPayload.artifact)",
        "    return",
        "  }",
        "  if (-not ($ClaimsPayload.PSObject.Properties.Name -contains 'claims')) {",
        "    $script:PrelaunchFailures += 'agent claims shape missing claims'",
        "    return",
        "  }",
        "  if ($ClaimsPayload.claims -isnot [System.Array]) {",
        "    $script:PrelaunchFailures += 'agent claims shape claims is not a list'",
        "    return",
        "  }",
        "  # Static audit markers for dynamic agent-claims count fields:",
        "  # agent claims shape missing claim_count",
        "  # agent claims shape missing ready_to_claim_count",
        "  # agent claims shape missing blocked_claim_count",
        "  # agent claims shape missing manual_claim_count",
        "  # agent claims shape invalid claim_count:",
        "  # agent claims shape invalid ready_to_claim_count:",
        "  # agent claims shape invalid blocked_claim_count:",
        "  # agent claims shape invalid manual_claim_count:",
        "  foreach ($CountField in @('claim_count','ready_to_claim_count','blocked_claim_count','manual_claim_count')) {",
        "    if (-not ($ClaimsPayload.PSObject.Properties.Name -contains $CountField)) {",
        "      $script:PrelaunchFailures += ('agent claims shape missing ' + $CountField)",
        "      return",
        "    }",
        "    $CountRaw = [string]$ClaimsPayload.PSObject.Properties[$CountField].Value",
        "    $Count = 0",
        "    if (-not [int]::TryParse($CountRaw, [ref]$Count) -or $Count -lt 0) {",
        "      $script:PrelaunchFailures += ('agent claims shape invalid ' + $CountField + ': ' + $CountRaw)",
        "      return",
        "    }",
        "  }",
        "  $ClaimIds = @()",
        "  foreach ($Claim in @($ClaimsPayload.claims)) {",
        "    if (-not ($Claim.PSObject.Properties.Name -contains 'claim_id')) {",
        "      $script:PrelaunchFailures += 'agent claims shape claim without claim_id'",
        "      return",
        "    }",
        "    $ClaimId = [string]$Claim.claim_id",
        "    if (-not $ClaimId) {",
        "      $script:PrelaunchFailures += 'agent claims shape claim without claim_id'",
        "      return",
        "    }",
        "    $ClaimIds += $ClaimId",
        "  }",
        "  $DuplicateClaimIds = @($ClaimIds | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name } | Sort-Object)",
        "  if ($DuplicateClaimIds.Count -gt 0) {",
        "    $script:PrelaunchFailures += ('agent claims shape duplicate claim_id: ' + ($DuplicateClaimIds -join ','))",
        "    return",
        "  }",
        "  if ([int]$ClaimsPayload.claim_count -ne @($ClaimsPayload.claims).Count) {",
        "    $script:PrelaunchFailures += ('agent claims shape claim_count mismatch: count=' + [string]$ClaimsPayload.claim_count + ' claims=' + [string]@($ClaimsPayload.claims).Count)",
        "    return",
        "  }",
        "  $ReadyClaims = @($ClaimsPayload.claims | Where-Object { [string]$_.claim_state -eq 'ready_to_claim' })",
        "  if ([int]$ClaimsPayload.ready_to_claim_count -ne $ReadyClaims.Count) {",
        "    $script:PrelaunchFailures += ('agent claims shape ready_to_claim_count mismatch: count=' + [string]$ClaimsPayload.ready_to_claim_count + ' claims=' + [string]$ReadyClaims.Count)",
        "    return",
        "  }",
        "  $BlockedClaims = @($ClaimsPayload.claims | Where-Object { [string]$_.claim_state -like 'blocked_*' })",
        "  if ([int]$ClaimsPayload.blocked_claim_count -ne $BlockedClaims.Count) {",
        "    $script:PrelaunchFailures += ('agent claims shape blocked_claim_count mismatch: count=' + [string]$ClaimsPayload.blocked_claim_count + ' claims=' + [string]$BlockedClaims.Count)",
        "    return",
        "  }",
        "  $ManualClaims = @($ClaimsPayload.claims | Where-Object { [string]$_.claim_state -eq 'manual_claim_required' })",
        "  if ([int]$ClaimsPayload.manual_claim_count -ne $ManualClaims.Count) {",
        "    $script:PrelaunchFailures += ('agent claims shape manual_claim_count mismatch: count=' + [string]$ClaimsPayload.manual_claim_count + ' claims=' + [string]$ManualClaims.Count)",
        "    return",
        "  }",
        "  Write-Host ('[prelaunch] agent claims shape valid: claims=' + [string]@($ClaimsPayload.claims).Count)",
        "}",
        "function Invoke-ClaimStatusReportShapeValidation {",
        "  param([string]$Path)",
        "  Write-Host '[prelaunch] claim status report shape'",
        "  if (-not (Test-Path -LiteralPath $Path)) {",
        "    $script:PrelaunchFailures += ('claim status report shape missing ' + $Path)",
        "    return",
        "  }",
        "  try { $Report = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('claim status report shape invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  if (-not ($Report.PSObject.Properties.Name -contains 'schema_version')) {",
        "    $script:PrelaunchFailures += 'claim status report shape missing schema_version'",
        "    return",
        "  }",
        "  if (-not ($Report.PSObject.Properties.Name -contains 'artifact')) {",
        "    $script:PrelaunchFailures += 'claim status report shape missing artifact'",
        "    return",
        "  }",
        "  if ([int]$Report.schema_version -ne 1) {",
        "    $script:PrelaunchFailures += ('claim status report shape invalid schema_version: ' + [string]$Report.schema_version)",
        "    return",
        "  }",
        "  if ([string]$Report.artifact -ne 'validation-claim-status-report') {",
        "    $script:PrelaunchFailures += ('claim status report shape invalid artifact: ' + [string]$Report.artifact)",
        "    return",
        "  }",
        "  if (-not ($Report.PSObject.Properties.Name -contains 'claims')) {",
        "    $script:PrelaunchFailures += 'claim status report shape missing claims'",
        "    return",
        "  }",
        "  if ($Report.claims -isnot [System.Array]) {",
        "    $script:PrelaunchFailures += 'claim status report shape claims is not a list'",
        "    return",
        "  }",
        "  # Static audit markers for dynamic claim-status count fields:",
        "  # claim status report shape missing claim_count",
        "  # claim status report shape missing ready_to_claim_count",
        "  # claim status report shape missing blocked_claim_count",
        "  # claim status report shape missing manual_claim_count",
        "  # claim status report shape missing locked_claim_count",
        "  # claim status report shape missing invalid_lock_count",
        "  # claim status report shape invalid claim_count:",
        "  # claim status report shape invalid ready_to_claim_count:",
        "  # claim status report shape invalid blocked_claim_count:",
        "  # claim status report shape invalid manual_claim_count:",
        "  # claim status report shape invalid locked_claim_count:",
        "  # claim status report shape invalid invalid_lock_count:",
        "  foreach ($CountField in @('claim_count','ready_to_claim_count','blocked_claim_count','manual_claim_count','locked_claim_count','invalid_lock_count')) {",
        "    if (-not ($Report.PSObject.Properties.Name -contains $CountField)) {",
        "      $script:PrelaunchFailures += ('claim status report shape missing ' + $CountField)",
        "      return",
        "    }",
        "    $CountRaw = [string]$Report.PSObject.Properties[$CountField].Value",
        "    $Count = 0",
        "    if (-not [int]::TryParse($CountRaw, [ref]$Count) -or $Count -lt 0) {",
        "      $script:PrelaunchFailures += ('claim status report shape invalid ' + $CountField + ': ' + $CountRaw)",
        "      return",
        "    }",
        "  }",
        "  $ClaimIds = @()",
        "  foreach ($Claim in @($Report.claims)) {",
        "    if (-not ($Claim.PSObject.Properties.Name -contains 'claim_id')) {",
        "      $script:PrelaunchFailures += 'claim status report shape claim without claim_id'",
        "      return",
        "    }",
        "    $ClaimId = [string]$Claim.claim_id",
        "    if (-not $ClaimId) {",
        "      $script:PrelaunchFailures += 'claim status report shape claim without claim_id'",
        "      return",
        "    }",
        "    $ClaimIds += $ClaimId",
        "  }",
        "  $DuplicateClaimIds = @($ClaimIds | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name } | Sort-Object)",
        "  if ($DuplicateClaimIds.Count -gt 0) {",
        "    $script:PrelaunchFailures += ('claim status report shape duplicate claim_id: ' + ($DuplicateClaimIds -join ','))",
        "    return",
        "  }",
        "  if ([int]$Report.claim_count -ne @($Report.claims).Count) {",
        "    $script:PrelaunchFailures += ('claim status report shape claim_count mismatch: count=' + [string]$Report.claim_count + ' claims=' + [string]@($Report.claims).Count)",
        "    return",
        "  }",
        "  $ReadyClaims = @($Report.claims | Where-Object { [string]$_.claim_state -eq 'ready_to_claim' })",
        "  if ([int]$Report.ready_to_claim_count -ne $ReadyClaims.Count) {",
        "    $script:PrelaunchFailures += ('claim status report shape ready_to_claim_count mismatch: count=' + [string]$Report.ready_to_claim_count + ' claims=' + [string]$ReadyClaims.Count)",
        "    return",
        "  }",
        "  $BlockedClaims = @($Report.claims | Where-Object { [string]$_.claim_state -like 'blocked_*' })",
        "  if ([int]$Report.blocked_claim_count -ne $BlockedClaims.Count) {",
        "    $script:PrelaunchFailures += ('claim status report shape blocked_claim_count mismatch: count=' + [string]$Report.blocked_claim_count + ' claims=' + [string]$BlockedClaims.Count)",
        "    return",
        "  }",
        "  $ManualClaims = @($Report.claims | Where-Object { [string]$_.claim_state -eq 'manual_claim_required' })",
        "  if ([int]$Report.manual_claim_count -ne $ManualClaims.Count) {",
        "    $script:PrelaunchFailures += ('claim status report shape manual_claim_count mismatch: count=' + [string]$Report.manual_claim_count + ' claims=' + [string]$ManualClaims.Count)",
        "    return",
        "  }",
        "  $LockedClaims = @($Report.claims | Where-Object { [string]$_.lock_state -eq 'locked' })",
        "  if ([int]$Report.locked_claim_count -ne $LockedClaims.Count) {",
        "    $script:PrelaunchFailures += ('claim status report shape locked_claim_count mismatch: count=' + [string]$Report.locked_claim_count + ' claims=' + [string]$LockedClaims.Count)",
        "    return",
        "  }",
        "  $InvalidLockClaims = @($Report.claims | Where-Object { [string]$_.lock_state -eq 'invalid' })",
        "  if ([int]$Report.invalid_lock_count -ne $InvalidLockClaims.Count) {",
        "    $script:PrelaunchFailures += ('claim status report shape invalid_lock_count mismatch: count=' + [string]$Report.invalid_lock_count + ' claims=' + [string]$InvalidLockClaims.Count)",
        "    return",
        "  }",
        "  Write-Host ('[prelaunch] claim status report shape valid: claims=' + [string]@($Report.claims).Count)",
        "}",
        "function Invoke-EnvQueueShapeValidation {",
        "  param([string]$Path)",
        "  Write-Host '[prelaunch] env unblock queue shape'",
        "  if (-not (Test-Path -LiteralPath $Path)) {",
        "    $script:PrelaunchFailures += ('env unblock queue shape missing ' + $Path)",
        "    return",
        "  }",
        "  try { $Queue = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json } catch {",
        "    $script:PrelaunchFailures += ('env unblock queue shape invalid JSON: ' + [string]$_.Exception.Message)",
        "    return",
        "  }",
        "  if ($null -eq $Queue -or -not ($Queue.PSObject.Properties.Name -contains 'entries')) {",
        "    $script:PrelaunchFailures += 'env unblock queue shape missing entries'",
        "    return",
        "  }",
        "  if ($Queue.entries -isnot [System.Array]) {",
        "    $script:PrelaunchFailures += 'env unblock queue shape entries is not a list'",
        "    return",
        "  }",
        "  $Entries = @()",
        "  if ($null -ne $Queue.entries) { $Entries = @($Queue.entries) }",
        "  $RequiredEnv = @()",
        "  foreach ($Entry in $Entries) {",
        "    $EnvName = [string]$Entry.env",
        "    if (-not $EnvName) {",
        "      $script:PrelaunchFailures += 'env unblock queue shape entry without env'",
        "      return",
        "    }",
        "    $RequiredEnv += $EnvName",
        "  }",
        "  $DuplicateEnv = @($RequiredEnv | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })",
        "  if ($DuplicateEnv.Count -gt 0) {",
        "    $script:PrelaunchFailures += ('env unblock queue shape duplicate env entries: ' + (($DuplicateEnv | Sort-Object) -join ', '))",
        "  }",
        "  if ($Queue.PSObject.Properties.Name -contains 'env_count') {",
        "    $EnvCountRaw = [string]$Queue.env_count",
        "    $EnvCount = 0",
        "    if (-not [int]::TryParse($EnvCountRaw, [ref]$EnvCount) -or $EnvCount -lt 0) {",
        "      $script:PrelaunchFailures += ('env unblock queue shape invalid env_count: ' + $EnvCountRaw)",
        "      return",
        "    }",
        "    if ($EnvCount -ne $RequiredEnv.Count) {",
        "      $script:PrelaunchFailures += ('env unblock queue shape env_count mismatch: env_count=' + [string]$EnvCount + ' entries=' + [string]$RequiredEnv.Count)",
        "      return",
        "    }",
        "  }",
        "  if (-not ($Queue.PSObject.Properties.Name -contains 'required_env_names')) {",
        "    $script:PrelaunchFailures += 'env unblock queue shape missing required_env_names'",
        "    return",
        "  }",
        "  if ($Queue.required_env_names -isnot [System.Array]) {",
        "    $script:PrelaunchFailures += 'env unblock queue shape required_env_names is not a list'",
        "    return",
        "  }",
        "  $RequiredEnvNames = @()",
        "  foreach ($RequiredEnvName in @($Queue.required_env_names)) {",
        "    $RequiredEnvNameText = [string]$RequiredEnvName",
        "    if (-not $RequiredEnvNameText) {",
        "      $script:PrelaunchFailures += 'env unblock queue shape required_env_names contains empty value'",
        "      return",
        "    }",
        "    $RequiredEnvNames += $RequiredEnvNameText",
        "  }",
        "  $RequiredEnvNames = @($RequiredEnvNames | Sort-Object)",
        "  $EntryEnvNames = @($RequiredEnv | Sort-Object)",
        "  if (($RequiredEnvNames -join '|') -ne ($EntryEnvNames -join '|')) {",
        "    $script:PrelaunchFailures += ('env unblock queue shape required_env_names mismatch: required_env_names=' + ($RequiredEnvNames -join ',') + ' entries=' + ($EntryEnvNames -join ','))",
        "    return",
        "  }",
        "  if (-not ($Queue.PSObject.Properties.Name -contains 'all_env_powershell_set_commands')) {",
        "    $script:PrelaunchFailures += 'env unblock queue shape missing all_env_powershell_set_commands'",
        "    return",
        "  }",
        "  if ($Queue.all_env_powershell_set_commands -isnot [System.Array]) {",
        "    $script:PrelaunchFailures += 'env unblock queue shape all_env_powershell_set_commands is not a list'",
        "    return",
        "  }",
        "  $CommandEnvNames = @()",
        "  $CommandTexts = @()",
        "  foreach ($Command in @($Queue.all_env_powershell_set_commands)) {",
        "    $CommandText = [string]$Command",
        "    if (-not $CommandText) {",
        "      $script:PrelaunchFailures += 'env unblock queue shape all_env_powershell_set_commands contains empty value'",
        "      return",
        "    }",
        "    $CommandMatch = [regex]::Match($CommandText, '^\\$env:([A-Za-z_][A-Za-z0-9_]*)\\s*=')",
        "    if (-not $CommandMatch.Success) {",
        "      $script:PrelaunchFailures += ('env unblock queue shape invalid env set command: ' + $CommandText)",
        "      return",
        "    }",
        "    $CommandEnvNames += $CommandMatch.Groups[1].Value",
        "    $CommandTexts += $CommandText",
        "  }",
        "  $DuplicateCommandEnv = @($CommandEnvNames | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })",
        "  if ($DuplicateCommandEnv.Count -gt 0) {",
        "    $script:PrelaunchFailures += ('env unblock queue shape duplicate env set commands: ' + (($DuplicateCommandEnv | Sort-Object) -join ', '))",
        "    return",
        "  }",
        "  $CommandEnvNames = @($CommandEnvNames | Sort-Object)",
        "  $EntryEnvNames = @($RequiredEnv | Sort-Object)",
        "  if (($CommandEnvNames -join '|') -ne ($EntryEnvNames -join '|')) {",
        "    $script:PrelaunchFailures += ('env unblock queue shape env set commands mismatch: commands=' + ($CommandEnvNames -join ',') + ' entries=' + ($EntryEnvNames -join ','))",
        "    return",
        "  }",
        "  $EntryCommands = @()",
        "  foreach ($Entry in $Entries) {",
        "    if (-not ($Entry.PSObject.Properties.Name -contains 'powershell_set_command')) {",
        "      $script:PrelaunchFailures += 'env unblock queue shape entry missing powershell_set_command'",
        "      return",
        "    }",
        "    $EntryCommand = [string]$Entry.powershell_set_command",
        "    if (-not $EntryCommand) {",
        "      $script:PrelaunchFailures += 'env unblock queue shape entry missing powershell_set_command'",
        "      return",
        "    }",
        "    foreach ($NextActionField in @('direct_next_action_summaries','indirect_next_action_summaries')) {",
        "      if (-not ($Entry.PSObject.Properties.Name -contains $NextActionField)) {",
        "        $script:PrelaunchFailures += ('env unblock queue shape entry missing ' + $NextActionField + ': ' + [string]$Entry.env)",
        "        return",
        "      }",
        "      if ($Entry.PSObject.Properties[$NextActionField].Value -isnot [System.Array]) {",
        "        $script:PrelaunchFailures += ('env unblock queue shape entry ' + $NextActionField + ' is not a list: ' + [string]$Entry.env)",
        "        return",
        "      }",
        "      if (@($Entry.PSObject.Properties[$NextActionField].Value | ForEach-Object { [string]$_ } | Where-Object { -not $_ }).Count -gt 0) {",
        "        $script:PrelaunchFailures += ('env unblock queue shape ' + $NextActionField + ' contains empty value: ' + [string]$Entry.env)",
        "        return",
        "      }",
        "    }",
        "    $EntryCommands += $EntryCommand",
        "  }",
        "  $SortedCommandTexts = @($CommandTexts | Sort-Object)",
        "  $SortedEntryCommands = @($EntryCommands | Sort-Object)",
        "  if (($SortedCommandTexts -join '|') -ne ($SortedEntryCommands -join '|')) {",
        "    $script:PrelaunchFailures += 'env unblock queue shape env set command text mismatch'",
        "    return",
        "  }",
        "  # Static audit markers for dynamic current-env shape failures:",
        "  # env unblock queue shape missing current_env_present_names",
        "  # env unblock queue shape current_env_present_names is not a list",
        "  # env unblock queue shape missing current_env_missing_names",
        "  # env unblock queue shape current_env_missing_names is not a list",
        "  # env unblock queue shape missing current_env_placeholder_names",
        "  # env unblock queue shape current_env_placeholder_names is not a list",
        "  # env unblock queue shape missing current_env_present_count",
        "  # env unblock queue shape missing current_env_missing_count",
        "  # env unblock queue shape missing current_env_placeholder_count",
        "  # env unblock queue shape invalid current_env_present_count:",
        "  # env unblock queue shape invalid current_env_missing_count:",
        "  # env unblock queue shape invalid current_env_placeholder_count:",
        "  # env unblock queue shape current_env_present_count mismatch:",
        "  # env unblock queue shape current_env_missing_count mismatch:",
        "  # env unblock queue shape current_env_placeholder_count mismatch:",
        "  # env unblock queue shape missing ready_with_current_env_claim_ids",
        "  # env unblock queue shape ready_with_current_env_claim_ids is not a list",
        "  # env unblock queue shape missing still_blocked_with_current_env_claim_ids",
        "  # env unblock queue shape still_blocked_with_current_env_claim_ids is not a list",
        "  # env unblock queue shape missing ready_after_all_env_claim_ids",
        "  # env unblock queue shape ready_after_all_env_claim_ids is not a list",
        "  # env unblock queue shape missing still_blocked_after_all_env_claim_ids",
        "  # env unblock queue shape still_blocked_after_all_env_claim_ids is not a list",
        "  # env unblock queue shape claim readiness ids contain empty value",
        "  # env unblock queue shape duplicate claim readiness ids in",
        "  # env unblock queue shape current claim readiness overlap:",
        "  # env unblock queue shape after-all claim readiness overlap:",
        "  # env unblock queue shape entry missing direct_next_action_summaries",
        "  # env unblock queue shape entry direct_next_action_summaries is not a list",
        "  # env unblock queue shape direct_next_action_summaries contains empty value",
        "  # env unblock queue shape entry missing indirect_next_action_summaries",
        "  # env unblock queue shape entry indirect_next_action_summaries is not a list",
        "  # env unblock queue shape indirect_next_action_summaries contains empty value",
        "  # env unblock queue shape missing blocked_claim_count",
        "  # env unblock queue shape invalid blocked_claim_count:",
        "  # env unblock queue shape blocked_claim_count below referenced claims:",
        "  foreach ($CurrentEnvField in @('current_env_present_names','current_env_missing_names','current_env_placeholder_names')) {",
        "    if (-not ($Queue.PSObject.Properties.Name -contains $CurrentEnvField)) {",
        "      $script:PrelaunchFailures += ('env unblock queue shape missing ' + $CurrentEnvField)",
        "      return",
        "    }",
        "    if ($Queue.PSObject.Properties[$CurrentEnvField].Value -isnot [System.Array]) {",
        "      $script:PrelaunchFailures += ('env unblock queue shape ' + $CurrentEnvField + ' is not a list')",
        "      return",
        "    }",
        "  }",
        "  foreach ($CurrentEnvCountField in @('current_env_present_count','current_env_missing_count','current_env_placeholder_count')) {",
        "    if (-not ($Queue.PSObject.Properties.Name -contains $CurrentEnvCountField)) {",
        "      $script:PrelaunchFailures += ('env unblock queue shape missing ' + $CurrentEnvCountField)",
        "      return",
        "    }",
        "  }",
        "  $CurrentEnvPresentNames = @($Queue.current_env_present_names | ForEach-Object { [string]$_ } | Sort-Object)",
        "  $CurrentEnvMissingNames = @($Queue.current_env_missing_names | ForEach-Object { [string]$_ } | Sort-Object)",
        "  $CurrentEnvPlaceholderNames = @($Queue.current_env_placeholder_names | ForEach-Object { [string]$_ } | Sort-Object)",
        "  if ((@($CurrentEnvPresentNames | Where-Object { -not $_ }).Count -gt 0) -or (@($CurrentEnvMissingNames | Where-Object { -not $_ }).Count -gt 0) -or (@($CurrentEnvPlaceholderNames | Where-Object { -not $_ }).Count -gt 0)) {",
        "    $script:PrelaunchFailures += 'env unblock queue shape current env names contain empty value'",
        "    return",
        "  }",
        "  $CurrentEnvOverlaps = @()",
        "  $CurrentEnvOverlaps += @($CurrentEnvPresentNames | Where-Object { $CurrentEnvMissingNames -contains $_ })",
        "  $CurrentEnvOverlaps += @($CurrentEnvPresentNames | Where-Object { $CurrentEnvPlaceholderNames -contains $_ })",
        "  $CurrentEnvOverlaps += @($CurrentEnvMissingNames | Where-Object { $CurrentEnvPlaceholderNames -contains $_ })",
        "  $CurrentEnvOverlaps = @($CurrentEnvOverlaps | Sort-Object -Unique)",
        "  if ($CurrentEnvOverlaps.Count -gt 0) {",
        "    $script:PrelaunchFailures += ('env unblock queue shape current env state overlap: ' + ($CurrentEnvOverlaps -join ','))",
        "    return",
        "  }",
        "  $CurrentEnvUnionNames = @(($CurrentEnvPresentNames + $CurrentEnvMissingNames + $CurrentEnvPlaceholderNames) | Sort-Object -Unique)",
        "  if (($CurrentEnvUnionNames -join '|') -ne ($EntryEnvNames -join '|')) {",
        "    $script:PrelaunchFailures += ('env unblock queue shape current env state mismatch: current=' + ($CurrentEnvUnionNames -join ',') + ' entries=' + ($EntryEnvNames -join ','))",
        "    return",
        "  }",
        "  $CurrentEnvExpectedCounts = @{",
        "    current_env_present_count = $CurrentEnvPresentNames.Count",
        "    current_env_missing_count = $CurrentEnvMissingNames.Count",
        "    current_env_placeholder_count = $CurrentEnvPlaceholderNames.Count",
        "  }",
        "  foreach ($CurrentEnvCountField in @('current_env_present_count','current_env_missing_count','current_env_placeholder_count')) {",
        "    $CurrentEnvCountRaw = [string]$Queue.PSObject.Properties[$CurrentEnvCountField].Value",
        "    $CurrentEnvCount = 0",
        "    if (-not [int]::TryParse($CurrentEnvCountRaw, [ref]$CurrentEnvCount) -or $CurrentEnvCount -lt 0) {",
        "      $script:PrelaunchFailures += ('env unblock queue shape invalid ' + $CurrentEnvCountField + ': ' + $CurrentEnvCountRaw)",
        "      return",
        "    }",
        "    if ($CurrentEnvCount -ne $CurrentEnvExpectedCounts[$CurrentEnvCountField]) {",
        "      $script:PrelaunchFailures += ('env unblock queue shape ' + $CurrentEnvCountField + ' mismatch: count=' + [string]$CurrentEnvCount + ' names=' + [string]$CurrentEnvExpectedCounts[$CurrentEnvCountField])",
        "      return",
        "    }",
        "  }",
        "  $ClaimReadinessByField = @{}",
        "  foreach ($ClaimReadinessField in @('ready_with_current_env_claim_ids','still_blocked_with_current_env_claim_ids','ready_after_all_env_claim_ids','still_blocked_after_all_env_claim_ids')) {",
        "    if (-not ($Queue.PSObject.Properties.Name -contains $ClaimReadinessField)) {",
        "      $script:PrelaunchFailures += ('env unblock queue shape missing ' + $ClaimReadinessField)",
        "      return",
        "    }",
        "    if ($Queue.PSObject.Properties[$ClaimReadinessField].Value -isnot [System.Array]) {",
        "      $script:PrelaunchFailures += ('env unblock queue shape ' + $ClaimReadinessField + ' is not a list')",
        "      return",
        "    }",
        "    $ClaimIds = @($Queue.PSObject.Properties[$ClaimReadinessField].Value | ForEach-Object { [string]$_ } | Sort-Object)",
        "    if (@($ClaimIds | Where-Object { -not $_ }).Count -gt 0) {",
        "      $script:PrelaunchFailures += 'env unblock queue shape claim readiness ids contain empty value'",
        "      return",
        "    }",
        "    $DuplicateClaimIds = @($ClaimIds | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name } | Sort-Object)",
        "    if ($DuplicateClaimIds.Count -gt 0) {",
        "      $script:PrelaunchFailures += ('env unblock queue shape duplicate claim readiness ids in ' + $ClaimReadinessField + ': ' + ($DuplicateClaimIds -join ','))",
        "      return",
        "    }",
        "    $ClaimReadinessByField[$ClaimReadinessField] = $ClaimIds",
        "  }",
        "  $CurrentClaimReadinessOverlap = @($ClaimReadinessByField['ready_with_current_env_claim_ids'] | Where-Object { $ClaimReadinessByField['still_blocked_with_current_env_claim_ids'] -contains $_ } | Sort-Object -Unique)",
        "  if ($CurrentClaimReadinessOverlap.Count -gt 0) {",
        "    $script:PrelaunchFailures += ('env unblock queue shape current claim readiness overlap: ' + ($CurrentClaimReadinessOverlap -join ','))",
        "    return",
        "  }",
        "  $AfterAllClaimReadinessOverlap = @($ClaimReadinessByField['ready_after_all_env_claim_ids'] | Where-Object { $ClaimReadinessByField['still_blocked_after_all_env_claim_ids'] -contains $_ } | Sort-Object -Unique)",
        "  if ($AfterAllClaimReadinessOverlap.Count -gt 0) {",
        "    $script:PrelaunchFailures += ('env unblock queue shape after-all claim readiness overlap: ' + ($AfterAllClaimReadinessOverlap -join ','))",
        "    return",
        "  }",
        "  if (-not ($Queue.PSObject.Properties.Name -contains 'blocked_claim_count')) {",
        "    $script:PrelaunchFailures += 'env unblock queue shape missing blocked_claim_count'",
        "    return",
        "  }",
        "  $BlockedClaimCountRaw = [string]$Queue.blocked_claim_count",
        "  $BlockedClaimCount = 0",
        "  if (-not [int]::TryParse($BlockedClaimCountRaw, [ref]$BlockedClaimCount) -or $BlockedClaimCount -lt 0) {",
        "    $script:PrelaunchFailures += ('env unblock queue shape invalid blocked_claim_count: ' + $BlockedClaimCountRaw)",
        "    return",
        "  }",
        "  $ReferencedClaimIds = @()",
        "  foreach ($Entry in $Entries) {",
        "    if ($Entry.PSObject.Properties.Name -contains 'claim_ids') {",
        "      foreach ($ClaimId in @($Entry.claim_ids)) {",
        "        $ClaimIdText = [string]$ClaimId",
        "        if ($ClaimIdText) { $ReferencedClaimIds += $ClaimIdText }",
        "      }",
        "    }",
        "  }",
        "  foreach ($ClaimReadinessField in @('ready_with_current_env_claim_ids','still_blocked_with_current_env_claim_ids','ready_after_all_env_claim_ids','still_blocked_after_all_env_claim_ids')) {",
        "    $ReferencedClaimIds += @($ClaimReadinessByField[$ClaimReadinessField])",
        "  }",
        "  $ReferencedClaimIds = @($ReferencedClaimIds | Sort-Object -Unique)",
        "  if ($BlockedClaimCount -lt $ReferencedClaimIds.Count) {",
        "    $script:PrelaunchFailures += ('env unblock queue shape blocked_claim_count below referenced claims: count=' + [string]$BlockedClaimCount + ' referenced=' + [string]$ReferencedClaimIds.Count)",
        "    return",
        "  }",
        "  Write-Host ('[prelaunch] env unblock queue shape valid: entries=' + [string]$RequiredEnv.Count)",
        "}",
    ]
    if dispatch_manifest_path:
        lines.append(f"Invoke-DispatchManifestShapeValidation {ps_single_quoted(stable_path(dispatch_manifest_path))}")
        lines.append(
            f"Invoke-DispatchRunnerManifestAlignmentValidation {ps_single_quoted(stable_path(dispatch_manifest_path))}"
        )
    if owner_launch_plan_json_path:
        lines.append(
            f"Invoke-OwnerLaunchPlanShapeValidation {ps_single_quoted(stable_path(owner_launch_plan_json_path))}"
        )
    if execution_matrix_json_path:
        lines.append(
            f"Invoke-ExecutionMatrixShapeValidation {ps_single_quoted(stable_path(execution_matrix_json_path))}"
        )
    if dispatch_manifest_path and owner_launch_plan_json_path and execution_matrix_json_path:
        lines.append(
            "Invoke-DispatchManifestPlanAlignmentValidation "
            f"{ps_single_quoted(stable_path(dispatch_manifest_path))} "
            f"{ps_single_quoted(stable_path(owner_launch_plan_json_path))} "
            f"{ps_single_quoted(stable_path(execution_matrix_json_path))}"
        )
    if owner_launch_plan_json_path and execution_matrix_json_path:
        lines.append(
            "Invoke-OwnerPlanExecutionMatrixAlignmentValidation "
            f"{ps_single_quoted(stable_path(owner_launch_plan_json_path))} "
            f"{ps_single_quoted(stable_path(execution_matrix_json_path))}"
        )
    if env_unblock_queue_json_path:
        lines.append(f"Invoke-EnvQueueShapeValidation {ps_single_quoted(stable_path(env_unblock_queue_json_path))}")
    if agent_spawn_plan_json_path:
        lines.append(f"Invoke-AgentSpawnPlanShapeValidation {ps_single_quoted(stable_path(agent_spawn_plan_json_path))}")
    if agent_claims_json_path:
        lines.append(f"Invoke-AgentClaimsShapeValidation {ps_single_quoted(stable_path(agent_claims_json_path))}")
    if claim_lock_helper_path and agent_claims_json_path:
        lines.append(
            "Invoke-ClaimLockHelperAgentClaimsAlignmentValidation "
            f"{ps_single_quoted(stable_path(claim_lock_helper_path))} "
            f"{ps_single_quoted(stable_path(agent_claims_json_path))}"
        )
    if env_unblock_queue_json_path and agent_claims_json_path:
        lines.append(
            "Invoke-EnvQueueAgentClaimsAlignmentValidation "
            f"{ps_single_quoted(stable_path(env_unblock_queue_json_path))} "
            f"{ps_single_quoted(stable_path(agent_claims_json_path))}"
        )
    if agent_claims_json_path and agent_spawn_plan_json_path:
        lines.append(
            "Invoke-AgentClaimsSpawnPlanAlignmentValidation "
            f"{ps_single_quoted(stable_path(agent_claims_json_path))} "
            f"{ps_single_quoted(stable_path(agent_spawn_plan_json_path))}"
        )
    if (
        agent_claims_json_path
        and ready_claims_launcher_path
        and ready_claims_parallel_launcher_path
        and env_bundle_ready_claims_launcher_path
    ):
        lines.append(
            "Invoke-ReadyLaunchersAgentClaimsAlignmentValidation "
            f"{ps_single_quoted(stable_path(agent_claims_json_path))} "
            f"{ps_single_quoted(stable_path(ready_claims_launcher_path))} "
            f"{ps_single_quoted(stable_path(ready_claims_parallel_launcher_path))} "
            f"{ps_single_quoted(stable_path(env_bundle_ready_claims_launcher_path))}"
        )
    if dispatch_manifest_path and agent_claims_json_path:
        lines.append(
            "Invoke-DispatchManifestAgentClaimsAlignmentValidation "
            f"{ps_single_quoted(stable_path(dispatch_manifest_path))} "
            f"{ps_single_quoted(stable_path(agent_claims_json_path))}"
        )
    if claim_status_report_json_path:
        lines.append(
            f"Invoke-ClaimStatusReportShapeValidation {ps_single_quoted(stable_path(claim_status_report_json_path))}"
        )
    if agent_claims_json_path and claim_status_report_json_path:
        lines.append(
            "Invoke-AgentClaimsStatusReportAlignmentValidation "
            f"{ps_single_quoted(stable_path(agent_claims_json_path))} "
            f"{ps_single_quoted(stable_path(claim_status_report_json_path))}"
        )
    if agent_spawn_launcher_path:
        lines.extend(
            [
                "Invoke-PrelaunchStep 'agent spawn dry run' @(",
                f"  'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', {ps_single_quoted(stable_path(agent_spawn_launcher_path))},",
                "  '-Provider', 'all', '-Phase', 'all', '-ShowBlocked'",
                ")",
                "Invoke-PrelaunchStep 'agent spawn balanced dry run' @(",
                f"  'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', {ps_single_quoted(stable_path(agent_spawn_launcher_path))},",
                "  '-Provider', 'balanced', '-Phase', 'all', '-ShowBlocked'",
                ")",
            ]
        )
    if ready_claims_launcher_path:
        lines.extend(
            [
                "Invoke-PrelaunchStep 'ready claims sequential validate-only' @(",
                f"  'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', {ps_single_quoted(stable_path(ready_claims_launcher_path))},",
                "  '-ValidateOnly'",
                ")",
            ]
        )
    if ready_claims_parallel_launcher_path:
        lines.extend(
            [
                "Invoke-PrelaunchStep 'ready claims parallel validate-only' @(",
                f"  'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', {ps_single_quoted(stable_path(ready_claims_parallel_launcher_path))},",
                "  '-ValidateOnly'",
                ")",
            ]
        )
    if claim_lock_helper_path:
        lines.append(f"Invoke-ClaimLockEmptyValidation {ps_single_quoted(stable_path(claim_lock_helper_path))}")
        lines.extend(
            [
                "Invoke-PrelaunchStep 'claim lock list' @(",
                f"  'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', {ps_single_quoted(stable_path(claim_lock_helper_path))},",
                "  '-List'",
                ")",
            ]
        )
    if env_bundle_ready_claims_launcher_path:
        lines.extend(
            [
                "if ($ValidateEnvBundle) {",
                "  Invoke-PrelaunchStep 'env bundle validate-only' @(",
                f"    'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', {ps_single_quoted(stable_path(env_bundle_ready_claims_launcher_path))},",
                "    '-ValidateOnly'",
                "  )",
                "} else {",
                "  Write-Host '[prelaunch] env bundle validate-only skipped; pass -ValidateEnvBundle after filling env_unblock_queue values'",
                "}",
            ]
        )
    lines.extend(
        [
            "if ($PrelaunchFailures.Count -gt 0) {",
            "  Write-Error ('Dispatch prelaunch validation failed: ' + ($PrelaunchFailures -join ', '))",
            "  exit 1",
            "}",
            "Write-Host 'Dispatch prelaunch validation passed.'",
            "exit 0",
            "",
        ]
    )
    return "\n".join(lines)


def write_dispatch_prelaunch_validation(
    output_dir: Path,
    agent_spawn_launcher_path: Path | None = None,
    ready_claims_launcher_path: Path | None = None,
    ready_claims_parallel_launcher_path: Path | None = None,
    env_bundle_ready_claims_launcher_path: Path | None = None,
    claim_lock_helper_path: Path | None = None,
    env_unblock_queue_json_path: Path | None = None,
    agent_spawn_plan_json_path: Path | None = None,
    agent_claims_json_path: Path | None = None,
    claim_status_report_json_path: Path | None = None,
    dispatch_manifest_path: Path | None = None,
    owner_launch_plan_json_path: Path | None = None,
    execution_matrix_json_path: Path | None = None,
) -> Path:
    validation_path = output_dir / "dispatch_prelaunch_validation.ps1"
    validation_path.write_text(
        render_dispatch_prelaunch_validation(
            agent_spawn_launcher_path,
            ready_claims_launcher_path,
            ready_claims_parallel_launcher_path,
            env_bundle_ready_claims_launcher_path,
            claim_lock_helper_path,
            env_unblock_queue_json_path,
            agent_spawn_plan_json_path,
            agent_claims_json_path,
            claim_status_report_json_path,
            dispatch_manifest_path,
            owner_launch_plan_json_path,
            execution_matrix_json_path,
        ),
        encoding="utf-8",
    )
    return validation_path


def render_dispatch_brief(
    packages: list[dict],
    preflight_path: Path,
    script_paths: dict[str, Path],
    prompt_paths: dict[str, Path] | None = None,
    launcher_paths: list[Path] | None = None,
    staged_launcher_paths: list[Path] | None = None,
    roster_path: Path | None = None,
    env_checklist_path: Path | None = None,
    env_template_path: Path | None = None,
    owner_launch_plan_path: Path | None = None,
    owner_launch_plan_json_path: Path | None = None,
    execution_matrix_path: Path | None = None,
    execution_matrix_json_path: Path | None = None,
    agent_claims_path: Path | None = None,
    agent_claims_json_path: Path | None = None,
    agent_spawn_plan_path: Path | None = None,
    agent_spawn_plan_json_path: Path | None = None,
    agent_spawn_launcher_path: Path | None = None,
    claim_status_report_path: Path | None = None,
    claim_status_report_json_path: Path | None = None,
    claim_lock_helper_path: Path | None = None,
    env_unblock_queue_path: Path | None = None,
    env_unblock_queue_json_path: Path | None = None,
    ready_claims_launcher_path: Path | None = None,
    ready_claims_parallel_launcher_path: Path | None = None,
    env_bundle_ready_claims_launcher_path: Path | None = None,
    dispatch_prelaunch_validation_path: Path | None = None,
    manifest_path: Path | None = None,
    dispatch_runner_path: Path | None = None,
) -> str:
    prompt_paths = prompt_paths or {}
    launcher_paths = launcher_paths or []
    staged_launcher_paths = staged_launcher_paths or []
    launched, skipped = launcher_membership(packages)
    staged = staged_launcher_membership(packages)
    spawn_plan: dict[str, object] = {}
    if agent_spawn_plan_json_path and agent_spawn_plan_json_path.exists():
        try:
            spawn_plan = json.loads(agent_spawn_plan_json_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            spawn_plan = {}
    current_env_multi_agent_actionable = bool(spawn_plan.get("current_env_multi_agent_actionable"))
    post_env_bundle_multi_agent_actionable = bool(spawn_plan.get("post_env_bundle_multi_agent_actionable"))
    launcher_by_wave: dict[int, Path] = {}
    for path in launcher_paths:
        parts = path.name.split("-")
        if len(parts) >= 3 and parts[0] == "wave":
            try:
                launcher_by_wave[int(parts[1])] = path
            except ValueError:
                continue
    staged_launcher_by_wave: dict[int, Path] = {}
    for path in staged_launcher_paths:
        parts = path.name.split("-")
        if len(parts) >= 3 and parts[0] == "wave":
            try:
                staged_launcher_by_wave[int(parts[1])] = path
            except ValueError:
                continue

    lines = [
        "# Validation Dispatch Brief",
        "",
        "Use this brief to fan out validation work to separate agents while preserving wave dependencies and resource ownership.",
        "",
        f"Source preflight: `{stable_path(preflight_path)}`",
    ]
    if manifest_path:
        lines.append(f"Dispatch manifest: `{stable_path(manifest_path)}`")
    if roster_path:
        lines.append(f"Agent roster: `{stable_path(roster_path)}`")
    if env_checklist_path:
        lines.append(f"Env checklist: `{stable_path(env_checklist_path)}`")
    if env_template_path:
        lines.append(f"Env template: `{stable_path(env_template_path)}`")
    if owner_launch_plan_path:
        lines.append(f"Owner launch plan: `{stable_path(owner_launch_plan_path)}`")
    if owner_launch_plan_json_path:
        lines.append(f"Owner launch plan JSON: `{stable_path(owner_launch_plan_json_path)}`")
    if execution_matrix_path:
        lines.append(f"Execution matrix: `{stable_path(execution_matrix_path)}`")
    if execution_matrix_json_path:
        lines.append(f"Execution matrix JSON: `{stable_path(execution_matrix_json_path)}`")
    if agent_claims_path:
        lines.append(f"Agent claims: `{stable_path(agent_claims_path)}`")
    if agent_claims_json_path:
        lines.append(f"Agent claims JSON: `{stable_path(agent_claims_json_path)}`")
    if agent_spawn_plan_path:
        lines.append(f"Agent spawn plan: `{stable_path(agent_spawn_plan_path)}`")
    if agent_spawn_plan_json_path:
        lines.append(f"Agent spawn plan JSON: `{stable_path(agent_spawn_plan_json_path)}`")
    if agent_spawn_launcher_path:
        lines.append(f"Agent spawn launcher: `{stable_path(agent_spawn_launcher_path)}`")
        launcher_ref = stable_path(agent_spawn_launcher_path)
        lines.append(
            "Agent spawn launcher command: "
            f"`powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider codex -Phase ready`"
        )
        lines.append(
            "Agent spawn launcher dry-run all command: "
            f"`powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider all -Phase all -ShowBlocked`"
        )
        if current_env_multi_agent_actionable:
            lines.append(
                "Agent spawn launcher balanced parallel execute command: "
                f"`$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider balanced -Phase ready -Execute -Parallel`"
            )
            lines.append(
                "Agent spawn launcher Codex parallel execute command: "
                f"`$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider codex -Phase ready -Execute -Parallel`"
            )
            lines.append(
                "Agent spawn launcher Claude parallel execute command: "
                f"`$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider claude -Phase ready -Execute -Parallel`"
            )
        else:
            lines.append(
                "Agent spawn launcher current-env parallel status: "
                "`current_env_multi_agent_actionable=false`; ready-phase fan-out is not actionable until at least two current-env claims are ready."
            )
        lines.append(
            "Agent spawn launcher Codex env-bundle execute command: "
            f"`$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; $env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'; powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider codex -Phase env-bundle -Execute -Parallel`"
        )
        lines.append(
            "Agent spawn launcher Claude env-bundle execute command: "
            f"`$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; $env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'; powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider claude -Phase env-bundle -Execute -Parallel`"
        )
        if post_env_bundle_multi_agent_actionable:
            lines.append(
                "Agent spawn launcher preferred env-bundle balanced execute command: "
                f"`$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; $env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'; powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider balanced -Phase env-bundle -Execute -Parallel`"
            )
        lines.append(
            "Agent spawn env-bundle guard: "
            "`-Phase env-bundle -Execute` refuses missing, placeholder, or malformed `env_unblock_queue.json` values before printing spawn commands."
        )
        lines.append(
            "Agent spawn duplicate-provider override guard: "
            "`-AllowDuplicateProviderPerClaim` also requires `TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM=1` and emits `[duplicate-provider-override]`."
        )
    if claim_status_report_path:
        lines.append(f"Claim status report: `{stable_path(claim_status_report_path)}`")
    if claim_status_report_json_path:
        lines.append(f"Claim status report JSON: `{stable_path(claim_status_report_json_path)}`")
    if manifest_path and claim_status_report_path and claim_status_report_json_path:
        manifest_ref = stable_path(manifest_path)
        lines.append(
            f"Claim status refresh command: `python tools/detection_validation/run_preflight_work_package.py --refresh-claim-status-report '{manifest_ref}'`"
        )
    if claim_lock_helper_path:
        lock_helper_ref = stable_path(claim_lock_helper_path)
        lines.append(f"Claim lock helper: `{lock_helper_ref}`")
        lines.append(
            f"Claim lock command: `powershell -NoProfile -ExecutionPolicy Bypass -File '{lock_helper_ref}' -ClaimId <claim-id> -AgentId <agent-id>`"
        )
        lines.append(
            f"Claim lock list command: `powershell -NoProfile -ExecutionPolicy Bypass -File '{lock_helper_ref}' -List`"
        )
        lines.append(
            f"Claim lock reset command: `powershell -NoProfile -ExecutionPolicy Bypass -File '{lock_helper_ref}' -ResetClaimId <claim-id> -Force`"
        )
    if env_unblock_queue_path:
        lines.append(f"Env unblock queue: `{stable_path(env_unblock_queue_path)}`")
        lines.append(
            "Env unblock queue handoff: includes copy/paste `Direct claim next actions:`, "
            "`Other affected claim next actions:`, and compatibility `Affected claim next actions:` context per env."
        )
    if env_unblock_queue_json_path:
        lines.append(f"Env unblock queue JSON: `{stable_path(env_unblock_queue_json_path)}`")
    if ready_claims_launcher_path:
        launcher_ref = stable_path(ready_claims_launcher_path)
        lines.append(f"Ready claims launcher: `{launcher_ref}`")
        lines.append(
            f"Ready claims sequential validation command: `powershell -NoProfile -ExecutionPolicy Bypass -File '{launcher_ref}' -ValidateOnly`"
        )
        lines.append(f"Ready claims command: `powershell -NoProfile -ExecutionPolicy Bypass -File '{launcher_ref}'`")
        lines.append("Ready claims guard: `TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH=1`")
    if ready_claims_parallel_launcher_path:
        parallel_launcher_ref = stable_path(ready_claims_parallel_launcher_path)
        lines.append(f"Ready claims parallel launcher: `{parallel_launcher_ref}`")
        lines.append(
            f"Ready claims validation command: `powershell -NoProfile -ExecutionPolicy Bypass -File '{parallel_launcher_ref}' -ValidateOnly`"
        )
        lines.append(
            f"Ready claims parallel command: `powershell -NoProfile -ExecutionPolicy Bypass -File '{parallel_launcher_ref}'`"
        )
        lines.append("Ready claims parallel guard: `TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH=1`")
    if env_bundle_ready_claims_launcher_path:
        env_bundle_launcher_ref = stable_path(env_bundle_ready_claims_launcher_path)
        lines.append(f"Env-bundle ready claims launcher: `{env_bundle_launcher_ref}`")
        lines.append(
            f"Env-bundle validation command: `powershell -NoProfile -ExecutionPolicy Bypass -File '{env_bundle_launcher_ref}' -ValidateOnly`"
        )
        lines.append(
            f"Env-bundle ready claims command: `powershell -NoProfile -ExecutionPolicy Bypass -File '{env_bundle_launcher_ref}'`"
        )
        lines.append("Env-bundle ready claims guard: `TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH=1`")
    if dispatch_prelaunch_validation_path:
        prelaunch_ref = stable_path(dispatch_prelaunch_validation_path)
        lines.append(f"Dispatch prelaunch validation: `{prelaunch_ref}`")
        lines.append(
            f"Dispatch prelaunch validation command: `powershell -NoProfile -ExecutionPolicy Bypass -File '{prelaunch_ref}'`"
        )
        lines.append(
            f"Dispatch prelaunch env-bundle validation command: `powershell -NoProfile -ExecutionPolicy Bypass -File '{prelaunch_ref}' -ValidateEnvBundle`"
        )
    if dispatch_runner_path:
        runner_ref = stable_path(dispatch_runner_path)
        lines.append(f"One-shot runner: `{runner_ref}`")
        lines.append(f"One-shot command: `powershell -NoProfile -ExecutionPolicy Bypass -File '{runner_ref}'`")
    lines.append("")
    launch_sequence: list[str] = []
    step = 1
    if agent_spawn_launcher_path:
        launcher_ref = stable_path(agent_spawn_launcher_path)
        if dispatch_prelaunch_validation_path:
            prelaunch_ref = stable_path(dispatch_prelaunch_validation_path)
            launch_sequence.extend(
                [
                    f"{step}. Dispatch prelaunch validation: "
                    f"`powershell -NoProfile -ExecutionPolicy Bypass -File '{prelaunch_ref}'`",
                    "   This runs no-execution checks for env queue shape, spawn dry-run, ready launchers, and claim-lock listing.",
                    "   Wrapped agent spawn dry run: "
                    f"`powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider all -Phase all -ShowBlocked`",
                    "   This prints Codex/Claude spawn commands and blocked-claim context; it does not execute package scripts.",
                ]
            )
        else:
            launch_sequence.extend(
                [
                    f"{step}. Agent spawn dry run: "
                    f"`powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider all -Phase all -ShowBlocked`",
                    "   This prints Codex/Claude spawn commands and blocked-claim context; it does not execute package scripts.",
                ]
            )
        if current_env_multi_agent_actionable:
            launch_sequence.extend(
                [
                    f"{step}a. Optional Codex current-env agent execution: "
                    "`$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; "
                    f"powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider codex -Phase ready -Execute -Parallel`",
                    f"{step}b. Optional Claude current-env agent execution: "
                    "`$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; "
                    f"powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider claude -Phase ready -Execute -Parallel`",
                    f"{step}c. Preferred balanced Codex/Claude current-env agent execution: "
                    "`$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; "
                    f"powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider balanced -Phase ready -Execute -Parallel`",
                ]
            )
        else:
            launch_sequence.append(
                f"{step}a. Current-env agent execution is not multi-agent actionable: "
                "`current_env_multi_agent_actionable=false`; use env-bundle fan-out after the complete bundle validates."
            )
        if dispatch_prelaunch_validation_path:
            launch_sequence.append(
                f"{step}b. Optional env-bundle prelaunch validation after env fill: "
                f"`powershell -NoProfile -ExecutionPolicy Bypass -File '{stable_path(dispatch_prelaunch_validation_path)}' -ValidateEnvBundle`"
            )
        launch_sequence.extend(
            [
                f"{step}c. Optional Codex env-bundle agent execution after complete env fill: "
                "`$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; $env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'; "
                f"powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider codex -Phase env-bundle -Execute -Parallel`",
                f"{step}d. Optional Claude env-bundle agent execution after complete env fill: "
                "`$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; $env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'; "
                f"powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider claude -Phase env-bundle -Execute -Parallel`",
                f"{step}e. Preferred balanced Codex/Claude env-bundle agent execution after complete env fill: "
                "`$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; $env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'; "
                f"powershell -NoProfile -ExecutionPolicy Bypass -File {ps_single_quoted(launcher_ref)} -Provider balanced -Phase env-bundle -Execute -Parallel`",
            ]
        )
        launch_sequence.extend(
            [
                "   Use one provider per claim; this acquires claim locks inline before spawning agents.",
                "   Env-bundle agent execution refuses missing, placeholder, or malformed `env_unblock_queue.json` values before printing spawn commands.",
                "   Duplicate-provider execution requires both `-AllowDuplicateProviderPerClaim` and `TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM=1`; override launches emit `[duplicate-provider-override]`.",
            ]
        )
        step += 1
    if ready_claims_parallel_launcher_path:
        parallel_launcher_ref = stable_path(ready_claims_parallel_launcher_path)
        launch_sequence.extend(
            [
                f"{step}. Ready package claims: "
                "`$env:TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH = '1'; "
                f"powershell -NoProfile -ExecutionPolicy Bypass -File '{parallel_launcher_ref}'`",
                f"   Validate first without launching: `powershell -NoProfile -ExecutionPolicy Bypass -File '{parallel_launcher_ref}' -ValidateOnly`",
                "   This launcher runs package scripts directly after acquiring claim locks; use the agent spawn dry run above for Codex/Claude commands.",
            ]
        )
        step += 1
    if env_unblock_queue_path:
        launch_sequence.append(f"{step}. Fill env bundle: `{stable_path(env_unblock_queue_path)}`")
        step += 1
    if env_bundle_ready_claims_launcher_path:
        env_bundle_launcher_ref = stable_path(env_bundle_ready_claims_launcher_path)
        launch_sequence.append(
            f"{step}. Post-env-bundle package claims: "
            "`$env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'; "
            f"powershell -NoProfile -ExecutionPolicy Bypass -File '{env_bundle_launcher_ref}'`"
        )
        launch_sequence.append(
            f"   Validate first without launching: `powershell -NoProfile -ExecutionPolicy Bypass -File '{env_bundle_launcher_ref}' -ValidateOnly`"
        )
        step += 1
    if manifest_path and claim_status_report_path and claim_status_report_json_path:
        manifest_ref = stable_path(manifest_path)
        launch_sequence.append(
            f"{step}. Refresh claim status: "
            f"`python tools/detection_validation/run_preflight_work_package.py --refresh-claim-status-report '{manifest_ref}'`"
        )
    if launch_sequence:
        lines.extend(["## Recommended Launch Sequence", "", *launch_sequence, ""])

    continuation_lines: list[str] = []
    for wave in sorted({int(package.get("wave") or 0) for package in packages}):
        wave_packages = [
            package
            for package in sorted(packages, key=lambda item: str(item.get("package_id") or ""))
            if int(package.get("wave") or 0) == wave
        ]
        dependencies = sorted(
            {
                dependency
                for package in wave_packages
                for dependency in dependent_waves(package)
            }
        )
        staged_launcher_path = staged_launcher_by_wave.get(wave)
        if staged_launcher_path:
            staged_launcher_ref = stable_path(staged_launcher_path)
            command = f"powershell -NoProfile -ExecutionPolicy Bypass -File '{staged_launcher_ref}'"
            if dependencies:
                command = "$env:TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH = '1'; " + command
            continuation_lines.append(
                f"- Wave {wave} staged continuation: `{command}`"
            )
        else:
            for package in wave_packages:
                if not dependent_waves(package):
                    continue
                package_id = str(package.get("package_id") or "")
                script_path = script_paths.get(package_id)
                if not script_path:
                    continue
                script_ref = stable_path(script_path)
                continuation_lines.append(
                    f"- Wave {wave} closure handoff: "
                    f"`powershell -NoProfile -ExecutionPolicy Bypass -File '{script_ref}'`"
                )
        if dependencies:
            continuation_lines.append(
                f"  Requires waves {markdown_code_list([str(value) for value in dependencies])} evidence to be green before launch."
            )
    if continuation_lines:
        lines.extend(
            [
                "## Dependency-Gated Continuation",
                "",
                "Run this after the recommended launch sequence and claim-status refresh; it preserves wave dependencies and does not create a closure claim by itself.",
                "",
                *continuation_lines,
                "",
            ]
        )

    for wave in sorted({int(package.get("wave") or 0) for package in packages}):
        wave_packages = [
            package
            for package in sorted(packages, key=lambda item: str(item.get("package_id") or ""))
            if int(package.get("wave") or 0) == wave
        ]
        dependencies = sorted(
            {
                dependency
                for package in wave_packages
                for dependency in dependent_waves(package)
            }
        )
        launcher_path = launcher_by_wave.get(wave)
        staged_launcher_path = staged_launcher_by_wave.get(wave)
        lines.extend([f"## Wave {wave}", ""])
        lines.append(f"Depends on waves: {markdown_code_list([str(value) for value in dependencies])}")
        if staged_launcher_path:
            staged_launcher_ref = stable_path(staged_launcher_path)
            lines.append(f"Staged launcher: `{staged_launcher_ref}`")
            lines.append(
                "Staged command: "
                f"`powershell -NoProfile -ExecutionPolicy Bypass -File '{staged_launcher_ref}'`"
            )
        else:
            lines.append("Staged launcher: -")
        if launcher_path:
            launcher_ref = stable_path(launcher_path)
            lines.append(f"Parallel launcher: `{launcher_ref}`")
            lines.append(
                "Launcher command: "
                f"`powershell -NoProfile -ExecutionPolicy Bypass -File '{launcher_ref}'`"
            )
        else:
            lines.append("Parallel launcher: -")
        lines.extend(
            [
                "",
                "| Package | Launcher | Staged | Owner | Resources | Required env | Missing effective env | Script | Prompt | Handoff notes |",
                "|---|---|---|---|---|---|---|---|---|---|",
            ]
        )
        for package in wave_packages:
            package_id = str(package.get("package_id") or "")
            selected = (
                package.get("launcher_selected")
                if "launcher_selected" in package
                else launched.get(package_id)
            )
            manual_reason = (
                package.get("manual_reason")
                if "manual_reason" in package
                else skipped.get(package_id)
            )
            selected_text = "-" if selected is None else ("auto" if selected else f"manual: {manual_reason}")
            staged_stage = (
                package.get("staged_stage")
                if "staged_stage" in package
                else staged.get(package_id)
            )
            staged_text = f"stage {staged_stage}" if staged_stage else "-"
            prompt_path = stable_path(prompt_paths[package_id]) if package_id in prompt_paths else "-"
            handoff_notes = package_handoff_notes(
                package,
                launcher_selected=selected,
                manual_reason=manual_reason,
                staged_stage=staged_stage,
            )
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{package_id}`",
                        selected_text,
                        staged_text,
                        str(package.get("recommended_owner_role") or "-"),
                        markdown_code_list(package_manifest_resource_tags(package)),
                        markdown_code_list([str(value) for value in package.get("required_env") or []]),
                        markdown_code_list(missing_effective_env(package)),
                        f"`{stable_path(script_paths[package_id])}`",
                        f"`{prompt_path}`",
                        markdown_code_list(handoff_notes),
                    ]
                )
                + " |"
            )
        lines.append("")
    return "\n".join(lines)


def write_dispatch_brief(
    packages: list[dict],
    preflight_path: Path,
    output_dir: Path,
    script_paths: dict[str, Path],
    prompt_paths: dict[str, Path] | None = None,
    launcher_paths: list[Path] | None = None,
    staged_launcher_paths: list[Path] | None = None,
    roster_path: Path | None = None,
    env_checklist_path: Path | None = None,
    env_template_path: Path | None = None,
    owner_launch_plan_path: Path | None = None,
    owner_launch_plan_json_path: Path | None = None,
    execution_matrix_path: Path | None = None,
    execution_matrix_json_path: Path | None = None,
    agent_claims_path: Path | None = None,
    agent_claims_json_path: Path | None = None,
    agent_spawn_plan_path: Path | None = None,
    agent_spawn_plan_json_path: Path | None = None,
    agent_spawn_launcher_path: Path | None = None,
    claim_status_report_path: Path | None = None,
    claim_status_report_json_path: Path | None = None,
    claim_lock_helper_path: Path | None = None,
    env_unblock_queue_path: Path | None = None,
    env_unblock_queue_json_path: Path | None = None,
    ready_claims_launcher_path: Path | None = None,
    ready_claims_parallel_launcher_path: Path | None = None,
    env_bundle_ready_claims_launcher_path: Path | None = None,
    dispatch_prelaunch_validation_path: Path | None = None,
    manifest_path: Path | None = None,
    dispatch_runner_path: Path | None = None,
) -> Path:
    brief_path = output_dir / "dispatch_brief.md"
    brief_path.write_text(
        render_dispatch_brief(
            packages,
            preflight_path,
            script_paths,
            prompt_paths,
            launcher_paths,
            staged_launcher_paths,
            roster_path,
            env_checklist_path,
            env_template_path,
            owner_launch_plan_path,
            owner_launch_plan_json_path,
            execution_matrix_path,
            execution_matrix_json_path,
            agent_claims_path,
            agent_claims_json_path,
            agent_spawn_plan_path,
            agent_spawn_plan_json_path,
            agent_spawn_launcher_path,
            claim_status_report_path,
            claim_status_report_json_path,
            claim_lock_helper_path,
            env_unblock_queue_path,
            env_unblock_queue_json_path,
            ready_claims_launcher_path,
            ready_claims_parallel_launcher_path,
            env_bundle_ready_claims_launcher_path,
            dispatch_prelaunch_validation_path,
            manifest_path,
            dispatch_runner_path,
        ),
        encoding="utf-8",
    )
    return brief_path


def render_dispatch_runner(
    packages: list[dict],
    script_paths: dict[str, Path],
    launcher_paths: list[Path] | None = None,
    staged_launcher_paths: list[Path] | None = None,
    manifest_path: Path | None = None,
) -> str:
    launcher_paths = launcher_paths or []
    staged_launcher_paths = staged_launcher_paths or []

    def launcher_wave(path: Path) -> int | None:
        parts = path.name.split("-")
        if len(parts) < 3 or parts[0] != "wave":
            return None
        try:
            return int(parts[1])
        except ValueError:
            return None

    parallel_by_wave = {
        wave: path
        for path in launcher_paths
        for wave in [launcher_wave(path)]
        if wave is not None
    }
    staged_by_wave = {
        wave: path
        for path in staged_launcher_paths
        for wave in [launcher_wave(path)]
        if wave is not None
    }
    waves = sorted({int(package.get("wave") or 0) for package in packages})
    manifest_ref = stable_path(manifest_path) if manifest_path else "dispatch_manifest.json"
    lines = [
        "# Generated one-shot runner for validation dispatch work packages.",
        "# Requires explicit operator opt-in before it launches package scripts.",
        "$ErrorActionPreference = 'Stop'",
        "Set-StrictMode -Version Latest",
        "$AllowOneShot = [Environment]::GetEnvironmentVariable('TAMANDUA_ALLOW_ONE_SHOT_DISPATCH')",
        "if ($AllowOneShot -ne '1') {",
        "  Write-Error 'Set TAMANDUA_ALLOW_ONE_SHOT_DISPATCH=1 only after reviewing dispatch_brief.md and env_checklist.md.'",
        "  exit 2",
        "}",
        "$env:TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH = '1'",
        "$DispatchAgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_DISPATCH_AGENT_ID')",
        "if (-not $DispatchAgentId) { $DispatchAgentId = [Environment]::UserName }",
        *ps_agent_id_guard_lines("DispatchAgentId", "TAMANDUA_DISPATCH_AGENT_ID"),
        "$DispatchFailures = @()",
        "$FailedWaves = @{}",
        f"$DispatchManifestPath = {ps_single_quoted(manifest_ref)}",
        "$DispatchRunnerDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
        "$ClaimLockHelperPath = Join-Path $DispatchRunnerDir 'claim_lock_helper.ps1'",
        "if (-not (Test-Path $ClaimLockHelperPath)) {",
        "  Write-Error ('Missing claim lock helper: ' + $ClaimLockHelperPath)",
        "  exit 2",
        "}",
        "function Invoke-DispatchStep {",
        "  param([string]$Label, [string]$ScriptPath, [int]$Wave, [string]$ClaimId)",
        "  Write-Host ('[dispatch] ' + $Label)",
        "  if ($ClaimId) { $env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId }",
        "  $env:TAMANDUA_AGENT_ID = $script:DispatchAgentId",
        "  if ($ClaimId) {",
        "    powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:ClaimLockHelperPath -ClaimId $ClaimId -AgentId $script:DispatchAgentId",
        "    if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {",
        "      $script:DispatchFailures += ($Label + ' claim lock exit ' + [string]$LASTEXITCODE)",
        "      $script:FailedWaves[$Wave] = $true",
        "      return",
        "    }",
        "    $env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
        "  }",
        "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath",
        "  if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {",
        "    $script:DispatchFailures += ($Label + ' exit ' + [string]$LASTEXITCODE)",
        "    $script:FailedWaves[$Wave] = $true",
        "  }",
        "}",
        "function Write-DispatchBlockedPackageStatus {",
        "  param([object]$Package, [string]$Note)",
        "  $StatusPath = [string]$Package.status_path",
        "  if (-not $StatusPath) {",
        "    $OutputDir = [string]$Package.output_dir",
        "    if (-not $OutputDir) { return }",
        "    $PackageDir = if ((Split-Path -Leaf $OutputDir) -ieq 'outputs') { Split-Path -Parent $OutputDir } else { $OutputDir }",
        "    $StatusPath = Join-Path $PackageDir 'agent_status.json'",
        "  }",
        "  $StatusDir = Split-Path -Parent $StatusPath",
        "  if ($StatusDir) { New-Item -ItemType Directory -Force -Path $StatusDir | Out-Null }",
        "  $ExpectedProfiles = @($Package.expected_profile_ids | ForEach-Object { [string]$_ })",
        "  $Status = [ordered]@{",
        "    package_id = [string]$Package.package_id",
        "    claim_id = 'claim-' + [string]$Package.package_id",
        "    agent_id = $script:DispatchAgentId",
        "    status = 'blocked'",
        "    artifacts = @()",
        "    blocker_cleared = $false",
        "    notes = @($Note)",
        "    exit_code = 2",
        "    expected_profiles = $ExpectedProfiles",
        "    missing_profiles = $ExpectedProfiles",
        "  }",
        "  $Status | ConvertTo-Json -Depth 6 | Set-Content -Path $StatusPath -Encoding UTF8",
        "}",
        "function Write-DispatchBlockedWaveStatuses {",
        "  param([int]$Wave, [string]$Note)",
        "  if (-not $Manifest -or -not $Manifest.packages) { return }",
        "  foreach ($Package in @($Manifest.packages)) {",
        "    if ([int]$Package.wave -eq $Wave) {",
        "      Write-DispatchBlockedPackageStatus $Package $Note",
        "    }",
        "  }",
        "}",
        "function Test-DispatchWaveDependencies {",
        "  param([int]$Wave, [int[]]$DependsOnWaves)",
        "  $FailedDependencies = @()",
        "  $MissingDependencyEvidence = @()",
        "  foreach ($DependencyWave in @($DependsOnWaves)) {",
        "    if ($script:FailedWaves.ContainsKey([int]$DependencyWave)) { $FailedDependencies += [string]$DependencyWave }",
        "  }",
        "  if (Test-Path $script:DispatchManifestPath) {",
        "    $Manifest = Get-Content -Raw -Path $script:DispatchManifestPath | ConvertFrom-Json",
        "    foreach ($DependencyWave in @($DependsOnWaves)) {",
        "      $WaveNumber = [int]$DependencyWave",
        "      $DependencyPackages = @($Manifest.packages | Where-Object { [int]$_.wave -eq $WaveNumber -and ($_.launcher_selected -eq $true -or $_.staged_launcher_selected -eq $true) })",
        "      if ($DependencyPackages.Count -eq 0) {",
        "        $MissingDependencyEvidence += ('wave-' + [string]$WaveNumber + ':missing_dependency_packages')",
        "        continue",
        "      }",
        "      foreach ($DependencyPackage in $DependencyPackages) {",
        "        $OutputDir = [string]$DependencyPackage.output_dir",
        "        if (-not $OutputDir -or -not (Test-Path $OutputDir)) {",
        "          $MissingDependencyEvidence += ([string]$DependencyPackage.package_id + ':missing_output_dir')",
        "          continue",
        "        }",
        "        $JsonOutputs = @(Get-ChildItem -Path $OutputDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*.comparison.json' })",
        "        if ($JsonOutputs.Count -eq 0) {",
        "          $MissingDependencyEvidence += ([string]$DependencyPackage.package_id + ':missing_json_output')",
        "          continue",
        "        }",
        "        foreach ($ExpectedProfile in @($DependencyPackage.expected_profile_ids)) {",
        "          $ProfilePassed = $false",
        "          foreach ($JsonOutput in $JsonOutputs) {",
        "            $Payload = $null",
        "            try { $Payload = Get-Content -Raw -Path $JsonOutput.FullName | ConvertFrom-Json } catch { $Payload = $null }",
        "            if ($Payload) {",
        "              $ProfileIdProperty = $Payload.PSObject.Properties['profile_id']",
        "              $QualityGateProperty = $Payload.PSObject.Properties['quality_gate']",
        "              if ($ProfileIdProperty -and $QualityGateProperty -and [string]$ProfileIdProperty.Value -eq [string]$ExpectedProfile) {",
        "                $PassedProperty = $QualityGateProperty.Value.PSObject.Properties['passed']",
        "                if ($PassedProperty -and $PassedProperty.Value -eq $true) {",
        "                  $ProfilePassed = $true",
        "                  break",
        "                }",
        "              }",
        "            }",
        "          }",
        "          if (-not $ProfilePassed) {",
        "            $MissingDependencyEvidence += ([string]$DependencyPackage.package_id + ':' + [string]$ExpectedProfile + ':quality_gate_not_passed')",
        "          }",
        "        }",
        "      }",
        "    }",
        "  } else {",
        "    $MissingDependencyEvidence += 'dispatch_manifest:missing'",
        "  }",
        "  if ($FailedDependencies.Count -gt 0) {",
        "    $Reason = 'wave ' + [string]$Wave + ' skipped because dependency wave failed: ' + ($FailedDependencies -join ', ')",
        "    $script:DispatchFailures += $Reason",
        "    Write-DispatchBlockedWaveStatuses $Wave $Reason",
        "    $script:FailedWaves[$Wave] = $true",
        "    return $false",
        "  }",
        "  if ($MissingDependencyEvidence.Count -gt 0) {",
        "    $Reason = 'wave ' + [string]$Wave + ' skipped because dependency evidence missing: ' + ($MissingDependencyEvidence -join ', ')",
        "    $script:DispatchFailures += $Reason",
        "    Write-DispatchBlockedWaveStatuses $Wave $Reason",
        "    $script:FailedWaves[$Wave] = $true",
        "    return $false",
        "  }",
        "  return $true",
        "}",
        "function Invoke-DispatchCommand {",
        "  param([string]$Label, [string[]]$Command)",
        "  Write-Host ('[dispatch] ' + $Label)",
        "  & $Command[0] $Command[1..($Command.Count - 1)]",
        "  if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {",
        "    $script:DispatchFailures += ($Label + ' exit ' + [string]$LASTEXITCODE)",
        "  }",
        "}",
        "",
    ]
    for wave in waves:
        wave_lines = []
        depends_on = sorted(
            {
                dependency
                for package in packages
                if int(package.get("wave") or 0) == wave
                for dependency in dependent_waves(package)
            }
        )
        launcher_path = staged_by_wave.get(wave) or parallel_by_wave.get(wave)
        if launcher_path:
            launcher_kind = "staged" if wave in staged_by_wave else "parallel"
            wave_lines.append(
                f"Invoke-DispatchStep {ps_single_quoted(f'wave {wave} {launcher_kind} launcher')} "
                f"{ps_single_quoted(stable_path(launcher_path))} {wave}"
            )
        else:
            wave_packages = [
                package
                for package in sorted(packages, key=lambda item: str(item.get("package_id") or ""))
                if int(package.get("wave") or 0) == wave
            ]
            for package in wave_packages:
                package_id = str(package.get("package_id") or "")
                wave_lines.append(
                    f"Invoke-DispatchStep {ps_single_quoted(f'wave {wave} package {package_id}')} "
                    f"{ps_single_quoted(stable_path(script_paths[package_id]))} {wave} {ps_single_quoted('claim-' + package_id)}"
                )
        if depends_on:
            lines.append(f"if (Test-DispatchWaveDependencies {wave} {ps_array([str(value) for value in depends_on])}) {{")
            lines.extend(f"  {line}" for line in wave_lines)
            lines.append("}")
        else:
            lines.extend(wave_lines)
    lines.extend(
        [
            "",
            "Invoke-DispatchCommand 'refresh dispatch handoff artifacts' @("
            "'python', 'tools/detection_validation/run_preflight_work_package.py', "
            f"'--refresh-dispatch-handoff-artifacts', {ps_single_quoted(manifest_ref)})",
            "Invoke-DispatchCommand 'summarize dispatch results' @("
            "'python', 'tools/detection_validation/run_preflight_work_package.py', "
            f"'--summarize-dispatch', {ps_single_quoted(manifest_ref)})",
            "Invoke-DispatchCommand 'promote dispatch results' @("
            "'python', 'tools/detection_validation/run_preflight_work_package.py', "
            f"'--promote-dispatch-results', {ps_single_quoted(manifest_ref)})",
            "Invoke-DispatchCommand 'refresh validation scorecard' @("
            "'python', 'tools/detection_validation/generate_validation_scorecard.py')",
            "Invoke-DispatchCommand 'run validation status consistency' @("
            "'python', 'tools/detection_validation/validation_status_consistency.py')",
            "if ($DispatchFailures.Count -gt 0) {",
            "  Write-Error ('Dispatch one-shot completed with failures: ' + ($DispatchFailures -join ', '))",
            "  exit 1",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def write_dispatch_runner(
    packages: list[dict],
    output_dir: Path,
    script_paths: dict[str, Path],
    launcher_paths: list[Path] | None = None,
    staged_launcher_paths: list[Path] | None = None,
    manifest_path: Path | None = None,
) -> Path:
    runner_path = output_dir / "dispatch_one_shot_runner.ps1"
    runner_path.write_text(
        render_dispatch_runner(packages, script_paths, launcher_paths, staged_launcher_paths, manifest_path),
        encoding="utf-8",
    )
    return runner_path


def launcher_membership(packages: list[dict]) -> tuple[dict[str, bool], dict[str, str]]:
    launched = {}
    skipped = {}
    waves = sorted({int(package.get("wave") or 0) for package in packages})
    for wave in waves:
        wave_packages = [
            package
            for package in packages
            if int(package.get("wave") or 0) == wave and package.get("parallelizable_in_wave")
        ]
        launchable_wave_packages = [
            package for package in wave_packages if package_is_launch_ready(package)
        ]
        used_resources = set()
        ordered_wave_packages = sorted(
            launchable_wave_packages,
            key=lambda package: (-package_impact_score(package), str(package.get("package_id") or "")),
        )
        for package in wave_packages:
            package_id = str(package.get("package_id"))
            blockers = package_launch_blockers(package)
            if blockers:
                launched[package_id] = False
                skipped[package_id] = "blocked: " + ", ".join(blockers)
        for package in ordered_wave_packages:
            package_id = str(package.get("package_id"))
            resources = set(package_resource_tags(package))
            overlap = sorted(used_resources & resources)
            if overlap:
                launched[package_id] = False
                skipped[package_id] = f"resource overlap: {', '.join(overlap)}"
                continue
            used_resources.update(resources)
            launched[package_id] = True
        if sum(1 for package in launchable_wave_packages if launched.get(str(package.get("package_id"))) is True) < 2:
            for package in launchable_wave_packages:
                package_id = str(package.get("package_id"))
                if launched.get(package_id) is True:
                    launched[package_id] = False
                    skipped[package_id] = "parallel launcher not emitted: fewer than two non-overlapping packages"
    return launched, skipped


def build_dispatch_manifest(
    packages: list[dict],
    preflight_path: Path,
    output_dir: Path,
    script_paths: dict[str, Path],
    prompt_paths: dict[str, Path] | None = None,
    launcher_paths: list[Path] | None = None,
    staged_launcher_paths: list[Path] | None = None,
    roster_path: Path | None = None,
    env_checklist_path: Path | None = None,
    env_template_path: Path | None = None,
    owner_launch_plan_path: Path | None = None,
    owner_launch_plan_json_path: Path | None = None,
    execution_matrix_path: Path | None = None,
    execution_matrix_json_path: Path | None = None,
    agent_claims_path: Path | None = None,
    agent_claims_json_path: Path | None = None,
    agent_spawn_plan_path: Path | None = None,
    agent_spawn_plan_json_path: Path | None = None,
    agent_spawn_launcher_path: Path | None = None,
    claim_status_report_path: Path | None = None,
    claim_status_report_json_path: Path | None = None,
    claim_lock_helper_path: Path | None = None,
    env_unblock_queue_path: Path | None = None,
    env_unblock_queue_json_path: Path | None = None,
    ready_claims_launcher_path: Path | None = None,
    ready_claims_parallel_launcher_path: Path | None = None,
    env_bundle_ready_claims_launcher_path: Path | None = None,
    dispatch_prelaunch_validation_path: Path | None = None,
    dispatch_brief_path: Path | None = None,
    dispatch_runner_path: Path | None = None,
    selection_mode: str | None = None,
    selected_wave: int | None = None,
) -> dict:
    prompt_paths = prompt_paths or {}
    launcher_paths = launcher_paths or []
    staged_launcher_paths = staged_launcher_paths or []
    launched, skipped = launcher_membership(packages)
    staged = staged_launcher_membership(packages)
    enriched_packages: dict[str, dict] = {}
    if owner_launch_plan_json_path and owner_launch_plan_json_path.exists():
        try:
            owner_launch_plan = load_json(owner_launch_plan_json_path)
        except json.JSONDecodeError:
            owner_launch_plan = {}
        for owner in owner_launch_plan.get("owners") or []:
            if not isinstance(owner, dict):
                continue
            for owner_package in owner.get("packages") or []:
                if not isinstance(owner_package, dict):
                    continue
                package_id = str(owner_package.get("package_id") or "")
                if package_id:
                    enriched_packages[package_id] = owner_package
    package_entries = []
    for package in sorted(packages, key=lambda item: (int(item.get("wave") or 0), str(item.get("package_id") or ""))):
        package_id = str(package.get("package_id"))
        script_path = script_paths[package_id]
        enriched_package = enriched_packages.get(package_id, {})
        launcher_selected = (
            package.get("launcher_selected")
            if isinstance(package.get("launcher_selected"), bool) or package.get("launcher_selected") is None
            else launched.get(package_id)
        )
        if "launcher_selected" not in package:
            launcher_selected = launched.get(package_id)
        manual_reason = (
            package.get("manual_reason")
            if package.get("manual_reason") is not None
            else skipped.get(package_id)
        )
        staged_launcher_selected = (
            bool(package.get("staged_launcher_selected"))
            if "staged_launcher_selected" in package
            else package_id in staged
        )
        staged_stage = (
            package.get("staged_stage")
            if package.get("staged_stage") is not None or "staged_stage" in package
            else staged.get(package_id)
        )
        current_next_action = enriched_package.get("current_next_action") if isinstance(enriched_package, dict) else {}
        if not isinstance(current_next_action, dict):
            current_next_action = {}
        current_next_action = package_current_next_action_or_task(package, current_next_action)
        package_for_env_details = dict(package)
        package_for_env_details["current_next_action"] = current_next_action
        input_details = env_details_by_env(package_for_env_details)
        next_action_required_env = (
            [str(value) for value in enriched_package.get("next_action_required_env") or []]
            if isinstance(enriched_package, dict) and enriched_package.get("next_action_required_env") is not None
            else package_next_action_env(package)
        )
        effective_required_env = (
            [str(value) for value in enriched_package.get("effective_required_env") or []]
            if isinstance(enriched_package, dict) and enriched_package.get("effective_required_env") is not None
            else package_effective_env_with_current_action(package, current_next_action)
        )
        missing_effective_env = (
            [str(value) for value in enriched_package.get("missing_effective_env") or []]
            if isinstance(enriched_package, dict) and enriched_package.get("missing_effective_env") is not None
            else [
                env_name
                for env_name in effective_required_env
                if not os.environ.get(env_name)
            ]
        )
        package_entries.append(
            {
                "package_id": package_id,
                "title": package.get("title") or "",
                "wave": int(package.get("wave") or 0),
                "recommended_owner_role": package.get("recommended_owner_role") or "",
                "parallelizable_in_wave": bool(package.get("parallelizable_in_wave")),
                "continue_on_failure": bool(package.get("continue_on_failure")),
                "launcher_selected": launcher_selected,
                "manual_reason": manual_reason,
                "staged_launcher_selected": staged_launcher_selected,
                "staged_stage": staged_stage,
                "handoff_notes": package_handoff_notes(
                    package,
                    launcher_selected=launcher_selected,
                    manual_reason=manual_reason,
                    staged_stage=staged_stage,
                    current_next_action=current_next_action,
                ),
                "depends_on_waves": dependent_waves(package),
                "resource_tags": package_manifest_resource_tags(package),
                "impact_score": package_impact_score(package),
                "required_env": [str(value) for value in package.get("required_env") or []],
                "next_action_required_env": next_action_required_env,
                "current_next_action": current_next_action,
                "current_next_action_required_env": next_action_env_from_action(current_next_action),
                "effective_required_env": effective_required_env,
                "missing_effective_env": missing_effective_env,
                "env_details": {
                    env_name: input_details.get(env_name, {"name": "", "flag": "", "description": ""})
                    for env_name in effective_required_env
                },
                "roadmaps": [str(value) for value in package.get("roadmaps") or []],
                "roadmap_next_actions": [
                    {
                        "roadmap": str(action.get("roadmap") or ""),
                        "roadmap_status": str(action.get("roadmap_status") or ""),
                        "blocking_profiles": [
                            str(value) for value in action.get("blocking_profiles") or []
                        ],
                        "required_env": [
                            str(value) for value in action.get("required_env") or []
                        ],
                        "action": str(action.get("action") or ""),
                    }
                    for action in package.get("roadmap_next_actions") or []
                    if isinstance(action, dict)
                ],
                "blocked_run_classes": [str(value) for value in package.get("blocked_run_classes") or []],
                "blocking_profiles": [str(value) for value in package.get("blocking_profiles") or []],
                "expected_profile_ids": [
                    str(value) for value in package.get("expected_profile_ids") or []
                ],
                "operator_inputs": [
                    {
                        "name": str(item.get("name") or ""),
                        "flag": str(item.get("flag") or ""),
                        "env": str(item.get("env") or ""),
                        "description": str(item.get("description") or ""),
                    }
                    for item in package.get("operator_inputs") or []
                    if isinstance(item, dict)
                ],
                "manual_prerequisites": [
                    str(value) for value in package.get("manual_prerequisites") or []
                ],
                "safe_commands": [
                    str(value) for value in package.get("safe_commands") or []
                ],
                "script_path": stable_path(script_path),
                "prompt_path": stable_path(prompt_paths[package_id]) if package_id in prompt_paths else None,
                "output_dir": stable_path(package_manifest_output_dir(package, script_path)),
                "status_path": stable_path(package_manifest_status_path(package, script_path)),
                "claim_output_contract": package_claim_output_contract(package),
            }
        )

    return {
        "profile_id": PROFILE_ID,
        "source_preflight": stable_path(preflight_path),
        "output_dir": stable_path(output_dir),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "selection_mode": selection_mode or "unspecified",
        "selected_wave": selected_wave,
        "expected_waves": sorted({int(package.get("wave") or 0) for package in packages}),
        "expected_package_ids": sorted(str(package.get("package_id")) for package in packages),
        "launcher_paths": [stable_path(path) for path in launcher_paths],
        "staged_launcher_paths": [stable_path(path) for path in staged_launcher_paths],
        "agent_roster_path": stable_path(roster_path) if roster_path else None,
        "env_checklist_path": stable_path(env_checklist_path) if env_checklist_path else None,
        "env_template_path": stable_path(env_template_path) if env_template_path else None,
        "owner_launch_plan_path": stable_path(owner_launch_plan_path) if owner_launch_plan_path else None,
        "owner_launch_plan_json_path": stable_path(owner_launch_plan_json_path) if owner_launch_plan_json_path else None,
        "execution_matrix_path": stable_path(execution_matrix_path) if execution_matrix_path else None,
        "execution_matrix_json_path": stable_path(execution_matrix_json_path) if execution_matrix_json_path else None,
        "agent_claims_path": stable_path(agent_claims_path) if agent_claims_path else None,
        "agent_claims_json_path": stable_path(agent_claims_json_path) if agent_claims_json_path else None,
        "agent_spawn_plan_path": stable_path(agent_spawn_plan_path) if agent_spawn_plan_path else None,
        "agent_spawn_plan_json_path": stable_path(agent_spawn_plan_json_path) if agent_spawn_plan_json_path else None,
        "agent_spawn_launcher_path": stable_path(agent_spawn_launcher_path) if agent_spawn_launcher_path else None,
        "claim_status_report_path": stable_path(claim_status_report_path) if claim_status_report_path else None,
        "claim_status_report_json_path": stable_path(claim_status_report_json_path) if claim_status_report_json_path else None,
        "claim_lock_helper_path": stable_path(claim_lock_helper_path) if claim_lock_helper_path else None,
        "env_unblock_queue_path": stable_path(env_unblock_queue_path) if env_unblock_queue_path else None,
        "env_unblock_queue_json_path": stable_path(env_unblock_queue_json_path) if env_unblock_queue_json_path else None,
        "ready_claims_launcher_path": stable_path(ready_claims_launcher_path) if ready_claims_launcher_path else None,
        "ready_claims_parallel_launcher_path": stable_path(ready_claims_parallel_launcher_path) if ready_claims_parallel_launcher_path else None,
        "env_bundle_ready_claims_launcher_path": stable_path(env_bundle_ready_claims_launcher_path) if env_bundle_ready_claims_launcher_path else None,
        "dispatch_prelaunch_validation_path": stable_path(dispatch_prelaunch_validation_path) if dispatch_prelaunch_validation_path else None,
        "dispatch_brief_path": stable_path(dispatch_brief_path) if dispatch_brief_path else None,
        "dispatch_runner_path": stable_path(dispatch_runner_path) if dispatch_runner_path else None,
        "packages": package_entries,
    }


def write_dispatch_manifest(
    packages: list[dict],
    preflight_path: Path,
    output_dir: Path,
    script_paths: dict[str, Path],
    prompt_paths: dict[str, Path] | None = None,
    launcher_paths: list[Path] | None = None,
    staged_launcher_paths: list[Path] | None = None,
    roster_path: Path | None = None,
    env_checklist_path: Path | None = None,
    env_template_path: Path | None = None,
    owner_launch_plan_path: Path | None = None,
    owner_launch_plan_json_path: Path | None = None,
    execution_matrix_path: Path | None = None,
    execution_matrix_json_path: Path | None = None,
    agent_claims_path: Path | None = None,
    agent_claims_json_path: Path | None = None,
    agent_spawn_plan_path: Path | None = None,
    agent_spawn_plan_json_path: Path | None = None,
    agent_spawn_launcher_path: Path | None = None,
    claim_status_report_path: Path | None = None,
    claim_status_report_json_path: Path | None = None,
    claim_lock_helper_path: Path | None = None,
    env_unblock_queue_path: Path | None = None,
    env_unblock_queue_json_path: Path | None = None,
    ready_claims_launcher_path: Path | None = None,
    ready_claims_parallel_launcher_path: Path | None = None,
    env_bundle_ready_claims_launcher_path: Path | None = None,
    dispatch_prelaunch_validation_path: Path | None = None,
    dispatch_brief_path: Path | None = None,
    dispatch_runner_path: Path | None = None,
    selection_mode: str | None = None,
    selected_wave: int | None = None,
) -> Path:
    manifest = build_dispatch_manifest(
        packages,
        preflight_path,
        output_dir,
        script_paths,
        prompt_paths,
        launcher_paths,
        staged_launcher_paths,
        roster_path,
        env_checklist_path,
        env_template_path,
        owner_launch_plan_path,
        owner_launch_plan_json_path,
        execution_matrix_path,
        execution_matrix_json_path,
        agent_claims_path,
        agent_claims_json_path,
        agent_spawn_plan_path,
        agent_spawn_plan_json_path,
        agent_spawn_launcher_path,
        claim_status_report_path,
        claim_status_report_json_path,
        claim_lock_helper_path,
        env_unblock_queue_path,
        env_unblock_queue_json_path,
        ready_claims_launcher_path,
        ready_claims_parallel_launcher_path,
        env_bundle_ready_claims_launcher_path,
        dispatch_prelaunch_validation_path,
        dispatch_brief_path,
        dispatch_runner_path,
        selection_mode,
        selected_wave,
    )
    manifest_path = output_dir / "dispatch_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path


def result_artifacts(output_dir: Path) -> list[Path]:
    def sort_key(path: Path) -> tuple[int, str]:
        try:
            payload = load_json(path)
            profile_id = str(payload.get("profile_id") or payload.get("profile") or "")
        except (OSError, json.JSONDecodeError):
            profile_id = ""
        return (RESULT_PROFILE_PRIORITY.get(profile_id, 100), path.name)

    return sorted(
        [
            path
            for path in output_dir.glob("*.json")
            if not path.name.endswith(".comparison.json") and path.name != "dispatch_results.json"
            and path.name != "agent_status.json"
        ],
        key=sort_key,
    )


def primary_result_artifact(output_dir: Path) -> Path | None:
    candidates = result_artifacts(output_dir)
    return candidates[0] if candidates else None


def latest_result_artifact(output_dir: Path) -> Path | None:
    candidates = result_artifacts(output_dir)
    return candidates[-1] if candidates else None


def result_artifact_paths(output_dir: Path) -> list[str]:
    return [
        str(path)
        for path in result_artifacts(output_dir)
    ]


def summarize_artifact(path: Path | None) -> dict:
    if path is None:
        return {
            "artifact_path": None,
            "profile_id": None,
            "status": "missing",
            "passed": False,
            "blocking_gaps": [],
            "failures": ["missing_package_artifact"],
            "first_gap": None,
        }
    data = load_json(path)
    quality_gate = data.get("quality_gate") or {}
    first_gap = None
    actionable_gaps = quality_gate.get("actionable_gaps") or []
    if actionable_gaps:
        gap = actionable_gaps[0]
        first_gap = {
            "test_id": gap.get("test_id") or gap.get("id"),
            "missing": [str(value) for value in gap.get("missing") or []],
            "gap_category": gap.get("gap_category"),
        }
    if first_gap is None:
        missed_tests = [test for test in data.get("tests") or [] if test.get("status") == "missed"]
        if missed_tests:
            test = missed_tests[0]
            missing = []
            for key in (
                "missing_expected_fields",
                "missing_expected_telemetry",
                "missing_expected_detections",
                "missing_expected_alerts",
                "missing_expected_correlations",
            ):
                missing.extend(str(value) for value in test.get(key) or [])
            first_gap = {
                "test_id": test.get("id") or test.get("test_id"),
                "missing": missing,
                "gap_category": test.get("gap_category"),
            }
    evidence_excerpt = build_evidence_excerpt(data, first_gap)
    return {
        "artifact_path": str(path),
        "profile_id": data.get("profile_id") or data.get("profile"),
        "run_id": data.get("run_id") or path.stem,
        "status": quality_gate.get("status") or ("pass" if quality_gate.get("passed") else "fail"),
        "passed": bool(quality_gate.get("passed")),
        "blocking_gaps": [str(value) for value in quality_gate.get("blocking_gaps") or []],
        "failures": [str(value) for value in quality_gate.get("failures") or []],
        "first_gap": first_gap,
        "evidence_excerpt": evidence_excerpt,
    }


def summarize_agent_status(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {}
    try:
        status = load_json(path)
    except json.JSONDecodeError:
        return {
            "agent_status_path": str(path),
            "agent_status": "invalid",
            "agent_notes": ["agent_status_json_invalid"],
            "agent_missing_required_env": [],
            "agent_blocker_cleared": False,
        }

    def list_has_blank_string(values: list) -> bool:
        return any(isinstance(value, str) and not value.strip() for value in values)

    validation_errors: list[str] = []
    if not isinstance(status, dict):
        validation_errors.append("status_json_not_object")
        status = {}
    status_value = status.get("status")
    package_id_value = status.get("package_id")
    claim_id_value = status.get("claim_id")
    agent_id_value = status.get("agent_id")
    if claim_id_value is None and isinstance(package_id_value, str) and package_id_value:
        claim_id_value = f"claim-{package_id_value}"
    if agent_id_value is None:
        agent_id_value = "unknown-agent"
    artifacts_value = status.get("artifacts")
    blocker_cleared_value = status.get("blocker_cleared")
    notes_value = status.get("notes")
    exit_code_value = status.get("exit_code")
    expected_profiles_value = status.get("expected_profiles")
    missing_profiles_value = status.get("missing_profiles")
    if not isinstance(package_id_value, str) or not package_id_value:
        validation_errors.append("package_id_not_string")
    if not isinstance(claim_id_value, str) or not claim_id_value:
        validation_errors.append("claim_id_not_string")
    if not isinstance(agent_id_value, str) or not agent_id_value:
        validation_errors.append("agent_id_not_string")
    if not isinstance(status_value, str) or status_value not in {"pass", "fail", "blocked"}:
        validation_errors.append("status_not_allowed")
    if not isinstance(artifacts_value, list):
        validation_errors.append("artifacts_not_list")
        artifacts_value = []
    elif not all(isinstance(value, str) for value in artifacts_value):
        validation_errors.append("artifacts_not_string_list")
        artifacts_value = []
    elif list_has_blank_string(artifacts_value):
        validation_errors.append("artifacts_has_blank_entry")
        artifacts_value = []
    if not isinstance(blocker_cleared_value, bool):
        validation_errors.append("blocker_cleared_not_bool")
        blocker_cleared_value = False
    if not isinstance(notes_value, list):
        validation_errors.append("notes_not_list")
        notes_value = []
    elif not all(isinstance(value, str) for value in notes_value):
        validation_errors.append("notes_not_string_list")
        notes_value = []
    elif list_has_blank_string(notes_value):
        validation_errors.append("notes_has_blank_entry")
        notes_value = []
    if type(exit_code_value) is not int:
        validation_errors.append("exit_code_not_int")
        exit_code_value = None
    if not isinstance(expected_profiles_value, list):
        validation_errors.append("expected_profiles_not_list")
        expected_profiles_value = []
    elif not all(isinstance(value, str) for value in expected_profiles_value):
        validation_errors.append("expected_profiles_not_string_list")
        expected_profiles_value = []
    elif list_has_blank_string(expected_profiles_value):
        validation_errors.append("expected_profiles_has_blank_entry")
        expected_profiles_value = []
    if not isinstance(missing_profiles_value, list):
        validation_errors.append("missing_profiles_not_list")
        missing_profiles_value = []
    elif not all(isinstance(value, str) for value in missing_profiles_value):
        validation_errors.append("missing_profiles_not_string_list")
        missing_profiles_value = []
    elif list_has_blank_string(missing_profiles_value):
        validation_errors.append("missing_profiles_has_blank_entry")
        missing_profiles_value = []
    if validation_errors:
        return {
            "agent_status_path": str(path),
            "agent_package_id": str(package_id_value or ""),
            "agent_claim_id": str(claim_id_value or ""),
            "agent_id": str(agent_id_value or ""),
            "agent_status": "invalid",
            "agent_exit_code": exit_code_value,
            "agent_notes": ["agent_status_contract_invalid", *validation_errors],
            "agent_missing_required_env": [],
            "agent_blocker_cleared": False,
            "agent_expected_profiles": [],
            "agent_missing_profiles": [],
            "agent_artifacts": [],
        }
    return {
        "agent_status_path": str(path),
        "agent_package_id": package_id_value,
        "agent_claim_id": claim_id_value,
        "agent_id": agent_id_value,
        "agent_status": status_value,
        "agent_exit_code": exit_code_value,
        "agent_notes": [str(value) for value in notes_value],
        "agent_missing_required_env": missing_required_env_from_notes([str(value) for value in notes_value]),
        "agent_blocker_cleared": blocker_cleared_value,
        "agent_expected_profiles": [str(value) for value in expected_profiles_value],
        "agent_missing_profiles": [str(value) for value in missing_profiles_value],
        "agent_artifacts": [str(value) for value in artifacts_value],
    }


def missing_required_env_from_notes(notes: list[str]) -> list[str]:
    missing: list[str] = []
    for note in notes:
        prefix = ""
        for candidate in ("missing_required_env:", "missing_effective_env:"):
            if note.startswith(candidate):
                prefix = candidate
                break
        if not prefix:
            continue
        values = note[len(prefix):].strip()
        for value in values.split(","):
            env_name = value.strip()
            if env_name and env_name not in missing:
                missing.append(env_name)
    return missing


def expected_agent_status_path(output_dir: Path) -> Path:
    package_dir = output_dir.parent if output_dir.name.lower() == "outputs" else output_dir
    return package_dir / "agent_status.json"


def agent_status_path_is_expected(status_path: Path, output_dir: Path) -> bool:
    expected_path = expected_agent_status_path(output_dir).resolve(strict=False)
    actual_path = status_path.resolve(strict=False)
    return os.path.normcase(str(actual_path)) == os.path.normcase(str(expected_path))


def invalid_agent_status_path_summary(path: Path | None, reason: str) -> dict:
    return {
        "agent_status_path": str(path) if path is not None else "",
        "agent_status": "invalid",
        "agent_notes": ["agent_status_contract_invalid", reason],
        "agent_claim_id": "",
        "agent_id": "",
        "agent_blocker_cleared": False,
        "agent_expected_profiles": [],
        "agent_missing_profiles": [],
        "agent_artifacts": [],
    }


def enrich_archived_agent_status(path: Path, package_id: str) -> None:
    try:
        payload = load_json(path)
    except json.JSONDecodeError:
        return
    if not isinstance(payload, dict):
        return
    changed = False
    if not isinstance(payload.get("claim_id"), str) or not str(payload.get("claim_id") or "").strip():
        payload["claim_id"] = f"claim-{package_id}"
        changed = True
    if not isinstance(payload.get("agent_id"), str) or not str(payload.get("agent_id") or "").strip():
        payload["agent_id"] = "unknown-agent"
        changed = True
    if changed:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def path_is_within(child: Path, parent: Path) -> bool:
    child_resolved = child.resolve(strict=False)
    parent_resolved = parent.resolve(strict=False)
    child_norm = os.path.normcase(str(child_resolved))
    parent_norm = os.path.normcase(str(parent_resolved))
    try:
        return child_norm == parent_norm or Path(child_norm).is_relative_to(Path(parent_norm))
    except AttributeError:
        return child_norm == parent_norm or child_norm.startswith(parent_norm.rstrip("\\/") + os.sep)


def resolve_manifest_package_output_dir(output_dir_value: object, manifest_dir: Path) -> Path:
    value = str(output_dir_value or "")
    if not value:
        return manifest_dir
    return resolve_dispatch_manifest_path_ref(value, manifest_dir)


def invalid_package_output_summary(output_dir: Path, reason: str) -> dict:
    return {
        "artifact_path": None,
        "profile_id": None,
        "run_id": None,
        "status": "fail",
        "passed": False,
        "blocking_gaps": [reason],
        "failures": [reason],
        "first_gap": {
            "test_id": reason,
            "missing": [reason],
            "gap_category": "dispatch-results",
        },
        "evidence_excerpt": {
            "missing": [reason],
            "gap_category": "dispatch-results",
        },
        "artifact_paths": [],
        "expected_profile_ids": [],
        "missing_expected_profiles": [],
        "unexpected_profile_ids": [],
        "profile_results": [],
    }


def package_expected_profile_ids(package: dict) -> object:
    expected_profile_ids = package.get("expected_profile_ids")
    if expected_profile_ids is not None:
        return expected_profile_ids
    claim_contract = package.get("claim_output_contract")
    if isinstance(claim_contract, dict):
        return claim_contract.get("required_json_profile_ids")
    return None


AGENT_STATUS_REQUIRED_FIELDS = [
    "package_id",
    "claim_id",
    "agent_id",
    "status",
    "artifacts",
    "blocker_cleared",
    "notes",
    "exit_code",
    "expected_profiles",
    "missing_profiles",
]

DISPATCH_MANIFEST_LIST_PATH_FAILURES = {
    "launcher_paths": {
        "not_list": "dispatch_manifest_launcher_paths_not_list",
        "invalid": "dispatch_manifest_launcher_paths_invalid",
        "outside": "dispatch_manifest_launcher_paths_outside_manifest",
    },
    "staged_launcher_paths": {
        "not_list": "dispatch_manifest_staged_launcher_paths_not_list",
        "invalid": "dispatch_manifest_staged_launcher_paths_invalid",
        "outside": "dispatch_manifest_staged_launcher_paths_outside_manifest",
    },
}

DISPATCH_MANIFEST_SCALAR_PATH_FAILURES = {
    "agent_roster_path": {
        "invalid": "dispatch_manifest_agent_roster_path_invalid",
        "outside": "dispatch_manifest_agent_roster_path_outside_manifest",
    },
    "env_checklist_path": {
        "invalid": "dispatch_manifest_env_checklist_path_invalid",
        "outside": "dispatch_manifest_env_checklist_path_outside_manifest",
    },
    "env_template_path": {
        "invalid": "dispatch_manifest_env_template_path_invalid",
        "outside": "dispatch_manifest_env_template_path_outside_manifest",
    },
    "owner_launch_plan_path": {
        "invalid": "dispatch_manifest_owner_launch_plan_path_invalid",
        "outside": "dispatch_manifest_owner_launch_plan_path_outside_manifest",
    },
    "owner_launch_plan_json_path": {
        "invalid": "dispatch_manifest_owner_launch_plan_json_path_invalid",
        "outside": "dispatch_manifest_owner_launch_plan_json_path_outside_manifest",
    },
    "execution_matrix_path": {
        "invalid": "dispatch_manifest_execution_matrix_path_invalid",
        "outside": "dispatch_manifest_execution_matrix_path_outside_manifest",
    },
    "execution_matrix_json_path": {
        "invalid": "dispatch_manifest_execution_matrix_json_path_invalid",
        "outside": "dispatch_manifest_execution_matrix_json_path_outside_manifest",
    },
    "agent_claims_path": {
        "invalid": "dispatch_manifest_agent_claims_path_invalid",
        "outside": "dispatch_manifest_agent_claims_path_outside_manifest",
    },
    "agent_claims_json_path": {
        "invalid": "dispatch_manifest_agent_claims_json_path_invalid",
        "outside": "dispatch_manifest_agent_claims_json_path_outside_manifest",
    },
    "agent_spawn_plan_path": {
        "invalid": "dispatch_manifest_agent_spawn_plan_path_invalid",
        "outside": "dispatch_manifest_agent_spawn_plan_path_outside_manifest",
    },
    "agent_spawn_plan_json_path": {
        "invalid": "dispatch_manifest_agent_spawn_plan_json_path_invalid",
        "outside": "dispatch_manifest_agent_spawn_plan_json_path_outside_manifest",
    },
    "agent_spawn_launcher_path": {
        "invalid": "dispatch_manifest_agent_spawn_launcher_path_invalid",
        "outside": "dispatch_manifest_agent_spawn_launcher_path_outside_manifest",
    },
    "claim_status_report_path": {
        "invalid": "dispatch_manifest_claim_status_report_path_invalid",
        "outside": "dispatch_manifest_claim_status_report_path_outside_manifest",
    },
    "claim_status_report_json_path": {
        "invalid": "dispatch_manifest_claim_status_report_json_path_invalid",
        "outside": "dispatch_manifest_claim_status_report_json_path_outside_manifest",
    },
    "claim_lock_helper_path": {
        "invalid": "dispatch_manifest_claim_lock_helper_path_invalid",
        "outside": "dispatch_manifest_claim_lock_helper_path_outside_manifest",
    },
    "env_unblock_queue_path": {
        "invalid": "dispatch_manifest_env_unblock_queue_path_invalid",
        "outside": "dispatch_manifest_env_unblock_queue_path_outside_manifest",
    },
    "env_unblock_queue_json_path": {
        "invalid": "dispatch_manifest_env_unblock_queue_json_path_invalid",
        "outside": "dispatch_manifest_env_unblock_queue_json_path_outside_manifest",
    },
    "ready_claims_launcher_path": {
        "invalid": "dispatch_manifest_ready_claims_launcher_path_invalid",
        "outside": "dispatch_manifest_ready_claims_launcher_path_outside_manifest",
    },
    "ready_claims_parallel_launcher_path": {
        "invalid": "dispatch_manifest_ready_claims_parallel_launcher_path_invalid",
        "outside": "dispatch_manifest_ready_claims_parallel_launcher_path_outside_manifest",
    },
    "env_bundle_ready_claims_launcher_path": {
        "invalid": "dispatch_manifest_env_bundle_ready_claims_launcher_path_invalid",
        "outside": "dispatch_manifest_env_bundle_ready_claims_launcher_path_outside_manifest",
    },
    "dispatch_prelaunch_validation_path": {
        "invalid": "dispatch_manifest_dispatch_prelaunch_validation_path_invalid",
        "outside": "dispatch_manifest_dispatch_prelaunch_validation_path_outside_manifest",
    },
    "dispatch_brief_path": {
        "invalid": "dispatch_manifest_dispatch_brief_path_invalid",
        "outside": "dispatch_manifest_dispatch_brief_path_outside_manifest",
    },
    "dispatch_runner_path": {
        "invalid": "dispatch_manifest_dispatch_runner_path_invalid",
        "outside": "dispatch_manifest_dispatch_runner_path_outside_manifest",
    },
}


def manifest_package_validation_failures(package: dict) -> list[str]:
    failures: list[str] = []
    package_id = package.get("package_id")
    wave = package.get("wave")
    expected_profile_ids = package_expected_profile_ids(package)
    resource_tags = package.get("resource_tags")
    required_env = package.get("required_env")
    depends_on_waves = package.get("depends_on_waves")
    safe_commands = package.get("safe_commands")
    claim_contract = package.get("claim_output_contract")
    manual_prerequisites = package.get("manual_prerequisites")
    operator_inputs = package.get("operator_inputs")
    roadmap_next_actions = package.get("roadmap_next_actions")
    roadmaps = package.get("roadmaps")
    blocking_profiles = package.get("blocking_profiles")
    blocked_run_classes = package.get("blocked_run_classes")
    recommended_owner_role = package.get("recommended_owner_role")
    continue_on_failure = package.get("continue_on_failure")
    launcher_selected = package.get("launcher_selected")
    manual_reason = package.get("manual_reason")
    staged_launcher_selected = package.get("staged_launcher_selected")
    staged_stage = package.get("staged_stage")
    if not isinstance(package_id, str) or not package_id.strip():
        failures.append("dispatch_package_id_missing")
    if type(wave) is not int or wave < 1:
        failures.append("dispatch_wave_invalid")
    if not isinstance(expected_profile_ids, list):
        failures.append("dispatch_expected_profiles_not_list")
    elif not all(isinstance(value, str) and value.strip() for value in expected_profile_ids):
        failures.append("dispatch_expected_profiles_invalid")
    if not isinstance(resource_tags, list):
        failures.append("dispatch_resource_tags_not_list")
    elif not resource_tags:
        failures.append("dispatch_resource_tags_empty")
    elif not all(isinstance(value, str) and value.strip() for value in resource_tags):
        failures.append("dispatch_resource_tags_invalid")
    if not isinstance(required_env, list):
        failures.append("dispatch_required_env_not_list")
    elif not all(isinstance(value, str) and value.strip() for value in required_env):
        failures.append("dispatch_required_env_invalid")
    if depends_on_waves is not None:
        if not isinstance(depends_on_waves, list):
            failures.append("dispatch_depends_on_waves_not_list")
        elif not all(type(value) is int and value >= 1 for value in depends_on_waves):
            failures.append("dispatch_depends_on_waves_invalid")
        elif type(wave) is int and wave >= 1 and any(value >= wave for value in depends_on_waves):
            failures.append("dispatch_depends_on_waves_not_prior")
    if safe_commands is not None:
        if not isinstance(safe_commands, list):
            failures.append("dispatch_safe_commands_not_list")
        elif not all(isinstance(value, str) and value.strip() for value in safe_commands):
            failures.append("dispatch_safe_commands_invalid")
        elif not all(command_is_allowed(value) for value in safe_commands):
            failures.append("dispatch_safe_commands_unsupported")
    if claim_contract is not None:
        if not isinstance(claim_contract, dict):
            failures.append("dispatch_claim_contract_not_dict")
        else:
            contract_profiles = claim_contract.get("required_json_profile_ids")
            if not isinstance(contract_profiles, list) or not all(
                isinstance(value, str) and value.strip() for value in contract_profiles
            ):
                failures.append("dispatch_claim_contract_profiles_invalid")
            elif isinstance(expected_profile_ids, list) and [
                str(value) for value in contract_profiles
            ] != [str(value) for value in expected_profile_ids]:
                failures.append("dispatch_claim_contract_profiles_mismatch")
            if claim_contract.get("status_required_fields") != AGENT_STATUS_REQUIRED_FIELDS:
                failures.append("dispatch_claim_contract_status_fields_invalid")
            if claim_contract.get("status_allowed_values") != ["pass", "fail", "blocked"]:
                failures.append("dispatch_claim_contract_status_values_invalid")
    if manual_prerequisites is not None:
        if not isinstance(manual_prerequisites, list):
            failures.append("dispatch_manual_prerequisites_not_list")
        elif not all(isinstance(value, str) and value.strip() for value in manual_prerequisites):
            failures.append("dispatch_manual_prerequisites_invalid")
    if operator_inputs is not None:
        if not isinstance(operator_inputs, list):
            failures.append("dispatch_operator_inputs_not_list")
        elif not all(isinstance(item, dict) for item in operator_inputs):
            failures.append("dispatch_operator_inputs_invalid")
        elif not all(
            isinstance(item.get("flag"), str)
            and all(
                isinstance(item.get(field), str) and item.get(field, "").strip()
                for field in ["name", "env", "description"]
            )
            for item in operator_inputs
        ):
            failures.append("dispatch_operator_inputs_invalid")
    if roadmap_next_actions is not None:
        if not isinstance(roadmap_next_actions, list):
            failures.append("dispatch_roadmap_next_actions_not_list")
        elif not all(isinstance(item, dict) for item in roadmap_next_actions):
            failures.append("dispatch_roadmap_next_actions_invalid")
        elif not all(
            isinstance(item.get("roadmap"), str)
            and item.get("roadmap", "").strip()
            and isinstance(item.get("action"), str)
            and item.get("action", "").strip()
            and isinstance(item.get("blocking_profiles"), list)
            and all(isinstance(value, str) and value.strip() for value in item.get("blocking_profiles"))
            and isinstance(item.get("required_env"), list)
            and all(isinstance(value, str) and value.strip() for value in item.get("required_env"))
            and (
                item.get("roadmap_status") is None
                or (isinstance(item.get("roadmap_status"), str) and item.get("roadmap_status", "").strip())
            )
            for item in roadmap_next_actions
        ):
            failures.append("dispatch_roadmap_next_actions_invalid")
    if roadmaps is not None:
        if not isinstance(roadmaps, list):
            failures.append("dispatch_roadmaps_not_list")
        elif not all(isinstance(value, str) and value.strip() for value in roadmaps):
            failures.append("dispatch_roadmaps_invalid")
    if blocking_profiles is not None:
        if not isinstance(blocking_profiles, list):
            failures.append("dispatch_blocking_profiles_not_list")
        elif not all(isinstance(value, str) and value.strip() for value in blocking_profiles):
            failures.append("dispatch_blocking_profiles_invalid")
    if blocked_run_classes is not None:
        if not isinstance(blocked_run_classes, list):
            failures.append("dispatch_blocked_run_classes_not_list")
        elif not all(isinstance(value, str) and value.strip() for value in blocked_run_classes):
            failures.append("dispatch_blocked_run_classes_invalid")
    if recommended_owner_role is not None and (
        not isinstance(recommended_owner_role, str) or not recommended_owner_role.strip()
    ):
        failures.append("dispatch_recommended_owner_role_invalid")
    if continue_on_failure is not None and not isinstance(continue_on_failure, bool):
        failures.append("dispatch_continue_on_failure_not_bool")
    if launcher_selected is not None and not isinstance(launcher_selected, bool):
        failures.append("dispatch_launcher_selected_not_bool")
    elif launcher_selected is False and (not isinstance(manual_reason, str) or not manual_reason.strip()):
        failures.append("dispatch_manual_reason_missing")
    elif launcher_selected is True and manual_reason not in (None, ""):
        failures.append("dispatch_manual_reason_unexpected")
    if staged_launcher_selected is not None and not isinstance(staged_launcher_selected, bool):
        failures.append("dispatch_staged_launcher_selected_not_bool")
    if staged_stage is not None and (type(staged_stage) is not int or staged_stage < 1):
        failures.append("dispatch_staged_stage_invalid")
    return failures


def invalid_manifest_package_summary(failures: list[str]) -> dict:
    first_failure = failures[0] if failures else "dispatch_manifest_package_invalid"
    return {
        "artifact_path": None,
        "profile_id": None,
        "run_id": None,
        "status": "fail",
        "passed": False,
        "blocking_gaps": failures,
        "failures": failures,
        "first_gap": {
            "test_id": first_failure,
            "missing": failures,
            "gap_category": "dispatch-results",
        },
        "evidence_excerpt": {
            "missing": failures,
            "gap_category": "dispatch-results",
        },
        "artifact_paths": [],
        "expected_profile_ids": [],
        "missing_expected_profiles": [],
        "unexpected_profile_ids": [],
        "profile_results": [],
    }


def dispatch_manifest_validation_failures(manifest: dict) -> list[str]:
    failures: list[str] = []
    profile_id = manifest.get("profile_id")
    source_preflight = manifest.get("source_preflight")
    packages = manifest.get("packages")
    if profile_id != PROFILE_ID:
        failures.append("dispatch_manifest_profile_id_invalid")
    if not isinstance(source_preflight, str) or not source_preflight.strip():
        failures.append("dispatch_manifest_source_preflight_missing")
    if not isinstance(packages, list):
        failures.append("dispatch_manifest_packages_not_list")
        return failures
    if not all(isinstance(package, dict) for package in packages):
        failures.append("dispatch_manifest_packages_invalid")
        return failures

    package_ids = [str(package.get("package_id") or "") for package in packages]
    package_waves = [package.get("wave") for package in packages]
    valid_package_ids = sorted(package_id for package_id in package_ids if package_id.strip())
    valid_package_waves = sorted({wave for wave in package_waves if type(wave) is int and wave >= 1})
    expected_waves = manifest.get("expected_waves")
    expected_package_ids = manifest.get("expected_package_ids")
    selected_wave = manifest.get("selected_wave")
    selection_mode = manifest.get("selection_mode")
    manifest_path_value = manifest.get("manifest_path")
    manifest_dir = Path(str(manifest_path_value)).parent if manifest_path_value else Path.cwd()

    if expected_waves is not None:
        if not isinstance(expected_waves, list):
            failures.append("dispatch_manifest_expected_waves_not_list")
        elif not all(type(value) is int and value >= 1 for value in expected_waves):
            failures.append("dispatch_manifest_expected_waves_invalid")
        elif sorted(set(expected_waves)) != valid_package_waves:
            failures.append("dispatch_manifest_expected_waves_mismatch")
    if expected_package_ids is not None:
        if not isinstance(expected_package_ids, list):
            failures.append("dispatch_manifest_expected_package_ids_not_list")
        elif not all(isinstance(value, str) and value.strip() for value in expected_package_ids):
            failures.append("dispatch_manifest_expected_package_ids_invalid")
        elif sorted(set(expected_package_ids)) != valid_package_ids:
            failures.append("dispatch_manifest_expected_package_ids_mismatch")
    if selected_wave is not None and (
        type(selected_wave) is not int or selected_wave < 1 or selected_wave not in valid_package_waves
    ):
        failures.append("dispatch_manifest_selected_wave_invalid")
    if selection_mode is not None and (not isinstance(selection_mode, str) or not selection_mode.strip()):
        failures.append("dispatch_manifest_selection_mode_invalid")
    for field, field_failures in DISPATCH_MANIFEST_LIST_PATH_FAILURES.items():
        value = manifest.get(field)
        if value is None:
            continue
        if not isinstance(value, list):
            failures.append(field_failures["not_list"])
            continue
        if not all(isinstance(path_value, str) and path_value.strip() for path_value in value):
            failures.append(field_failures["invalid"])
            continue
        for path_value in value:
            path = Path(path_value)
            if not path.is_absolute():
                path = manifest_dir / path
            if not path_is_within(path, manifest_dir):
                failures.append(field_failures["outside"])
                break
    for field, field_failures in DISPATCH_MANIFEST_SCALAR_PATH_FAILURES.items():
        value = manifest.get(field)
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip():
            failures.append(field_failures["invalid"])
            continue
        path = Path(value)
        if not path.is_absolute():
            path = manifest_dir / path
        if not path_is_within(path, manifest_dir):
            failures.append(field_failures["outside"])
    return failures


def canonical_artifact_ref(path_value: str | Path) -> str:
    path = Path(str(path_value))
    if not path.is_absolute():
        path = REPO_ROOT / path
    return os.path.normcase(str(path.resolve(strict=False)))


def package_missing_evidence(package: dict, missing_profiles: list[str], failures: list[str]) -> dict:
    excerpt: dict[str, object] = {
        "missing_package": {
            "missing_expected_profiles": [str(value) for value in missing_profiles],
            "failures": [str(value) for value in failures],
            "required_env": [str(value) for value in package.get("required_env") or []],
            "resource_tags": [str(value) for value in package.get("resource_tags") or []],
        }
    }
    manual_reason = package.get("manual_reason")
    if manual_reason:
        excerpt["missing_package"]["manual_reason"] = str(manual_reason)
    prerequisites = [str(value) for value in package.get("manual_prerequisites") or [] if value]
    if prerequisites:
        excerpt["missing_package"]["manual_prerequisites"] = prerequisites
    operator_inputs = [
        {
            "name": str(item.get("name") or ""),
            "env": str(item.get("env") or ""),
            "flag": str(item.get("flag") or ""),
            "description": str(item.get("description") or ""),
        }
        for item in package.get("operator_inputs") or []
        if isinstance(item, dict)
    ]
    if operator_inputs:
        excerpt["missing_package"]["operator_inputs"] = operator_inputs
    return excerpt


def summarize_package_artifacts(output_dir: Path, expected_profile_ids: list[str], package: dict | None = None) -> dict:
    package = package or {}
    artifact_paths = result_artifacts(output_dir)
    status_path_value = str(package.get("status_path") or "")
    status_path = Path(status_path_value) if status_path_value else None
    if status_path is None:
        status_summary = {}
    elif not agent_status_path_is_expected(status_path, output_dir):
        status_summary = invalid_agent_status_path_summary(status_path, "agent_status_path_unexpected")
    elif not status_path.exists():
        status_summary = (
            invalid_agent_status_path_summary(status_path, "agent_status_missing")
            if artifact_paths
            else {}
        )
    else:
        status_summary = summarize_agent_status(status_path)
    agent_artifacts = [str(path) for path in status_summary.get("agent_artifacts") or []]
    for declared_artifact in agent_artifacts:
        declared_ref = stable_artifact_ref(declared_artifact)
        declared_path = Path(declared_artifact)
        if not declared_path.is_absolute():
            declared_path = REPO_ROOT / declared_path
        if (
            declared_ref.startswith("docs/benchmarks/runs/")
            and declared_path.exists()
            and declared_path.is_file()
            and canonical_artifact_ref(declared_path) not in {canonical_artifact_ref(path) for path in artifact_paths}
        ):
            artifact_paths.append(declared_path)
    artifact_summaries = [summarize_artifact(path) for path in artifact_paths]
    summaries_by_profile: dict[str, dict] = {
        str(summary.get("profile_id")): summary
        for summary in artifact_summaries
        if summary.get("profile_id")
    }

    if not expected_profile_ids:
        artifact_path = artifact_paths[0] if artifact_paths else None
        summary = summarize_artifact(artifact_path)
        return {
            **summary,
            **status_summary,
            "artifact_paths": [str(path) for path in artifact_paths],
            "expected_profile_ids": [],
            "missing_expected_profiles": [],
            "profile_results": artifact_summaries,
        }

    missing_profiles = [
        profile_id
        for profile_id in expected_profile_ids
        if profile_id not in summaries_by_profile
    ]
    unexpected_profiles = [
        str(summary.get("profile_id"))
        for summary in artifact_summaries
        if summary.get("profile_id") and str(summary.get("profile_id")) not in expected_profile_ids
    ]
    failing_expected = [
        summaries_by_profile[profile_id]
        for profile_id in expected_profile_ids
        if profile_id in summaries_by_profile and not summaries_by_profile[profile_id].get("passed")
    ]
    selected_summary = failing_expected[0] if failing_expected else (
        summaries_by_profile.get(expected_profile_ids[0]) if expected_profile_ids else None
    )
    if selected_summary is None:
        selected_summary = summarize_artifact(None)
    passed = not missing_profiles and not failing_expected and not unexpected_profiles
    failures = [str(value) for value in selected_summary.get("failures") or []]
    if missing_profiles:
        failures = ["missing_expected_profile_artifact", *failures]
    if unexpected_profiles:
        failures = ["unexpected_profile_artifact", *failures]
    status = selected_summary.get("status")
    if missing_profiles:
        status = "missing"
    elif unexpected_profiles:
        status = "fail"
    elif not passed:
        status = status or "fail"
    else:
        status = "pass"

    package_id = str(package.get("package_id") or "")
    agent_package_id = str(status_summary.get("agent_package_id") or "")
    if agent_package_id and package_id and agent_package_id != package_id:
        failures.append("agent_status_package_id_mismatch")
        passed = False
        status = "fail"
    expected_claim_id = f"claim-{package_id}" if package_id else ""
    agent_claim_id = str(status_summary.get("agent_claim_id") or "")
    if agent_claim_id and expected_claim_id and agent_claim_id != expected_claim_id:
        failures.append("agent_status_claim_id_mismatch")
        passed = False
        status = "fail"

    agent_expected_profiles = [str(profile) for profile in status_summary.get("agent_expected_profiles") or []]
    if agent_expected_profiles and agent_expected_profiles != expected_profile_ids:
        failures.append("agent_status_expected_profiles_mismatch")
        passed = False
        status = "fail"

    if agent_artifacts or (status_summary.get("agent_status") == "pass" and artifact_paths):
        actual_artifacts = {canonical_artifact_ref(path) for path in artifact_paths}
        declared_artifacts = {canonical_artifact_ref(path) for path in agent_artifacts}
        if declared_artifacts - actual_artifacts:
            failures.append("agent_status_unknown_artifact")
            passed = False
            status = "fail"
        if actual_artifacts - declared_artifacts:
            failures.append("agent_status_missing_artifact")
            passed = False
            status = "fail"

    agent_status = str(status_summary.get("agent_status") or "")
    if agent_status:
        agent_exit_code = status_summary.get("agent_exit_code")
        allowed_status = agent_status in {"pass", "fail", "blocked", "invalid"}
        if not allowed_status:
            failures.append("agent_status_unexpected")
            passed = False
            status = "fail"
        elif agent_status in {"fail", "blocked", "invalid"}:
            failures.append(f"agent_status_{agent_status}")
            if agent_status in {"fail", "blocked"} and agent_exit_code == 0:
                failures.append("agent_status_failure_exit_code_zero")
            if agent_status in {"fail", "blocked"} and not status_summary.get("agent_notes"):
                failures.append("agent_status_failure_notes_empty")
            passed = False
            status = agent_status
        elif not status_summary.get("agent_blocker_cleared"):
            failures.append("agent_status_blocker_not_cleared")
            passed = False
            status = "fail"
        elif agent_status == "pass" and agent_exit_code != 0:
            failures.append("agent_status_pass_exit_code_nonzero")
            passed = False
            status = "fail"
        agent_missing_profiles = [
            profile
            for profile in status_summary.get("agent_missing_profiles") or []
            if profile and profile not in missing_profiles
        ]
        if agent_missing_profiles:
            missing_profiles.extend(agent_missing_profiles)
            if agent_status == "pass":
                failures.append("agent_status_missing_profiles")
                passed = False
                status = "missing"
        unexpected_agent_missing_profiles = [
            profile for profile in agent_missing_profiles if profile not in expected_profile_ids
        ]
        if unexpected_agent_missing_profiles:
            failures.append("agent_status_unexpected_missing_profile")
            passed = False
            status = "fail"

    result = {
        **selected_summary,
        **status_summary,
        "status": status,
        "passed": passed,
        "failures": failures,
        "artifact_paths": [str(path) for path in artifact_paths],
        "expected_profile_ids": expected_profile_ids,
        "missing_expected_profiles": missing_profiles,
        "unexpected_profile_ids": unexpected_profiles,
        "profile_results": [
            summaries_by_profile[profile_id]
            for profile_id in expected_profile_ids
            if profile_id in summaries_by_profile
        ],
    }
    if missing_profiles and not result.get("evidence_excerpt"):
        result["evidence_excerpt"] = package_missing_evidence(package, missing_profiles, failures)
    return result


def compact_agent(agent: dict) -> dict:
    return {
        key: agent.get(key)
        for key in (
            "hostname",
            "id",
            "agent_id",
            "status",
            "health",
            "last_seen",
            "last_seen_age_seconds",
            "endpoint_telemetry",
            "live_response",
            "kernel_sensor",
            "os_type",
            "os_version",
            "reasons",
        )
        if agent.get(key) not in (None, "", [])
    }


def build_evidence_excerpt(data: dict, first_gap: dict | None) -> dict:
    def next_action_excerpt(action: dict, missing_key: str) -> dict:
        excerpt = {
            "next_action": {
                "agent_id": action.get("agent_id"),
                "host": action.get("host"),
                "node": action.get("node"),
                "vmid": action.get("vmid"),
                "caldera_url": action.get("caldera_url"),
                "requested_paw": action.get("requested_paw"),
                "requested_group": action.get("requested_group"),
                "freshness_seconds": action.get("freshness_seconds"),
                "target_agent_id": action.get("target_agent_id"),
                "target_hostname": action.get("target_hostname"),
                missing_key: [str(value) for value in action.get(missing_key) or []],
                "required_env": [str(value) for value in action.get("required_env") or []],
                "blockers": [str(value) for value in action.get("blockers") or []],
                "action": action.get("action"),
            }
        }
        if "observed_501_not_implemented" in action:
            excerpt["next_action"]["observed_501_not_implemented"] = bool(
                action.get("observed_501_not_implemented")
            )
        if "non_executed_profiles" in action:
            excerpt["next_action"]["non_executed_profiles"] = [
                str(value) for value in action.get("non_executed_profiles") or []
            ]
        if "missing_metadata_profiles" in action:
            excerpt["next_action"]["missing_metadata_profiles"] = [
                str(value) for value in action.get("missing_metadata_profiles") or []
            ]
        if isinstance(action.get("field_gaps"), dict):
            excerpt["next_action"]["field_gaps"] = action.get("field_gaps")
        if isinstance(action.get("required_inputs"), dict):
            excerpt["next_action"]["required_inputs"] = action.get("required_inputs")
        if isinstance(action.get("manual_prerequisites"), list):
            excerpt["next_action"]["manual_prerequisites"] = [
                str(value) for value in action.get("manual_prerequisites") or []
            ]
        for key in (
            "login_command",
            "token_env",
            "token_login_command",
                "saved_server",
            "target_server",
            "server_matches_target",
            "remote_config_path",
            "has_token",
            "expires_at",
        ):
            if key in action and action.get(key) is not None:
                excerpt["next_action"][key] = action.get(key)
        next_action = excerpt["next_action"]
        if (
            next_action.get("login_command")
            and next_action.get("target_server")
            and not next_action.get("token_login_command")
        ):
            next_action["token_env"] = "TAMANDUA_TOKEN"
            next_action["token_login_command"] = (
                "tamandua-ctl remote login --server "
                f"{next_action['target_server']} --token $env:TAMANDUA_TOKEN"
            )
        return excerpt

    inferred_auth_action = infer_auth_next_action_from_artifact(data)
    if inferred_auth_action:
        return next_action_excerpt(inferred_auth_action, "missing_readiness")

    for container_name, missing_key in (
        ("connection_stability", "missing_stability"),
        ("proxmox_qga_readiness", "missing_readiness"),
        ("proxmox_qga_file_diagnostics", "missing_diagnostics"),
        ("caldera_api_shape", "missing_endpoints"),
        ("caldera_paw_readiness", "missing_readiness"),
        ("fresh_restore_provenance", "missing_profiles"),
        ("macos_backend_readiness", "missing_readiness"),
    ):
        container = data.get(container_name) if isinstance(data.get(container_name), dict) else {}
        action = container.get("next_action") if isinstance(container.get("next_action"), dict) else {}
        if action:
            return next_action_excerpt(action, missing_key)

    if not first_gap:
        return {}

    first_gap_id = first_gap.get("test_id")
    quality_gate = data.get("quality_gate") or {}
    for gap in quality_gate.get("actionable_gaps") or []:
        if isinstance(gap, dict) and gap.get("test_id") == first_gap_id:
            evidence = gap.get("evidence") if isinstance(gap.get("evidence"), dict) else {}
            action = evidence.get("next_action") if isinstance(evidence.get("next_action"), dict) else {}
            if action:
                return next_action_excerpt(action, "missing_readiness")
            agents = evidence.get("macos_agents")
            if isinstance(agents, list) and agents:
                return {"agent": compact_agent(agents[0])}
            target = evidence.get("target")
            if isinstance(target, dict):
                return {"agent": compact_agent(target)}
            return {
                "missing": [str(value) for value in gap.get("missing") or []],
                "gap_category": gap.get("gap_category"),
            }

    for test in data.get("tests") or []:
        if not isinstance(test, dict):
            continue
        if (test.get("id") or test.get("test_id")) != first_gap_id:
            continue
        evidence = test.get("evidence") if isinstance(test.get("evidence"), dict) else {}
        target = evidence.get("target")
        if isinstance(target, dict):
            return {"agent": compact_agent(target)}
        missing = first_gap.get("missing") if isinstance(first_gap.get("missing"), list) else evidence.get("missing")
        excerpt = {"gap_category": test.get("gap_category")}
        if isinstance(missing, list) and missing:
            excerpt["missing"] = [str(value) for value in missing]
        return excerpt
    return {}


def build_dispatch_results(manifest: dict) -> dict:
    packages = []
    manifest_path_value = manifest.get("manifest_path")
    manifest_dir = Path(str(manifest_path_value)).parent if manifest_path_value else Path.cwd()
    manifest_failures = dispatch_manifest_validation_failures(manifest)
    raw_packages = manifest.get("packages") if isinstance(manifest.get("packages"), list) else []
    manifest_packages = [package for package in raw_packages if isinstance(package, dict)]
    if manifest_failures and not manifest_packages:
        manifest_packages = [{"package_id": "dispatch_manifest", "wave": None, "output_dir": str(manifest_dir)}]
    for package in manifest_packages:
        output_dir = resolve_manifest_package_output_dir(package.get("output_dir"), manifest_dir)
        expected_profile_ids = [
            str(value) for value in package_expected_profile_ids(package) or []
        ]
        package_failures = manifest_package_validation_failures(package)
        if manifest_failures:
            artifact_summary = invalid_manifest_package_summary(manifest_failures)
        elif package_failures:
            artifact_summary = invalid_manifest_package_summary(package_failures)
        elif not path_is_within(output_dir, manifest_dir):
            artifact_summary = invalid_package_output_summary(output_dir, "dispatch_output_dir_outside_manifest")
        else:
            artifact_summary = summarize_package_artifacts(output_dir, expected_profile_ids, package)
        current_next_action = package_current_next_action_or_task(
            package,
            package.get("current_next_action") if isinstance(package.get("current_next_action"), dict) else {},
        )
        if current_next_action:
            evidence_excerpt = artifact_summary.get("evidence_excerpt")
            if not isinstance(evidence_excerpt, dict):
                evidence_excerpt = {}
            evidence_excerpt.setdefault("next_action", compact_next_action(current_next_action))
            artifact_summary["evidence_excerpt"] = evidence_excerpt
        packages.append(
            {
                "package_id": package.get("package_id"),
                "wave": package.get("wave"),
                "launcher_selected": package.get("launcher_selected"),
                "manual_reason": package.get("manual_reason"),
                "staged_launcher_selected": package.get("staged_launcher_selected"),
                "staged_stage": package.get("staged_stage"),
                "title": package.get("title"),
                "recommended_owner_role": package.get("recommended_owner_role"),
                "parallelizable_in_wave": package.get("parallelizable_in_wave"),
                "depends_on_waves": package.get("depends_on_waves") or [],
                "handoff_notes": package.get("handoff_notes") or [],
                "resource_tags": package.get("resource_tags") or [],
                "required_env": package.get("required_env") or [],
                "effective_required_env": package.get("effective_required_env") or package.get("required_env") or [],
                "roadmaps": package.get("roadmaps") or [],
                "blocking_profiles": package.get("blocking_profiles") or [],
                "blocked_run_classes": package.get("blocked_run_classes") or [],
                "output_dir": str(output_dir),
                **artifact_summary,
            }
        )
    status_counts = dispatch_package_status_counts(packages)
    required_env_blockers = dispatch_required_env_blockers(packages)
    owner_handoff = dispatch_owner_handoff(packages)
    return {
        "profile_id": manifest.get("profile_id") or PROFILE_ID,
        "source_preflight": manifest.get("source_preflight"),
        "dispatch_manifest": manifest.get("manifest_path"),
        "manifest_failures": manifest_failures,
        "summarized_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "packages": packages,
        "passed_count": sum(1 for package in packages if package.get("passed")),
        "failed_count": sum(1 for package in packages if not package.get("passed")),
        "status_counts": status_counts,
        "blocked_count": status_counts["blocked"],
        "failed_status_count": status_counts["fail"],
        "missing_count": status_counts["missing"],
        "invalid_count": status_counts["invalid"],
        "missing_required_env": sorted(
            {
                env_name
                for blocker in required_env_blockers
                for env_name in blocker.get("missing_required_env", [])
            }
        ),
        "required_env_blockers": required_env_blockers,
        "owner_handoff": owner_handoff,
    }


def dispatch_package_status_counts(packages: list[dict]) -> dict[str, int]:
    counts = {
        "pass": 0,
        "fail": 0,
        "blocked": 0,
        "missing": 0,
        "invalid": 0,
        "unknown": 0,
    }
    for package in packages:
        status = str(package.get("status") or "").strip().lower()
        if status not in counts:
            status = "unknown"
        counts[status] += 1
    return counts


def dispatch_required_env_blockers(packages: list[dict]) -> list[dict]:
    blockers = []
    for package in packages:
        missing_env = [str(value) for value in package.get("agent_missing_required_env") or []]
        if not missing_env:
            continue
        blockers.append(
            {
                "package_id": package.get("package_id"),
                "wave": package.get("wave"),
                "title": package.get("title"),
                "recommended_owner_role": package.get("recommended_owner_role"),
                "status": package.get("status"),
                "roadmaps": [str(value) for value in package.get("roadmaps") or []],
                "blocking_profiles": [str(value) for value in package.get("blocking_profiles") or []],
                "blocked_run_classes": [str(value) for value in package.get("blocked_run_classes") or []],
                "missing_required_env": missing_env,
                "declared_required_env": [str(value) for value in package.get("effective_required_env") or package.get("required_env") or []],
            }
        )
    return blockers


def dispatch_owner_handoff(packages: list[dict]) -> list[dict]:
    owners: dict[str, dict] = {}
    for package in packages:
        owner = str(package.get("recommended_owner_role") or "unassigned")
        entry = owners.setdefault(
            owner,
            {
                "owner": owner,
                "package_count": 0,
                "passed_count": 0,
                "blocked_count": 0,
                "failed_status_count": 0,
                "missing_count": 0,
                "invalid_count": 0,
                "packages": [],
                "missing_required_env": [],
                "roadmaps": [],
            },
        )
        status = str(package.get("status") or "").strip().lower()
        entry["package_count"] += 1
        if bool(package.get("passed")):
            entry["passed_count"] += 1
        if status == "blocked":
            entry["blocked_count"] += 1
        elif status == "fail":
            entry["failed_status_count"] += 1
        elif status == "missing":
            entry["missing_count"] += 1
        elif status == "invalid":
            entry["invalid_count"] += 1
        entry["packages"].append(
            {
                "package_id": package.get("package_id"),
                "wave": package.get("wave"),
                "status": package.get("status"),
                "title": package.get("title"),
                "parallelizable_in_wave": package.get("parallelizable_in_wave"),
                "depends_on_waves": package.get("depends_on_waves") or [],
                "handoff_notes": package.get("handoff_notes") or [],
            }
        )
        for env_name in package.get("agent_missing_required_env") or []:
            value = str(env_name)
            if value not in entry["missing_required_env"]:
                entry["missing_required_env"].append(value)
        for roadmap in package.get("roadmaps") or []:
            value = str(roadmap)
            if value not in entry["roadmaps"]:
                entry["roadmaps"].append(value)

    for entry in owners.values():
        entry["missing_required_env"] = sorted(entry["missing_required_env"])
        entry["roadmaps"] = sorted(entry["roadmaps"])
    return sorted(owners.values(), key=lambda item: item["owner"])


def render_dispatch_results_markdown(results: dict) -> str:
    def md_cell(value: object) -> str:
        text = str(value if value is not None else "-")
        return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")

    lines = [
        "# Dispatch Results",
        "",
        f"- Source preflight: `{results.get('source_preflight')}`",
        f"- Passed packages: `{results.get('passed_count')}`",
        f"- Failed/missing packages: `{results.get('failed_count')}`",
        f"- Blocked packages: `{results.get('blocked_count', 0)}`",
        f"- Failed packages with artifacts: `{results.get('failed_status_count', 0)}`",
        f"- Missing packages: `{results.get('missing_count', 0)}`",
        f"- Invalid packages: `{results.get('invalid_count', 0)}`",
        f"- Missing required env: `{', '.join(str(value) for value in results.get('missing_required_env') or []) or '-'}`",
        "",
    ]
    owner_handoff = results.get("owner_handoff") or []
    if owner_handoff:
        lines.extend(
            [
                "## Owner Handoff",
                "",
                "| Owner | Packages | Passed | Blocked | Failed | Missing env | Roadmaps |",
                "|---|---:|---:|---:|---:|---|---|",
            ]
        )
        for owner in owner_handoff:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{md_cell(owner.get('owner'))}`",
                        md_cell(owner.get("package_count")),
                        md_cell(owner.get("passed_count")),
                        md_cell(owner.get("blocked_count")),
                        md_cell(owner.get("failed_status_count")),
                        ", ".join(f"`{md_cell(value)}`" for value in owner.get("missing_required_env") or []) or "-",
                        ", ".join(f"`{md_cell(value)}`" for value in owner.get("roadmaps") or []) or "-",
                    ]
                )
                + " |"
            )
        lines.append("")
        lines.extend(
            [
                "## Owner Package Queue",
                "",
                "| Owner | Package | Wave | Status | Title | Depends on waves | Parallel in wave | Handoff notes |",
                "|---|---|---:|---|---|---|---|---|",
            ]
        )
        for owner in owner_handoff:
            for package in owner.get("packages") or []:
                depends_on = package.get("depends_on_waves") or []
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            f"`{md_cell(owner.get('owner'))}`",
                            f"`{md_cell(package.get('package_id'))}`",
                            md_cell(package.get("wave") or "-"),
                            f"`{md_cell(package.get('status'))}`",
                            md_cell(package.get("title") or "-"),
                            ", ".join(f"`{md_cell(value)}`" for value in depends_on) or "-",
                            md_cell(str(bool(package.get("parallelizable_in_wave"))).lower()),
                            ", ".join(f"`{md_cell(value)}`" for value in package.get("handoff_notes") or []) or "-",
                        ]
                    )
                    + " |"
                )
        lines.append("")
    required_env_blockers = results.get("required_env_blockers") or []
    if required_env_blockers:
        lines.extend(
            [
                "## Required Env Blockers",
                "",
                "| Package | Wave | Owner | Roadmaps | Missing env | Blocking profiles |",
                "|---|---:|---|---|---|---|",
            ]
        )
        for blocker in required_env_blockers:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{md_cell(blocker.get('package_id'))}`",
                        md_cell(blocker.get("wave") or "-"),
                        f"`{md_cell(blocker.get('recommended_owner_role') or '-')}`",
                        ", ".join(f"`{md_cell(value)}`" for value in blocker.get("roadmaps") or []) or "-",
                        ", ".join(f"`{md_cell(value)}`" for value in blocker.get("missing_required_env") or []) or "-",
                        ", ".join(f"`{md_cell(value)}`" for value in blocker.get("blocking_profiles") or []) or "-",
                    ]
                )
                + " |"
            )
        lines.append("")
    lines.extend(
        [
            "| Package | Wave | Selected | Status | Artifact | Blockers | First gap |",
            "|---|---:|---|---|---|---|---|",
        ]
    )
    for package in results.get("packages") or []:
        first_gap = package.get("first_gap") or {}
        first_gap_text = first_gap.get("test_id") or "-"
        blockers = package.get("blocking_gaps") or package.get("failures") or []
        artifact = package.get("artifact_path") or "-"
        selected = package.get("launcher_selected")
        selected_text = "-" if selected is None else str(bool(selected)).lower()
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{md_cell(package.get('package_id'))}`",
                    md_cell(package.get("wave") or "-"),
                    md_cell(selected_text),
                    f"`{md_cell(package.get('status'))}`",
                    f"`{md_cell(artifact)}`",
                    ", ".join(f"`{md_cell(value)}`" for value in blockers) or "-",
                    f"`{md_cell(first_gap_text)}`",
                ]
            )
            + " |"
        )
        if package.get("agent_status_path") or package.get("agent_status"):
            details = []
            if package.get("agent_status"):
                details.append("status=" + str(package.get("agent_status")))
            if package.get("agent_exit_code") is not None:
                details.append("exit_code=" + str(package.get("agent_exit_code")))
            if package.get("agent_blocker_cleared") is not None:
                details.append("blocker_cleared=" + str(bool(package.get("agent_blocker_cleared"))).lower())
            notes = package.get("agent_notes") or []
            if notes:
                details.append("notes=" + ", ".join(str(value) for value in notes))
            missing_env = package.get("agent_missing_required_env") or []
            if missing_env:
                details.append("missing_required_env=" + ", ".join(str(value) for value in missing_env))
            lines.append(f"| | | | | | agent status | `{md_cell('; '.join(details) or '-')}` |")
        evidence = package.get("evidence_excerpt") or {}
        agent = evidence.get("agent") if isinstance(evidence, dict) else None
        if isinstance(agent, dict) and agent:
            agent_bits = []
            for key in ("hostname", "status", "health", "last_seen", "last_seen_age_seconds", "endpoint_telemetry", "live_response"):
                if agent.get(key) not in (None, "", []):
                    agent_bits.append(f"{key}={agent[key]}")
            if agent_bits:
                lines.append(f"| | | | | | evidence | `{md_cell('; '.join(agent_bits))}` |")
        elif isinstance(evidence, dict) and evidence.get("missing"):
            lines.append(f"| | | | | | evidence | `{md_cell(', '.join(evidence['missing']))}` |")
        elif isinstance(evidence, dict) and isinstance(evidence.get("missing_package"), dict):
            missing_package = evidence["missing_package"]
            details = []
            required_env = missing_package.get("required_env")
            if isinstance(required_env, list) and required_env:
                details.append("required_env=" + ", ".join(str(value) for value in required_env))
            missing_profiles = missing_package.get("missing_expected_profiles")
            if isinstance(missing_profiles, list) and missing_profiles:
                details.append("missing_profiles=" + ", ".join(str(value) for value in missing_profiles))
            manual_reason = missing_package.get("manual_reason")
            if manual_reason:
                details.append("manual_reason=" + str(manual_reason))
            next_action = evidence.get("next_action")
            if isinstance(next_action, dict) and next_action:
                details.append("next_action=" + render_current_next_action_summary(next_action))
            lines.append(f"| | | | | | missing package | `{md_cell('; '.join(details) or '-')}` |")
        elif isinstance(evidence, dict) and isinstance(evidence.get("next_action"), dict):
            action = evidence["next_action"]
            missing_values = (
                action.get("missing_stability")
                or action.get("missing_readiness")
                or action.get("missing_diagnostics")
                or action.get("missing_endpoints")
                or action.get("missing_profiles")
                or []
            )
            missing = ", ".join(str(value) for value in missing_values) or "-"
            action_text = str(action.get("action") or "-")
            action_details = [f"missing={missing}", f"action={action_text}"]
            if action.get("login_command"):
                action_details.append("login_command=" + str(action.get("login_command")))
            if action.get("token_login_command"):
                action_details.append("token_login_command=" + str(action.get("token_login_command")))
            lines.append(f"| | | | | | next action | `{md_cell('; '.join(action_details))}` |")
        for profile_result in package.get("profile_results") or []:
            if not isinstance(profile_result, dict):
                continue
            profile_evidence = profile_result.get("evidence_excerpt")
            if not isinstance(profile_evidence, dict):
                continue
            action = profile_evidence.get("next_action")
            if not isinstance(action, dict):
                continue
            profile_id = str(profile_result.get("profile_id") or "-")
            missing_values = (
                action.get("missing_stability")
                or action.get("missing_readiness")
                or action.get("missing_diagnostics")
                or action.get("missing_endpoints")
                or action.get("missing_profiles")
                or []
            )
            missing = ", ".join(str(value) for value in missing_values) or "-"
            action_text = str(action.get("action") or "-")
            action_details = [f"missing={missing}", f"action={action_text}"]
            if action.get("login_command"):
                action_details.append("login_command=" + str(action.get("login_command")))
            if action.get("token_login_command"):
                action_details.append("token_login_command=" + str(action.get("token_login_command")))
            lines.append(
                f"| | | | | | `{md_cell(profile_id)}` next action | `{md_cell('; '.join(action_details))}` |"
            )
    lines.append("")
    return "\n".join(lines)


def normalize_dispatch_result_refs(results: dict) -> dict:
    for field_name in ("dispatch_manifest", "source_preflight"):
        if results.get(field_name):
            results[field_name] = stable_artifact_ref(results[field_name])
    for package in results.get("packages") or []:
        if not isinstance(package, dict):
            continue
        for field_name in ("output_dir", "agent_status_path", "artifact_path"):
            if package.get(field_name):
                package[field_name] = stable_artifact_ref(package[field_name])
        for field_name in ("artifact_paths", "agent_artifacts", "archived_artifacts"):
            if isinstance(package.get(field_name), list):
                package[field_name] = [stable_artifact_ref(value) for value in package[field_name]]
        for profile_result in package.get("profile_results") or []:
            if not isinstance(profile_result, dict):
                continue
            if profile_result.get("artifact_path"):
                profile_result["artifact_path"] = stable_artifact_ref(profile_result["artifact_path"])
    return results


def summarize_dispatch(manifest_or_dir: Path) -> tuple[Path, Path]:
    manifest_path = manifest_or_dir
    if manifest_path.is_dir():
        manifest_path = manifest_path / "dispatch_manifest.json"
    manifest = load_json(manifest_path)
    manifest["manifest_path"] = str(manifest_path)
    results = normalize_dispatch_result_refs(build_dispatch_results(manifest))
    output_dir = manifest_path.parent
    json_path = output_dir / "dispatch_results.json"
    markdown_path = output_dir / "dispatch_results.md"
    json_path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_dispatch_results_markdown(results), encoding="utf-8")
    return json_path, markdown_path


def archive_dispatch_evidence(results: dict, manifest_path: Path, archive_dir: Path) -> dict:
    archive_dir.mkdir(parents=True, exist_ok=True)
    manifest = load_json(manifest_path) if manifest_path.exists() else None
    package_root = archive_dir / "packages"

    if manifest:
        replacements: dict[str, str] = {}
        copied_handoff_paths: list[Path] = []
        if manifest.get("source_preflight"):
            source_preflight = manifest.get("source_preflight")
            manifest["source_preflight"] = stable_artifact_ref(manifest.get("source_preflight"))
            results["source_preflight"] = manifest["source_preflight"]
            for old in replacement_variants(source_preflight):
                replacements[old] = manifest["source_preflight"]
        original_output_dir = manifest.get("output_dir")
        manifest["output_dir"] = repo_relative(archive_dir)
        for old in replacement_variants(original_output_dir):
            replacements[old] = manifest["output_dir"]
        launcher_paths = []
        copied_launcher_paths = []
        launcher_root = archive_dir / "launchers"
        for manifest_field in ("launcher_paths", "staged_launcher_paths"):
            archived_launcher_paths = []
            for launcher_value in manifest.get(manifest_field) or []:
                launcher_path = Path(str(launcher_value))
                if launcher_path.exists() and launcher_path.is_file():
                    launcher_root.mkdir(parents=True, exist_ok=True)
                    launcher_dest = launcher_root / launcher_path.name
                    shutil.copy2(launcher_path, launcher_dest)
                    copied_launcher_paths.append(launcher_dest)
                    archived_launcher_paths.append(repo_relative(launcher_dest))
                    for old in replacement_variants(launcher_value):
                        replacements[old] = repo_relative(launcher_dest)
            manifest[manifest_field] = archived_launcher_paths
        for manifest_field in (
            "agent_roster_path",
            "env_checklist_path",
            "env_template_path",
            "owner_launch_plan_path",
            "owner_launch_plan_json_path",
            "execution_matrix_path",
            "execution_matrix_json_path",
            "agent_claims_path",
            "agent_claims_json_path",
            "agent_spawn_plan_path",
            "agent_spawn_plan_json_path",
            "agent_spawn_launcher_path",
            "claim_status_report_path",
            "claim_status_report_json_path",
            "claim_lock_helper_path",
            "env_unblock_queue_path",
            "env_unblock_queue_json_path",
            "ready_claims_launcher_path",
            "ready_claims_parallel_launcher_path",
            "env_bundle_ready_claims_launcher_path",
            "dispatch_brief_path",
            "dispatch_prelaunch_validation_path",
            "dispatch_runner_path",
        ):
            handoff_value = manifest.get(manifest_field)
            if not handoff_value:
                continue
            handoff_path = Path(str(handoff_value))
            if handoff_path.exists() and handoff_path.is_file():
                handoff_dest = archive_dir / handoff_path.name
                shutil.copy2(handoff_path, handoff_dest)
                manifest[manifest_field] = repo_relative(handoff_dest)
                copied_handoff_paths.append(handoff_dest)
                for old in replacement_variants(handoff_value):
                    replacements[old] = manifest[manifest_field]
            else:
                manifest[manifest_field] = None

        handoff_root = archive_dir / "handoffs"
        for manifest_package in manifest.get("packages") or []:
            if not isinstance(manifest_package, dict):
                continue
            package_id = str(manifest_package.get("package_id") or "package")
            package_dir = package_root / safe_filename(package_id)
            original_output_dir = manifest_package.get("output_dir")
            manifest_package["output_dir"] = repo_relative(package_dir)
            for old in replacement_variants(original_output_dir):
                replacements[old] = manifest_package["output_dir"]
            original_status_path = manifest_package.get("status_path")
            if original_status_path:
                manifest_package["status_path"] = repo_relative(package_dir / "agent_status.json")
                for old in replacement_variants(original_status_path):
                    replacements[old] = manifest_package["status_path"]
            for field_name in ("script_path", "prompt_path"):
                handoff_value = manifest_package.get(field_name)
                if not handoff_value:
                    continue
                handoff_path = Path(str(handoff_value))
                if handoff_path.exists() and handoff_path.is_file():
                    package_handoff_dir = handoff_root / safe_filename(package_id)
                    package_handoff_dir.mkdir(parents=True, exist_ok=True)
                    handoff_dest = package_handoff_dir / handoff_path.name
                    shutil.copy2(handoff_path, handoff_dest)
                    copied_handoff_paths.append(handoff_dest)
                    manifest_package[field_name] = repo_relative(handoff_dest)
                    for old in replacement_variants(handoff_value):
                        replacements[old] = manifest_package[field_name]
                else:
                    manifest_package[field_name] = None

        manifest_dest = archive_dir / "dispatch_manifest.json"
        for old in replacement_variants(manifest_path):
            replacements[old] = repo_relative(manifest_dest)

        for copied_path in [*copied_launcher_paths, *copied_handoff_paths]:
            rewrite_archived_handoff_file(copied_path, replacements)

        manifest_dest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        results["dispatch_manifest"] = repo_relative(manifest_dest)

    for package in results.get("packages") or []:
        package_dir = package_root / safe_filename(str(package.get("package_id") or "package"))
        package["output_dir"] = repo_relative(package_dir)
        package_dir.mkdir(parents=True, exist_ok=True)
        artifact_values = [str(value) for value in package.get("artifact_paths") or []]
        artifact_value = package.get("artifact_path")
        if artifact_value and str(artifact_value) not in artifact_values:
            artifact_values.insert(0, str(artifact_value))
        status_value = package.get("agent_status_path")
        status_dest = None
        if status_value:
            status_path = Path(str(status_value))
            if status_path.exists() and status_path.is_file():
                status_dest = package_dir / "agent_status.json"
                shutil.copy2(status_path, status_dest)
                enrich_archived_agent_status(status_dest, str(package.get("package_id") or ""))
                package["agent_status_path"] = repo_relative(status_dest)
            else:
                package.pop("agent_status_path", None)
        if not artifact_values:
            continue
        copied_paths = []
        artifact_replacements: dict[str, str] = {}
        primary_artifact_name = Path(str(artifact_value)).name if artifact_value else ""
        for artifact_source in artifact_values:
            artifact_path = Path(str(artifact_source))
            if not artifact_path.exists():
                continue
            for sibling in sorted(artifact_path.parent.glob(f"{artifact_path.stem}*")):
                if sibling.is_file():
                    dest = package_dir / sibling.name
                    shutil.copy2(sibling, dest)
                    archived_ref = repo_relative(dest)
                    copied_paths.append(archived_ref)
                    for old in replacement_variants(str(sibling)):
                        artifact_replacements[old] = archived_ref
        if copied_paths:
            if primary_artifact_name:
                package["artifact_path"] = repo_relative(package_dir / primary_artifact_name)
            package["artifact_paths"] = [
                path
                for path in copied_paths
                if path.endswith(".json") and not path.endswith(".comparison.json")
            ]
            for profile_result in package.get("profile_results") or []:
                if not isinstance(profile_result, dict):
                    continue
                profile_artifact = profile_result.get("artifact_path")
                if profile_artifact:
                    profile_result["artifact_path"] = replace_artifact_ref(
                        str(profile_artifact),
                        artifact_replacements,
                    )
            package["agent_artifacts"] = [
                replace_artifact_ref(str(path), artifact_replacements)
                for path in package.get("agent_artifacts") or []
            ]
            package["archived_artifacts"] = sorted(set(copied_paths))
        if status_dest and status_dest.exists():
            rewrite_archived_handoff_file(status_dest, {**replacements, **artifact_replacements})
        if artifact_replacements:
            for copied_path in copied_handoff_paths:
                rewrite_archived_handoff_file(copied_path, artifact_replacements)
    return results


def promote_dispatch_results(manifest_or_dir: Path, runs_dir: Path = RUNS_DIR) -> tuple[Path, Path, Path]:
    manifest_path = manifest_or_dir
    if manifest_path.is_dir():
        manifest_path = manifest_path / "dispatch_manifest.json"
    manifest = load_json(manifest_path)
    validate_dispatch_manifest_source(manifest, runs_dir)
    manifest["manifest_path"] = str(manifest_path)
    results = build_dispatch_results(manifest)
    now = datetime.now(timezone.utc)
    run_id = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{DISPATCH_RESULTS_PROFILE_ID}"
    archive_dir = runs_dir / f"{run_id}.package-artifacts"
    results = archive_dispatch_evidence(results, manifest_path, archive_dir)
    packages = results.get("packages") or []
    tests = tests_from_dispatch_packages(packages)
    covered = sum(1 for test in tests if test.get("status") == "covered")
    missed = len(tests) - covered
    passed = bool(packages) and all(package.get("passed") for package in packages)
    report = {
        **results,
        "run_id": run_id,
        "profile_id": DISPATCH_RESULTS_PROFILE_ID,
        "profile": DISPATCH_RESULTS_PROFILE_ID,
        "benchmark_lane": "claim-boundary",
        "claim_boundary": (
            "Dispatch-results coordination artifact only. It summarizes package scripts "
            "and their latest local output artifacts; it does not promote package artifacts "
            "to official roadmap evidence or claim closure."
        ),
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "summary": {
            "tests": len(tests),
            "total": len(tests),
            "covered": covered,
            "missed": missed,
            "partial": 0,
            "planned": 0,
            "skipped": 0,
            "execution_failed": 0,
            "category_coverage": {
                "validation_dispatch_results": {
                    "covered": covered,
                    "missed": missed,
                }
            },
        },
        "tests": tests,
        "quality_gate": {
            "passed": passed,
            "status": "pass" if passed else "fail",
            "failures": [] if passed else ["dispatch_results_incomplete"],
            "blocking_gaps": [] if passed else [
                str(package.get("package_id"))
                for package in packages
                if not package.get("passed")
            ],
        },
    }
    runs_dir.mkdir(parents=True, exist_ok=True)
    json_path = runs_dir / f"{run_id}.json"
    markdown_path = runs_dir / f"{run_id}.md"
    comparison_path = runs_dir / f"{run_id}.comparison.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_dispatch_results_markdown(report), encoding="utf-8")
    (archive_dir / "dispatch_results.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (archive_dir / "dispatch_results.md").write_text(
        render_dispatch_results_markdown(report),
        encoding="utf-8",
    )
    comparison = {
        "schema_version": 1,
        "profile_id": DISPATCH_RESULTS_PROFILE_ID,
        "benchmark_lane": report["benchmark_lane"],
        "claim_boundary": report["claim_boundary"],
        "quality_gate": report["quality_gate"],
        "summary": {
            "passed_count": report.get("passed_count"),
            "failed_count": report.get("failed_count"),
            "status_counts": report.get("status_counts"),
            "blocked_count": report.get("blocked_count"),
            "failed_status_count": report.get("failed_status_count"),
            "missing_count": report.get("missing_count"),
            "invalid_count": report.get("invalid_count"),
            "missing_required_env": report.get("missing_required_env"),
            "required_env_blockers": report.get("required_env_blockers"),
            "owner_handoff": report.get("owner_handoff"),
            "covered": covered,
            "tests": len(tests),
            "source_preflight": report.get("source_preflight"),
            "dispatch_manifest": report.get("dispatch_manifest"),
        },
        "tests": tests,
        "packages": packages,
    }
    comparison_path.write_text(json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return json_path, markdown_path, comparison_path


def tests_from_dispatch_packages(packages: list[dict]) -> list[dict]:
    tests = []
    for package in packages:
        package_id = str(package.get("package_id") or "package")
        passed = bool(package.get("passed"))
        first_gap = package.get("first_gap") if isinstance(package.get("first_gap"), dict) else {}
        missing = []
        if first_gap:
            missing = [str(value) for value in first_gap.get("missing") or []]
        elif not passed:
            missing = [str(value) for value in package.get("failures") or ["dispatch_package_incomplete"]]
        tests.append(
            {
                "id": f"dispatch-package-{safe_filename(package_id)}",
                "name": f"Dispatch package {package_id}",
                "status": "covered" if passed else "missed",
                "gap_category": None if passed else "dispatch-results",
                "validation_category": "validation_dispatch_results",
                "execution_class": "local_dispatch_result_summary",
                "fallback_used": False,
                "claim_level": "dispatch_results_claim_boundary",
                "tactics": [],
                "techniques": [],
                "evidence": {
                    "package_id": package_id,
                    "artifact_path": package.get("artifact_path"),
                    "profile_id": package.get("profile_id"),
                    "run_id": package.get("run_id"),
                    "status": package.get("status"),
                    "first_gap": first_gap or None,
                    "evidence_excerpt": package.get("evidence_excerpt") or {},
                },
                "missing_expected_fields": [] if passed else missing,
                "missing_expected_telemetry": [],
                "missing_expected_detections": [],
                "missing_expected_alerts": [],
                "missing_expected_correlations": [],
                "missing_expected_driver_raw_event_types": [],
            }
        )
    return tests


def package_list_entry(package: dict, environ: dict[str, str] | None = None) -> dict:
    required_env = [str(value) for value in package.get("required_env") or []]
    missing_env = missing_required_env(package, environ)
    dependencies = dependent_waves(package)
    input_details = env_details_by_env(package)
    return {
        "package_id": str(package.get("package_id") or ""),
        "title": str(package.get("title") or ""),
        "wave": int(package.get("wave") or 0),
        "recommended_owner_role": str(package.get("recommended_owner_role") or ""),
        "parallelizable_in_wave": bool(package.get("parallelizable_in_wave")),
        "handoff_notes": package_handoff_notes(package, environ=environ),
        "resource_tags": package_manifest_resource_tags(package),
        "required_env": required_env,
        "next_action_required_env": package_next_action_env(package),
        "effective_required_env": package_effective_env(package),
        "env_details": {
            env_name: input_details.get(env_name, {"name": "", "flag": "", "description": ""})
            for env_name in package_effective_env(package)
        },
        "missing_env": missing_env,
        "missing_effective_env": [
            name
            for name in package_effective_env(package)
            if not (environ if environ is not None else os.environ).get(name)
        ],
        "depends_on_waves": dependencies,
        "roadmaps": [str(value) for value in package.get("roadmaps") or []],
        "expected_profile_ids": [str(value) for value in package.get("expected_profile_ids") or []],
        "safe_commands": [str(value) for value in package.get("safe_commands") or []],
        "roadmap_next_actions": [
            {
                "roadmap": str(action.get("roadmap") or ""),
                "roadmap_status": str(action.get("roadmap_status") or ""),
                "required_env": [str(value) for value in action.get("required_env") or []],
                "action": str(action.get("action") or ""),
            }
            for action in package.get("roadmap_next_actions") or []
            if isinstance(action, dict)
        ],
    }


def package_list_entries(packages: list[dict], environ: dict[str, str] | None = None) -> list[dict]:
    return [
        package_list_entry(package, environ)
        for package in sorted(packages, key=lambda item: (int(item.get("wave") or 0), str(item.get("package_id") or "")))
    ]


def print_package_list(packages: list[dict]) -> None:
    for package in sorted(packages, key=lambda item: (int(item.get("wave") or 0), str(item.get("package_id") or ""))):
        package_id = package.get("package_id")
        title = package.get("title")
        wave = package.get("wave")
        owner = package.get("recommended_owner_role")
        parallel = "parallel" if package.get("parallelizable_in_wave") else "serial"
        print(f"{package_id}\twave={wave}\towner={owner}\t{parallel}\t{title}")


def print_package_detail_list(packages: list[dict]) -> None:
    for entry in package_list_entries(packages):
        parallel = "parallel" if entry["parallelizable_in_wave"] else "serial"
        print(
            f"{entry['package_id']}\twave={entry['wave']}\t"
            f"owner={entry['recommended_owner_role']}\t{parallel}\t{entry['title']}"
        )
        print(f"  resources: {', '.join(entry['resource_tags']) or '-'}")
        print(f"  roadmaps: {', '.join(entry['roadmaps']) or '-'}")
        print(f"  depends_on_waves: {', '.join(str(value) for value in entry['depends_on_waves']) or '-'}")
        print(f"  expected_profiles: {', '.join(entry['expected_profile_ids']) or '-'}")
        print(f"  handoff_notes: {', '.join(entry['handoff_notes']) or '-'}")
        print(f"  required_env: {', '.join(entry['required_env']) or '-'}")
        print(f"  next_action_required_env: {', '.join(entry['next_action_required_env']) or '-'}")
        print(f"  effective_required_env: {', '.join(entry['effective_required_env']) or '-'}")
        print(f"  missing_env: {', '.join(entry['missing_env']) or '-'}")
        print(f"  missing_effective_env: {', '.join(entry['missing_effective_env']) or '-'}")
        detailed_env = [
            f"{env_name} flag={details.get('flag') or '-'}"
            for env_name, details in entry["env_details"].items()
            if details.get("flag") or details.get("description")
        ]
        if detailed_env:
            print(f"  env_details: {'; '.join(detailed_env)}")
        if entry["roadmap_next_actions"]:
            print("  roadmap_next_actions:")
            for action in entry["roadmap_next_actions"]:
                action_env = ", ".join(action["required_env"]) or "-"
                print(
                    f"    - {action['roadmap']} ({action['roadmap_status']}), "
                    f"required_env={action_env}: {action['action']}"
                )
        print("  safe_commands:")
        for command in entry["safe_commands"]:
            print(f"    {command}")


def execute_script(script_path: Path) -> int:
    shell = "powershell.exe" if os.name == "nt" else "pwsh"
    completed = subprocess.run(
        [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
        cwd=REPO_ROOT,
        check=False,
    )
    return int(completed.returncode)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Materialize safe validation preflight work-package commands as PowerShell scripts."
    )
    parser.add_argument("--summarize-dispatch", type=Path, help="Read a dispatch manifest/dir and write results summary.")
    parser.add_argument("--promote-dispatch-results", type=Path, help="Write dispatch results as an official runs artifact.")
    parser.add_argument(
        "--refresh-claim-status-report",
        type=Path,
        help="Refresh claim_status_report.md/json from a dispatch manifest after claim locks or agent statuses change.",
    )
    parser.add_argument(
        "--refresh-dispatch-handoff-artifacts",
        type=Path,
        help="Refresh status-sensitive dispatch handoff artifacts from a dispatch manifest.",
    )
    parser.add_argument("--runs-output-dir", type=Path, default=RUNS_DIR, help="Runs directory for promoted dispatch results.")
    parser.add_argument("--preflight-json", type=Path, help="Explicit validation preflight JSON artifact.")
    parser.add_argument("--runs-dir", type=Path, default=RUNS_DIR, help="Runs directory used to find the latest preflight.")
    parser.add_argument("--list", action="store_true", help="List package IDs without writing scripts.")
    parser.add_argument("--list-detail", action="store_true", help="List packages with resources, env, dependencies, and commands.")
    parser.add_argument("--list-json", action="store_true", help="List packages as JSON without writing scripts.")
    parser.add_argument("--package-id", help="Package ID from parallel_work_packages.")
    parser.add_argument("--wave", type=int, help="Materialize every package in one parallel unblock wave.")
    parser.add_argument("--all", action="store_true", help="Materialize every package from parallel_work_packages.")
    parser.add_argument("--output-dir", type=Path, help="Directory for generated scripts.")
    parser.add_argument("--emit-agent-prompts", action="store_true", help="Also write one handoff prompt per package.")
    parser.add_argument("--emit-agent-roster", action="store_true", help="Also write agent_roster.md for multi-agent handoff.")
    parser.add_argument("--emit-env-checklist", action="store_true", help="Also write env_checklist.md for required env handoff.")
    parser.add_argument("--emit-wave-launcher", action="store_true", help="Also write parallel launcher scripts for waves.")
    parser.add_argument("--emit-staged-wave-launcher", action="store_true", help="Also write staged wave launchers that serialize resource overlaps automatically.")
    parser.add_argument("--emit-dispatch-manifest", action="store_true", help="Also write dispatch_manifest.json.")
    parser.add_argument("--emit-dispatch-brief", action="store_true", help="Also write dispatch_brief.md for one-shot multi-agent handoff.")
    parser.add_argument("--emit-dispatch-runner", action="store_true", help="Also write dispatch_one_shot_runner.ps1 for opt-in wave execution and local gates.")
    parser.add_argument("--execute", action="store_true", help="Execute the generated PowerShell script.")
    parser.add_argument(
        "--allow-dependent-wave-execute",
        action="store_true",
        help="Allow --execute for a package that declares depends_on_waves.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.summarize_dispatch:
        try:
            json_path, markdown_path = summarize_dispatch(args.summarize_dispatch)
        except (FileNotFoundError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(f"dispatch_results={json_path}")
        print(f"dispatch_results_markdown={markdown_path}")
        return 0
    if args.promote_dispatch_results:
        try:
            json_path, markdown_path, comparison_path = promote_dispatch_results(
                args.promote_dispatch_results,
                args.runs_output_dir,
            )
        except (FileNotFoundError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(f"dispatch_results_artifact={json_path}")
        print(f"dispatch_results_markdown={markdown_path}")
        print(f"dispatch_results_comparison={comparison_path}")
        return 0
    if args.refresh_claim_status_report:
        try:
            with local_dotenv_environment():
                markdown_path, json_path = refresh_claim_status_report_from_manifest(args.refresh_claim_status_report)
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(f"claim_status_report={markdown_path}")
        print(f"claim_status_report_json={json_path}")
        return 0
    if args.refresh_dispatch_handoff_artifacts:
        try:
            with local_dotenv_environment():
                refreshed = refresh_dispatch_handoff_artifacts_from_manifest(args.refresh_dispatch_handoff_artifacts)
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        for key in sorted(refreshed):
            print(f"{key}={refreshed[key]}")
        return 0

    if args.execute and not args.preflight_json:
        print("--execute requires --preflight-json so execution cannot use an implicit latest artifact", file=sys.stderr)
        return 2

    preflight_path = args.preflight_json or latest_preflight_path(args.runs_dir)
    artifact = load_json(preflight_path)
    try:
        validate_preflight_artifact(artifact)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    packages = preflight_packages(artifact)
    output_dir = args.output_dir or unique_default_output_dir()

    if sum(1 for value in (args.list, args.list_detail, args.list_json) if value) > 1:
        print("select only one of --list, --list-detail, or --list-json", file=sys.stderr)
        return 2

    if args.list:
        print_package_list(packages)
        return 0
    if args.list_detail:
        print_package_detail_list(packages)
        return 0
    if args.list_json:
        print(json.dumps(package_list_entries(packages), indent=2, sort_keys=True))
        return 0

    if args.execute and not args.package_id:
        print("--execute is only supported with --package-id", file=sys.stderr)
        return 2

    try:
        selected = [
            package_with_latest_current_next_action(package)
            for package in select_packages(packages, args.package_id, args.wave, args.all)
        ]
        selection_mode = "package" if args.package_id else ("wave" if args.wave is not None else "all")
        selected_wave = args.wave if args.wave is not None else None
        for package in selected:
            validate_safe_commands(package)
            if args.execute:
                missing = missing_required_env(package)
                if missing:
                    raise ValueError(
                        f"package {package.get('package_id')} missing required env: {', '.join(missing)}"
                    )
                dependencies = dependent_waves(package)
                if dependencies and not args.allow_dependent_wave_execute:
                    raise ValueError(
                        f"package {package.get('package_id')} depends on waves: "
                        f"{', '.join(str(value) for value in dependencies)}"
                    )
        script_paths = {
            str(package.get("package_id")): write_package_script(package, preflight_path, output_dir)
            for package in selected
        }
        prompt_paths = []
        prompt_path_map = {}
        if args.emit_agent_prompts:
            for package in selected:
                package_id = str(package.get("package_id"))
                prompt_path = write_agent_prompt(package, script_paths[package_id], preflight_path, output_dir)
                prompt_path_map[package_id] = prompt_path
                prompt_paths.append(prompt_path)
        launcher_paths = []
        if args.emit_wave_launcher:
            launcher_paths = write_wave_launchers(selected, script_paths, output_dir)
        staged_launcher_paths = []
        if args.emit_staged_wave_launcher:
            staged_launcher_paths = write_staged_wave_launchers(selected, script_paths, output_dir)
        roster_path = None
        if args.emit_agent_roster:
            roster_path = write_agent_roster(selected, script_paths, prompt_path_map, output_dir)
        env_checklist_path = None
        env_template_path = None
        if args.emit_env_checklist:
            env_checklist_path = write_env_checklist(selected, output_dir)
            env_template_path = write_env_template(selected, output_dir)
        owner_launch_plan_path = None
        owner_launch_plan_json_path = None
        execution_matrix_path = None
        execution_matrix_json_path = None
        agent_claims_path = None
        agent_claims_json_path = None
        agent_spawn_plan_path = None
        agent_spawn_plan_json_path = None
        agent_spawn_launcher_path = None
        claim_status_report_path = None
        claim_status_report_json_path = None
        claim_lock_helper_path = None
        env_unblock_queue_path = None
        env_unblock_queue_json_path = None
        ready_claims_launcher_path = None
        ready_claims_parallel_launcher_path = None
        env_bundle_ready_claims_launcher_path = None
        claim_lock_helper_path = output_dir / "claim_lock_helper.ps1"
        claim_lock_helper_path.write_text(
            render_claim_lock_helper(
                {
                    "claims": [
                        {"claim_id": "claim-" + str(package.get("package_id") or "")}
                        for package in selected
                    ]
                }
            ),
            encoding="utf-8",
        )
        planned_manifest_path = output_dir / "dispatch_manifest.json" if args.emit_dispatch_manifest else None
        if args.emit_agent_roster:
            owner_launch_plan_path = write_owner_launch_plan(
                selected,
                output_dir,
                script_paths,
                prompt_path_map,
                env_checklist_path,
                env_template_path,
            )
            owner_launch_plan_json_path = write_owner_launch_plan_json(
                selected,
                output_dir,
                script_paths,
                prompt_path_map,
                env_checklist_path,
                env_template_path,
            )
            execution_matrix_path, execution_matrix_json_path = write_execution_matrix(
                owner_launch_plan_json_path,
                output_dir,
            )
            agent_claims_path, agent_claims_json_path = write_agent_claims(
                execution_matrix_json_path,
                output_dir,
            )
            agent_spawn_plan_path, agent_spawn_plan_json_path = write_agent_spawn_plan(
                agent_claims_json_path,
                output_dir,
            )
            agent_spawn_launcher_path = write_agent_spawn_launcher(
                agent_spawn_plan_json_path,
                output_dir,
            )
            claim_status_report_path, claim_status_report_json_path = write_claim_status_report(
                agent_claims_json_path,
                output_dir,
            )
            claim_lock_helper_path = write_claim_lock_helper(
                agent_claims_json_path,
                output_dir,
            )
            env_unblock_queue_path, env_unblock_queue_json_path = write_env_unblock_queue(
                agent_claims_json_path,
                output_dir,
                agent_spawn_launcher_path,
            )
            ready_claims_launcher_path = write_ready_claims_launcher(
                agent_claims_json_path,
                output_dir,
            )
            ready_claims_parallel_launcher_path = write_ready_claims_parallel_launcher(
                agent_claims_json_path,
                output_dir,
            )
            env_bundle_ready_claims_launcher_path = write_env_bundle_ready_claims_launcher(
                agent_claims_json_path,
                output_dir,
            )
            dispatch_prelaunch_validation_path = write_dispatch_prelaunch_validation(
                output_dir,
                agent_spawn_launcher_path,
                ready_claims_launcher_path,
                ready_claims_parallel_launcher_path,
                env_bundle_ready_claims_launcher_path,
                claim_lock_helper_path,
                env_unblock_queue_json_path,
                agent_spawn_plan_json_path,
                agent_claims_json_path,
                claim_status_report_json_path,
                planned_manifest_path,
                owner_launch_plan_json_path,
                execution_matrix_json_path,
            )
        else:
            dispatch_prelaunch_validation_path = None
        dispatch_runner_path = None
        if args.emit_dispatch_runner:
            dispatch_runner_path = write_dispatch_runner(
                selected,
                output_dir,
                script_paths,
                launcher_paths,
                staged_launcher_paths,
                planned_manifest_path,
            )
        dispatch_brief_path = None
        if args.emit_dispatch_brief:
            dispatch_brief_path = write_dispatch_brief(
                selected,
                preflight_path,
                output_dir,
                script_paths,
                prompt_path_map,
                launcher_paths,
                staged_launcher_paths,
                roster_path,
                env_checklist_path,
                env_template_path,
                owner_launch_plan_path,
                owner_launch_plan_json_path,
                execution_matrix_path,
                execution_matrix_json_path,
                agent_claims_path,
                agent_claims_json_path,
                agent_spawn_plan_path,
                agent_spawn_plan_json_path,
                agent_spawn_launcher_path,
                claim_status_report_path,
                claim_status_report_json_path,
                claim_lock_helper_path,
                env_unblock_queue_path,
                env_unblock_queue_json_path,
                ready_claims_launcher_path,
                ready_claims_parallel_launcher_path,
                env_bundle_ready_claims_launcher_path,
                dispatch_prelaunch_validation_path,
                planned_manifest_path,
                dispatch_runner_path,
            )
        manifest_path = None
        if args.emit_dispatch_manifest:
            manifest_path = write_dispatch_manifest(
                selected,
                preflight_path,
                output_dir,
                script_paths,
                prompt_path_map,
                launcher_paths,
                staged_launcher_paths,
                roster_path,
                env_checklist_path,
                env_template_path,
                owner_launch_plan_path,
                owner_launch_plan_json_path,
                execution_matrix_path,
                execution_matrix_json_path,
                agent_claims_path,
                agent_claims_json_path,
                agent_spawn_plan_path,
                agent_spawn_plan_json_path,
                agent_spawn_launcher_path,
                claim_status_report_path,
                claim_status_report_json_path,
                claim_lock_helper_path,
                env_unblock_queue_path,
                env_unblock_queue_json_path,
                ready_claims_launcher_path,
                ready_claims_parallel_launcher_path,
                env_bundle_ready_claims_launcher_path,
                dispatch_prelaunch_validation_path,
                dispatch_brief_path,
                dispatch_runner_path,
                selection_mode,
                selected_wave,
            )
    except (KeyError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    for package in selected:
        package_id = str(package.get("package_id"))
        print(f"script={script_paths[package_id]}")
        print(f"package_id={package_id}")
        print("commands:")
        for command in package.get("safe_commands") or []:
            print(f"  {command}")
    for prompt_path in prompt_paths:
        print(f"agent_prompt={prompt_path}")
    for launcher_path in launcher_paths:
        print(f"wave_launcher={launcher_path}")
    for launcher_path in staged_launcher_paths:
        print(f"staged_wave_launcher={launcher_path}")
    if roster_path:
        print(f"agent_roster={roster_path}")
    if env_checklist_path:
        print(f"env_checklist={env_checklist_path}")
    if env_template_path:
        print(f"env_template={env_template_path}")
    if owner_launch_plan_path:
        print(f"owner_launch_plan={owner_launch_plan_path}")
    if owner_launch_plan_json_path:
        print(f"owner_launch_plan_json={owner_launch_plan_json_path}")
    if execution_matrix_path:
        print(f"execution_matrix={execution_matrix_path}")
    if execution_matrix_json_path:
        print(f"execution_matrix_json={execution_matrix_json_path}")
    if agent_claims_path:
        print(f"agent_claims={agent_claims_path}")
    if agent_claims_json_path:
        print(f"agent_claims_json={agent_claims_json_path}")
    if agent_spawn_plan_path:
        print(f"agent_spawn_plan={agent_spawn_plan_path}")
    if agent_spawn_plan_json_path:
        print(f"agent_spawn_plan_json={agent_spawn_plan_json_path}")
    if agent_spawn_launcher_path:
        print(f"agent_spawn_launcher={agent_spawn_launcher_path}")
    if claim_status_report_path:
        print(f"claim_status_report={claim_status_report_path}")
    if claim_status_report_json_path:
        print(f"claim_status_report_json={claim_status_report_json_path}")
    if claim_lock_helper_path:
        print(f"claim_lock_helper={claim_lock_helper_path}")
    if env_unblock_queue_path:
        print(f"env_unblock_queue={env_unblock_queue_path}")
    if env_unblock_queue_json_path:
        print(f"env_unblock_queue_json={env_unblock_queue_json_path}")
    if ready_claims_launcher_path:
        print(f"ready_claims_launcher={ready_claims_launcher_path}")
    if ready_claims_parallel_launcher_path:
        print(f"ready_claims_parallel_launcher={ready_claims_parallel_launcher_path}")
    if env_bundle_ready_claims_launcher_path:
        print(f"env_bundle_ready_claims_launcher={env_bundle_ready_claims_launcher_path}")
    if dispatch_brief_path:
        print(f"dispatch_brief={dispatch_brief_path}")
    if dispatch_runner_path:
        print(f"dispatch_runner={dispatch_runner_path}")
    if manifest_path:
        print(f"dispatch_manifest={manifest_path}")

    if args.execute:
        return execute_script(next(iter(script_paths.values())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
