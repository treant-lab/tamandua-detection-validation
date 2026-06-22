#!/usr/bin/env python3
"""Refresh validation authority artifacts in dependency order.

This helper keeps the roadmap closure gate, execution preflight, dispatch
package, promoted dispatch results, generated scorecard, and product-readiness
summary aligned. It is intentionally sequential because the preflight must bind
to the closure gate created by the same refresh pass; in other words, the
preflight must bind to the closure gate before dispatch packages are created.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
GENERATED_DIR = ROOT / "docs" / "benchmarks" / "generated"

PACKAGE_EMIT_FLAGS = [
    "--emit-agent-prompts",
    "--emit-agent-roster",
    "--emit-env-checklist",
    "--emit-wave-launcher",
    "--emit-staged-wave-launcher",
    "--emit-dispatch-runner",
    "--emit-dispatch-brief",
    "--emit-dispatch-manifest",
]


@dataclass(frozen=True)
class StepResult:
    label: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


def repo_rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def parse_key_values(stdout: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in stdout.splitlines():
        for token in raw_line.strip().split():
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key and value:
                values[key] = value
    return values


def command_plan(
    *,
    runs_dir: Path = RUNS_DIR,
    generated_dir: Path = GENERATED_DIR,
    closure_json: Path | None = None,
    preflight_json: Path | None = None,
    package_output_dir: Path | None = None,
    manifest_path: Path | None = None,
) -> list[tuple[str, list[str], tuple[int, ...]]]:
    closure_ref = closure_json or Path("<closure-json-from-previous-step>")
    preflight_ref = preflight_json or Path("<preflight-json-from-previous-step>")
    package_dir = package_output_dir or default_package_output_dir(preflight_ref)
    manifest_ref = manifest_path or package_dir / "dispatch_manifest.json"
    python = sys.executable
    return [
        (
            "scorecard-before-closure",
            [
                python,
                "tools/detection_validation/generate_validation_scorecard.py",
                "--runs-dir",
                str(runs_dir),
                "--output-dir",
                str(generated_dir),
            ],
            (0,),
        ),
        (
            "roadmap-closure-gate",
            [
                python,
                "tools/detection_validation/roadmap_closure_gate_probe.py",
                "--scorecard-json",
                str(generated_dir / "validation_roadmap_scorecard.json"),
                "--output-dir",
                str(runs_dir),
            ],
            (0, 1),
        ),
        (
            "validation-execution-preflight",
            [
                python,
                "tools/detection_validation/validation_execution_preflight_probe.py",
                "--scorecard-json",
                str(generated_dir / "validation_roadmap_scorecard.json"),
                "--closure-gate-json",
                str(closure_ref),
                "--output-dir",
                str(runs_dir),
            ],
            (0, 1),
        ),
        (
            "preflight-work-package",
            [
                python,
                "tools/detection_validation/run_preflight_work_package.py",
                "--preflight-json",
                str(preflight_ref),
                "--all",
                "--output-dir",
                str(package_dir),
                *PACKAGE_EMIT_FLAGS,
            ],
            (0,),
        ),
        (
            "dispatch-results",
            [
                python,
                "tools/detection_validation/run_preflight_work_package.py",
                "--promote-dispatch-results",
                str(manifest_ref),
                "--runs-output-dir",
                str(runs_dir),
            ],
            (0,),
        ),
        (
            "scorecard-after-dispatch",
            [
                python,
                "tools/detection_validation/generate_validation_scorecard.py",
                "--runs-dir",
                str(runs_dir),
                "--output-dir",
                str(generated_dir),
            ],
            (0,),
        ),
        (
            "product-readiness-summary",
            [
                python,
                "tools/detection_validation/generate_product_readiness_summary.py",
                "--scorecard-json",
                str(generated_dir / "validation_roadmap_scorecard.json"),
                "--output-dir",
                str(generated_dir),
            ],
            (0,),
        ),
    ]


def default_package_output_dir(preflight_path: Path) -> Path:
    if str(preflight_path) == "<preflight-json-from-previous-step>":
        return Path("<preflight-json-from-previous-step>.package-artifacts")
    return preflight_path.with_suffix(".package-artifacts")


def run_step(label: str, command: list[str], allowed_returncodes: tuple[int, ...]) -> StepResult:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    result = StepResult(label, command, int(completed.returncode), completed.stdout, completed.stderr)
    if result.returncode not in allowed_returncodes:
        raise RuntimeError(
            f"{label} failed with exit {result.returncode}\n"
            f"command={' '.join(command)}\n"
            f"stdout={result.stdout.strip()}\n"
            f"stderr={result.stderr.strip()}"
        )
    return result


def require_output_path(result: StepResult, key: str) -> Path:
    value = parse_key_values(result.stdout).get(key)
    if not value:
        raise RuntimeError(f"{result.label} did not print {key}=...")
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    if not path.exists():
        raise RuntimeError(f"{result.label} printed missing {key} path: {path}")
    return path


def materialize_plan(args: argparse.Namespace) -> list[dict[str, object]]:
    plan = command_plan(
        runs_dir=args.runs_dir,
        generated_dir=args.generated_dir,
        closure_json=args.closure_json,
        preflight_json=args.preflight_json,
        package_output_dir=args.package_output_dir,
        manifest_path=args.dispatch_manifest,
    )
    return [
        {"label": label, "allowed_returncodes": list(allowed), "command": command}
        for label, command, allowed in plan
    ]


def print_dry_run(args: argparse.Namespace) -> None:
    print(json.dumps({"steps": materialize_plan(args)}, indent=2, sort_keys=True))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", type=Path, default=RUNS_DIR)
    parser.add_argument("--generated-dir", type=Path, default=GENERATED_DIR)
    parser.add_argument("--closure-json", type=Path, help="Use an existing closure artifact instead of generating one.")
    parser.add_argument("--preflight-json", type=Path, help="Use an existing preflight artifact instead of generating one.")
    parser.add_argument("--package-output-dir", type=Path, help="Directory for generated dispatch package artifacts.")
    parser.add_argument("--dispatch-manifest", type=Path, help="Use an existing dispatch manifest instead of the package output manifest.")
    parser.add_argument("--dry-run", action="store_true", help="Print the sequential command plan without running it.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.dry_run:
        print_dry_run(args)
        return 0

    results: list[StepResult] = []
    plan = command_plan(runs_dir=args.runs_dir, generated_dir=args.generated_dir)

    label, command, allowed = plan[0]
    results.append(run_step(label, command, allowed))

    if args.closure_json:
        closure_json = args.closure_json
    else:
        label, command, allowed = plan[1]
        closure_result = run_step(label, command, allowed)
        results.append(closure_result)
        closure_json = require_output_path(closure_result, "json")

    if args.preflight_json:
        preflight_json = args.preflight_json
    else:
        label, command, allowed = command_plan(
            runs_dir=args.runs_dir,
            generated_dir=args.generated_dir,
            closure_json=closure_json,
        )[2]
        preflight_result = run_step(label, command, allowed)
        results.append(preflight_result)
        preflight_json = require_output_path(preflight_result, "json")

    package_output_dir = args.package_output_dir or default_package_output_dir(preflight_json)
    if args.dispatch_manifest:
        dispatch_manifest = args.dispatch_manifest
    else:
        label, command, allowed = command_plan(
            runs_dir=args.runs_dir,
            generated_dir=args.generated_dir,
            preflight_json=preflight_json,
            package_output_dir=package_output_dir,
        )[3]
        package_result = run_step(label, command, allowed)
        results.append(package_result)
        dispatch_manifest = require_output_path(package_result, "dispatch_manifest")

    label, command, allowed = command_plan(
        runs_dir=args.runs_dir,
        generated_dir=args.generated_dir,
        manifest_path=dispatch_manifest,
    )[4]
    results.append(run_step(label, command, allowed))

    label, command, allowed = plan[5]
    results.append(run_step(label, command, allowed))

    label, command, allowed = plan[6]
    results.append(run_step(label, command, allowed))

    summary = {
        "closure_json": repo_rel(closure_json),
        "preflight_json": repo_rel(preflight_json),
        "package_output_dir": repo_rel(package_output_dir),
        "dispatch_manifest": repo_rel(dispatch_manifest),
        "steps": [
            {
                "label": result.label,
                "returncode": result.returncode,
                "command": result.command,
            }
            for result in results
        ],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
