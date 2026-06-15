#!/usr/bin/env python3
"""Build a compact index for all detection roadmap JSON files."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
ROADMAP_DIR = ROOT / "tools" / "detection_validation" / "roadmaps"
OUT = ROADMAP_DIR / "index.json"
MD_OUT = ROOT / "docs" / "benchmarks" / "DETECTION_ROADMAP_INDEX.md"


def load_roadmaps() -> list[dict[str, object]]:
    roadmaps = []
    for path in sorted(ROADMAP_DIR.glob("*_detection_roadmap_300.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        scenarios = data.get("scenarios") or []
        p0 = [scenario for scenario in scenarios if scenario.get("priority") == "P0"]
        planned_p0 = [scenario for scenario in p0 if scenario.get("status") == "planned"]
        roadmaps.append(
            {
                "roadmap_id": data.get("roadmap_id"),
                "platform": data.get("platform"),
                "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                "scenario_count": len(scenarios),
                "priority_counts": data.get("priority_counts") or dict(Counter(s.get("priority") for s in scenarios)),
                "status_counts": data.get("scenario_status_counts") or dict(Counter(s.get("status") for s in scenarios)),
                "executor_counts": data.get("executor_counts") or dict(Counter(s.get("executor") for s in scenarios)),
                "p0_count": len(p0),
                "planned_p0_count": len(planned_p0),
                "first_planned_p0": [
                    {
                        "id": scenario.get("id"),
                        "tactic": scenario.get("tactic"),
                        "technique_id": scenario.get("technique_id"),
                        "variant": scenario.get("variant"),
                        "executor": scenario.get("executor"),
                    }
                    for scenario in planned_p0[:15]
                ],
            }
        )
    return roadmaps


def write_json(roadmaps: list[dict[str, object]]) -> None:
    payload = {
        "schema_version": 1,
        "roadmap_count": len(roadmaps),
        "total_scenarios": sum(int(r["scenario_count"]) for r in roadmaps),
        "platforms": [r["platform"] for r in roadmaps],
        "roadmaps": roadmaps,
    }
    OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_md(roadmaps: list[dict[str, object]]) -> None:
    total = sum(int(r["scenario_count"]) for r in roadmaps)
    lines = [
        "# Detection Roadmap Index",
        "",
        "This index summarizes the platform roadmaps used to grow Tamandua validation coverage. A roadmap item is not a product claim until it has a runnable profile and reproducible evidence.",
        "",
        f"- Total platform roadmaps: `{len(roadmaps)}`",
        f"- Total scenarios: `{total}`",
        "",
        "| Platform | Scenarios | P0 | Planned P0 | Status Counts | Executor Counts | File |",
        "|----------|-----------|----|------------|---------------|-----------------|------|",
    ]
    for roadmap in roadmaps:
        lines.append(
            f"| `{roadmap['platform']}` | `{roadmap['scenario_count']}` | `{roadmap['p0_count']}` | "
            f"`{roadmap['planned_p0_count']}` | `{roadmap['status_counts']}` | "
            f"`{roadmap['executor_counts']}` | `{roadmap['path']}` |"
        )
    lines.extend(
        [
            "",
            "## Execution Order",
            "",
            "1. Convert planned `P0` sensor-contract scenarios into runnable profiles.",
            "2. Add benign baselines for the same areas before promoting alert rules.",
            "3. Add Atomic/CALDERA-backed runs for adversary-emulation confidence.",
            "4. Gate release claims on persisted telemetry, alert quality, correlation/storyline and response audit evidence.",
        ]
    )
    MD_OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    roadmaps = load_roadmaps()
    write_json(roadmaps)
    write_md(roadmaps)
    print(f"roadmaps={len(roadmaps)} total={sum(int(r['scenario_count']) for r in roadmaps)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
