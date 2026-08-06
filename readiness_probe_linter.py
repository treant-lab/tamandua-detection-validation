#!/usr/bin/env python3
"""Compatibility wrapper for the readiness probe linter.

The implementation lives under ``tools/detection_validation/scripts`` so the
standalone mirror keeps executable helpers grouped together. Historical
operator docs may still invoke this root path.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


_IMPL_PATH = Path(__file__).resolve().parent / "scripts" / "readiness_probe_linter.py"


def _load_impl() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_tamandua_readiness_probe_linter_impl", _IMPL_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load readiness probe linter implementation: {_IMPL_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_impl = _load_impl()

for _name in dir(_impl):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_impl, _name)


def main() -> int:
    return _impl.main()


if __name__ == "__main__":
    raise SystemExit(main())
