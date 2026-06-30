#!/usr/bin/env python3
"""Compatibility wrapper for the ML contract validator.

The implementation lives under ``tools/detection_validation/scripts`` so the
standalone mirror can keep executable helpers grouped together. Historical
tests, generated commands, and operator docs still import or execute this path.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


_IMPL_PATH = Path(__file__).resolve().parent / "scripts" / "validate_ml_contracts.py"


def _load_impl() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_tamandua_validate_ml_contracts_impl", _IMPL_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load ML contract validator implementation: {_IMPL_PATH}")
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
