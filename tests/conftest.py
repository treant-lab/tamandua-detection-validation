from __future__ import annotations

import sys
from pathlib import Path


DETECTION_VALIDATION_ROOT = Path(__file__).resolve().parents[1]
MONOREPO_ROOT = Path(__file__).resolve().parents[3]

for path in (DETECTION_VALIDATION_ROOT, MONOREPO_ROOT):
    path_text = str(path)
    if path_text not in sys.path:
        sys.path.insert(0, path_text)
