"""In-process runner for gate-script CLIs.

The detection-validation suite historically spawned ``sys.executable`` for
every gate invocation.  On Windows each process spawn carries a fixed wall
time cost, and most of these tests only assert on the exit code plus
parseable stdout -- a contract that the script's ``main()`` already provides
in-process.

``run_cli_in_process`` loads the target script once (cached), invokes its
``main()`` with a patched ``sys.argv``, captures stdout/stderr, and returns a
``subprocess.CompletedProcess`` so existing assertions keep working verbatim.

Honest contract notes:

* This does NOT exercise the real OS process boundary (interpreter startup,
  the ``if __name__ == "__main__"`` guard, argv handoff to a fresh process).
  Every converted test file therefore keeps at least one true ``subprocess``
  smoke test per script so the real CLI entrypoint stays covered.
* ``SystemExit`` raised by ``argparse`` or by the script is translated the
  same way the interpreter would translate it at process exit: ``None`` -> 0,
  ``int`` -> that code, anything else -> printed to stderr with exit code 1.
* Side benefit: in-process gate runs are covered by the permanent socket
  guard in ``conftest.py`` (subprocess runs never were -- documented
  limitation there).
"""

from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType
from typing import Sequence


_MODULE_CACHE: dict[Path, ModuleType] = {}


def load_script_module(script: Path) -> ModuleType:
    """Load ``script`` as a module (cached per resolved path).

    Mirrors the ``spec_from_file_location`` pattern already established across
    this suite.  The script's parent directory is prepended to ``sys.path`` so
    sibling imports (e.g. ``sdk_release_summary``) resolve exactly as they do
    when the script runs as a process from its own directory.
    """
    resolved = script.resolve()
    cached = _MODULE_CACHE.get(resolved)
    if cached is not None:
        return cached
    parent = str(resolved.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    spec = importlib.util.spec_from_file_location(resolved.stem, resolved)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _MODULE_CACHE[resolved] = module
    return module


def run_cli_in_process(
    script: Path, argv: Sequence[str] = ()
) -> subprocess.CompletedProcess[str]:
    """Invoke ``script``'s ``main()`` in-process, mimicking ``subprocess.run``.

    Returns a ``subprocess.CompletedProcess`` with the same ``returncode`` /
    ``stdout`` / ``stderr`` contract the converted tests were already
    asserting against.
    """
    module = load_script_module(script)
    stdout = io.StringIO()
    stderr = io.StringIO()
    original_argv = sys.argv
    sys.argv = [str(script), *[str(arg) for arg in argv]]
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                returncode: object = module.main()
            except SystemExit as exc:  # argparse errors / explicit exits
                returncode = exc.code
    finally:
        sys.argv = original_argv
    if returncode is None:
        returncode = 0
    elif not isinstance(returncode, int):
        stderr.write(f"{returncode}\n")
        returncode = 1
    return subprocess.CompletedProcess(
        [sys.executable, str(script), *[str(arg) for arg in argv]],
        returncode,
        stdout=stdout.getvalue(),
        stderr=stderr.getvalue(),
    )
