from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest


DETECTION_VALIDATION_ROOT = Path(__file__).resolve().parents[1]
DETECTION_VALIDATION_SCRIPTS = DETECTION_VALIDATION_ROOT / "scripts"
DETECTION_VALIDATION_TESTS = Path(__file__).resolve().parent
MONOREPO_ROOT = Path(__file__).resolve().parents[3]

for path in (
    DETECTION_VALIDATION_SCRIPTS,
    DETECTION_VALIDATION_ROOT,
    DETECTION_VALIDATION_TESTS,
    MONOREPO_ROOT,
):
    path_text = str(path)
    if path_text not in sys.path:
        sys.path.insert(0, path_text)


# ---------------------------------------------------------------------------
# Network guard
# ---------------------------------------------------------------------------
#
# This suite is a pure unit/contract suite: it was dynamically proven (socket
# blocking plugin + sitecustomize.py for subprocesses) that every test passes
# with *all* ``socket.connect`` calls raising -- zero real network I/O.  The
# guard below makes that property permanent so a regression that introduces a
# real connection fails loudly instead of silently depending on the network.
#
# Opt-in escape hatches (both restore the real behaviour for one test only):
#
#   * marker:   ``@pytest.mark.allow_network``
#   * fixture:  ``def test_x(allow_network): ...``
#
# Honest limitation: the guard patches ``socket.socket.connect`` /
# ``connect_ex`` in *this* interpreter only.  Tests that spawn real
# subprocesses (7 ``sys.executable`` smoke call-sites -- one per gate script,
# kept deliberately after the in-process conversion via
# ``inprocess_gate_cli.run_cli_in_process`` -- plus the PowerShell ``.ps1``
# CLI tests) are NOT covered by this guard -- covering them would require
# injecting a ``sitecustomize.py`` via PYTHONPATH, which risks perturbing
# module resolution inside the scripts under test, so it is deliberately left
# out.  The subprocess paths were part of the dynamic proof above and are
# re-proven by the suite remaining green offline.  Gate invocations converted
# to in-process ARE now covered by this guard.


class NetworkAccessBlockedError(RuntimeError):
    """Raised when a test attempts a real socket connection."""


_BLOCK_MESSAGE = (
    "Real network access blocked in unit tests; use the "
    "@pytest.mark.allow_network marker or the allow_network fixture "
    "to deliberately opt in for a single test."
)

# ``socket.socket`` is the Python subclass of ``_socket.socket``; ``connect``
# and ``connect_ex`` are inherited C method descriptors.  Assigning on the
# subclass shadows them; re-assigning the saved descriptors restores the
# original behaviour (descriptors bind normally through the subclass).
_REAL_SOCKET_CONNECT = socket.socket.connect
_REAL_SOCKET_CONNECT_EX = socket.socket.connect_ex


def _blocked_connect(self, *args, **kwargs):  # noqa: ANN001 - socket signature
    raise NetworkAccessBlockedError(_BLOCK_MESSAGE)


def _blocked_connect_ex(self, *args, **kwargs):  # noqa: ANN001 - socket signature
    raise NetworkAccessBlockedError(_BLOCK_MESSAGE)


def _install_network_guard() -> None:
    socket.socket.connect = _blocked_connect
    socket.socket.connect_ex = _blocked_connect_ex


def _uninstall_network_guard() -> None:
    socket.socket.connect = _REAL_SOCKET_CONNECT
    socket.socket.connect_ex = _REAL_SOCKET_CONNECT_EX


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "allow_network: opt out of the socket guard and allow real network "
        "access for this test (must be deliberate and local)",
    )
    _install_network_guard()


def pytest_unconfigure(config: pytest.Config) -> None:  # noqa: ARG001
    _uninstall_network_guard()


@pytest.fixture(autouse=True)
def _network_guard_marker_opt_in(request: pytest.FixtureRequest):
    """Honour ``@pytest.mark.allow_network`` by restoring real sockets."""
    if request.node.get_closest_marker("allow_network") is None:
        yield
        return
    _uninstall_network_guard()
    try:
        yield
    finally:
        _install_network_guard()


@pytest.fixture
def allow_network():
    """Explicit fixture opt-in: restores real socket behaviour for one test."""
    _uninstall_network_guard()
    try:
        yield
    finally:
        _install_network_guard()
