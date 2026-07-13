"""Pin the conftest socket guard: blocked by default, opt-in restores.

No test here performs real network I/O; opt-in verification only inspects
which callables are installed on ``socket.socket``.
"""

from __future__ import annotations

import socket

import pytest

import conftest


def test_connect_is_blocked_by_default():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(conftest.NetworkAccessBlockedError, match="allow_network"):
            sock.connect(("127.0.0.1", 9))
    finally:
        sock.close()


def test_connect_ex_is_blocked_by_default():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(conftest.NetworkAccessBlockedError, match="allow_network"):
            sock.connect_ex(("127.0.0.1", 9))
    finally:
        sock.close()


def test_blocked_error_is_a_runtime_error():
    assert issubclass(conftest.NetworkAccessBlockedError, RuntimeError)


def test_allow_network_fixture_restores_real_socket_methods(allow_network):
    assert socket.socket.connect is conftest._REAL_SOCKET_CONNECT
    assert socket.socket.connect_ex is conftest._REAL_SOCKET_CONNECT_EX


@pytest.mark.allow_network
def test_allow_network_marker_restores_real_socket_methods():
    assert socket.socket.connect is conftest._REAL_SOCKET_CONNECT
    assert socket.socket.connect_ex is conftest._REAL_SOCKET_CONNECT_EX


def test_guard_reinstalled_after_opt_in_tests_ran_earlier_in_module():
    # The two opt-in tests above run before this one (pytest preserves
    # definition order within a module); the guard must be back in place.
    assert socket.socket.connect is conftest._blocked_connect
    assert socket.socket.connect_ex is conftest._blocked_connect_ex
