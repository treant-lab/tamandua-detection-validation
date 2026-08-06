import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def production_before_tests(source: str) -> str:
    return source.split("#[cfg(test)]", 1)[0]


def test_runtime_has_no_recovery_bearer_store_or_load_contract():
    runtime = "\n".join(
        read(path)
        for path in (
            "apps/tamandua_agent/src/installer/mod.rs",
            "apps/tamandua_agent/src/installer/token.rs",
            "apps/tamandua_agent/src/transport/mod.rs",
            "apps/tamandua_agent/src/transport/token_manager.rs",
        )
    )

    forbidden_function = re.compile(
        r"(?:pub\s+)?(?:async\s+)?fn\s+(?:store|get)_recovery_token\b"
    )
    assert forbidden_function.search(runtime) is None
    assert "store_recovery_token(" not in runtime
    assert "get_recovery_token(" not in runtime


def test_token_manager_has_no_bootstrap_config_or_csr_fallback():
    manager = production_before_tests(
        read("apps/tamandua_agent/src/transport/token_manager.rs")
    )
    transport = read("apps/tamandua_agent/src/transport/mod.rs")

    assert "installation_token" not in manager
    assert "installation_token" not in transport
    for source in (manager, transport):
        assert "enroll_with_csr" not in source
        assert "/api/v1/enrollment/csr" not in source


def test_legacy_storage_identifiers_are_cleanup_only():
    token_source = production_before_tests(
        read("apps/tamandua_agent/src/installer/token.rs")
    )
    cleanup_start = token_source.index(
        "/// Idempotently remove the obsolete cleartext recovery token"
    )
    cleanup_end = token_source.index("/// Convert a WebSocket URL", cleanup_start)
    cleanup = token_source[cleanup_start:cleanup_end]

    assert 'delete_value("RecoveryToken")' in cleanup
    assert 'Path::new("/etc/tamandua/.recovery_token")' in cleanup
    assert "remove_file" in cleanup
    for forbidden in (
        "get_value",
        "set_value",
        "read_to_string",
        "std::fs::read",
        "std::fs::write",
        "File::open",
        "File::create",
    ):
        assert forbidden not in cleanup

    other_runtime = "\n".join(
        (
            production_before_tests(
                read("apps/tamandua_agent/src/installer/mod.rs")
            ),
            read("apps/tamandua_agent/src/transport/mod.rs"),
            production_before_tests(
                read("apps/tamandua_agent/src/transport/token_manager.rs")
            ),
        )
    )
    assert '"RecoveryToken"' not in other_runtime
    assert '"/etc/tamandua/.recovery_token"' not in other_runtime


def test_fresh_install_cleans_legacy_value_without_persisting_bootstrap_bearer():
    installer = production_before_tests(read("apps/tamandua_agent/src/installer/mod.rs"))
    install_body = installer[installer.index("pub async fn install(") :]

    cleanup_call = install_body.index('cleanup_legacy_recovery_token_best_effort("install")')
    validation = install_body.index("validate_token(")
    assert cleanup_call < validation
    assert "store_recovery_token" not in install_body
    assert 'set_value("RecoveryToken"' not in install_body
    assert 'write("/etc/tamandua/.recovery_token"' not in install_body


def test_recovery_states_and_cleanup_failure_category_are_stable():
    manager = read("apps/tamandua_agent/src/transport/token_manager.rs")
    token_source = read("apps/tamandua_agent/src/installer/token.rs")
    transport = read("apps/tamandua_agent/src/transport/mod.rs")

    for state in (
        "jwt_active",
        "refresh_retrying",
        "transient_backoff",
        "operator_reenrollment_required",
    ):
        assert state in manager
    assert "legacy_secret_cleanup_failed" in token_source
    assert "cleanup_legacy_recovery_token" in transport


def test_startup_cleanup_precedes_missing_credentials_and_terminal_token_is_latched():
    transport = read("apps/tamandua_agent/src/transport/mod.rs")
    manager = production_before_tests(
        read("apps/tamandua_agent/src/transport/token_manager.rs")
    )
    connect = transport[transport.index("pub async fn connect(&self)") :]

    cleanup = connect.index('cleanup_legacy_recovery_secret("backend_connect_startup")')
    missing_credentials = connect.index("missing_enrollment_credentials()")
    assert cleanup < missing_credentials

    assert "auth_terminal_token_fingerprint" in transport
    assert transport.count("new_with_terminal_latch(") >= 2
    assert transport.count("self.auth_terminal_token_fingerprint.clone()") >= 2
    assert "Sha256::digest(token.as_bytes())" in manager
    assert "terminal.as_ref() == Some(&fingerprint)" in manager
    assert "Detected a new credential; clearing terminal auth recovery latch" in manager
    assert "latch_current_token_terminal" in manager


def test_active_rotation_docs_describe_fail_closed_recovery_and_uninstall_scope():
    docs = {
        path: read(path)
        for path in (
            "docs/TOKEN_ROTATION_QUICKSTART.md",
            "docs/TOKEN_ROTATION_MIGRATION_GUIDE.md",
            "docs/TOKEN_ROTATION_IMPLEMENTATION.md",
            "docs/SECURITY_TOKEN_ROTATION.md",
        )
    }

    forbidden_claims = (
        "fallback to re-enrollment",
        "automatically re-enroll",
        'installation_token = "',
        "installation_token: Some(",
    )
    for path, source in docs.items():
        lowered = source.lower()
        for claim in forbidden_claims:
            assert claim.lower() not in lowered, f"{path} retains stale claim: {claim}"
        for state in (
            "jwt_active",
            "refresh_retrying",
            "transient_backoff",
            "operator_reenrollment_required",
        ):
            assert state in source, f"{path} omits recovery state {state}"
        assert "scope=cli_only" in source
        assert "msi_covered=false" in source

    combined = "\n".join(docs.values()).lower()
    assert "does not persist" in combined
    assert "authenticated jwt refresh" in combined
    assert "csr fallback" in combined or "csr enrollment endpoint as a fallback" in combined
    assert "legacy_secret_cleanup_failed" in combined
