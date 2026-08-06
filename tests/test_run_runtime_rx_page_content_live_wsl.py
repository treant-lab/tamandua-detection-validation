from pathlib import Path
import hashlib
import json
import re
import shlex
import subprocess


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "tools/detection_validation/scripts/run_runtime_rx_page_content_live_wsl.ps1"
PRIOR_RUN_ID = "20260717T103431Z-runtime-rx-live-bd8f677afb36c3e9db28bc06"
PRIOR_FAILURE_MANIFEST = (
    b'{"cleanup_status":"completed","exit_code":1,"log_sha256":'
    b'{"cargo_build_stderr":"ee4610806950184b725d870626045798976db013ab2b9d51273673129c64a5e9",'
    b'"cargo_metadata_stderr":"8942c765d32c4b6cdd91dda06e6ed40cdbac93c730dd41ab12815821e239e7e2"},'
    b'"raw_logs_retained":false,"run_id":"20260717T103431Z-runtime-rx-live-bd8f677afb36c3e9db28bc06",'
    b'"schema":"tamandua.runtime_integrity_live_probe_failure/v1","stage":"isolated_probe"}'
)


def prior_manifest(tmp_path: Path) -> Path:
    path = tmp_path / "prior-failure-manifest.json"
    path.write_bytes(PRIOR_FAILURE_MANIFEST)
    return path


def source() -> str:
    return RUNNER.read_text(encoding="utf-8")


def embedded_bash() -> str:
    text = source()
    prefix = "$Bash = @'\n"
    start = text.index(prefix) + len(prefix)
    end = text.index("\n'@", start)
    return text[start:end]


def embedded_bash_function(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}$", embedded_bash(), re.M | re.S)
    assert match, f"embedded bash function not found: {name}"
    return match.group(0)


def actual_on_exit_function() -> str:
    bash = embedded_bash()
    start = bash.index("on_exit() {\n")
    end = bash.index("\n}\n\nensure_protected_parent()", start) + 2
    function = bash[start:end]
    assert bash[start:end] == function
    assert function.count("    os.fsync(directory)") == 2
    return function


def instrument_nth(text: str, needle: str, replacement: str, ordinal: int) -> str:
    positions = [match.start() for match in re.finditer(re.escape(needle), text)]
    assert len(positions) >= ordinal
    position = positions[ordinal - 1]
    return text[:position] + replacement + text[position + len(needle):]


def run_actual_terminal_harness(
    tmp_path: Path, *, probe_started: bool, timed_out: bool = False,
    inject_diagnostic_dir_fsync: bool = False, inject_failure_dir_fsync: bool = False,
) -> tuple[list[str], dict | None]:
    function = actual_on_exit_function()
    needle = "    os.fsync(directory)"
    injection = '    raise OSError("injected directory fsync failure")'
    if inject_diagnostic_dir_fsync:
        function = instrument_nth(function, needle, injection, 1)
    if inject_failure_dir_fsync:
        function = instrument_nth(function, needle, injection, 2)

    suffix = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:20]
    base = f"/tmp/tamandua-runner-terminal-{suffix}"
    evidence = f"{base}/evidence"
    prior = prior_manifest(tmp_path)
    root_wsl = subprocess.run(
        ["wsl.exe", "wslpath", "-a", str(ROOT).replace("\\", "/")], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    ).stdout.strip()
    prior_wsl = subprocess.run(
        ["wsl.exe", "wslpath", "-a", str(prior).replace("\\", "/")], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    ).stdout.strip()
    process_exit_observed = "false" if timed_out else "true"
    process_exit_code = "" if timed_out else "1"
    trace_state = "partial" if timed_out else "complete"
    harness = f'''#!/usr/bin/env bash
set +e
umask 077
base={shlex.quote(base)}
evidence_root={shlex.quote(evidence)}
mkdir -p "$evidence_root" "$base/logs"
run_id={shlex.quote(PRIOR_RUN_ID)}
root={shlex.quote(root_wsl)}
prior_failure_manifest={shlex.quote(prior_wsl)}
log_dir="$base/logs"
build_root="$base/build"
install_root="$base/install"
config_root="$base/config"
receipt_probe_input="$evidence_root/.probe-output.json"
failure_manifest="$evidence_root/failure-manifest.json"
failure_manifest_tmp="$evidence_root/.failure-manifest.tmp"
diagnostic="$evidence_root/diagnostic.json"
diagnostic_tmp="$evidence_root/.diagnostic.tmp"
evidence_owned=true
probe_started={str(probe_started).lower()}
probe_exit_observed={process_exit_observed}
probe_exit_code={shlex.quote(process_exit_code)}
probe_timed_out={str(timed_out).lower()}
output_state=partial
output_bytes=173
output_sha=5a61637b9c03cc60d52d588f366c326598bc249754c0910b36f330fe0d14e4bd
trace_state={trace_state}
trace_sha=d6cd41dd48533f30a2358583ce53188476709d39a548a3218d87ef97f6c37bd1
time_sha=93f18742d3dfcc8b0b3f5017e69eea1fd57b4ff465dede410eb0c9cc38319ac3
network_syscalls=0
mutation_syscalls=0
artifact_unchanged=true
config_unchanged=true
diagnostic_eligible=false
diagnostic_committed=false
stage=test_terminal_harness
cleanup_targets() {{ return 0; }}
{function}
on_exit
'''
    harness_path = tmp_path / "terminal-harness.sh"
    harness_path.write_text(harness, encoding="utf-8", newline="\n")
    harness_wsl = subprocess.run(
        ["wsl.exe", "wslpath", "-a", str(harness_path).replace("\\", "/")], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    ).stdout.strip()
    try:
        completed = subprocess.run(
            ["wsl.exe", "bash", harness_wsl], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30,
        )
        listed = subprocess.run(
            ["wsl.exe", "find", evidence, "-mindepth", "1", "-maxdepth", "1", "-printf", "%f\n"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        ).stdout.splitlines()
        finals = [name for name in listed if not name.startswith(".")]
        payload = None
        if len(finals) == 1:
            raw = subprocess.run(
                ["wsl.exe", "cat", f"{evidence}/{finals[0]}"], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            ).stdout
            payload = json.loads(raw)
        assert completed.returncode in {0, 1, 86, 91}
        return sorted(listed), payload
    finally:
        assert base.startswith("/tmp/tamandua-runner-terminal-")
        subprocess.run(
            ["wsl.exe", "rm", "-rf", "--", base], check=True,
        )


def test_default_lane_is_preflight_only_and_non_mutating() -> None:
    text = source()
    assert "[switch]$Execute" in text
    assert "if (-not $Execute)" in text
    assert 'mutation_performed = $false' in text
    completed = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(RUNNER)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert '"execute": false' in completed.stdout


def test_runner_pins_frozen_hashes_offline_locked_build_and_exact_gate() -> None:
    text = source()
    assert "cargo metadata --locked --offline --no-deps" in text
    command = "cargo build --release --locked --manifest-path apps/tamandua_agent/Cargo.toml --bin tamandua-agent"
    assert text.count(command) >= 2
    assert "CARGO_NET_OFFLINE=true" in text
    assert 'export CARGO_HOME="${toolchain_home}/.cargo"' in text
    assert 'export RUSTUP_HOME="${toolchain_home}/.rustup"' in text
    assert '--receipt "$receipt" --require-executed' in text
    assert "dcc9ef777bd03174f74a98afbf9ef95937de8dc9ac038e171500da29f7bd4c3f" in text


def test_runner_pins_diagnostic_authority_agent_source_and_prior_failure_bytes() -> None:
    text = source()
    for digest in (
        "7e9c1431e496763970ea91fdfd8ab3cb66b810806ec1340532d3d24de3753db7",
        "567d5380053731d561ed41a8ff711221ff8f3218bba60c49cd83fb240e310274",
        "a640fd58e57bd550b91b1c6c71e20bdc09d84816c9d48197bdde08acda07012e",
        "66ada2c927415f5a190bec031d7997ff6fa4912888e3b4bce33dc84b8a991de5",
        "35820ac8139863498dc7356542abc11474ab98d0998076533813f4ced067988e",
        "70f0b15c6387946134946c86be6ddc557a148ba5cf2b98d952eba1469ebca5df",
    ):
        assert digest in text
    assert hashlib.sha256(PRIOR_FAILURE_MANIFEST).hexdigest() in text
    assert "[string]$PriorFailureManifest" in text
    assert "RunId must exactly match the bound prior failure manifest" in text


def test_retry_prior_mismatch_fails_before_any_wsl_call(tmp_path: Path) -> None:
    marker = tmp_path / "wsl-called"
    fake_wsl = tmp_path / "must-not-run.ps1"
    fake_wsl.write_text(
        f'New-Item -ItemType File -Path "{marker.as_posix()}" | Out-Null; exit 99',
        encoding="utf-8",
    )
    bad = tmp_path / "bad-prior.json"
    bad.write_bytes(PRIOR_FAILURE_MANIFEST + b"\n")
    completed = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(RUNNER), "-Execute",
         "-PriorFailureManifest", str(bad), "-WslExecutable", str(fake_wsl)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode != 0
    assert not marker.exists()
    assert "byte hash is not the frozen retry input" in completed.stderr


def test_controlled_failure_capture_and_exact_internal_diagnostic_parser_are_closed() -> None:
    text = source()
    assert "set +e\ntimeout --signal=TERM --kill-after=5s 60s unshare --net" in text
    assert 'probe_exit_observed=false' in text
    assert 'probe_timed_out=true' in text
    assert 'set(value) != {"schema", "state", "checkpoint", "code"}' in text
    assert 'value["schema"] != "tamandua.runtime_integrity_probe_internal_diagnostic/v1"' in text
    assert 'value["state"] != "categorical_diagnostic"' in text
    agent = (ROOT / "apps/tamandua_agent/src/main.rs").read_text(encoding="utf-8")
    frozen_pairs = set(re.findall(r'Self::new\("([^"]+)", "([^"]+)"\)', agent))
    allowed_block = re.search(r"allowed_pairs = \{(.*?)\n\}", text, re.S)
    assert allowed_block
    runner_pairs = set(re.findall(r'\("([^"]+)", "([^"]+)"\)', allowed_block.group(1)))
    assert len(frozen_pairs) == 12
    assert runner_pairs == frozen_pairs
    assert 'assert len(allowed_pairs) == 12' in text
    assert "cat -- \"$probe_stderr\"" in text
    assert 'printf \'%s\' "$probe_stderr"' not in text


def test_trace_precedence_aggregation_cleanup_and_terminal_authorities_are_ordered() -> None:
    text = source()
    aggregate = text.index('stage="probe_trace_aggregate"')
    cleanup = text.index('stage="contained_cleanup"')
    purge = text.index('find "$evidence_root" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +')
    network = text.index('if [ "$probe_exit_observed" = true ] && [ "$network_syscalls" -gt 0 ]')
    filesystem = text.index('elif [ "$probe_exit_observed" = true ] && [ "$mutation_syscalls" -gt 0 ]')
    timeout = text.index('elif [ "$probe_timed_out" = true ]', filesystem)
    trace_incomplete = text.index('elif [ "$trace_state" != complete ]', timeout)
    diagnostic_gate = text.index('--diagnostic "$diagnostic_tmp" --require-executed')
    prior = text.index('--prior-failure-manifest "$prior_failure_manifest"', diagnostic_gate)
    publish = text.index('os.replace(sys.argv[1], sys.argv[2])', diagnostic_gate)
    receipt = text.index('"tamandua.runtime_integrity_live_probe_receipt/v1"')
    assert aggregate < cleanup
    assert purge < network < filesystem < timeout < trace_incomplete < diagnostic_gate < prior < publish
    assert diagnostic_gate < receipt
    assert 'find "$evidence_root" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +' in text
    assert '"raw_logs_retained": False' in text
    assert '"$trace_log" 2>/dev/null || true' in text
    for stage in (
        "probe_ipc_policy_uncategorizable",
        "probe_exec_attestation_uncategorizable",
        "probe_rss_uncategorizable",
    ):
        assert stage in text


def test_runner_binds_every_execution_authority_and_dirty_input() -> None:
    text = source()
    assert "Get-FileHash -LiteralPath $PSCommandPath" in text
    for field in (
        "runner_sha256", "receipt_schema_sha256", "receipt_gate_sha256",
        "synthetic_fixture_sha256", "scoped_dirty", "scoped_dirty_diff_sha256",
        "receipt_sha256",
    ):
        assert field in text
    assert '"tamandua.runtime_integrity_live_probe_execution_manifest/v1"' in text
    assert 'with open(sys.argv[1], "x"' in text


def test_runner_uses_unique_contained_paths_and_cleanup_guards() -> None:
    text = source()
    assert "RandomNumberGenerator]::Fill" in text
    for prefix in ("/var/tmp/tamandua-loop68/", "/opt/tamandua-loop68/", "/etc/tamandua-loop68/"):
        assert prefix in text
    assert 'resolved="$(realpath -m -- "$candidate")"' in text
    assert "refusing cleanup outside run containment" in text
    assert 'rm -rf -- "$install_root"' in text
    assert 'rm -rf -- "$config_root"' in text
    assert 'rm -rf -- "$build_root"' in text


def test_runner_isolated_probe_has_no_backend_or_secret_ingress() -> None:
    text = source()
    assert "unshare --net" in text
    assert "ip link set lo down" in text
    assert "strace -f -qq" in text
    assert "trace=%network,%file" in text
    assert "/usr/bin/time -v" in text
    assert "runtime-integrity-preview-probe" in text
    namespace_fallback = text.index(
        'stage="isolated_namespace_setup"', text.index('stage="probe_trace_aggregate"')
    )
    protection = text.index('stage="probe_protection_validate"')
    assert namespace_fallback < protection
    assert not re.search(r"server_url|auth_token|--server|--agent-id|--token", text, re.I)


def test_actual_wsl_loopback_unknown_operstate_accepts_admin_down_and_rejects_up(
    tmp_path: Path,
) -> None:
    assertion = embedded_bash_function("assert_loopback_admin_down")
    script = f'''set -eu
{assertion}
ip link set lo down >/dev/null
test "$(cat /sys/class/net/lo/operstate)" = unknown
assert_loopback_admin_down
ip link set lo up >/dev/null
if assert_loopback_admin_down; then exit 41; fi
'''
    script_path = tmp_path / "loopback-admin-state.sh"
    script_path.write_text(script, encoding="utf-8", newline="\n")
    wsl_path = subprocess.run(
        ["wsl.exe", "wslpath", "-a", str(script_path).replace("\\", "/")], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    ).stdout.strip()
    completed = subprocess.run(
        ["wsl.exe", "--user", "root", "unshare", "--net", "bash", wsl_path],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_actual_wsl_missing_trace_normalizes_counters_and_selects_sanitized_fallback(
    tmp_path: Path,
) -> None:
    normalize = embedded_bash_function("normalize_counter")
    classify = embedded_bash_function("classify_probe_process_result")
    script = f'''set -eu
{normalize}
{classify}
trace_log=/definitely/absent/tamandua-loop71-strace.log
network_syscalls="$(grep -Ec socket "$trace_log" 2>/dev/null || true)"
ipc_syscalls="$(grep -Ec pipe "$trace_log" 2>/dev/null || true)"
probe_branch_execs="$(grep -Ec execve "$trace_log" 2>/dev/null || true)"
all_execs="$(grep -Ec execve "$trace_log" 2>/dev/null || true)"
metadata_mutations="$(grep -Ec creat "$trace_log" 2>/dev/null || true)"
unexpected_data_writes="$(grep -Ec write "$trace_log" 2>/dev/null || true)"
network_syscalls="$(normalize_counter "$network_syscalls")"
ipc_syscalls="$(normalize_counter "$ipc_syscalls")"
probe_branch_execs="$(normalize_counter "$probe_branch_execs")"
all_execs="$(normalize_counter "$all_execs")"
metadata_mutations="$(normalize_counter "$metadata_mutations")"
unexpected_data_writes="$(normalize_counter "$unexpected_data_writes")"
mutation_syscalls="$((metadata_mutations + unexpected_data_writes))"
trace_state=unavailable
probe_result=86
stage=isolated_probe
probe_started=true
probe_timed_out=false
probe_exit_observed=false
probe_exit_code=
classify_probe_process_result
NETWORK_SYSCALLS="$network_syscalls" MUTATION_SYSCALLS="$mutation_syscalls" python3 - <<'PY'
import json, os
payload = {{"network": int(os.environ["NETWORK_SYSCALLS"]),
            "mutation": int(os.environ["MUTATION_SYSCALLS"])}}
assert json.dumps(payload, sort_keys=True) == '{{"mutation": 0, "network": 0}}'
PY
test "$trace_state" = unavailable
test "$stage" = isolated_namespace_setup
test "$probe_started" = false
test "$probe_exit_observed" = false
'''
    script_path = tmp_path / "missing-trace-fallback.sh"
    script_path.write_text(script, encoding="utf-8", newline="\n")
    wsl_path = subprocess.run(
        ["wsl.exe", "wslpath", "-a", str(script_path).replace("\\", "/")], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    ).stdout.strip()
    completed = subprocess.run(
        ["wsl.exe", "bash", wsl_path], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_runner_binds_provenance_custody_and_zero_side_effect_counts() -> None:
    text = source()
    for token in (
        "source_sha", "scoped_dirty_diff_sha256", "cargo_lock_sha256",
        "artifact_sha256_before", "artifact_sha256_after", "config_sha256_before",
        "config_sha256_after", "strace_network_syscalls",
        "strace_filesystem_mutation_syscalls", "max_rss_source",
    ):
        assert token in text
    assert '[ "$network_syscalls" -ne 0 ]' in text
    assert '[ "$mutation_syscalls" -ne 0 ]' in text


def test_runner_closes_extended_mutation_ipc_and_measured_claims() -> None:
    text = source()
    assert "trace=%network,%file,%ipc,%desc" in text
    for syscall in (
        "utimensat", "fsetxattr", "fremovexattr", "fallocate", "eventfd2",
        "memfd_create", "epoll_create1", "pwrite64", "copy_file_range",
    ):
        assert syscall in text
    assert '[ "$ipc_syscalls" -ne 0 ]' in text
    assert '[ "$probe_branch_execs" -ne 1 ]' in text
    assert 'test "$probe_branch_attested" = true' in text
    assert '"artifact_regular_file": os.environ["ARTIFACT_REGULAR"] == "true"' in text
    assert '"backend_constructed": not (' in text
    assert '"ipc_constructed": int(os.environ["IPC_SYSCALLS"]) != 0' in text
    assert "backend_constructed=false" not in text
    assert "ipc_constructed=false" not in text
    assert 'test $((8#$candidate_mode & 8#022)) -eq 0' in text


def test_runner_failure_cleanup_is_fail_closed_and_sanitized() -> None:
    text = source()
    assert 'cleanup_status="failed"' in text
    assert "code=91" in text
    assert '"raw_logs_retained": os.environ["CLEANUP_STATUS"] != "completed"' in text
    assert '"tamandua.runtime_integrity_live_probe_failure/v1"' in text
    assert 'tail -n 32' not in text
    assert 'cleanup_targets >/dev/null 2>&1 || true' not in text
    purge = text.index('find "$evidence_root" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +')
    failure = text.index('python3 - "$failure_manifest_tmp" "$failure_manifest"', purge)
    assert purge < failure
    failure_block = text[failure:text.index("\nPY\n", failure) + 3]
    assert 'with open(sys.argv[1], "x"' in failure_block
    assert "stream.flush()" in failure_block
    assert "os.fsync(stream.fileno())" in failure_block
    assert "os.replace(sys.argv[1], sys.argv[2])" in failure_block
    assert "os.fsync(directory)" in failure_block
    assert 'failure_manifest_tmp="${evidence_root}/.failure-manifest.tmp"' in text
    assert "trap - EXIT" in text[text.index("on_exit() {"):purge]


def test_terminal_failure_publish_never_leaves_partial_or_coexisting_authorities() -> None:
    text = source()
    diagnostic_publish = text.index('python3 - "$diagnostic_tmp" "$diagnostic"')
    diagnostic_replace = text.index("os.replace(sys.argv[1], sys.argv[2])", diagnostic_publish)
    diagnostic_dir_fsync = text.index("os.fsync(directory)", diagnostic_replace)
    purge_after_failed_commit = text.index(
        'rm -f -- "$diagnostic" "$diagnostic_tmp"', diagnostic_dir_fsync
    )
    generic_guard = text.index('if [ "$diagnostic_committed" != true ]', purge_after_failed_commit)
    generic_purge = text.index(
        'rm -f -- "$diagnostic" "$diagnostic_tmp" "$failure_manifest" "$failure_manifest_tmp"',
        generic_guard,
    )
    failure_publish = text.index(
        'python3 - "$failure_manifest_tmp" "$failure_manifest"', generic_purge
    )
    failure_replace = text.index("os.replace(sys.argv[1], sys.argv[2])", failure_publish)
    failed_failure_cleanup = text.index(
        'rm -f -- "$failure_manifest_tmp" "$failure_manifest"', failure_replace
    )
    assert diagnostic_publish < diagnostic_replace < diagnostic_dir_fsync
    assert diagnostic_dir_fsync < purge_after_failed_commit < generic_guard < generic_purge
    assert generic_purge < failure_publish < failure_replace < failed_failure_cleanup
    assert 'with open(sys.argv[2], "x"' not in text[failure_publish:]


def test_actual_terminal_code_recovers_from_post_diagnostic_replace_fsync_failure(
    tmp_path: Path,
) -> None:
    names, payload = run_actual_terminal_harness(
        tmp_path, probe_started=True, timed_out=True,
        inject_diagnostic_dir_fsync=True,
    )
    assert names == ["failure-manifest.json"]
    assert payload is not None
    assert payload["schema"] == "tamandua.runtime_integrity_live_probe_failure/v1"
    assert set(payload) == {
        "schema", "run_id", "stage", "exit_code", "cleanup_status",
        "log_sha256", "raw_logs_retained",
    }


def test_actual_terminal_code_post_fallback_replace_fsync_failure_leaves_no_partial(
    tmp_path: Path,
) -> None:
    names, payload = run_actual_terminal_harness(
        tmp_path, probe_started=False, inject_failure_dir_fsync=True,
    )
    assert names == []
    assert payload is None


def test_actual_terminal_code_successful_fallback_is_exact_final_json_only(
    tmp_path: Path,
) -> None:
    names, payload = run_actual_terminal_harness(tmp_path, probe_started=False)
    assert names == ["failure-manifest.json"]
    assert payload is not None
    assert payload == {
        "schema": "tamandua.runtime_integrity_live_probe_failure/v1",
        "run_id": PRIOR_RUN_ID,
        "stage": "test_terminal_harness",
        "exit_code": 0,
        "cleanup_status": "completed",
        "log_sha256": {"cargo_metadata_stderr": None, "cargo_build_stderr": None},
        "raw_logs_retained": False,
    }


def test_actual_terminal_code_timeout_classifies_before_partial_trace(
    tmp_path: Path,
) -> None:
    names, payload = run_actual_terminal_harness(
        tmp_path, probe_started=True, timed_out=True,
    )
    assert names == ["diagnostic.json"]
    assert payload is not None
    assert payload["process"] == {
        "started": True, "exit_observed": False, "exit_code": None, "timed_out": True,
    }
    assert payload["trace"]["state"] == "partial"
    assert payload["trace"]["network_syscall_count"] == 0
    assert payload["trace"]["filesystem_mutation_syscall_count"] == 0
    assert (payload["checkpoint"], payload["code"]) == ("probe_execute", "probe_timeout")


def test_execute_rejects_a_reused_run_id_via_atomic_reservation(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    fake_wsl = tmp_path / "reservation-wsl.ps1"
    fake_wsl.write_text(
        rf'''param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)
$joined = $Rest -join " "
if ($Rest -contains "wslpath") {{
    $candidate = $Rest[-1]
        if ($candidate -match "tamandua$") {{ Write-Output "/mnt/d/treant/tamandua" }}
        elseif ($candidate -match '\.sh$') {{ Write-Output $candidate }}
    else {{ Write-Output "/mnt/c/tamandua-runner-input" }}
    exit 0
}}
if ($joined -like '*printf %s "$HOME"*') {{ Write-Output "/home/tester"; exit 0 }}
if ($Rest -contains "-lc") {{ exit 0 }}
$script = Get-Content -Raw -LiteralPath $Rest[3]
$runId = $Rest[5]
$marker = Join-Path "{state.as_posix()}" "$runId.marker"
$atomicReservation = $script.Contains('mkdir -m 0700 -- "$evidence_root"')
if (Test-Path -LiteralPath $marker) {{
    if ($atomicReservation) {{ exit 73 }}
    Write-Output "RECEIPT=reused"
    exit 0
}}
New-Item -ItemType File -Path $marker | Out-Null
Write-Output "RECEIPT=first"
exit 0
''',
        encoding="utf-8",
    )
    run_id = PRIOR_RUN_ID
    prior = prior_manifest(tmp_path)
    command = [
        "pwsh", "-NoProfile", "-File", str(RUNNER), "-Execute", "-RunId", run_id,
        "-WslExecutable", str(fake_wsl), "-PriorFailureManifest", str(prior),
    ]
    first = subprocess.run(
        command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=30,
    )
    second = subprocess.run(
        command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=30,
    )
    assert first.returncode == 0, first.stdout + first.stderr
    assert second.returncode != 0, second.stdout + second.stderr
    assert "Executed live-probe runner failed closed" in second.stderr


def test_execute_path_retains_receipt_input_and_digests_until_after_cleanup(tmp_path: Path) -> None:
    fake_wsl = tmp_path / "fake-wsl.ps1"
    fake_wsl.write_text(
        r'''param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)
$joined = $Rest -join " "
if ($Rest -contains "wslpath") {
    $candidate = $Rest[-1]
        if ($candidate -match "tamandua$") { Write-Output "/mnt/d/treant/tamandua" }
        elseif ($candidate -match '\.sh$') { Write-Output $candidate }
    else { Write-Output "/mnt/c/tamandua-runner-input" }
    exit 0
}
if ($joined -like '*printf %s "$HOME"*') { Write-Output "/home/tester"; exit 0 }
if ($Rest -contains "-lc") { exit 0 }

$scriptPath = $Rest[3]
$script = Get-Content -Raw -LiteralPath $scriptPath
$retain = $script.IndexOf('install -m 0600 -- "$probe_stdout" "$receipt_probe_input"')
$traceHash = $script.IndexOf('trace_sha="$(sha256sum "$trace_log"')
$cleanup = $script.IndexOf("`ncleanup_targets`n")
$receiptRead = $script.IndexOf('export MAX_RSS="$max_rss" PROBE_STDOUT="$receipt_probe_input"')
$rawDigestRead = $script.IndexOf('sha256sum "$trace_log" "$time_log"')
$temporaryRemoval = $script.IndexOf('rm -f -- "$receipt_probe_input"', $receiptRead)
$digestWrite = $script.IndexOf('> "${evidence_root}/sanitized-log-digests.sha256"')
$manifestWrite = $script.IndexOf('python3 - "$execution_manifest_tmp" "$execution_manifest"')
    $atomicPublish = $script.IndexOf('os.replace(sys.argv[1], sys.argv[2])', $manifestWrite)
$terminalTrap = $script.IndexOf('trap - EXIT', $atomicPublish)

if ($retain -lt 0 -or $traceHash -lt 0 -or $cleanup -lt 0 -or $receiptRead -lt 0 -or
    $retain -gt $cleanup -or $traceHash -gt $cleanup -or $receiptRead -lt $cleanup -or
    $rawDigestRead -ge 0 -or $temporaryRemoval -lt $receiptRead -or
    $digestWrite -lt $receiptRead -or $manifestWrite -lt $digestWrite -or
    $atomicPublish -lt $manifestWrite -or $terminalTrap -lt $atomicPublish) {
    Write-Error "receipt lifecycle would read deleted or retained raw artifacts"
    exit 42
}
Write-Output "RECEIPT=/var/tmp/tamandua-loop68-receipts/fake/receipt.json"
exit 0
''',
        encoding="utf-8",
    )
    run_id = PRIOR_RUN_ID
    prior = prior_manifest(tmp_path)
    completed = subprocess.run(
        [
            "pwsh", "-NoProfile", "-File", str(RUNNER), "-Execute", "-RunId", run_id,
                "-WslExecutable", str(fake_wsl), "-PriorFailureManifest", str(prior),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "RECEIPT=/var/tmp/tamandua-loop68-receipts/fake/receipt.json" in completed.stdout


def test_execute_late_failure_leaves_only_failure_authority(tmp_path: Path) -> None:
    modeled_evidence = tmp_path / "modeled-evidence"
    fake_wsl = tmp_path / "late-failure-wsl.ps1"
    fake_wsl.write_text(
        rf'''param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)
$joined = $Rest -join " "
if ($Rest -contains "wslpath") {{
    $candidate = $Rest[-1]
        if ($candidate -match "tamandua$") {{ Write-Output "/mnt/d/treant/tamandua" }}
        elseif ($candidate -match '\.sh$') {{ Write-Output $candidate }}
    else {{ Write-Output "/mnt/c/tamandua-runner-input" }}
    exit 0
}}
if ($joined -like '*printf %s "$HOME"*') {{ Write-Output "/home/tester"; exit 0 }}
if ($Rest -contains "-lc") {{ exit 0 }}
$script = Get-Content -Raw -LiteralPath $Rest[3]
$evidence = New-Item -ItemType Directory -Force -Path "{modeled_evidence.as_posix()}"
foreach ($name in @('receipt.json','receipt.sha256','gate.stdout','sanitized-log-digests.sha256','.execution-manifest.tmp')) {{
    Set-Content -LiteralPath (Join-Path $evidence $name) -Value 'partial'
}}
$purge = $script.IndexOf('find "$evidence_root" -mindepth 1 -maxdepth 1 -exec rm -rf -- {{}} +')
$failure = $script.IndexOf('"tamandua.runtime_integrity_live_probe_failure/v1"')
if ($purge -ge 0 -and $purge -lt $failure) {{
    Get-ChildItem -Force -LiteralPath $evidence | Remove-Item -Recurse -Force
}}
Set-Content -LiteralPath (Join-Path $evidence 'failure-manifest.json') -Value '{{"cleanup_status":"completed"}}'
exit 88
''',
        encoding="utf-8",
    )
    run_id = PRIOR_RUN_ID
    prior = prior_manifest(tmp_path)
    completed = subprocess.run(
        [
            "pwsh", "-NoProfile", "-File", str(RUNNER), "-Execute", "-RunId", run_id,
                "-WslExecutable", str(fake_wsl), "-PriorFailureManifest", str(prior),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    assert completed.returncode != 0
    assert sorted(path.name for path in modeled_evidence.iterdir()) == ["failure-manifest.json"]
