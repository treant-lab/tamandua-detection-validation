[CmdletBinding()]
param(
    [switch]$Execute,
    [string]$Distribution = "",
    [string]$RunId = "",
    [string]$PriorFailureManifest = "",
    [string]$WslExecutable = "wsl.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$Schema = Join-Path $Root "schemas\runtime_rx_page_content_live_probe_v1.schema.json"
$Gate = Join-Path $Root "tools\detection_validation\scripts\runtime_rx_page_content_live_probe_v1.py"
$Fixture = Join-Path $Root "tools\detection_validation\fixtures\runtime_rx_page_content_live_probe_v1.json"
$DiagnosticSchema = Join-Path $Root "schemas\runtime_rx_page_content_live_probe_diagnostic_v1.schema.json"
$DiagnosticGate = Join-Path $Root "tools\detection_validation\scripts\runtime_rx_page_content_live_probe_diagnostic_v1.py"
$DiagnosticFixture = Join-Path $Root "tools\detection_validation\fixtures\runtime_rx_page_content_live_probe_diagnostic_v1.json"
$DiagnosticTests = Join-Path $Root "tools\detection_validation\tests\test_runtime_rx_page_content_live_probe_diagnostic_v1.py"
$AgentMain = Join-Path $Root "apps\tamandua_agent\src\main.rs"
$ExpectedPriorFailureManifestSha = "70f0b15c6387946134946c86be6ddc557a148ba5cf2b98d952eba1469ebca5df"
$Frozen = @{
    $Schema = "dcc9ef777bd03174f74a98afbf9ef95937de8dc9ac038e171500da29f7bd4c3f"
    $Gate = "b5be6564417d65a9630fa99d22a03d98aef2e32da499552a933031051ea74493"
    $Fixture = "bbf29c0773713e211d91579900b9e1aaa10213bdafffed4100de842c7c846e0d"
    $DiagnosticSchema = "7e9c1431e496763970ea91fdfd8ab3cb66b810806ec1340532d3d24de3753db7"
    $DiagnosticGate = "a640fd58e57bd550b91b1c6c71e20bdc09d84816c9d48197bdde08acda07012e"
    $DiagnosticFixture = "567d5380053731d561ed41a8ff711221ff8f3218bba60c49cd83fb240e310274"
    $DiagnosticTests = "66ada2c927415f5a190bec031d7997ff6fa4912888e3b4bce33dc84b8a991de5"
    $AgentMain = "35820ac8139863498dc7356542abc11474ab98d0998076533813f4ced067988e"
}

foreach ($item in $Frozen.GetEnumerator()) {
    $actual = (Get-FileHash -LiteralPath $item.Key -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $item.Value) {
        throw "Frozen live-probe authority hash mismatch: $([IO.Path]::GetFileName($item.Key))"
    }
}
$RunnerSha = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$SchemaSha = $Frozen[$Schema]
$GateSha = $Frozen[$Gate]
$FixtureSha = $Frozen[$Fixture]
$DiagnosticSchemaSha = $Frozen[$DiagnosticSchema]
$DiagnosticGateSha = $Frozen[$DiagnosticGate]
$DiagnosticFixtureSha = $Frozen[$DiagnosticFixture]
$DiagnosticTestsSha = $Frozen[$DiagnosticTests]
$AgentMainSha = $Frozen[$AgentMain]

$PriorManifestResolved = $null
$PriorManifestRunId = $null
if ($PriorFailureManifest) {
    $PriorManifestResolved = (Resolve-Path -LiteralPath $PriorFailureManifest).Path
    $priorHash = (Get-FileHash -LiteralPath $PriorManifestResolved -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($priorHash -ne $ExpectedPriorFailureManifestSha) {
        throw "Prior failure manifest byte hash is not the frozen retry input"
    }
    try { $prior = Get-Content -Raw -LiteralPath $PriorManifestResolved | ConvertFrom-Json }
    catch { throw "Prior failure manifest is not valid JSON" }
    $priorFields = @($prior.PSObject.Properties.Name | Sort-Object)
    $expectedPriorFields = @("cleanup_status", "exit_code", "log_sha256", "raw_logs_retained", "run_id", "schema", "stage") | Sort-Object
    if (($priorFields -join ',') -ne ($expectedPriorFields -join ',') -or
        $prior.schema -ne "tamandua.runtime_integrity_live_probe_failure/v1" -or
        $prior.stage -ne "isolated_probe" -or $prior.cleanup_status -ne "completed" -or
        $prior.raw_logs_retained -ne $false) {
        throw "Prior failure manifest does not match the closed retry contract"
    }
    $PriorManifestRunId = [string]$prior.run_id
    if ($PriorManifestRunId -notmatch '^[0-9]{8}T[0-9]{6}Z-runtime-rx-live-[0-9a-f]{24}$') {
        throw "Prior failure manifest run_id is invalid"
    }
}

$WslArgs = @()
if ($Distribution) { $WslArgs += @("--distribution", $Distribution) }
$WslRoot = (& $WslExecutable @WslArgs wslpath -a ($Root -replace '\\', '/')).Trim()
if (-not $WslRoot.StartsWith("/mnt/")) { throw "Workspace must resolve inside a WSL mounted drive" }
$WslToolchainHome = (& $WslExecutable @WslArgs sh -lc 'printf %s "$HOME"').Trim()
if ($WslToolchainHome -notmatch '^/home/[A-Za-z0-9._-]+$') {
    throw "WSL user toolchain home must resolve below /home"
}

$Preflight = @'
set -eu
for tool in cargo rustc git python3 strace unshare timeout sha256sum stat realpath file find ip sudo /usr/bin/time; do
  if ! command -v "$tool" >/dev/null 2>&1 && [ ! -x "$tool" ]; then
    echo "missing:$tool"
    exit 21
  fi
done
grep -qi microsoft /proc/version
'@
& $WslExecutable @WslArgs bash -lc $Preflight
if ($LASTEXITCODE -ne 0) { throw "WSL2 live-probe preflight failed" }
$null = & $WslExecutable @WslArgs --user root bash -lc "test `$(id -u) -eq 0 -a `$(id -ru) -eq 0; unshare --net -- true" 2>$null
$RootLaneReady = $LASTEXITCODE -eq 0

if (-not $Execute) {
    [ordered]@{
        execute = $false
        evidence_class = "preflight_only"
        execution_scope = "wsl2_network_isolated"
        frozen_authority_verified = $true
        mutation_performed = $false
        execute_ready = $RootLaneReady
        blocker = if ($RootLaneReady) { $null } else { "wsl_root_network_namespace_required" }
        retry_input_verified = $null -ne $PriorManifestResolved
        retry_run_id = $PriorManifestRunId
    } | ConvertTo-Json
    return
}

if (-not $RootLaneReady) { throw "Execute requires the non-interactive WSL root namespace lane" }
if (-not $PriorManifestResolved) { throw "Execute requires -PriorFailureManifest bound to the frozen failure bytes" }

if (-not $RunId) { $RunId = $PriorManifestRunId }
if ($RunId -notmatch '^[0-9]{8}T[0-9]{6}Z-runtime-rx-live-[0-9a-f]{24}$') {
    throw "RunId must contain a UTC timestamp and 96-bit lowercase cryptographic nonce"
}
if ($RunId -ne $PriorManifestRunId) { throw "RunId must exactly match the bound prior failure manifest" }
$runId = $RunId
$trackedDiff = (& git -C $Root diff --binary HEAD -- apps/tamandua_agent/Cargo.lock apps/tamandua_agent) -join "`n"
$untrackedLines = [Collections.Generic.List[string]]::new()
$untracked = & git -C $Root ls-files --others --exclude-standard -- apps/tamandua_agent
foreach ($relative in ($untracked | Sort-Object)) {
    $digest = (Get-FileHash -LiteralPath (Join-Path $Root $relative) -Algorithm SHA256).Hash.ToLowerInvariant()
    $untrackedLines.Add("UNTRACKED $relative $digest")
}
$scopedCanonical = @($trackedDiff) + $untrackedLines
$scopedText = ($scopedCanonical -join "`n").Trim()
$scopedDirty = $scopedText.Length -gt 0
$scopedDirtyText = $scopedDirty.ToString().ToLowerInvariant()
$scopedBytes = [Text.Encoding]::UTF8.GetBytes($scopedText)
$scopedDiffSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($scopedBytes)).ToLowerInvariant()
$attemptRandom = [byte[]]::new(12)
[Security.Cryptography.RandomNumberGenerator]::Fill($attemptRandom)
$attemptNonce = -join ($attemptRandom | ForEach-Object { $_.ToString("x2") })
$WslPriorManifest = (& $WslExecutable @WslArgs wslpath -a ($PriorManifestResolved -replace '\\', '/')).Trim()
if (-not $WslPriorManifest.StartsWith("/mnt/")) { throw "Prior failure manifest must resolve through the WSL mounted drive" }

$Bash = @'
#!/usr/bin/env bash
set -euo pipefail
umask 077

root="$1"
run_id="$2"
toolchain_home="$5"
prior_failure_manifest="${10}"
attempt_nonce="${11}"
diagnostic_schema_sha="${12}"
diagnostic_gate_sha="${13}"
diagnostic_fixture_sha="${14}"
diagnostic_tests_sha="${15}"
agent_main_sha="${16}"
export CARGO_HOME="${toolchain_home}/.cargo"
export RUSTUP_HOME="${toolchain_home}/.rustup"
export PATH="${CARGO_HOME}/bin:${PATH}"
attempt_id="${run_id}-retry-${attempt_nonce}"
build_root="/var/tmp/tamandua-loop68/${attempt_id}"
target_dir="${build_root}/cargo-target"
log_dir="${build_root}/logs"
install_root="/opt/tamandua-loop68/${attempt_id}"
config_root="/etc/tamandua-loop68/${attempt_id}"
artifact="${install_root}/tamandua-agent"
config="${config_root}/agent.toml"
evidence_root="/var/tmp/tamandua-loop68-receipts/${attempt_id}"
receipt="${evidence_root}/receipt.json"
receipt_probe_input="${evidence_root}/.probe-output.json"
execution_manifest="${evidence_root}/execution-manifest.json"
execution_manifest_tmp="${evidence_root}/.execution-manifest.tmp"
failure_manifest="${evidence_root}/failure-manifest.json"
failure_manifest_tmp="${evidence_root}/.failure-manifest.tmp"
diagnostic="${evidence_root}/diagnostic.json"
diagnostic_tmp="${evidence_root}/.diagnostic.tmp"
build_command='cargo build --release --locked --manifest-path apps/tamandua_agent/Cargo.toml --bin tamandua-agent'
build_created=false
install_created=false
config_created=false
evidence_owned=false
probe_started=false
probe_exit_observed=false
probe_exit_code=""
probe_timed_out=false
output_state="absent"
output_bytes=0
output_sha="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
trace_state="unavailable"
trace_sha=""
time_sha=""
network_syscalls=0
mutation_syscalls=0
ipc_syscalls=0
probe_branch_execs=0
all_execs=0
metadata_mutations=0
unexpected_data_writes=0
artifact_unchanged=true
config_unchanged=true
internal_diagnostic_valid=false
diagnostic_eligible=false
diagnostic_committed=false

safe_target() {
  local candidate resolved
  candidate="$1"
  resolved="$(realpath -m -- "$candidate")"
  case "$resolved" in
    "/var/tmp/tamandua-loop68/${attempt_id}"|"/var/tmp/tamandua-loop68/${attempt_id}/"*|\
    "/opt/tamandua-loop68/${attempt_id}"|"/opt/tamandua-loop68/${attempt_id}/"*|\
    "/etc/tamandua-loop68/${attempt_id}"|"/etc/tamandua-loop68/${attempt_id}/"*) return 0 ;;
    *) echo "refusing cleanup outside run containment" >&2; return 90 ;;
  esac
}

cleanup_targets() {
  local failed=0
  safe_target "$build_root"
  safe_target "$install_root"
  safe_target "$config_root"
  if [ "$install_created" = true ]; then rm -rf -- "$install_root" || failed=1; fi
  if [ "$config_created" = true ]; then rm -rf -- "$config_root" || failed=1; fi
  if [ "$build_created" = true ]; then rm -rf -- "$build_root" || failed=1; fi
  [ ! -e "$install_root" ] && install_created=false
  [ ! -e "$config_root" ] && config_created=false
  [ ! -e "$build_root" ] && build_created=false
  [ "$failed" -eq 0 ] && [ "$install_created" = false ] && \
    [ "$config_created" = false ] && [ "$build_created" = false ]
}
stage="initialization"
on_exit() {
  local code="$?" candidate digest cleanup_status remaining checkpoint diagnostic_code
  local metadata_digest="" build_digest=""
  trap - EXIT
  set +e
  for candidate in "${log_dir}/cargo-metadata.stderr" "${log_dir}/cargo-build.stderr"; do
    if [ -f "$candidate" ]; then
      digest="$(sha256sum "$candidate" | awk '{print $1}')"
      case "$(basename "$candidate")" in
        cargo-metadata.stderr) metadata_digest="$digest" ;;
        cargo-build.stderr) build_digest="$digest" ;;
      esac
    fi
  done
  rm -f -- "$receipt_probe_input"
  cleanup_status="completed"
  if ! cleanup_targets >/dev/null 2>&1; then
    cleanup_status="failed"
    code=91
  fi
  if [ "$evidence_owned" = true ]; then
    # A failed run has exactly one authority. Remove receipts, gate output,
    # digests, temporary manifests, and any other partial success material.
    find "$evidence_root" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    remaining=0
    [ -e "$build_root" ] && remaining=$((remaining + 1))
    [ -e "$install_root" ] && remaining=$((remaining + 1))
    [ -e "$config_root" ] && remaining=$((remaining + 1))

    # Once the isolated process started, classify from aggregate observations.
    # Positive trace counts take deterministic network-before-filesystem
    # precedence, as required by the frozen diagnostic validator.
    if [ "$probe_started" = true ] && [ "$cleanup_status" = completed ] && [ "$remaining" -eq 0 ]; then
      diagnostic_eligible=true
      if [ "$probe_exit_observed" = true ] && [ "$network_syscalls" -gt 0 ]; then
        checkpoint=runner_trace_policy; diagnostic_code=trace_network_syscall_observed
      elif [ "$probe_exit_observed" = true ] && [ "$mutation_syscalls" -gt 0 ]; then
        checkpoint=runner_trace_policy; diagnostic_code=trace_filesystem_mutation_observed
      elif [ "$probe_timed_out" = true ]; then
        checkpoint=probe_execute; diagnostic_code=probe_timeout
      elif [ "$artifact_unchanged" != true ]; then
        checkpoint=custody_validate; diagnostic_code=artifact_changed
      elif [ "$config_unchanged" != true ]; then
        checkpoint=custody_validate; diagnostic_code=config_changed
      elif [ "$trace_state" != complete ]; then
        checkpoint=runner_trace_policy; diagnostic_code=trace_incomplete
      elif [ "$output_bytes" -gt 2097152 ]; then
        checkpoint=probe_execute; diagnostic_code=output_oversize
      elif [ "$output_state" = absent ]; then
        checkpoint=probe_execute; diagnostic_code=output_absent
      elif [ "$output_state" = empty ]; then
        checkpoint=probe_execute; diagnostic_code=output_empty
      elif [ "$output_state" = complete_invalid ]; then
        checkpoint=probe_execute; diagnostic_code=output_invalid
      else
        checkpoint=probe_execute; diagnostic_code=process_exit_nonzero
      fi
    fi

    if [ "$diagnostic_eligible" = true ]; then
      RUN_ID="$run_id" CHECKPOINT="$checkpoint" DIAGNOSTIC_CODE="$diagnostic_code" \
      PROBE_EXIT_OBSERVED="$probe_exit_observed" PROBE_EXIT_CODE="$probe_exit_code" \
      PROBE_TIMED_OUT="$probe_timed_out" OUTPUT_STATE="$output_state" OUTPUT_BYTES="$output_bytes" \
      OUTPUT_SHA="$output_sha" TRACE_STATE="$trace_state" TRACE_SHA="$trace_sha" TIME_SHA="$time_sha" \
      NETWORK_SYSCALLS="$network_syscalls" MUTATION_SYSCALLS="$mutation_syscalls" \
      ARTIFACT_UNCHANGED="$artifact_unchanged" CONFIG_UNCHANGED="$config_unchanged" \
      CLEANUP_STATUS="$cleanup_status" REMAINING="$remaining" python3 - "$diagnostic_tmp" <<'PY'
import json, os, sys
from datetime import datetime, timezone
def truth(name): return os.environ[name] == "true"
payload = {
  "schema": "tamandua.runtime_integrity_live_probe_diagnostic/v1",
  "evidence_class": "local_live_probe_failure_diagnostic",
  "execution_scope": "wsl2_network_isolated", "execute": True,
  "diagnostic_provenance": "live_probe_runner",
  "external_claim_allowed": False, "fpr_claim_allowed": False,
  "performance_claim_allowed": False, "production_ready_claimed": False,
  "vendor_parity_claimed": False, "run_id": os.environ["RUN_ID"],
  "observed_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "prior_failure_manifest_sha256": "70f0b15c6387946134946c86be6ddc557a148ba5cf2b98d952eba1469ebca5df",
  "checkpoint": os.environ["CHECKPOINT"], "code": os.environ["DIAGNOSTIC_CODE"],
  "process": {"started": True, "exit_observed": truth("PROBE_EXIT_OBSERVED"),
    "exit_code": int(os.environ["PROBE_EXIT_CODE"]) if os.environ["PROBE_EXIT_CODE"] else None,
    "timed_out": truth("PROBE_TIMED_OUT")},
  "output": {"state": os.environ["OUTPUT_STATE"], "bytes": int(os.environ["OUTPUT_BYTES"]),
    "sha256": os.environ["OUTPUT_SHA"]},
  "trace": {"state": os.environ["TRACE_STATE"],
    "network_syscall_count": int(os.environ["NETWORK_SYSCALLS"]),
    "filesystem_mutation_syscall_count": int(os.environ["MUTATION_SYSCALLS"]),
    "strace_sha256": os.environ["TRACE_SHA"] or None, "time_sha256": os.environ["TIME_SHA"] or None},
  "custody": {"artifact_unchanged": truth("ARTIFACT_UNCHANGED"),
    "config_unchanged": truth("CONFIG_UNCHANGED")},
  "cleanup": {"attempted": True, "completed": os.environ["CLEANUP_STATUS"] == "completed",
    "temporary_artifacts_remaining": int(os.environ["REMAINING"]), "raw_logs_retained": False}}
with open(sys.argv[1], "x", encoding="utf-8") as stream:
    json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
    stream.flush(); os.fsync(stream.fileno())
PY
      if python3 "$root/tools/detection_validation/scripts/runtime_rx_page_content_live_probe_diagnostic_v1.py" \
          --diagnostic "$diagnostic_tmp" --require-executed \
          --prior-failure-manifest "$prior_failure_manifest" >/dev/null 2>&1; then
        if python3 - "$diagnostic_tmp" "$diagnostic" <<'PY'
import os, sys
os.replace(sys.argv[1], sys.argv[2])
directory = os.open(os.path.dirname(sys.argv[2]), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
        then
          diagnostic_committed=true
          printf 'DIAGNOSTIC=%s\n' "$diagnostic" >&2
        else
          # A rename followed by failed directory fsync is not accepted as a
          # committed diagnostic authority. Purge both names before fallback.
          rm -f -- "$diagnostic" "$diagnostic_tmp"
          diagnostic_eligible=false
        fi
      else
        rm -f -- "$diagnostic_tmp"
        diagnostic_eligible=false
      fi
    fi

    if [ "$diagnostic_committed" != true ]; then
      rm -f -- "$diagnostic" "$diagnostic_tmp" "$failure_manifest" "$failure_manifest_tmp"
      if ! RUN_ID="$run_id" FAILURE_STAGE="$stage" FAILURE_EXIT="$code" \
      CLEANUP_STATUS="$cleanup_status" METADATA_DIGEST="$metadata_digest" BUILD_DIGEST="$build_digest" \
        python3 - "$failure_manifest_tmp" "$failure_manifest" <<'PY'
import json, os, sys
payload = {
  "schema": "tamandua.runtime_integrity_live_probe_failure/v1",
  "run_id": os.environ["RUN_ID"],
  "stage": os.environ["FAILURE_STAGE"],
  "exit_code": int(os.environ["FAILURE_EXIT"]),
  "cleanup_status": os.environ["CLEANUP_STATUS"],
  "log_sha256": {
    "cargo_metadata_stderr": os.environ["METADATA_DIGEST"] or None,
    "cargo_build_stderr": os.environ["BUILD_DIGEST"] or None,
  },
  "raw_logs_retained": os.environ["CLEANUP_STATUS"] != "completed",
}
with open(sys.argv[1], "x", encoding="utf-8") as stream:
    json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
    stream.flush()
    os.fsync(stream.fileno())
os.replace(sys.argv[1], sys.argv[2])
directory = os.open(os.path.dirname(sys.argv[2]), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
      then
        rm -f -- "$failure_manifest_tmp" "$failure_manifest"
      fi
    fi
  fi
  printf 'BLOCKED_STAGE=%s CLEANUP=%s\n' "$stage" "$cleanup_status" >&2
  exit "$code"
}

ensure_protected_parent() {
  local candidate="$1" mode
  if [ -e "$candidate" ]; then
    test -d "$candidate" && test ! -L "$candidate"
    test "$(stat -Lc '%u' "$candidate")" -eq 0
    mode="$(stat -Lc '%a' "$candidate")"
    test $((8#$mode & 8#022)) -eq 0
  else
    install -d -o root -g root -m 0755 -- "$candidate"
  fi
}

assert_loopback_admin_down() {
  local link flags
  link="$(ip -o link show dev lo 2>/dev/null)" || return 86
  printf '%s\n' "$link" | grep -Eq ' state DOWN( |$)' || return 86
  flags="${link#*<}"
  flags="${flags%%>*}"
  case ",$flags," in
    *,UP,*) return 86 ;;
  esac
}

normalize_counter() {
  case "${1-}" in
    ''|*[!0-9]*) printf '0\n' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

classify_probe_process_result() {
  if [ "$probe_result" -eq 86 ] && [ ! -s "$trace_log" ]; then
    stage="isolated_namespace_setup"
    probe_started=false
  else
    stage="probe_process_capture"
    probe_started=true
  fi
  if [ "$probe_started" = true ] && { [ "$probe_result" -eq 124 ] || [ "$probe_result" -eq 137 ]; }; then
    probe_timed_out=true
  elif [ "$probe_started" = true ]; then
    probe_exit_observed=true
    probe_exit_code="$probe_result"
  fi
}

stage="frozen_retry_input_preflight"
test "$(sha256sum "$prior_failure_manifest" | awk '{print $1}')" = \
  "70f0b15c6387946134946c86be6ddc557a148ba5cf2b98d952eba1469ebca5df"
test "$(sha256sum "$root/schemas/runtime_rx_page_content_live_probe_diagnostic_v1.schema.json" | awk '{print $1}')" = "$diagnostic_schema_sha"
test "$(sha256sum "$root/tools/detection_validation/scripts/runtime_rx_page_content_live_probe_diagnostic_v1.py" | awk '{print $1}')" = "$diagnostic_gate_sha"
test "$(sha256sum "$root/tools/detection_validation/fixtures/runtime_rx_page_content_live_probe_diagnostic_v1.json" | awk '{print $1}')" = "$diagnostic_fixture_sha"
test "$(sha256sum "$root/tools/detection_validation/tests/test_runtime_rx_page_content_live_probe_diagnostic_v1.py" | awk '{print $1}')" = "$diagnostic_tests_sha"
test "$(sha256sum "$root/apps/tamandua_agent/src/main.rs" | awk '{print $1}')" = "$agent_main_sha"

stage="run_reservation"
ensure_protected_parent "/var/tmp/tamandua-loop68"
ensure_protected_parent "/var/tmp/tamandua-loop68-receipts"
ensure_protected_parent "/opt/tamandua-loop68"
ensure_protected_parent "/etc/tamandua-loop68"
if ! mkdir -m 0700 -- "$evidence_root"; then
  printf 'BLOCKED_STAGE=run_reservation REASON=run_id_already_reserved\n' >&2
  exit 73
fi
evidence_owned=true
trap on_exit EXIT
for candidate in "$build_root" "$install_root" "$config_root"; do
  if [ -e "$candidate" ]; then
    stage="run_path_collision"
    exit 74
  fi
done
mkdir -m 0700 -- "$build_root" && build_created=true
mkdir -m 0755 -- "$install_root" && install_created=true
mkdir -m 0755 -- "$config_root" && config_created=true
mkdir -m 0700 -- "$target_dir" "$log_dir"
source_sha="$(git -c safe.directory="$root" -C "$root" rev-parse HEAD)"
cargo_lock_sha="$(sha256sum "$root/apps/tamandua_agent/Cargo.lock" | awk '{print $1}')"
rustc_version="$(rustc --version)"
cargo_version="$(cargo --version)"
build_command_sha="$(printf '%s' "$build_command" | sha256sum | awk '{print $1}')"

scoped_dirty="$3"
scoped_dirty_diff_sha="$4"
runner_sha="$6"
schema_sha="$7"
gate_sha="$8"
fixture_sha="$9"

cd "$root"
export CARGO_TARGET_DIR="$target_dir"
export CARGO_NET_OFFLINE=true
stage="cargo_metadata_locked_offline"
cargo metadata --locked --offline --no-deps --manifest-path apps/tamandua_agent/Cargo.toml \
  >"${log_dir}/cargo-metadata.json" 2>"${log_dir}/cargo-metadata.stderr"
stage="cargo_build_release_locked_offline"
cargo build --release --locked --manifest-path apps/tamandua_agent/Cargo.toml --bin tamandua-agent \
  >"${log_dir}/cargo-build.stdout" 2>"${log_dir}/cargo-build.stderr"
built="${target_dir}/release/tamandua-agent"
stage="artifact_verification"
test -f "$built" && test ! -L "$built"
file "$built" | grep -q 'ELF 64-bit.*x86-64'

install -o root -g root -m 0555 "$built" "$artifact"
artifact_sha="$(sha256sum "$artifact" | awk '{print $1}')"
artifact_size="$(stat -Lc '%s' "$artifact")"
config_source="${log_dir}/agent.toml"
printf '[collectors.runtime_rx_page_content]\nenabled = true\nexpected_sha256 = "%s"\n' "$artifact_sha" > "$config_source"
install -o root -g root -m 0600 "$config_source" "$config"
config_sha="$(sha256sum "$config" | awk '{print $1}')"

artifact_before="$artifact_sha"
config_before="$config_sha"
probe_stdout="${log_dir}/probe-output.json"
probe_stderr="${log_dir}/probe-diagnostic.json"
trace_log="${log_dir}/strace.log"
time_log="${log_dir}/time-v.txt"
stage="isolated_probe"
export -f assert_loopback_admin_down
set +e
timeout --signal=TERM --kill-after=5s 60s unshare --net -- bash -ceu '
  ip link set lo down >/dev/null 2>&1 || exit 86
  assert_loopback_admin_down || exit 86
  exec /usr/bin/time -v -o "$1" strace -f -qq -s 4096 -o "$2" \
    -e trace=%network,%file,%ipc,%desc,%process \
    "$3" --config "$4" runtime-integrity-preview-probe > "$5" 2> "$6"
' bash "$time_log" "$trace_log" "$artifact" "$config" "$probe_stdout" "$probe_stderr"
probe_result="$?"
set -e
classify_probe_process_result

stage="probe_output_capture"
stdout_bytes=0; stderr_bytes=0
[ -f "$probe_stdout" ] && stdout_bytes="$(stat -Lc '%s' "$probe_stdout")"
[ -f "$probe_stderr" ] && stderr_bytes="$(stat -Lc '%s' "$probe_stderr")"
output_bytes="$((stdout_bytes + stderr_bytes))"
if [ "$output_bytes" -gt 0 ]; then
  output_sha="$( { cat -- "$probe_stdout" 2>/dev/null || true; cat -- "$probe_stderr" 2>/dev/null || true; } | sha256sum | awk '{print $1}')"
fi
if [ ! -e "$probe_stdout" ] && [ ! -e "$probe_stderr" ]; then
  output_state=absent
elif [ "$output_bytes" -eq 0 ]; then
  output_state=empty
elif [ "$probe_timed_out" = true ]; then
  output_state=partial
else
  output_state=complete_invalid
fi

# Agent failure stderr is accepted only as the exact four-field categorical
# JSON contract; the raw value is never printed or retained.
if [ "$probe_result" -ne 0 ] && [ "$stderr_bytes" -gt 0 ] && [ "$stderr_bytes" -le 4096 ]; then
  if python3 - "$probe_stderr" <<'PY'
import json, sys
allowed_pairs = {
  ("preconditions", "root_required"), ("preconditions", "override_rejected"),
  ("config_open", "config_open_failed"), ("config_parse", "config_shape_invalid"),
  ("config_parse", "baseline_invalid"), ("runtime_build", "runtime_build_failed"),
  ("sweep", "probe_timeout"), ("summary_validation", "invalid_progression"),
  ("completion_validation", "sweep_exhausted"), ("timing_validation", "timing_exceeded"),
  ("serialization", "serialization_failed"), ("output_bound", "output_too_large"),
}
assert len(allowed_pairs) == 12
try:
    raw = open(sys.argv[1], "rb").read()
    value = json.loads(raw.decode("utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(value, dict) or set(value) != {"schema", "state", "checkpoint", "code"}:
    raise SystemExit(1)
if value["schema"] != "tamandua.runtime_integrity_probe_internal_diagnostic/v1":
    raise SystemExit(1)
if value["state"] != "categorical_diagnostic":
    raise SystemExit(1)
if (value["checkpoint"], value["code"]) not in allowed_pairs:
    raise SystemExit(1)
PY
  then
    internal_diagnostic_valid=true
    output_state=complete_valid
  fi
fi

if [ "$probe_result" -eq 0 ] && [ "$stderr_bytes" -eq 0 ] && \
    [ "$stdout_bytes" -gt 0 ] && [ "$stdout_bytes" -le 2097152 ] && \
    python3 -m json.tool "$probe_stdout" >/dev/null 2>&1; then
  output_state=complete_valid
fi

stage="probe_trace_aggregate"
network_syscalls="$(grep -Ec '(^|[[:space:]])(socket|socketpair|connect|accept|accept4|bind|listen|sendto|recvfrom|sendmsg|recvmsg|getsockname|getpeername|shutdown)\(' "$trace_log" 2>/dev/null || true)"
ipc_syscalls="$(grep -Ec '(^|[[:space:]])(msgget|msgsnd|msgrcv|msgctl|semget|semop|semtimedop|semctl|shmget|shmat|shmdt|shmctl|eventfd|eventfd2|pipe|pipe2|memfd_create|epoll_create|epoll_create1|inotify_init|inotify_init1|signalfd|signalfd4)\(' "$trace_log" 2>/dev/null || true)"
probe_branch_execs="$(grep -Ec 'execve\(.*runtime-integrity-preview-probe' "$trace_log" 2>/dev/null || true)"
all_execs="$(grep -Ec '(^|[[:space:]])execve\(' "$trace_log" 2>/dev/null || true)"
metadata_mutations="$(grep -Ec '(^|[[:space:]])(creat|unlink|unlinkat|rename|renameat|renameat2|mkdir|mkdirat|rmdir|truncate|ftruncate|chmod|fchmod|fchmodat|chown|fchown|fchownat|link|linkat|symlink|symlinkat|mknod|mknodat|utime|utimes|futimesat|utimensat|setxattr|lsetxattr|fsetxattr|removexattr|lremovexattr|fremovexattr|fallocate)\(|open(at|at2)?\([^\n]*(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND|O_TMPFILE)' "$trace_log" 2>/dev/null || true)"
unexpected_data_writes="$(grep -E '(^|[[:space:]])(write|writev|pwrite64|pwritev|pwritev2|copy_file_range|sendfile|splice|vmsplice|tee)\(' "$trace_log" 2>/dev/null | grep -Evc '(^|[[:space:]])write(v)?\(1,' 2>/dev/null || true)"
network_syscalls="$(normalize_counter "$network_syscalls")"
ipc_syscalls="$(normalize_counter "$ipc_syscalls")"
probe_branch_execs="$(normalize_counter "$probe_branch_execs")"
all_execs="$(normalize_counter "$all_execs")"
metadata_mutations="$(normalize_counter "$metadata_mutations")"
unexpected_data_writes="$(normalize_counter "$unexpected_data_writes")"
mutation_syscalls="$((metadata_mutations + unexpected_data_writes))"
if [ -s "$trace_log" ]; then trace_sha="$(sha256sum "$trace_log" | awk '{print $1}')"; fi
if [ -s "$time_log" ]; then time_sha="$(sha256sum "$time_log" | awk '{print $1}')"; fi
if [ -n "$trace_sha" ] || [ -n "$time_sha" ]; then trace_state=partial; fi
if [ -n "$trace_sha" ] && [ -n "$time_sha" ] && [ "$probe_exit_observed" = true ]; then trace_state=complete; fi
if [ "$probe_started" != true ]; then
  stage="isolated_namespace_setup"
  exit 86
fi

stage="probe_custody_validate"
artifact_after="$(sha256sum "$artifact" | awk '{print $1}')"
config_after="$(sha256sum "$config" | awk '{print $1}')"
if [ "$artifact_before" != "$artifact_after" ]; then artifact_unchanged=false; fi
if [ "$config_before" != "$config_after" ]; then config_unchanged=false; fi
stage="probe_protection_validate"
artifact_mode="$(stat -Lc '%a' "$artifact")"
artifact_uid="$(stat -Lc '%u' "$artifact")"
config_mode="$(stat -Lc '%a' "$config")"
config_uid="$(stat -Lc '%u' "$config")"
artifact_regular=false; artifact_symlink=true
config_regular=false; config_symlink=true
if [ -f "$artifact" ]; then artifact_regular=true; fi
if [ ! -L "$artifact" ]; then artifact_symlink=false; fi
if [ -f "$config" ]; then config_regular=true; fi
if [ ! -L "$config" ]; then config_symlink=false; fi
test "$artifact_regular" = true && test "$artifact_symlink" = false
test "$config_regular" = true && test "$config_symlink" = false
test "$artifact_uid" -eq 0 && test "$config_uid" -eq 0
test "$artifact_mode" = 555 -o "$artifact_mode" = 755
test "$config_mode" = 600
for candidate in / /opt /opt/tamandua-loop68 "$install_root" /etc /etc/tamandua-loop68 "$config_root"; do
  test -d "$candidate" && test ! -L "$candidate"
  test "$(stat -Lc '%u' "$candidate")" -eq 0
  candidate_mode="$(stat -Lc '%a' "$candidate")"
  test $((8#$candidate_mode & 8#022)) -eq 0
done
protected_ancestors=true
probe_branch_attested=false
if [ "$probe_branch_execs" -eq 1 ] && [ "$all_execs" -eq 1 ]; then
  probe_branch_attested=true
fi
test "$probe_branch_attested" = true
stage="probe_rss_validate"
max_rss="$(awk -F: '/Maximum resident set size \(kbytes\)/ {gsub(/[[:space:]]/,"",$2); print $2}' "$time_log")"

# Only the fully valid clean lane proceeds to receipt v1. Every isolated
# failure reaches the trap after all safe aggregates have been captured.
if [ "$probe_result" -ne 0 ] || [ "$output_state" != complete_valid ] || \
   [ "$network_syscalls" -ne 0 ] || [ "$ipc_syscalls" -ne 0 ] || \
   [ "$probe_branch_execs" -ne 1 ] || [ "$all_execs" -ne 1 ] || \
   [ "$mutation_syscalls" -ne 0 ] || [ "$artifact_unchanged" != true ] || \
   [ "$config_unchanged" != true ] || [ -z "$max_rss" ]; then
  if [ "$ipc_syscalls" -ne 0 ]; then
    stage="probe_ipc_policy_uncategorizable"
  elif [ "$probe_branch_execs" -ne 1 ] || [ "$all_execs" -ne 1 ]; then
    stage="probe_exec_attestation_uncategorizable"
  elif [ -z "$max_rss" ]; then
    stage="probe_rss_uncategorizable"
  else
    stage="isolated_probe_categorized_failure"
  fi
  exit 86
fi

# Retain only the sanitized JSON needed to compose the receipt and the hashes of
# the raw diagnostic logs. The logs themselves stay below build_root and are
# removed before any receipt claims cleanup completion.
install -m 0600 -- "$probe_stdout" "$receipt_probe_input"
# trace_sha and time_sha were computed before cleanup for both outcomes.

stage="contained_cleanup"
cleanup_targets
test ! -e "$build_root" && test ! -e "$install_root" && test ! -e "$config_root"

export RUN_ID="$run_id" SOURCE_SHA="$source_sha" SCOPED_DIRTY="$scoped_dirty"
export SCOPED_DIFF_SHA="$scoped_dirty_diff_sha" CARGO_LOCK_SHA="$cargo_lock_sha"
export RUSTC_VERSION="$rustc_version" CARGO_VERSION="$cargo_version"
export BUILD_COMMAND="$build_command" BUILD_COMMAND_SHA="$build_command_sha"
export ARTIFACT_SHA="$artifact_sha" ARTIFACT_SIZE="$artifact_size" CONFIG_SHA="$config_sha"
export ARTIFACT_BEFORE="$artifact_before" ARTIFACT_AFTER="$artifact_after"
export CONFIG_BEFORE="$config_before" CONFIG_AFTER="$config_after"
export ARTIFACT_MODE="0${artifact_mode}" ARTIFACT_UID="$artifact_uid"
export CONFIG_MODE="0${config_mode}" CONFIG_UID="$config_uid"
export NETWORK_SYSCALLS="$network_syscalls" MUTATION_SYSCALLS="$mutation_syscalls"
export ARTIFACT_REGULAR="$artifact_regular" ARTIFACT_SYMLINK="$artifact_symlink"
export CONFIG_REGULAR="$config_regular" CONFIG_SYMLINK="$config_symlink"
export PROTECTED_ANCESTORS="$protected_ancestors"
export PROBE_BRANCH_ATTESTED="$probe_branch_attested" PROBE_BRANCH_EXECS="$probe_branch_execs"
export IPC_SYSCALLS="$ipc_syscalls" ALL_EXECS="$all_execs"
export MAX_RSS="$max_rss" PROBE_STDOUT="$receipt_probe_input" RECEIPT="$receipt"
stage="receipt_gate"
python3 - <<'PY'
import json, os
from datetime import datetime, timezone
probe = json.load(open(os.environ["PROBE_STDOUT"], encoding="utf-8"))
final = probe["final_summary"]
receipt = {
  "schema": "tamandua.runtime_integrity_live_probe_receipt/v1",
  "evidence_class": "local_live_collector_smoke", "execution_scope": "wsl2_network_isolated",
  "execute": True, "external_claim_allowed": False, "fpr_claim_allowed": False,
  "performance_claim_allowed": False, "vendor_parity_claimed": False,
  "run_id": os.environ["RUN_ID"],
  "executed_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "receipt_provenance": "live_probe_runner", "scenario": "owned_release_clean",
  "provenance": {
    "source_sha": os.environ["SOURCE_SHA"], "scoped_dirty": os.environ["SCOPED_DIRTY"] == "true",
    "scoped_dirty_diff_sha256": os.environ["SCOPED_DIFF_SHA"],
    "cargo_lock_sha256": os.environ["CARGO_LOCK_SHA"], "rustc_version": os.environ["RUSTC_VERSION"],
    "cargo_version": os.environ["CARGO_VERSION"], "build_command": os.environ["BUILD_COMMAND"],
    "build_command_sha256": os.environ["BUILD_COMMAND_SHA"], "artifact_sha256": os.environ["ARTIFACT_SHA"],
    "artifact_size_bytes": int(os.environ["ARTIFACT_SIZE"]), "artifact_arch": "x86_64",
    "artifact_profile": "release", "config_sha256": os.environ["CONFIG_SHA"]},
  "custody": {"artifact_sha256_before": os.environ["ARTIFACT_BEFORE"],
    "artifact_sha256_after": os.environ["ARTIFACT_AFTER"], "artifact_unchanged": True,
    "config_sha256_before": os.environ["CONFIG_BEFORE"], "config_sha256_after": os.environ["CONFIG_AFTER"],
    "config_unchanged": True},
  "protection": {"artifact_regular_file": os.environ["ARTIFACT_REGULAR"] == "true",
    "artifact_symlink": os.environ["ARTIFACT_SYMLINK"] == "true",
    "artifact_owner_uid": int(os.environ["ARTIFACT_UID"]), "artifact_mode": os.environ["ARTIFACT_MODE"],
    "config_regular_file": os.environ["CONFIG_REGULAR"] == "true",
    "config_symlink": os.environ["CONFIG_SYMLINK"] == "true", "config_owner_uid": int(os.environ["CONFIG_UID"]),
    "config_mode": os.environ["CONFIG_MODE"],
    "protected_ancestor_directories": os.environ["PROTECTED_ANCESTORS"] == "true"},
  "isolation": {"wsl2": True, "network_namespace_isolated": True, "loopback_disabled": True,
    "backend_constructed": not (
      os.environ["PROBE_BRANCH_ATTESTED"] == "true"
      and int(os.environ["NETWORK_SYSCALLS"]) == 0
      and int(os.environ["ALL_EXECS"]) == 1),
    "ipc_constructed": int(os.environ["IPC_SYSCALLS"]) != 0,
    "strace_network_syscalls": int(os.environ["NETWORK_SYSCALLS"]),
    "strace_filesystem_mutation_syscalls": int(os.environ["MUTATION_SYSCALLS"])},
  "measurements": {"config_load_elapsed_us": probe["config_load_elapsed_us"],
    "collector_init_elapsed_us": probe["collector_init_elapsed_us"],
    "probe_wall_elapsed_us": probe["probe_wall_elapsed_us"], "max_rss_kib": int(os.environ["MAX_RSS"]),
    "max_rss_source": "usr_bin_time_v"},
  "probe_output": probe,
  "benign_matrix": {"input_class": "owned_release_unchanged", "expected_status": "clean",
    "compromise_observed": False, "drift_observed": False},
  "cleanup": {"completed": True, "temporary_artifacts_remaining": 0, "network_namespace_removed": True}}
with open(os.environ["RECEIPT"], "x", encoding="utf-8") as stream:
    json.dump(receipt, stream, sort_keys=True, separators=(",", ":"))
PY
rm -f -- "$receipt_probe_input"

python3 "$root/tools/detection_validation/scripts/runtime_rx_page_content_live_probe_v1.py" \
  --receipt "$receipt" --require-executed > "${evidence_root}/gate.stdout"
sha256sum "$receipt" > "${evidence_root}/receipt.sha256"
receipt_sha="$(awk '{print $1}' "${evidence_root}/receipt.sha256")"
printf '%s  strace.log\n%s  time-v.txt\n' "$trace_sha" "$time_sha" \
  > "${evidence_root}/sanitized-log-digests.sha256"
sanitized_digests_sha="$(sha256sum "${evidence_root}/sanitized-log-digests.sha256" | awk '{print $1}')"
gate_stdout_sha="$(sha256sum "${evidence_root}/gate.stdout" | awk '{print $1}')"
export RECEIPT_SHA="$receipt_sha" RUNNER_SHA="$runner_sha" SCHEMA_SHA="$schema_sha"
export GATE_SHA="$gate_sha" FIXTURE_SHA="$fixture_sha"
export TRACE_SHA="$trace_sha" TIME_SHA="$time_sha" SANITIZED_DIGESTS_SHA="$sanitized_digests_sha"
export GATE_STDOUT_SHA="$gate_stdout_sha"
stage="terminal_success_manifest"
python3 - "$execution_manifest_tmp" "$execution_manifest" <<'PY'
import json, os, sys
manifest = {
  "schema": "tamandua.runtime_integrity_live_probe_execution_manifest/v1",
  "complete": True,
  "run_id": os.environ["RUN_ID"],
  "receipt_file": "receipt.json",
  "receipt_sha256": os.environ["RECEIPT_SHA"],
  "gate_stdout_sha256": os.environ["GATE_STDOUT_SHA"],
  "sanitized_log_digests": {
    "strace_sha256": os.environ["TRACE_SHA"],
    "time_v_sha256": os.environ["TIME_SHA"],
    "digest_file_sha256": os.environ["SANITIZED_DIGESTS_SHA"],
  },
  "attestation": {
    "preview_branch_exec_count": int(os.environ["PROBE_BRANCH_EXECS"]),
    "preview_branch_attested": os.environ["PROBE_BRANCH_ATTESTED"] == "true",
  },
  "inputs": {
    "runner_sha256": os.environ["RUNNER_SHA"],
    "receipt_schema_sha256": os.environ["SCHEMA_SHA"],
    "receipt_gate_sha256": os.environ["GATE_SHA"],
    "synthetic_fixture_sha256": os.environ["FIXTURE_SHA"],
    "scoped_dirty": os.environ["SCOPED_DIRTY"] == "true",
    "scoped_dirty_diff_sha256": os.environ["SCOPED_DIFF_SHA"],
  },
  "raw_logs_retained": False,
}
with open(sys.argv[1], "x", encoding="utf-8") as stream:
    json.dump(manifest, stream, sort_keys=True, separators=(",", ":"))
    stream.flush()
    os.fsync(stream.fileno())
os.replace(sys.argv[1], sys.argv[2])
directory = os.open(os.path.dirname(sys.argv[2]), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
test -f "$execution_manifest" && test ! -e "$execution_manifest_tmp"
trap - EXIT
printf 'RECEIPT=%s\n' "$receipt"
printf 'RECEIPT_SHA256=%s\n' "$(awk '{print $1}' "${evidence_root}/receipt.sha256")"
'@

$temp = Join-Path ([IO.Path]::GetTempPath()) "tamandua-loop68-$runId.sh"
try {
    [IO.File]::WriteAllText($temp, ($Bash -replace "`r`n", "`n"), [Text.UTF8Encoding]::new($false))
    $wslTemp = (& $WslExecutable @WslArgs wslpath -a ($temp -replace '\\', '/')).Trim()
    & $WslExecutable @WslArgs --user root bash $wslTemp $WslRoot $runId $scopedDirtyText $scopedDiffSha $WslToolchainHome $RunnerSha $SchemaSha $GateSha $FixtureSha $WslPriorManifest $attemptNonce $DiagnosticSchemaSha $DiagnosticGateSha $DiagnosticFixtureSha $DiagnosticTestsSha $AgentMainSha
    if ($LASTEXITCODE -ne 0) { throw "Executed live-probe runner failed closed" }
}
finally {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
}
