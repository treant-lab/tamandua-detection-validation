from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/build_elixir_postgres_runtime_runner.py"
DOCKERFILE = ROOT / "apps/tamandua_server/Dockerfile.runtime-validation-runner"
SCHEMA = ROOT / "schemas/elixir_postgres_runtime_runner_receipt_v1.schema.json"
SPEC = importlib.util.spec_from_file_location("runtime_runner", SCRIPT)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def args(**overrides):
    values = dict(
        base_image="hexpm/elixir:1.18.4-erlang-27.3.4-alpine-3.21.3@sha256:" + "a" * 64,
        base_platform_image="hexpm/elixir@sha256:" + "f" * 64,
        expected_base_image_id="sha256:" + "b" * 64,
        source_sha=runner.current_source_sha(),
        elixir_version="1.18.4",
        erlang_version="27.3.4",
        otp_release="27",
        alpine_version="3.21.3",
        hex_version="2.2.1",
        apk_repository_branch="v3.21",
        postgresql_client_package="postgresql16-client",
        postgresql_client_package_version="16.14-r0",
        psql_version="16.14",
        alpine_toolchain_packages="build-base git python3 pkgconf openssl-dev libxml2-dev",
        platform="linux/amd64",
        expected_package_manifest_sha256="d" * 64,
        repository="tamandua/runtime-validation-runner",
        invocation_id="local-12345678",
        execute=False,
        output=None,
    )
    values.update(overrides)
    return argparse.Namespace(**values)


class FakeCommands:
    def __init__(self, namespace, provenance, *, fail_post=False, invalid_iid=False,
                 preexisting=False, fail_tag_remove=False, divergent_tag=False,
                 post_exception=False, bad_labels=False, build_failure=None):
        self.namespace = namespace
        self.provenance = provenance
        self.fail_post = fail_post
        self.calls = []
        self.image_id = "sha256:" + "e" * 64
        self.build_done = False
        self.image_exists = preexisting
        self.tag_exists = False
        self.invalid_iid = invalid_iid
        self.preexisting = preexisting
        self.fail_tag_remove = fail_tag_remove
        self.divergent_tag = divergent_tag
        self.post_exception = post_exception
        self.bad_labels = bad_labels
        self.build_failure = build_failure
        self.divergent_id = "sha256:" + "7" * 64

    def run(self, command, timeout=1800):
        self.calls.append(command)
        if command[:3] == ["docker", "image", "inspect"]:
            if command[3] in (self.namespace.base_image, self.namespace.base_platform_image):
                payload = [{"Id": self.namespace.expected_base_image_id, "Os": "linux", "Architecture": "amd64", "Config": {"Labels": {}}}]
            elif command[3].startswith(self.namespace.repository + ":"):
                if not self.tag_exists:
                    return subprocess.CompletedProcess(command, 1, "", "not found")
                image_id = self.divergent_id if self.divergent_tag else self.image_id
                labels = {} if self.divergent_tag or self.bad_labels else runner.expected_labels(self.namespace, self.provenance)
                payload = [{"Id": image_id, "Os": "linux", "Architecture": "amd64", "RepoTags": [command[3]], "Config": {"Labels": labels}}]
            elif command[3] == self.image_id and self.image_exists:
                tags = [] if not self.tag_exists else [
                    self.namespace.repository + ":" + self.namespace.source_sha[:12] + "-" + self.namespace.invocation_id
                ]
                labels = {} if self.bad_labels else runner.expected_labels(self.namespace, self.provenance)
                payload = [{"Id": self.image_id, "Os": "linux", "Architecture": "amd64", "RepoTags": tags, "Config": {"Labels": labels}}]
            elif not self.build_done:
                return subprocess.CompletedProcess(command, 1, "", "not found")
            else:
                return subprocess.CompletedProcess(command, 1, "", "not found")
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command[:2] == ["docker", "build"]:
            Path(command[command.index("--iidfile") + 1]).write_text(
                "invalid" if self.invalid_iid else self.image_id, encoding="ascii"
            )
            self.build_done = True
            self.image_exists = True
            self.tag_exists = True
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:3] == ["docker", "image", "ls"]:
            inventory = (
                self.image_id + "\n"
                if "--quiet" in command and self.preexisting and not self.build_done
                else ""
            )
            return subprocess.CompletedProcess(command, 0, inventory, "")
        if command[:3] == ["docker", "image", "rm"]:
            reference = command[3]
            if reference.startswith(self.namespace.repository + ":"):
                if self.fail_tag_remove:
                    return subprocess.CompletedProcess(command, 1, "", "tag busy")
                self.tag_exists = False
            elif reference == self.image_id:
                self.image_exists = False
                if not self.divergent_tag:
                    self.tag_exists = False
            else:
                raise AssertionError(command)
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:2] == ["docker", "run"]:
            if self.post_exception:
                raise OSError("synthetic postverify failure")
            return subprocess.CompletedProcess(command, 1 if self.fail_post else 0, "", "")
        raise AssertionError(command)

    def run_build(self, command, timeout=1800):
        if self.build_failure is None:
            return self.run(command, timeout=timeout)
        self.calls.append(command)
        return self.build_failure


def test_input_provenance_is_complete_and_stable():
    first = runner.input_provenance()
    second = runner.input_provenance()
    assert first == second
    assert first["config_file_count"] > 0
    for key in ("dockerfile_sha256", "mix_exs_sha256", "mix_lock_sha256", "config_sha256", "input_bundle_sha256"):
        assert runner.SHA256.fullmatch(first[key])


def test_inspect_mode_is_fail_closed_without_docker_calls():
    namespace = args()
    result, code = runner.execute(namespace)
    assert code == 2
    assert result["status"] == "blocked"
    assert result["diagnostic_contract_version"] == 2
    assert result["build_failure_diagnostic"] is None
    assert result["claims"] == {
        "build_verified": False,
        "runtime_validation_executed": False,
        "runtime_validated": False,
        "byte_reproducible": False,
        "product_ready": False,
        "production_validated": False,
        "external_claim_allowed": False,
        "vendor_parity": False,
    }
    assert result["tag"].endswith(namespace.source_sha[:12] + "-local-12345678")
    assert not result["tag"].endswith(":latest")
    Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(result)


def test_legacy_loop107_receipt_without_diagnostic_contract_remains_valid():
    namespace = args()
    legacy = runner.receipt(
        namespace,
        runner.input_provenance(),
        f"{namespace.repository}:{namespace.source_sha[:12]}-{namespace.invocation_id}",
    )
    legacy.pop("diagnostic_contract_version")
    legacy.pop("build_failure_diagnostic")

    Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(legacy)

    invalid_new = json.loads(json.dumps(legacy))
    invalid_new["diagnostic_contract_version"] = 1
    with pytest.raises(Exception):
        Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(invalid_new)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("base_image", "elixir:latest", "base_image_must_be_exact_hexpm_alpine_index_digest"),
        ("base_platform_image", "hexpm/elixir:latest", "base_platform_image_must_be_exact_amd64_manifest_digest"),
        ("expected_base_image_id", "sha256:abcd", "expected_base_config_id_must_be_full"),
        ("source_sha", "abc", "source_sha_must_be_full_git_sha"),
        ("expected_package_manifest_sha256", "abc", "expected_package_manifest_sha256_must_be_full"),
        ("psql_version", "17.1", "unexpected_alpine_chain_value:psql_version"),
        ("apk_repository_branch", "edge", "unexpected_alpine_chain_value:apk_repository_branch"),
        ("platform", "linux/arm64", "unexpected_alpine_chain_value:platform"),
        ("invocation_id", "latest", "invocation_id_invalid"),
        ("repository", "tamandua/runtime-validation-runner:latest", "repository_invalid"),
    ],
)
def test_invalid_or_mutable_inputs_are_rejected(field, value, message):
    namespace = args(**{field: value})
    with pytest.raises(ValueError, match=message):
        runner.validate_args(namespace)


def test_build_command_binds_every_provenance_input_and_never_pulls(tmp_path):
    namespace = args()
    provenance = runner.input_provenance()
    command = runner.build_args(
        namespace, tmp_path, provenance, "tamandua/runtime-validation-runner:unique", tmp_path / "iid"
    )
    rendered = " ".join(command)
    assert command[:6] == ["docker", "build", "--platform", "linux/amd64", "--pull=false", "--progress=plain"]
    assert "--tag tamandua/runtime-validation-runner:unique" in rendered
    assert "--iidfile" in command
    for value in (
        namespace.base_image, namespace.base_platform_image, namespace.expected_base_image_id, namespace.source_sha,
        namespace.elixir_version, namespace.erlang_version, namespace.otp_release,
        namespace.alpine_version, namespace.hex_version, namespace.apk_repository_branch,
        namespace.postgresql_client_package, namespace.postgresql_client_package_version,
        namespace.psql_version, namespace.alpine_toolchain_packages,
        namespace.expected_package_manifest_sha256, provenance["dockerfile_sha256"],
        provenance["mix_exs_sha256"], provenance["mix_lock_sha256"],
        provenance["config_sha256"], provenance["input_bundle_sha256"], namespace.invocation_id,
    ):
        assert value in rendered


def test_post_build_verification_is_full_id_network_none_and_read_only():
    namespace = args()
    image_id = "sha256:" + "f" * 64
    command = runner.verify_command(image_id, namespace)
    rendered = " ".join(command)
    assert command[:2] == ["docker", "run"]
    assert command[2:4] == ["--platform", "linux/amd64"]
    assert "--network none" in rendered
    assert "--read-only" in command
    assert command.index(image_id) > command.index("--entrypoint")
    assert "mix deps.check" in rendered
    assert "mix deps.get" not in rendered
    assert "local.hex" not in rendered
    assert "psql --version" in rendered
    assert "mix hex.info" in rendered
    assert "apk info -v" in rendered and "apk info -vv" not in rendered
    assert runner.APK_MAIN_REPOSITORY in rendered
    assert runner.APK_COMMUNITY_REPOSITORY in rendered
    assert "dpkg" not in rendered and "apt-get" not in rendered


def test_existing_invocation_tag_stops_before_build():
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    commands = FakeCommands(namespace, provenance)

    def existing(command, timeout=1800):
        commands.calls.append(command)
        if command[:3] == ["docker", "image", "inspect"]:
            if command[3] in (namespace.base_image, namespace.base_platform_image):
                payload = {"Id": namespace.expected_base_image_id, "Os": "linux", "Architecture": "amd64", "Config": {"Labels": {}}}
            else:
                payload = {"Id": "sha256:" + "7" * 64, "Os": "linux", "Architecture": "amd64", "Config": {"Labels": {}}}
            return subprocess.CompletedProcess(command, 0, json.dumps([payload]), "")
        raise AssertionError(command)

    commands.run = existing
    result, code = runner.execute(namespace, commands)
    assert code == 2
    assert result["checks"]["tag_absent_before_build"] is False
    assert not any(call[:2] == ["docker", "build"] for call in commands.calls)


def test_mocked_execution_verifies_full_id_labels_and_offline_post_build(monkeypatch):
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    commands = FakeCommands(namespace, provenance)
    result, code = runner.execute(namespace, commands)
    assert code == 0
    assert result["status"] == "pass"
    assert result["diagnostic_contract_version"] == 2
    assert result["build_failure_diagnostic"] is None
    assert result["image"]["full_id"] == commands.image_id
    assert result["claims"]["build_verified"] is True
    assert result["claims"]["runtime_validation_executed"] is False
    assert result["claims"]["runtime_validated"] is False
    assert result["claims"]["byte_reproducible"] is False
    assert all(result["checks"].values())
    build = next(call for call in commands.calls if call[:2] == ["docker", "build"])
    verify = next(call for call in commands.calls if call[:2] == ["docker", "run"])
    assert "--pull=false" in build and build[build.index("--platform") + 1] == "linux/amd64"
    assert commands.image_id in verify
    assert namespace.repository + ":" + namespace.source_sha[:12] + "-" + namespace.invocation_id not in verify
    Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(result)


def test_post_build_failure_never_promotes_build_claim():
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    commands = FakeCommands(namespace, provenance, fail_post=True)
    result, code = runner.execute(namespace, commands)
    assert code == 2
    assert result["status"] == "blocked"
    assert result["claims"]["build_verified"] is False
    assert result["image"]["post_build_verified"] is False
    assert result["cleanup"] == {
        "required": True,
        "attempted": True,
        "complete": True,
        "tag": {"attempted": True, "outcome": "removed", "observed_image_id": commands.image_id, "error": None},
        "image": {"attempted": True, "outcome": "removed", "observed_image_id": commands.image_id, "error": None},
        "residuals": [],
    }
    Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(result)

    dishonest = json.loads(json.dumps(result))
    dishonest["cleanup"] = runner.cleanup_state()
    with pytest.raises(Exception):
        Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(dishonest)


def test_build_failure_diagnostic_is_bounded_canonical_and_secretless():
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    secret = "super-secret-password"
    output = subprocess.CompletedProcess(
        ["docker", "build"],
        17,
        "x" * 70000 + "\n#7 [1/8] FROM token=" + secret + "\n",
        "\x1b[31m#1 WARN: UndefinedVar: credential=" + secret + "\x1b[0m\n"
        "#2 WARN: SuperSecretPassword: value=" + secret + "\n"
        "#8 [builder 2/8] RUN password=" + secret + "\n"
        "#8 0.125 TAMANDUA_RUNNER_FAILURE_V1:apk_install\n"
        "#8 ERROR: process prompt=" + secret + " did not complete successfully: exit code: 17\n"
        "failed to solve: bearer=" + secret + "\n\x01untrusted prompt " + secret + "\n",
    )
    output.stdout_observed_bytes = 70080
    output.stderr_observed_bytes = len(output.stderr.encode("utf-8"))
    output.stdout_truncated = True
    output.stderr_truncated = False
    output.timed_out = False
    commands = FakeCommands(namespace, provenance, build_failure=output)

    result, code = runner.execute(namespace, commands)

    assert code == 2
    diagnostic = result["build_failure_diagnostic"]
    assert result["diagnostic_contract_version"] == 2
    assert diagnostic["failure_kind"] == "process_exit"
    assert diagnostic["failure_checkpoint"] == "apk_install"
    assert diagnostic["command_exit_code"] == 17
    assert diagnostic["process_exit_code"] == 17
    assert diagnostic["error_step_id"] == 8
    assert diagnostic["step"] == {
        "buildkit_id": 8, "index": 2, "total": 8, "stage": "named", "instruction": "RUN"
    }
    assert diagnostic["warnings"] == ["UndefinedVar", "Other"]
    assert len(diagnostic["canonical_tail"]) <= runner.BUILD_DIAGNOSTIC_MAX_LINES
    assert diagnostic["stdout"] == {
        "observed_bytes": 70080, "retained_bytes": runner.BUILD_STREAM_TAIL_BYTES, "truncated": True
    }
    assert diagnostic["stderr"]["retained_bytes"] <= runner.BUILD_STREAM_TAIL_BYTES
    canonical = "\n".join(diagnostic["canonical_tail"]) + "\n"
    assert diagnostic["canonical_tail_sha256"] == runner.hashlib.sha256(canonical.encode("ascii")).hexdigest()
    rendered = json.dumps(diagnostic, sort_keys=True)
    for forbidden in (secret, "TAMANDUA_RUNNER_FAILURE_V1", "SuperSecretPassword", "credential=", "password=", "bearer=", "untrusted prompt", "\x1b", "\x01"):
        assert forbidden not in rendered
    Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(result)


def test_build_stage_name_is_never_serialized_or_schema_admitted():
    secret = "super-secret-password"
    output = subprocess.CompletedProcess(
        ["docker", "build"],
        17,
        "",
        f"#7 [{secret} 1/1] RUN echo x\n#7 ERROR: exit code: 17\n",
    )
    output.timed_out = False

    diagnostic = runner.build_failure_diagnostic(output)

    assert diagnostic["step"]["stage"] == "named"
    assert diagnostic["failure_checkpoint"] == "unknown"
    assert secret not in json.dumps(diagnostic, sort_keys=True)

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    invalid = runner.receipt(
        args(), runner.input_provenance(), "tamandua/runtime-validation-runner:" + "a" * 12 + "-local-test01"
    )
    invalid["status"] = "blocked"
    invalid["limitations"].append("docker_build_failed")
    invalid["build_failure_diagnostic"] = diagnostic | {
        "step": diagnostic["step"] | {"stage": secret}
    }
    with pytest.raises(Exception):
        Draft202012Validator(schema).validate(invalid)


def test_timeout_diagnostic_is_categorical_and_deterministic():
    timed_out = subprocess.CompletedProcess(["docker", "build"], 124, "", "arbitrary secret output")
    timed_out.timed_out = True
    first = runner.build_failure_diagnostic(timed_out)
    second = runner.build_failure_diagnostic(timed_out)
    assert first == second
    assert first["failure_kind"] == "timeout"
    assert first["canonical_tail"] == ["timeout", "checkpoint:unknown"]
    assert "arbitrary secret output" not in json.dumps(first)


@pytest.mark.parametrize("checkpoint", runner.RUNNER_FAILURE_CHECKPOINTS)
@pytest.mark.parametrize("elapsed", ["0.123", "0.123s"])
def test_terminal_buildkit_failure_checkpoint_is_parsed_from_allowlist(checkpoint, elapsed):
    output = subprocess.CompletedProcess(
        ["docker", "build"],
        19,
        "",
        "#7 [2/8] RUN checkpoint\n"
        f"#7 {elapsed} TAMANDUA_RUNNER_FAILURE_V1:{checkpoint}\n"
        "#7 ERROR: process did not complete successfully: exit code: 19\n",
    )
    output.timed_out = False

    diagnostic = runner.build_failure_diagnostic(output)

    assert diagnostic["failure_checkpoint"] == checkpoint
    assert diagnostic["canonical_tail"][-1] == f"checkpoint:{checkpoint}"
    assert "TAMANDUA_RUNNER_FAILURE_V1" not in json.dumps(diagnostic, sort_keys=True)


@pytest.mark.parametrize("stderr", [
    "TAMANDUA_RUNNER_FAILURE_V1:repositories\n#7 ERROR: exit code: 19\n",
    "noise #7 0.123 TAMANDUA_RUNNER_FAILURE_V1:repositories\n#7 ERROR: exit code: 19\n",
    "#7 0.123 TAMANDUA_RUNNER_FAILURE_V1:repositories trailing\n#7 ERROR: exit code: 19\n",
    "#7 0.123 TAMANDUA_RUNNER_FAILURE_V1:not_allowlisted\n#7 ERROR: exit code: 19\n",
    "#7 0.123 TAMANDUA_RUNNER_FAILURE_V1:repositories\n#7 0.124 later output\n#7 ERROR: exit code: 19\n",
    "#7 0.123 TAMANDUA_RUNNER_FAILURE_V1:repositories\n#8 ERROR: exit code: 19\n",
    "#7 0.123 TAMANDUA_RUNNER_FAILURE_V1:repositories\n",
    "#7 0.123 TAMANDUA_RUNNER_FAILURE_V1:repositories\n#7 ERROR: exit code: 19\n#8 ERROR: exit code: 20\n",
])
def test_spoofed_or_nonterminal_failure_checkpoint_is_unknown(stderr):
    output = subprocess.CompletedProcess(["docker", "build"], 19, "", stderr)
    output.timed_out = False

    diagnostic = runner.build_failure_diagnostic(output)

    assert diagnostic["failure_checkpoint"] == "unknown"
    assert diagnostic["canonical_tail"][-1] == "checkpoint:unknown"
    assert "TAMANDUA_RUNNER_FAILURE_V1" not in json.dumps(diagnostic, sort_keys=True)


def test_conflicting_terminal_failure_checkpoints_are_unknown():
    output = subprocess.CompletedProcess(
        ["docker", "build"],
        19,
        "",
        "#7 0.123 TAMANDUA_RUNNER_FAILURE_V1:repositories\n"
        "#7 ERROR: exit code: 19\n"
        "#8 0.124 TAMANDUA_RUNNER_FAILURE_V1:apk_install\n"
        "#8 ERROR: exit code: 19\n",
    )
    output.timed_out = False

    diagnostic = runner.build_failure_diagnostic(output)

    assert diagnostic["failure_checkpoint"] == "unknown"
    assert diagnostic["canonical_tail"][-1] == "checkpoint:unknown"


def test_stdout_checkpoint_cannot_pair_with_stderr_buildkit_error():
    output = subprocess.CompletedProcess(
        ["docker", "build"],
        19,
        "#7 0.123 TAMANDUA_RUNNER_FAILURE_V1:repositories\n",
        "#7 ERROR: exit code: 19\n",
    )
    output.timed_out = False

    diagnostic = runner.build_failure_diagnostic(output)

    assert diagnostic["failure_checkpoint"] == "unknown"


def test_duplicate_structured_checkpoint_is_unknown_even_if_one_is_terminal():
    output = subprocess.CompletedProcess(
        ["docker", "build"],
        19,
        "",
        "#7 0.122 TAMANDUA_RUNNER_FAILURE_V1:repositories\n"
        "#7 0.123 later output\n"
        "#7 0.124 TAMANDUA_RUNNER_FAILURE_V1:repositories\n"
        "#7 ERROR: exit code: 19\n",
    )
    output.timed_out = False

    diagnostic = runner.build_failure_diagnostic(output)

    assert diagnostic["failure_checkpoint"] == "unknown"


def test_later_exit_like_prose_cannot_override_final_buildkit_error_exit():
    output = subprocess.CompletedProcess(
        ["docker", "build"],
        1,
        "",
        "#7 0.123 TAMANDUA_RUNNER_FAILURE_V1:repositories\n"
        "#7 ERROR: process did not complete successfully: exit code: 19\n"
        "failed to solve: untrusted summary exit code: 88\n",
    )
    output.timed_out = False

    diagnostic = runner.build_failure_diagnostic(output)

    assert diagnostic["failure_checkpoint"] == "repositories"
    assert diagnostic["process_exit_code"] == 19
    assert [item for item in diagnostic["canonical_tail"] if item.startswith("process_exit:")] == [
        "process_exit:19"
    ]


def test_diagnostic_contract_v1_receipt_remains_schema_valid_without_checkpoint():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    legacy = runner.receipt(
        args(), runner.input_provenance(), "tamandua/runtime-validation-runner:" + "a" * 12 + "-local-test01"
    )
    legacy["status"] = "blocked"
    legacy["limitations"].append("docker_build_failed")
    output = subprocess.CompletedProcess(["docker", "build"], 17, "", "#7 ERROR: exit code: 17\n")
    output.timed_out = False
    diagnostic = runner.build_failure_diagnostic(output)
    diagnostic.pop("failure_checkpoint")
    diagnostic["canonical_tail"].remove("checkpoint:unknown")
    payload = ("\n".join(diagnostic["canonical_tail"]) + "\n").encode("ascii")
    diagnostic["canonical_tail_sha256"] = runner.hashlib.sha256(payload).hexdigest()
    legacy["diagnostic_contract_version"] = 1
    legacy["build_failure_diagnostic"] = diagnostic

    Draft202012Validator(schema).validate(legacy)


def test_diagnostic_contract_v2_rejects_diagnostic_without_checkpoint():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    receipt = runner.receipt(
        args(), runner.input_provenance(), "tamandua/runtime-validation-runner:" + "a" * 12 + "-local-test01"
    )
    receipt["status"] = "blocked"
    receipt["limitations"].append("docker_build_failed")
    output = subprocess.CompletedProcess(["docker", "build"], 17, "", "#7 ERROR: exit code: 17\n")
    output.timed_out = False
    diagnostic = runner.build_failure_diagnostic(output)
    diagnostic.pop("failure_checkpoint")
    receipt["build_failure_diagnostic"] = diagnostic

    with pytest.raises(Exception):
        Draft202012Validator(schema).validate(receipt)


def test_diagnostic_contract_v2_rejects_conflicting_checkpoint_event():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    receipt = runner.receipt(
        args(), runner.input_provenance(), "tamandua/runtime-validation-runner:" + "a" * 12 + "-local-test01"
    )
    receipt["status"] = "blocked"
    receipt["limitations"].append("docker_build_failed")
    output = subprocess.CompletedProcess(
        ["docker", "build"], 17, "",
        "#7 0.123 TAMANDUA_RUNNER_FAILURE_V1:repositories\n#7 ERROR: exit code: 17\n",
    )
    output.timed_out = False
    diagnostic = runner.build_failure_diagnostic(output)
    receipt["build_failure_diagnostic"] = diagnostic

    conflicting_field = json.loads(json.dumps(receipt))
    conflicting_field["build_failure_diagnostic"]["failure_checkpoint"] = "apk_install"
    with pytest.raises(Exception):
        Draft202012Validator(schema).validate(conflicting_field)

    conflicting_events = json.loads(json.dumps(receipt))
    conflicting_events["build_failure_diagnostic"]["canonical_tail"].insert(-1, "checkpoint:apk_install")
    with pytest.raises(Exception):
        Draft202012Validator(schema).validate(conflicting_events)


def test_real_build_adapter_retains_only_bounded_stream_tails():
    result = runner.Commands().run_build([
        sys.executable,
        "-c",
        "import sys; sys.stdout.write('A' * 70000); sys.stderr.write('B' * 70001)",
    ], timeout=30)
    assert result.returncode == 0
    assert result.stdout_observed_bytes == 70000
    assert result.stderr_observed_bytes == 70001
    assert result.stdout_truncated is True and result.stderr_truncated is True
    assert len(result.stdout.encode("utf-8")) == runner.BUILD_STREAM_TAIL_BYTES
    assert len(result.stderr.encode("utf-8")) == runner.BUILD_STREAM_TAIL_BYTES


def test_invalid_iid_recovers_identity_from_owned_tag_and_cleans_both_resources():
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    commands = FakeCommands(namespace, provenance, invalid_iid=True)
    result, code = runner.execute(namespace, commands)
    assert code == 2
    assert "build_iidfile_invalid" in result["limitations"]
    assert result["cleanup"]["complete"] is True
    assert result["cleanup"]["tag"]["outcome"] == "removed"
    assert result["cleanup"]["image"]["outcome"] == "removed"


def test_cleanup_continues_to_exact_image_after_tag_remove_failure():
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    commands = FakeCommands(namespace, provenance, fail_post=True, fail_tag_remove=True)
    result, code = runner.execute(namespace, commands)
    assert code == 2
    assert result["cleanup"]["tag"]["outcome"] == "absent"
    assert result["cleanup"]["image"]["attempted"] is True
    assert result["cleanup"]["image"]["outcome"] == "removed"
    assert result["cleanup"]["residuals"] == []


def test_cleanup_never_removes_a_preexisting_image_id():
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    commands = FakeCommands(namespace, provenance, fail_post=True, preexisting=True)
    result, code = runner.execute(namespace, commands)
    assert code == 2
    assert result["cleanup"]["tag"]["outcome"] == "skipped_preexisting"
    assert result["cleanup"]["image"]["outcome"] == "skipped_preexisting"
    assert commands.image_exists is True
    assert not any(call[:3] == ["docker", "image", "rm"] and call[3] == commands.image_id for call in commands.calls)


def test_cleanup_preserves_divergent_tag_but_removes_proven_owned_image():
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    commands = FakeCommands(namespace, provenance, fail_post=True, divergent_tag=True)
    result, code = runner.execute(namespace, commands)
    assert code == 2
    assert result["cleanup"]["tag"]["outcome"] == "skipped_divergent"
    assert result["cleanup"]["image"]["outcome"] == "removed"
    assert commands.tag_exists is True
    assert not any(call[:3] == ["docker", "image", "rm"] and call[3].startswith(namespace.repository + ":") for call in commands.calls)


def test_success_receipt_schema_failure_cleans_before_returning_blocked(monkeypatch):
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    commands = FakeCommands(namespace, provenance)
    real_validate = runner.validate_receipt

    def reject_pass(payload):
        if payload["status"] == "pass":
            raise ValueError("synthetic_schema_failure")
        real_validate(payload)

    monkeypatch.setattr(runner, "validate_receipt", reject_pass)
    result, code = runner.execute(namespace, commands)
    assert code == 2
    assert "receipt_schema_validation_failed" in result["limitations"]
    assert result["cleanup"]["attempted"] is True
    assert result["claims"]["build_verified"] is False


def test_postverify_adapter_exception_still_cleans_built_resources():
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    commands = FakeCommands(namespace, provenance, post_exception=True)
    result, code = runner.execute(namespace, commands)
    assert code == 2
    assert "offline_read_only_post_build_verification_error" in result["limitations"]
    assert result["cleanup"]["complete"] is True


def test_unproven_labels_leave_both_resources_as_honest_residuals():
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    commands = FakeCommands(namespace, provenance, bad_labels=True)
    result, code = runner.execute(namespace, commands)
    assert code == 2
    assert "provenance_labels_mismatch" in result["limitations"]
    assert result["cleanup"]["complete"] is False
    assert result["cleanup"]["residuals"] == ["tag", "image"]
    assert result["cleanup"]["tag"]["outcome"] == "skipped_divergent"
    assert result["cleanup"]["image"]["outcome"] == "skipped_divergent"
    assert not any(call[:3] == ["docker", "image", "rm"] for call in commands.calls)


@pytest.mark.parametrize(
    ("failing_reference", "reason"),
    [("image", "built_image_inspect_failed"), ("tag", "build_tag_inspect_failed")],
)
def test_post_build_inspect_failure_still_cleans_after_identity_recovers(failing_reference, reason):
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    commands = FakeCommands(namespace, provenance)
    original = commands.run
    failed = False

    def fail_once(command, timeout=1800):
        nonlocal failed
        target = commands.image_id if failing_reference == "image" else (
            namespace.repository + ":" + namespace.source_sha[:12] + "-" + namespace.invocation_id
        )
        if (commands.build_done and not failed and command[:3] == ["docker", "image", "inspect"]
                and command[3] == target):
            failed = True
            commands.calls.append(command)
            return subprocess.CompletedProcess(command, 1, "", "daemon unavailable")
        return original(command, timeout=timeout)

    commands.run = fail_once
    result, code = runner.execute(namespace, commands)
    assert code == 2
    assert reason in result["limitations"]
    assert result["cleanup"]["complete"] is True


def test_base_id_mismatch_stops_before_build():
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    commands = FakeCommands(namespace, provenance)
    commands.namespace.expected_base_image_id = "sha256:" + "9" * 64
    # The fake observes the updated expectation, so replace inspection explicitly.
    def mismatch(command, timeout=1800):
        commands.calls.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps([{"Id": "sha256:" + "8" * 64, "Config": {"Labels": {}}}]), "")
    commands.run = mismatch
    result, code = runner.execute(namespace, commands)
    assert code == 2
    assert result["checks"]["base_id_verified"] is False
    assert not any(call[:2] == ["docker", "build"] for call in commands.calls)


def test_base_platform_mismatch_stops_before_build():
    namespace = args(execute=True)
    provenance = runner.input_provenance()
    commands = FakeCommands(namespace, provenance)
    original = commands.run

    def arm64_platform(command, timeout=1800):
        if command[:3] == ["docker", "image", "inspect"] and command[3] == namespace.base_platform_image:
            commands.calls.append(command)
            payload = [{"Id": namespace.expected_base_image_id, "Os": "linux", "Architecture": "arm64", "Config": {"Labels": {}}}]
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        return original(command, timeout=timeout)

    commands.run = arm64_platform
    result, code = runner.execute(namespace, commands)
    assert code == 2
    assert "base_platform_mismatch" in result["limitations"]
    assert result["checks"]["base_id_verified"] is True
    assert result["checks"]["base_platform_verified"] is False
    assert not any(call[:2] == ["docker", "build"] for call in commands.calls)


def test_receipt_semantics_reject_manifest_identity_drift():
    namespace = args()
    result, _ = runner.execute(namespace)
    result["base"]["platform_manifest_digest"] = "sha256:" + "9" * 64
    with pytest.raises(ValueError, match="receipt_base_platform_manifest_digest_mismatch"):
        runner.validate_receipt(result)


def test_dockerfile_has_locked_hydration_and_local_only_labels():
    text = DOCKERFILE.read_text(encoding="utf-8")
    from_marker = "FROM --platform=linux/amd64 ${BASE_PLATFORM_IMAGE}"
    assert text.count("ARG BASE_PLATFORM_IMAGE") == 2
    assert from_marker in text
    assert "ARG BASE_PLATFORM_IMAGE" in text.split(from_marker, 1)[1]
    assert "mix local.hex \"${HEX_VERSION}\" --force" in text
    assert '"${POSTGRESQL_CLIENT_PACKAGE}=${POSTGRESQL_CLIENT_PACKAGE_VERSION}"' in text
    assert 'test "${POSTGRESQL_CLIENT_PACKAGE}" = "postgresql16-client"' in text
    assert 'test "${POSTGRESQL_CLIENT_PACKAGE_VERSION}" = "16.14-r0"' in text
    assert "apk add --no-cache" in text and "apk info -v" in text and "apk info -vv" not in text
    assert runner.APK_MAIN_REPOSITORY in text and runner.APK_COMMUNITY_REPOSITORY in text
    assert "apt-get" not in text and "dpkg" not in text and "DEBIAN" not in text
    assert "mix deps.get --only test --locked" in text
    assert "mix deps.compile" in text and "mix compile" in text and "mix deps.check" in text
    assert text.count("sha256sum mix.lock") >= 2
    assert 'io.tamandua.validation.claim-scope="local-only"' in text
    assert 'io.tamandua.validation.product-ready="false"' in text
    assert 'io.tamandua.validation.package.manager="apk"' in text
    assert f'io.tamandua.validation.package.repository-main="{runner.APK_MAIN_REPOSITORY}"' in text
    assert f'io.tamandua.validation.package.repository-community="{runner.APK_COMMUNITY_REPOSITORY}"' in text
    assert 'io.tamandua.validation.platform="linux/amd64"' in text
    assert "EXPECTED_PACKAGE_MANIFEST_SHA256" in text
    assert 'io.tamandua.validation.invocation.id="${INVOCATION_ID}"' in text
    assert ".tamandua-config-files.sha256" in text


def test_dockerfile_failure_checkpoints_have_exact_source_hash_and_order():
    text = DOCKERFILE.read_text(encoding="utf-8")
    checkpoints = runner.RUNNER_FAILURE_CHECKPOINTS
    provenance = runner.input_provenance()
    assert provenance["dockerfile_sha256"] == runner.sha256_file(DOCKERFILE)

    marker_positions = []
    for checkpoint in checkpoints:
        marker = f"TAMANDUA_RUNNER_FAILURE_V1:{checkpoint}"
        handler = f"|| {{ rc=$?; printf '%s\\n' '{marker}' >&2; exit \"$rc\"; }}"
        assert text.count(marker) == 1
        assert handler in text
        marker_positions.append(text.index(marker))
    assert marker_positions == sorted(marker_positions)

    preflight = text[text.index("USER root"):marker_positions[0]]
    assert 'elixir --version' in preflight and '"${EXPECTED_ELIXIR_VERSION}"' in preflight
    assert 'erlang:system_info(otp_release)' in preflight and '"${EXPECTED_OTP_RELEASE}"' in preflight
    assert 'test "$(apk --print-arch)" = "x86_64"' in preflight
    assert "TAMANDUA_RUNNER_FAILURE_V1" not in preflight

    assert text.index("grep -Fqx 'https://dl-cdn.alpinelinux.org/alpine/v3.21/main'") < marker_positions[0]
    assert marker_positions[0] < text.index("RUN apk add --no-cache") < marker_positions[1]
    assert marker_positions[1] < text.index("RUN test \"$(psql --version") < marker_positions[2]
    assert marker_positions[2] < text.index("RUN ( mkdir -p /opt/tamandua/provenance") < marker_positions[3]


def test_dockerfile_source_change_updates_both_provenance_hashes(tmp_path):
    changed = tmp_path / DOCKERFILE.name
    changed.write_bytes(DOCKERFILE.read_bytes() + b"\n# source-contract-change\n")

    original = runner.input_provenance()
    modified = runner.input_provenance(dockerfile=changed)

    assert modified["dockerfile_sha256"] == runner.sha256_file(changed)
    assert modified["dockerfile_sha256"] != original["dockerfile_sha256"]
    assert modified["input_bundle_sha256"] != original["input_bundle_sha256"]
    for key in ("mix_exs_sha256", "mix_lock_sha256", "config_sha256", "config_file_count"):
        assert modified[key] == original[key]


def test_receipt_schema_is_closed_and_distinguishes_build_from_runtime():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert schema["additionalProperties"] is False
    assert schema["properties"]["diagnostic_contract_version"]["enum"] == [1, 2]
    assert schema["$defs"]["build_failure_diagnostic"]["properties"]["failure_checkpoint"]["enum"] == [
        "repositories", "apk_install", "psql_version", "closure_digest", "unknown"
    ]
    claims = schema["properties"]["claims"]["properties"]
    assert claims["build_verified"]["type"] == "boolean"
    for name in ("runtime_validation_executed", "runtime_validated", "byte_reproducible",
                 "product_ready", "production_validated", "external_claim_allowed", "vendor_parity"):
        assert claims[name]["const"] is False
    assert schema["allOf"]


def test_any_level_config_symlink_is_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "value.exs").write_text("value", encoding="utf-8")
    link = tmp_path / "linked"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(RuntimeError, match="symlink_input_forbidden:linked"):
        runner.canonical_tree_digest(tmp_path)


def test_invalid_cli_emits_a_schema_valid_blocked_error_receipt(capsys):
    code = runner.main([
        "--base-image", "elixir:latest",
        "--base-platform-image", "hexpm/elixir@sha256:" + "f" * 64,
        "--expected-base-image-id", "sha256:" + "b" * 64,
        "--source-sha", runner.current_source_sha(),
        "--elixir-version", "1.18.4", "--erlang-version", "27.3.4", "--otp-release", "27",
        "--alpine-version", "3.21.3", "--hex-version", "2.2.1",
        "--apk-repository-branch", "v3.21", "--postgresql-client-package", "postgresql16-client",
        "--postgresql-client-package-version", "16.14-r0", "--psql-version", "16.14",
        "--alpine-toolchain-packages", "build-base git python3 pkgconf openssl-dev libxml2-dev",
        "--platform", "linux/amd64",
        "--expected-package-manifest-sha256", "d" * 64,
    ])
    payload = json.loads(capsys.readouterr().out)
    Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(payload)
    assert code == 2
    assert payload["status"] == "blocked"
    assert payload["claims"]["build_verified"] is False
