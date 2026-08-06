from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/build_elixir_runtime_validation_runner.py"
DOCKERFILE = ROOT / "apps/tamandua_server/Dockerfile.elixir-runtime-validation-runner"
SCHEMA = ROOT / "schemas/elixir_runtime_validation_runner_receipt_v1.schema.json"
SPEC = importlib.util.spec_from_file_location("elixir_runner", SCRIPT)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


HYDRATOR = runner.HYDRATOR_IMAGE_ID
FINAL_BASE = runner.FINAL_BASE_IMAGE_ID
ARTIFACT = "sha256:" + "c" * 64
FOREIGN = "sha256:" + "d" * 64


def hydrator_run_line(step=7):
    return (
        f"#{step} [hydrator 4/7] RUN --network=default set -eu; "
        "lock_before=\"$(sha256sum mix.lock | cut -d' ' -f1)\"; "
        "if ! mix deps.get --only test --check-locked; then "
        "printf '%s\\n' 'TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1' >&2; exit 41; fi; "
        "printf '%s\\n' 'TAMANDUA_HYDRATOR_DEPS_GET_OK_V1'; "
        "if test \"$(sha256sum mix.lock | cut -d' ' -f1)\" != \"${lock_before}\"; then "
        "printf '%s\\n' 'TAMANDUA_HYDRATOR_LOCK_CHANGED_V1' >&2; exit 42; fi"
    )


def test_build_command_captures_one_ordered_progress_stream(monkeypatch):
    observed = {}

    def completed(command, **kwargs):
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 1, "ordered progress\n", None)

    monkeypatch.setattr(runner.subprocess, "run", completed)
    result = runner.Commands().run_build(["docker", "build"], timeout=17)

    assert result.stdout == "ordered progress\n"
    assert result.stderr is None
    assert observed["stdout"] is subprocess.PIPE
    assert observed["stderr"] is subprocess.STDOUT
    assert observed["text"] is True
    assert observed["check"] is False
    assert observed["timeout"] == 17


def test_build_timeout_preserves_only_the_combined_stdout_stream(monkeypatch):
    def timed_out(command, **kwargs):
        raise subprocess.TimeoutExpired(
            command, kwargs["timeout"], output=b"#7 ordered progress\n",
            stderr=b"TOKEN=must-not-leak",
        )

    monkeypatch.setattr(runner.subprocess, "run", timed_out)
    result = runner.Commands().run_build(["docker", "build"], timeout=17)

    assert result.returncode == 124
    assert result.stdout == "#7 ordered progress\n"
    assert result.stderr is None
    assert "must-not-leak" not in json.dumps(runner.diagnostic(result))


def test_build_oserror_is_categorical_and_never_serializes_exception_text(monkeypatch):
    def adapter_failure(command, **kwargs):
        raise OSError("credential_leak")

    monkeypatch.setattr(runner.subprocess, "run", adapter_failure)
    result = runner.Commands().run_build(["docker", "build"], timeout=17)
    observed = runner.diagnostic(result)

    assert result.returncode == 125
    assert result.stdout == "adapter_error\n"
    assert result.stderr is None
    assert observed["kind"] == "adapter"
    assert "adapter_error" in observed["canonical_tail"]
    assert "credential_leak" not in json.dumps(observed)


def test_nonbuild_oserror_is_categorical_and_never_serializes_exception_text(monkeypatch):
    def adapter_failure(command, **kwargs):
        raise OSError("credential_leak")

    monkeypatch.setattr(runner.subprocess, "run", adapter_failure)
    result = runner.Commands().run(["docker", "image", "inspect", ARTIFACT], timeout=17)

    assert result.returncode == 125
    assert result.stdout == ""
    assert result.stderr == "adapter_error"
    assert "credential_leak" not in repr(result)


@pytest.mark.parametrize("stdout", ["adapter_error\n", b"adapter_error\n"])
def test_adapter_diagnostic_requires_exact_closed_tuple(stdout):
    result = subprocess.CompletedProcess(["docker", "build"], 125, stdout, None)
    observed = runner.diagnostic(result)

    assert observed["kind"] == "adapter"
    assert observed["canonical_tail"].count("adapter_error") == 1


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr"),
    [
        (125, "prefix adapter_error\n", None),
        (125, "adapter_error\ntrailing", None),
        (125, "adapter_error", None),
        (125, b"prefix adapter_error\n", None),
        (125, b"adapter_error\ntrailing", None),
        (0, "adapter_error\n", None),
        (1, "adapter_error\n", None),
        (124, "adapter_error\n", None),
        (125, "adapter_error\n", ""),
        (125, "adapter_error\n", "credential_leak"),
    ],
)
def test_adapter_diagnostic_rejects_substrings_wrong_rc_and_nonempty_stderr(
    returncode, stdout, stderr,
):
    result = subprocess.CompletedProcess(["docker", "build"], returncode, stdout, stderr)
    observed = runner.diagnostic(result)

    assert observed["kind"] != "adapter"
    assert "adapter_error" not in observed["canonical_tail"]
    assert "credential_leak" not in json.dumps(observed)


def args(**overrides):
    values = {
        "hydrator_image": HYDRATOR,
        "final_base_image": FINAL_BASE,
        "source_sha": runner.git_state()["head"],
        "rebar_version": runner.REBAR_VERSION,
        "repository": "tamandua/elixir-runtime-validation-runner",
        "invocation_id": "local-12345678",
        "postverify_timeout": 300,
        "execute": False,
        "output": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def image(image_id, layers, labels=None, tags=None):
    return {
        "Id": image_id, "Os": "linux", "Architecture": "amd64",
        "RootFS": {"Type": "layers", "Layers": layers},
        "Config": {"Labels": labels or {}}, "RepoTags": tags or [],
    }


class FakeCommands:
    def __init__(self, namespace, *, build_exit=0, post_exit=0, bad_labels=False,
                 bad_lineage=False, bad_base_lineage=False, hydrator_contamination=False,
                 preexisting=False, preexisting_alias=None, fail_alias_create=None,
                 partial_alias_create=None, drift_after_build=None, fail_alias_remove=None,
                 partial_alias_remove=None, drop_final_reference_on_alias_failure=False,
                 fail_alias_postinspect_once=None, preflight_alias_inspect_error=None,
                 postbuild_alias_inspect_error=None, fail_artifact_cleanup=False,
                 partial_artifact_tag_remove=False, build_failure=None):
        self.args = namespace
        self.build_exit = build_exit
        self.post_exit = post_exit
        self.bad_labels = bad_labels
        self.bad_lineage = bad_lineage
        self.hydrator_contamination = hydrator_contamination
        self.preexisting = preexisting
        self.tag = f"{namespace.repository}:{namespace.source_sha[:12]}-{namespace.invocation_id}"
        self.final = image(FINAL_BASE, ["sha256:" + "2" * 64], tags=["tamandua/preexisting:final"])
        hydrator_prefix = ["sha256:" + "8" * 64] if bad_base_lineage else self.final["RootFS"]["Layers"]
        self.hydrator = image(HYDRATOR, hydrator_prefix + ["sha256:" + "1" * 64],
                              tags=["tamandua/preexisting:hydrator"])
        self.artifact_exists = preexisting
        self.tag_exists = False
        self.aliases = runner.base_aliases(namespace, runner.git_state())
        self.alias_ids = {self.aliases[preexisting_alias]: FOREIGN} if preexisting_alias else {}
        self.fail_alias_create = fail_alias_create
        self.partial_alias_create = partial_alias_create
        self.drift_after_build = drift_after_build
        self.fail_alias_remove = fail_alias_remove
        self.partial_alias_remove = partial_alias_remove
        self.drop_final_reference_on_alias_failure = drop_final_reference_on_alias_failure
        self.fail_alias_postinspect_once = fail_alias_postinspect_once
        self.pending_alias_inspect_failure = None
        self.pending_alias_inspect_error = (
            self.aliases[preflight_alias_inspect_error] if preflight_alias_inspect_error else None
        )
        self.postbuild_alias_inspect_error = postbuild_alias_inspect_error
        self.fail_artifact_cleanup = fail_artifact_cleanup
        self.partial_artifact_tag_remove = partial_artifact_tag_remove
        self.build_failure = build_failure
        self.calls = []

    def labels(self):
        provenance = runner.input_provenance()
        source = runner.git_state()
        expected = runner.expected_labels(
            self.args, provenance, source, runner.rootfs_digest(self.hydrator), runner.rootfs_digest(self.final)
        )
        return {} if self.bad_labels else expected

    def artifact(self):
        layers = (["sha256:" + "9" * 64] if self.bad_lineage else self.final["RootFS"]["Layers"]) + [
            "sha256:" + "3" * 64
        ]
        if self.hydrator_contamination:
            layers.append("sha256:" + "1" * 64)
        return image(ARTIFACT, layers, self.labels(), [self.tag] if self.tag_exists else [])

    def run(self, command, timeout=1800):
        self.calls.append(command)
        if command[:3] == ["docker", "image", "inspect"]:
            reference = command[3]
            if reference == self.pending_alias_inspect_error:
                self.pending_alias_inspect_error = None
                return subprocess.CompletedProcess(
                    command, 1, "", "daemon unavailable TOKEN=must-not-leak",
                )
            if reference == self.pending_alias_inspect_failure:
                self.pending_alias_inspect_failure = None
                raise OSError("credential_leak")
            payload = None
            if reference == HYDRATOR:
                payload = self.hydrator
            elif reference == FINAL_BASE:
                payload = self.final
            elif reference == self.tag and self.tag_exists:
                payload = self.artifact()
            elif reference == ARTIFACT and self.artifact_exists:
                payload = self.artifact()
            elif reference in self.aliases.values() and reference in self.alias_ids:
                alias_id = self.alias_ids[reference]
                if alias_id == HYDRATOR:
                    payload = image(HYDRATOR, self.hydrator["RootFS"]["Layers"], tags=[reference])
                elif alias_id == FINAL_BASE:
                    payload = image(FINAL_BASE, self.final["RootFS"]["Layers"], tags=[reference])
                else:
                    payload = image(FOREIGN, ["sha256:" + "4" * 64], tags=[reference])
            if payload is None:
                return subprocess.CompletedProcess(command, 1, "", "not found")
            return subprocess.CompletedProcess(command, 0, json.dumps([payload]), "")
        if command[:3] == ["docker", "image", "ls"]:
            output = HYDRATOR + "\n" + FINAL_BASE + "\n" + (ARTIFACT + "\n" if self.preexisting else "")
            return subprocess.CompletedProcess(command, 0, output, "")
        if command[:3] == ["docker", "image", "tag"]:
            image_id, alias = command[3], command[4]
            role = next(name for name, value in self.aliases.items() if value == alias)
            if self.partial_alias_create == role:
                self.alias_ids[alias] = image_id
                return subprocess.CompletedProcess(command, 1, "", "synthetic post-mutation tag failure")
            if self.fail_alias_postinspect_once == role:
                self.alias_ids[alias] = image_id
                self.pending_alias_inspect_failure = alias
                return subprocess.CompletedProcess(command, 0, "", "")
            if self.fail_alias_create == role:
                if role == "final_base" and self.drop_final_reference_on_alias_failure:
                    self.final["RepoTags"] = []
                return subprocess.CompletedProcess(command, 1, "", "synthetic tag failure")
            self.alias_ids[alias] = image_id
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:3] == ["docker", "image", "rm"]:
            if command[3] == self.tag:
                if self.fail_artifact_cleanup:
                    raise OSError("synthetic artifact cleanup adapter failure")
                self.tag_exists = False
                if self.partial_artifact_tag_remove:
                    return subprocess.CompletedProcess(
                        command, 1, "", "synthetic post-mutation artifact tag removal failure",
                    )
            elif command[3] == ARTIFACT:
                self.artifact_exists = False
                self.tag_exists = False
            elif command[3] in self.aliases.values():
                role = next(name for name, value in self.aliases.items() if value == command[3])
                if self.partial_alias_remove == role:
                    self.alias_ids.pop(command[3], None)
                    return subprocess.CompletedProcess(command, 1, "", "synthetic post-mutation remove failure")
                if self.fail_alias_remove == role:
                    return subprocess.CompletedProcess(command, 1, "", "synthetic alias remove failure")
                self.alias_ids.pop(command[3], None)
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:2] == ["docker", "run"]:
            output = "TAMANDUA_ELIXIR_RUNNER_POSTVERIFY_V1\n" if self.post_exit == 0 else ""
            return subprocess.CompletedProcess(command, self.post_exit, output, "")
        raise AssertionError(command)

    def run_build(self, command, timeout=1800):
        self.calls.append(command)
        self.tag_exists = True
        self.artifact_exists = True
        iidfile = Path(command[command.index("--iidfile") + 1])
        iidfile.write_text(ARTIFACT, encoding="ascii")
        if self.drift_after_build:
            self.alias_ids[self.aliases[self.drift_after_build]] = FOREIGN
        if self.postbuild_alias_inspect_error:
            self.pending_alias_inspect_error = self.aliases[self.postbuild_alias_inspect_error]
        if self.build_failure == "dependency_fetch_failed":
            return subprocess.CompletedProcess(
                command, 1,
                hydrator_run_line() + "\n"
                "#7 0.479 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\nTOKEN=must-not-leak\n",
                '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n'
                'ERROR: failed to solve: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
            )
        if self.build_failure == "dependency_lock_guard_failed":
            return subprocess.CompletedProcess(
                command, 1,
                hydrator_run_line() + "\n"
                "#7 0.479 TAMANDUA_HYDRATOR_DEPS_GET_OK_V1\n"
                "#7 0.481 TAMANDUA_HYDRATOR_LOCK_CHANGED_V1\nTOKEN=must-not-leak\n",
                '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 42\n'
                'ERROR: failed to solve: process "/bin/sh -c redacted" did not complete successfully: exit code: 42\n',
            )
        if self.build_exit:
            return subprocess.CompletedProcess(
                command, self.build_exit,
                "#7 [hydrator 4/7] RUN --network=default mix deps.get\nTOKEN=must-not-leak\n",
                "#7 ERROR\nfailed to solve: process exited with exit code: 1\n",
            )
        return subprocess.CompletedProcess(command, 0, "", "")


def schema():
    payload = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(payload)
    return Draft202012Validator(payload)


@pytest.mark.parametrize("message", ["not found", "Error response from daemon: No such image: local:test",
                                      "Error: No such object: local:test"])
def test_inspect_image_accepts_only_canonical_absence(message):
    class Missing:
        def run(self, command, timeout=60):
            return subprocess.CompletedProcess(command, 1, "", message)

    assert runner.inspect_image(Missing(), "local:test") is None


def test_inspect_image_adapter_failure_is_secretless_and_not_absence():
    class Broken:
        def run(self, command, timeout=60):
            return subprocess.CompletedProcess(command, 1, "", "daemon unavailable TOKEN=must-not-leak")

    with pytest.raises(RuntimeError, match="^docker_inspect_failed$") as caught:
        runner.inspect_image(Broken(), "local:test")
    assert "TOKEN" not in str(caught.value)


@pytest.mark.parametrize("message", [
    "daemon unavailable after no such image cache miss TOKEN=must-not-leak",
    "Error response from daemon: No such image: foreign:test",
    "Error: No such object: foreign:test",
])
def test_inspect_image_rejects_noncanonical_or_wrong_reference_absence(message):
    class Broken:
        def run(self, command, timeout=60):
            return subprocess.CompletedProcess(command, 1, "", message)

    with pytest.raises(RuntimeError, match="^docker_inspect_failed$") as caught:
        runner.inspect_image(Broken(), "local:test")
    assert "TOKEN" not in str(caught.value)


def test_inspect_mode_is_offline_fail_closed_and_schema_valid():
    result, code = runner.execute(args())
    assert code == 2
    assert result["status"] == "blocked"
    assert result["claims"] == runner.FALSE_CLAIMS
    assert result["mode"] == "inspect"
    assert not result["tag"].endswith(":latest")
    schema().validate(result)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("hydrator_image", "sha256:" + "a" * 64, "hydrator_image_must_match"),
        ("final_base_image", "sha256:" + "b" * 64, "final_base_image_must_match"),
        ("invocation_id", "latest", "invocation_id_invalid"),
        ("repository", "Tamandua/Runner", "repository_invalid"),
        ("rebar_version", "latest", "rebar_version_invalid"),
        ("postverify_timeout", 29, "postverify_timeout_out_of_range"),
    ],
)
def test_mutable_or_wrong_identity_inputs_are_rejected(field, value, message):
    with pytest.raises(ValueError, match=message):
        runner.validate_args(args(**{field: value}))


def test_source_sha_must_match_current_head():
    with pytest.raises(ValueError, match="source_sha_does_not_match_head"):
        runner.execute(args(source_sha="0" * 40))


def test_provenance_binds_all_four_contracts_and_dirty_source():
    provenance = runner.input_provenance()
    source = runner.git_state()
    for key in (
        "mix_exs_sha256", "mix_lock_sha256", "config_sha256", "dockerfile_sha256",
        "helper_sha256", "schema_sha256", "bundle_sha256",
    ):
        assert runner.SHA256.fullmatch(provenance[key])
    assert provenance["config_file_count"] > 0
    assert runner.SHA256.fullmatch(source["status_sha256"])
    assert source["dirty"] is True


def test_provenance_rejects_non_hex_dependency_source(tmp_path, monkeypatch):
    server = tmp_path / "server"
    (server / "config").mkdir(parents=True)
    (server / "config" / "config.exs").write_text("import Config\n", encoding="utf-8")
    (server / "mix.exs").write_text('[{:local_dep, path: "../local"}]\n', encoding="utf-8")
    (server / "mix.lock").write_text("%{}\n", encoding="utf-8")
    monkeypatch.setattr(runner, "SERVER", server)
    with pytest.raises(RuntimeError, match="non_hex_dependency_source_forbidden"):
        runner.input_provenance()


def test_stage_context_contains_no_application_source(tmp_path):
    provenance = runner.input_provenance()
    source = runner.git_state()
    temporary, context = runner.stage_context(provenance, source)
    try:
        assert sorted(path.name for path in context.iterdir()) == [
            ".tamandua-config-files.sha256", ".tamandua-input-provenance.json",
            "Dockerfile.elixir-runtime-validation-runner", "config", "mix.exs", "mix.lock",
        ]
        assert not any((context / name).exists() for name in ("lib", "priv", "test", "deps", "_build"))
        assert runner.staged_context_matches(context, provenance, source) is True
        (context / "mix.lock").write_text("tampered", encoding="utf-8")
        assert runner.staged_context_matches(context, provenance, source) is False
    finally:
        temporary.cleanup()


def test_canonical_tree_rejects_symlink(tmp_path):
    tree = tmp_path / "config"
    tree.mkdir()
    (tree / "real.exs").write_text("ok", encoding="utf-8")
    try:
        (tree / "link.exs").symlink_to(tree / "real.exs")
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(RuntimeError, match="special_or_symlink_input_forbidden"):
        runner.canonical_tree(tree)


@pytest.mark.skipif(os.name == "nt", reason="FIFO is unavailable on Windows")
def test_canonical_tree_rejects_special_file(tmp_path):
    tree = tmp_path / "config"
    tree.mkdir()
    os.mkfifo(tree / "pipe")
    with pytest.raises(RuntimeError, match="special_or_symlink_input_forbidden"):
        runner.canonical_tree(tree)


def test_dockerfile_has_one_networked_run_and_clean_final_boundary():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "mix deps.check" not in text
    assert text.count("mix deps.loadpaths --no-compile") == 4
    assert "mix deps.get --only test --check-locked" in text
    assert "mix deps.get --only test --locked" not in text
    assert text.count("RUN --network=default") == 1
    assert text.count("RUN --network=none") >= 3
    networked = text.split("RUN --network=default", 1)[1].split("RUN --network=none", 1)[0]
    assert re.findall(r"\bmix [a-z.]+", networked) == ["mix deps.get"]
    assert networked.index(runner.DEPS_GET_FAILED_MARKER) < networked.index("exit 41")
    lock_guard = 'if test "$(sha256sum mix.lock'
    assert networked.index(runner.DEPS_GET_OK_MARKER) < networked.index(lock_guard)
    assert networked.index(runner.DEPS_GET_OK_MARKER) < networked.index(runner.LOCK_CHANGED_MARKER)
    assert networked.index(runner.LOCK_CHANGED_MARKER) < networked.index("exit 42")
    assert "WORKDIR /hydrate" in text
    final = text.split("FROM ${FINAL_BASE_LOCAL_ALIAS} AS final", 1)[1]
    assert "COPY --from=hydrator /hydrate/lib" not in final
    assert "COPY --from=hydrator /hydrate/priv" not in final
    assert "COPY --from=hydrator /hydrate/test" not in final
    assert "mix deps.compile" not in final
    assert final.count("mix deps.loadpaths --no-compile") == 2
    assert "! command -v psql" in final and "find / -xdev -type f -name psql" in final
    assert "FROM ${HYDRATOR_LOCAL_ALIAS} AS hydrator" in text
    assert "ARG HYDRATOR_LOCAL_ALIAS" in text and "ARG FINAL_BASE_LOCAL_ALIAS" in text
    assert "cp -a /root/.mix/." not in text
    assert 'hex-${HEX_VERSION}' in text
    assert 'test "${nif_count}" -gt 0' in final
    assert "-exec sh -c 'for nif do ldd \"$nif\" || exit 1; done'" in final
    assert "test -s /tmp/nif-ldd.txt" in final
    assert "-exec ldd '{}' ';'" not in final
    assert runner.ERLANG_VERSION == "28.5.0.2"
    assert runner.OTP_RELEASE == "28"
    assert runner.HEX_VERSION == "2.5.1"
    assert runner.REBAR_VERSION == "3.26.0"
    assert "latest" not in text.lower()


def test_build_command_binds_full_ids_hashes_and_never_pulls(tmp_path):
    namespace = args()
    provenance = runner.input_provenance()
    source = runner.git_state()
    command = runner.build_args(
        namespace, tmp_path, "tamandua/elixir-runtime-validation-runner:unique", tmp_path / "iid",
        provenance, source, "1" * 64, "2" * 64, runner.base_aliases(namespace, source),
    )
    rendered = " ".join(command)
    assert command[:6] == ["docker", "build", "--platform", "linux/amd64", "--pull=false", "--progress=plain"]
    assert "--iidfile" in command
    assert "latest" not in rendered
    for value in (HYDRATOR, FINAL_BASE, source["head"], source["status_sha256"],
                  provenance["helper_sha256"], provenance["schema_sha256"], provenance["bundle_sha256"]):
        assert value in rendered
    for alias in runner.base_aliases(namespace, source).values():
        assert alias in rendered and not alias.endswith(":latest")
    assert "HYDRATOR_IMAGE=" not in rendered and "FINAL_BASE_IMAGE=" not in rendered


def test_postverify_is_full_id_network_none_read_only_and_complete():
    namespace = args(execute=True)
    fake = FakeCommands(namespace)
    result, code = runner.execute(namespace, fake)
    assert code == 0
    assert result["status"] == "pass"
    assert result["claims"]["artifact_verified"] is True
    assert all(value is True for value in result["checks"].values())
    docker_run = next(command for command in fake.calls if command[:2] == ["docker", "run"])
    assert docker_run[docker_run.index("--network") + 1] == "none"
    assert "--read-only" in docker_run and ARTIFACT in docker_run
    assert "psql" in docker_run[-1] and "ldd" in docker_run[-1]
    assert "mix deps.check" not in docker_run[-1]
    assert "mix deps.loadpaths --no-compile" in docker_run[-1]
    assert "mix deps.compile" not in docker_run[-1]
    assert "ldd \"$nif\" || exit 1" in docker_run[-1]
    assert "test -s /tmp/nif-ldd.txt" in docker_run[-1]
    assert "-exec ldd '{}' ';'" not in docker_run[-1]
    assert result["cleanup"]["tag"]["outcome"] == "removed"
    assert result["cleanup"]["image"]["outcome"] == "retained_full_id"
    assert result["cleanup"]["hydrator_alias"]["outcome"] == "removed"
    assert result["cleanup"]["final_base_alias"]["outcome"] == "removed"
    assert fake.alias_ids == {}
    assert fake.artifact_exists is True and fake.tag_exists is False
    schema().validate(result)


def test_nonzero_artifact_tag_remove_with_absent_postcondition_retains_verified_image():
    namespace = args(execute=True)
    fake = FakeCommands(namespace, partial_artifact_tag_remove=True)
    result, code = runner.execute(namespace, fake)
    assert code == 0
    assert result["status"] == "pass"
    assert result["cleanup"]["tag"]["outcome"] == "removed"
    assert result["cleanup"]["image"]["outcome"] == "retained_full_id"
    assert fake.tag_exists is False and fake.artifact_exists is True
    schema().validate(result)


@pytest.mark.parametrize(("option", "error"), [("bad_labels", "artifact_provenance_mismatch"),
                                                  ("bad_lineage", "artifact_provenance_mismatch"),
                                                  ("post_exit", "offline_read_only_postverify_failed")])
def test_postbuild_failure_removes_only_owned_artifact(option, error):
    namespace = args(execute=True)
    fake = FakeCommands(namespace, **{option: True if option != "post_exit" else 1})
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert result["status"] == "blocked"
    assert result["claims"] == runner.FALSE_CLAIMS
    assert error in result["limitations"]
    assert fake.artifact_exists is False and fake.tag_exists is False
    assert result["cleanup"]["complete"] is True
    schema().validate(result)


@pytest.mark.parametrize("option", ["bad_base_lineage", "hydrator_contamination"])
def test_incompatible_base_or_hydrator_layer_contamination_blocks(option):
    namespace = args(execute=True)
    fake = FakeCommands(namespace, **{option: True})
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert result["claims"] == runner.FALSE_CLAIMS
    assert result["status"] == "blocked"
    schema().validate(result)


def test_failed_build_has_sanitized_diagnostic_and_zero_owned_residue():
    namespace = args(execute=True)
    fake = FakeCommands(namespace, build_exit=1)
    result, code = runner.execute(namespace, fake)
    assert code == 2
    rendered = json.dumps(result)
    assert "TOKEN" not in rendered and "must-not-leak" not in rendered
    assert result["diagnostic"]["canonical_tail"]
    assert result["checks"]["build_succeeded"] is False
    assert result["cleanup"]["complete"] is True
    assert fake.artifact_exists is False and fake.tag_exists is False
    assert not any(command[:3] == ["docker", "image", "inspect"] and command[3] == "None"
                   for command in fake.calls)
    schema().validate(result)


@pytest.mark.parametrize(
    ("failure", "category", "required_tail", "forbidden_tail"),
    [
        ("dependency_fetch_failed", "dependency_fetch_failed", "dependency_fetch_failed",
         "dependency_fetch_succeeded"),
        ("dependency_lock_guard_failed", "dependency_lock_guard_failed", "dependency_lock_guard_failed",
         "dependency_fetch_failed"),
    ],
)
def test_hydrator_failure_receipt_is_categorical_and_never_serializes_raw_logs(
    failure, category, required_tail, forbidden_tail,
):
    namespace = args(execute=True)
    fake = FakeCommands(namespace, build_failure=failure)
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert result["diagnostic"]["category"] == category
    assert required_tail in result["diagnostic"]["canonical_tail"]
    assert forbidden_tail not in result["diagnostic"]["canonical_tail"]
    if failure == "dependency_lock_guard_failed":
        assert "dependency_fetch_succeeded" in result["diagnostic"]["canonical_tail"]
    rendered = json.dumps(result)
    assert "TOKEN" not in rendered and "must-not-leak" not in rendered
    assert "TAMANDUA_HYDRATOR_" not in rendered
    assert result["checks"]["build_succeeded"] is False
    assert result["cleanup"]["complete"] is True
    assert fake.artifact_exists is False and fake.tag_exists is False
    schema().validate(result)


@pytest.mark.parametrize(
    ("marker_lines", "internal_exit", "outer_exit", "category"),
    [
        ("#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n", 41, 1, "dependency_fetch_failed"),
        ("#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n", 41, 41, "dependency_fetch_failed"),
        (
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_OK_V1\n"
            "#7 0.5 TAMANDUA_HYDRATOR_LOCK_CHANGED_V1\n",
            42, 1, "dependency_lock_guard_failed",
        ),
        (
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_OK_V1\n"
            "#7 0.5 TAMANDUA_HYDRATOR_LOCK_CHANGED_V1\n",
            42, 42, "dependency_lock_guard_failed",
        ),
    ],
)
def test_hydrator_category_binds_exact_run_and_safe_outer_exit(
    marker_lines, internal_exit, outer_exit, category,
):
    observed = runner.diagnostic(subprocess.CompletedProcess(
        ["docker", "build"], outer_exit,
        hydrator_run_line() + "\n" + marker_lines,
        f'#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: {internal_exit}\n',
    ))
    assert observed["category"] == category


@pytest.mark.parametrize("outer_exit", [0, 2, 42, 124])
def test_hydrator_category_rejects_inconsistent_outer_exit(outer_exit):
    observed = runner.diagnostic(subprocess.CompletedProcess(
        ["docker", "build"], outer_exit,
        hydrator_run_line() + "\n#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n",
        '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
    ))
    assert observed["category"] == "other"


@pytest.mark.parametrize(
    ("stdout", "stderr"),
    [
        (
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n",
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 42\n',
        ),
        (
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_OK_V1\n",
            "#7 0.5 TAMANDUA_HYDRATOR_LOCK_CHANGED_V1\n"
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
        ),
        (
            "#7 0.4 TAMANDUA_HYDRATOR_LOCK_CHANGED_V1\n"
            "#7 0.5 TAMANDUA_HYDRATOR_DEPS_GET_OK_V1\n",
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 42\n',
        ),
        (
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n"
            "#7 0.5 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n",
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
        ),
        (
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n",
            '#8 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
        ),
        (
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_OK_V1\n"
            "#8 0.5 TAMANDUA_HYDRATOR_LOCK_CHANGED_V1\n",
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 42\n',
        ),
        (
            "prefix #7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n",
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
        ),
        (
            " #7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n",
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
        ),
        (
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1 trailing\n",
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
        ),
        (
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1 TAMANDUA_HYDRATOR_DEPS_GET_OK_V1\n",
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
        ),
        (
            "#7 [hydrator 4/7] RUN printf TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n",
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
        ),
        (
            hydrator_run_line() + "\n"
            "#8 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n",
            '#8 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
        ),
        (
            hydrator_run_line() + "\n" + hydrator_run_line() + "\n"
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n",
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
        ),
    ],
)
def test_hydrator_category_requires_exact_marker_order_and_matching_internal_exit(stdout, stderr):
    observed = runner.diagnostic(subprocess.CompletedProcess(["docker", "build"], 1, stdout, stderr))
    assert observed["category"] == "other"
    assert "dependency_fetch_failed" not in observed["canonical_tail"]
    assert "dependency_fetch_succeeded" not in observed["canonical_tail"]
    assert "dependency_lock_guard_failed" not in observed["canonical_tail"]
    assert "TAMANDUA_HYDRATOR_" not in json.dumps(observed)


@pytest.mark.parametrize(
    "stdout",
    [
        (
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n"
            + hydrator_run_line() + "\n"
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n'
        ),
        (
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_OK_V1\n"
            "#7 0.5 TAMANDUA_HYDRATOR_LOCK_CHANGED_V1\n"
            + hydrator_run_line() + "\n"
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 42\n'
        ),
        (
            hydrator_run_line() + "\n"
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n'
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n"
        ),
        (
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n'
            + hydrator_run_line() + "\n"
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n"
        ),
        (
            hydrator_run_line() + "\n"
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_OK_V1\n"
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 42\n'
            "#7 0.5 TAMANDUA_HYDRATOR_LOCK_CHANGED_V1\n"
        ),
        (
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 42\n'
            + hydrator_run_line() + "\n"
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_OK_V1\n"
            "#7 0.5 TAMANDUA_HYDRATOR_LOCK_CHANGED_V1\n"
        ),
        (
            hydrator_run_line() + "\n"
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n"
            "#7 0.5 TAMANDUA_HYDRATOR_DEPS_GET_OK_V1\n"
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n'
        ),
        (
            hydrator_run_line() + "\n"
            "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_OK_V1\n"
            "#7 0.5 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n"
            "#7 0.6 TAMANDUA_HYDRATOR_LOCK_CHANGED_V1\n"
            '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 42\n'
        ),
    ],
)
def test_hydrator_category_rejects_out_of_order_or_interleaved_categorical_events(stdout):
    observed = runner.diagnostic(subprocess.CompletedProcess(["docker", "build"], 1, stdout, ""))
    assert observed["category"] == "other"
    assert "dependency_fetch_failed" not in observed["canonical_tail"]
    assert "dependency_fetch_succeeded" not in observed["canonical_tail"]
    assert "dependency_lock_guard_failed" not in observed["canonical_tail"]


@pytest.mark.parametrize("run_line", [
    "prefix " + hydrator_run_line(),
    hydrator_run_line() + " trailing",
    hydrator_run_line() + " " + hydrator_run_line(),
    hydrator_run_line().replace("if ! mix deps.get", "if ! sh -c 'mix deps.get'"),
    hydrator_run_line().replace("if ! mix deps.get", "if ! echo mix deps.get"),
    hydrator_run_line().replace("mix deps.get", 'mix "deps.get"'),
])
def test_hydrator_category_rejects_run_prefix_suffix_and_shell_spoofs(run_line):
    observed = runner.diagnostic(subprocess.CompletedProcess(
        ["docker", "build"], 1,
        run_line + "\n#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n",
        '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
    ))
    assert observed["category"] == "other"


def test_hydrator_category_rejects_an_extra_networked_run_prefix():
    stdout = (
        hydrator_run_line() + "\n"
        "#8 [hydrator 5/7] RUN --network=default echo mix deps.get --only test --check-locked\n"
        "#7 0.4 TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1\n"
    )
    observed = runner.diagnostic(subprocess.CompletedProcess(
        ["docker", "build"], 1, stdout,
        '#7 ERROR: process "/bin/sh -c redacted" did not complete successfully: exit code: 41\n',
    ))
    assert observed["category"] == "other"


def test_registry_style_sha_resolution_failure_has_safe_category_only():
    failure = subprocess.CompletedProcess(
        ["docker", "build"], 1,
        "#3 [internal] load metadata for docker.io/library/sha256:f314-secret\nAUTH=must-not-leak\n",
        "#3 ERROR\nfailed to solve: pull access denied\n",
    )
    observed = runner.diagnostic(failure)
    assert observed["category"] == "base_reference_resolution"
    assert "base_reference_resolution" in observed["canonical_tail"]
    assert "must-not-leak" not in json.dumps(observed)
    assert HYDRATOR not in json.dumps(observed)


@pytest.mark.parametrize("role", ["hydrator", "final_base"])
def test_preexisting_or_foreign_alias_is_refused_without_removal(role):
    namespace = args(execute=True)
    fake = FakeCommands(namespace, preexisting_alias=role)
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert "local_base_alias_preexisting" in result["limitations"]
    assert fake.aliases[role] in fake.alias_ids
    assert not any(command[:3] == ["docker", "image", "rm"] and command[3] == fake.aliases[role]
                   for command in fake.calls)


def test_alias_preflight_adapter_failure_never_overwrites_or_removes_foreign_alias():
    namespace = args(execute=True)
    fake = FakeCommands(
        namespace, preexisting_alias="hydrator", preflight_alias_inspect_error="hydrator",
    )
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert "docker_inspect_failed" in result["limitations"]
    assert "must-not-leak" not in json.dumps(result)
    assert fake.alias_ids[fake.aliases["hydrator"]] == FOREIGN
    assert not any(command[:3] == ["docker", "image", "tag"] for command in fake.calls)
    assert not any(command[:3] == ["docker", "image", "rm"] for command in fake.calls)


def test_partial_alias_creation_cleans_first_alias_and_preserves_bases():
    namespace = args(execute=True)
    fake = FakeCommands(namespace, fail_alias_create="final_base")
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert "final_base_alias_creation_failed" in result["limitations"]
    assert fake.alias_ids == {}
    assert result["cleanup"]["hydrator_alias"]["outcome"] == "removed"
    assert result["cleanup"]["final_base_alias"]["outcome"] == "absent"
    assert result["checks"]["base_images_preserved"] is True


@pytest.mark.parametrize("role", ["hydrator", "final_base"])
def test_failed_tag_that_created_exact_alias_is_owned_and_cleaned(role):
    namespace = args(execute=True)
    fake = FakeCommands(namespace, partial_alias_create=role)
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert f"{role}_alias_creation_failed" in result["limitations"]
    assert fake.aliases[role] not in fake.alias_ids
    assert result["cleanup"][f"{role}_alias"]["outcome"] == "removed"


def test_post_tag_inspect_adapter_failure_still_cleans_exact_alias():
    namespace = args(execute=True)
    fake = FakeCommands(namespace, fail_alias_postinspect_once="hydrator")
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert "oserror" in result["limitations"]
    assert "credential_leak" not in json.dumps(result)
    assert fake.alias_ids == {}
    assert result["cleanup"]["hydrator_alias"]["outcome"] == "removed"


def test_postbuild_inspect_adapter_failure_cleans_owned_aliases_without_raw_error():
    namespace = args(execute=True)
    fake = FakeCommands(namespace, postbuild_alias_inspect_error="hydrator")
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert "docker_inspect_failed" in result["limitations"]
    assert "must-not-leak" not in json.dumps(result)
    assert fake.alias_ids == {}
    assert result["cleanup"]["hydrator_alias"]["outcome"] == "removed"
    assert result["cleanup"]["final_base_alias"]["outcome"] == "removed"


def test_base_reference_preservation_checks_unaliased_base_after_partial_failure():
    namespace = args(execute=True)
    fake = FakeCommands(
        namespace, fail_alias_create="final_base", drop_final_reference_on_alias_failure=True,
    )
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert result["checks"]["base_images_preserved"] is False
    assert "missing_preexisting_base:final_base" in result["cleanup"]["residuals"]


def test_alias_drift_blocks_and_never_removes_foreign_replacement():
    namespace = args(execute=True)
    fake = FakeCommands(namespace, drift_after_build="hydrator")
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert "local_base_alias_drift_after_build" in result["limitations"]
    assert fake.alias_ids[fake.aliases["hydrator"]] == FOREIGN
    assert result["cleanup"]["hydrator_alias"]["outcome"] == "skipped_unowned"
    assert result["cleanup"]["final_base_alias"]["outcome"] == "removed"
    assert result["cleanup"]["complete"] is False


def test_alias_cleanup_continues_after_first_removal_failure():
    namespace = args(execute=True)
    fake = FakeCommands(namespace, post_exit=1, fail_alias_remove="hydrator")
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert result["cleanup"]["hydrator_alias"]["outcome"] == "unknown"
    assert result["cleanup"]["final_base_alias"]["outcome"] == "removed"
    assert fake.aliases["hydrator"] in fake.alias_ids
    assert fake.aliases["final_base"] not in fake.alias_ids
    assert result["checks"]["base_images_preserved"] is True


def test_nonzero_alias_remove_with_absent_postcondition_counts_as_removed():
    namespace = args(execute=True)
    fake = FakeCommands(namespace, post_exit=1, partial_alias_remove="hydrator")
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert result["cleanup"]["hydrator_alias"]["outcome"] == "removed"
    assert fake.alias_ids == {}


def test_alias_cleanup_is_independent_of_artifact_cleanup_exception():
    namespace = args(execute=True)
    fake = FakeCommands(namespace, post_exit=1, fail_artifact_cleanup=True)
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert fake.alias_ids == {}
    assert result["cleanup"]["hydrator_alias"]["outcome"] == "removed"
    assert result["cleanup"]["final_base_alias"]["outcome"] == "removed"
    assert any(item.startswith("artifact_cleanup_error:") for item in result["cleanup"]["residuals"])


def test_aliases_are_unique_scoped_and_never_latest():
    namespace = args()
    first = runner.base_aliases(namespace, runner.git_state())
    second = runner.base_aliases(args(invocation_id="local-87654321"), runner.git_state())
    assert set(first.values()).isdisjoint(second.values())
    assert all(reference.startswith(runner.LOCAL_ALIAS_REPOSITORY + ":") for reference in first.values())
    assert all(not reference.endswith(":latest") for reference in [*first.values(), *second.values()])


def test_cleanup_never_removes_preexisting_or_unowned_image():
    namespace = args(execute=True)
    fake = FakeCommands(namespace, preexisting=True, post_exit=1)
    result, code = runner.execute(namespace, fake)
    assert code == 2
    assert fake.artifact_exists is True
    assert fake.tag_exists is False
    assert result["cleanup"]["complete"] is True
    assert result["cleanup"]["tag"]["outcome"] == "removed"
    assert result["cleanup"]["image"]["outcome"] == "skipped_preexisting"


def test_schema_rejects_unknown_check_name():
    result, _ = runner.execute(args())
    result["checks"]["unreviewed_claim"] = True
    with pytest.raises(Exception):
        schema().validate(result)


def test_schema_binds_alias_roles_and_exact_base_ids():
    result, _ = runner.execute(args())
    result["aliases"]["hydrator"]["reference"] = result["aliases"]["final_base"]["reference"]
    with pytest.raises(Exception):
        schema().validate(result)
    result, _ = runner.execute(args())
    result["images"]["hydrator"]["expected_id"] = FOREIGN
    with pytest.raises(Exception):
        schema().validate(result)


@pytest.mark.parametrize(("complete", "residuals"), [
    (True, ["owned_alias_residual"]),
    (False, []),
])
def test_schema_binds_cleanup_completion_to_residuals(complete, residuals):
    result, _ = runner.execute(args())
    result["cleanup"].update({"complete": complete, "residuals": residuals})
    with pytest.raises(Exception):
        schema().validate(result)


def test_blocked_preflight_error_receipt_is_closed_and_schema_valid():
    payload = runner.blocked_error(ValueError("repository_invalid"))
    assert payload["claims"] == runner.FALSE_CLAIMS
    schema().validate(payload)


def test_blocked_oserror_never_serializes_grammar_safe_exception_text():
    payload = runner.blocked_error(OSError("credential_leak"))
    assert payload["error"] == "oserror"
    assert "credential_leak" not in json.dumps(payload)
    schema().validate(payload)
