from __future__ import annotations

import contextlib, copy, hashlib, importlib.util, io, json, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/runtime_self_image_live_compare_gate.py"
SCHEMA = ROOT / "schemas/runtime_self_image_live_compare_receipt_v1.schema.json"
SPEC = importlib.util.spec_from_file_location("runtime_self_image_live_compare_gate", SCRIPT)
GATE = importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(GATE)
SOURCE_COMMIT = "1" * 40; DIRTY = "2" * 64
COMMAND = hashlib.sha256(b"cargo test --locked --manifest-path apps/tamandua_agent/Cargo.toml --target x86_64-pc-windows-msvc --release --no-default-features --lib --no-run --message-format=json-render-diagnostics").hexdigest()
TOOLCHAIN = "rustc-vv-sha256-" + "3" * 64
PROVENANCE = {"source_commit":SOURCE_COMMIT,"dirty_patch_sha256":DIRTY,"build_command_sha256":COMMAND,"toolchain_id":TOOLCHAIN}


def digest(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()


def pe64_fixture(*, delay: bool = False, bad_reloc: bool = False, relocation: bool = True,
                 readable: bool = True, writable: bool = False, text_pages: int = 2, cross_page: bool = False,
                 imports: str = "none", virtual_pages: int | None = None) -> bytes:
    virtual_pages = text_pages if virtual_pages is None else virtual_pages
    reloc_rva = 0x1000 + max(text_pages, virtual_pages) * 0x1000; reloc_raw = 0x400 + text_pages * 0x1000
    data = bytearray(reloc_raw + 0x400); pe = 0x80; opt = pe + 24
    data[:2] = b"MZ"; data[0x3C:0x40] = pe.to_bytes(4, "little"); data[pe:pe+4] = b"PE\0\0"
    data[pe+4:pe+6] = (0x8664).to_bytes(2, "little"); data[pe+6:pe+8] = (2).to_bytes(2, "little")
    data[pe+20:pe+22] = (240).to_bytes(2, "little"); data[pe+22:pe+24] = (0x22).to_bytes(2, "little")
    data[opt:opt+2] = (0x20B).to_bytes(2, "little"); data[opt+32:opt+36] = (0x1000).to_bytes(4, "little")
    data[opt+36:opt+40] = (0x200).to_bytes(4, "little"); data[opt+56:opt+60] = (reloc_rva + 0x1000).to_bytes(4, "little")
    data[opt+60:opt+64] = (0x400).to_bytes(4, "little"); data[opt+108:opt+112] = (16).to_bytes(4, "little")
    # base relocation directory, one DIR64 relocation touching first of two RX pages
    dd = opt + 112
    if relocation: data[dd+5*8:dd+5*8+4] = reloc_rva.to_bytes(4, "little"); data[dd+5*8+4:dd+5*8+8] = (12).to_bytes(4, "little")
    if delay: data[dd+13*8:dd+13*8+4] = reloc_rva.to_bytes(4, "little"); data[dd+13*8+4:dd+13*8+8] = (8).to_bytes(4, "little")
    table = opt + 240
    def section(at: int, name: bytes, vs: int, rva: int, raw_size: int, raw: int, flags: int) -> None:
        data[at:at+8] = name.ljust(8, b"\0"); data[at+8:at+12] = vs.to_bytes(4, "little"); data[at+12:at+16] = rva.to_bytes(4, "little")
        data[at+16:at+20] = raw_size.to_bytes(4, "little"); data[at+20:at+24] = raw.to_bytes(4, "little"); data[at+36:at+40] = flags.to_bytes(4, "little")
    text_flags = (0x60000020 if readable else 0x20000020) | (0x80000000 if writable else 0)
    section(table, b".text", virtual_pages*0x1000, 0x1000, text_pages*0x1000, 0x400, text_flags)
    section(table+40, b".reloc", 0x400, reloc_rva, 0x400, reloc_raw, 0x42000040)
    data[reloc_raw:reloc_raw+4] = (0x1000).to_bytes(4, "little"); data[reloc_raw+4:reloc_raw+8] = (12).to_bytes(4, "little")
    kind = 3 if bad_reloc else 10; within = 0xffc if cross_page else 0
    data[reloc_raw+8:reloc_raw+10] = ((kind << 12) | within).to_bytes(2, "little")
    if imports != "none":
        imp_rva, lookup_rva, name_rva, ibn_rva = reloc_rva+0x40, reloc_rva+0x80, reloc_rva+0xa0, reloc_rva+0xb0
        data[dd+12*8:dd+12*8+4]=(0x2000).to_bytes(4,"little"); data[dd+12*8+4:dd+12*8+8]=(16).to_bytes(4,"little")
        if imports == "standalone_iat": return bytes(data)
        data[dd+1*8:dd+1*8+4] = imp_rva.to_bytes(4,"little"); data[dd+1*8+4:dd+1*8+8]=(40).to_bytes(4,"little")
        at=reloc_raw+0x40; data[at:at+4]=lookup_rva.to_bytes(4,"little"); data[at+12:at+16]=name_rva.to_bytes(4,"little")
        first_thunk = 0x5000 if imports == "first_thunk" else 0x2000; data[at+16:at+20]=first_thunk.to_bytes(4,"little")
        lookup=reloc_raw+0x80; data[lookup:lookup+8]=ibn_rva.to_bytes(8,"little")
        if imports != "bad_name": data[reloc_raw+0xa0:reloc_raw+0xa6]=b"x.dll\0"
        else: data[reloc_raw+0xa0:reloc_raw+0x400] = b"A" * (0x400 - 0xa0)
        if imports != "bad_name":
            data[reloc_raw+0xb0:reloc_raw+0xb2]=b"\0\0"; data[reloc_raw+0xb2:reloc_raw+0xb4]=b"f\0"
    return bytes(data)


class LiveCompareGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); root = Path(self.temp.name)
        self.artifact, self.planner, self.harness, self.lock = (root / n for n in ("artifact.exe", "page_content.rs", "harness.exe", "Cargo.lock"))
        self.artifact.write_bytes(pe64_fixture()); self.planner.write_bytes(b"planner"); self.harness.write_bytes(b"harness"); self.lock.write_bytes(b"lock")
        zero = {"clean_pages":0,"compared_pages":0,"mismatch_pages":0,"planned_pages":0,"relocation_excluded_pages":0,"unstable_pages":0}
        sha = digest(self.artifact)
        self.receipt = {
            "actions":{"current_main_modified":False,"disposable_mapping_restored":False,"disposable_sec_image_used":False,"live_memory_compared":True},
            "artifact_sha256_after":sha,"artifact_sha256_before":sha,"artifact_size":self.artifact.stat().st_size,
            "build_command_id":"cargo-test-release-nodefault-windows-x86_64-msvc-live-lab-v1","build_command_sha256":COMMAND,"cargo_lock_sha256":digest(self.lock),
            "claims":{"external_claim_allowed":False,"production_ready":False,"release_authority":False,"runtime_detection_proven":False,"telemetry_emitted":False,"verimatrix_parity":False},
            "cost":{"budget_state":"within_budget","cpu_time_ms":1,"elapsed_ms":2,"query_count":3,"read_attempt_count":2,"read_bytes":8192,"working_set_after":1,"working_set_before":1,"working_set_delta_bytes":0,"working_set_peak_delta_bytes":0},
            "counts":{"clean_pages":1,"compared_pages":1,"mismatch_pages":0,"planned_pages":1,"relocation_excluded_pages":1,"unstable_pages":0},
            "degraded_reason":"none","dirty_patch_sha256":DIRTY,"evidence_class":"windows-live-compare-lab","harness_sha256":digest(self.harness),
            "identity":{"anchor_within_main_image":True,"anchor_module_matches_main":True,"artifact_matches_main_exe":True,"disposable_mapping_disjoint_from_main":False,"file_id_stable":True,"locked_read_handle":True,"mapped_file_object_identity_proven":False,"mapped_name_matches_locked_artifact":True,"module_size_matches_pe":True,"native_amd64_process":True,"page_size_matches":True},
            "measurement_boundary":"pre_receipt_serialization","page_size":4096,"planner_source_sha256":digest(self.planner),"receipt_encoding_and_write_measured":False,"post_restore_counts":zero,"post_restore_state":"not_applicable",
            "scenario":"current-main-observe","schema_version":"tamandua.runtime_self_image_live_compare_receipt/v1","source_commit":SOURCE_COMMIT,"state":"clean","target":"x86_64-pc-windows-msvc","toolchain_id":TOOLCHAIN,
        }

    def tearDown(self) -> None: self.temp.cleanup()
    def write(self, value: dict, canonical: bool = True) -> Path:
        p = Path(self.temp.name)/"receipt.json"; p.write_text(json.dumps(value, separators=(",",":"), sort_keys=True) if canonical else json.dumps(value, indent=2), encoding="utf-8"); return p
    def validate(self, value: dict | None = None):
        return GATE.validate(self.write(self.receipt if value is None else value), self.artifact, self.planner, self.harness, self.lock, SCHEMA, derived_provenance=PROVENANCE)

    def test_accepts_clean_current_main_with_artifact_proven_relocation(self): self.assertEqual(self.validate()["state"], "clean")

    def test_accepts_exact_controlled_mismatch_and_clean_restore(self):
        v=copy.deepcopy(self.receipt); v["scenario"]="disposable-sec-image-controlled-drift"; v["state"]="controlled_mismatch_detected"
        v["actions"].update(disposable_mapping_restored=True,disposable_sec_image_used=True); v["identity"]["disposable_mapping_disjoint_from_main"]=True
        v["counts"].update(clean_pages=0,mismatch_pages=1); v["post_restore_state"]="clean"; v["post_restore_counts"].update(clean_pages=1,compared_pages=1,planned_pages=1,relocation_excluded_pages=1)
        v["cost"].update(read_bytes=16384,read_attempt_count=4,query_count=6); self.assertEqual(self.validate(v)["state"], "controlled_mismatch_detected")

    def test_controlled_rejects_unstable_or_dirty_restore(self):
        for mutation in ("unstable", "restore"):
            v=copy.deepcopy(self.receipt); v["scenario"]="disposable-sec-image-controlled-drift"; v["state"]="controlled_mismatch_detected"; v["actions"].update(disposable_mapping_restored=True,disposable_sec_image_used=True); v["identity"]["disposable_mapping_disjoint_from_main"]=True
            v["counts"].update(clean_pages=0,mismatch_pages=1); v["post_restore_state"]="clean"; v["post_restore_counts"].update(clean_pages=1,compared_pages=1,planned_pages=1,relocation_excluded_pages=1); v["cost"].update(read_bytes=16384,read_attempt_count=4,query_count=6)
            if mutation=="unstable": v["counts"].update(compared_pages=0,mismatch_pages=0,unstable_pages=1); v["cost"].update(read_bytes=8192,read_attempt_count=2)
            else: v["post_restore_counts"].update(clean_pages=0,mismatch_pages=1)
            with self.assertRaises(GATE.GateError): self.validate(v)

    def test_rejects_receipt_plan_not_derived_from_artifact(self):
        for field in ("planned_pages","relocation_excluded_pages"):
            v=copy.deepcopy(self.receipt); v["counts"][field]+=1
            with self.assertRaises(GATE.GateError): self.validate(v)

    def test_rejects_unsupported_relocation_and_delay_import(self):
        for kwargs in ({"bad_reloc":True},{"delay":True}):
            self.artifact.write_bytes(pe64_fixture(**kwargs)); sha=digest(self.artifact); v=copy.deepcopy(self.receipt); v.update(artifact_sha256_before=sha,artifact_sha256_after=sha)
            with self.assertRaises(GATE.GateError): self.validate(v)

    def test_parser_requires_readable_rx_and_marks_dir64_cross_page(self):
        self.artifact.write_bytes(pe64_fixture(readable=False))
        with self.assertRaises(GATE.GateError): GATE._pe_metrics(self.artifact)
        self.artifact.write_bytes(pe64_fixture(writable=True))
        with self.assertRaises(GATE.GateError): GATE._pe_metrics(self.artifact)
        self.artifact.write_bytes(pe64_fixture(text_pages=3, cross_page=True))
        metrics = GATE._pe_metrics(self.artifact)
        self.assertEqual((metrics.eligible_pages, metrics.relocation_excluded_pages), (1, 2))
        self.artifact.write_bytes(pe64_fixture(text_pages=2, virtual_pages=3))
        metrics = GATE._pe_metrics(self.artifact)
        self.assertEqual((metrics.eligible_pages, metrics.relocation_excluded_pages), (1, 1))

    def test_parser_validates_lookup_names_and_entire_first_thunk(self):
        self.artifact.write_bytes(pe64_fixture(text_pages=3, imports="valid"))
        metrics = GATE._pe_metrics(self.artifact)
        self.assertEqual((metrics.eligible_pages, metrics.relocation_excluded_pages), (1, 2))
        for mode in ("bad_name", "first_thunk"):
            self.artifact.write_bytes(pe64_fixture(text_pages=3, imports=mode))
            with self.assertRaises(GATE.GateError): GATE._pe_metrics(self.artifact)

    def test_standalone_iat_is_validated_excluded_and_half_metadata_rejected(self):
        self.artifact.write_bytes(pe64_fixture(text_pages=3, imports="standalone_iat"))
        metrics = GATE._pe_metrics(self.artifact)
        self.assertEqual((metrics.eligible_pages, metrics.relocation_excluded_pages), (1, 2))
        for index in (1, 12):
            for half in (0, 1):
                data = bytearray(pe64_fixture(text_pages=3, imports="valid"))
                pe = int.from_bytes(data[0x3c:0x40], "little"); directory = pe + 24 + 112 + index * 8
                data[directory + half * 4:directory + half * 4 + 4] = b"\0" * 4
                self.artifact.write_bytes(data)
                with self.assertRaises(GATE.GateError): GATE._pe_metrics(self.artifact)

    def test_missing_relocation_is_only_accepted_as_non_live_degradation(self):
        self.artifact.write_bytes(pe64_fixture(relocation=False)); sha=digest(self.artifact); v=copy.deepcopy(self.receipt)
        v.update(artifact_sha256_before=sha, artifact_sha256_after=sha, state="degraded", degraded_reason="relocation_exclusion_not_positive")
        v["actions"]["live_memory_compared"]=False
        v["counts"].update(clean_pages=0,compared_pages=0,mismatch_pages=0,planned_pages=2,relocation_excluded_pages=0,unstable_pages=2)
        v["cost"].update(query_count=0,read_attempt_count=0,read_bytes=0)
        self.assertEqual(self.validate(v)["state"], "degraded")
        exceeded=copy.deepcopy(v); exceeded.update(degraded_reason="cost_budget_exceeded")
        exceeded["cost"].update(elapsed_ms=30001,budget_state="exceeded")
        self.assertEqual(self.validate(exceeded)["degraded_reason"],"cost_budget_exceeded")
        exceeded["degraded_reason"]="relocation_exclusion_not_positive"
        with self.assertRaises(GATE.GateError): self.validate(exceeded)
        v["actions"]["live_memory_compared"]=True
        with self.assertRaises(GATE.GateError): self.validate(v)

    def test_unstable_after_reads_accepts_honest_attempted_counters(self):
        v=copy.deepcopy(self.receipt); v["state"]="unstable"; v["counts"].update(clean_pages=0,compared_pages=0,unstable_pages=1)
        v["cost"].update(query_count=3,read_attempt_count=2,read_bytes=8192)
        self.assertEqual(self.validate(v)["state"], "unstable")
        v["cost"]["query_count"]=2
        with self.assertRaises(GATE.GateError): self.validate(v)

    def test_in_loop_budget_abort_has_explicit_degraded_precedence(self):
        v=copy.deepcopy(self.receipt); v.update(state="degraded",degraded_reason="cost_budget_exceeded")
        v["counts"].update(clean_pages=0,compared_pages=0,unstable_pages=1)
        v["cost"].update(elapsed_ms=30001,query_count=0,read_attempt_count=0,read_bytes=0,budget_state="exceeded")
        self.assertEqual(self.validate(v)["state"],"degraded")

    def test_measurement_boundary_cannot_include_receipt_serialization(self):
        for field,value in (("measurement_boundary","full_run"),("receipt_encoding_and_write_measured",True)):
            v=copy.deepcopy(self.receipt); v[field]=value
            with self.assertRaises(GATE.GateError): self.validate(v)

    def test_rejects_any_identity_weakening(self):
        for field in GATE.IDENTITY_KEYS-{"disposable_mapping_disjoint_from_main","mapped_file_object_identity_proven"}:
            v=copy.deepcopy(self.receipt); v["identity"][field]=False
            with self.assertRaises(GATE.GateError): self.validate(v)

    def test_rejects_provenance_transplant(self):
        for field in ("source_commit","dirty_patch_sha256","build_command_sha256","toolchain_id"):
            v=copy.deepcopy(self.receipt); v[field]="0"*(40 if field=="source_commit" else 64) if field!="toolchain_id" else "other"
            with self.assertRaises(GATE.GateError): self.validate(v)
        v=copy.deepcopy(self.receipt); v["build_command_sha256"]=hashlib.sha256(GATE.BUILD_COMMAND_ID.encode("ascii")).hexdigest()
        with self.assertRaises(GATE.GateError): self.validate(v)

    def test_rejects_cost_counter_or_budget_lie(self):
        for field,value in (("read_bytes",0),("query_count",4),("budget_state","exceeded")):
            v=copy.deepcopy(self.receipt); v["cost"][field]=value
            with self.assertRaises(GATE.GateError): self.validate(v)
        v=copy.deepcopy(self.receipt); v["cost"].update(working_set_after=600*1024*1024,working_set_delta_bytes=600*1024*1024-1,working_set_peak_delta_bytes=600*1024*1024-1)
        with self.assertRaises(GATE.GateError): self.validate(v)

    def test_rejects_positive_claim_current_main_write_or_privacy(self):
        for field in GATE.CLAIM_KEYS:
            v=copy.deepcopy(self.receipt); v["claims"][field]=True
            with self.assertRaises(GATE.GateError): self.validate(v)
        v=copy.deepcopy(self.receipt); v["actions"]["current_main_modified"]=True
        with self.assertRaises(GATE.GateError): self.validate(v)
        v=copy.deepcopy(self.receipt); v["module_path"]="secret"
        with self.assertRaises(GATE.GateError): self.validate(v)

    def test_requires_canonical_json_and_schema(self):
        with self.assertRaises(GATE.GateError):
            GATE.validate(self.write(self.receipt,False),self.artifact,self.planner,self.harness,self.lock,SCHEMA,derived_provenance=PROVENANCE)
        schema=json.loads(SCHEMA.read_text()); Draft202012Validator.check_schema(schema); Draft202012Validator(schema).validate(self.receipt)

    def test_scoped_bundle_digest_is_binary_safe_and_content_bound(self):
        root=Path(self.temp.name)/"repo"
        for index, relative in enumerate(GATE.PROVENANCE_PATHS):
            path=root/relative; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(bytes((index,0,255)))
        with patch.object(GATE,"_run_identity",return_value=b"100644 deadbeef 0\tfile\n"):
            before=GATE._bundle_digest(root); (root/GATE.PROVENANCE_PATHS[-1]).write_bytes(b"changed\0\xff"); after=GATE._bundle_digest(root)
        self.assertNotEqual(before,after)

    def test_derived_provenance_normalizes_rustc_and_hashes_exact_command(self):
        def fake(command, root):
            return b"1"*40+b"\n" if command[0]=="git" and command[1]=="rev-parse" else b"rustc 1.88\r\nhost: x\r\n"
        with patch.object(GATE,"_resolve_executable",side_effect=lambda name:name), patch.object(GATE,"_run_identity",side_effect=fake), patch.object(GATE,"_bundle_digest",return_value="2"*64):
            value=GATE.derive_provenance(Path(self.temp.name))
        self.assertEqual(value["source_commit"],"1"*40); self.assertEqual(value["dirty_patch_sha256"],"2"*64)
        self.assertEqual(value["build_command_sha256"],hashlib.sha256(GATE.CANONICAL_BUILD_COMMAND.encode("ascii")).hexdigest())
        self.assertTrue(value["toolchain_id"].startswith("rustc-vv-sha256-"))

    def test_preflight_accepts_marker_shape_and_rejects_zero_relocation(self):
        self.artifact.write_bytes(pe64_fixture())
        self.assertEqual(GATE.preflight_artifact(self.artifact),{"eligible_pages":1,"relocation_excluded_pages":1})
        output=io.StringIO()
        with contextlib.redirect_stdout(output): self.assertEqual(GATE.main(["--preflight-artifact","--artifact",str(self.artifact)]),0)
        self.assertEqual(json.loads(output.getvalue()),{"eligible_pages":1,"relocation_excluded_pages":1})
        self.artifact.write_bytes(pe64_fixture(relocation=False))
        with self.assertRaises(GATE.GateError): GATE.preflight_artifact(self.artifact)

    def test_scoped_bundle_rejects_nonregular_inputs(self):
        root=Path(self.temp.name)/"nonregular"
        for relative in GATE.PROVENANCE_PATHS:
            path=root/relative; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(b"x")
        victim=root/GATE.PROVENANCE_PATHS[-1]; victim.unlink(); victim.mkdir()
        with patch.object(GATE,"_resolve_executable",return_value="git"), patch.object(GATE,"_run_identity",return_value=b""):
            with self.assertRaises(GATE.GateError): GATE._bundle_digest(root)


if __name__ == "__main__": unittest.main()
