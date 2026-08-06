#![deny(warnings)]

use std::arch::global_asm;
use std::env;
use std::ffi::c_void;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;
use std::slice;
use std::time::Instant;

const PAGE_SIZE: usize = 4096;
const DRIFT_OFFSET: usize = 137;
const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const PROT_EXEC: i32 = 0x4;
const MAP_PRIVATE: i32 = 0x02;
const MAP_ANONYMOUS: i32 = 0x20;

global_asm!(
    r#"
    .pushsection .text.tamandua_probe,"ax",@progbits
    .balign 4096
    .global tamandua_probe_page
    .type tamandua_probe_page,@object
tamandua_probe_page:
    .rept 4096
    .byte 0x90
    .endr
    .size tamandua_probe_page, .-tamandua_probe_page
    .popsection
"#
);

extern "C" {
    static tamandua_probe_page: u8;
    fn mmap(
        address: *mut c_void,
        length: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: isize,
    ) -> *mut c_void;
    fn mprotect(address: *mut c_void, length: usize, protection: i32) -> i32;
    fn munmap(address: *mut c_void, length: usize) -> i32;
}

#[derive(Clone)]
struct Mapping {
    start: usize,
    end: usize,
    permissions: String,
    file_offset: usize,
    inode: u64,
    path: String,
}

struct Record {
    scenario: &'static str,
    state: &'static str,
    outcome: &'static str,
    backing_state: &'static str,
    final_protection: &'static str,
    observed_permissions: String,
    mapping_file_offset: usize,
    probe_file_offset: usize,
    load_bias: usize,
    mapping_inode: u64,
    backing_inode: Option<u64>,
    baseline_sha256: Option<String>,
    current_sha256: Option<String>,
    drift_offsets: Vec<usize>,
    limitations: Vec<&'static str>,
    compared_bytes: usize,
    comparison_pipeline_duration_ns: Option<u128>,
    cleanup: &'static str,
}

#[allow(unused_unsafe)]
fn probe_address() -> usize {
    unsafe { ptr::addr_of!(tamandua_probe_page) as usize }
}

fn parse_mapping(line: &str) -> Option<Mapping> {
    let columns: Vec<&str> = line.split_whitespace().collect();
    if columns.len() < 5 {
        return None;
    }
    let (start, end) = columns[0].split_once('-')?;
    Some(Mapping {
        start: usize::from_str_radix(start, 16).ok()?,
        end: usize::from_str_radix(end, 16).ok()?,
        permissions: columns[1].to_string(),
        file_offset: usize::from_str_radix(columns[2], 16).ok()?,
        inode: columns[4].parse().ok()?,
        path: columns.get(5..).unwrap_or_default().join(" "),
    })
}

fn mapping_for(address: usize) -> Result<Mapping, String> {
    let maps = fs::read_to_string("/proc/self/maps").map_err(|_| "maps_unavailable")?;
    maps.lines()
        .filter_map(parse_mapping)
        .find(|mapping| address >= mapping.start && address < mapping.end)
        .ok_or_else(|| "mapping_not_found".to_string())
}

fn file_identity(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.ino())
        .map_err(|_| "backing_identity_unavailable".to_string())
}

fn probe_file_offset(mapping: &Mapping, address: usize) -> Result<usize, String> {
    mapping
        .file_offset
        .checked_add(
            address
                .checked_sub(mapping.start)
                .ok_or("load_bias_invalid")?,
        )
        .ok_or_else(|| "probe_file_offset_overflow".to_string())
}

fn baseline_page(mapping: &Mapping, address: usize) -> Result<(usize, Vec<u8>), String> {
    let offset = probe_file_offset(mapping, address)?;
    let mut executable =
        File::open("/proc/self/exe").map_err(|_| "self_executable_unavailable".to_string())?;
    executable
        .seek(SeekFrom::Start(offset as u64))
        .map_err(|_| "probe_file_seek_failed".to_string())?;
    let mut bytes = vec![0_u8; PAGE_SIZE];
    executable
        .read_exact(&mut bytes)
        .map_err(|_| "probe_file_read_exact_failed".to_string())?;
    Ok((offset, bytes))
}

fn read_probe() -> Vec<u8> {
    unsafe { slice::from_raw_parts(probe_address() as *const u8, PAGE_SIZE) }.to_vec()
}

fn protect_probe(protection: i32) -> Result<(), String> {
    if protection & PROT_WRITE != 0 && protection & PROT_EXEC != 0 {
        return Err("writable_executable_mapping_forbidden".to_string());
    }
    if probe_address() % PAGE_SIZE != 0 {
        return Err("probe_not_page_aligned".to_string());
    }
    if unsafe { mprotect(probe_address() as *mut c_void, PAGE_SIZE, protection) } != 0 {
        return Err("probe_mprotect_failed".to_string());
    }
    Ok(())
}

fn mutate_probe() -> Result<(), String> {
    protect_probe(PROT_READ | PROT_WRITE)?;
    unsafe {
        let target = (probe_address() as *mut u8).add(DRIFT_OFFSET);
        target.write(target.read() ^ 0xff);
    }
    protect_probe(PROT_READ | PROT_EXEC)
}

fn sha256(bytes: &[u8]) -> Result<String, String> {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "sha256_process_unavailable".to_string())?;
    child
        .stdin
        .take()
        .ok_or("sha256_stdin_unavailable")?
        .write_all(bytes)
        .map_err(|_| "sha256_input_failed".to_string())?;
    let output = child
        .wait_with_output()
        .map_err(|_| "sha256_process_failed".to_string())?;
    if !output.status.success() {
        return Err("sha256_process_failed".to_string());
    }
    let rendered = String::from_utf8(output.stdout).map_err(|_| "sha256_output_invalid")?;
    let digest = rendered
        .split_whitespace()
        .next()
        .ok_or("sha256_output_missing")?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("sha256_output_invalid".to_string());
    }
    Ok(digest.to_ascii_lowercase())
}

fn offsets_json(offsets: &[usize]) -> String {
    format!(
        "[{}]",
        offsets
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn strings_json(values: &[&str]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn nullable_string(value: Option<String>) -> String {
    value.map_or_else(|| "null".to_string(), |item| format!("\"{item}\""))
}

fn nullable_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_string(), |item| item.to_string())
}

fn nullable_u128(value: Option<u128>) -> String {
    value.map_or_else(|| "null".to_string(), |item| item.to_string())
}

fn supported_record(scenario: &'static str, drift: bool) -> Result<Record, String> {
    let address = probe_address();
    let initial = mapping_for(address)?;
    if initial.permissions.as_bytes().get(2) != Some(&b'x') || initial.inode == 0 {
        return Err("probe_not_file_backed_executable".to_string());
    }
    let started = Instant::now();
    let (file_offset, baseline) = baseline_page(&initial, address)?;
    if drift {
        mutate_probe()?;
    }
    let final_mapping = mapping_for(address)?;
    if final_mapping.permissions.as_bytes().get(0) != Some(&b'r')
        || final_mapping.permissions.as_bytes().get(1) == Some(&b'w')
        || final_mapping.permissions.as_bytes().get(2) != Some(&b'x')
    {
        return Err("probe_did_not_finish_rx".to_string());
    }
    let current = read_probe();
    let drift_offsets = baseline
        .iter()
        .zip(current.iter())
        .enumerate()
        .filter_map(|(offset, (before, after))| (before != after).then_some(offset))
        .collect();
    let baseline_sha256 = sha256(&baseline)?;
    let current_sha256 = sha256(&current)?;
    let duration = started.elapsed().as_nanos();
    let backing_inode = file_identity(Path::new("/proc/self/exe"))?;
    Ok(Record {
        scenario,
        state: "supported",
        outcome: if drift { "finding" } else { "clean" },
        backing_state: "original",
        final_protection: "rx",
        observed_permissions: final_mapping.permissions,
        mapping_file_offset: initial.file_offset,
        probe_file_offset: file_offset,
        load_bias: initial.start.saturating_sub(initial.file_offset),
        mapping_inode: initial.inode,
        backing_inode: Some(backing_inode),
        baseline_sha256: Some(baseline_sha256),
        current_sha256: Some(current_sha256),
        drift_offsets,
        limitations: Vec::new(),
        compared_bytes: PAGE_SIZE,
        comparison_pipeline_duration_ns: Some(duration),
        cleanup: "process_exit_discards_private_mapping",
    })
}

fn unavailable_record(
    scenario: &'static str,
    state: &'static str,
    backing_state: &'static str,
    protection: &'static str,
    permissions: String,
    limitation: &'static str,
    mapping: Option<&Mapping>,
    backing_inode: Option<u64>,
    cleanup: &'static str,
) -> Record {
    let mapping_file_offset = mapping.map(|item| item.file_offset).unwrap_or(0);
    let address = probe_address();
    let file_offset = mapping
        .and_then(|item| probe_file_offset(item, address).ok())
        .unwrap_or(0);
    let load_bias = mapping
        .map(|item| item.start.saturating_sub(item.file_offset))
        .unwrap_or(0);
    Record {
        scenario,
        state,
        outcome: state,
        backing_state,
        final_protection: protection,
        observed_permissions: permissions,
        mapping_file_offset,
        probe_file_offset: file_offset,
        load_bias,
        mapping_inode: mapping.map(|item| item.inode).unwrap_or(0),
        backing_inode,
        baseline_sha256: None,
        current_sha256: None,
        drift_offsets: Vec::new(),
        limitations: vec![limitation],
        compared_bytes: 0,
        comparison_pipeline_duration_ns: None,
        cleanup,
    }
}

fn case_binary_path() -> Result<PathBuf, String> {
    let path =
        PathBuf::from(env::var("TAMANDUA_CASE_BINARY_PATH").map_err(|_| "case_path_missing")?);
    let rendered = path.to_string_lossy();
    if !rendered.starts_with("/tmp/tamandua-rx-elf-lab.") || rendered.contains("..") {
        return Err("case_path_outside_lab_namespace".to_string());
    }
    Ok(path)
}

fn deleted_record() -> Result<Record, String> {
    let address = probe_address();
    let before = mapping_for(address)?;
    let path = case_binary_path()?;
    fs::remove_file(&path).map_err(|_| "delete_backing_failed")?;
    let after = mapping_for(address)?;
    let exe_target = fs::read_link("/proc/self/exe").map_err(|_| "self_link_unavailable")?;
    if !after.path.ends_with(" (deleted)") && !exe_target.to_string_lossy().ends_with(" (deleted)")
    {
        return Err("deleted_backing_not_observed".to_string());
    }
    Ok(unavailable_record(
        "deleted_backing",
        "degraded",
        "deleted",
        "rx",
        after.permissions.clone(),
        "file_backing_deleted",
        Some(&before),
        None,
        "case_binary_unlinked",
    ))
}

fn replaced_record() -> Result<Record, String> {
    let address = probe_address();
    let mapping = mapping_for(address)?;
    let path = case_binary_path()?;
    let replacement = path.with_extension("replacement");
    fs::copy("/proc/self/exe", &replacement).map_err(|_| "replacement_copy_failed")?;
    fs::rename(&replacement, &path).map_err(|_| "replacement_rename_failed")?;
    let replacement_inode = file_identity(&path)?;
    if replacement_inode == mapping.inode {
        return Err("replacement_identity_did_not_change".to_string());
    }
    fs::remove_file(&path).map_err(|_| "replacement_cleanup_failed")?;
    Ok(unavailable_record(
        "replaced_backing",
        "degraded",
        "replaced",
        "rx",
        mapping.permissions.clone(),
        "file_backing_identity_changed",
        Some(&mapping),
        Some(replacement_inode),
        "replacement_removed",
    ))
}

fn anonymous_record() -> Result<Record, String> {
    let raw = unsafe {
        mmap(
            ptr::null_mut(),
            PAGE_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if raw as isize == -1 {
        return Err("anonymous_mmap_failed".to_string());
    }
    unsafe { ptr::write_bytes(raw, 0x90, PAGE_SIZE) };
    if unsafe { mprotect(raw, PAGE_SIZE, PROT_READ | PROT_EXEC) } != 0 {
        unsafe { munmap(raw, PAGE_SIZE) };
        return Err("anonymous_mprotect_failed".to_string());
    }
    let mapping = mapping_for(raw as usize)?;
    if mapping.inode != 0 || mapping.permissions.as_bytes().get(1) == Some(&b'w') {
        unsafe { munmap(raw, PAGE_SIZE) };
        return Err("anonymous_mapping_contract_invalid".to_string());
    }
    if unsafe { munmap(raw, PAGE_SIZE) } != 0 {
        return Err("anonymous_unmap_failed".to_string());
    }
    Ok(unavailable_record(
        "anonymous_jit_no_baseline",
        "unsupported",
        "anonymous",
        "rx",
        mapping.permissions,
        "anonymous_executable_has_no_file_baseline",
        None,
        None,
        "anonymous_mapping_unmapped",
    ))
}

fn execute_only_record() -> Result<Record, String> {
    let initial = mapping_for(probe_address())?;
    protect_probe(PROT_EXEC)?;
    let execute_only = mapping_for(probe_address())?;
    if execute_only.permissions.as_bytes().get(0) == Some(&b'r')
        || execute_only.permissions.as_bytes().get(1) == Some(&b'w')
        || execute_only.permissions.as_bytes().get(2) != Some(&b'x')
    {
        protect_probe(PROT_READ | PROT_EXEC)?;
        return Err("execute_only_permissions_not_observed".to_string());
    }
    protect_probe(PROT_READ | PROT_EXEC)?;
    Ok(unavailable_record(
        "execute_only_file_backed",
        "degraded",
        "original",
        "x",
        execute_only.permissions,
        "execute_only_policy_refused_dereference",
        Some(&initial),
        Some(file_identity(Path::new("/proc/self/exe"))?),
        "probe_permissions_restored_rx",
    ))
}

fn emit(record: Record) {
    println!(
        "{{\"schema\":\"tamandua.runtime-rx-filebacked-elf-linux-raw/v1\",\"scenario\":\"{}\",\"state\":\"{}\",\"outcome\":\"{}\",\"backing_state\":\"{}\",\"page_size_bytes\":{},\"initial_protection\":\"rx\",\"final_protection\":\"{}\",\"observed_permissions\":\"{}\",\"mapping_file_offset\":{},\"probe_file_offset\":{},\"load_bias\":{},\"mapping_inode\":{},\"backing_inode\":{},\"baseline_sha256\":{},\"current_sha256\":{},\"drift_offsets\":{},\"limitations\":{},\"compared_bytes\":{},\"comparison_pipeline_duration_ns\":{},\"writable_executable_used\":false,\"mapped_bytes_executed\":false,\"absolute_paths_emitted\":false,\"cleanup\":\"{}\"}}",
        record.scenario,
        record.state,
        record.outcome,
        record.backing_state,
        PAGE_SIZE,
        record.final_protection,
        record.observed_permissions,
        record.mapping_file_offset,
        record.probe_file_offset,
        record.load_bias,
        record.mapping_inode,
        nullable_u64(record.backing_inode),
        nullable_string(record.baseline_sha256),
        nullable_string(record.current_sha256),
        offsets_json(&record.drift_offsets),
        strings_json(&record.limitations),
        record.compared_bytes,
        nullable_u128(record.comparison_pipeline_duration_ns),
        record.cleanup,
    );
}

fn run() -> Result<Record, String> {
    match env::args().nth(1).as_deref() {
        Some("clean_file_backed_rx") => supported_record("clean_file_backed_rx", false),
        Some("file_backed_rw_to_rx_drift") => supported_record("file_backed_rw_to_rx_drift", true),
        Some("deleted_backing") => deleted_record(),
        Some("replaced_backing") => replaced_record(),
        Some("anonymous_jit_no_baseline") => anonymous_record(),
        Some("execute_only_file_backed") => execute_only_record(),
        Some(_) => Err("scenario_invalid".to_string()),
        None => Err("scenario_required".to_string()),
    }
}

fn main() {
    match run() {
        Ok(record) => emit(record),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
