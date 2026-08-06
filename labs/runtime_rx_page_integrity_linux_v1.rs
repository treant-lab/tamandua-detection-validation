#![deny(warnings)]

use std::env;
use std::ffi::c_void;
use std::fs;
use std::ptr;
use std::slice;
use std::time::Instant;

const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const PROT_EXEC: i32 = 0x4;
const MAP_PRIVATE: i32 = 0x02;
const MAP_ANONYMOUS: i32 = 0x20;
const SC_PAGESIZE: i32 = 30;
const DRIFT_OFFSET: usize = 137;

extern "C" {
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
    fn sysconf(name: i32) -> isize;
}

struct OwnedMapping {
    address: *mut u8,
    length: usize,
    active: bool,
    readable: bool,
    writable: bool,
    executable: bool,
}

impl OwnedMapping {
    fn new(length: usize) -> Result<Self, String> {
        let raw = unsafe {
            mmap(
                ptr::null_mut(),
                length,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw as isize == -1 {
            return Err("mmap_failed".to_string());
        }
        Ok(Self {
            address: raw.cast(),
            length,
            active: true,
            readable: true,
            writable: true,
            executable: false,
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() != self.length || !self.active || !self.writable {
            return Err("mapping_write_contract_invalid".to_string());
        }
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), self.address, self.length) };
        Ok(())
    }

    fn mutate(&mut self, offset: usize) -> Result<(), String> {
        if offset >= self.length || !self.active || !self.writable {
            return Err("mapping_mutation_contract_invalid".to_string());
        }
        unsafe {
            let current = self.address.add(offset).read();
            self.address.add(offset).write(current ^ 0xff);
        }
        Ok(())
    }

    fn protect(&mut self, protection: i32) -> Result<(), String> {
        if !self.active {
            return Err("mapping_protection_contract_invalid".to_string());
        }
        if protection & PROT_WRITE != 0 && protection & PROT_EXEC != 0 {
            return Err("writable_executable_mapping_forbidden".to_string());
        }
        if unsafe { mprotect(self.address.cast(), self.length, protection) } != 0 {
            return Err("mprotect_failed".to_string());
        }
        self.readable = protection & PROT_READ != 0;
        self.writable = protection & PROT_WRITE != 0;
        self.executable = protection & PROT_EXEC != 0;
        Ok(())
    }

    fn read_rx(&self) -> Result<Vec<u8>, String> {
        if !self.active || !self.readable || self.writable || !self.executable {
            return Err("mapping_read_contract_invalid".to_string());
        }
        Ok(unsafe { slice::from_raw_parts(self.address, self.length) }.to_vec())
    }

    fn permissions(&self) -> Result<String, String> {
        let maps = fs::read_to_string("/proc/self/maps").map_err(|_| "maps_unavailable")?;
        let target = self.address as usize;
        for line in maps.lines() {
            let mut columns = line.split_whitespace();
            let range = columns.next().unwrap_or_default();
            let permissions = columns.next().unwrap_or_default();
            let Some((start, end)) = range.split_once('-') else {
                continue;
            };
            let Ok(start) = usize::from_str_radix(start, 16) else {
                continue;
            };
            let Ok(end) = usize::from_str_radix(end, 16) else {
                continue;
            };
            if target >= start && target < end {
                return Ok(permissions.to_string());
            }
        }
        Err("mapping_metadata_unavailable".to_string())
    }

    fn unmap(&mut self) -> Result<(), String> {
        if !self.active {
            return Err("mapping_already_unmapped".to_string());
        }
        if unsafe { munmap(self.address.cast(), self.length) } != 0 {
            return Err("munmap_failed".to_string());
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for OwnedMapping {
    fn drop(&mut self) {
        if self.active {
            let _ = unsafe { munmap(self.address.cast(), self.length) };
            self.active = false;
        }
    }
}

fn page_size() -> Result<usize, String> {
    let size = unsafe { sysconf(SC_PAGESIZE) };
    if size <= 0 {
        Err("page_size_unavailable".to_string())
    } else {
        Ok(size as usize)
    }
}

fn baseline(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| ((index.wrapping_mul(31).wrapping_add(17)) % 251) as u8)
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn offsets_json(offsets: &[usize]) -> String {
    let values: Vec<String> = offsets.iter().map(usize::to_string).collect();
    format!("[{}]", values.join(","))
}

struct ResultRecord {
    scenario: &'static str,
    state: &'static str,
    page_size: usize,
    final_protection: &'static str,
    baseline_hex: Option<String>,
    current_hex: Option<String>,
    drift_offsets: Vec<usize>,
    limitations_json: &'static str,
    observed_permissions: String,
    compared_bytes: usize,
    comparison_duration_ns: Option<u128>,
}

fn run_supported(drift: bool) -> Result<ResultRecord, String> {
    let size = page_size()?;
    let expected = baseline(size);
    let mut mapping = OwnedMapping::new(size)?;
    mapping.write(&expected)?;
    if drift {
        mapping.mutate(DRIFT_OFFSET)?;
    }
    mapping.protect(PROT_READ | PROT_EXEC)?;
    let permissions = mapping.permissions()?;
    let started = Instant::now();
    let current = mapping.read_rx()?;
    let drift_offsets = expected
        .iter()
        .zip(current.iter())
        .enumerate()
        .filter_map(|(offset, (before, after))| (before != after).then_some(offset))
        .collect();
    let elapsed = started.elapsed().as_nanos();
    mapping.unmap()?;
    Ok(ResultRecord {
        scenario: if drift {
            "rx_restored_drift"
        } else {
            "clean_no_relocation"
        },
        state: "supported",
        page_size: size,
        final_protection: "rx",
        baseline_hex: Some(hex(&expected)),
        current_hex: Some(hex(&current)),
        drift_offsets,
        limitations_json: "[]",
        observed_permissions: permissions,
        compared_bytes: size,
        comparison_duration_ns: Some(elapsed),
    })
}

fn run_unavailable(jit: bool) -> Result<ResultRecord, String> {
    let size = page_size()?;
    let bytes = baseline(size);
    let mut mapping = OwnedMapping::new(size)?;
    mapping.write(&bytes)?;
    let (scenario, state, final_protection, protection, limitations) = if jit {
        (
            "jit_no_baseline",
            "unsupported",
            "rx",
            PROT_READ | PROT_EXEC,
            "[\"jit_region_has_no_stable_baseline\"]",
        )
    } else {
        (
            "execute_only_unreadable",
            "degraded",
            "x",
            PROT_EXEC,
            "[\"execute_only_policy_refused_dereference\"]",
        )
    };
    mapping.protect(protection)?;
    let permissions = mapping.permissions()?;
    // Deliberately do not dereference JIT-without-baseline or execute-only pages.
    mapping.unmap()?;
    Ok(ResultRecord {
        scenario,
        state,
        page_size: size,
        final_protection,
        baseline_hex: None,
        current_hex: None,
        drift_offsets: Vec::new(),
        limitations_json: limitations,
        observed_permissions: permissions,
        compared_bytes: 0,
        comparison_duration_ns: None,
    })
}

fn nullable_string(value: Option<String>) -> String {
    value.map_or_else(|| "null".to_string(), |item| format!("\"{item}\""))
}

fn nullable_number(value: Option<u128>) -> String {
    value.map_or_else(|| "null".to_string(), |item| item.to_string())
}

fn emit(record: ResultRecord) {
    println!(
        "{{\"schema\":\"tamandua.runtime-rx-page-integrity-linux-raw/v1\",\"scenario\":\"{}\",\"state\":\"{}\",\"page_size_bytes\":{},\"initial_protection\":\"rw\",\"final_protection\":\"{}\",\"baseline_hex\":{},\"current_hex\":{},\"drift_offsets\":{},\"limitations\":{},\"observed_permissions\":\"{}\",\"mapped_pages\":1,\"compared_bytes\":{},\"comparison_duration_ns\":{},\"cleanup\":\"unmapped\"}}",
        record.scenario,
        record.state,
        record.page_size,
        record.final_protection,
        nullable_string(record.baseline_hex),
        nullable_string(record.current_hex),
        offsets_json(&record.drift_offsets),
        record.limitations_json,
        record.observed_permissions,
        record.compared_bytes,
        nullable_number(record.comparison_duration_ns),
    );
}

fn run() -> Result<(), String> {
    let scenario = env::args().nth(1).ok_or("scenario_required")?;
    let result = match scenario.as_str() {
        "clean_no_relocation" => run_supported(false),
        "rx_restored_drift" => run_supported(true),
        "jit_no_baseline" => run_unavailable(true),
        "execute_only_unreadable" => run_unavailable(false),
        _ => Err("scenario_invalid".to_string()),
    }?;
    emit(result);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
