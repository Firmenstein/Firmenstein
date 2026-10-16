#![forbid(unsafe_code)]

//! Shared state across all hooks. Lives in host heap, persistent for whole
//! harness process lifetime.
//!
//! Just like the x86_64 demo, we stash the **absolute VAs** of
//! `guarded_network_startup` and `apply_runtime_profile` (read via
//! `readelf -s` once the MIPS guest is built) and compute the runtime
//! PC delta when the outer hook fires. For ET_EXEC the delta is just
//! `APPLY_RUNTIME_PROFILE_VA - GUARDED_NETWORK_STARTUP_VA` (load_base
//! is irrelevant).
//!
//! NOTE: The VA constants below are placeholders (0) pending a MIPS-LE
//! cross-compile of the guest. Fill them in from `readelf -s
//! fmst_mips_nvram_guest` once the toolchain is available.

use std::collections::HashMap;
use std::sync::{Mutex, atomic::AtomicU64};

/// Absolute VA (ET_EXEC non-PIE) of `guarded_network_startup` as reported
/// by `readelf -s`. PLACEHOLDER — fill in once guest is built.
pub const GUARDED_NETWORK_STARTUP_VA: u64 = 0x0000_0000;

/// Absolute VA (ET_EXEC non-PIE) of `apply_runtime_profile` as reported
/// by `readelf -s`. PLACEHOLDER — fill in once guest is built.
pub const APPLY_RUNTIME_PROFILE_VA: u64 = 0x0000_0000;

/// Where nvram_get returns its value buffer. Inside IIB's scratch page
/// (matches `IIB_SCRATCH_PAGE_ADDR` in `fmst_iib_runtime::module`).
pub const NVRAM_GET_VALUE_BUFFER_ADDR: u64 = 0x7f00_0000;
pub const NVRAM_GET_VALUE_BUFFER_SIZE: usize = 256;

#[derive(Default)]
pub struct NvramState {
    /// Simulated NVRAM key-value store.
    pub kv: Mutex<HashMap<String, String>>,

    /// Populated by the outer stub on first fire; 0 means "not yet resolved".
    pub apply_runtime_profile_pc: AtomicU64,

    /// Event log for assertions in the E2E test.
    pub events: Mutex<Vec<String>>,
}

impl NvramState {
    pub fn log_event(&self, msg: String) {
        // Use eprintln! directly (the log crate inside a cdylib doesn't
        // share the harness's env_logger initialisation, so `log::info!`
        // would be a no-op here). The E2E test scrapes these lines from
        // the harness's stderr.
        eprintln!("[iib-event] {msg}");
        if let Ok(mut v) = self.events.lock() {
            v.push(msg);
        }
    }

    /// Resolve apply_runtime_profile's runtime PC from the outer hook's
    /// observed self PC. Works for both ET_EXEC (load_base irrelevant
    /// since VAs are absolute and the delta is a constant) and ET_DYN
    /// (load_base cancels out of the subtraction).
    pub fn apply_runtime_profile_from_guarded_pc(guarded_pc: u64) -> u64 {
        let delta = (APPLY_RUNTIME_PROFILE_VA as i64) - (GUARDED_NETWORK_STARTUP_VA as i64);
        (guarded_pc as i64 + delta) as u64
    }
}
