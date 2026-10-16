#![forbid(unsafe_code)]

//! Shared state across all hooks. Lives in host heap, persistent for whole
//! harness process lifetime.
//!
//! Unlike the ARM demo we can't compute `apply_runtime_profile`'s PC from
//! the outer hook's own PC with a fixed delta — on x86_64 the compiler
//! re-orders functions and the distance is whatever happens to fall out
//! of codegen. Instead we stash the **absolute VA** from `readelf -s` and
//! fix it up once we see the outer hook fire (so we know the real load
//! base picked by qemu-user's `build_load_map`). Specifically we compute
//! `apply_pc = apply_absolute_va - guarded_absolute_va + guarded_runtime_pc`.
//! That reduces to a signed delta at runtime but encodes the absolute VAs
//! at build time, avoiding a symbol-distance assumption.

use std::collections::HashMap;
use std::sync::{Mutex, atomic::AtomicU64};

/// Absolute VA (ET_EXEC non-PIE) of `guarded_network_startup` as reported
/// by `readelf -s`. Used together with `APPLY_RUNTIME_PROFILE_VA` to
/// compute the signed delta to apply_runtime_profile.
pub const GUARDED_NETWORK_STARTUP_VA: u64 = 0x401202;

/// Absolute VA (ET_EXEC non-PIE) of `apply_runtime_profile` as reported
/// by `readelf -s`.
pub const APPLY_RUNTIME_PROFILE_VA: u64 = 0x4011c3;

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
