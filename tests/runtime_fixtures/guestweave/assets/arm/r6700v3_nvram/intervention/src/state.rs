//! Shared state across all hooks. Lives in host heap, persistent for whole
//! harness process lifetime.
//!
//! Key design: `apply_runtime_profile_pc` is populated by the outer hook
//! the first time it fires. At that point, IIB's deferred registration has
//! completed, so load_base for the guest binary is known and the outer stub
//! can derive the sibling function's address from its own PC + known offset.

use std::collections::HashMap;
use std::sync::{Mutex, atomic::AtomicU64};

/// Offset (within fmst_nvram_guest) from guarded_network_startup to
/// apply_runtime_profile: 0x8654 - 0x86a0 = -0x4c (apply comes BEFORE guarded
/// in the .text layout). Use signed delta when computing at runtime.
pub const APPLY_RUNTIME_PROFILE_DELTA_FROM_GUARDED: i64 = -0x4c;

/// Where nvram_get returns its value buffer. This is a fixed guest address
/// inside a dedicated scratch page that post_qemu_init mmap'd for us.
///
/// Must match `IIB_SCRATCH_PAGE_ADDR` in `fmst_iib_runtime::module`.
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

    pub fn apply_runtime_profile_from_guarded_pc(guarded_pc: u64) -> u64 {
        (guarded_pc as i64 + APPLY_RUNTIME_PROFILE_DELTA_FROM_GUARDED) as u64
    }
}
