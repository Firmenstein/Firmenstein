//! Outer hook: replaces `guarded_network_startup(ifname)` in the MIPS-LE demo.
//!
//! Invokes the sibling `apply_runtime_profile(ifname)` via IIB `native_call`.
//! While that runs, the nvram_* nested hooks fire — exercising the paper
//! §3.4 nested bidirectional flow end-to-end on MIPS-LE.
//!
//! MIPS O32 ABI puts the first 4 integer args in $a0-$a3 and the return
//! value in $v0. `IIBContextOps::read_arg` / `set_return_value` already
//! abstract over the calling convention, so this code is arch-neutral.

use fmst_iib_api::context::{IIBContextOps, state_of};
use std::sync::atomic::Ordering;
use crate::state::NvramState;

pub fn intercept(ctx: &mut dyn IIBContextOps) {
    // Read arg0 + compute apply_pc while holding an immutable borrow of state.
    // Drop the borrow BEFORE invoking native_call, which takes &mut ctx.
    let (ifname_ptr, _ifname, apply_pc) = {
        let state = state_of::<NvramState>(ctx);

        let ifname_ptr = ctx.read_arg(0).expect("read arg0");
        let ifname = ctx.read_cstr(ifname_ptr, 16)
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "<unreadable>".to_string());
        state.log_event(format!("outer hook fired for ifname={ifname}"));

        // Resolve apply_runtime_profile's PC from our own PC + known delta.
        // For ET_EXEC (non-PIE) the delta is the same whether we compute
        // via "readelf abs VAs" or "runtime PCs"; load_base cancels.
        let apply_pc = {
            let cached = state.apply_runtime_profile_pc.load(Ordering::SeqCst);
            if cached != 0 {
                cached
            } else {
                let self_pc = ctx.current_pc();
                let resolved = NvramState::apply_runtime_profile_from_guarded_pc(self_pc);
                state.apply_runtime_profile_pc.store(resolved, Ordering::SeqCst);
                state.log_event(format!(
                    "outer hook resolved apply_runtime_profile_pc = {resolved:#x} (self_pc={self_pc:#x})"
                ));
                resolved
            }
        };

        state.log_event(format!("outer hook -> native_call(apply_runtime_profile, ifname_ptr={ifname_ptr:#x})"));
        (ifname_ptr, ifname, apply_pc)
    };

    // IIB native_call into apply_runtime_profile(ifname) — takes &mut ctx.
    let result = ctx.native_call(apply_pc, &[ifname_ptr]);

    // Now safe to re-borrow state for logging + set_return_value.
    let state = state_of::<NvramState>(ctx);
    let ret_value = match result {
        Ok(r) => {
            state.log_event(format!("outer hook <- native_call returned {r:#x}"));
            r
        }
        Err(e) => {
            state.log_event(format!("outer hook native_call failed: {e:?}"));
            u64::MAX
        }
    };
    let _ = ctx.set_return_value(ret_value);
}
