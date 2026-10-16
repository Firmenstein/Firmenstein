//! nvram_set(key: *const c_char, value: *const c_char) -> int.
//! Stub: write (key, value) into the in-memory HashMap, return 0.
//! MIPS O32 puts arg0 in $a0, arg1 in $a1 — but `IIBContextOps::read_arg`
//! handles the calling convention so this code is arch-neutral.

use fmst_iib_api::context::{IIBContextOps, state_of};
use crate::state::NvramState;

pub fn intercept(ctx: &mut dyn IIBContextOps) {
    let state = state_of::<NvramState>(ctx);

    let key_ptr = ctx.read_arg(0).unwrap();
    let val_ptr = ctx.read_arg(1).unwrap();
    let key = ctx.read_cstr(key_ptr, 256)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "<bad-key>".to_string());
    let val = ctx.read_cstr(val_ptr, 4096)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "<bad-val>".to_string());

    state.kv.lock().unwrap().insert(key.clone(), val.clone());
    state.log_event(format!("nested hook nvram_set({key:?}, {val:?}) -> 0"));

    let _ = ctx.set_return_value(0);
}
