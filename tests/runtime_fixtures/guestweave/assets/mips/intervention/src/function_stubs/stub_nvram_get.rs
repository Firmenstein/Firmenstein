//! nvram_get(key: *const c_char) -> char*.
//! Stub: look up key; if found, copy value into a reserved guest buffer at
//! IIB's scratch page and return that pointer. If not found, return NULL.

use fmst_iib_api::context::{IIBContextOps, state_of};
use crate::state::{NVRAM_GET_VALUE_BUFFER_ADDR, NVRAM_GET_VALUE_BUFFER_SIZE, NvramState};

pub fn intercept(ctx: &mut dyn IIBContextOps) {
    let state = state_of::<NvramState>(ctx);

    let key_ptr = ctx.read_arg(0).unwrap();
    let key = ctx.read_cstr(key_ptr, 256)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "<bad-key>".to_string());

    let kv = state.kv.lock().unwrap();
    match kv.get(&key) {
        Some(v) => {
            let mut bytes = v.as_bytes().to_vec();
            bytes.push(0);
            if bytes.len() > NVRAM_GET_VALUE_BUFFER_SIZE {
                state.log_event(format!(
                    "nested hook nvram_get({key:?}) value too long ({} > {NVRAM_GET_VALUE_BUFFER_SIZE})",
                    bytes.len()
                ));
                let _ = ctx.set_return_value(0);
                return;
            }
            let _ = ctx.write_mem(NVRAM_GET_VALUE_BUFFER_ADDR, &bytes);
            state.log_event(format!(
                "nested hook nvram_get({key:?}) -> {v:?} @ {NVRAM_GET_VALUE_BUFFER_ADDR:#x}"
            ));
            let _ = ctx.set_return_value(NVRAM_GET_VALUE_BUFFER_ADDR);
        }
        None => {
            state.log_event(format!("nested hook nvram_get({key:?}) -> NULL"));
            let _ = ctx.set_return_value(0);
        }
    }
}
