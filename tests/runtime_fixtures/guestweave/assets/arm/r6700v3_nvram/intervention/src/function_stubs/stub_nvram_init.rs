//! nvram_init() -> int. Real implementation opens /dev/nvram which is absent.
//! Stub: log + return 0.

use fmst_iib_api::context::{IIBContextOps, state_of};
use crate::state::NvramState;

pub fn intercept(ctx: &mut dyn IIBContextOps) {
    let state = state_of::<NvramState>(ctx);
    state.log_event("nested hook nvram_init fired -> returning 0".to_string());
    let _ = ctx.set_return_value(0);
}
