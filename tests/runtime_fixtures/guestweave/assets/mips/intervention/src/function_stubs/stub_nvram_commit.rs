//! nvram_commit() -> int. Default guest impl returns -1.
//! Stub: log + return 0.

use fmst_iib_api::context::{IIBContextOps, state_of};
use crate::state::NvramState;

pub fn intercept(ctx: &mut dyn IIBContextOps) {
    let state = state_of::<NvramState>(ctx);
    state.log_event("nested hook nvram_commit fired -> returning 0".to_string());
    let _ = ctx.set_return_value(0);
}
