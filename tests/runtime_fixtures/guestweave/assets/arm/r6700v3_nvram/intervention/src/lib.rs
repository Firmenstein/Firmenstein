//! Real-world IIB test against R6700v3 firmware's libnvram.so.
//! Demonstrates nested bidirectional call through native_call.

pub mod function_stubs;
pub mod state;

include!(concat!(env!("OUT_DIR"), "/fmst_manifest.rs"));
