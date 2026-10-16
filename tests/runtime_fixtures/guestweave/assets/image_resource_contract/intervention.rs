use fmst_iib_api::{
    context::IIBContextOps,
    manifest::*,
    pseudo_file::{PseudoFile, PseudoFileOpen},
    types::*,
};
include!("layout.rs");

struct State {
    bytes: Vec<u8>,
    cursor: usize,
}
impl PseudoFile for State {
    fn read(
        &mut self,
        address: GuestAddr,
        len: usize,
        ctx: &mut dyn IIBContextOps,
    ) -> Result<usize, Errno> {
        let n = len.min(self.bytes.len().saturating_sub(self.cursor));
        ctx.write_mem(address, &self.bytes[self.cursor..self.cursor + n])?;
        self.cursor += n;
        Ok(n)
    }
    fn write(
        &mut self,
        address: GuestAddr,
        len: usize,
        ctx: &mut dyn IIBContextOps,
    ) -> Result<usize, Errno> {
        let mut bytes = vec![0; len];
        ctx.read_mem(address, &mut bytes)?;
        self.bytes = bytes;
        self.cursor = len;
        Ok(len)
    }
    fn lseek(&mut self, offset: i64, whence: i32) -> Result<i64, Errno> {
        if whence != 0 || offset < 0 || offset as usize > self.bytes.len() {
            return Err(Errno::EINVAL);
        }
        self.cursor = offset as usize;
        Ok(offset)
    }
    fn exec_snapshot(&mut self) -> Result<Option<Vec<u8>>, Errno> {
        #[cfg(feature = "no-snapshot")]
        return Ok(None);
        #[cfg(not(feature = "no-snapshot"))]
        {
            let mut state = vec![1, self.cursor as u8];
            state.extend_from_slice(&self.bytes);
            Ok(Some(state))
        }
    }
    fn exec_restore(&mut self, state: &[u8]) -> Result<(), Errno> {
        if state.len() < 2 || state[0] != 1 || state[1] as usize > state.len() - 2 {
            return Err(Errno::EINVAL);
        }
        self.cursor = state[1] as usize;
        self.bytes = state[2..].to_vec();
        Ok(())
    }
}
fn factory(_: &str, _: i64) -> PseudoFileOpen {
    PseudoFileOpen::Handled(Box::new(State {
        bytes: b"INITIAL".to_vec(),
        cursor: 0,
    }))
}
fn hook(ctx: &mut dyn IIBContextOps) {
    // Offset is derived from this build's ELF symbols, never a runtime VA.
    let target = ctx.current_pc().wrapping_add_signed(NATIVE_DELTA);
    let invalid = ctx.native_call(ctx.current_pc().wrapping_add_signed(DATA_DELTA), &[]); // data is mapped but not executable
    if invalid.is_ok() {
        let _ = ctx.set_return_value(0);
        return;
    }
    let result = ctx.native_call(target, &[]).unwrap_or(0);
    let _ = ctx.set_return_value(result);
}
fn init() -> Box<dyn std::any::Any + Send + Sync> {
    Box::new(())
}
static MANIFEST: StaticManifest = StaticManifest {
    abi_version: CURRENT_ABI_VERSION,
    arch: Arch::X86_64,
    global_state: StaticGlobalState {
        type_name: "()",
        init_fn: init,
    },
    callsite_hooks: &[],
    function_stubs: &[FunctionStubStatic {
        id: "parent-hook",
        target: ModuleTargetStatic {
            binary: "parent",
            offset: HOOK_OFFSET,
            symbol_hint: None,
        },
        flavor: HookFlavor::Enter,
        entry_fn: hook,
    }],
    pseudo_files: &[PseudoFileStatic {
        id: "shared-state",
        paths: &["/dev/contract-state"],
        factory,
        impl_name: "StateV1",
    }],
};
#[unsafe(no_mangle)]
pub extern "Rust" fn fmst_manifest() -> &'static StaticManifest {
    &MANIFEST
}
