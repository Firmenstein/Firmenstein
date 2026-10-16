# R6700v3 libnvram Guest

This directory contains a minimal custom ARM guest binary for early emulator and IIB bring-up.

The binary is intentionally small:

- It does not use the firmware's `nvram` utility.
- It does not require a C runtime startup object.
- It links directly against the firmware's `libnvram.so`.
- It is considered successful if it starts, resolves `libnvram.so`, enters the library calls, and executes under `qemu-arm-static`.

The current guest does not try to solve the `/dev/nvram` dependency. That roadblock is expected and is left for later IIB or pseudo-device handling.

## Call Graph

```text
guest_main
  -> guarded_network_startup("fmst0")            # A: top-level guard, good outer hook target
	  -> firmware_netif_ioctl_precheck("fmst0") # ioctl-based roadblock
	  -> apply_runtime_profile("fmst0")         # B: native function to re-enter from hook
		  -> sync_nvram_cache(...)              # C: nested hook target
			  -> nvram_init
			  -> nvram_set
			  -> nvram_get
			  -> nvram_commit
```

`fmst0` is intentionally chosen as a synthetic interface name so the baseline run hits the ioctl roadblock before reaching the NVRAM stage. That makes it suitable for testing an outer hook that bypasses the roadblock and then uses `native_call()` to run the native profile path.

## Suggested IIB Flow

1. Hook `guarded_network_startup` as the outer interception point.
2. In the hook, skip or replace the failing ioctl logic.
3. From the hook, call native `apply_runtime_profile` through `native_call()`.
4. While that native call executes, intercept either `sync_nvram_cache` or one of the `nvram_*` callsites.
5. Return from the nested hook back into `apply_runtime_profile`, then back to the outer hook, then to the original caller.

## Files

- `src/entry.c`: minimal `_start` entry written in C, with inline ARM Linux syscalls for logging and exit
- `src/guest_main.c`: custom probe logic that calls `nvram_init`, `nvram_set`, `nvram_get`, and `nvram_commit`
- `include/libnvram_abi.h`: hand-written ABI declarations for the imported functions
- `scripts/build.sh`: builds a dynamic ARM ELF against the firmware rootfs libraries
- `scripts/run.sh`: runs the built guest under `qemu-arm-static`

## Expected behavior

The binary should:

1. Print a startup marker.
2. Successfully load through `/lib/ld-uClibc.so.0`.
3. Resolve `libnvram.so` and call into it.
4. Eventually hit the `/dev/nvram` roadblock and continue or exit.

That is enough for the current stage because the goal is binary loading and execution shape, not correct NVRAM semantics.

## Build

```bash
tests/runtime_fixtures/guestweave/assets/arm/r6700v3_nvram/nvram_guest/scripts/build.sh
```

## Run

```bash
tests/runtime_fixtures/guestweave/assets/arm/r6700v3_nvram/nvram_guest/scripts/run.sh
```

To include qemu syscall tracing:

```bash
QEMU_STRACE=1 tests/runtime_fixtures/guestweave/assets/arm/r6700v3_nvram/nvram_guest/scripts/run.sh
```