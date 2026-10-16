//! End-to-end test on the MIPS-LE self-contained nvram demo.
//!
//! Mirrors `x86_64_nvram_e2e.rs` but targets a statically-linked MIPS-LE
//! ET_EXEC guest with the four nvram_* functions and the outer
//! `guarded_network_startup` all in the single ELF. Asserts the same
//! nested bidirectional IIB event sequence.
//!
//! This test is currently `#[ignore]` and skipped at runtime whenever the
//! guest binary is absent because the dev host lacks a MIPS-LE cross
//! compiler. To enable it, install a toolchain that provides
//! `mipsel-linux-musl-gcc` (or equivalent — see
//! `assets/mips/nvram_guest/Makefile`), build the guest with `make` in
//! that directory, then fill in the placeholder absolute VAs in
//! `assets/mips/intervention/manifest.json` and
//! `assets/mips/intervention/src/state.rs` from `readelf -s` output and
//! `cargo build --release` the intervention crate.

use std::path::PathBuf;
use std::process::Command;

fn asset(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets/mips")
        .join(rel)
}

fn workspace_release(bin: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../../../GuestWeave/target/release").join(bin)
}

#[test]
#[ignore = "requires mipsel cross-compiler for guest binary (see AGENTS.md IIB Runtime)"]
fn mips_nvram_nested_bidirectional() {
    let guest_bin = asset("nvram_guest/fmst_mips_nvram_guest");
    if !guest_bin.exists() {
        eprintln!(
            "skipping: MIPS-LE guest binary not built ({guest:?}); \
             install a mipsel cross-compiler and run \
             `cd tests/runtime_fixtures/guestweave/assets/mips/nvram_guest && make`",
            guest = guest_bin,
        );
        return;
    }

    let harness = workspace_release("fmst-harness-mips");
    assert!(
        harness.exists(),
        "build harness first: cargo build --release -p fmst-harness-mips; expected {:?}",
        harness
    );

    let intervention_so = asset("intervention/target/release/libintervention_mips_nvram.so");
    assert!(
        intervention_so.exists(),
        "build intervention first: cd tests/runtime_fixtures/guestweave/assets/mips/intervention && cargo build --release"
    );

    // Fully statically linked guest needs no rootfs; /tmp is enough.
    let rootfs = PathBuf::from("/tmp");
    assert!(rootfs.exists(), "/tmp missing (!?)");

    let output = Command::new(&harness)
        .env("RUST_LOG", "info")
        .arg("--intervention-so")
        .arg(&intervention_so)
        .arg("--binary")
        .arg(&guest_bin)
        .arg("--rootfs")
        .arg(&rootfs)
        .output()
        .expect("failed to spawn harness-mips");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- harness stdout ---\n{stdout}\n--- harness stderr ---\n{stderr}");

    assert!(
        output.status.success(),
        "harness exited with {:?}; stderr:\n{stderr}",
        output.status.code()
    );

    // Boot + done markers from the guest's _start.
    assert!(
        stdout.contains("[guest] entering libnvram probe"),
        "missing MSG_BOOT marker; guest didn't reach _start"
    );
    assert!(
        stdout.contains("[guest] probe finished"),
        "missing MSG_DONE marker; guest didn't complete guest_main"
    );

    // IIB event trace from our intervention.
    for required in [
        "outer hook fired for ifname=fmst0",
        "outer hook -> native_call(apply_runtime_profile",
        "nested hook nvram_init fired",
        "nested hook nvram_set(",
        "nested hook nvram_get(",
        "nested hook nvram_commit fired",
        "outer hook <- native_call returned",
    ] {
        assert!(
            stderr.contains(required),
            "missing expected IIB event '{required}' in stderr:\n{stderr}"
        );
    }

    // Sanity: the KV pair that sync_nvram_cache sets ("fmst_probe_key" -> "fmst0").
    assert!(
        stderr.contains(r#"nvram_set("fmst_probe_key", "fmst0")"#),
        "nvram_set arguments don't match expected (key=fmst_probe_key, value=fmst0)"
    );

    // nvram_get should not have fallen back to the default NULL path —
    // the intervention's nvram_set populated the KV first, so nvram_get
    // must return the scratch buffer pointer (non-zero). Cheap check:
    // stderr should contain '->' with a hex addr, not '-> NULL'.
    assert!(
        !stderr.contains(r#"nvram_get("fmst_probe_key") -> NULL"#),
        "nvram_get returned NULL — intervention ordering bug"
    );
}
