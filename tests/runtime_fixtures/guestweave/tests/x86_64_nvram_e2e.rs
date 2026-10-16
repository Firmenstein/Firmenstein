//! End-to-end test on the x86_64 self-contained nvram demo.
//!
//! Mirrors `r6700v3_nvram_e2e.rs` but targets a statically-linked x86_64
//! ET_EXEC guest with the four nvram_* functions and the outer
//! `guarded_network_startup` all in the single ELF. Asserts the same
//! nested bidirectional IIB event sequence.

use std::path::PathBuf;
use std::process::Command;

fn asset(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets/x86_64")
        .join(rel)
}

fn workspace_release(bin: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../../../GuestWeave/target/release").join(bin)
}

#[test]
#[ignore = "requires x86_64 demo guest built + intervention .so built; run: cargo test --release --test x86_64_nvram_e2e -- --ignored --nocapture"]
fn x86_64_nvram_nested_bidirectional() {
    let harness = workspace_release("fmst-harness-x86");
    assert!(
        harness.exists(),
        "build harness first: cargo build --release -p fmst-harness-x86; expected {:?}",
        harness
    );

    let guest_bin = asset("nvram_guest/fmst_x86_nvram_guest");
    assert!(
        guest_bin.exists(),
        "build guest first: cd tests/runtime_fixtures/guestweave/assets/x86_64/nvram_guest && make"
    );

    let intervention_so = asset("intervention/target/release/libintervention_x86_nvram.so");
    assert!(
        intervention_so.exists(),
        "build intervention first: cd tests/runtime_fixtures/guestweave/assets/x86_64/intervention && cargo build --release"
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
        .expect("failed to spawn harness-x86");

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
