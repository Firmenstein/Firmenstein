//! End-to-end test on the R6700v3 NVRAM demo.
//!
//! Spawns harness-arm with the firmware rootfs + demo guest binary + our
//! intervention .so, captures stderr, and asserts that:
//!   (a) outer hook fired
//!   (b) native_call was issued
//!   (c) all four nested nvram_* hooks fired (init/set/get/commit)
//!   (d) harness exited cleanly

use std::path::PathBuf;
use std::process::Command;

fn asset(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets/arm/r6700v3_nvram")
        .join(rel)
}

fn workspace_release(bin: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../../../GuestWeave/target/release").join(bin)
}

#[test]
#[ignore = "requires firmware rootfs + demo guest built + intervention .so built; run: cargo test --release --test r6700v3_nvram_e2e -- --ignored --nocapture"]
fn r6700v3_nvram_nested_bidirectional() {
    let harness = workspace_release("fmst-harness-arm");
    assert!(
        harness.exists(),
        "build harness first: cargo build --release -p fmst-harness-arm; expected {:?}",
        harness
    );

    let guest_bin = asset("nvram_guest/build/fmst_nvram_guest");
    assert!(guest_bin.exists(),
        "build guest first: cd tests/runtime_fixtures/guestweave/assets/arm/r6700v3_nvram/nvram_guest && scripts/build.sh; expected {guest_bin:?}");

    let intervention_so = asset("intervention/target/release/libintervention_r6700v3_nvram.so");
    assert!(intervention_so.exists(),
        "build intervention first: cd assets/arm/r6700v3_nvram/intervention && cargo build --release");

    let rootfs = PathBuf::from(
        std::env::var_os("ROOTFS").expect("set ROOTFS to the extracted R6700v3 rootfs directory"),
    );
    assert!(rootfs.exists(), "R6700v3 rootfs missing");

    let output = Command::new(&harness)
        .env("RUST_LOG", "info")
        .arg("--intervention-so")
        .arg(&intervention_so)
        .arg("--binary")
        .arg(&guest_bin)
        .arg("--rootfs")
        .arg(&rootfs)
        .output()
        .expect("failed to spawn harness-arm");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- harness stdout ---\n{stdout}\n--- harness stderr ---\n{stderr}");

    assert!(
        output.status.success(),
        "harness exited with {:?}; stderr:\n{stderr}",
        output.status.code()
    );

    // Both boot markers from entry.c should appear.
    assert!(
        stdout.contains("[guest] entering libnvram probe"),
        "missing MSG_BOOT marker; guest didn't reach _start"
    );
    assert!(
        stdout.contains("[guest] probe finished"),
        "missing MSG_DONE marker; guest didn't complete guest_main"
    );

    // IIB event trace from our intervention (events also go through log::info! -> stderr).
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
}
