# GuestWeave integration fixtures

These fixtures belong to Firmenstein. The public GuestWeave workspace does not
depend on them. Run the Python scripts with the Firmenstein virtual environment;
they load the project `.env` and require the local Linux Docker builder.

- `run_child_association_fixture.py`: current production Sandbox, normal
  response, related child crash and unrelated child crash.
- `run_diagnostic_isolation.py`: real guest stdout/stderr and host diagnostics.
- `run_image_resource_contract.py`: guest image/resource and exec contracts.
- `revalidate_publication.py`: verify frozen inputs, build current runtime,
  execute the original scenario, publish a new configuration and replay it in a
  fresh session. It preserves the parent publication and shares one budget.
  `--authored-candidate` requires a reason, saves a diff and source hashes, and
  builds/tests the explicit candidate. It never silently upgrades a frozen ABI.
  `--reviewed-scenario` requires `--review-reason`, retains snapshots of both
  scenes and rejects removal or weakening of the original executable checks.
  Extra reviewed checks run during both validation and clean replay; this is
  human-reviewed validation, not an Agent-generated repair or scene.
- `run_demo_regression.py`: run all 13 retained final publications and their
  unchanged original scenarios with the current Core, without rebuilding or
  calling an Agent. The explicit inventory is
  `docs/workflow/samples/runtime-v2.json`. At most four sessions run concurrently;
  overlapping configured subnets are serialized. Frozen trees and ELF identity
  are verified, generated supervisor differences are retained, and each run has
  a separate receipt. This is current-version validation, not strict replay of
  archived validator code or full device acceptance.

Example from `Firmenstein/`:

```sh
src/.venv/bin/python tests/runtime_fixtures/guestweave/revalidate_publication.py \
  /path/to/original/manifest.json --output tmp/revalidation/new-run

src/.venv/bin/python tests/runtime_fixtures/guestweave/run_demo_regression.py \
  --output tmp/demo-regression/new-run --concurrency 4
```

`tests/*_nvram_e2e.rs` and their `assets/` are older opt-in demos. Their Cargo
dependencies now resolve to GuestWeave, but that alone does not validate their
guest binaries, hook offsets or manifest ABI. They remain ignored until their
documented assets are prepared; an ignored test is not a passing guest test.
The R6700v3 demo requires an explicit `ROOTFS` environment variable for its
build/run scripts and Rust test. Its `run.sh` uses ordinary `qemu-arm-static` for
the guest baseline; it is not a GuestWeave runtime test.
