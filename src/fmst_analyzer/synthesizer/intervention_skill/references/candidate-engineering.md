# Firmenstein candidate engineering

Use this reference to understand or revise a generated intervention. It describes
the candidate layout, not permissions or a required test phase. The active task
supplies the writable scope, goal and execution environment. GuestWeave's selected
engineering Skill, API/ABI, runtime and build references define library behavior.

## Source and state

The intervention crate's `Cargo.toml` selects its API dependency and crate name.
`src/lib.rs` declares Unit modules and includes the generated manifest code;
`build.rs` consumes `manifest.json`, including its resolved binding addresses.
Inspect those files before adding or changing a binding. Bind addresses to the matching ELF.

Each Unit module contains `logic.rs`, `state.rs` and binding adapters. Keep business
behavior in ordinary Rust logic; adapters decode guest inputs, invoke logic and
write caller-visible results. Logic receives ordinary values and state rather
than `IIBContextOps`. The template's top-level `src/state.rs` defines `GlobalState`,
which contains Unit state fields. Reuse shared state for cooperating operations.

In this generated layout, use `fmst_iib_api::state_of` with
`crate::state::GlobalState`; do not invent another `state_of` module. The concrete
state type named by the manifest must match the type requested from the context.
Generated headers describe authorship, not the active task's editing permissions.
For a new Unit, account for the module, state field, manifest entry and binding
as well as its behavior implementation. Actual candidate files remain authoritative
for the layout; an incomplete candidate may need missing files created.

## Build and exercise

Build against the API and harness version selected by the task. Cargo's artifact
output identifies the actual library; a prior `.so` is not refreshed by a source
edit. Launch configuration must select the resulting artifact. Check loading and
runtime evidence separately from successful compilation. The task guide supplies
the current paths and launcher interface.

Generated `test_harness` crates support focused `MockIIBContextOps` checks. When
using them, seed the exact manifest state, for example
`mock.set_state(intervention_target::state::GlobalState::default())`, with the
actual crate name. A binding-local `State` alias is not the top-level manifest
state. A fall-through `Call` hook has an unset `return_value` and does not invoke
`native_call`. MIPS-BE generated test crates enable the big-endian mock; numeric
fixtures still need target byte order. Other ABI rules come from GuestWeave.

Choose checks from caller behavior and independent evidence, including consumed
output memory, state transitions and retained native behavior. Correct mistaken
expectations with evidence; do not weaken an assertion to hide a failed behavior.
Mock checks and native execution establish different facts. The active stage
determines which checks are required; native service quality needs actual use.
