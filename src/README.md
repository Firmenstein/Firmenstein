# Firmenstein Python package

The package contains `fmst_analyzer` (analysis, planning, generation and runtime
orchestration) and `fmst_basic` (firmware extraction, Agent adapters and shared
infrastructure).

Run the CLI from the project directory with `python main.py --help`.
The current setup and execution entry points are in the [project README](../README.md).
CLI flags are defined in [main.py](../main.py); do not maintain a second copied
flag/default table here.

GuestWeave is an external dependency selected by `FMST_GUESTWEAVE_WORKSPACE`.
Prepare the pinned dependency with `python src/scripts/prepare_guestweave.py`
and set the printed path in `.env`; GuestWeave is not bundled into this package.
