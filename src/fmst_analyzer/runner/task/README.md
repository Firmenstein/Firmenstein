# Autonomous Runner task

`/task/task.json` gives the service goal, input identities and entrypoint hints.
The goal comes from the explicit caller, current configuration, retained Plan,
or a default local service goal, in that order; `goal_source` records its origin.
The caller may select container memory, swap, CPU, process and shared-memory
limits through `ContainerRehostingRunner(resources=...)` or the workdir's
`runner-options.json`. Omitted limits use the Docker engine defaults. Firmware
concurrency, host headroom and emergency stopping belong to the external batch
launcher. The task records selected limits and samples resources for observation;
its repair deadline applies only until service completion.
`/task/input` preserves source material. Work in `/task/work`: private firmware
rootfs, candidate and GuestWeave/backend sources. Existing analysis is in
`/task/analysis`; the selected target's reports are in `/task/input/reports`.
`/task/input/materials.json` indexes supplied material, source/container paths,
content identities and missing inputs. It includes available reports for other
analyzed targets in this firmware, plus the actual source workdir's graph,
C/assembly and IDB directories. `resolve_material_path` resolves historical
report paths without rewriting their provenance. This is a firmware-scoped
copy, not the host workdir; unrelated firmware and old Runner dumps are excluded.

Start investigation and repair from the Generator code in `/task/work/candidate`;
`/task/input/candidate` preserves the original. Review the material index and
available Analyzer, Plan and Generator overviews to understand prior findings,
dependencies, launch options and the candidate. Each Analyzer's review reports
can support the investigation. Read details and corresponding code relevant to
the current problem on demand, and check prior conclusions against native execution.
Analyzer, Plan and Generator reports are reference material only. They can contain
false positives and false negatives. Check relevant findings against the current
code and native execution; an omitted issue does not prove that no problem exists.

When `input_mode="upstream_repair"`, an ordinary upstream tool/analysis failure
prevented a usable publication. `task.json.upstream_repair.input` binds the
selected ELF and original rootfs hashes and retains the failed stage, actual
exception chain and task execution ledger. Failed reports remain under `.attempts`;
they are partial evidence and are never complete-cache or Catalog sources.
Prefer a validated Generator publication when supplied. Otherwise
`candidate_origin="diagnostic_scaffold"` identifies a fresh GuestWeave executable
with native syscall tracing, not a completed intervention or a firmware success.
Fresh unfinished Generator files may be supplied separately in `upstream-generator`
as unvalidated repair material. Verify their input, ABI and bindings before reuse.
Investigate the native failure and implement interventions where needed.
Provider, resource, cancellation and input-identity failures prohibit this handoff.
The same Runner keeps its original budget and native completion criteria.

The selected target's report directories are:

| Material | Container directory |
|---|---|
| IPC Analyzer | `/task/input/reports/ipc_reports/` |
| File Analyzer | `/task/input/reports/file_reports/` |
| Network Analyzer | `/task/input/reports/network_reports/` |
| Process lifecycle Analyzer | `/task/input/reports/process_lifecycle_reports/` |
| Init/launch Analyzer | `/task/input/reports/init_launch_reports/` |
| Plan | `/task/input/reports/intervention_plan_reports/` |
| Generator | `/task/input/reports/intervention_generation_reports/` |

Start with each available `index.md`; the same directories contain structured
JSON and detailed reports. Reports for other analyzed targets in this firmware
are under `/task/input/firmware-reports/<target>/`, as indexed by
`/task/input/materials.json` and `task.json.report_paths`. Resolve source paths
quoted in reports to these container copies before reading the referenced material.

Firmware rootfs input uses a GNU tar stream with numeric ownership, permissions,
links, ACLs and xattrs preserved. Both the received tree and its working copy are
checked before this session starts. `/task/evidence/input-transfer/rootfs/` holds
the source/received/work manifests, stderr logs and transfer receipt. Its
`runtime-entries.json` describes source device nodes and sockets left for runtime
setup; no regular-file placeholders are substituted. Use these descriptions when
investigating a missing runtime resource. Source ownership already lost during
upstream extraction cannot be recovered by copying.

The private image includes IDA, its Python bindings and license configuration.
`IDADIR=/opt/ida` and `IDAUSR=/opt/ida-user` work without host IDA files or
per-task license injection. Keep new databases and analysis under `/task/analysis`;
their writable state is private to this task. Do not copy license contents into
evidence or reports.

You have full Claude Code Bash/editing tools, networking and passwordless sudo.
Task requirements and the concrete Goal arrive in the first user message, over
Claude Code's unmodified system preset. The selected GuestWeave engineering
Skill is available through the native `Skill` tool as
`fmst-task:guestweave-intervention-engineering`; its body and references load on
demand from the working copy. Relative reference paths remain valid through the
session-local plugin. It is the only task Skill. The user message supplies the
intervention reasoning and local usability goal; the Planner Skill and its
stage workflow are not registered. No separate project `CLAUDE.md` is required.

Use any suitable commands and install tools when needed. The GuestWeave Skill
describes intervention APIs; the user message defines the local test environment
and representative native interaction scope. The task goal takes precedence over historical
stage permissions in source reports. Planner and Generator instructions describe
their original jobs; generated-file comments do not restrict your working-copy
repairs. Preserve `/task/input` as the original evidence.

When prepared native sources are supplied, `/task/work/native/qemu` and
`/task/work/native/libvharness` contain the selected pinned sources. The build
environment selects these private copies via `LIBAFL_QEMU_DIR`/`VHARNESS_DIR`.
They can be edited and rebuilt as needed; do not replace the shared host source.

`/task/task.json` supplies `runtime.harness`, pointing to a precompiled harness
under `/opt/guestweave/runtime/<architecture>/`. Its receipt and selected source
identities are in `/task/evidence/image-runtime.json`. Use it immediately without
downloading a toolchain or rebuilding QEMU. The fixed Rust toolchain and
`/task/work/.cargo/config.toml` with `/opt/guestweave/vendor` allow current
dependencies to build without networking. New dependencies may require extending
the vendor or changing this private Cargo configuration; normal Internet access
remains available. If you change the private framework/native sources, rebuild
the harness against those edits and use the new artifact.

## Candidate and intervention

When revising the generated layout, `/task/input/candidate-engineering.md` explains the
generated crate's modules, adapters, `GlobalState`, manifest and optional mock
checks. The supplied GuestWeave Skill points to the selected API/ABI and build
documentation under `/task/work/framework/GuestWeave`. Its public-API advice
applies to intervention code; you may also repair this private backend when needed.

`/task/work/candidate` is the editable copy of `/task/input/candidate`.
Depending on what Generation produced, it contains `intervention/Cargo.toml`,
`intervention/manifest.json`, `intervention/src`, `test_harness` and
`environment/setup_rootfs.py`. Missing or incomplete files are repair inputs.
Keep a shared state model when adding or revising cooperating bindings; no
upstream Unit-admission request is needed in this container.

The optional helper accepts the actual candidate manifest:

```sh
python -m fmst_analyzer.runner.task.guest build /task/work/candidate/intervention/Cargo.toml > /task/evidence/build.log 2>&1
```

You may invoke Cargo directly, including its JSON artifact output to find the
resulting library. Build against the selected API dependency; input preparation
records its working-copy relocation in `/task/evidence/dependency-relocation.json`.
For the supplied launcher, the configuration's `intervention_so` selects that
library; `python -m fmst_analyzer.runner.task.guest --help` describes the other
fields. The launcher copies the selected library into that execution's bundle.
A rebuild does not replace a library already used by a running process; relaunch
the affected service with the new artifact when testing the change.

An execution record identifies the selected/bundled artifact, not proof that a
particular hook fired. Check load diagnostics and the relevant trace or focused
behavioral observation. Custom launchers remain available, but delivered native
operations must execute through GuestWeave with runtime trace. Plain QEMU can
help diagnosis; its business behavior alone does not establish that delivery.
Keep original failures and compare the native operation after repair.
Mock tests are optional diagnostics here; native interaction remains the goal.

## Execution and analysis evidence

Each supplied guest launch writes `/task/evidence/executions/<id>/execution.json`:
launch configuration, process/start identity, actual harness/intervention/images,
logs, trace roots and core collection state. `/task/evidence/execution.json` points
to the current firmware execution; starting a compiler, proxy or browser job
does not change it. `view_executions` returns the index; evidence tools read the
selected record on every call. Select an earlier execution explicitly when needed.

`view_runtime_trace_files` discovers nested process traces inside that execution,
excluding derived query output. Raw `query_runtime_events` filters keep complete
retained pages in files and return paths/counts/checkpoint hashes. Source mapping
is requested only for semantic filters or explicit mapped views. Fork/exec
checkpoints can overlap; their command count is not a business success metric.

`view_container_log` reads the associated firmware job log or an explicit path.
`inspect_emulator_cpu` queries the recorded harness's QEMU models/build sources,
not host CPU usage. Custom launchers can pass explicit paths or register an
execution using `runner.task.execution`; jobs support `--execution` and `--role`.
Missing registration means automatic selection is unavailable, not that nothing ran.

The supplied launcher collects changed task-local core files when it exits.
`collect_runtime_cores` also works while the main service is alive, for a crashed
child/CGI. Collection retains at most 64 MiB with a disk reserve and leaves original
files accessible. It records collection failures, missing cores and uncertain
process associations separately. `inspect_runtime_core` can use a captured core
or an explicit file; explicit access does not invent a process association.
Cross-architecture inspection uses the image's `gdb-multiarch`.

Reports, exported C/assembly, logs, ELF metadata, raw trace queries and core/GDB
inspection do not initialize IDA. Semantic tools and new binary onboarding use a
lazy, separate native analysis process. A missing topology or IDA failure returns
its diagnostic log path; the Agent and basic evidence tools remain usable.
Repair the dependency and retry in this session; a dead analysis process restarts
on the next call. `onboard_binary` can initialize a missing analysis topology.

## Services that survive Agent exit

The Runner's native Claude history is retained in `/task/sessions/runner/`.
`session.json` records its identity; `config/projects/` contains the native
transcripts. Ending the Agent closes its SDK connection and retains this state.
Explicit follow-ups use the same native session and keep separate reports under
`/task/evidence/resumes/`. Original completion records remain intact.

Start a long-lived process through the container init. This accepts arbitrary
commands and returns its PID, start ticks and log path:

```sh
python -m fmst_analyzer.runner.task.jobs -- python -m http.server 8080
```

Jobs run as container root (you already have sudo). For an ordinary-user process,
prefix the command with `runuser -u runner --`. Workdir defaults to the current
directory. Jobs are independent of the SDK's background-shell lifecycle.

`python -m fmst_analyzer.runner.task.guest --help` supplies generic helpers for
building an intervention and launching a guest in a private chroot/PID/network
namespace. It is optional; you can edit it or use your own scripts. GuestWeave's
rootfs option is a loader prefix, so do not run firmware directly in the Agent's
Ubuntu root. A private guest namespace protects the Agent's network/processes.

## Native browser and evidence

`agent-browser skills get core` loads the installed CLI's matching guide.
The browser is installed in this container. Run it in the guest network namespace
when the firmware requires native IPs/ports; for the supplied launcher use:

```sh
sudo --preserve-env=PYTHONPATH /opt/venv/bin/python -m fmst_analyzer.runner.task.netns fmst-guest -- runuser -u runner -- agent-browser --session firmware open http://192.168.1.1
```

Use native hostnames and ports. `/etc/netns/fmst-guest/hosts` can define firmware
DNS names for commands run through this helper. For privileged Python commands,
use `/opt/venv/bin/python` (Python 3.12) and preserve `PYTHONPATH` to import the
task modules. The helper enters the network and hosts
view without `ip netns exec`'s `/sys` remount, which a rootless container cannot
perform. Use it with any command, or use `nsenter --net=/run/netns/fmst-guest`
when you only need the network. Store interaction evidence,
screenshots, trace and build logs under `/task/evidence`. Read them selectively;
the tools also expose report and trace views without requiring huge context dumps.

On completion, keep the service running and call `complete_service`. Report
representative operations and state observations, evidence files, service PID
and start ticks, native URL, usable access instructions and known limitations.
You can use a SOCKS proxy in the guest namespace for native origin access from a
user browser, or provide precise `docker exec` browser commands. Do not silently
rewrite firmware pages/responses to hide broken native behavior.

The supplied guest launcher also runs a SOCKS5 proxy in its network namespace.
Docker exposes it on a random **host loopback** port; the host handoff records
that port. A user browser configured with this SOCKS proxy (remote DNS enabled)
can open the exact native URL with its original hostname and port.

The initial delivery retains this same container. Cold rebuild, clean replay,
host reboot recovery and migration are not completion prerequisites; they are
unverified unless actually exercised. Never put model credentials in delivery.
