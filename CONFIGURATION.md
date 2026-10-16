# Configuration

[Back to README](README.md) · [Runner setup](docker/runner-agent/README.md)

This reference covers the command-line workflow and its local Runner. Use
[.env.example](.env.example) as a starting point and fill in your own values.

- [Loading configuration](#loading-configuration)
- [Setup requirements](#setup-requirements)
- [Environment variables](#environment-variables)
- [Command-line options](#command-line-options)
- [Runner options](#runner-options)
- [Concurrency and time budgets](#concurrency-and-time-budgets)
- [Common configuration problems](#common-configuration-problems)

## Loading configuration

Run commands from the repository root with the Python environment activated:

```sh
source src/.venv/bin/activate
```

For a new checkout, copy `.env.example` to `.env` as shown in the README. Keep an
existing populated `.env`. The CLI and private/runtime image-build helpers load
this file automatically. Values
already exported in the process environment take precedence over `.env`.
Explicit image-builder options override their environment defaults.

Most settings are read when a process or stage starts. Editing `.env` does not
reconfigure an existing process. `runner-options.json` is read when the Runner
stage starts, as described below.

Use absolute paths for installations, dependencies and runtime inputs. Quote
values containing spaces. Omit optional variables to use their defaults;
an empty value is not a valid substitute for every option. The plain `docker`
command does not load `.env`: export a variable before using it in a shell command.
Keep the populated `.env` local; it is excluded from Git.

## Setup requirements

Use the installation order in the [README](README.md#getting-started), followed
by [Runner setup](docker/runner-agent/README.md). The host needs Git, uv, GNU tar,
Docker Engine with Compose, and permission to use Docker as the pipeline user.
Use Python 3.12 for the host virtual environment and the Runner. The package
requires Python 3.12 or newer; the supplied image recipes use the 3.12 series
explicitly. See [Python setup and migration](docker/runner-agent/README.md#python-compatibility).

Install `./src[ida]` in that environment. This brings in `ida-domain` and its
`idapro` binding; the licensed IDA installation is a separate prerequisite.
Use **IDA Pro 9.1+ for Linux x86_64**, with idalib and the Hex-Rays decompiler
for the firmware architecture. Set `IDADIR` to that installation. The private
image recipe also expects its `idalib/python/idapro-*.whl` and an initialized
profile with `.hexlic` authorization files and `ida.reg`.

Build the extractor and Runner images locally. The optional host `7z` command
enables an additional extraction fallback; the README builds the two primary
extractors. The private Runner layer is not downloaded from a registry.
For `./fmst open`, install Chrome/Chromium on a desktop host; a headless host
uses the access instructions in its generated delivery README.

## Environment variables

### Model access

The current CLI uses Claude Agent SDK. Configure an Anthropic Messages-compatible
endpoint and a model available through it. The credential is sent as
`Authorization: Bearer ...`. An OpenAI Chat Completions-only endpoint is
insufficient. Supply the provider's base URL, without appending `/v1/messages`;
the SDK adds the request path. These settings also supply the container Runner's
model connection. Its base URL must be reachable from the task container;
`localhost` there refers to the container, not a model server on the host.

| Variable | Default when omitted | Meaning |
|---|---|---|
| `FMST_CLAUDE_BASE_URL` | None; set explicitly | Base URL of your Anthropic Messages-compatible API. |
| `FMST_CLAUDE_AUTH_TOKEN` | None; required | Credential for that endpoint. |
| `FMST_CLAUDE_MODEL` | `deepseek-flash[1m]` | Model used by the Agents. Set this explicitly if your endpoint serves a different model. |
| `FMST_CLAUDE_REASONING_EFFORT` | `high` | Reasoning effort. The installed SDK accepts `low`, `medium`, `high`, `xhigh`, and `max`; the selected model must support the requested value. |
| `FMST_AGENT_CONCURRENCY_LIMIT` | `5` | Positive integer limiting parallel Agent work within a stage. See [concurrency](#concurrency-and-time-budgets). |
| `FMST_PLANNER_MODEL` | The common Agent model | Override the model for planning only. |
| `FMST_PLANNER_REASONING_EFFORT` | The common Agent effort | Override reasoning effort for planning only. |
| `FMST_REHOSTING_GOAL` | Built-in local service objective | Describe the behavior you want to test. This goal is passed through planning, generation and Runner. |

For example, after entering your endpoint and token:

```dotenv
FMST_CLAUDE_MODEL=your-supported-model
FMST_CLAUDE_REASONING_EFFORT=high
FMST_AGENT_CONCURRENCY_LIMIT=5
FMST_REHOSTING_GOAL="Make the original management UI usable for local testing."
```

The default model name is a routing default, not a bundled model service. For
DeepSeek Flash, the adapter maps the requested model through Claude's role
aliases; `deepseek-flash` is normalized to `deepseek-flash[1m]`.

`FMST_CODEX_BASE_URL` and `FMST_CODEX_AUTH_TOKEN` are accepted as older fallback
names if the corresponding `FMST_CLAUDE_*` value is empty. Prefer the Claude
names in new configurations. The CLI does **not** read `FMST_AGENT_PROVIDER`;
setting that name does not switch SDK backends. The separate Codex adapter is
available to Python callers, outside this CLI configuration reference.

`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` are read for model
networking; lowercase equivalents are recognized. With the supplied dependencies,
use an HTTP(S) proxy URL. SOCKS URLs require HTTPX's optional `socksio` dependency,
which the stock Runner requirements do not install. These model proxy settings
do not configure Docker image downloads or native browser traffic.

### IDA and GuestWeave

| Variable | Used by | Meaning |
|---|---|---|
| `IDADIR` | Native analysis and private image construction | Absolute path to your licensed Linux IDA Pro 9.1+ installation with idalib and the required decompiler. |
| `IDAUSR` | Native analysis and private image construction | IDA user-profile search path. The private-image helper accepts multiple directories separated by `:` on Linux; if omitted, it checks `~/.idapro`. The selected profile must contain `ida.reg`; `.hexlic` files may also come from `IDADIR`. |
| `FMST_GUESTWEAVE_WORKSPACE` | Planning, generation and Runner | Absolute path printed by `python src/scripts/prepare_guestweave.py`. Select the GuestWeave project directory, not its parent. |

Pure CLI help and firmware extraction do not need IDA. Analysis needs the
host installation; Runner uses the installation in its private image. Follow
[Runner setup](docker/runner-agent/README.md) to build that image.

Set `FMST_GUESTWEAVE_WORKSPACE` explicitly in a fresh checkout. The older
`src/fmst_iib_runtime` fallback is not shipped as a populated dependency.
The selected GuestWeave and LibAFL sources must match the runtime image;
rebuild the image after changing those sources.

The dependency pin selects a revision-specific directory under `.fmst/dependencies`.
Run the preparation command again after updating the pin and use its newly printed
path. The previous checkout remains intact. ABI 4 runtimes require rebuilt ABI 4
plugins; keep older deliveries with their original image and dependency identities.

### Runner and build environment

| Variable | Default when omitted | Meaning |
|---|---|---|
| `DOCKER_HOST` | Docker CLI selection; image helpers fall back to `unix:///var/run/docker.sock` | Ordinary local engine for extraction and compilation. Export the same endpoint when building images; see [engine setup](docker/runner-agent/README.md#toolchain-and-task-engine). |
| `FMST_RUNNER_BACKEND` | `agent_container` | Use the autonomous container Runner. `legacy` selects the older implementation. |
| `FMST_RUNNER_DOCKER_HOST` | `DOCKER_HOST`, then `unix:///var/run/docker.sock` for task operations | Task-container engine. Use the endpoint printed by `start-engine.py`; the engine must support per-container user namespaces. |
| `FMST_RUNNER_AGENT_IMAGE` | `firmenstein/runner-agent:py312-runtime` | Locally built runtime image in the task engine. The tag is not a public image download. |
| `FMST_RUNNER_RUNTIME_INPUTS` | None | Verified offline-input directory used by `build-runtime-image.py` as its default `--delivery`. Running Agents use the payload already built into their image. |
| `FMST_RUNTIME_BUILDER_IMAGE` | Unset; native host builder | Linux builder image for pipeline compilation/tests. The setup recipe uses `firmenstein/runtime-builder:rust1.98-py312-bookworm`. |
| `FMST_RUNTIME_BUILDER_PLATFORM` | Docker's platform selection | Optional builder platform, such as `linux/amd64`. This is the build host platform, not the firmware architecture. |
| `FMST_RUNTIME_BUILDER_MEMORY` | `6g` | Pipeline Docker compilation-builder memory limit; its swap allowance is set to the same value. |
| `FMST_RUNTIME_BUILDER_CPUS` | `2` | CPU quota for that compilation builder. |
| `FMST_RUNTIME_BUILD_JOBS` | `2` | Cargo parallelism inside that compilation builder. |

The last three settings apply when the pipeline uses a Docker compilation
builder. They do not configure Agent task containers or the standalone image
build helper. Use [Runner resources](#container-resources) for task containers,
and the helper flags below for runtime-image builds.

The README's setup selects `FMST_RUNTIME_BUILDER_IMAGE`. Omit it only when the
host already has GuestWeave's required Rust/LLVM toolchain and native build
dependencies installed; the Python package does not install those host tools.

The runtime-image builder accepts these options:

| Option | Meaning |
|---|---|
| `--output PATH` | Required output directory for build records. |
| `--delivery PATH` | Offline inputs; overrides `FMST_RUNNER_RUNTIME_INPUTS`. |
| `--engine ENDPOINT` | Task engine receiving the image; overrides `FMST_RUNNER_DOCKER_HOST`. Set one explicitly. |
| `--build-engine ENDPOINT` | Build engine; defaults to `DOCKER_HOST` or the system socket. |
| `--base-image IMAGE` | Private base; defaults to `firmenstein/runner-agent:py312-ida-private`. |
| `--tag IMAGE` | Output tag; defaults to `firmenstein/runner-agent:py312-runtime`. |
| `--memory SIZE`, `--cpus N`, `--pids-limit N`, `--jobs N` | Optional build limits. `--memory` also disables swap. These helper options have no fixed resource defaults. |
| `--min-free-gib N` | Optional free-space requirement on the output filesystem. |

See [Runner setup](docker/runner-agent/README.md) for the full build order
and private-image handling.

## Command-line options

Use `python main.py --help` or `python main.py COMMAND --help` for the installed
CLI. Global logging options go **before** the command:

```sh
python main.py --log-level DEBUG analyze \
  --firmware-metadata workspace/demo/metadata.json \
  --target-binary httpd \
  --workdir workspace/demo/runs \
  --run-after-generation
```

### Extract

| Option | Required/default | Meaning |
|---|---|---|
| `--input PATH` | Required | Firmware image. |
| `--output PATH` | `_<image-stem>.rootfs` beside the input | Destination for the extracted filesystem. |
| `--metadata-output PATH` | `<output-directory-name>.metadata.json` beside the output | Metadata consumed by `analyze`. Existing metadata is not overwritten. |

### Analyze

| Option | Required/default | Meaning |
|---|---|---|
| `--firmware-metadata PATH` | Required | Metadata generated by extraction. |
| `--target-binary NAME` | Required | Service inside the firmware, such as `httpd`. |
| `--workdir PATH` | Required; directory must already exist | Parent directory for runs. The CLI creates a firmware-specific child directory. |
| `--run-after-generation` | Off | Start Runner after generation. Without it, the pipeline ends after generation. |
| `--skip-synthesis` | Off | Skip planning, generation and the downstream Runner path. |
| `--resume-analyzer-tasks` | Off | Revalidate and reuse successful Analyzer checkpoints with matching inputs; run missing or failed tasks. |
| `--runner-timeout SECONDS` | `7200` | Positive wall-clock budget for one Runner task. See [time budgets](#concurrency-and-time-budgets). |
| `--runner-max-attempts N` | Unset | Attempt cap for `legacy` only. The default `agent_container` backend rejects this option. |

Cache and output cleanup flags default to off:

| Option | What it removes |
|---|---|
| `--clear-graph-cache` | Graph/semantic cache and dependent C/assembly output. |
| `--clear-decompiler-db-cache` | IDA database cache, graph/semantic cache and dependent C/assembly output. |
| `--clear-decompiled-code` | Generated C and assembly output. |
| `--clear-agent-debug` | Agent debug records. |
| `--clear-logs` | Log files. |
| `--clear-synthesis` | Planning/generation reports and related intervention, test, environment and Runner artifacts. |
| `--clear-all` | The firmware-specific run directory, which is recreated. |

Use a new work directory when you want to keep the existing run's evidence.
`--clear-all` also deletes an existing `runner-options.json` in that directory;
omit this flag when using a prewritten options file.

### Logs and stage checks

`--log-level` accepts `DEBUG`, `INFO`, `WARNING`, `ERROR` and `CRITICAL`; its
default is `INFO`. `--log PATH` selects a log file. Without it, extraction logs
to `full.log`, while analysis and stage checks use the firmware run's
`logs/full.log`.

`test` takes the same three required input options as `analyze`, plus `--stage`
(default: `all`). Run `python main.py test --help` for the stage names.
These pipeline checks may use IDA, model APIs and Docker. The
`intervention-runner` stage starts Runner only when explicitly selected;
it is not included in `--stage all`.

## Runner options

For `agent_container`, place `runner-options.json` in the **firmware-specific
run directory**, not directly in the `--workdir` parent or a reports directory:

```text
workspace/demo/runs/                         # --workdir
└── <image-label>__<first-12-sha256-characters>/
    ├── runner-options.json
    └── diagnostic_reports/
```

The exact directory name comes from `firmware_workdir_name()` in
[metadata.py](src/fmst_basic/FirmProbe/metadata.py). For a SHA-prefixed input
filename, that helper removes the redundant leading hash from the label.
The file is read once when Runner starts and applies to tasks launched from
that firmware run. Unknown fields or invalid values are rejected.

To find and create that directory before starting the pipeline, run this from
the repository root after extraction:

```sh
python - <<'PY'
from pathlib import Path
from fmst_basic.FirmProbe.metadata import firmware_workdir_name, load_firmware_metadata

metadata = load_firmware_metadata(Path("workspace/demo/metadata.json"))
run = Path("workspace/demo/runs") / firmware_workdir_name(
    metadata["image_name"], metadata["sha256"]
)
run.mkdir(parents=True, exist_ok=True)
print(run.resolve() / "runner-options.json")
PY
```

Save one of the following JSON examples at the printed path before running
`analyze --run-after-generation`.

For rehosting without capturing a final delivery image:

```json
{
  "schema_version": 1,
  "delivery_mode": "rehosting_only"
}
```

| Field | Default | Meaning |
|---|---|---|
| `schema_version` | `1` | Supported options version. |
| `delivery_mode` | `full` | `full` collects a post-Goal handoff and captures a delivery package/image. `rehosting_only` retains the service, completion evidence and session without that packaging step. |
| `resources` | Omitted | Optional task-container limits. |

### Container resources

All resource fields are optional. Omitted fields leave the Docker engine's
default in effect. For example:

```json
{
  "schema_version": 1,
  "delivery_mode": "rehosting_only",
  "resources": {
    "memory_bytes": 8589934592,
    "memory_swap_bytes": 8589934592,
    "cpus": 2,
    "pids_limit": 1024,
    "shm_bytes": 268435456
  }
}
```

| Field | Value |
|---|---|
| `memory_bytes` | Positive integer; container memory limit in bytes. |
| `memory_swap_bytes` | Positive integer; total memory plus swap. Requires `memory_bytes` and must be at least that large. Equal values disable swap. |
| `cpus` | Positive number; CPU quota, such as `0.5` or `2`. |
| `pids_limit` | Positive integer; maximum container processes. |
| `shm_bytes` | Positive integer; `/dev/shm` size in bytes for tools such as the browser. |

These are example limits, not presets applied to every run. If the engine does
not support a requested limit, task creation fails rather than ignoring it.

## Concurrency and time budgets

`FMST_AGENT_CONCURRENCY_LIMIT` controls parallel Agent work within a stage,
including independent analysis or generation tasks. It is not a global limit
across firmware processes. Each container Runner uses one native Agent session;
raising this value does not create that many Runner sessions.

To run several firmwares, a caller launches separate pipeline processes and
accounts for their combined model and host usage. Firmware batch concurrency
and host admission policy belong to that launcher.

`--runner-timeout` begins with Runner task preparation and covers its Agent
work, including the completion handoff. It does not limit upstream extraction,
analysis, planning or generation. Those Agents have no total reasoning deadline;
individual tool and API request timeouts still apply. Final archiving and image
capture may continue after the Agent budget, and a completed service remains
running until explicitly stopped.

## Common configuration problems

| Symptom | Check |
|---|---|
| Editing `.env` has no effect | Check exported values and the environment of the launching process; already running stages keep their existing configuration. |
| Missing credential or unsupported model | Fill `FMST_CLAUDE_BASE_URL` and `FMST_CLAUDE_AUTH_TOKEN`, and select a model your endpoint supports. |
| Concurrency value is rejected | Use a positive integer, or omit the variable. An empty assignment is invalid. |
| IDA fails to import or decompile | Check IDA 9.1+, `IDADIR`, the initialized profile, the target architecture's decompiler and the active Python environment. |
| Runner reports a missing image or user-namespace support | Use the dedicated engine from [Runner setup](docker/runner-agent/README.md), and load/build the image in that engine. |
| The namespace helper reports missing `os.setns` or `os.unshare` | An older interpreter/image is still selected. Use the Python 3.12 image chain and update the image settings; see [migration](docker/runner-agent/README.md#python-compatibility). |
| Runtime source identity mismatch | Rebuild the image against the selected GuestWeave/LibAFL sources and offline inputs. |
| `runner-options.json` appears ignored | Check its location under the firmware-specific run directory and ensure it was written before Runner entered. |

Implementation references: [Agent defaults](src/fmst_basic/agent/config.py),
[pipeline configuration](src/fmst_analyzer/global_config.py), [CLI](main.py),
and [Runner option fields](src/fmst_analyzer/runner/task/options.py).
