# Runner setup

Run these commands from the Core repository root with its Python environment
activated. The current Runner image recipe targets Linux x86_64. It runs ARM,
MIPSEL, MIPSBE and x86_64 firmware through GuestWeave.

See the [configuration reference](../../CONFIGURATION.md) for environment
variables, Runner options, and resource settings.

## Python compatibility

Use Python 3.12 for both the host virtual environment and the Runner. The Core
builder copies the official `python:3.12-slim-bookworm` installation into the
Rust/Bookworm image, and the tools image creates `/opt/venv` with `python3.12`.
Build checks verify the interpreter, namespace APIs and the interpreter used
through sudo. OS utilities can still use Debian's `/usr/bin/python3`.

The image chain uses distinct tags:

| Layer | Local image tag |
|---|---|
| Build toolchain | `firmenstein/runtime-builder:rust1.98-py312-bookworm` |
| Runner tools | `firmenstein/runner-agent:py312-tools` |
| Private IDA installation | `firmenstein/runner-agent:py312-ida-private` |
| Runtime and offline inputs | `firmenstein/runner-agent:py312-runtime` |

For an existing checkout, verify `python --version` after activating its venv.
If it is older than 3.12, preserve that environment, create a new 3.12 venv and
install `./src[ida]` there. Build all four image layers below, then update
`FMST_RUNTIME_BUILDER_IMAGE` and `FMST_RUNNER_AGENT_IMAGE` in your existing `.env`.
Keep the other populated settings. Merely retagging an older image does not
upgrade its Python. Existing task containers and delivery packages keep their
recorded image identities; rebuilding this chain does not migrate them.

## Toolchain and task engine

The commands below assume the ordinary build/extraction engine uses the system
socket. If yours has a different local endpoint, substitute it in the export.
Use the same `DOCKER_HOST` when later running the pipeline; for launches from a
different shell, also put it in `.env`. A `DOCKER_CONTEXT` override would take
precedence for plain Docker commands, so clear it for this recipe:

```sh
unset DOCKER_CONTEXT
export DOCKER_HOST=unix:///var/run/docker.sock
```

Prepare the pinned GuestWeave checkout first and put its printed path in `.env`:

```sh
python src/scripts/prepare_guestweave.py
docker build -t firmenstein/runtime-builder:rust1.98-py312-bookworm docker/runtime-builder
```

The Core builder installs the Rust/LLVM toolchain, Python 3.12 and native
prerequisites. It also serves GuestWeave's offline-input preparation below.
Use an ordinary local engine without userns-remap for the builds.
`FMST_RUNNER_DOCKER_HOST` selects the separate task engine; keep `DOCKER_HOST`
pointing to the ordinary engine. The image helpers use explicit `--host`
endpoints, so a Docker CLI context alone does not configure them.

The task engine needs Docker, systemd user services, subordinate UID/GID ranges,
`newuidmap`, `newgidmap`, RootlessKit, `slirp4netns` and `dockerd-rootless.sh`.
Install these tools on PATH or in `.fmst/runner-engine/bin`.

The user needs at least 65,536 subordinate IDs in both `/etc/subuid` and
`/etc/subgid`, a working systemd user session with `XDG_RUNTIME_DIR`, and kernel
support for unprivileged user namespaces. The helper checks prerequisites but
does not install them or allocate host subordinate IDs. Resource limits also
require the corresponding cgroup controllers to be delegated to the user service.

Then run as the ordinary pipeline user:

```sh
python docker/runner-agent/start-engine.py
```

Set the printed `FMST_RUNNER_DOCKER_HOST` in `.env` and export it in the shell
for the following Docker command. For a normal Linux user session it is usually:

```sh
export FMST_RUNNER_DOCKER_HOST="unix://$XDG_RUNTIME_DIR/fmst-runner-engine/docker.sock"
docker --host "$FMST_RUNNER_DOCKER_HOST" info --format '{{json .SecurityOptions}}'
```

Continue only once the command succeeds and reports both `name=rootless` and
`name=userns`. The start helper launches the user service asynchronously; its
printed endpoint alone does not prove readiness. If startup fails, inspect
`journalctl --user -u fmst-runner-engine`.

This dedicated engine combines Rootless Docker with per-container userns-remap;
the helper reuses an existing valid engine without restarting it. It does not
change the system daemon, subordinate-ID files or home permissions. Preserve
its `/var/tmp/fmst-runner-engine-UID` storage while retaining services.

## Tools and private IDA image

Build the tools-only image in your ordinary local Docker engine and stream it
to the task engine:

```sh
docker build -t firmenstein/runner-agent:py312-tools docker/runner-agent
docker save firmenstein/runner-agent:py312-tools \
  | docker --host "$FMST_RUNNER_DOCKER_HOST" load
```

The tools build downloads stable Chrome from Google's Chrome for Testing channel
into the Runner user's browser directory. Its downloader allows slow transfers
and retries failed requests; a connection below 1 KiB/s for 60 seconds times out.

Configure your own `IDADIR` and `IDAUSR` in `.env`. Use Linux x86_64 IDA Pro 9.1+
with idalib and the target architecture's decompiler. The installation must
include `idalib/python/idapro-*.whl`; the profile needs an existing `ida.reg`,
and `.hexlic` files must be in the profile or installation. Build the private
layer on top of the tools image:

```sh
python docker/runner-agent/build-private-image.py \
  --tag firmenstein/runner-agent:py312-ida-private \
  --receipt tmp/runner-private-image/build.json
```

The helper streams only the selected installation and authorization files into
the local build context. It uses the ordinary engine for building and streams
the resulting image to the task engine. `--build-engine` selects the builder;
direct builds on a remapped engine are rejected because they can shift image
ownership. Neither model configuration nor the project directory enters this
private context.

**This image is private.** It contains your IDA installation and license. The
runtime image and captured delivery images inherit that private layer. Keep all
of them local; do not attach them to a public GitHub release or push them to a
public container registry. Other users build their own private layer using
their own authorization. The build helpers perform no registry push.

## Offline inputs and runtime image

Export the same `FMST_GUESTWEAVE_WORKSPACE` path you put in `.env`, then prepare
a new offline-input directory. Preparation may download pinned sources/crates:

```sh
export FMST_GUESTWEAVE_WORKSPACE="$PWD/.fmst/dependencies/guestweave-b5808428000c/GuestWeave"
python "$FMST_GUESTWEAVE_WORKSPACE/tools/offline.py" prepare \
  --builder-image firmenstein/runtime-builder:rust1.98-py312-bookworm \
  --output "$PWD/.fmst/runtime-inputs"
```

The workspace export above uses the preparation script's default checkout.
If you selected another checkout, replace it with the path that script printed.

Set `FMST_RUNNER_RUNTIME_INPUTS` to that absolute directory in `.env`. Existing
offline directories remain intact; choose a new output path for each preparation.
The directory contains a verified `DELIVERY.json`, native source archives and
Cargo vendor sources. See GuestWeave's `docs/build.md` for fully offline
preparation with existing source repositories and a registry cache.

Build the final local Runner image:

```sh
python docker/runner-agent/build-runtime-image.py \
  --delivery "$PWD/.fmst/runtime-inputs" \
  --base-image firmenstein/runner-agent:py312-ida-private \
  --output tmp/runner-dependencies/py312-image
```

The helper verifies the inventory and source pins, installs the native build
libraries, then builds all four harnesses sequentially with network disabled.
Its output directory must not already exist; choose a new path for each build.
The default result is `firmenstein/runner-agent:py312-runtime`; set it as
`FMST_RUNNER_AGENT_IMAGE`. Receipts bind the selected GuestWeave and LibAFL
content identities and harness hashes. Rebuild when those dependencies change.

Resource limits have no fixed local-batch defaults. If desired, pass
`--memory 8g --cpus 2 --jobs 2 --pids-limit 1024` to the runtime builder;
`--memory` also disables swap. Either image helper accepts `--min-free-gib`
for an explicit free-space requirement on its output/receipt filesystem.
Image layers, caches and temporary build files still need sufficient disk space.
GuestWeave input preparation can separately export a builder without IDA;
this is distinct from the private IDA/Runner images.

New intervention lockfiles may need extra vendor versions. Use
`python docker/runner-agent/extend-runtime-delivery.py --delivery INPUT --lock-list LIST.json --output NEW`
to add the exact required registry crates into a new verified delivery. The list
contains absolute paths to consumer Cargo.lock files; existing inputs and locks
are preserved. Set the new input path and rebuild the runtime image afterward.

## Retained tasks

Each result records its engine in `docker-engine.json`; use that endpoint when
managing the task. The native SOCKS endpoint is bound to host loopback. Stop the
individual task rather than its engine, which may host other retained services.

Model configuration is injected into per-task tmpfs through a local relay and
is excluded from images and session backups. The service, native interactions,
traces and private resumable session remain after Runner completion. The standard
delivery package provides its own `fmst` lifecycle commands. In
`rehosting_only` mode, completion retains the service and evidence without
capturing a delivery image.
