import os
import sys
import shutil
from loguru import logger
from pathlib import Path
from typing import Literal, Optional

from fmst_basic.agent import (
    default_concurrency_for_provider,
)
from fmst_basic.agent.config import (
    DEFAULT_AGENT_PROVIDER,
    configured_claude_model,
    configured_codex_model,
)

class GlobalConfig:

    # Libraries treated as "well-known default" (standard C, crypto, etc.)
    # Their internal functions are NOT analyzed — only their exported prototypes are used.
    DEFAULT_LIB = [
        # Basic C library
        "libc.so", "libc-", "ld-",
        "libm.so", "libm-", "libpthread.so", "libpthread-",
        "libdl.so", "libdl-", "librt.so", "librt-",
        "libresolv.so", "libresolv-", "libnsl.so", "libnsl-",
        "libutil.so", "libutil-", "libanl.so", "libanl-",
        "libgcc_s.so", "libstdc++.so", "libcrt.so", "libatomic.so",
        "libffi.so",

        # cryptography and security
        "libcrypt.so", "libcrypt-", "libcrypto.so", "libssl.so",
        "libcap.so", "libseccomp.so",
        "libgnutls.so", "libgcrypt.so", "libgpg-error.so",
        "libmbedtls.so", "libmbedcrypto.so", "libmbedx509.so",
        "libwolfssl.so",

        # event loop
        "libevent.so", "libevent_core.so", "libevent_extra.so",
        "libev.so", "libuv.so",

        # Netlink / Netfilter
        "libmnl.so", "libnfnetlink.so",
        "libnftnl.so", "libnetfilter_queue.so",
        "libnetfilter_conntrack.so",
        "libxtables.so", "libipset.so",

        # data serialization and database
        "libprotobuf.so", "libprotobuf-c.so",
        "libsqlite3.so",

        # common supplements
        "libz.so", "liblzma.so", "libbz2.so",
        "libzstd.so", "liblz4.so", "liblzo2.so", "libarchive.so",
        "libuuid.so", "libpcre.so", "libpcre2.so",
        "libjson-c.so", "libjansson.so", "libyajl.so",
        "libxml2.so", "libexpat.so",

        # networking
        "libcurl.so", "libpcap.so",
        "libcares.so", "libnghttp2.so",
        "libidn2.so", "libpsl.so", "libssh2.so",
        "libnl-3.so", "libnl-genl-3.so", "libnl-route-3.so",

        # logging and control
        "liblog.so", "libsystemd.so",
    ]

    def __init__(self):
        # The provider and its model are explicit, repository-defined defaults.
        self.agent_provider = DEFAULT_AGENT_PROVIDER
        self.resume_analyzer_tasks = False
        default_agent_model = (
            configured_codex_model()
            if self.agent_provider == "codex"
            else configured_claude_model()
        )
        self.diagnosis_model = default_agent_model
        self.synthesizer_model = default_agent_model
        # Planner experiments must not silently change Analyzer provenance or
        # the Generator/Runner model in the same process.
        self.planner_model = os.getenv("FMST_PLANNER_MODEL", "").strip() or default_agent_model
        self.planner_reasoning_effort = os.getenv("FMST_PLANNER_REASONING_EFFORT", "").strip() or None
        self.rehosting_goal = os.getenv("FMST_REHOSTING_GOAL", "").strip() or None
        
        # Working directories
        self.workdir = None
        self.graph_dots_dir = None
        self.graph_cache_dir = None
        self.binary_cache_dir = None
        self.decompiler_db_dir = None
        self.decompiled_code_dir = None
        self.disassembled_code_dir = None
        self.agent_debug_dir = None
        self.log_dir = None

        # Log
        self.log_path = None
        self.log_level = None

        # Max parallel LLM requests per analyzer; local development may override it.
        concurrency = os.getenv("FMST_AGENT_CONCURRENCY_LIMIT")
        try:
            self.agent_concurrency_limit = (
                default_concurrency_for_provider(self.agent_provider)
                if concurrency is None else int(concurrency)
            )
        except ValueError:
            raise ValueError("FMST_AGENT_CONCURRENCY_LIMIT must be a positive integer") from None
        if self.agent_concurrency_limit < 1:
            raise ValueError("FMST_AGENT_CONCURRENCY_LIMIT must be a positive integer")

        # On macOS, Linux-only LibAFL-QEMU builds are delegated to a Docker
        # builder. The runtime containers still use the same Docker daemon;
        # this setting selects only the build/test backend.
        self.runtime_builder_image = os.getenv("FMST_RUNTIME_BUILDER_IMAGE")
        self.runtime_builder_platform = os.getenv("FMST_RUNTIME_BUILDER_PLATFORM")
        self.runner_backend = os.getenv("FMST_RUNNER_BACKEND", "agent_container")
        if self.runner_backend not in {"agent_container", "legacy"}:
            raise ValueError("FMST_RUNNER_BACKEND must be agent_container or legacy")
        self.runtime_workspace = Path(os.getenv("FMST_GUESTWEAVE_WORKSPACE") or
            Path(__file__).resolve().parents[1] / "fmst_iib_runtime").expanduser().resolve()

        # Worklist-scoped: the basename of the binary currently being
        # analyzed. Set by FirmAnalyzer for the selected target, and by
        # PipelineTester on construction (test subcommand is single-target).
        # Output paths that must not collide across targets (diagnostic
        # reports, agent traces) are scoped under this via the helpers
        # below.
        self.current_target: Optional[str] = None

        # Absolute path to the firmware's extracted rootfs. Set by
        # FirmAnalyzer / PipelineTester at init. FileResolver uses this
        # for in-rootfs existence checks during Node 4 classification.
        self.fw_rootfs_path: Optional[Path] = None

        # FileResolver: which resource classes trigger the Node 5/6
        # resource-analysis agent. Three monotonically-increasing tiers:
        #   "pseudo_fs_only": only PSEUDO_FS_* (/dev /proc /sys) creating
        #     callsites go through the agent; MISSING_NON_PSEUDO_FS stays
        #     shallow. Cheapest tier.
        #   "with_allowlist" (default): pseudo_fs + MISSING_NON_PSEUDO_FS
        #     callsites whose path extension matches
        #     ``file_resolver_normal_fs_ext_allowlist``. Selects on file
        #     type (e.g. .pid / .conf / .crt) instead of directory prefix
        #     so /var/run/wlanconfigd.pid AND /tmp/openvpnd.pid both
        #     enter, while /tmp/cache_state.txt does not.
        #   "full": all MISSING_NON_PSEUDO_FS creating callsites run the
        #     agent regardless of extension. Useful when Env-Intervention
        #     synthesizer needs the full picture including /tmp/
        #     transient state and unnamed files.
        self.file_resolver_scope: Literal[
            "pseudo_fs_only", "with_allowlist", "full",
        ] = "with_allowlist"

        # FileResolver: scope="with_allowlist" admits a MISSING_NON_PSEUDO_FS
        # callsite iff its path's extension (basename's last '.' suffix,
        # lowercased) is in this set. Has no effect at scope="pseudo_fs_only"
        # (always skipped) or scope="full" (always admitted).
        #
        # Design intent: file-type semantics are a stronger "is this
        # synthesis-relevant?" signal than directory prefixes. Daemon state
        # / config / TLS material have recognizable extensions regardless
        # of where they're written; ad-hoc /tmp scratch files do not.
        # rootfs survey on a real Netgear firmware confirmed prefix-based
        # gating mostly added long-tail noise (.so / .sh / version files
        # under /opt /etc /mnt) without catching anything an extension
        # filter wouldn't.
        self.file_resolver_normal_fs_ext_allowlist: set[str] = {
            ".pid", ".lock", ".leases",                          # state / control
            ".conf", ".cfg", ".ini", ".toml", ".yaml", ".yml",   # config
            ".crt", ".key", ".pem", ".p12", ".pfx", ".cer",      # TLS / auth
        }

        # FileResolver: chunk size gate for FileResourceAnalysisAgent.
        # Resources with this many open callsites or fewer run as a single
        # agent call that fills the whole FileResourceReport. Larger
        # resources split into map (per-chunk CallSiteReport workers) +
        # reduce (top-level synthesis) stages to keep each LLM context
        # focused — per-callsite fd tracing is non-trivial, so the
        # threshold is conservative.
        self.file_resolver_resource_chunk_size: int = 10

    @staticmethod
    def _remove_dir_if_exists(path: Path, description: str):
        if path.exists():
            logger.info(f"Clearing {description}: {path}")
            shutil.rmtree(path)
        else:
            logger.info(f"Skip clearing {description}, directory does not exist: {path}")

    def setup_workdir(self, workdir: Path,
                                 clear_graph_cache: bool = False,
                                 clear_decompiler_db_cache: bool = False,
                                 clear_decompiled_code: bool = False,
                                 clear_agent_debug: bool = False,
                                 clear_logs: bool = False,
                                 clear_all: bool = False,
                                 clear_synthesis: bool = False):
        self.workdir = workdir
        self.graph_cache_dir = self.workdir / "graph_cache"
        self.binary_cache_dir = self.workdir / "graph_cache" / "binary_cache"
        self.graph_dots_dir = self.workdir / "graph_dots"
        self.decompiler_db_dir = self.workdir / "decompiler_db"
        self.agent_debug_dir = self.workdir / "agent_debug"
        self.log_dir = self.workdir / "logs"
        self.decompiled_code_dir = self.workdir / "decompiled_code"
        self.disassembled_code_dir = self.workdir / "disassembled_code"
        # Derived-artifact dependency chain:
        # IDB -> graph/semantic snapshots -> C/S. Clearing an
        # upstream cache must invalidate everything downstream, otherwise a
        # fresh IDB/CallGraph can be paired with stale C/S data.
        effective_clear_graph = clear_graph_cache or clear_decompiler_db_cache
        effective_clear_code = clear_decompiled_code or effective_clear_graph

        if clear_all or effective_clear_graph:
            # Disk removal must not leave process-global IDALib objects
            # pointing at deleted databases or carrying a stale CallGraph.
            from .nodes.decompiler.ida.ida_binary import IDABinary
            IDABinary.clear_cache()

        if clear_all:
            self._remove_dir_if_exists(self.workdir, "entire workdir")
            self.workdir.mkdir(parents=True, exist_ok=True)
        else:
            if effective_clear_graph:
                self._remove_dir_if_exists(self.graph_cache_dir, "graph cache")
            if clear_decompiler_db_cache:
                self._remove_dir_if_exists(self.decompiler_db_dir, "decompiler database cache")
            if effective_clear_code:
                self._remove_dir_if_exists(self.decompiled_code_dir, "decompiled code cache")
                self._remove_dir_if_exists(
                    self.disassembled_code_dir,
                    "disassembled code cache",
                )
            if clear_agent_debug:
                self._remove_dir_if_exists(self.agent_debug_dir, "agent debug")
            if clear_logs:
                self._remove_dir_if_exists(self.log_dir, "logs")

        # Clear synthesizer outputs. Split from the other clear_* blocks
        # because clear_synthesis is orthogonal to clear_all (clear_all
        # already nukes workdir wholesale), but the per-target
        # synthesis-report scrub only runs without clear_all
        # branch so diagnostic_reports/<target>/ survives for replay.
        if clear_synthesis or clear_all:
            for sub in (
                self.workdir / "interventions",
                self.workdir / "test_harnesses",
                self.workdir / "env_scripts",
                self.workdir / "intervention_baselines",
                self.workdir / "runner_sessions",
                self.workdir / "runner_workspaces",
            ):
                if sub.exists():
                    self._remove_dir_if_exists(sub, sub.name)
            if clear_synthesis and not clear_all:
                diag_root = self.workdir / "diagnostic_reports"
                if diag_root.exists():
                    for sub in diag_root.iterdir():
                        if sub.is_dir():
                            for report_name in (
                                "intervention_plan_reports",
                                "intervention_generation_reports",
                                "runner_reports",
                                "intervention_planner_inputs",
                            ):
                                report_dir = sub / report_name
                                if report_dir.exists():
                                    self._remove_dir_if_exists(
                                        report_dir,
                                        f"{report_name} for {sub.name}",
                                    )

        self.graph_cache_dir.mkdir(parents=True, exist_ok=True)
        self.binary_cache_dir.mkdir(parents=True, exist_ok=True)
        self.graph_dots_dir.mkdir(parents=True, exist_ok=True)
        self.decompiler_db_dir.mkdir(parents=True, exist_ok=True)
        self.agent_debug_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.decompiled_code_dir.mkdir(parents=True, exist_ok=True)
        self.disassembled_code_dir.mkdir(parents=True, exist_ok=True)

    def target_diagnostic_reports_dir(self) -> Path:
        """Return <workdir>/diagnostic_reports/<current_target>/, creating
        it on demand. Raises if current_target / workdir unset — callers
        are expected to scope output to a concrete target."""
        assert self.current_target and self.workdir, (
            "target_diagnostic_reports_dir requires both current_target and "
            "workdir to be set"
        )
        d = self.workdir / "diagnostic_reports" / self.current_target
        d.mkdir(parents=True, exist_ok=True)
        return d

    def target_agent_debug_dir(self) -> Path:
        """Return <workdir>/agent_debug/<current_target>/, creating it on
        demand. Same contract as target_diagnostic_reports_dir."""
        assert self.current_target and self.workdir, (
            "target_agent_debug_dir requires both current_target and "
            "workdir to be set"
        )
        d = self.workdir / "agent_debug" / self.current_target
        d.mkdir(parents=True, exist_ok=True)
        return d

    def setup_logger(self, log_path: str, log_level: str):
        log_path = Path(log_path).absolute().resolve()
        self.log_path = log_path
        self.log_level = log_level

        # remove existing log files
        if self.log_path.exists():
            try:
                self.log_path.unlink()
            except Exception as e:
                print(f"Failed to remove old log file {self.log_path}: {e}")
                
        # also remove `file.xxxx.log` files if exist
        for f in self.log_path.parent.glob(f"{self.log_path.stem}.*{self.log_path.suffix}"):
            try:
                f.unlink()
            except Exception as e:
                print(f"Failed to remove old log file {f}: {e}")

        logger.remove()
        logger.add(self.log_path, level=self.log_level,
                format="[{time:YYYY-MM-DD HH:mm:ss} - {level} - {file.path}:{line}]\n\t{message}")
        logger.add(sys.stderr, level=self.log_level, colorize=True,
                format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{file.path}:{line}</cyan>\n\t{message}")
