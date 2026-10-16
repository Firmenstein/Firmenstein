from loguru import logger
import argparse
import pathlib
import sys
import asyncio
import faulthandler
import signal
import dotenv

# Load .env before importing fmst_analyzer, which checks IDADIR at import time
dotenv.load_dotenv()

# Enable faulthandler stack dump on SIGUSR1 — when a stage hangs,
# ``kill -USR1 <pid>`` dumps every thread's Python stack to stderr so
# we can see exactly where the deadlock / HTTP wait / tool loop is
# sitting. Cheap, zero impact at runtime.
faulthandler.enable()
faulthandler.register(signal.SIGUSR1, all_threads=True, chain=False)

from fmst_basic.FirmProbe import FirmProbe
from fmst_basic.FirmProbe.metadata import firmware_workdir_name, load_firmware_metadata
from fmst_analyzer.FirmAnalyzer import FirmAnalyzer
from fmst_analyzer.global_config import GlobalConfig
from fmst_analyzer.testing.stages import STAGE_ORDER, STAGE_REGISTRY

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Firmenstein CLI Tools")
    subparsers = parser.add_subparsers(dest="action", required=True, help="Operation to perform")

    # extract operation
    extract_parser = subparsers.add_parser("extract", help="Extract firmware")
    extract_parser.add_argument("--input", required=True, type=pathlib.Path, help="Firmware image's file path")
    extract_parser.add_argument("--output", required=False, type=pathlib.Path, help="Extracted rootfs's output directory")
    extract_parser.add_argument("--metadata-output", required=False, type=pathlib.Path,
                                help="Firmware metadata JSON path")

    # analyze operation
    analyze_parser = subparsers.add_parser("analyze", help="Analyze rootfs")
    analyze_parser.add_argument("--firmware-metadata", required=True, type=pathlib.Path,
                                help="FirmProbe metadata.json path")
    analyze_parser.add_argument("--target-binary", required=True, type=str, help="Target binary inside the rootfs")
    analyze_parser.add_argument("--workdir", required=True, type=pathlib.Path, help="Working directory Firmenstein")
    analyze_parser.add_argument("--clear-graph-cache", action="store_true", help="Clear graph/semantic cache and dependent C/S artifacts")
    analyze_parser.add_argument("--clear-decompiler-db-cache", action="store_true", help="Clear IDB and all dependent graph/semantic/C/S artifacts")
    analyze_parser.add_argument("--clear-decompiled-code", action="store_true", help="Clear generated C/S artifacts")
    analyze_parser.add_argument("--clear-agent-debug", action="store_true", help="Clear agent debug traces and outputs")
    analyze_parser.add_argument("--clear-logs", action="store_true", help="Clear log files")
    analyze_parser.add_argument("--clear-all", action="store_true", help="Clear entire workdir and recreate")
    analyze_parser.add_argument("--clear-synthesis", action="store_true",
                                help="Clear intervention plan, generation, Rust, test, and environment artifacts")
    analyze_parser.add_argument("--skip-synthesis", action="store_true",
                                help="Skip intervention planning and generation")
    analyze_parser.add_argument("--resume-analyzer-tasks", action="store_true",
                                help="Revalidate and reuse successful exact-input Analyzer task checkpoints; rerun missing/failed tasks")
    analyze_parser.add_argument("--run-after-generation", action="store_true",
                                help="Run the generated plan in a disposable Docker/IIB refinement loop")
    analyze_parser.add_argument("--runner-max-attempts", type=int, default=None,
                                help="Optional explicit attempt cap; default retries within the session budget")
    analyze_parser.add_argument("--runner-timeout", type=float, default=7200.0,
                                help="Total per-target Runner session wall-clock seconds, including cleanup")

    # test operation
    test_parser = subparsers.add_parser("test", help="Run pipeline smoke tests")
    test_parser.add_argument("--firmware-metadata", required=True, type=pathlib.Path,
                             help="FirmProbe metadata.json path")
    test_parser.add_argument("--target-binary", required=True, type=str, help="Target binary inside the rootfs")
    test_parser.add_argument("--workdir", required=True, type=pathlib.Path, help="Working directory Firmenstein")
    test_parser.add_argument(
        "--stage",
        default="all",
        choices=["all"] + list(STAGE_REGISTRY),
        help="Which test stage to run",
    )
    test_parser.add_argument("--clear-graph-cache", action="store_true", help="Clear graph/semantic cache and dependent C/S artifacts")
    test_parser.add_argument("--clear-decompiler-db-cache", action="store_true", help="Clear IDB and all dependent graph/semantic/C/S artifacts")
    test_parser.add_argument("--clear-decompiled-code", action="store_true", help="Clear generated C/S artifacts")
    test_parser.add_argument("--clear-agent-debug", action="store_true", help="Clear agent debug traces")
    test_parser.add_argument("--clear-logs", action="store_true", help="Clear log files")
    test_parser.add_argument("--clear-all", action="store_true", help="Clear entire workdir and recreate")
    test_parser.add_argument("--resume-analyzer-tasks", action="store_true",
                             help="Recover successful exact-input Analyzer tasks")

    # General log parameters
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Log level")
    parser.add_argument("--log", default=None, type=str, help="Log output file path (default: <workdir>/logs/full.log)")

    return parser.parse_args()

async def run_analyze(args: argparse.Namespace, global_config: GlobalConfig):
    """Thin CLI wrapper around FirmAnalyzer. Handles workdir + logger
    setup (CLI-level concerns), then delegates all firmware-level
    orchestration (metadata loading, graph build, CTree onboarding, worklist
    loop) to FirmAnalyzer."""
    global_config.resume_analyzer_tasks = args.resume_analyzer_tasks
    workdir = pathlib.Path(args.workdir).absolute().resolve()
    if not workdir.is_dir() or not workdir.exists():
        raise ValueError(f"Workdir {args.workdir} is not a valid directory.")

    fw_metadata = load_firmware_metadata(args.firmware_metadata)
    image_name = firmware_workdir_name(
        fw_metadata["image_name"], fw_metadata["sha256"],
    )

    # make sub-workdir for current image
    workdir = workdir / image_name
    workdir.mkdir(parents=True, exist_ok=True)

    global_config.setup_workdir(
        workdir,
        clear_graph_cache=args.clear_graph_cache,
        clear_decompiler_db_cache=args.clear_decompiler_db_cache,
        clear_decompiled_code=args.clear_decompiled_code,
        clear_agent_debug=args.clear_agent_debug,
        clear_logs=args.clear_logs,
        clear_all=args.clear_all,
        clear_synthesis=args.clear_synthesis,
    )

    # Setup logger after workdir so full.log lands in logs/
    log_path = args.log if args.log else str(global_config.log_dir / "full.log")
    global_config.setup_logger(log_path, args.log_level)

    analyzer = FirmAnalyzer(
        firmware_metadata=fw_metadata,
        target_binary=args.target_binary,
        global_config=global_config,
        skip_synthesis=args.skip_synthesis,
        run_after_generation=args.run_after_generation,
        runner_max_attempts=args.runner_max_attempts,
        runner_timeout_seconds=args.runner_timeout,
    )
    await analyzer.run()

async def run_test(args: argparse.Namespace, global_config: GlobalConfig):
    """Run pipeline smoke tests."""
    from fmst_analyzer.testing import PipelineTester
    global_config.resume_analyzer_tasks = args.resume_analyzer_tasks

    workdir = pathlib.Path(args.workdir).absolute().resolve()
    if not workdir.is_dir() or not workdir.exists():
        raise ValueError(f"Workdir {args.workdir} is not a valid directory.")

    fw_metadata = load_firmware_metadata(args.firmware_metadata)
    image_name = firmware_workdir_name(
        fw_metadata["image_name"], fw_metadata["sha256"],
    )
    workdir = workdir / image_name
    workdir.mkdir(parents=True, exist_ok=True)

    global_config.setup_workdir(
        workdir,
        clear_graph_cache=args.clear_graph_cache,
        clear_decompiler_db_cache=args.clear_decompiler_db_cache,
        clear_decompiled_code=args.clear_decompiled_code,
        clear_agent_debug=args.clear_agent_debug,
        clear_logs=args.clear_logs,
        clear_all=args.clear_all,
    )

    # Setup logger after workdir so full.log lands in logs/
    log_path = args.log if args.log else str(global_config.log_dir / "full.log")
    global_config.setup_logger(log_path, args.log_level)

    tester = PipelineTester(
        fw_metadata, args.target_binary, global_config,
        clear_graph_cache=args.clear_graph_cache,
    )

    stages = ["all"] if args.stage == "all" else [args.stage]
    results = await tester.run(stages)

    # Exit with non-zero if any stage failed
    if not all(passed for passed, _ in results.values()):
        sys.exit(1)


def main():
    try:
        args = parse_arguments()

        global_config = GlobalConfig()

        # For extract, setup logger immediately (no workdir involved)
        if args.action == "extract":
            log_path = args.log if args.log else "full.log"
            global_config.setup_logger(log_path, args.log_level)

        logger.info(f"Starting Firmenstein with action: {args.action}")

        if args.action == "extract":
            image_path = pathlib.Path(args.input).absolute().resolve()
            if not image_path.is_file():
                raise ValueError(f"Input path {args.input} is not a file.")

            target_rootfs_path = None
            metadata_path = None
            if args.output:
                target_rootfs_path = pathlib.Path(args.output).absolute().resolve()
            else:
                # For example:
                # image path : ../netgear_fw/R6700v3/1.0.4.120_10.0.91/R6700v3-V1.0.4.120_10.0.91.zip
                # default rootfs path: ../netgear_fw/R6700v3/1.0.4.120_10.0.91/rootfs_R6700v3-V1.0.4.120_10.0.91
                target_rootfs_path = image_path.parent / f"_{image_path.stem}.rootfs"
            if args.metadata_output:
                metadata_path = pathlib.Path(args.metadata_output).absolute().resolve()

            logger.info(f"Extracting firmware {args.input}, rootfs will be moved to {target_rootfs_path}")
            extracted_rootfs = FirmProbe.run_extract(
                image_path,
                target_rootfs_path,
                metadata_path,
            )
            logger.success(f"Firmware rootfs extracted to {extracted_rootfs}")

        elif args.action == "analyze":
            asyncio.run(run_analyze(args, global_config))

        elif args.action == "test":
            asyncio.run(run_test(args, global_config))

    except Exception as e:
        logger.exception(f"Error occurred: {e}")
        sys.exit(1)
    finally:
        # Release an initialized backend even on SystemExit, but do not load
        # optional IDA bindings just to exit help or an extraction command.
        try:
            backend = sys.modules.get("fmst_analyzer.nodes.decompiler.ida.idb_manager")
            if backend is not None:
                backend.IDBManager.close_current_idb()
        except Exception as close_error:
            logger.error(f"Failed to close the current IDA database: {close_error}")

if __name__ == "__main__":
    main()
