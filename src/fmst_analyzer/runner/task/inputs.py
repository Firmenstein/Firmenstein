"""Package original candidates and analysis into a private task copy."""
from __future__ import annotations
from pathlib import Path
from .host import ContainerTask, copy_tree, docker
from .common import write_json
from .rootfs_transfer import transfer_rootfs


def image_analysis_environment(task: ContainerTask) -> dict[str, str]:
    """Use the private image's installed IDA; never read host IDA/user files."""
    try:
        docker("exec", "--user", "runner", task.name, "python", "-c",
           "from pathlib import Path;from importlib.metadata import version;"
           "assert Path('/opt/ida/libidalib.so').is_file(), 'Private image lacks IDA';"
           "assert Path('/opt/ida-user/ida.reg').is_file(), 'Private image lacks IDA user configuration';"
           "assert any(Path('/opt/ida-user').glob('*.hexlic')), 'Private image lacks IDA license';"
           "version('idapro')")
    except RuntimeError as error:
        result = getattr(error, 'process_result', None)
        if result is None:
            raise
        # A repairable optional backend must not prevent shell/evidence access.
        record = {'status': 'unavailable', 'returncode': result.returncode,
                  'notice': 'Private image analysis packages/configuration need repair; basic evidence tools remain available.'}
        write_json(task.output / 'image-analysis.json', record)
        task.put_json('/task/evidence/image-analysis.json', record)
    return {"IDADIR": "/opt/ida", "IDAUSR": "/opt/ida-user"}


def prepare(task: ContainerTask, *, config, view, rootfs: Path, framework: Path,
            service_goal: str | None = None) -> dict:
    analysis_env = image_analysis_environment(task)
    from fmst_analyzer.synthesizer.intervention_plan_analyzer import load_persisted_intervention_plan
    from fmst_analyzer.synthesizer.intervention_generator.reports import load_persisted_intervention_generation
    from fmst_analyzer.synthesizer.intervention_generator.publication import validate_generation_publication
    from fmst_analyzer.synthesizer.intervention_skill import CANDIDATE_ENGINEERING
    reports = config.target_diagnostic_reports_dir()
    catalog, plan = load_persisted_intervention_plan(reports, global_config=config,
                                                   require_current_implementation=False)
    goal = "Make the selected native service usable for local testing, analysis and bug reproduction."
    goal_source = "default"
    for source, value in (("caller", service_goal),
                          ("configuration", getattr(config, "rehosting_goal", None)),
                          ("plan", plan.service_goal)):
        if value is not None and value.strip():
            goal, goal_source = value.strip(), source
            break
    generation = load_persisted_intervention_generation(reports, plan, require_complete=False)
    baseline = validate_generation_publication(generation, plan)
    source_root = rootfs.resolve(strict=True)
    from fmst_analyzer.runner.identity import tree_sha256
    source_root_hash = tree_sha256(source_root)
    rootfs_transfer = transfer_rootfs(task, source_root)
    copy_tree(task.name, baseline.root, "/task/input/candidate")
    from .materials import package_analysis
    materials = package_analysis(task, config=config, view=view, reports=reports,
                                 rootfs=source_root, rootfs_sha256=source_root_hash, candidate=baseline.root)
    copy_tree(task.name, framework, "/task/work/framework/GuestWeave",
              exclude=(".git", "target", "__pycache__"))
    dependency = framework.parent / "lib/LibAFL"
    if dependency.is_dir():
        copy_tree(task.name, dependency, "/task/work/framework/lib/LibAFL",
                  exclude=(".git", "target", "__pycache__"))
    from .runtime_inputs import prepare_runtime
    runtime = prepare_runtime(task, framework, generation.arch)
    native_environment = {"LIBAFL_QEMU_DIR": "/task/work/native/qemu",
                          "VHARNESS_DIR": "/task/work/native/libvharness",
                          "RUSTUP_TOOLCHAIN": "1.98.0"}
    copy_tree(task.name, CANDIDATE_ENGINEERING, "/task/input/candidate-engineering.md")
    docker("exec", task.name, "cp", "-a", "/task/input/candidate", "/task/work/candidate")
    docker("exec", task.name, "chown", "-R", "runner:runner", "/task/work/candidate",
           "/task/work/framework", "/task/analysis")
    docker("exec", "--user", "runner", task.name, "python", "-c",
           "from pathlib import Path;from fmst_analyzer.runner.dependencies import bind_guestweave_api;"
           "import json;from fmst_analyzer.runner.task.common import write_json;"
           "r=bind_guestweave_api([Path('/task/work/candidate/intervention'),Path('/task/work/candidate/test_harness')],"
           "Path('/task/work/framework/GuestWeave'));write_json(Path('/task/evidence/dependency-relocation.json'),r)")
    selected = catalog.launch_candidates.get(plan.launch_choice.recipe_id)
    result = {"target": config.current_target, "arch": generation.arch,
              "delivery_mode": task.delivery_mode,
              "resources": task.resource_limits.model_dump(mode="json") if task.resource_limits else None,
              "source_rootfs": str(source_root), "source_rootfs_sha256": source_root_hash,
              "baseline_id": baseline.baseline_id,
              "goal": goal, "goal_source": goal_source,
              "launch_hint": selected.model_dump(mode="json") if selected else None,
              "analysis_environment": analysis_env,
              "analysis_source_rootfs": materials['analysis_source_rootfs'],
              "report_paths": materials['report_paths'],
              "rootfs_transfer": rootfs_transfer,
              "build_environment": native_environment,
              "runtime": runtime,
              "paths": {"rootfs": "/task/work/rootfs", "candidate": "/task/work/candidate",
                        "harness": runtime['harness'],
                        "framework": "/task/work/framework/GuestWeave",
                        "analysis": "/task/analysis", "reports": "/task/input/reports",
                        "materials": "/task/input/materials.json",
                        "candidate_engineering": "/task/input/candidate-engineering.md"}}
    # Store public facts only. IDA credentials belong to the private image;
    # model credentials remain in tmpfs. Neither is copied into task reports.
    write_json(task.output / "inputs.json", result)
    return result
