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


def load_bound_candidate(reports: Path, config):
    """Preflight immutable Generator input without creating a container."""
    from fmst_analyzer.synthesizer.intervention_plan_analyzer import load_persisted_intervention_plan
    from fmst_analyzer.synthesizer.intervention_generator.reports import load_persisted_intervention_generation
    from fmst_analyzer.synthesizer.intervention_generator.publication import validate_generation_publication
    catalog, plan = load_persisted_intervention_plan(reports, global_config=config,
                                                   require_current_implementation=False)
    generation = load_persisted_intervention_generation(reports, plan, require_complete=False)
    return catalog, plan, generation, validate_generation_publication(generation, plan)


def prepare(task: ContainerTask, *, config, view, rootfs: Path, framework: Path,
            service_goal: str | None = None, repair_input=None) -> dict:
    from fmst_analyzer.synthesizer.intervention_skill import CANDIDATE_ENGINEERING
    reports = config.target_diagnostic_reports_dir()
    source_root = rootfs.resolve(strict=True)
    from fmst_analyzer.runner.identity import tree_sha256
    source_root_hash = tree_sha256(source_root)
    repair_record = None
    if repair_input is not None:
        from fmst_analyzer.runner.repair_intake import persist_repair_input
        selected_target = repair_input.validate_source(source_root)
        persist_repair_input(reports, repair_input)
        repair_record = {"input": repair_input.model_dump(mode="json")}
    try:
        catalog, plan, generation, baseline = load_bound_candidate(reports, config)
        candidate_root, baseline_id, arch = baseline.root, baseline.baseline_id, generation.arch
        plan_goal = plan.service_goal
        selected = catalog.launch_candidates.get(plan.launch_choice.recipe_id)
        launch_hint = selected.model_dump(mode="json") if selected else None
        candidate_origin = "generation_publication"
    except (OSError, ValueError, RuntimeError) as error:
        if repair_input is None:
            raise
        from fmst_analyzer.runner.repair_intake import blocks_new_runner
        if blocks_new_runner(error):
            raise
        # The repair input is a separate, explicit contract. Corrupt/incomplete
        # Plan sources remain unusable; no receipt or full Result is fabricated.
        from fmst_analyzer.analysis.base.execution import diagnostic_reason
        from fmst_analyzer.synthesizer.intervention_generator.architecture import detect_generator_arch
        from fmst_analyzer.synthesizer.intervention_generator.repair_candidate import publish_repair_candidate
        arch = detect_generator_arch(selected_target)
        candidate = publish_repair_candidate(task.output / "repair-candidate", config=config,
                                             repair_input=repair_input, arch=arch)
        candidate_root, baseline_id = candidate["root"], candidate["baseline_id"]
        plan_goal, launch_hint, candidate_origin = None, None, "diagnostic_scaffold"
        repair_record.update(candidate_validation_failure=diagnostic_reason(error), candidate=candidate["record"])
    goal = "Make the selected native service usable for local testing, analysis and bug reproduction."
    goal_source = "default"
    for source, value in (("caller", service_goal),
                          ("configuration", getattr(config, "rehosting_goal", None)),
                          ("plan", plan_goal)):
        if value is not None and value.strip():
            goal, goal_source = value.strip(), source
            break
    analysis_env = image_analysis_environment(task)
    rootfs_transfer = transfer_rootfs(task, source_root)
    copy_tree(task.name, candidate_root, "/task/input/candidate")
    from .materials import package_analysis
    materials = package_analysis(task, config=config, view=view, reports=reports,
                                 rootfs=source_root, rootfs_sha256=source_root_hash, candidate=candidate_root)
    copy_tree(task.name, framework, "/task/work/framework/GuestWeave",
              exclude=(".git", "target", "__pycache__"))
    dependency = framework.parent / "lib/LibAFL"
    if dependency.is_dir():
        copy_tree(task.name, dependency, "/task/work/framework/lib/LibAFL",
                  exclude=(".git", "target", "__pycache__"))
    from .runtime_inputs import prepare_runtime
    runtime = prepare_runtime(task, framework, arch)
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
    result = {"target": config.current_target, "arch": arch,
              "delivery_mode": task.delivery_mode,
              "resources": task.resource_limits.model_dump(mode="json") if task.resource_limits else None,
              "source_rootfs": str(source_root), "source_rootfs_sha256": source_root_hash,
              "baseline_id": baseline_id,
              "input_mode": "upstream_repair" if repair_input is not None else "generation",
              "candidate_origin": candidate_origin,
              "upstream_repair": repair_record,
              "goal": goal, "goal_source": goal_source,
              "launch_hint": launch_hint,
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
