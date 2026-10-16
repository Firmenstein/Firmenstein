"""Schema and Controller tests for single-Agent InitLaunch discovery."""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.init_launch.analyzer import InitLaunchAnalyzer
from fmst_analyzer.analysis.init_launch.analyzer_schema import (
    AnalysisGap,
    InitLaunchAnalysisResult,
    LaunchRecipeAgentOutput,
    LaunchRecipeDraft,
    LaunchRecipeAnalysis,
    SourceSnippet,
    TargetIdentity,
)
from fmst_analyzer.analysis.init_launch.controller import finalise_agent_output
from fmst_analyzer.analysis.init_launch.reports import (
    recipe_report_stem,
    render_index,
    render_recipe,
)


def _identity() -> TargetIdentity:
    return TargetIdentity(
        target_basename="httpd",
        selected_rootfs_path="sbin/httpd",
        target_aliases=["usr/sbin/httpd"],
    )


def _rootfs(tmp_path: Path) -> Path:
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin/httpd").write_bytes(b"\x7fELF")
    (rootfs / "usr/sbin").mkdir(parents=True)
    (rootfs / "usr/sbin/httpd").symlink_to("../../sbin/httpd")
    (rootfs / "etc/init.d").mkdir(parents=True)
    (rootfs / "etc/init.d/rcS").write_text(
        "mkdir -p /var/run\n/sbin/httpd -f /etc/httpd.conf\n",
        encoding="utf-8",
    )
    return rootfs


def _analysis(**kwargs):
    kwargs.setdefault("context_anchor", kwargs["launch_site"])
    kwargs.setdefault("applicability", "The supplied initialization entry executes this direct invocation.")
    return LaunchRecipeAnalysis(
        finding={
            "summary": "Initialization contains a source-backed target invocation.",
            "claims": [{"kind": "guarantee", "statement": "The initialization entry attempts the cited target command; readiness is not established.",
                        "evidence_refs": ["/launch_site"], "unknown_kind": None}],
            "reachability_refs": ["/initialization_chain/0"], "coverage_refs": [],
        },
        **kwargs,
    )


def _draft(location: str = "line 2") -> LaunchRecipeDraft:
    launch_site = SourceSnippet(
        path="etc/init.d/rcS",
        location=location,
        text="/sbin/httpd -f /etc/httpd.conf",
    )
    return _analysis(
        launch_site=launch_site,
        executable_path="/sbin/httpd",
        command_template=["/sbin/httpd", "-f", "/etc/httpd.conf"],
        initialization_chain=[launch_site],
        preparation_actions=[SourceSnippet(
            path="etc/init.d/rcS",
            location="line 1",
            text="mkdir -p /var/run",
        )],
    )


def test_schema_two_round_trip(tmp_path: Path) -> None:
    result = finalise_agent_output(
        _rootfs(tmp_path),
        _identity(),
        LaunchRecipeAgentOutput(launch_recipes=[_draft()]),
    )
    loaded = InitLaunchAnalysisResult.model_validate_json(
        result.model_dump_json()
    )
    assert loaded == result
    assert loaded.schema_version == 7


def test_trailing_shell_background_operator_is_not_argv(
    tmp_path: Path,
) -> None:
    rootfs = _rootfs(tmp_path)
    source = rootfs / "etc/init.d/rcS"
    source.write_text(
        "mkdir -p /var/run\n/sbin/httpd -f /etc/httpd.conf &\n",
        encoding="utf-8",
    )
    launch_site = SourceSnippet(
        path="etc/init.d/rcS",
        location="line 2",
        text="/sbin/httpd -f /etc/httpd.conf &",
    )
    draft = _analysis(
        launch_site=launch_site,
        executable_path="/sbin/httpd",
        command_template=["/sbin/httpd", "-f", "/etc/httpd.conf", "&"],
        initialization_chain=[launch_site],
    )

    result = finalise_agent_output(
        rootfs,
        _identity(),
        LaunchRecipeAgentOutput(launch_recipes=[draft]),
    )
    recipe = next(iter(result.launch_recipes.values()))

    assert recipe.launch_site.text.endswith(" &")
    assert recipe.command_template == [
        "/sbin/httpd",
        "-f",
        "/etc/httpd.conf", "&",
    ]


def test_embedded_shell_control_tokens_are_preserved(tmp_path: Path) -> None:
    rootfs = _rootfs(tmp_path)
    draft = _draft().model_copy(update={
        "command_template": [
            "/sbin/httpd",
            "-f",
            "/etc/httpd.conf",
            "|",
            "logger",
        ],
    })

    result = finalise_agent_output(
        rootfs,
        _identity(),
        LaunchRecipeAgentOutput(launch_recipes=[draft]),
    )
    assert next(iter(result.launch_recipes.values())).command_template == draft.command_template


def test_persisted_recipe_preserves_shell_control_token(
    tmp_path: Path,
) -> None:
    result = finalise_agent_output(
        _rootfs(tmp_path),
        _identity(),
        LaunchRecipeAgentOutput(launch_recipes=[_draft()]),
    )
    payload = result.model_dump(mode="json")
    recipe = next(iter(payload["launch_recipes"].values()))
    recipe["command_template"].append("&")

    replayed = InitLaunchAnalysisResult.model_validate(payload)
    assert next(iter(replayed.launch_recipes.values())).command_template == recipe["command_template"]


def test_exact_duplicate_is_deduplicated_and_id_is_stable(tmp_path: Path) -> None:
    rootfs = _rootfs(tmp_path)
    output = LaunchRecipeAgentOutput(launch_recipes=[_draft(), _draft()])
    first = finalise_agent_output(rootfs, _identity(), output)
    second = finalise_agent_output(rootfs, _identity(), output)
    assert len(first.launch_recipes) == 1
    assert first.launch_recipes.keys() == second.launch_recipes.keys()


def test_different_initialization_contexts_survive_independent_of_order(
    tmp_path: Path,
) -> None:
    rootfs = _rootfs(tmp_path)
    rc_dir = rootfs / "etc/rc.d"
    rc_dir.mkdir()
    (rc_dir / "S50httpd").symlink_to("../init.d/rcS")
    direct = _draft()
    longer = direct.model_copy(update={
        "context_anchor": SourceSnippet(
            path="etc/rc.d/S50httpd", location="symlink", text="../init.d/rcS",
        ),
        "applicability": "Invocation through the S50httpd boot entry.",
        "initialization_chain": [SourceSnippet(
            path="etc/rc.d/S50httpd",
            location="symlink",
            text="../init.d/rcS",
        ), direct.launch_site],
    })

    forward = finalise_agent_output(
        rootfs,
        _identity(),
        LaunchRecipeAgentOutput(launch_recipes=[longer, direct]),
    )
    reverse = finalise_agent_output(
        rootfs,
        _identity(),
        LaunchRecipeAgentOutput(launch_recipes=[direct, longer]),
    )

    assert forward == reverse
    assert len(forward.launch_recipes) == 2
    assert {len(recipe.initialization_chain) for recipe in forward.launch_recipes.values()} == {1, 2}


def test_different_launch_sites_are_not_merged(tmp_path: Path) -> None:
    rootfs = _rootfs(tmp_path)
    rc = rootfs / "etc/init.d/rcS"
    rc.write_text(rc.read_text() + "/sbin/httpd -f /etc/httpd.conf\n")
    output = LaunchRecipeAgentOutput(
        launch_recipes=[_draft("line 2"), _draft("line 3")]
    )
    result = finalise_agent_output(rootfs, _identity(), output)
    assert len(result.launch_recipes) == 2


def test_repeated_excerpt_validates_declared_occurrence(tmp_path: Path) -> None:
    rootfs = _rootfs(tmp_path)
    rc = rootfs / "etc/init.d/rcS"
    rc.write_text(rc.read_text() + "/sbin/httpd -f /etc/httpd.conf\n")
    result = finalise_agent_output(
        rootfs,
        _identity(),
        LaunchRecipeAgentOutput(launch_recipes=[_draft("line 3")]),
    )
    assert len(result.launch_recipes) == 1


def test_initialization_chain_must_start_at_known_entry(
    tmp_path: Path,
) -> None:
    rootfs = _rootfs(tmp_path)
    other = rootfs / "etc/other"
    other.write_text("call rcS\n")
    draft = _draft().model_copy(update={
        "initialization_chain": [SourceSnippet(
            path="etc/other",
            location="line 1",
            text="call rcS",
        ), _draft().launch_site],
    })
    finalise_agent_output(
        rootfs,
        _identity(),
        LaunchRecipeAgentOutput(launch_recipes=[draft]),
    )


def test_initialization_chain_must_end_at_launch_site(tmp_path: Path) -> None:
    rootfs = _rootfs(tmp_path)
    draft = _draft().model_copy(update={
        "initialization_chain": [SourceSnippet(
            path="etc/init.d/rcS",
            location="line 1",
            text="mkdir -p /var/run",
        )],
    })
    with pytest.raises(ValueError, match="must end"):
        finalise_agent_output(
            rootfs,
            _identity(),
            LaunchRecipeAgentOutput(launch_recipes=[draft]),
        )


def test_initialization_chain_accepts_verified_rc_symlink(
    tmp_path: Path,
) -> None:
    rootfs = _rootfs(tmp_path)
    rc_dir = rootfs / "etc/rc.d"
    rc_dir.mkdir()
    (rc_dir / "S50httpd").symlink_to("../init.d/rcS")
    draft = _draft().model_copy(update={
        "initialization_chain": [SourceSnippet(
            path="etc/rc.d/S50httpd",
            location="symlink",
            text="../init.d/rcS",
        ), _draft().launch_site],
    })

    result = finalise_agent_output(
        rootfs,
        _identity(),
        LaunchRecipeAgentOutput(launch_recipes=[draft]),
    )
    recipe = next(iter(result.launch_recipes.values()))
    assert recipe.initialization_chain[0].location == "symlink"


@pytest.mark.parametrize("target", ["/tmp/generated.conf", "../tmp/generated.conf"])
def test_dangling_guest_symlink_is_valid_link_evidence_not_file_contents(tmp_path, target):
    rootfs = _rootfs(tmp_path)
    link = rootfs / "etc/generated.conf"
    link.symlink_to(target)
    source = SourceSnippet(path="etc/generated.conf", location="symlink", text=target)
    draft = _draft().model_copy(update={"preparation_actions": [source]})
    result = finalise_agent_output(rootfs, _identity(), LaunchRecipeAgentOutput(launch_recipes=[draft]))
    assert next(iter(result.launch_recipes.values())).preparation_actions == [source]
    # A link's known raw target proves neither existence nor file content.
    with pytest.raises(ValueError, match="symlink source location"):
        finalise_agent_output(rootfs, _identity(), LaunchRecipeAgentOutput(launch_recipes=[
            draft.model_copy(update={"preparation_actions": [source.model_copy(update={
                "location": "line 1", "text": "invented content"})]})]))


def test_source_and_executable_aliases_use_guest_absolute_directory_semantics(tmp_path):
    rootfs = _rootfs(tmp_path)
    (rootfs / "alias").symlink_to("/etc", target_is_directory=True)
    (rootfs / "usr/sbin/httpd").unlink()
    (rootfs / "usr/sbin/httpd").symlink_to("/sbin/httpd")
    source = SourceSnippet(path="alias/init.d/rcS", location="line 1", text="mkdir -p /var/run")
    draft = _draft().model_copy(update={"executable_path": "/usr/sbin/httpd",
                                      "preparation_actions": [source]})
    result = finalise_agent_output(rootfs, _identity(), LaunchRecipeAgentOutput(launch_recipes=[draft]))
    recipe = next(iter(result.launch_recipes.values()))
    assert recipe.executable_path == "/usr/sbin/httpd"
    assert recipe.preparation_actions == [source]


def test_executable_reads_require_a_real_confined_guest_target(tmp_path):

    rootfs = _rootfs(tmp_path)
    alias = rootfs / "usr/sbin/httpd"
    alias.unlink()
    alias.symlink_to("/sbin/httpd")
    outside = tmp_path / "outside"
    outside.write_bytes(b"\x7fELF")
    for target in ("/sbin/missing", "../../../outside", "httpd"):
        alias.unlink()
        alias.symlink_to(target)
        with pytest.raises(ValueError, match="executable is missing or escapes"):
            finalise_agent_output(rootfs, _identity(), LaunchRecipeAgentOutput(
                launch_recipes=[_draft().model_copy(update={
                    "executable_path": "/usr/sbin/httpd"})]))


def test_link_metadata_never_reads_escaped_or_cyclic_parent(tmp_path):
    rootfs = _rootfs(tmp_path)
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside/link").symlink_to("unread")
    (rootfs / "escape").symlink_to("../outside", target_is_directory=True)
    (rootfs / "loop").symlink_to("loop", target_is_directory=True)
    for path in ("escape/link", "loop/link"):
        draft = _draft().model_copy(update={"preparation_actions": [
            SourceSnippet(path=path, location="symlink", text="unread")]})
        with pytest.raises(ValueError, match="missing or escapes"):
            finalise_agent_output(rootfs, _identity(), LaunchRecipeAgentOutput(launch_recipes=[draft]))


def test_alias_is_accepted_but_different_same_basename_is_rejected(
    tmp_path: Path,
) -> None:
    rootfs = _rootfs(tmp_path)
    alias_draft = _draft().model_copy(
        update={"executable_path": "/usr/sbin/httpd"}
    )
    assert finalise_agent_output(
        rootfs,
        _identity(),
        LaunchRecipeAgentOutput(launch_recipes=[alias_draft]),
    ).launch_recipes

    (rootfs / "opt").mkdir()
    (rootfs / "opt/httpd").write_bytes(b"different ELF")
    wrong = _draft().model_copy(update={"executable_path": "/opt/httpd"})
    with pytest.raises(ValueError, match="does not name selected target"):
        finalise_agent_output(
            rootfs,
            _identity(),
            LaunchRecipeAgentOutput(launch_recipes=[wrong]),
        )


def test_source_path_escape_is_rejected(tmp_path: Path) -> None:
    rootfs = _rootfs(tmp_path)
    escaped = SourceSnippet(
        path="../outside", location="line 1", text="x"
    )
    bad = _draft().model_copy(update={
        "launch_site": escaped,
        "initialization_chain": [escaped],
    })
    with pytest.raises(ValueError, match="escapes"):
        finalise_agent_output(
            rootfs,
            _identity(),
            LaunchRecipeAgentOutput(launch_recipes=[bad]),
        )


def test_wrapper_elf_location_uses_section_offset_without_ida(
    tmp_path: Path, elf_wrapper: Path,
) -> None:
    rootfs = _rootfs(tmp_path)
    wrapper = rootfs / "usr/sbin/launcher"
    shutil.copy2(elf_wrapper, wrapper)
    draft = _draft().model_copy(update={
        "launch_site": SourceSnippet(
            path="usr/sbin/launcher",
            location=".text+0x0",
            text="wrapper call to /sbin/httpd",
        ),
        "initialization_chain": [SourceSnippet(
            path="etc/init.d/rcS",
            location="line 2",
            text="/sbin/httpd -f /etc/httpd.conf",
        ), SourceSnippet(
            path="usr/sbin/launcher",
            location=".text+0x0",
            text="wrapper call to /sbin/httpd",
        )],
    })
    # A valid section offset does not substantiate fabricated launcher prose.
    with pytest.raises(ValueError, match="does not match"):
        finalise_agent_output(rootfs, _identity(), LaunchRecipeAgentOutput(launch_recipes=[draft]))
    from fmst_analyzer.analysis.init_launch.controller import _validate_snippet
    exact = SourceSnippet(path="usr/sbin/launcher", location=".text+0x0", text="0x0: ret")
    assert _validate_snippet(rootfs, exact, {}) == exact


def test_invalid_wrapper_elf_offset_is_rejected(tmp_path: Path, elf_wrapper: Path) -> None:
    rootfs = _rootfs(tmp_path)
    wrapper = rootfs / "usr/sbin/launcher"
    shutil.copy2(elf_wrapper, wrapper)
    draft = _draft().model_copy(update={
        "launch_site": SourceSnippet(
            path="usr/sbin/launcher",
            location=".text+0xffffffffff",
            text="wrapper call to /sbin/httpd",
        ),
        "initialization_chain": [SourceSnippet(
            path="etc/init.d/rcS",
            location="line 2",
            text="/sbin/httpd -f /etc/httpd.conf",
        ), SourceSnippet(
            path="usr/sbin/launcher",
            location=".text+0xffffffffff",
            text="wrapper call to /sbin/httpd",
        )],
    })
    with pytest.raises(ValueError, match="section offset"):
        finalise_agent_output(
            rootfs,
            _identity(),
            LaunchRecipeAgentOutput(launch_recipes=[draft]),
        )


def test_repeated_elf_snippets_parse_provider_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, elf_wrapper: Path,
) -> None:
    import lief

    rootfs = _rootfs(tmp_path)
    wrapper = rootfs / "usr/sbin/launcher"
    shutil.copy2(elf_wrapper, wrapper)
    site = SourceSnippet(
        path="usr/sbin/launcher",
        location=".text+0x0",
        text="wrapper call to /sbin/httpd",
    )
    real_parse = lief.parse
    parse_calls = 0

    def _parse(path):
        nonlocal parse_calls
        parse_calls += 1
        return real_parse(path)

    monkeypatch.setattr(lief, "parse", _parse)
    from fmst_analyzer.analysis.init_launch.controller import _validate_snippet
    cache = {}
    exact = site.model_copy(update={"text": "0x0: ret"})
    assert _validate_snippet(rootfs, exact, cache) == exact
    assert _validate_snippet(rootfs, exact, cache) == exact
    assert parse_calls == 1


def test_gap_requires_verifiable_source_when_present(tmp_path: Path) -> None:
    rootfs = _rootfs(tmp_path)
    result = finalise_agent_output(
        rootfs,
        _identity(),
        LaunchRecipeAgentOutput(analysis_gaps=[AnalysisGap(
            source=SourceSnippet(
                path="etc/init.d/rcS",
                location="line 2",
                text="/sbin/httpd -f /etc/httpd.conf",
            ),
            reason="The reference is guarded by an unresolved wrapper call.",
        )]),
    )
    assert len(result.analysis_gaps) == 1


def test_unrelated_text_cannot_be_promoted_to_recipe(tmp_path: Path) -> None:
    rootfs = _rootfs(tmp_path)
    source = rootfs / "etc/init.d/other"
    source.write_text("start unrelated_service\n")
    draft = _draft().model_copy(update={
        "launch_site": SourceSnippet(
            path="etc/init.d/other",
            location="line 1",
            text="start unrelated_service",
        ),
        "initialization_chain": [SourceSnippet(
            path="etc/init.d/rcS",
            location="line 2",
            text="/sbin/httpd -f /etc/httpd.conf",
        ), SourceSnippet(
            path="etc/init.d/other",
            location="line 1",
            text="start unrelated_service",
        )],
        "preparation_actions": [],
    })
    finalise_agent_output(
        rootfs,
        _identity(),
        LaunchRecipeAgentOutput(launch_recipes=[draft]),
    )


def test_empty_agent_output_is_not_a_pseudo_success(tmp_path: Path) -> None:
    finalise_agent_output(
        _rootfs(tmp_path), _identity(), LaunchRecipeAgentOutput()
    )


def test_agent_failure_persists_execution_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    rootfs = _rootfs(tmp_path)
    reports = tmp_path / "reports"
    config = SimpleNamespace(
        fw_rootfs_path=rootfs,
        workdir=tmp_path,
        agent_concurrency_limit=1,
        diagnosis_model="test",
        agent_provider="claude",
        target_diagnostic_reports_dir=lambda: reports,
    )

    async def _fail(*args, **kwargs):
        raise RuntimeError("provider failed")

    monkeypatch.setattr(
        "fmst_analyzer.analysis.init_launch.analyzer.LaunchRecipeAgent.analyze",
        _fail,
    )
    result = asyncio.run(InitLaunchAnalyzer(config).run(rootfs / "sbin/httpd"))
    assert result.execution.status == "failed"
    assert result.launch_recipes == {} and result.planning_findings == {}
    assert result.analysis_gaps == []
    assert "provider failed" in result.execution.model_dump_json()
    path = reports / "init_launch_reports" / "init_launch_analysis_result.json"
    assert not path.exists()
    diagnostic = next(reports.glob(".attempts/init_launch/*/artifacts/reports/init_launch_analysis_result.json"))
    assert InitLaunchAnalysisResult.model_validate_json(diagnostic.read_bytes()) == result


def test_json_markdown_symmetry_and_stale_cleanup(tmp_path: Path) -> None:
    rootfs = _rootfs(tmp_path)
    result = finalise_agent_output(
        rootfs,
        _identity(),
        LaunchRecipeAgentOutput(launch_recipes=[_draft()]),
    )
    reports = tmp_path / "reports"
    config = SimpleNamespace(
        workdir=tmp_path,
        agent_concurrency_limit=1,
        target_diagnostic_reports_dir=lambda: reports,
    )
    out_dir = reports / "init_launch_reports"
    out_dir.mkdir(parents=True)
    (out_dir / "recipe_stale__launch-deadbeef.json").write_text("{}")
    (out_dir / "recipe_stale__launch-deadbeef.md").write_text("stale")
    source_json = result.model_dump_json()
    (out_dir / "init_launch_analysis_result.json").write_text(source_json)

    published = InitLaunchAnalyzer(config).publish_reports(result)

    assert not (out_dir / "recipe_stale__launch-deadbeef.json").exists()
    assert not (out_dir / "recipe_stale__launch-deadbeef.md").exists()
    loaded = InitLaunchAnalysisResult.model_validate_json(
        (out_dir / "init_launch_analysis_result.json").read_text()
    )
    assert loaded == result
    assert published == loaded
    assert published is not result
    assert (
        out_dir / "init_launch_analysis_result.json"
    ).read_text() != source_json
    assert (out_dir / "index.md").read_text() == render_index(result)
    recipe = next(iter(result.launch_recipes.values()))
    stem = recipe_report_stem(recipe)
    index_markdown = (out_dir / "index.md").read_text()
    recipe_markdown = (out_dir / f"{stem}.md").read_text()
    assert recipe_markdown == render_recipe(recipe)
    assert "\n```text\n" not in index_markdown
    assert "\n```text\n" not in recipe_markdown
    assert "\n  ```text\n" in index_markdown
    assert "\n  ```text\n" in recipe_markdown
    assert recipe.model_validate_json(
        (out_dir / f"{stem}.json").read_text()
    ) == recipe


def test_old_schema_is_rejected() -> None:
    with pytest.raises(Exception):
        InitLaunchAnalysisResult.model_validate({
            "schema_version": 1,
            "phase": "full",
            "root_binary": "httpd",
            "target_identity": {
                "target_basename": "httpd",
                "target_rootfs_paths": ["sbin/httpd"],
                "target_aliases": [],
            },
            "launch_recipes": {},
        })


def test_schema_two_recipe_without_initialization_chain_is_rejected() -> None:
    with pytest.raises(Exception):
        InitLaunchAnalysisResult.model_validate({
            "schema_version": 2,
            "target_identity": _identity().model_dump(),
            "launch_recipes": {
                "launch-old": {
                    "recipe_id": "launch-old",
                    "launch_site": _draft().launch_site.model_dump(),
                    "executable_path": "/sbin/httpd",
                    "command_template": ["/sbin/httpd"],
                    "preparation_actions": [],
                },
            },
            "analysis_gaps": [],
        })


def test_schema_three_argv_template_is_rejected() -> None:
    draft = _draft().model_dump()
    draft["argv_template"] = draft.pop("command_template")
    with pytest.raises(Exception):
        InitLaunchAnalysisResult.model_validate({
            "schema_version": 3,
            "target_identity": _identity().model_dump(),
            "launch_recipes": {
                "launch-old": {
                    "recipe_id": "launch-old",
                    **draft,
                },
            },
            "analysis_gaps": [],
        })


def test_full_and_static_launch_stages_are_registered() -> None:
    from fmst_analyzer.testing.stages import STAGE_REGISTRY

    assert "init-launch" in STAGE_REGISTRY
    assert "init-launch-static" in STAGE_REGISTRY


def test_pipeline_cache_is_keyed_by_exact_selected_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester

    rootfs = _rootfs(tmp_path)
    (rootfs / "opt").mkdir()
    (rootfs / "opt/httpd").write_bytes(b"other ELF")
    reports = tmp_path / "reports"
    cache_dir = reports / "init_launch_reports"
    cache_dir.mkdir(parents=True)
    from fmst_analyzer.analysis.init_launch.target_identity import finding_target_for_identity
    stale = InitLaunchAnalysisResult(execution={"tasks": {}},
        schema_version=7, phase="full", initialization_roots=[], planning_findings={},
        finding_target={"path": "opt/httpd", "sha256": "a" * 64},
        target_identity=TargetIdentity(
            target_basename="httpd",
            selected_rootfs_path="opt/httpd",
            target_aliases=[],
        ),
        analysis_gaps=[AnalysisGap(reason="stale target")],
    )
    (cache_dir / "init_launch_analysis_result.json").write_text(
        stale.model_dump_json()
    )
    expected = InitLaunchAnalysisResult(execution={"tasks": {}},
        schema_version=7, phase="full", initialization_roots=[], planning_findings={},
        finding_target=finding_target_for_identity(rootfs, _identity()),
        target_identity=_identity(),
        analysis_gaps=[AnalysisGap(reason="current target")],
    )
    calls = 0

    async def _run(_self, target_path, *, phase):
        nonlocal calls
        calls += 1
        assert target_path == rootfs / "sbin/httpd"
        return expected

    monkeypatch.setattr(
        "fmst_analyzer.analysis.init_launch.InitLaunchAnalyzer.run", _run
    )
    tester = object.__new__(PipelineTester)
    tester._init_launch_result = {}
    tester.target_binary_path = rootfs / "sbin/httpd"
    tester.global_config = SimpleNamespace(
        fw_rootfs_path=rootfs,
        workdir=tmp_path,
        agent_concurrency_limit=1,
        target_diagnostic_reports_dir=lambda: reports,
    )

    actual = asyncio.run(tester.ensure_init_launch_result())

    assert calls == 1
    assert actual == expected
