"""Regression for FileResolver schema refactor (2026-04-20).

Covers three coordinated schema changes:

- UsageReport.operation (FileOperation enum) -> api_name (str):
  * api_name preserved verbatim (pread != read, fread != read)
  * post_use_constraint defaults to None; accepts free-form string

- FileResourceReport.observed_operations (agent-filled) -> observed_apis
  (computed_field): sorted, deduped from usage_reports[*].api_name;
  cannot be set at construction.

- FileResolverResult.covered_api_calls (new computed_field):
  Source A (self.callsites) + Source B (resource_reports[*]
  .callsite_reports[*].usage_reports[*]) merged and deduped by
  (binary, function, api_name, line_number). Skipped callsites are
  excluded.

Usage:
    source src/.venv/bin/activate
    python -m unittest tests.test_file_resolver_schema_refactor -v
"""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fmst_analyzer.analysis.base.coverage import CoveredAPICall
from fmst_analyzer.analysis.base.coverage_flow import CoverageFlow
from fmst_analyzer.analysis.file_resolver.analyzer_schema import (
    CallSiteReport,
    FileCallsite,
    FileResolverResult,
    FileResource,
    FileResourceClass,
    FileResourceReport,
    UsageReport,
)
from fmst_analyzer.analysis.file_resolver.resource_analysis_agent import (
    _validate_report_positions,
)


def _make_usage(
    api: str,
    line: int,
    function_name: str = "main",
    details: str = "reads 4 bytes",
    post_use_constraint=None,
) -> UsageReport:
    return UsageReport(
        binary_name="httpd",
        function_name=function_name,
        line_number=line,
        api_name=api,
        details=details,
        post_use_constraint=post_use_constraint,
    )


def _make_callsite(
    binary: str,
    function_name: str,
    line: int,
    api: str,
    path: str = "/dev/foo",
    resource_class: FileResourceClass = FileResourceClass.PSEUDO_FS_DEV,
) -> FileCallsite:
    cid = f"{binary}::{function_name}::L{line}::{api}"
    return FileCallsite(
        callsite_id=cid,
        candidate_idx=0,
        profile_key=f"{cid}#0",
        binary_name=binary,
        function_name=function_name,
        line_number=line,
        api_name=api,
        path_arg_index=0,
        requested_path=path,
        path_value=path,
        path_kind="concrete",
        resolution_source="literal_static",
        resource_class=resource_class,
    )


def _resource(site, report):
    site.resource_group_id = report.resource_group_id
    return FileResource(
        resource_group_id=report.resource_group_id, path_value=site.path_value,
        path_kind=site.path_kind, resource_class=site.resource_class, callsites=[site],
    )


def _make_result(**fields):
    """Current complete test Result; never adapt legacy production records."""
    from fmst_analyzer.analysis.base.finding_binding import FindingSemantics, FindingTarget
    from fmst_analyzer.analysis.file_resolver.findings import FileResourceAnalysis, build_findings
    target = FindingTarget(path="usr/sbin/" + fields["root_binary"], sha256="a" * 64)
    reports = fields.get("resource_reports", {})
    from fmst_analyzer.analysis.base.execution import AnalysisExecution
    execution = AnalysisExecution.model_validate(fields.pop("execution", {"tasks": {}}))
    fields.setdefault("phase", "full" if reports or execution.status != "complete" else "static")
    analyses = {key: FileResourceAnalysis(report, FindingSemantics(
        summary="Coverage fixture; semantic behavior is unassessed.",
        claims=[dict(kind="unknown", statement="Synthetic coverage data only.",
                     unknown_kind="semantics", evidence_refs=[])],
        reachability_refs=[], coverage_refs=[],
    )) for key, report in reports.items()}
    return FileResolverResult(execution=execution,
        schema_version=12, finding_target=target,
        planning_findings=build_findings(target, fields.get("resources", {}), analyses, failed_resources=execution.unsuccessful_subjects("resource")),
        **fields,
    )


class UsageReportSchemaTests(unittest.TestCase):

    def test_api_name_verbatim_no_normalization(self):
        """pread, read, fread, readv are four distinct api_name values."""
        apis = ("read", "pread", "fread", "readv")
        for api in apis:
            ur = _make_usage(api=api, line=10)
            self.assertEqual(ur.api_name, api)

    def test_post_use_constraint_defaults_none(self):
        ur = _make_usage(api="ioctl", line=42)
        self.assertIsNone(ur.post_use_constraint)

    def test_post_use_constraint_accepts_string(self):
        text = "ioctl retval != 0 -> exit(1) at L125"
        ur = _make_usage(api="ioctl", line=42, post_use_constraint=text)
        self.assertEqual(ur.post_use_constraint, text)

    def test_model_json_schema_has_descriptions(self):
        """Verify Pydantic Field(description=...) makes it into the
        JSON schema seen by the LLM tool call."""
        schema = UsageReport.model_json_schema()
        props = schema["properties"]
        for name, field in props.items():
            with self.subTest(field=name):
                self.assertTrue(field.get("description", "").strip())


class FileResourceReportObservedApisTests(unittest.TestCase):

    def _build_report(self, *usage_lists) -> FileResourceReport:
        callsite_reports = []
        for i, usages in enumerate(usage_lists):
            callsite_reports.append(
                CallSiteReport(
                    callsite_id=f"bin::f::L{i}::open",
                    containing_function_purpose="test",
                    setup_details="O_RDONLY",
                    usage_reports=list(usages),
                )
            )
        return FileResourceReport(
            resource_group_id="rg_0",
            primary_path="/dev/foo",
            resource_class=FileResourceClass.PSEUDO_FS_DEV,
            callsite_reports=callsite_reports,

            summary="test",
        )

    def test_observed_apis_dedups_and_sorts(self):
        report = self._build_report(
            [
                _make_usage(api="read", line=10),
                _make_usage(api="ioctl", line=11),
                _make_usage(api="read", line=12),
            ],
            [
                _make_usage(api="close", line=20),
                _make_usage(api="ioctl", line=21),
            ],
        )
        self.assertEqual(report.observed_apis, ["close", "ioctl", "read"])

    def test_observed_apis_empty_when_no_usages(self):
        report = self._build_report()
        self.assertEqual(report.observed_apis, [])

    def test_observed_apis_preserves_variants(self):
        """pread and read must both appear — not collapsed."""
        report = self._build_report(
            [
                _make_usage(api="read", line=10),
                _make_usage(api="pread", line=11),
                _make_usage(api="fread", line=12),
            ],
        )
        self.assertEqual(report.observed_apis, ["fread", "pread", "read"])


class FileResolverResultCoveredTests(unittest.TestCase):

    def test_schema8_cache_is_rejected(self):
        from pydantic import ValidationError

        with self.assertRaises(ValidationError):
            FileResolverResult.model_validate({
                "schema_version": 8,
                "root_binary": "httpd",
            })

    def test_old_family_grouping_schema_is_rejected(self):
        from pydantic import ValidationError

        with self.assertRaises(ValidationError):
            FileResolverResult.model_validate({
                "phase": "full",
                "root_binary": "httpd",
                "exact_groups": {},
                "merged_groups": {},
                "resource_reports": {},
            })

    def test_resource_execution_failure_round_trip_and_markdown(self):
        from fmst_analyzer.analysis.file_resolver.reports import render_index

        callsite = _make_callsite("httpd", "main", 10, "open")
        resource = FileResource(
            resource_group_id="file_dev_foo_0123456789ab",
            path_value="/dev/foo",
            path_kind="concrete",
            resource_class=FileResourceClass.PSEUDO_FS_DEV,
            callsites=[callsite],
        )
        result = _make_result(
            root_binary="httpd",
            callsites={callsite.profile_key: callsite},
            resources={resource.resource_group_id: resource},
            execution={"tasks": {f"resource:{resource.resource_group_id}": {
                "subject_id": resource.resource_group_id, "status": "failed",
                "failure": {"kind": "provider", "reason": "RuntimeError: provider unavailable"},
            }}},
        )
        restored = FileResolverResult.model_validate_json(
            result.model_dump_json()
        )
        self.assertEqual(
            restored.execution,
            result.execution,
        )
        rendered = render_index(restored)
        self.assertIn("## execution", rendered)
        self.assertIn("RuntimeError: provider unavailable", rendered)

    def test_markdown_styles_structured_code_references(self):
        from fmst_analyzer.analysis.file_resolver.reports import (
            render_index,
            render_per_resource_report,
        )

        callsite = _make_callsite(
            "uhttpd",
            "main",
            10,
            "fopen",
            path="/etc/httpd.conf",
            resource_class=FileResourceClass.MISSING_NON_PSEUDO_FS,
        ).model_copy(update={
            "resolution_source": "file_path_agent",
            "resolution_evidence": [
                "uhttpd::main L8-L10 passes /etc/httpd.conf to fopen."
            ],
        })
        resource = FileResource(
            resource_group_id="file_etc_httpd_conf_0123456789ab",
            path_value="/etc/httpd.conf",
            path_kind="concrete",
            resource_class=FileResourceClass.MISSING_NON_PSEUDO_FS,
            callsites=[callsite],
        )
        report = FileResourceReport(
            resource_group_id=resource.resource_group_id,
            primary_path=resource.path_value,
            resource_class=resource.resource_class,
            callsite_reports=[CallSiteReport(
                callsite_id=callsite.callsite_id,
                containing_function_purpose="uhttpd::main reads configuration.",
                setup_details="Opens /etc/httpd.conf at L10.",
                usage_reports=[_make_usage(
                    api="fgets",
                    line=12,
                    details="uhttpd::main reads /etc/httpd.conf.",
                )],
            )],

            summary=(
                "uhttpd::main tolerates a missing /etc/httpd.conf. "
                "It also opens /dev/null."
            ),
        )
        result = _make_result(
            phase="full",
            root_binary="uhttpd",
            callsites={callsite.profile_key: callsite},
            resources={resource.resource_group_id: resource},
            resource_reports={resource.resource_group_id: report},
        )

        index = render_index(result)
        detail = render_per_resource_report(report)
        self.assertIn("# File Resolver Report — `uhttpd`", index)
        for field in ("callsites", "resources", "resource_reports", "planning_findings"):
            self.assertIn(field, index)
        self.assertIn("uhttpd::main L8-L10 passes /etc/httpd.conf to fopen.", index)
        self.assertIn("[md](file_etc_httpd_conf_0123456789ab.md)", index)
        self.assertIn("[json](file_etc_httpd_conf_0123456789ab_result.json)", index)
        for field, value in report.model_dump(mode="json").items():
            self.assertIn(field, detail)
        self.assertIn(report.summary, detail)
        self.assertIn(report.callsite_reports[0].setup_details, detail)

    def test_markdown_renders_requested_symlink_alias(self):
        from fmst_analyzer.analysis.file_resolver.reports import render_index

        callsite = _make_callsite(
            "httpd", "main", 10, "open", path="/etc/runtime.conf",
        ).model_copy(update={
            "path_value": "/var/generated/runtime.conf",
            "resolution_evidence": [
                "guest symlink chain: /etc/runtime.conf -> "
                "/var/generated/runtime.conf"
            ],
        })
        result = _make_result(
            root_binary="httpd",
            callsites={callsite.profile_key: callsite},
        )
        rendered = render_index(result)
        self.assertIn("requested_path", rendered)
        self.assertIn("/etc/runtime.conf", rendered)
        self.assertIn("/var/generated/runtime.conf", rendered)
        self.assertIn(callsite.resolution_evidence[0], rendered)

    def test_markdown_explains_candidate_resource_and_gap_relationship(self):
        from fmst_analyzer.analysis.file_resolver.reports import render_index

        selected = _make_callsite(
            "httpd", "open_runtime", 10, "open", path="/tmp/runtime.pid",
            resource_class=FileResourceClass.MISSING_NON_PSEUDO_FS,
        )
        alternate = selected.model_copy(update={
            "candidate_idx": 1,
            "profile_key": f"{selected.callsite_id}#1",
            "requested_path": "/tmp/runtime-alt.pid",
            "path_value": "/tmp/runtime-alt.pid",
        })
        resource = FileResource(
            resource_group_id="file_tmp_runtime_pid_0123456789ab",
            path_value=selected.path_value,
            path_kind="concrete",
            resource_class=selected.resource_class,
            callsites=[selected],
        )
        result = _make_result(
            root_binary="httpd",
            callsites={
                selected.profile_key: selected,
                alternate.profile_key: alternate,
            },
            path_resolution_gaps={
                selected.callsite_id: ["runtime branch remains unknown"],
                "httpd::other::L20::open": ["caller value unavailable"],
            },
            resources={resource.resource_group_id: resource},
        )

        rendered = render_index(result)
        for value in (selected.profile_key, "path_resolution_gaps", "runtime branch remains unknown",
                      "httpd::other::L20::open", "caller value unavailable", resource.resource_group_id):
            self.assertIn(value, rendered)

    def test_missing_section_does_not_recommend_current_scope(self):
        from fmst_analyzer.analysis.file_resolver.reports import render_index

        callsite = _make_callsite(
            "httpd",
            "main",
            10,
            "access",
            path="/runtime/state",
            resource_class=FileResourceClass.MISSING_NON_PSEUDO_FS,
        )
        result = _make_result(
            root_binary="httpd",
            callsites={callsite.profile_key: callsite},
        )

        rendered = render_index(result)
        self.assertIn("access", rendered)
        self.assertIn("/runtime/state", rendered)
        self.assertNotIn("Switch scope to `with_allowlist`", rendered)

    def test_markdown_accounts_for_unselected_pseudo_fs_callsites(self):
        from fmst_analyzer.analysis.file_resolver.reports import render_index

        query = _make_callsite(
            "httpd", "probe_device", 10, "stat", path="/dev/example",
        )
        result = _make_result(
            root_binary="httpd",
            callsites={query.profile_key: query},
        )

        rendered = render_index(result)
        for value in ("/dev/example", "stat", "httpd::probe_device::L10::stat"):
            self.assertIn(value, rendered)

    def test_covered_api_calls_source_a_only(self):
        """With no resource_reports, covered_api_calls == callsites values."""
        cs1 = _make_callsite("httpd", "main", 10, "open")
        cs2 = _make_callsite("httpd", "init", 20, "stat")
        result = _make_result(
            root_binary="httpd",
            callsites={cs1.profile_key: cs1, cs2.profile_key: cs2},
        )
        covered = result.covered_api_calls
        self.assertEqual(len(covered), 2)
        keys = {(c.binary_name, c.function_name, c.api_name, c.line_number) for c in covered}
        self.assertIn(("httpd", "main", "open", 10), keys)
        self.assertIn(("httpd", "init", "stat", 20), keys)

    def test_covered_api_calls_merges_source_a_and_b(self):
        cs_open = _make_callsite("httpd", "get_if_ip", 80, "open", path="/dev/net")
        ur_ioctl = _make_usage(
            api="ioctl",
            line=87,
            function_name="get_if_ip",
            details="SIOCGIFADDR",
            post_use_constraint="strcmp(buf, lan_ip) != 0 -> exit(1) at L95",
        )
        cr = CallSiteReport(
            callsite_id="httpd::get_if_ip::L80::open",
            containing_function_purpose="read MAC",
            setup_details="AF_INET socket",
            usage_reports=[ur_ioctl],
        )
        report = FileResourceReport(
            resource_group_id="rg_0",
            primary_path="/dev/net",
            resource_class=FileResourceClass.PSEUDO_FS_DEV,
            callsite_reports=[cr],

            summary="t",
        )
        result = _make_result(
            root_binary="httpd",
            callsites={cs_open.profile_key: cs_open},
            resources={"rg_0": _resource(cs_open, report)},
            resource_reports={"rg_0": report},
        )
        covered = result.covered_api_calls
        keys = {(c.binary_name, c.function_name, c.api_name, c.line_number) for c in covered}
        self.assertIn(("httpd", "get_if_ip", "open", 80), keys)
        self.assertIn(("httpd", "get_if_ip", "ioctl", 87), keys)
        # ioctl entry's reason reflects the resource_class
        ioctl = next(c for c in covered if c.api_name == "ioctl")
        self.assertIn("pseudo_fs_dev", ioctl.reason)
        self.assertIn("ioctl", ioctl.reason)

    def test_covered_api_calls_dedups(self):
        """Same (binary, func, api, line) in Source A and Source B is
        not duplicated."""
        cs = _make_callsite("httpd", "f", 10, "open", path="/dev/x")
        ur_dup = _make_usage(api="open", line=10, function_name="f")
        cr = CallSiteReport(
            callsite_id="httpd::f::L10::open",
            containing_function_purpose="x",
            setup_details="x",
            usage_reports=[ur_dup],
        )
        report = FileResourceReport(
            resource_group_id="rg_0",
            primary_path="/dev/x",
            resource_class=FileResourceClass.PSEUDO_FS_DEV,
            callsite_reports=[cr],

            summary="t",
        )
        result = _make_result(
            root_binary="httpd",
            callsites={cs.profile_key: cs},
            resources={"rg_0": _resource(cs, report)},
            resource_reports={"rg_0": report},
        )
        covered = result.covered_api_calls
        self.assertEqual(len(covered), 1)

    def test_upstream_skip_field_is_rejected(self):
        cs = _make_callsite("httpd", "f", 10, "open")
        with self.assertRaisesRegex(ValueError, "skipped"):
            _make_result(root_binary="httpd", callsites={cs.profile_key: cs},
                         skipped={"httpd::other::L55::open": "ipc_callsite_covered"})

    def test_covered_api_calls_preserves_cross_binary_usage(self):
        usage = _make_usage(api="read", line=33, function_name="load")
        usage.binary_name = "libcfg.so"
        report = FileResourceReport(
            resource_group_id="rg_cross",
            primary_path="/dev/cfg",
            resource_class=FileResourceClass.PSEUDO_FS_DEV,
            callsite_reports=[CallSiteReport(
                callsite_id="httpd::main::L10::open",
                containing_function_purpose="test",
                setup_details="test",
                usage_reports=[usage],
            )],

            summary="test",
        )
        site = _make_callsite("httpd", "main", 10, "open", path="/dev/cfg")
        result = _make_result(
            root_binary="httpd",
            callsites={site.profile_key: site},
            resources={"rg_cross": _resource(site, report)},
            resource_reports={"rg_cross": report},
        )
        self.assertEqual(next(c for c in result.covered_api_calls if c.api_name == "read").binary_name, "libcfg.so")


class CoveredAPICallSchemaTests(unittest.TestCase):

    def test_covered_api_call_fields(self):
        c = CoveredAPICall(
            binary_name="httpd",
            function_name="main",
            api_name="ioctl",
            line_number=42,
            reason="filesystem ioctl on pseudo_fs_dev",
        )
        self.assertEqual(c.binary_name, "httpd")
        self.assertEqual(c.api_name, "ioctl")
        self.assertEqual(c.reason, "filesystem ioctl on pseudo_fs_dev")

    def test_covered_api_call_schema_has_descriptions(self):
        schema = CoveredAPICall.model_json_schema()
        for field_name in ("binary_name", "function_name", "api_name", "line_number", "reason"):
            self.assertIn(
                "description",
                schema["properties"][field_name],
                msg=f"{field_name} missing description",
            )


class AgentPositionValidationTests(unittest.TestCase):
    def _report(self, usage: UsageReport) -> CallSiteReport:
        return CallSiteReport(
            callsite_id="httpd::main::L10::open",
            containing_function_purpose="test",
            setup_details="test",
            usage_reports=[usage],
        )

    def test_cross_binary_usage_position_is_accepted(self):
        usage = UsageReport(
            binary_name="libcfg.so",
            function_name="load_value",
            line_number=24,
            api_name="read",
            details="reads state",
        )
        _validate_report_positions(
            [self._report(usage)],
            [],
            _source_view("libcfg.so", "load_value", 24),
        )

    def test_usage_without_binary_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "binary_name"):
            UsageReport(
                function_name="load_value",
                line_number=24,
                api_name="read",
                details="reads state",
            )

    def test_wrong_line_is_rejected(self):
        usage = UsageReport(
            binary_name="libcfg.so",
            function_name="load_value",
            line_number=25,
            api_name="read",
            details="reads state",
        )
        with self.assertRaisesRegex(ValueError, "libcfg.so::load_value: line_number=25"):
            _validate_report_positions(
                [self._report(usage)],
                [],
                _source_view("libcfg.so", "load_value", 24),
            )

    def test_coverage_import_prefix_is_position_equivalent(self):
        flow = CoverageFlow(
            flow_id="read_config",
            description="test",
            setup=[],
            use=[CoveredAPICall(
                binary_name="httpd",
                function_name="main",
                line_number=30,
                api_name="__imp_read",
                reason="test",
            )],
            termination=[],
        )
        _validate_report_positions(
            [],
            [flow],
            _source_view("httpd", "main", 30),
        )



if __name__ == "__main__":
    unittest.main()


def _source_view(binary, function, length):
    return SimpleNamespace(lib_dep_graph=SimpleNamespace(get_node_by_name=lambda name: object() if name == binary else None),
        get_function_ea=lambda b, f: 0x1000 if (b, f) == (binary, function) else None,
        get_full_code=lambda *_: "source\n" * length)
