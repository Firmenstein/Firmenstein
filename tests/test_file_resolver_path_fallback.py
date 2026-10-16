"""Regression tests for FileResolver's path-only fallback Agent."""

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fmst_analyzer.analysis.file_resolver.analyzer import (  # noqa: E402
    FILE_API_PATH_ARG,
    FileResolver,
    _file_callsite_id,
)
from fmst_analyzer.analysis.file_resolver.analyzer_schema import (  # noqa: E402
    FilePathCandidate,
    FilePathResolution,
)
from fmst_analyzer.nodes.callsite import ArgInfo, ArgType  # noqa: E402


class FilePathResolutionSchemaTests(unittest.TestCase):
    def test_common_large_file_and_creat_variants_are_covered(self):
        self.assertEqual(FILE_API_PATH_ARG["open64"], 0)
        self.assertEqual(FILE_API_PATH_ARG["openat64"], 1)
        self.assertEqual(FILE_API_PATH_ARG["creat"], 0)
        self.assertEqual(FILE_API_PATH_ARG["creat64"], 0)
        self.assertEqual(FILE_API_PATH_ARG["freopen"], 0)
        self.assertEqual(FILE_API_PATH_ARG["statfs64"], 0)
        self.assertEqual(FILE_API_PATH_ARG["statvfs64"], 0)

    def test_empty_result_requires_missing_evidence(self):
        with self.assertRaisesRegex(ValueError, "missing_evidence"):
            FilePathResolution()

    def test_duplicate_candidates_are_rejected(self):
        candidate = FilePathCandidate(
            value="/tmp/state",
            kind="concrete",
            evidence=["httpd::main:L10"],
        )
        result = FilePathResolution(candidates=[candidate, candidate])
        self.assertEqual(result.candidates, [candidate])

    def test_partial_resolution_keeps_candidate_and_gap(self):
        result = FilePathResolution(
            candidates=[FilePathCandidate(
                value="/dev/mtd%d",
                kind="pattern",
                evidence=["httpd::build_path:L20 snprintf format"],
            )],
            missing_evidence=["second branch comes from runtime NVRAM"],
        )
        self.assertEqual(result.candidates[0].value, "/dev/mtd%d")
        self.assertEqual(len(result.missing_evidence), 1)


class FilePathFallbackNodeTests(unittest.IsolatedAsyncioTestCase):
    def _resolver(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        config = SimpleNamespace(
            agent_provider="codex",
            diagnosis_model="test-model",
            agent_concurrency_limit=2,
            target_agent_debug_dir=lambda: root / "agent_debug",
        )
        return tmp, FileResolver(config)

    @staticmethod
    def _callsite(api_name="open"):
        return SimpleNamespace(
            binary_name="httpd",
            line_number=42,
            file_resolver_api_name=api_name,
            file_resolver_caller_name="load_state",
            file_resolver_id=f"httpd::load_state::L42::{api_name}",
        )

    async def test_multiple_candidates_and_partial_gap_are_preserved(self):
        tmp, resolver = self._resolver()

        class FakeAgent:
            def __init__(self, **_kwargs):
                pass

            async def analyze(self, **_kwargs):
                return FilePathResolution(
                    candidates=[
                        FilePathCandidate(
                            value='"/etc/config"',
                            kind="concrete",
                            evidence=["httpd::load_state:L40 literal"],
                        ),
                        FilePathCandidate(
                            value="/tmp/state%d",
                            kind="pattern",
                            evidence=["httpd::load_state:L41 snprintf"],
                        ),
                    ],
                    missing_evidence=["third branch comes from getenv"],
                )

        try:
            with patch(
                "fmst_analyzer.analysis.file_resolver.analyzer.CodeAnalyzerAgent",
                FakeAgent,
            ):
                profiles, gaps = await resolver._node3_path_fallback_resolve(
                    SimpleNamespace(), [self._callsite()]
                )
        finally:
            tmp.cleanup()

        self.assertEqual(
            [profile.path_value for profile in profiles],
            ["/etc/config", "/tmp/state%d"],
        )
        self.assertTrue(all(
            profile.resolution_source == "file_path_agent"
            for profile in profiles
        ))
        self.assertEqual(
            gaps["httpd::load_state::L42::open"],
            ["third branch comes from getenv"],
        )

    async def test_agent_failure_is_not_a_semantic_gap(self):
        tmp, resolver = self._resolver()

        class FailingAgent:
            def __init__(self, **_kwargs):
                pass

            async def analyze(self, **_kwargs):
                raise RuntimeError("provider unavailable")

        try:
            with patch(
                "fmst_analyzer.analysis.file_resolver.analyzer.CodeAnalyzerAgent",
                FailingAgent,
            ):
                profiles, gaps = await resolver._node3_path_fallback_resolve(
                    SimpleNamespace(), [self._callsite()]
                )
        finally:
            tmp.cleanup()

        self.assertEqual(profiles, [])
        self.assertEqual(gaps, {})
        self.assertEqual(
            resolver.execution.record.tasks["path:httpd::load_state::L42::open"].failure.reason,
            "RuntimeError: provider unavailable",
        )

    async def test_static_phase_cannot_construct_agent(self):
        tmp, resolver = self._resolver()
        try:
            with patch(
                "fmst_analyzer.analysis.file_resolver.analyzer.CodeAnalyzerAgent"
            ) as agent_cls:
                profiles, gaps = await resolver._node3_path_fallback_resolve(
                    SimpleNamespace(), [self._callsite()], phase="static"
                )
        finally:
            tmp.cleanup()

        self.assertEqual((profiles, gaps), ([], {}))
        agent_cls.assert_not_called()

    async def test_query_only_callsite_cannot_construct_agent(self):
        tmp, resolver = self._resolver()
        try:
            with patch(
                "fmst_analyzer.analysis.file_resolver.analyzer.CodeAnalyzerAgent"
            ) as agent_cls:
                profiles, gaps = await resolver._node3_path_fallback_resolve(
                    SimpleNamespace(), [self._callsite("stat")]
                )
        finally:
            tmp.cleanup()

        self.assertEqual(profiles, [])
        self.assertIn(
            "query-only API stat",
            gaps["httpd::load_state::L42::stat"][0],
        )
        agent_cls.assert_not_called()

    async def test_fallback_relative_candidate_becomes_gap(self):
        tmp, resolver = self._resolver()

        class FakeAgent:
            def __init__(self, **_kwargs):
                pass

            async def analyze(self, **_kwargs):
                return FilePathResolution(candidates=[FilePathCandidate(
                    value="state.db",
                    kind="concrete",
                    evidence=["httpd::load_state:L42"],
                )])

        try:
            with patch(
                "fmst_analyzer.analysis.file_resolver.analyzer.CodeAnalyzerAgent",
                FakeAgent,
            ):
                profiles, gaps = await resolver._node3_path_fallback_resolve(
                    SimpleNamespace(), [self._callsite()]
                )
        finally:
            tmp.cleanup()

        self.assertEqual(profiles, [])
        self.assertIn("relative candidate 'state.db'", gaps[
            "httpd::load_state::L42::open"
        ][0])


class FileStaticRelativePathTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _callsite(value, *, api_name="open", arg_type=ArgType.LITERAL):
        argument = ArgInfo(1, value, arg_type)
        return SimpleNamespace(
            binary_name="httpd",
            line_number=12,
            column_number=1,
            callsite_ea=0x1000,
            ctree_index=7,
            file_resolver_api_name=api_name,
            file_resolver_caller_name="main",
            file_resolver_id=f"httpd::main::L12::{api_name}@ctree7",
            get_argument=lambda index: argument if index == 1 else None,
        )

    async def test_relative_literal_is_gap_not_fallback(self):
        resolver = FileResolver(SimpleNamespace(agent_concurrency_limit=1))
        profiles, fallback, gaps = await resolver._node2_static_resolve(
            SimpleNamespace(), [self._callsite('"state.db"')]
        )
        self.assertEqual(profiles, [])
        self.assertEqual(fallback, [])
        self.assertIn("'state.db'", gaps[
            "httpd::main::L12::open@ctree7"
        ][0])

    async def test_empty_literal_is_gap_not_fallback(self):
        resolver = FileResolver(SimpleNamespace(agent_concurrency_limit=1))
        profiles, fallback, gaps = await resolver._node2_static_resolve(
            SimpleNamespace(), [self._callsite('""')]
        )
        self.assertEqual((profiles, fallback), ([], []))
        self.assertIn("candidate ''", gaps[
            "httpd::main::L12::open@ctree7"
        ][0])

    async def test_absolute_literal_remains_static(self):
        resolver = FileResolver(SimpleNamespace(agent_concurrency_limit=1))
        profiles, fallback, gaps = await resolver._node2_static_resolve(
            SimpleNamespace(), [self._callsite('"/etc/config"')]
        )
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0].requested_path, "/etc/config")
        self.assertEqual(fallback, [])
        self.assertEqual(gaps, {})

    async def test_unresolved_query_is_gap_not_fallback(self):
        resolver = FileResolver(SimpleNamespace(agent_concurrency_limit=1))
        profiles, fallback, gaps = await resolver._node2_static_resolve(
            SimpleNamespace(), [self._callsite(
                None,
                api_name="stat",
                arg_type=ArgType.OTHER,
            )]
        )
        self.assertEqual(profiles, [])
        self.assertEqual(fallback, [])
        self.assertIn(
            "query-only API stat",
            gaps["httpd::main::L12::stat@ctree7"][0],
        )

    async def test_unresolved_creating_api_still_queues_fallback(self):
        resolver = FileResolver(SimpleNamespace(agent_concurrency_limit=1))
        profiles, fallback, gaps = await resolver._node2_static_resolve(
            SimpleNamespace(), [self._callsite(
                None,
                api_name="open",
                arg_type=ArgType.OTHER,
            )]
        )
        self.assertEqual(profiles, [])
        self.assertEqual(len(fallback), 1)
        self.assertEqual(gaps, {})


class FileCallsiteIdentityTests(unittest.TestCase):

    def test_ctree_identity_distinguishes_same_line_calls(self):
        from fmst_analyzer.nodes.callsite import CallSite

        def make(index):
            return CallSite(
                binary_name="httpd",
                caller_ea=0x1000,
                caller_name="load",
                callee_ea=0,
                callee_name="open",
                callsite_ea=0x1010,
                line_number=42,
                column_number=4,
                snapshot_hash="snapshot",
                ctree_index=index,
            )

        first = _file_callsite_id("httpd", "load", 42, "open", make(10))
        second = _file_callsite_id("httpd", "load", 42, "open", make(11))
        self.assertNotEqual(first, second)
        self.assertTrue(first.endswith("@ctree10"))
        self.assertTrue(second.endswith("@ctree11"))





if __name__ == "__main__":
    unittest.main()
