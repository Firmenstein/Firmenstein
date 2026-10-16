"""Unit tests for the shared resource-usage-sites renderer."""
from dotenv import load_dotenv
load_dotenv()

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import (
    EffectiveCallsite,
)
from fmst_analyzer.analysis.base.reports_shared import (
    format_resource_usage_sites_for_agent,
    format_resource_usage_sites_md,
)


def _mk(func: str, line: int, snippet: str = "L10: foo();") -> EffectiveCallsite:
    return EffectiveCallsite(
        binary="httpd",
        function=func,
        representative_line=line,
        reached_via=f"wrapper_{func} → target",
        context_snippet=snippet,
    )


def test_agent_block_empty_shows_note():
    out = format_resource_usage_sites_for_agent([], total=0)
    assert "<resource_usage_sites" in out
    assert "No call sites" in out or "count=\"0\"" in out


def test_agent_block_includes_count_and_total():
    sites = [_mk("a", 10), _mk("b", 20)]
    out = format_resource_usage_sites_for_agent(sites, total=5)
    assert 'count="2"' in out
    assert 'total="5"' in out
    assert "httpd::a::L10" in out
    assert "httpd::b::L20" in out


def test_agent_block_includes_reached_via():
    sites = [_mk("a", 10)]
    out = format_resource_usage_sites_for_agent(sites, total=1)
    assert "reached via" in out
    assert "wrapper_a → target" in out


def test_agent_block_includes_context_snippet():
    sites = [_mk("a", 10, "L8: do_setup();\nL9: retval = foo();\nL10: if (!retval) exit(1);")]
    out = format_resource_usage_sites_for_agent(sites, total=1)
    assert "L10: if (!retval) exit(1);" in out


def test_md_section_uses_details_block():
    sites = [_mk("a", 10)]
    out = format_resource_usage_sites_md(sites, total=3)
    assert "## Resource Usage Sites" in out
    assert "1 of 3" in out
    assert "<details>" in out
    assert "</details>" in out


def test_md_section_empty_sentinel():
    out = format_resource_usage_sites_md([], total=0)
    assert "## Resource Usage Sites" in out
    # No <details> when empty; just a sentinel line
    assert "<details>" not in out
    assert "no call sites" in out.lower() or "none" in out.lower()


def test_md_section_supports_nested_field_heading():
    out = format_resource_usage_sites_md(
        [],
        total=0,
        heading_level=4,
        title="resource_usage_sites",
        empty_message="_None beyond `usage_reports`._",
    )
    assert out.startswith("#### resource_usage_sites")
    assert "None beyond `usage_reports`" in out
