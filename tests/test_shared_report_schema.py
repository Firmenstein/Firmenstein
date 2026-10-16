"""Regression: analysis.base.report_schema is the shared source of truth.

After Step 1 of the NetworkAnalyzer v1 refactor, FileResolver imports
``CallSiteReport`` / ``UsageReport`` from ``analysis.base.report_schema``
instead of defining its own copies, and renames ``open_details`` →
``setup_details``. This test pins:

- ``CallSiteReport`` exposes ``setup_details`` (not ``open_details``)
- FileResolver's re-exported ``CallSiteReport`` is literally the base
  class (not a subclass, not a copy)
- Pydantic Field descriptions remain present in the model-visible schema

Usage:
    source src/.venv/bin/activate
    python -m unittest tests.test_shared_report_schema -v
"""
import sys
import unittest
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fmst_analyzer.analysis.base.report_schema import (
    CallSiteReport as BaseCSR,
    UsageReport as BaseUR,
)
from fmst_analyzer.analysis.file_resolver import (
    CallSiteReport as FileCSR,
    UsageReport as FileUR,
)


class SharedSchemaIdentity(unittest.TestCase):

    def test_file_reexports_base_classes(self):
        self.assertIs(FileCSR, BaseCSR)
        self.assertIs(FileUR, BaseUR)

class SetupDetailsFieldRename(unittest.TestCase):

    def test_callsite_report_has_setup_details(self):
        fields = set(BaseCSR.model_fields.keys())
        self.assertIn("setup_details", fields)

    def test_callsite_report_does_not_have_open_details(self):
        fields = set(BaseCSR.model_fields.keys())
        self.assertNotIn("open_details", fields)

    def test_setup_details_description_is_model_visible(self):
        schema = BaseCSR.model_json_schema()
        description = schema["properties"]["setup_details"]["description"]
        self.assertTrue(description.strip())

    def test_can_construct_with_setup_details(self):
        cr = BaseCSR(
            callsite_id="httpd::main::L10::socket",
            containing_function_purpose="starts server",
            setup_details="socket(AF_INET, SOCK_STREAM, 0)",
            usage_reports=[],
        )
        self.assertEqual(cr.setup_details, "socket(AF_INET, SOCK_STREAM, 0)")


class UsageReportSchemaStability(unittest.TestCase):

    def test_fields_match(self):
        fields = set(BaseUR.model_fields.keys())
        self.assertEqual(
            fields,
            {"binary_name", "function_name", "line_number", "api_name", "details",
             "post_use_constraint"},
        )


if __name__ == "__main__":
    unittest.main()
