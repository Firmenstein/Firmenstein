"""Cross-analyzer coverage schema.

Each analyzer exposes ``covered_api_calls`` on its Result to declare
which API callsites it considers itself responsible for. Downstream
consumers read the list to dedup or drive conflict detection.

When the producer count reaches 3+ or consumers need complex queries
(conflict detection / owner lookup / multi-source dedup), introduce a
``CrossAnalyzerCoverage`` helper here that aggregates multiple analyzer
Results. Currently manual list merge is enough.

``CoveredAPICall`` lives in ``covered_api_call`` and is re-exported
here for backward compatibility.
"""
from __future__ import annotations

from fmst_analyzer.analysis.base.covered_api_call import CoveredAPICall
from fmst_analyzer.analysis.base.coverage_flow import CoverageFlow

__all__ = ["CoveredAPICall", "CoverageFlow"]
