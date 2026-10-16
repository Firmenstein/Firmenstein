"""Shared model: one coherent setup-use-failure unit for a resource.

Used by IPC endpoint coverage claims, FileResourceReport, and
NetworkInteractionAnalysis.

Conditional behavior remains in the Analyzer finding, including lifecycle
effects that have no explicit terminating API call (such as main returning).
"""
from typing import List

from pydantic import BaseModel, Field

from .covered_api_call import CoveredAPICall, CoveredAPICallResolver


class CoverageFlow(BaseModel):
    """One end-to-end usage pattern of a resource.

    A flow is NOT a happy path. It is a complete setup-use-failure
    unit: an explicit exit guard belongs in `termination`. An empty list
    makes no assertion about target survival or uninspected caller behavior.
    """

    flow_id: str = Field(
        description="Stable snake_case identifier. Same logical flow "
        "across sibling member profiles of THE SAME resource MUST use "
        "the SAME label (rendering merges by this id). Action-describing "
        "labels preferred: 'rendezvous_read_path', "
        "'uds_connect_send_recv', 'config_file_read', "
        "'tcp_listen_accept'. Avoid resource-specific names."
    )
    description: str = Field(
        description="One sentence: what this flow does and the "
        "precondition it needs."
    )
    setup: List[CoveredAPICall] = Field(
        description="APIs that establish or locate the resource "
        "identifier along this flow."
    )
    use: List[CoveredAPICall] = Field(
        description="APIs that operate on the identifier produced "
        "by this flow's setup."
    )
    termination: List[CoveredAPICall] = Field(
        description="exit / _exit / _Exit / quick_exit / abort / "
        "__assert_fail callsites "
        "reachable along this flow when any setup or use op fails. "
        "Distinguish child/parent/target effects in reason and finding claims. "
        "Returning from main also terminates a process, but is not an API call; "
        "record that propagation in the finding instead of inventing a callsite. "
        "Each entry's `reason` MUST name the triggering op, e.g. "
        "'exit on fopen(L65) NULL' or 'exit on socket(L12) < 0'."
    )


def resolve_coverage_flows(
    resolver: CoveredAPICallResolver,
    flows: List[CoverageFlow],
) -> List[CoverageFlow]:
    """Replace uniquely located display citations with CTree identities."""
    return [
        flow.model_copy(update={
            "setup": resolver.resolve_many(flow.setup),
            "use": resolver.resolve_many(flow.use),
            "termination": resolver.resolve_many(flow.termination),
        })
        for flow in flows
    ]
