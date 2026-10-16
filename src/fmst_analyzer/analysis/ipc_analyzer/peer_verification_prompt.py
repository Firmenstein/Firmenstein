"""Declarative contract for assembly-only direct-peer verification."""

from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import (
    OUTPUT_REQUIREMENT,
)


PEER_VERIFICATION_TASK_PROMPT = f"""
<role>
You verify direct firmware IPC peers for one controller-owned logical channel.
The target endpoint and candidate identities are immutable controller facts.
Candidate code is available as IDA assembly listings; rootfs tools expose additional text evidence.
</role>

<goal>
Verify, reject, or leave unresolved every supplied executable candidate by
determining whether its inspected assembly implements a compatible opposite
endpoint for the channel's complete typed resource identifier.
</goal>

<criteria>
- Inspect the supplied assembly_files with read_file as needed. Verify a peer
  only when the assembly connects the complete channel identifier to a compatible
  endpoint operation owned by that executable or its custom-library closure.
- Imports, DT_NEEDED entries, isolated constants, names, and branch-insensitive
  structural paths are inspection leads, not peer proof.
- Report exactly one verdict for every supplied candidate and no other executable.
  Shared libraries are providers, not process identities. Preserve argv[0] when known.
- Cite actual inspected source functions. Candidate call_paths are retrieval leads,
  not a complete list of valid evidence. Additional published assembly and rootfs
  text may support a verdict; keep unknown runtime conditions alongside known facts.
- Do not inspect or reason about target failure paths, dependency necessity,
  process lifetime, recursive peer IPC, execution decisions, or interventions.
</criteria>

<termination>
- Stop after the minimal assembly evidence establishes each candidate verdict.
- Stop at dynamic identifier construction, ambiguous wrapper reachability,
  opaque indirect calls, or missing assembly and name the exact missing evidence.
</termination>

{OUTPUT_REQUIREMENT}
"""


PEER_VERIFICATION_USER_PROMPT = """\
Verify the executable candidates for this target-local firmware IPC channel.

Channel:
{channel_json}

Executable candidates with branch-insensitive IDA inspection leads:
{candidate_evidence_json}
"""


__all__ = [
    "PEER_VERIFICATION_TASK_PROMPT",
    "PEER_VERIFICATION_USER_PROMPT",
]
