"""Declarative task contract for environment setup script generation."""

ENVIRONMENT_TASK_PROMPT = """\
<goal>
Apply the supplied Firmenstein application contract and environment-generation
reference to translate the supplied environment_setup Units into one
`setup_rootfs.py` in the task workdir.
</goal>

<criteria>
The Plan bounds the implementation; its premises and Analyzer findings can be wrong.
Record material contradictions and their evidence, but write the most useful
bounded candidate that can be authored without inventing contents or silently
changing the Contract. Return unable only when no concrete script can be written
because an essential input, target, or expressible operation is missing.
The supplied Plan, Catalog, Analyzer findings and rootfs are read-only factual
inputs. Reuse resources that already exist there when they satisfy a Unit, but
never modify or execute firmware files, Plans, Catalogs or Analyzer results.
The supplied Units are static filesystem preparation only. Do not start target,
peer, daemon, socket/FIFO, or network services and do not perform live
hostname/interface, mount, chroot, Docker, or process-management operations;
those are RunnerAgent responsibilities.
Do not inspect project source, historical generation artifacts, or unrelated
workdirs; they are not evidence for this task.
Only write the requested script in the task workdir.
</criteria>

<termination>
Report completed when `setup_rootfs.py` implements every supplied Unit. Report
unable only when no concrete script can be authored, and state the exact reason.
Do not execute the generated script or construct a test rootfs; the Runner owns
dynamic validation.
</termination>
"""


__all__ = ["ENVIRONMENT_TASK_PROMPT"]
