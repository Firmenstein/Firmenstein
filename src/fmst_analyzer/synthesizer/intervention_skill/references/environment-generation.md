# Environment Generation

Use this reference only when implementing `environment_setup` Units.

Generate one `setup_rootfs.py` that accepts exactly one command-line argument:
the staged rootfs path. Resolve every mutation relative to that root and keep
repeated execution idempotent. The normalized Units, selected launch, and
finding evidence are preserved records, not certified facts. If material premises
conflict, record the source and reason and write the most useful bounded candidate
that the available evidence supports; return unable only when no concrete script
can be authored. Choose ordinary filesystem operations that faithfully provide
those dependencies. Do not follow a fixed action whitelist.

An absolute path in the firmware namespace is not the same as joining its text
to the host path. Resolve guest components one at a time: an absolute symlink
target restarts at the staged root, a relative target stays relative to the
symlink's guest directory, and every final host path must remain inside the
staged root. Do not use host `realpath` or a direct `os.path.join(root, "/x")`
as a substitute for this resolution; either can follow `/var -> /tmp` against
the host filesystem or silently write outside the staged root.
Treat the supplied firmware rootfs as a read-only factual source. Prefer an
existing real resource or copy source when it satisfies the Unit, but never
modify the original rootfs or execute firmware files while generating the
script.

The script is only a static pre-import rootfs transformation. It must not
start target or peer processes, provide IPC or network endpoints, change live
hostname/interface state, invoke Docker, or perform mount/chroot/process
management. Those responsibilities belong to RunnerAgent runtime tasks.

Generation stops after writing the script. Do not execute `setup_rootfs.py` or
construct a test rootfs during generation; the Runner owns dynamic validation
on its disposable staged-rootfs copy.

Do not invent unknown file contents or copy sources. Do not represent runtime
behavior as a filesystem mutation: starting a peer, serving an IPC or network
endpoint, changing live hostname/interface state, mounting, chrooting, or
managing guest processes belongs to a `runner_task` rather than this
script.

Report `unable` with the missing fact only when an essential input, target, or
expressible operation is missing and no concrete script can be authored. Do not
silently omit an Environment Unit; a written candidate with a recorded
assumption remains a candidate for Runner feedback.
