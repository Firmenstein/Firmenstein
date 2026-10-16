"""Start long-lived services under container init, surviving Agent exit.

Usage: python -m fmst_analyzer.runner.task.jobs [--cwd DIR] -- COMMAND ARG...
"""
import argparse
import json
import time
import uuid
from pathlib import Path
from .common import TASK, write_json


def spawn(argv: list[str], cwd: str = "/task/work", env: dict | None = None,
          execution_path: Path | None = None, role: str = 'job'):
    key = uuid.uuid4().hex
    write_json(TASK / "control/requests" / (key + ".json"),
               {"argv": argv, "cwd": cwd, "env": env or {},
                "execution_path": str(execution_path) if execution_path else None, 'role': role})
    reply = TASK / "control/replies" / (key + ".json")
    deadline = time.monotonic() + 15
    while not reply.exists():
        if time.monotonic() > deadline:
            raise TimeoutError("Task init did not acknowledge the job; inspect container logs")
        time.sleep(.1)
    result = json.loads(reply.read_text())
    if "error" in result:
        raise RuntimeError(result["error"])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cwd", default=str(Path.cwd()))
    parser.add_argument('--execution', type=Path, help='Optional execution.json to associate logs and process exit')
    parser.add_argument('--role', default='job', help='firmware identifies the service job; other jobs do not change its state')
    parser.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.argv[1:] if args.argv and args.argv[0] == "--" else args.argv
    if not argv:
        parser.error("a command is required")
    print(json.dumps(spawn(argv, args.cwd, execution_path=args.execution, role=args.role)))


if __name__ == "__main__":
    main()
