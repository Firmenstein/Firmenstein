"""CLI entry point for verified frozen-input replays (no Agent/build)."""

from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path.cwd() / ".env")

from .publication import main


if __name__ == "__main__":
    main()
