#!/usr/bin/env python3
"""Run the downloaded uninstaller without installing/upgrading the manager."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server_guard.cli import main


if __name__ == "__main__":
    sys.argv = [sys.argv[0], "uninstall", *sys.argv[1:]]
    sys.exit(main())
