#!/usr/bin/env python3
"""Run the candidate install driver without importing the installed manager."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server_guard.installation import install_main


if __name__ == "__main__":
    sys.exit(install_main())
