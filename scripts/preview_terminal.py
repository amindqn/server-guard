#!/usr/bin/env python3
"""Preview the real terminal UI using temporary sample state and no host commands."""
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server_guard.core import Files, GuardError, PolicyStore, defaults
from server_guard.host import Host
from server_guard.tui import TerminalApp, TerminalConsole


class PreviewRunner:
    def run(self, *args, **kwargs):
        raise GuardError("Preview mode does not execute host commands.")


def main():
    with tempfile.TemporaryDirectory(prefix="server-guard-ui-preview-") as root:
        files = Files(root)
        state = defaults()
        state["users"]["admin"] = {"role": "admin", "sessions": 3, "disabled": False}
        PolicyStore(files).save(state)
        files.write("/var/lib/server-guard/prepared.json", "{}")
        files.write("/etc/server-guard/firewall.nft", "# preview only\n")
        console = TerminalConsole()
        console.say("PREVIEW: sample configuration. Commands and host changes are disabled.", "note")
        def disabled(args):
            console.say("Preview only: command not executed.", "note")
        try:
            TerminalApp(Host(files, PreviewRunner()), disabled, console).run()
        except EOFError:
            pass


if __name__ == "__main__":
    main()
