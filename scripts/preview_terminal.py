#!/usr/bin/env python3
"""Preview the real terminal UI using temporary sample state and no host commands."""
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server_guard.core import Files, GuardError, PolicyStore, defaults
from server_guard.host import Host
from server_guard.tui import TerminalApp, TerminalConsole
from server_guard.health import HealthView, ReportStore


def example_health():
    return {"id": "00000000000000000001-example", "time": time.time(), "status": "WARN", "scope": "EXAMPLE DATA: resources and security",
            "counts": {"WARN": 1, "PASS": 1}, "metrics": {"resources": {
                "cpu_percent": 28.4, "cpus": 4, "load": [1.2, 0.9, 0.8], "iowait_percent": 1.0, "steal_percent": 0.0,
                "memory_percent": 55.0, "memory_available": 3600 * 1024 ** 2, "memory_total": 8000 * 1024 ** 2,
                "swap_used": 0, "swap_total": 1024 ** 3, "uptime_seconds": 90000, "sample_seconds": 1,
                "network": [{"interface": "eth0", "rx_bytes_s": 131072, "tx_bytes_s": 65536}], "processes_skipped": 0,
                "top_cpu": [{"pid": 1200, "uid": 1001, "cpu_percent": 62.0, "rss": 200 * 1024 ** 2, "name": "node"}],
                "top_memory": [{"pid": 1300, "uid": 110, "cpu_percent": 14.0, "rss": 650 * 1024 ** 2, "name": "mongod"}]},
                "disks": [{"mount": "/", "percent": 87.0, "available": 10 * 1024 ** 3, "inode_percent": 32.0}]},
            "checks": [{"name": "CPU busy", "status": "PASS", "detail": "28.4% sampled busy time.", "action": ""},
                       {"name": "/ space", "status": "WARN", "detail": "87.0% used; warning at 85%.", "action": "Inspect Storage explorer, then review one cleanup action."}]}


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
        ReportStore(files).save(example_health())
        console = TerminalConsole()
        console.say("PREVIEW: sample configuration. Commands and host changes are disabled.", "note")
        def disabled(args):
            console.say("Preview only: command not executed.", "note")
            if args[:2] in [["health", "check"], ["health", "show"], ["health", "watch"]]:
                if args[1] == "check":
                    for i, label in enumerate(["Sampling resources (EXAMPLE)", "Checking storage (EXAMPLE)", "Checking security (EXAMPLE)"], 1):
                        console.say(f"[{i}/3] {label}")
                HealthView.show(example_health())
        try:
            TerminalApp(Host(files, PreviewRunner()), disabled, console).run()
        except EOFError:
            pass


if __name__ == "__main__":
    main()
