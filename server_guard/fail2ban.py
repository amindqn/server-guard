"""Bounded native-daemon readiness, independent of systemd's started state."""
from __future__ import annotations

import subprocess
import time

from .core import GuardError


class Fail2BanService:
    """Adapter: restart once, then await its control socket and required jails."""
    def __init__(self, runner, *, timeout=30, interval=0.25, clock=None, pause=None):
        self.r = runner
        self.timeout, self.interval = timeout, interval
        self.clock, self.pause = clock or time.monotonic, pause or time.sleep
        if not 0 < timeout <= 60 or not 0 < interval <= 1:
            raise GuardError("Invalid Fail2Ban readiness budget.")

    def restart(self, jails=()):
        self.r.run("systemctl", "restart", "fail2ban")
        self.wait(jails)

    def wait(self, jails=()):
        deadline = self.clock() + self.timeout
        probes = [("fail2ban-client", "ping"), *[("fail2ban-client", "status", jail) for jail in jails]]
        last_probe, detail, state = probes[0], "No successful readiness response yet.", "unknown"
        while self.clock() < deadline:
            ready = True
            for probe in probes:
                remaining = deadline - self.clock()
                if remaining <= 0:
                    ready = False
                    break
                last_probe = probe
                try:
                    result = self.r.run(*probe, check=False, timeout=min(2, remaining))
                    if result.returncode == 0:
                        continue
                    detail = (result.stderr or result.stdout or "Client probe failed.").strip()[-700:]
                except FileNotFoundError as exc:
                    raise GuardError("Fail2Ban client is missing; repair the prepared dependencies before retrying.") from exc
                except subprocess.TimeoutExpired:
                    detail = "Client probe timed out."
                except OSError as exc:
                    detail = str(exc)
                ready = False
                break
            if ready:
                return
            remaining = deadline - self.clock()
            if remaining > 0:
                try:
                    status = self.r.run("systemctl", "show", "fail2ban.service", "--property=ActiveState", "--value",
                                        check=False, timeout=min(2, remaining))
                    if status.returncode == 0:
                        state = status.stdout.strip() or "unknown"
                except (OSError, subprocess.TimeoutExpired):
                    state = "unknown"
            if state in {"failed", "inactive"}:
                self._failed(last_probe, detail, state)
            remaining = deadline - self.clock()
            if remaining <= 0:
                break
            self.pause(min(self.interval, remaining))
        self._failed(last_probe, detail, state)

    def _failed(self, probe, detail, state):
        raise GuardError(f"Fail2Ban is not ready (maximum wait {self.timeout:g}s; service: {state}; waiting for {' '.join(probe)}).\n"
                         f"Last readiness result: {detail}\n"
                         "Inspect: sudo systemctl status fail2ban --no-pager -l\n"
                         "Inspect: sudo journalctl -u fail2ban -n 80 --no-pager\n"
                         "Validate: sudo fail2ban-client -t")
