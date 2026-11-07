#!/usr/bin/python3 -I
"""PAM SSH-session admission, counted under a lock, independent of PTY/utmp.

MaxSessions=1 prevents multiplexed shell/SFTP channels. OpenSSH 9.6 opens PAM
once per authenticated transport, including tunnel-only transports. Validate
this behavior on the target package; this is not an unauthenticated socket cap.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import sys
import syslog


def process_token(pid, proc=Path("/proc")):
    try:
        raw = (proc / str(pid) / "stat").read_text()
        # comm may contain spaces or ')' characters; fields after its last ')'.
        fields = raw[raw.rfind(")") + 2:].split()
        if fields[0] == "Z":
            return None
        return fields[19]  # field 22: process start time, disambiguates reused PIDs
    except (OSError, IndexError):
        return None


def admit(ledger, user, pid, token, maximum, lookup=process_token, closing=False):
    live = [row for row in ledger if lookup(row["pid"]) == row["token"]]
    mine = {"user": user, "pid": pid, "token": token}
    if closing:
        return True, [row for row in live if row != mine]
    if mine in live:
        return True, live
    if sum(row["user"] == user for row in live) >= maximum:
        return False, live
    return True, live + [mine]


def main():
    if os.geteuid() != 0:
        return 1
    action = os.environ.get("PAM_TYPE")
    if os.environ.get("PAM_SERVICE") != "sshd" or action not in {"open_session", "close_session"}:
        return 0
    try:
        policy = json.loads(Path("/etc/server-guard/sshd-sessions.json").read_text())
        user = os.environ.get("PAM_USER", "")
        if user not in policy:
            return 0
        runtime = Path("/run/server-guard")
        runtime.mkdir(mode=0o700, exist_ok=True)
        pid = os.getppid()
        token = process_token(pid)
        if token is None:
            raise RuntimeError("PAM parent disappeared")
        with (runtime / "sessions.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            path = runtime / "sessions.json"
            ledger = json.loads(path.read_text()) if path.exists() else []
            allowed, ledger = admit(ledger, user, pid, token, policy[user],
                                    closing=action == "close_session")
            tmp = runtime / "sessions.tmp"
            tmp.write_text(json.dumps(ledger))
            tmp.chmod(0o600)
            tmp.replace(path)
        if not allowed:
            syslog.syslog(syslog.LOG_WARNING, f"server-guard: SSH session limit reached for {user}")
        return 0 if allowed else 1
    except Exception as exc:
        syslog.syslog(syslog.LOG_ERR, f"server-guard: PAM session guard error: {exc}")
        return 0 if action == "close_session" else 1


if __name__ == "__main__":
    sys.exit(main())
