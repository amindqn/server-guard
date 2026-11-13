"""Bounded, descriptor-anchored inspection of selected security-critical files."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import PurePosixPath
import stat
import time

from .core import GuardError, POLICY, username
from .defense_config import CONFIG, DATABASE, JAIL, TIMER, UNIT


@contextmanager
def opened(files, name, directory=False):
    """Never follow a link or block on a FIFO, including parent directories."""
    path = PurePosixPath(name)
    if not path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
        raise GuardError("Unsafe integrity path.")
    descriptors = [os.open(files.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    try:
        for part in path.parts[1:-1]:
            descriptors.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptors[-1]))
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if directory else 0)
        descriptors.append(os.open(path.name, flags, dir_fd=descriptors[-1]))
        yield descriptors[-1]
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def file_state(files, name, directory=False):
    try:
        with opened(files, name, directory) as descriptor:
            before = os.fstat(descriptor)
            identity = {"uid": before.st_uid, "gid": before.st_gid, "mode": stat.S_IMODE(before.st_mode)}
            if directory:
                children, subdirectories = [], []
                # Do not allocate an unbounded list from a hostile directory.
                with os.scandir(descriptor) as entries:
                    for item in entries:
                        children.append(item.name)
                        if item.is_dir(follow_symlinks=False):
                            subdirectories.append(item.name)
                        if len(children) > 128:
                            raise GuardError("Security directory exceeds the 128-entry limit.")
                identity.update(kind="directory", children=sorted(children), subdirectories=sorted(subdirectories))
            else:
                if not stat.S_ISREG(before.st_mode) or before.st_size > 2 * 1024 ** 2:
                    raise GuardError("Expected a regular security file of at most 2 MiB.")
                digest, size = hashlib.sha256(), 0
                while chunk := os.read(descriptor, 65536):
                    size += len(chunk)
                    if size > 2 * 1024 ** 2:
                        raise GuardError("Security file grew beyond its read limit.")
                    digest.update(chunk)
                identity.update(kind="file", sha256=digest.hexdigest(), size=size)
            after = os.fstat(descriptor)
            if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise GuardError("Security path changed during inspection.")
            return identity
    except FileNotFoundError:
        return {"kind": "missing"}
    except (OSError, GuardError) as exc:
        return {"kind": "error", "error": str(exc)}


class IntegrityMonitor:
    """A small security-file inventory; not a whole-host malware scanner."""
    def __init__(self, host):
        self.h = host

    def key_paths(self, users):
        homes = {}
        try:
            with opened(self.h.f, "/etc/passwd") as descriptor:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 ** 2:
                    raise GuardError("Cannot safely inspect local account home directories.")
                payload = bytearray()
                while chunk := os.read(descriptor, 65536):
                    payload.extend(chunk)
                    if len(payload) > 2 * 1024 ** 2:
                        raise GuardError("Local account database exceeded its size limit.")
                for line in payload.decode().splitlines():
                    fields = line.split(":")
                    if len(fields) == 7:
                        homes[fields[0]] = fields[5]
        except FileNotFoundError:
            pass
        paths = []
        for name in users:
            name = username(name)
            home = PurePosixPath(homes.get(name, f"/home/{name}"))
            if not home.is_absolute() or ".." in home.parts:
                raise GuardError("Review the managed account's nonstandard home directory: " + name)
            paths.append(str(home / ".ssh/authorized_keys"))
        return paths

    def capture(self, previous=None):
        fixed = [POLICY, CONFIG, JAIL, DATABASE, TIMER, UNIT, "/etc/passwd", "/etc/group", "/etc/shadow",
            "/etc/gshadow", "/etc/sudoers", "/etc/ld.so.preload", "/etc/crontab", "/etc/rc.local",
            "/etc/fail2ban/jail.conf", "/etc/fail2ban/jail.local", "/etc/fail2ban/fail2ban.conf", "/etc/fail2ban/fail2ban.local",
            "/etc/server-guard/firewall.nft", "/etc/server-guard/sshd-sessions.json",
            "/etc/ssh/server-guard.conf", "/etc/ssh/server-guard-users.conf",
            "/etc/apt/apt.conf.d/90-server-guard", "/etc/systemd/system/server-guard-firewall.service",
            "/etc/systemd/system/server-guard-health.timer", "/etc/systemd/system/server-guard-health.service",
            "/etc/server-guard-v2ray/config.json", "/etc/server-guard/mongodb.json", "/etc/mongod.conf",
            "/usr/local/sbin/server-guard", "/opt/server-guard/server_guard/pam_sessions.py",
            "/root/.ssh/authorized_keys", "/var/spool/cron/crontabs/root"]
        watches = dict((previous or {}).get("watches", {}))
        watches.update({name: False for name in fixed})
        directories = ["/etc/ssh", "/etc/ssh/sshd_config.d", "/etc/pam.d", "/etc/sudoers.d", "/etc/cron.d",
                       "/etc/apt/apt.conf.d", "/etc/fail2ban/jail.d", "/etc/fail2ban/fail2ban.d"]
        state = self.h.store.load()
        fixed_keys = self.key_paths(state["users"])
        watches.update({name: False for name in fixed_keys})
        observations, started, total = {}, time.monotonic(), 0
        for name in directories:
            watches[name] = True
            observation = file_state(self.h.f, name, True)
            observations[name] = observation
            for child in observation.get("children", []):
                watches[name + "/" + child] = child in observation.get("subdirectories", [])
        # The explicitly inspected subdirectory is a directory, not a file.
        for name in directories:
            watches[name] = True
        if len(watches) > 500:
            raise GuardError("Integrity inventory exceeds 500 paths; no baseline was accepted.")
        for name, directory in sorted(watches.items()):
            if name not in observations:
                observations[name] = file_state(self.h.f, name, directory)
            total += observations[name].get("size", 0)
            if total > 20 * 1024 ** 2 or time.monotonic() - started > 20:
                raise GuardError("Integrity inventory exceeded its 20 MiB/20-second budget; coverage is incomplete.")
        return {"schema": 1, "time": time.time(), "watches": watches, "entries": observations}

    @staticmethod
    def require_complete(snapshot):
        failed = [name for name, info in snapshot["entries"].items() if info["kind"] == "error"]
        if failed:
            raise GuardError("Could not establish a complete trusted baseline. Review linked/oversized/inaccessible paths: "
                             + ", ".join(repr(name) for name in failed[:8]))

    @staticmethod
    def compare(baseline, current):
        findings = []
        for name in sorted(set(baseline["entries"]) | set(current["entries"])):
            before, after = baseline["entries"].get(name), current["entries"].get(name)
            if after and after.get("kind") == "error":
                findings.append({"status": "UNKNOWN", "path": name, "detail": "Could not safely inspect this path."})
            elif before != after:
                findings.append({"status": "CRITICAL", "path": name, "detail": "Content, ownership, permissions, presence or directory entries changed."})
        return findings
