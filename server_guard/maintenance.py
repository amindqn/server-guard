"""Reviewable storage cleanup and reversible application CPU scheduling changes."""
from __future__ import annotations

import heapq
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from .core import GuardError
from .health import clean, size


SCANS = "/var/lib/server-guard/storage-scans"
TUNING = "/var/lib/server-guard/cpu-priorities.json"
APPLICATION_UNITS = {"mongodb": "mongod.service", "v2ray": "server-guard-v2ray.service",
                     "nginx": "nginx.service", "mysql": "mysql.service", "mariadb": "mariadb.service"}


def absolute_path(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or any(ord(c) < 32 or ord(c) == 127 for c in str(path)):
        raise GuardError("Use an absolute path without .. or control characters.")
    return str(path)


class StorageManager:
    """Inventory is bounded/read-only. Removal requires a saved exact-file identity."""
    def __init__(self, host, clock=time.monotonic):
        self.h, self.f, self.clock = host, host.f, clock

    @staticmethod
    def identity(info):
        return {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size,
                "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
                "uid": info.st_uid, "links": info.st_nlink}

    def parent_fd(self, path):
        """Walk directory descriptors with NOFOLLOW, including every parent."""
        parts = Path(absolute_path(path)).parts[1:]
        if not parts:
            raise GuardError("Select a file, not the filesystem root.")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(self.f.root, flags)
        try:
            for part in parts[:-1]:
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd, parts[-1]
        except BaseException:
            os.close(fd)
            raise

    def directory(self, path):
        # A no-follow directory open prevents a symlink root from broadening a scan.
        parent, name = self.parent_fd(path) if path != "/" else (None, None)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent) if parent is not None else os.open(self.f.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        finally:
            if parent is not None:
                os.close(parent)
        return fd

    def scan(self, path="/var", minimum_mib=100, limit=20, progress=None, max_entries=100000, max_seconds=30):
        path = absolute_path(path)
        if not 1 <= minimum_mib <= 1048576 or not 1 <= limit <= 100:
            raise GuardError("Minimum must be 1..1048576 MiB; displayed files 1..100.")
        if not 1 <= max_entries <= 10000000 or not 1 <= max_seconds <= 3600:
            raise GuardError("Scan budget must be 1..10000000 entries and 1..3600 seconds.")
        fd = self.directory(path)
        started, entries, errors, skipped, heap = self.clock(), 0, 0, 0, []
        truncated, reason, file_count, directory_count = False, "", 0, 0
        skipped_paths = []
        try:
            device = os.fstat(fd).st_dev
            def onerror(exc):
                nonlocal errors
                errors += 1

            def budget():
                nonlocal entries, truncated, reason
                elapsed = self.clock() - started
                if entries >= max_entries or elapsed >= max_seconds:
                    truncated = True
                    reason = "entry limit" if entries >= max_entries else "time limit"
                    return False
                entries += 1
                if progress and entries % 1000 == 0:
                    progress(entries, elapsed)
                return True

            def priority(name, base):
                candidate = str(Path(path) / base / name)
                if "backup" in name.casefold():
                    return (0, name.casefold())
                preferred = ("/var/backups", "/www/backup", "/root", "/home", "/srv", "/mnt", "/media")
                rank = next((i + 1 for i, root in enumerate(preferred)
                    if candidate == root or root.startswith(candidate + "/") or candidate.startswith(root + "/")), 100)
                return (rank, name.casefold())

            def skip(candidate):
                nonlocal skipped
                skipped += 1
                if len(skipped_paths) < 20:
                    skipped_paths.append(candidate)

            # fwalk pins each traversed directory and never follows directory symlinks.
            for base, folders, files, dirfd in os.fwalk(".", dir_fd=fd, follow_symlinks=False,
                                                       onerror=onerror):
                if self.clock() - started >= max_seconds or entries >= max_entries:
                    truncated = True
                    reason = "entry limit" if entries >= max_entries else "time limit"
                    break
                relative = Path(base)
                if len(relative.parts) > 32:
                    for folder in folders:
                        skip(str(Path(path) / relative / folder))
                    folders[:] = []
                # Visit likely backup locations before package/application trees
                # consume a bounded scan. This changes order, not coverage rules.
                folders.sort(key=lambda name: priority(name, relative))
                for folder in list(folders):
                    if not budget():
                        break
                    directory_count += 1
                    absolute = str(Path(path) / relative / folder)
                    try:
                        info = os.stat(folder, dir_fd=dirfd, follow_symlinks=False)
                        if info.st_dev != device or stat.S_ISLNK(info.st_mode) or absolute in {"/proc", "/sys", "/dev", "/run"}:
                            folders.remove(folder)
                            skip(absolute)
                    except OSError:
                        folders.remove(folder)
                        errors += 1
                if truncated:
                    break
                for name in files:
                    if not budget():
                        break
                    file_count += 1
                    try:
                        info = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                        if not stat.S_ISREG(info.st_mode) or info.st_dev != device or info.st_size < minimum_mib * 1024 ** 2:
                            continue
                        absolute = str(Path(path) / relative / name)
                        allocated = info.st_blocks * 512
                        item = {"path": absolute, "identity": self.identity(info), "allocated": allocated,
                                "modified": info.st_mtime, "removable": self.allowed(absolute)}
                        record = (allocated, absolute, item)
                        if len(heap) < limit:
                            heapq.heappush(heap, record)
                        elif record[:2] > heap[0][:2]:
                            heapq.heapreplace(heap, record)
                    except OSError:
                        errors += 1
                if truncated:
                    break
        finally:
            os.close(fd)
        report = {"id": uuid.uuid4().hex, "time": time.time(), "root": path, "entries": entries,
                  "errors": errors, "skipped": skipped, "truncated": truncated,
                  "truncated_reason": reason, "file_entries": file_count, "directory_entries": directory_count,
                  "minimum_mib": minimum_mib, "max_entries": max_entries, "max_seconds": max_seconds,
                  "skipped_paths": skipped_paths,
                  "seconds": round(self.clock() - started, 2), "files": [row[2] for row in sorted(heap, reverse=True)]}
        self.f.path(SCANS).mkdir(parents=True, mode=0o700, exist_ok=True)
        self.f.write(SCANS + "/" + report["id"] + ".json", json.dumps(report, indent=2))
        for old in sorted(self.f.path(SCANS).glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[10:]:
            old.unlink(missing_ok=True)
        return report

    @staticmethod
    def allowed(path):
        parts = Path(path).parts
        blocked = {".ssh", ".gnupg", "mongodb", "mongod", "mysql", "mariadb", "postgresql", "redis", "pgdata", "databases", "db", "server-guard", "server-guard-retained"}
        if blocked.intersection(parts) or path.lower().endswith((".journal", ".journal~", ".wt", ".wti", ".ibd", ".myd", ".myi", ".mdb", ".sqlite", ".sqlite3", ".db", ".rdb", ".aof", ".wal")) or Path(path).name.startswith("WiredTiger"):
            return False
        roots = ("/home/", "/root/", "/srv/", "/tmp/", "/var/tmp/", "/var/backups/", "/www/backup/", "/var/log/")
        return path.startswith(roots)

    @staticmethod
    def show(report):
        print(f"STORAGE SCAN {report['id']} | {clean(report['root'])} | {report['entries']} entries checked | {report['seconds']}s")
        print(f"Coverage: {'PARTIAL: ' + report.get('truncated_reason', 'time/entry limit') + ' reached' if report['truncated'] else 'completed within scan limits'}; {report['errors']} errors; {report['skipped']} symlinks/mounts/deep directories skipped.")
        for path in report.get("skipped_paths", []):
            print("Skipped (scan separately if needed): " + clean(path))
        print("Ranked by allocated disk bytes; sparse files may have much larger logical sizes.")
        for i, item in enumerate(report["files"], 1):
            print(f" {i:>3} {size(item['allocated']):>12} allocated | {size(item['identity']['size']):>12} logical | {'review/delete' if item['removable'] else 'inspect only'} | {clean(item['path'])}")
        if not report["files"]:
            print(f"No matching files found in the checked portion (minimum {report.get('minimum_mib', '?')} MiB).")
        if report["truncated"]:
            print("This is not proof that no other large files exist. Scan /var/backups, /www/backup, /root or /home directly, lower --min-mib, or raise --max-entries/--max-seconds.")
        print("No files deleted. Review one listed item with health delete SCAN_ID ITEM; deleting requires --yes.")

    def item(self, scan_id, index):
        if not re.fullmatch(r"[a-f0-9]{32}", scan_id):
            raise GuardError("Use the storage scan ID printed by health files.")
        try:
            report = json.loads(self.f.path(SCANS + "/" + scan_id + ".json").read_text())
            if time.time() - report["time"] > 3600:
                raise GuardError("The storage scan is older than one hour. Scan again before deleting.")
            if index < 1:
                raise IndexError()
            return report["files"][index - 1]
        except (OSError, ValueError, IndexError, KeyError):
            raise GuardError("Storage scan or item not found. Run health files again.") from None

    def open_handles(self, identity):
        """Best-effort current-open check; incomplete coverage refuses deletion."""
        started, count = self.clock(), 0
        for process in self.f.path("/proc").iterdir():
            if not process.name.isdigit():
                continue
            try:
                with os.scandir(process / "fd") as descriptors:
                    for descriptor in descriptors:
                        count += 1
                        if count > 100000 or self.clock() - started > 10:
                            raise GuardError("Open-file inspection reached its limit. Use the application's own retention tools.")
                        try:
                            info = descriptor.stat(follow_symlinks=True)
                            if info.st_dev == identity["device"] and info.st_ino == identity["inode"]:
                                return True
                        except FileNotFoundError:
                            pass
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError:
                raise GuardError("Could not inspect all process file handles; refusing deletion.") from None
        return False

    def delete(self, scan_id, index, yes=False):
        item = self.item(scan_id, index)
        path, identity = absolute_path(item["path"]), item["identity"]
        print(f"Selected: {clean(path)} | {size(item['allocated'])} allocated | {size(identity['size'])} logical")
        if not self.allowed(path):
            raise GuardError("This path is inspect-only. Use the application/database/package's supported maintenance tools.")
        if not yes:
            print("Preview only. Permanent deletion is not recoverable by SSH rollback. Repeat with --yes after reviewing the file and your backup.")
            return
        self.h.tx.require_clear()
        parent, name = self.parent_fd(path)
        quarantine, qfd = None, None
        moved = False
        try:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(current.st_mode) or self.identity(current) != identity or current.st_nlink != 1:
                raise GuardError("File changed, is not a regular file or has hard links. Scan again; nothing deleted.")
            if self.open_handles(identity):
                raise GuardError("The file is open by a process. Use log rotation or application maintenance; nothing deleted.")
            # Move into a private pinned directory before deleting. If the source
            # name is swapped concurrently, preserve the unexpected object here.
            quarantine = ".server-guard-review-" + uuid.uuid4().hex
            os.mkdir(quarantine, mode=0o700, dir_fd=parent)
            qfd = os.open(quarantine, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            info = os.fstat(qfd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise GuardError("Private review directory changed; refusing deletion.")
            os.rename(name, "selected", src_dir_fd=parent, dst_dir_fd=qfd)
            moved = True
            after = os.stat("selected", dir_fd=qfd, follow_symlinks=False)
            fields = self.identity(after)
            fields.pop("ctime_ns")  # rename may legitimately change ctime
            if not stat.S_ISREG(after.st_mode) or fields != {k: v for k, v in identity.items() if k != "ctime_ns"}:
                raise GuardError(f"Concurrent file change. Nothing deleted; retained for recovery at {Path(path).parent / quarantine / 'selected'}")
            os.unlink("selected", dir_fd=qfd)
            moved = False
            print(f"Deleted the reviewed file. Up to {size(item['allocated'])} may be reclaimed; open races/snapshots can delay space recovery. Run health check to verify.")
        finally:
            if qfd is not None:
                os.close(qfd)
            if quarantine and not moved:
                os.rmdir(quarantine, dir_fd=parent)
            os.close(parent)


class MaintenanceActions:
    """Command facade for named cleanup and runtime scheduling, never arbitrary shell."""
    def __init__(self, host):
        self.h, self.f, self.r = host, host.f, host.r

    def cleanup(self, action, days=14, yes=False):
        if action not in {"apt-cache", "journal"} or not 7 <= days <= 3650:
            raise GuardError("Choose apt-cache or journal; journal retention must be 7..3650 days.")
        command = ("apt-get", "clean") if action == "apt-cache" else ("journalctl", f"--vacuum-time={days}d")
        print("Plan:", " ".join(command))
        print("Removes downloaded APT package archives; installed packages remain." if action == "apt-cache" else
              f"Deletes archived journal files older than {days} days; active journals may keep extra space. Historical log evidence is permanently removed.")
        if not yes:
            print("Preview only. Use --yes to execute this cleanup.")
            return
        self.h.tx.require_clear()
        before = os.statvfs(self.f.root)
        self.r.run(*command, capture=False, timeout=120)
        after = os.statvfs(self.f.root)
        print(f"Root filesystem available-space change: {size((after.f_bavail - before.f_bavail) * after.f_frsize)}. Check separate /var mounts with health check.")

    def cpu_weight(self, service, weight=None, reset=False, yes=False):
        if service not in APPLICATION_UNITS or (not reset and (type(weight) is not int or not 1 <= weight <= 10000)):
            raise GuardError("Choose an offered application service and a CPU weight from 1..10000, or --reset.")
        unit = APPLICATION_UNITS[service]
        print(f"Plan: {'restore prior CPU weight for' if reset else f'set CPU weight {weight} for'} {unit} (runtime only, no restart).")
        print("CPU weight shares CPU under contention; it does not add CPU capacity or impose a hard cap. Lower weights give other workloads more opportunity.")
        if not yes:
            print("Preview only. Use --yes after reviewing application impact.")
            return
        self.h.tx.require_clear()
        boot = self.f.path("/proc/sys/kernel/random/boot_id").read_text().strip()
        saved = json.loads(self.f.path(TUNING).read_text()) if self.f.path(TUNING).exists() else {}
        if saved.get("boot") != boot:
            saved = {"boot": boot, "units": {}}
        if reset:
            if unit not in saved["units"]:
                raise GuardError("No CPU change recorded for this service in this boot. Runtime changes disappear on reboot.")
            original = saved["units"][unit]
            value = original
        else:
            result = self.r.run("systemctl", "show", unit, "-p", "LoadState", "-p", "CPUWeight", timeout=8)
            values = dict(row.split("=", 1) for row in result.stdout.splitlines() if "=" in row)
            if values.get("LoadState") != "loaded":
                raise GuardError("Application unit is not loaded; nothing changed.")
            original = values.get("CPUWeight", "")
            if original in {"[not set]", "18446744073709551615", ""}:
                original = ""
            elif not original.isdigit() or not 1 <= int(original) <= 10000:
                raise GuardError("Could not safely read the current CPU weight.")
            saved["units"].setdefault(unit, original)
            value = str(weight)
            self.f.write(TUNING, json.dumps(saved, indent=2))
        self.r.run("systemctl", "set-property", "--runtime", unit, "CPUWeight=" + value, timeout=15)
        if reset:
            del saved["units"][unit]
            self.f.write(TUNING, json.dumps(saved, indent=2))
        print("Runtime CPU scheduling updated. Monitor application latency and several CPU/pressure samples before making further changes.")
