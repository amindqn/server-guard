"""Transactional, configuration-preserving publication of the management tool."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from .core import Files, GuardError
from .releases import GitHubSource, SOURCE_INFO, source_version, version_tuple


PROGRAM = "/opt/server-guard"
CURRENT = PROGRAM + "/current"
LAUNCHER = "/usr/local/sbin/server-guard"
DOCS = "/usr/local/share/doc/server-guard"
PAM_HELPER = PROGRAM + "/server_guard/pam_sessions.py"
UPDATE_BACKUPS = "/var/backups/server-guard/updates"


class ToolInstaller:
    """Facade: lock -> inspect -> stage -> snapshot -> publish -> verify/restore.

    SSH, policy, state and application data are never rewritten. Launchers resolve
    current once, pinning every import to one immutable release directory.
    """
    def __init__(self, root=Path("/")):
        self.f = Files(Path(root).resolve())
        self.changed = {}

    def active_project(self):
        current = self.f.path(CURRENT)
        if current.is_symlink():
            target = current.resolve(strict=True)
            if not target.is_relative_to(self.f.path(PROGRAM + "/releases")):
                raise GuardError("The current program link points outside the managed release directory.")
            return target
        if current.exists():
            raise GuardError("Unexpected current program path; review it before updating.")
        legacy = self.f.path(PROGRAM)
        return legacy if (legacy / "server_guard/cli.py").is_file() else None

    def require_clear(self):
        if self.f.path("/var/lib/server-guard/pending.json").exists():
            raise GuardError("Confirm or roll back the pending access change before updating the manager.")

    def _directory(self, path, mode=0o755):
        """Create missing directories with explicit modes despite the root umask."""
        target = self.f.path(path)
        missing = []
        while not target.exists() and target != self.f.root:
            missing.append(target)
            target = target.parent
        for directory in reversed(missing):
            directory.mkdir(mode=mode if directory == missing[0] else 0o755)
            directory.chmod(mode if directory == missing[0] else 0o755)

    def _atomic(self, path, content=None, mode=0o644, link=None):
        target = self.f.path(path)
        if target.is_symlink() and path != CURRENT:
            raise GuardError(f"Refusing update through managed symlink: {path}")
        if path not in self.changed:
            if target.is_symlink():
                self.changed[path] = ("link", os.readlink(target))
            elif target.exists():
                stat = target.stat()
                self.changed[path] = ("file", target.read_bytes(), stat.st_mode & 0o7777, stat.st_uid, stat.st_gid)
            else:
                self.changed[path] = None
        self._write(path, content, mode, link)

    def _write(self, path, content=None, mode=0o644, link=None):
        target = self.f.path(path)
        self._directory(str(target.parent.relative_to(self.f.root)))
        if link is None:
            self.f.write(path, content, mode)
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.parent / (".guard-link-" + uuid.uuid4().hex)
        try:
            temporary.symlink_to(link)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def _restore(self):
        for path, saved in reversed(list(self.changed.items())):
            if saved is None:
                self.f.path(path).unlink(missing_ok=True)
            elif saved[0] == "link":
                self._write(path, link=saved[1])
            else:
                self._write(path, saved[1], saved[2])
                os.chown(self.f.path(path), saved[3], saved[4])

    def _backup(self, active):
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
        backup = self.f.path(UPDATE_BACKUPS + "/" + stamp)
        backup.mkdir(parents=True, mode=0o700)
        backup.chmod(0o700)
        targets = [LAUNCHER, CURRENT, SOURCE_INFO, PAM_HELPER, DOCS, "/etc/ssh", "/etc/pam.d/sshd",
                   "/etc/server-guard", "/etc/server-guard-v2ray"]
        for name in targets:
            source = self.f.path(name)
            if not (source.exists() or source.is_symlink()):
                continue
            target = backup / name.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir() and not source.is_symlink():
                shutil.copytree(source, target, symlinks=True)
            else:
                shutil.copy2(source, target, follow_symlinks=False)
        if active:
            # Copy only the active package, never old release trees or app data.
            shutil.copytree(active / "server_guard", backup / "previous-program/server_guard", symlinks=True,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (backup / "manifest.json").write_text(json.dumps({"previous_project": str(active) if active else None,
            "previous_version": source_version(active) if active else None, "status": "prepared"}, indent=2))
        return backup

    def _validate(self, program, expected):
        command = "import sys; sys.path.insert(0, sys.argv[1]); from server_guard.cli import main; sys.argv=['server-guard','--version']; main()"
        result = subprocess.run([sys.executable, "-I", "-c", command, str(program)], capture_output=True, text=True, timeout=30)
        if result.returncode or result.stdout.strip() != expected:
            raise GuardError("The candidate program failed its isolated import/version check: " + (result.stderr or "unexpected version")[-1500:])

    def install(self, source, *, upgrade_only=False, source_info=None, allow_downgrade=False):
        source = Path(source).resolve()
        lock = self.f.path("/run/server-guard/management.lock")
        lock.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        with lock.open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            return self._install(source, upgrade_only, source_info, allow_downgrade)

    def _install(self, source, upgrade_only, source_info, allow_downgrade):
        self.require_clear()
        active = self.active_project()
        if upgrade_only and (not active or not self.f.path(LAUNCHER).is_file()):
            raise GuardError("No installed manager found. Use the normal installer for a first installation.")
        version = source_version(source)
        if active and version_tuple(version) < version_tuple(source_version(active)) and not allow_downgrade:
            raise GuardError("Refusing a downgrade. Select a newer ref, or explicitly use --allow-downgrade.")
        if source_info:
            source_info = GitHubSource(source_info["repository"], source_info["ref"]).metadata(source_info["archive_sha256"])
        elif active and self.f.path(SOURCE_INFO).exists():
            previous = json.loads(self.f.path(SOURCE_INFO).read_text())
            if not isinstance(previous, dict):
                raise GuardError("Invalid installed source metadata; specify a reviewed --repo/--ref/archive checksum.")
            if previous.get("repository") and previous.get("ref"):
                origin = GitHubSource(previous["repository"], previous["ref"])
                # A local tree has no known GitHub archive digest. Retain its
                # update channel without attributing stale content to the tree.
                source_info = {"repository": origin.repository, "ref": origin.ref}
        releases = self.f.path(PROGRAM + "/releases")
        self._directory(PROGRAM + "/releases")
        stage = Path(tempfile.mkdtemp(prefix=".staging-", dir=releases))
        release = releases / (version + "-" + uuid.uuid4().hex[:12])
        backup = None
        previous_handlers = {}
        self.changed = {}
        def interrupted(signum, frame):
            raise GuardError("Installation interrupted; restoring the previous manager.")
        try:
            if threading.current_thread() is threading.main_thread():
                for sig in [signal.SIGTERM, signal.SIGHUP]:
                    previous_handlers[sig] = signal.signal(sig, interrupted)
            package = stage / "server_guard"
            package.mkdir(mode=0o755)
            package.chmod(0o755)
            files = list((source / "server_guard").glob("*.py"))
            if not files or not (source / "server_guard/pam_sessions.py").is_file():
                raise GuardError("The source package is incomplete.")
            for file in files:
                if file.is_symlink():
                    raise GuardError("Refusing a linked source module.")
                payload = file.read_bytes()
                compile(payload, str(file), "exec")
                (package / file.name).write_bytes(payload)
                (package / file.name).chmod(0o755 if file.name == "pam_sessions.py" else 0o644)
            docs = stage / "guide"
            docs.mkdir(mode=0o755)
            docs.chmod(0o755)
            guide_files = [source / "README.md", *sorted((source / "docs").glob("*.md"))]
            for file in guide_files:
                if not file.is_file() or file.is_symlink():
                    raise GuardError("The source guide is missing or linked.")
                destination = docs / ("README.md" if file == source / "README.md" else "docs/" + file.name)
                destination.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
                destination.parent.chmod(0o755)
                destination.write_bytes(file.read_bytes())
                destination.chmod(0o644)
            self._validate(stage, version)
            stage.chmod(0o755)
            stage.rename(release)
            backup = self._backup(active)
            self.require_clear()
            self._directory("/etc/server-guard", 0o700)
            self._directory("/var/lib/server-guard", 0o700)
            # Retain the stable standalone PAM path used by older installations.
            self._atomic(PAM_HELPER, (release / "server_guard/pam_sessions.py").read_bytes(), 0o755)
            for file in (release / "guide").rglob("*.md"):
                self._atomic(DOCS + "/" + str(file.relative_to(release / "guide")), file.read_bytes())
            metadata = dict(source_info or {}, installed_version=version, installed_at=time.time(), previous_backup=str(backup))
            self._atomic(SOURCE_INFO, json.dumps(metadata, indent=2) + "\n", 0o600)
            self._atomic(CURRENT, link=str(release))
            launcher = ("#!/usr/bin/python3 -I\nfrom pathlib import Path\nimport sys\n"
                        f"sys.path.insert(0, str(Path({str(self.f.path(CURRENT))!r}).resolve(strict=True)))\n"
                        "from server_guard.cli import main\nsys.exit(main())\n")
            self._atomic(LAUNCHER, launcher, 0o755)
            result = subprocess.run([sys.executable, "-I", str(self.f.path(LAUNCHER)), "--version"],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode or result.stdout.strip() != version:
                raise GuardError("The published launcher failed validation.")
            manifest = json.loads((backup / "manifest.json").read_text())
            manifest.update(status="complete", installed_version=version, installed_project=str(release))
            self.f.write(str((backup / "manifest.json").relative_to(self.f.root)), json.dumps(manifest, indent=2))
            print(f"{'Updated' if active else 'Installed'} Server Guard {version}. Recovery backup: {backup}")
            print("Existing configuration, SSH access, users/keys, monitoring history and application/database data were preserved.")
            return {"version": version, "backup": str(backup), "project": str(release)}
        except BaseException:
            try:
                if self.changed:
                    self._restore()
            except OSError as exc:
                raise GuardError(f"Update recovery needs manual attention: {exc}. Recovery backup: {backup}") from exc
            if backup:
                print(f"Update stopped; the previous manager was restored. Recovery backup: {backup}")
            raise
        finally:
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)
            if stage.exists():
                shutil.rmtree(stage)


def install_main():
    import argparse
    parser = argparse.ArgumentParser(description="Install/update only Server Guard management files.")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--upgrade-only", action="store_true")
    parser.add_argument("--allow-downgrade", action="store_true")
    parser.add_argument("--repo")
    parser.add_argument("--ref")
    parser.add_argument("--archive-sha256")
    args = parser.parse_args()
    try:
        info = None
        if any([args.repo, args.ref, args.archive_sha256]):
            info = GitHubSource(args.repo, args.ref).metadata(args.archive_sha256)
        ToolInstaller().install(args.source_root, upgrade_only=args.upgrade_only,
                                source_info=info, allow_downgrade=args.allow_downgrade)
        return 0
    except (GuardError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print(f"Installation failed: {exc}", file=sys.stderr)
        return 1
