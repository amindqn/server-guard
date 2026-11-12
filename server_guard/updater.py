"""Download/check source outside the access lock, then publish transactionally."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile

from .core import GuardError, sha256
from .installation import ToolInstaller
from .releases import DEFAULT_REF, DEFAULT_REPOSITORY, GitHubSource, SOURCE_INFO, extract_source, source_version, version_tuple


class UpdateManager:
    def __init__(self, host):
        self.h = host

    def run(self, *, check=False, repository=None, ref=None, expected=None, allow_downgrade=False):
        installer = ToolInstaller(self.h.f.root)
        if not check:
            installer.require_clear()
        active = installer.active_project()
        if not active or not self.h.f.path("/usr/local/sbin/server-guard").is_file():
            raise GuardError("No installed Server Guard found. Use the bootstrap installer first.")
        previous = {}
        if self.h.f.path(SOURCE_INFO).exists():
            previous = json.loads(self.h.f.path(SOURCE_INFO).read_text())
            if not isinstance(previous, dict):
                raise GuardError("Invalid installed source metadata; review " + SOURCE_INFO)
        source = GitHubSource(repository or previous.get("repository") or DEFAULT_REPOSITORY,
                              ref or previous.get("ref") or DEFAULT_REF)
        if expected:
            source.metadata(expected)  # validate the hash before downloading
        current = source_version(active)
        print(f"Installed: {current}\nSource: {source.repository} at {source.ref}", flush=True)
        with tempfile.TemporaryDirectory(prefix="server-guard-update-") as directory:
            archive = Path(directory) / "source.tar.gz"
            self.h.r.run("curl", "--fail", "--show-error", "--silent", "--location", "--proto", "=https",
                         "--proto-redir", "=https", "--tlsv1.2", "--connect-timeout", "20", "--max-time", "300",
                         "--max-filesize", "33554432", "--output", archive, source.archive_url,
                         capture=False, timeout=310)
            digest = sha256(archive)
            if expected and digest != expected.lower():
                raise GuardError("Source archive checksum mismatch; the installed manager was not changed.")
            project = extract_source(archive, Path(directory) / "source")
            target = source_version(project)
            same = (current == target and previous.get("repository") == source.repository and previous.get("ref") == source.ref
                    and previous.get("archive_sha256") == digest)
            print(f"Available: {target}\nSource archive SHA256: {digest}", flush=True)
            if check:
                print("Already current." if same else "A different source is available. Run self-update to install it; configuration and data are retained.")
                return {"version": target, "changed": False, "available": not same}
            if same:
                print("Already current. No installed files changed.")
                return {"version": target, "changed": False, "available": False}
            if version_tuple(target) < version_tuple(current) and not allow_downgrade:
                raise GuardError("The selected ref is older than the installed version. Use a newer ref or explicitly pass --allow-downgrade.")
            result = installer.install(project, upgrade_only=True, source_info=source.metadata(digest),
                                       allow_downgrade=allow_downgrade)
            return dict(result, changed=True, available=False)
