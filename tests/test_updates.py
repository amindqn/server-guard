"""Exercise real program publication against a private filesystem, never the host."""
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from server_guard import __version__
from server_guard.cli import execute_locked, parser
from server_guard.core import Files, GuardError
from server_guard.host import Host
from server_guard.installation import CURRENT, DOCS, LAUNCHER, PAM_HELPER, PROGRAM, ToolInstaller
from server_guard.releases import GitHubSource, SOURCE_INFO, extract_source, source_version
from server_guard.updater import UpdateManager


ROOT = Path(__file__).resolve().parents[1]
SENTINELS = ["/etc/server-guard/policy.json", "/etc/server-guard/sshd-sessions.json",
    "/etc/server-guard/firewall.nft", "/etc/server-guard/mongodb.json",
    "/etc/server-guard/monitor.json", "/var/lib/server-guard/history/old.json",
    "/var/lib/server-guard/health/report.json", "/run/server-guard/sessions.json",
    "/etc/server-guard-v2ray/config.json", "/etc/ssh/sshd_config", "/etc/pam.d/sshd",
    "/home/amin/.ssh/authorized_keys", "/var/lib/mongodb/database.wt", "/etc/mongod.conf",
    "/www/server/panel/data/config.json", "/home/site/htdocs/index.html",
    "/etc/systemd/system/server-guard-health.timer"]


def candidate(directory, version=__version__):
    project = Path(directory) / "candidate"
    shutil.copytree(ROOT / "server_guard", project / "server_guard",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(ROOT / "README.md", project / "README.md")
    shutil.copytree(ROOT / "docs", project / "docs")
    (project / "server_guard/__init__.py").write_text(f'__version__ = "{version}"\n')
    return project


def installed(directory):
    files = Files(Path(directory) / "host")
    for index, name in enumerate(SENTINELS):
        files.write(name, f"Keep all existing bytes: {name}\n", 0o600 if index % 2 else 0o640)
    files.write(PROGRAM + "/server_guard/__init__.py", '__version__ = "1.4.0"\n', 0o644)
    files.write(PROGRAM + "/server_guard/cli.py",
        "import argparse\nfrom . import __version__\n"
        "def main():\n p=argparse.ArgumentParser(); p.add_argument('--version',action='version',version=__version__); p.parse_args()\n", 0o644)
    files.write(PAM_HELPER, "# Legacy standalone PAM admission helper\n", 0o755)
    files.write(LAUNCHER, f"import sys\nsys.path.insert(0, {str(files.path(PROGRAM))!r})\n"
        "from server_guard.cli import main\nmain()\n", 0o755)
    files.write(DOCS + "/README.md", "old guide", 0o644)
    files.write(SOURCE_INFO, json.dumps(GitHubSource().metadata("a" * 64)))
    return files


def snapshot(files, paths):
    result = {}
    for name in paths:
        file = files.path(name)
        stat = file.stat()
        result[name] = (file.read_bytes(), stat.st_mode, stat.st_uid, stat.st_gid)
    return result


def run_install(installer, source, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()):
        return installer.install(source, **kwargs)


def launcher_version(files):
    result = subprocess.run([sys.executable, "-I", str(files.path(LAUNCHER)), "--version"],
                            capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def archive_project(project, output):
    with tarfile.open(output, "w:gz") as archive:
        archive.add(project, arcname="repo-master", filter=lambda info: None if "__pycache__" in info.name else info)


class ToolInstallationTests(unittest.TestCase):
    def test_real_legacy_upgrade_preserves_server_data_and_access_with_private_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            files, project = installed(directory), candidate(directory)
            expected = snapshot(files, SENTINELS)
            old_modules = snapshot(files, [PROGRAM + "/server_guard/cli.py", PROGRAM + "/server_guard/__init__.py"])
            old_mask = os.umask(0o077)
            try:
                result = run_install(ToolInstaller(files.root), project, upgrade_only=True,
                                     source_info=GitHubSource().metadata("b" * 64))
            finally:
                os.umask(old_mask)
            self.assertEqual(launcher_version(files), __version__)
            self.assertEqual(snapshot(files, SENTINELS), expected)
            self.assertEqual(snapshot(files, old_modules), old_modules)
            active = files.path(CURRENT).resolve()
            self.assertEqual(active, Path(result["project"]))
            for name in [active, active / "server_guard", active / "guide", active / "guide/docs",
                         files.path(DOCS), files.path(DOCS + "/docs")]:
                self.assertEqual(name.stat().st_mode & 0o777, 0o755)
            backup = Path(result["backup"])
            self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
            self.assertEqual((backup / "etc/server-guard/policy.json").read_bytes(), expected[SENTINELS[0]][0])
            self.assertEqual(source_version(backup / "previous-program"), "1.4.0")
            self.assertFalse((backup / "var/lib/mongodb").exists())
            self.assertEqual(json.loads((backup / "manifest.json").read_text())["status"], "complete")
            metadata = json.loads(files.path(SOURCE_INFO).read_text())
            self.assertEqual(metadata["installed_version"], __version__)
            self.assertEqual(metadata["archive_sha256"], "b" * 64)

    def test_fresh_install_creates_private_empty_configuration_and_state(self):
        with tempfile.TemporaryDirectory() as directory:
            project = candidate(directory)
            installer = ToolInstaller(Path(directory) / "host")
            run_install(installer, project)
            self.assertEqual(launcher_version(installer.f), __version__)
            for name in ["/etc/server-guard", "/var/lib/server-guard"]:
                folder = installer.f.path(name)
                self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
                self.assertEqual(list(folder.iterdir()), [])

    def test_upgrade_only_refuses_an_uninstalled_host(self):
        with tempfile.TemporaryDirectory() as directory:
            installer = ToolInstaller(Path(directory) / "host")
            with self.assertRaisesRegex(GuardError, "No installed manager"):
                run_install(installer, candidate(directory), upgrade_only=True)
            self.assertFalse(installer.f.path(PROGRAM).exists())

    def test_local_upgrade_preserves_custom_source_channel_without_stale_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            files, project = installed(directory), candidate(directory)
            files.write(SOURCE_INFO, json.dumps(GitHubSource("owner/fork", "stable").metadata("f" * 64)))
            run_install(ToolInstaller(files.root), project, upgrade_only=True)
            metadata = json.loads(files.path(SOURCE_INFO).read_text())
            self.assertEqual((metadata["repository"], metadata["ref"]), ("owner/fork", "stable"))
            self.assertNotIn("archive_sha256", metadata)

    def test_pending_change_refuses_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            files, project = installed(directory), candidate(directory)
            files.write("/var/lib/server-guard/pending.json", "{}")
            expected = snapshot(files, [LAUNCHER, PAM_HELPER, SOURCE_INFO, *SENTINELS])
            with self.assertRaisesRegex(GuardError, "pending"):
                run_install(ToolInstaller(files.root), project, upgrade_only=True)
            self.assertEqual(snapshot(files, expected), expected)
            self.assertFalse(files.path(CURRENT).exists())

    def test_bad_candidate_import_or_syntax_leaves_old_launcher_working(self):
        for content in ["def invalid(:", "raise RuntimeError('bad release')"]:
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                files, project = installed(directory), candidate(directory)
                (project / "server_guard/cli.py").write_text(content)
                expected = snapshot(files, [LAUNCHER, PAM_HELPER, SOURCE_INFO, *SENTINELS])
                with self.assertRaises((GuardError, SyntaxError)):
                    run_install(ToolInstaller(files.root), project, upgrade_only=True)
                self.assertEqual(snapshot(files, expected), expected)
                self.assertEqual(launcher_version(files), "1.4.0")

    def test_failure_after_switch_restores_legacy_launcher_helper_docs_and_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            files, project = installed(directory), candidate(directory)
            expected = snapshot(files, [LAUNCHER, PAM_HELPER, SOURCE_INFO, DOCS + "/README.md", *SENTINELS])
            installer = ToolInstaller(files.root)
            publish = installer._atomic
            def fail_launcher(path, *args, **kwargs):
                if path == LAUNCHER:
                    self.assertTrue(files.path(CURRENT).is_symlink())
                    raise OSError("Simulated failed launcher publication")
                return publish(path, *args, **kwargs)
            with patch.object(installer, "_atomic", side_effect=fail_launcher):
                with self.assertRaisesRegex(OSError, "Simulated"):
                    run_install(installer, project, upgrade_only=True)
            self.assertEqual(snapshot(files, expected), expected)
            self.assertFalse(files.path(CURRENT).exists())
            self.assertFalse(files.path(DOCS + "/docs/OPERATIONS.md").exists())
            self.assertEqual(launcher_version(files), "1.4.0")

    def test_new_layout_upgrade_keeps_inflight_release_and_recovers_current_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            files, project = installed(directory), candidate(directory)
            run_install(ToolInstaller(files.root), project, upgrade_only=True)
            previous = files.path(CURRENT).resolve()
            major, minor, patch_number = __version__.split(".")
            next_version = f"{major}.{minor}.{int(patch_number) + 1}"
            (project / "server_guard/__init__.py").write_text(f'__version__="{next_version}"\n')
            installer = ToolInstaller(files.root)
            publish = installer._atomic
            def fail_launcher(path, *args, **kwargs):
                if path == LAUNCHER:
                    raise KeyboardInterrupt()
                return publish(path, *args, **kwargs)
            with patch.object(installer, "_atomic", side_effect=fail_launcher), self.assertRaises(KeyboardInterrupt):
                run_install(installer, project, upgrade_only=True)
            self.assertEqual(files.path(CURRENT).resolve(), previous)
            self.assertEqual(launcher_version(files), __version__)
            result = run_install(ToolInstaller(files.root), project, upgrade_only=True)
            self.assertEqual(launcher_version(files), next_version)
            self.assertTrue(previous.is_dir())
            self.assertEqual(source_version(previous), __version__)
            self.assertFalse((Path(result["backup"]) / "opt/server-guard/releases").exists())

    def test_downgrade_requires_explicit_option(self):
        with tempfile.TemporaryDirectory() as directory:
            files, project = installed(directory), candidate(directory, "1.3.0")
            with self.assertRaisesRegex(GuardError, "downgrade"):
                run_install(ToolInstaller(files.root), project, upgrade_only=True)
            run_install(ToolInstaller(files.root), project, upgrade_only=True, allow_downgrade=True)
            self.assertEqual(launcher_version(files), "1.3.0")

    def test_publication_holds_access_lock_and_rechecks_pending_under_it(self):
        with tempfile.TemporaryDirectory() as directory:
            files, project = installed(directory), candidate(directory)
            installer = ToolInstaller(files.root)
            validate = installer._validate
            def check_lock(program, expected):
                with files.path("/run/server-guard/management.lock").open("a") as other:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                validate(program, expected)
                files.write("/var/lib/server-guard/pending.json", "{}")
            with patch.object(installer, "_validate", side_effect=check_lock), self.assertRaisesRegex(GuardError, "pending"):
                run_install(installer, project, upgrade_only=True)
            self.assertEqual(launcher_version(files), "1.4.0")

    def test_installer_driver_options_work_without_old_update_command(self):
        from server_guard.installation import install_main
        with patch.object(sys, "argv", ["install_tool.py", "--source-root", str(ROOT), "--upgrade-only",
                "--repo", "amindqn/server-guard", "--ref", "master", "--archive-sha256", "d" * 64]), \
             patch.object(ToolInstaller, "install") as install:
            self.assertEqual(install_main(), 0)
        self.assertTrue(install.call_args.kwargs["upgrade_only"])
        self.assertEqual(install.call_args.kwargs["source_info"]["archive_sha256"], "d" * 64)


class SourceUpdateTests(unittest.TestCase):
    def fixture(self, directory):
        files = installed(directory)
        project = candidate(directory)
        archive = Path(directory) / "download.tgz"
        archive_project(project, archive)
        case = self
        class DownloadRunner:
            def __init__(self):
                self.calls = []
            def run(self, *args, **kwargs):
                self.calls.append(args)
                case.assertEqual(args[0], "curl")
                # Network I/O must never block the access rollback timer.
                with files.path("/run/server-guard/management.lock").open("a") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                shutil.copyfile(archive, args[args.index("--output") + 1])
        host = Host(files, DownloadRunner())
        files.path("/run/server-guard").mkdir(parents=True, exist_ok=True)
        return host, UpdateManager(host), archive

    def run_update(self, updater, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return updater.run(**kwargs)

    def test_real_download_fixture_upgrade_and_identical_source_noop(self):
        with tempfile.TemporaryDirectory() as directory:
            host, updater, archive = self.fixture(directory)
            expected = snapshot(host.f, SENTINELS)
            first = self.run_update(updater)
            self.assertTrue(first["changed"])
            self.assertEqual(launcher_version(host.f), __version__)
            self.assertEqual(snapshot(host.f, SENTINELS), expected)
            pointer = os.readlink(host.f.path(CURRENT))
            second = self.run_update(updater)
            self.assertFalse(second["changed"])
            self.assertEqual(os.readlink(host.f.path(CURRENT)), pointer)
            self.assertEqual(json.loads(host.f.path(SOURCE_INFO).read_text())["archive_sha256"],
                             hashlib.sha256(archive.read_bytes()).hexdigest())

    def test_check_does_not_publish_even_during_pending_change(self):
        with tempfile.TemporaryDirectory() as directory:
            host, updater, _ = self.fixture(directory)
            host.f.write("/var/lib/server-guard/pending.json", "{}")
            expected = snapshot(host.f, [LAUNCHER, SOURCE_INFO, PAM_HELPER, *SENTINELS])
            with patch.object(ToolInstaller, "install", side_effect=AssertionError("Must not install")):
                self.assertTrue(self.run_update(updater, check=True)["available"])
            self.assertEqual(snapshot(host.f, expected), expected)
            self.assertFalse(host.f.path(CURRENT).exists())

    def test_pending_update_and_bad_expected_hash_refuse_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            host, updater, _ = self.fixture(directory)
            with self.assertRaises(GuardError):
                self.run_update(updater, expected="bad")
            host.f.write("/var/lib/server-guard/pending.json", "{}")
            with self.assertRaisesRegex(GuardError, "pending"):
                self.run_update(updater)
            self.assertEqual(host.r.calls, [])

    def test_checksum_mismatch_keeps_existing_manager(self):
        with tempfile.TemporaryDirectory() as directory:
            host, updater, _ = self.fixture(directory)
            with self.assertRaisesRegex(GuardError, "checksum mismatch"):
                self.run_update(updater, expected="0" * 64)
            self.assertEqual(launcher_version(host.f), "1.4.0")

    def test_cli_download_runs_without_outer_management_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            host, _, _ = self.fixture(directory)
            with contextlib.redirect_stdout(io.StringIO()):
                execute_locked(host, parser().parse_args(["self-update", "--check"]))
            self.assertEqual(len(host.r.calls), 1)

    def test_source_defaults_and_explicit_ref_override(self):
        with tempfile.TemporaryDirectory() as directory:
            host, updater, _ = self.fixture(directory)
            host.f.path(SOURCE_INFO).unlink()
            self.run_update(updater, check=True)
            self.assertTrue(host.r.calls[-1][-1].endswith("/amindqn/server-guard/tar.gz/master"))
            self.run_update(updater, check=True, repository="owner/project", ref="v1.5.0")
            self.assertTrue(host.r.calls[-1][-1].endswith("/owner/project/tar.gz/v1.5.0"))


class SourceInspectionTests(unittest.TestCase):
    def test_version_inspection_never_executes_package(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "server_guard"
            package.mkdir()
            (package / "__init__.py").write_text('raise RuntimeError("must not execute")\n__version__="1.5.0"\n')
            self.assertEqual(source_version(directory), "1.5.0")

    def test_extractor_refuses_links_traversal_duplicate_and_invalid_archive(self):
        for name, kind in [("../escape", None), ("/absolute", None), ("repo/link", tarfile.SYMTYPE),
                ("repo/link", tarfile.LNKTYPE), ("repo/file", "duplicate"), ("repo/huge", "huge")]:
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "source.tgz"
                with tarfile.open(archive, "w:gz") as tar:
                    info = tarfile.TarInfo(name)
                    if kind == "huge":
                        info.size = 64 * 1024 ** 2 + 1
                        # Header alone: the size must be rejected before data is read.
                        tar.fileobj.write(info.tobuf())
                    elif kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                        info.type, info.linkname = kind, "/outside"
                        tar.addfile(info)
                    else:
                        tar.addfile(info)
                        if kind == "duplicate":
                            tar.addfile(info)
                with self.assertRaises(GuardError):
                    extract_source(archive, Path(directory) / "extract")
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "invalid.tgz"
            archive.write_bytes(b"not a gzip archive")
            with self.assertRaisesRegex(GuardError, "valid complete archive"):
                extract_source(archive, Path(directory) / "extract")

    def test_source_identity_rejects_bad_repository_ref_and_digest(self):
        for repository, ref in [("owner/repo;id", "master"), ("owner/repo", "../master")]:
            with self.assertRaises(GuardError):
                GitHubSource(repository, ref)
        for digest in [None, 12, "not-a-checksum"]:
            with self.assertRaises(GuardError):
                GitHubSource().metadata(digest)


if __name__ == "__main__":
    unittest.main()
