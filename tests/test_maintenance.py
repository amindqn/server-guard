import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from server_guard.core import Files, GuardError
from server_guard.host import Host
from server_guard.maintenance import (SCANS, TUNING, MaintenanceActions, StorageManager)
from server_guard.health import MONITOR_TIMER, MONITOR_UNIT
import test_uninstall


class MaintenanceRunner:
    def __init__(self):
        self.calls = []

    def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        output = "LoadState=loaded\nCPUWeight=200\n" if args[:2] == ("systemctl", "show") else ""
        return subprocess.CompletedProcess(args, 0, output, "")


class StorageTests(unittest.TestCase):
    def fixture(self, root):
        host = Host(Files(root), MaintenanceRunner())
        host.f.path("/proc").mkdir()
        host.f.write("/home/operator/archive.tar", b"a" * 1024 ** 2)
        return host, StorageManager(host)

    def delete(self, storage, report, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return storage.delete(report["id"], 1, **kwargs)

    def test_inventory_is_read_only_and_deletion_requires_explicit_yes(self):
        with tempfile.TemporaryDirectory() as root:
            host, storage = self.fixture(root)
            report = storage.scan("/home", minimum_mib=1)
            self.assertEqual(report["files"][0]["path"], "/home/operator/archive.tar")
            path = host.f.path("/home/operator/archive.tar")
            before = path.read_bytes()
            self.delete(storage, report)
            self.assertEqual(path.read_bytes(), before)
            self.delete(storage, report, yes=True)
            self.assertFalse(path.exists())
            self.assertEqual(list(path.parent.glob(".server-guard-review-*")), [])
            self.assertEqual(host.r.calls, [])

    def test_changed_file_identity_and_hard_links_refuse_deletion(self):
        for change in ["contents", "hardlink"]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as root:
                host, storage = self.fixture(root)
                report = storage.scan("/home", minimum_mib=1)
                path = host.f.path("/home/operator/archive.tar")
                if change == "contents":
                    with path.open("ab") as stream:
                        stream.write(b"changed")
                else:
                    os.link(path, path.parent / "also.tar")
                with self.assertRaises(GuardError):
                    self.delete(storage, report, yes=True)
                self.assertTrue(path.exists())

    def test_active_open_file_is_not_removed(self):
        with tempfile.TemporaryDirectory() as root:
            host, storage = self.fixture(root)
            report = storage.scan("/home", minimum_mib=1)
            fd = host.f.path("/proc/123/fd")
            fd.mkdir(parents=True)
            (fd / "9").symlink_to(host.f.path("/home/operator/archive.tar"))
            with self.assertRaisesRegex(GuardError, "open by a process"):
                self.delete(storage, report, yes=True)

    def test_sensitive_data_and_configuration_are_inspect_only(self):
        for path in ["/var/lib/mongodb/data", "/srv/mysql/data", "/etc/shadow", "/usr/bin/example",
                     "/home/operator/.ssh/key", "/var/log/journal/example.journal", "/var/backups/server-guard/private"]:
            with self.subTest(path=path):
                self.assertFalse(StorageManager.allowed(path))
        self.assertTrue(StorageManager.allowed("/var/backups/old-release.tar.gz"))
        self.assertTrue(StorageManager.allowed("/var/log/nginx/access.log.9.gz"))

    def test_symlink_scan_root_and_parent_replacement_cannot_redirect_removal(self):
        with tempfile.TemporaryDirectory() as root:
            host, storage = self.fixture(root)
            host.f.path("/link").symlink_to(host.f.path("/home"))
            with self.assertRaises(OSError):
                storage.scan("/link", minimum_mib=1)
            report = storage.scan("/home", minimum_mib=1)
            directory = host.f.path("/home/operator")
            directory.rename(host.f.path("/home/saved"))
            directory.symlink_to(host.f.path("/home/saved"))
            with self.assertRaises(OSError):
                self.delete(storage, report, yes=True)
            self.assertTrue(host.f.path("/home/saved/archive.tar").exists())

    def test_scan_bounds_and_permission_coverage_are_explicit(self):
        with tempfile.TemporaryDirectory() as root:
            host, storage = self.fixture(root)
            report = storage.scan("/home", minimum_mib=1, max_entries=1)
            self.assertTrue(report["truncated"])
            self.assertLessEqual(report["entries"], 1)

    def test_backup_folder_is_visited_before_large_unrelated_tree_uses_budget(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), MaintenanceRunner())
            for number in range(5):
                host.f.write(f"/scan/aaa-packages/tiny{number}", "small")
            host.f.write("/scan/z-backups/archive.tar", b"a" * 1024 ** 2)
            report = StorageManager(host).scan("/scan", minimum_mib=1, max_entries=3)
            self.assertTrue(report["truncated"])
            self.assertEqual(report["files"][0]["path"], "/scan/z-backups/archive.tar")
            self.assertEqual(report["truncated_reason"], "entry limit")

    def test_last_budget_entry_is_inspected_and_empty_partial_result_is_explained(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), MaintenanceRunner())
            host.f.write("/scan/archive.tar", b"a" * 1024 ** 2)
            storage = StorageManager(host)
            report = storage.scan("/scan", minimum_mib=1, max_entries=1)
            self.assertEqual(len(report["files"]), 1)
            report = storage.scan("/scan", minimum_mib=500, max_entries=1)
            report["truncated"] = True
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                storage.show(report)
            self.assertIn("minimum 500 MiB", output.getvalue())
            self.assertIn("not proof that no other large files exist", output.getvalue())

    def test_progress_is_emitted_for_small_files_and_scan_budget_can_be_increased(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), MaintenanceRunner())
            for number in range(1005):
                host.f.write(f"/scan/tiny{number}", "small")
            progress = []
            report = StorageManager(host).scan("/scan", minimum_mib=1, max_entries=2000,
                                              progress=lambda *args: progress.append(args))
            self.assertEqual(progress[0][0], 1000)
            self.assertFalse(report["truncated"])
            self.assertEqual(report["file_entries"], 1005)
            with self.assertRaises(GuardError):
                StorageManager(host).scan("/scan", max_entries=0)

    def test_stale_inventory_and_pending_access_change_block_deletion(self):
        with tempfile.TemporaryDirectory() as root:
            host, storage = self.fixture(root)
            report = storage.scan("/home", minimum_mib=1)
            host.f.write("/var/lib/server-guard/pending.json", '{"id":"pending"}')
            with self.assertRaises(GuardError):
                self.delete(storage, report, yes=True)
            host.f.path("/var/lib/server-guard/pending.json").unlink()
            report["time"] = time.time() - 3601
            host.f.write(SCANS + "/" + report["id"] + ".json", json.dumps(report))
            with self.assertRaises(GuardError):
                self.delete(storage, report, yes=True)
            self.assertTrue(host.f.path("/home/operator/archive.tar").exists())

    def test_concurrent_name_swap_is_preserved_instead_of_deleting_wrong_file(self):
        with tempfile.TemporaryDirectory() as root:
            host, storage = self.fixture(root)
            report = storage.scan("/home", minimum_mib=1)
            real_rename = os.rename
            source = host.f.path("/home/operator/archive.tar")
            def swap(*args, **kwargs):
                source.unlink()
                source.write_bytes(b"replacement that must survive")
                return real_rename(*args, **kwargs)
            with patch("server_guard.maintenance.os.rename", side_effect=swap), self.assertRaisesRegex(GuardError, "retained for recovery"):
                self.delete(storage, report, yes=True)
            retained = list(source.parent.glob(".server-guard-review-*/selected"))
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].read_bytes(), b"replacement that must survive")


class MaintenanceActionTests(unittest.TestCase):
    def fixture(self, root):
        host = Host(Files(root), MaintenanceRunner())
        host.f.write("/proc/sys/kernel/random/boot_id", "boot-one")
        return host, MaintenanceActions(host)

    def test_cleanup_preview_does_not_execute_and_actual_command_is_allowlisted(self):
        with tempfile.TemporaryDirectory() as root:
            host, actions = self.fixture(root)
            with contextlib.redirect_stdout(io.StringIO()):
                actions.cleanup("journal", 14)
                self.assertEqual(host.r.calls, [])
                actions.cleanup("journal", 14, yes=True)
            self.assertEqual(host.r.calls[0][0], ("journalctl", "--vacuum-time=14d"))
            with self.assertRaises(GuardError):
                actions.cleanup("everything", yes=True)
            with self.assertRaises(GuardError):
                actions.cleanup("journal", 1, yes=True)

    def test_cpu_weight_remembers_original_once_and_can_restore_without_restart(self):
        with tempfile.TemporaryDirectory() as root:
            host, actions = self.fixture(root)
            with contextlib.redirect_stdout(io.StringIO()):
                actions.cpu_weight("v2ray", 25, yes=True)
                actions.cpu_weight("v2ray", 50, yes=True)
                actions.cpu_weight("v2ray", reset=True, yes=True)
            mutations = [args for args, _ in host.r.calls if args[:2] == ("systemctl", "set-property")]
            self.assertEqual([args[-1] for args in mutations], ["CPUWeight=25", "CPUWeight=50", "CPUWeight=200"])
            self.assertTrue(all("--runtime" in args for args in mutations))
            self.assertEqual(json.loads(host.f.path(TUNING).read_text())["units"], {})

    def test_cpu_control_cannot_target_ssh_and_old_boot_snapshot_is_not_reapplied(self):
        with tempfile.TemporaryDirectory() as root:
            host, actions = self.fixture(root)
            with self.assertRaises(GuardError):
                actions.cpu_weight("ssh", 10, yes=True)
            with contextlib.redirect_stdout(io.StringIO()):
                actions.cpu_weight("nginx", 25, yes=True)
            host.f.write("/proc/sys/kernel/random/boot_id", "boot-two")
            count = len(host.r.calls)
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(GuardError):
                actions.cpu_weight("nginx", reset=True, yes=True)
            self.assertEqual(len(host.r.calls), count)

    def test_pending_change_blocks_cleanup_and_scheduling_mutations(self):
        with tempfile.TemporaryDirectory() as root:
            host, actions = self.fixture(root)
            host.f.write("/var/lib/server-guard/pending.json", '{"id":"pending"}')
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(GuardError):
                    actions.cleanup("apt-cache", yes=True)
                with self.assertRaises(GuardError):
                    actions.cpu_weight("nginx", 10, yes=True)
            self.assertEqual(host.r.calls, [])

    def test_uninstall_stops_monitor_before_deleting_command(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = test_uninstall.UninstallTests().fixture(root)
            host.f.write(MONITOR_UNIT, "[Service]\nExecStart=/usr/local/sbin/server-guard health check --json\n")
            host.f.write(MONITOR_TIMER, "[Timer]\nOnBootSec=2min\n")
            with contextlib.redirect_stdout(io.StringIO()):
                backup = manager.remove()
            self.assertFalse(host.f.path(MONITOR_UNIT).exists())
            self.assertFalse(host.f.path(MONITOR_TIMER).exists())
            self.assertTrue((backup / MONITOR_UNIT.lstrip("/")).exists())
            commands = [args for args, _ in host.r.calls]
            self.assertIn(("systemctl", "disable", "--now", "server-guard-health.timer"), commands)
            self.assertIn(("systemctl", "stop", "server-guard-health.service"), commands)


if __name__ == "__main__":
    unittest.main()
