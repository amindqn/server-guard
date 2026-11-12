"""Removal contract exercised against an isolated filesystem, never the host."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from server_guard.core import Files, GuardError, SSHBuilder
from server_guard.host import FIREWALL_SERVICE, Host
from server_guard.uninstall import (CONFIG, DOCS, EGRESS_UNIT, FW_UNIT, LAUNCHER,
    NATIVE_FIREWALL, OLD_HELPER, PAM, PROGRAM, RETAINED, STATE, UninstallManager)


class RuntimeRunner:
    def __init__(self, fail=None):
        self.calls, self.fail = [], fail

    def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.fail and args[:len(self.fail)] == self.fail:
            raise GuardError("Injected validation failure")
        return subprocess.CompletedProcess(args, 1 if args[:2] == ("nft", "list") else 0, "", "")


class UninstallTests(unittest.TestCase):
    def test_uninstall_after_versioned_update_detaches_runtime_and_preserves_data(self):
        from server_guard.installation import ToolInstaller
        with tempfile.TemporaryDirectory() as root:
            host, manager = self.fixture(root, applied=True)
            host.f.write(PROGRAM + "/server_guard/__init__.py", '__version__="1.4.0"\n')
            with contextlib.redirect_stdout(io.StringIO()):
                ToolInstaller(host.f.root).install(Path(__file__).resolve().parents[1], upgrade_only=True)
            self.assertTrue(host.f.path(PROGRAM + "/current").is_symlink())
            backup = self.remove(manager)
            self.assertFalse(host.f.path(PROGRAM).exists())
            self.assertTrue(host.f.path(RETAINED + "/pam_sessions.py").is_file())
            self.assertTrue(host.f.path("/var/lib/mongodb/important.data").is_file())
            self.assertTrue(host.f.path("/home/admin/.ssh/authorized_keys").is_file())
            self.assertTrue((backup / "opt/server-guard/current").is_symlink())

    def fixture(self, root, applied=False):
        host = Host(Files(root), RuntimeRunner())
        f = host.f
        for path, value in [(PROGRAM + "/server_guard/cli.py", "# manager"),
                            (OLD_HELPER, "#!/usr/bin/python3\n# standalone PAM helper\n"),
                            (LAUNCHER, "# launcher"), (STATE + "/history/old.json", "{}"),
                            (CONFIG + "/policy.json", "{}"), (DOCS + "/README.md", "guide"),
                            ("/home/admin/.ssh/authorized_keys", "keep key"),
                            ("/var/lib/mongodb/important.data", "keep database"),
                            ("/www/server/panel/data/app", "keep panel"),
                            ("/etc/ssh/sshd_config", "# keep SSH\n"),
                            (PAM, "@include common-session\n")]:
            f.write(path, value)
        if applied:
            f.write(PAM, SSHBuilder.pam_config(f.path(PAM).read_text()), 0o644)
            f.write(FW_UNIT, FIREWALL_SERVICE, 0o644)
            f.write(CONFIG + "/firewall.nft", "table inet server_guard {}\n")
            f.write(CONFIG + "/sshd-sessions.json", '{"admin":3}')
            f.write("/etc/ssh/server-guard.conf", "PasswordAuthentication no\n")
        return host, UninstallManager(host)

    def remove(self, manager, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return manager.remove(**kwargs)

    def test_early_uninstall_preserves_apps_keys_and_creates_private_recovery(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = self.fixture(root)
            backup = self.remove(manager)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
            self.assertEqual((backup / "opt/server-guard/server_guard/cli.py").read_text(), "# manager")
            for path in [PROGRAM, LAUNCHER, STATE, DOCS]:
                self.assertFalse(host.f.path(path).exists())
            self.assertTrue(host.f.path(CONFIG + "/policy.json").exists())
            for path, value in [("/home/admin/.ssh/authorized_keys", "keep key"),
                                ("/var/lib/mongodb/important.data", "keep database"),
                                ("/www/server/panel/data/app", "keep panel")]:
                self.assertEqual(host.f.path(path).read_text(), value)
            self.assertIsNone(self.remove(manager))

    def test_active_protection_detaches_without_restarting_access_or_flushing_rules(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = self.fixture(root, applied=True)
            backup = self.remove(manager)
            pam = host.f.path(PAM).read_text()
            self.assertIn(RETAINED + "/pam_sessions.py", pam)
            self.assertNotIn(OLD_HELPER, pam)
            self.assertTrue(host.f.path(RETAINED + "/pam_sessions.py").exists())
            unit = host.f.path(FW_UNIT).read_text()
            self.assertNotIn(LAUNCHER, unit)
            self.assertEqual(unit.count(RETAINED + "/firewall-load server_guard"), 2)
            self.assertEqual(host.f.path(CONFIG + "/sshd-sessions.json").read_text(), '{"admin":3}')
            self.assertTrue((backup / "etc/ssh/server-guard.conf").is_file())
            self.assertEqual(host.f.path("/etc/ssh/sshd_config").read_text(), "# keep SSH\n")
            for args, options in host.r.calls:
                if args[0] == "nft":
                    self.assertIn(args[1], {"list", "--check"})
                self.assertFalse(args[:2] == ("systemctl", "restart"))
            result = subprocess.run(["bash", "-n", str(host.f.path(RETAINED + "/firewall-load"))], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_v2ray_egress_keeps_independent_startup_dependency(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = self.fixture(root, applied=True)
            host.f.write(EGRESS_UNIT, f"[Service]\nExecStart={LAUNCHER} v2ray-egress-load\n")
            host.f.write("/etc/systemd/system/server-guard-v2ray.service", "Requires=server-guard-v2ray-egress.service\n")
            rules = "table inet server_guard_v2ray {}\n"
            with patch("server_guard.services.V2RayManager.egress_rules", return_value=rules):
                self.remove(manager)
            self.assertEqual(host.f.path(RETAINED + "/v2ray-egress.nft").read_text(), rules)
            self.assertNotIn(LAUNCHER, host.f.path(EGRESS_UNIT).read_text())
            self.assertTrue(host.f.path("/etc/systemd/system/server-guard-v2ray.service").exists())

    def test_failed_validation_restores_runtime_and_keeps_manager(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = self.fixture(root, applied=True)
            original = host.f.path(PAM).read_bytes()
            host.r.fail = ("sshd", "-t")
            with self.assertRaises(GuardError):
                self.remove(manager)
            self.assertEqual(host.f.path(PAM).read_bytes(), original)
            self.assertEqual(host.f.path(FW_UNIT).read_text(), FIREWALL_SERVICE)
            self.assertTrue(host.f.path(LAUNCHER).is_file())
            self.assertFalse(host.f.path(RETAINED + "/firewall-load").exists())

    def test_pending_change_and_changed_review_both_refuse_removal(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = self.fixture(root)
            host.f.write(STATE + "/pending.json", '{"id":"pending"}')
            with self.assertRaises(GuardError):
                self.remove(manager)
            host.f.path(STATE + "/pending.json").unlink()
            plan = manager.plan()
            host.f.write(PAM, "# changed after review\n")
            with self.assertRaises(GuardError):
                self.remove(manager, expected=plan["fingerprint"])
            self.assertTrue(host.f.path(LAUNCHER).exists())
            self.assertFalse(host.f.path("/var/backups/server-guard").exists())

    def test_purge_is_only_allowed_before_protection_or_optional_service_setup(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = self.fixture(root)
            self.remove(manager, purge=True)
            self.assertFalse(host.f.path(CONFIG).exists())
        for marker in ["/etc/ssh/server-guard.conf", CONFIG + "/mongodb.json",
                       "/etc/systemd/system/server-guard-v2ray.service"]:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as root:
                host, manager = self.fixture(root)
                host.f.write(marker, "configured")
                with self.assertRaises(GuardError):
                    self.remove(manager, purge=True)
                self.assertTrue(host.f.path(LAUNCHER).exists())

    def test_custom_integrations_and_symlinks_are_not_silently_broken(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = self.fixture(root)
            host.f.write("/etc/systemd/system/custom.service", f"ExecStart={LAUNCHER} status\n")
            with self.assertRaises(GuardError):
                self.remove(manager)
            host.f.path("/etc/systemd/system/custom.service").unlink()
            target = host.f.path(PAM)
            target.unlink()
            target.symlink_to(host.f.path("/etc/ssh/sshd_config"))
            with self.assertRaises(GuardError):
                self.remove(manager)

    def test_missing_protection_state_does_not_leave_broken_required_pam(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = self.fixture(root, applied=True)
            host.f.path(CONFIG + "/sshd-sessions.json").unlink()
            with self.assertRaises(GuardError):
                self.remove(manager)
            self.assertTrue(host.f.path(OLD_HELPER).exists())

    def test_reinstall_replaces_retained_pam_hook_exactly_once(self):
        original = "@include common-session\n" + f"session required pam_exec.so quiet {RETAINED}/pam_sessions.py\n"
        updated = SSHBuilder.pam_config(original)
        self.assertEqual(updated.count(OLD_HELPER), 1)
        self.assertNotIn(RETAINED, updated)
        self.assertEqual(SSHBuilder.pam_config(updated), updated)

    def test_retained_required_pam_policy_is_not_purged_on_a_later_removal(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = self.fixture(root)
            host.f.write(PAM, f"session required pam_exec.so quiet {RETAINED}/pam_sessions.py\n")
            host.f.write(CONFIG + "/sshd-sessions.json", '{"admin":3}')
            with self.assertRaises(GuardError):
                self.remove(manager, purge=True)
            self.assertTrue(host.f.path(CONFIG + "/sshd-sessions.json").exists())

    def test_native_loader_limits_scope_and_has_no_manager_dependency(self):
        self.assertNotIn("flush ruleset", NATIVE_FIREWALL)
        self.assertNotIn(PROGRAM, NATIVE_FIREWALL)
        self.assertIn("nft --check", NATIVE_FIREWALL)
        self.assertIn("Unsupported retained firewall", NATIVE_FIREWALL)


if __name__ == "__main__":
    unittest.main()
