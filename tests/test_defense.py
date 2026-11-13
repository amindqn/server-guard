"""Defense integration against isolated files and an explicit native-command adapter."""
import contextlib
import copy
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from server_guard.cli import execute_locked, parser
from server_guard.core import Files, GuardError, POLICY, PolicyStore, defaults
from server_guard.defense import DefenseManager
from server_guard.defense_config import BASELINE, CONFIG, DATABASE, JAIL, RESULTS, TIMER, UNIT, DefensePolicy, fail2ban_config
from server_guard.host import Host
from server_guard.integrity import IntegrityMonitor, file_state
from server_guard.transactions import PENDING


FIREWALL = {"nftables": [{"metainfo": {"version": "test"}},
    {"table": {"name": "server_guard", "family": "inet", "handle": 1}},
    {"chain": {"family": "inet", "table": "server_guard", "name": "input", "policy": "drop", "handle": 2}},
    {"chain": {"family": "inet", "table": "server_guard", "name": "forward", "policy": "drop", "handle": 3}},
    {"rule": {"family": "inet", "table": "server_guard", "chain": "input", "handle": 4,
              "expr": [{"counter": {"packets": 20, "bytes": 3000}}, {"accept": None}]}}]}


class DefenseRunner:
    def __init__(self):
        self.calls, self.fail = [], None
        self.active = {"fail2ban", "server-guard-firewall", "apt-daily.timer", "apt-daily-upgrade.timer", "auditd"}
        self.enabled = set(self.active)
        self.firewall = copy.deepcopy(FIREWALL)
        self.missing_jail = None

    def run(self, *args, check=True, **kwargs):
        self.calls.append(args)
        if self.fail and args[:len(self.fail)] == self.fail:
            self.fail = None  # recoverable one-shot failure, not a broken recovery adapter
            raise GuardError("Injected defense configuration failure")
        code, output = 0, ""
        if args[:2] == ("systemctl", "is-active"):
            code = 0 if args[-1] in self.active else 3
        elif args[:2] == ("systemctl", "is-enabled"):
            code = 0 if args[-1] in self.enabled else 1
        elif args[0] == "systemctl" and args[1] in {"enable", "disable"}:
            names = [item for item in args[2:] if not item.startswith("-")]
            for name in names:
                (self.enabled.add if args[1] == "enable" else self.enabled.discard)(name)
                if "--now" in args:
                    (self.active.add if args[1] == "enable" else self.active.discard)(name)
        elif args[0] == "systemctl" and args[1] in {"restart", "stop"}:
            (self.active.add if args[1] == "restart" else self.active.discard)(args[-1])
        elif args[:2] == ("sysctl", "-n"):
            output = "0\n"
        elif args[:2] == ("nft", "-j"):
            output = json.dumps(self.firewall)
        elif args[:2] == ("nft", "list"):
            output = "table inet server_guard {}\n"
        elif args[:2] == ("fail2ban-client", "status") and args[-1] == self.missing_jail:
            code = 1
        elif args[:2] == ("fail2ban-client", "get"):
            output = {"maxretry": "5", "findtime": "600", "bantime": "3600", "actions": "nftables-multiport",
                      "dbpurgeage": "2592000", "ignoreip": "127.0.0.1/8 ::1 203.0.113.20",
                      "dbfile": "/var/lib/fail2ban/fail2ban.sqlite3"}[args[-1]]
        elif args[0] == "apt-config":
            output = "SG_PERIODIC='1'\nSG_LISTS='1'\nSG_UPGRADES='1'\nSG_REBOOT='false'\n"
        if code and check:
            raise GuardError("Native command refused")
        return subprocess.CompletedProcess(args, code, output, "")


def fixture(directory):
    host = Host(Files(Path(directory)), DefenseRunner())
    policy = defaults(2222)
    policy["users"]["admin"] = {"role": "admin", "sessions": 3, "disabled": False}
    PolicyStore(host.f).save(policy)
    for name, content in [("/etc/server-guard/firewall.nft", "table inet server_guard {}\n"),
            ("/etc/ssh/sshd_config", "Keep original SSH configuration\n"),
            ("/etc/pam.d/sshd", "# keep original PAM"), ("/etc/sudoers", "# keep sudo"),
            ("/home/admin/.ssh/authorized_keys", "keep the existing key"),
            ("/www/app/database.wt", "keep important database bytes"),
            (JAIL, "# previous SSH bans\n"), ("/etc/apt/apt.conf.d/90-server-guard", "# previous updates\n")]:
        host.f.write(name, content)
    host.f.path("/run/server-guard").mkdir(parents=True)
    # Effective OpenSSH parsing is tested separately; this adapter never queries a host SSH daemon.
    host.check_effective_ssh = lambda state: None
    return host, DefenseManager(host)


def silent(call, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()):
        return call(*args, **kwargs)


def enable(manager, **kwargs):
    with patch.dict(os.environ, {"SSH_CONNECTION": "203.0.113.20 50000 198.51.100.1 2222"}):
        return silent(manager.enable, manager.proposed(**kwargs), yes=True)


def confirm_fixture(host):
    silent(host.tx.archive, host.tx.pending(), "confirmed")


class DefensePolicyTests(unittest.TestCase):
    def test_trusted_ips_and_log_paths_cannot_inject_config_or_exempt_everyone(self):
        for value in ["any", "0.0.0.0/0", "::/0", "1.2.3.4\n[sshd]", "$(reboot)", "224.0.0.0/4"]:
            with self.subTest(value=value), self.assertRaises(GuardError):
                DefensePolicy(trusted=[value])
        for value in ["/etc/shadow", "/var/log/nginx/*.log", "/var/log/../error.log", "/var/log/nginx/x.log\nenabled=false", "/var/log/%(x)s.log"]:
            with self.subTest(value=value), self.assertRaises(GuardError):
                DefensePolicy(nginx_logs=[value])
        self.assertEqual(DefensePolicy(trusted=["2001:db8::1", "203.0.113.1/24"]).trusted,
                         ["2001:db8::1/128", "203.0.113.0/24"])

    def test_native_jails_are_scoped_and_keep_ssh_port_changes(self):
        policy = DefensePolicy(True, ["203.0.113.9"], ["/var/log/nginx/error.log"])
        config = fail2ban_config(2222, policy)
        self.assertIn("port = 2222", config)
        self.assertIn("bantime.increment = true", config)
        self.assertIn("bantime.maxtime = 1d", config)
        self.assertIn("nftables-multiport", config)
        self.assertIn("journalmatch = _UID=0 _COMM=sshd", config)
        self.assertIn("203.0.113.9/32", config)
        self.assertIn("port = 80,443", config)
        self.assertIn("backend = polling", config)
        self.assertIn("filter = nginx-botsearch", config)
        self.assertNotIn("[DEFAULT]", config)  # no changes to third-party jails

    def test_current_client_is_exempt_and_proxy_web_bans_require_explicit_selection(self):
        with tempfile.TemporaryDirectory() as root:
            _, manager = fixture(root)
            with patch.dict(os.environ, {"SSH_CONNECTION": "::ffff:203.0.113.20 42 198.51.100.1 2222"}):
                self.assertIn("203.0.113.20/32", manager.proposed().trusted)
            with self.assertRaisesRegex(GuardError, "direct-web-clients"):
                manager.proposed(nginx_logs=["/var/log/nginx/error.log"])


class IntegrityTests(unittest.TestCase):
    def test_adopted_local_account_keys_follow_its_real_home_directory(self):
        with tempfile.TemporaryDirectory() as root:
            host, _ = fixture(root)
            host.f.write("/etc/passwd", "admin:x:1001:1001::/srv/panel-account:/bin/bash\n")
            host.f.write("/srv/panel-account/.ssh/authorized_keys", "adopted account key")
            monitor = IntegrityMonitor(host)
            saved = monitor.capture()
            self.assertIn("/srv/panel-account/.ssh/authorized_keys", saved["entries"])
            host.f.write("/srv/panel-account/.ssh/authorized_keys", "changed key")
            self.assertTrue(any(row["path"] == "/srv/panel-account/.ssh/authorized_keys"
                                for row in monitor.compare(saved, monitor.capture(saved))))

    def test_real_content_permission_presence_and_directory_changes_are_detected(self):
        with tempfile.TemporaryDirectory() as root:
            host, _ = fixture(root)
            monitor = IntegrityMonitor(host)
            saved = monitor.capture()
            monitor.require_complete(saved)
            host.f.write("/etc/ssh/sshd_config", "Unexpected SSH policy", 0o644)
            host.f.write("/etc/sudoers.d/new-admin", "# added access")
            host.f.path("/home/admin/.ssh/authorized_keys").unlink()
            findings = monitor.compare(saved, monitor.capture(saved))
            names = {finding["path"] for finding in findings}
            self.assertTrue({"/etc/ssh/sshd_config", "/etc/sudoers.d", "/etc/sudoers.d/new-admin",
                             "/home/admin/.ssh/authorized_keys"}.issubset(names))
            self.assertNotIn("/www/app/database.wt", saved["entries"])

    def test_link_parent_link_fifo_and_large_file_are_not_followed_or_blocked(self):
        with tempfile.TemporaryDirectory() as root:
            host, _ = fixture(root)
            target = host.f.path("/private")
            target.write_text("secret must not be copied")
            host.f.path("/link").symlink_to(target)
            host.f.path("/parent").symlink_to(host.f.path("/etc"), target_is_directory=True)
            os.mkfifo(host.f.path("/fifo"))
            host.f.path("/huge").write_bytes(b"x" * (2 * 1024 ** 2 + 1))
            for name in ["/link", "/parent/sudoers", "/fifo", "/huge"]:
                with self.subTest(name=name):
                    self.assertEqual(file_state(host.f, name)["kind"], "error")

    def test_directory_budget_cannot_establish_a_false_clean_baseline(self):
        with tempfile.TemporaryDirectory() as root:
            host, _ = fixture(root)
            for index in range(129):
                host.f.write(f"/etc/sudoers.d/item-{index}", "# oversized inventory")
            saved = IntegrityMonitor(host).capture()
            with self.assertRaisesRegex(GuardError, "complete trusted baseline"):
                IntegrityMonitor.require_complete(saved)

    def test_nested_ssh_directories_are_supported_without_reading_directories_as_files(self):
        with tempfile.TemporaryDirectory() as root:
            host, _ = fixture(root)
            host.f.write("/etc/ssh/ssh_config.d/50-client.conf", "# client")
            host.f.write("/etc/ssh/sshd_config.d/50-daemon.conf", "# server")
            saved = IntegrityMonitor(host).capture()
            IntegrityMonitor.require_complete(saved)
            self.assertIn("/etc/ssh/sshd_config.d/50-daemon.conf", saved["entries"])


class DefenseWorkflowTests(unittest.TestCase):
    def test_preview_does_not_write_policy_start_services_or_arm_timer(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            silent(manager.enable, manager.proposed())
            self.assertEqual(host.r.calls, [])
            self.assertFalse(host.f.path(CONFIG).exists())
            self.assertFalse(host.f.path(PENDING).exists())

    def test_enable_arms_recovery_and_preserves_access_and_application_data(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            names = [POLICY, "/etc/ssh/sshd_config", "/etc/pam.d/sshd", "/home/admin/.ssh/authorized_keys", "/www/app/database.wt"]
            before = {name: host.f.path(name).read_bytes() for name in names}
            txid = enable(manager)
            self.assertEqual(host.tx.pending()["id"], txid)
            self.assertTrue(DefensePolicy.load(host.f).enabled)
            self.assertIn("server-guard-defense.timer", host.r.active)
            self.assertEqual(host.f.path(BASELINE).stat().st_mode & 0o777, 0o600)
            self.assertEqual({name: host.f.path(name).read_bytes() for name in names}, before)
            self.assertIn("ProtectSystem=strict", host.f.path(UNIT).read_text())
            self.assertNotIn(("systemctl", "reload", "ssh"), host.r.calls)

    def test_failed_validation_restores_files_and_leaves_pending_history_for_review(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            original = host.f.path(JAIL).read_bytes()
            host.r.fail = ("fail2ban-client", "-t")
            with self.assertRaisesRegex(GuardError, "Injected"):
                enable(manager)
            self.assertEqual(host.f.path(JAIL).read_bytes(), original)
            self.assertFalse(host.f.path(CONFIG).exists())
            self.assertFalse(host.f.path(BASELINE).exists())
            self.assertFalse(host.f.path(PENDING).exists())
            self.assertTrue(list(host.f.path("/var/lib/server-guard/history").glob("*-rolled-back.json")))

    def test_baseline_exists_before_timer_can_trigger_on_an_old_boot(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            original = host.r.run
            def timer_start(*args, **kwargs):
                if args == ("systemctl", "enable", "--now", "server-guard-defense.timer"):
                    self.assertIn("firewall_sha256", json.loads(host.f.path(BASELINE).read_text()))
                return original(*args, **kwargs)
            with patch.object(host.r, "run", side_effect=timer_start):
                enable(manager)

    def test_overridden_auto_update_policy_does_not_report_successful_enable(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            original = host.r.run
            def disabled_updates(*args, **kwargs):
                result = original(*args, **kwargs)
                if args[0] == "apt-config":
                    result.stdout = "SG_LISTS='1'\nSG_UPGRADES='0'\nSG_REBOOT='true'"
                return result
            with patch.object(host.r, "run", side_effect=disabled_updates), self.assertRaisesRegex(GuardError, "Effective APT"):
                enable(manager)
            self.assertFalse(host.f.path(CONFIG).exists())
            self.assertNotIn("server-guard-defense.timer", host.r.active)

    def test_effective_jail_conflict_rolls_back_and_longer_ban_history_is_retained(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            original = host.r.run
            def conflicting(*args, **kwargs):
                result = original(*args, **kwargs)
                if args[:2] == ("fail2ban-client", "get") and args[-1] == "maxretry":
                    result.stdout = "99"
                return result
            with patch.object(host.r, "run", side_effect=conflicting), self.assertRaisesRegex(GuardError, "overrides"):
                enable(manager)
            self.assertFalse(host.f.path(CONFIG).exists())
            enable(manager)
            self.assertIn("dbpurgeage = 2592000", host.f.path(DATABASE).read_text())

    def test_explicit_rollback_restores_profile_timer_baseline_and_update_settings(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            previous = host.f.path("/etc/apt/apt.conf.d/90-server-guard").read_bytes()
            enable(manager)
            silent(host.tx.rollback)
            for name in [CONFIG, BASELINE, DATABASE, UNIT, TIMER]:
                self.assertFalse(host.f.path(name).exists())
            self.assertNotIn("server-guard-defense.timer", host.r.active)
            self.assertEqual(host.f.path("/etc/apt/apt.conf.d/90-server-guard").read_bytes(), previous)

    def test_empty_pending_marker_and_staged_ssh_changes_block_enable_before_mutation(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            host.f.write(PENDING, "{}")
            with self.assertRaisesRegex(GuardError, "pending"):
                enable(manager)
            self.assertFalse(host.f.path(CONFIG).exists())
            host.f.path(PENDING).unlink()
            def reject(state):
                raise GuardError("Effective SSH port differs from staged policy")
            host.check_effective_ssh = reject
            with self.assertRaisesRegex(GuardError, "Effective SSH"):
                enable(manager)
            self.assertFalse(host.f.path(PENDING).exists())

    def test_web_logs_are_optional_scoped_and_reject_writable_or_linked_files(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            log = "/var/log/nginx/error.log"
            host.f.write(log, "", 0o666)
            with self.assertRaisesRegex(GuardError, "root-owned"):
                enable(manager, nginx_logs=[log], direct_web_clients=True)
            host.f.path(log).chmod(0o640)
            enable(manager, nginx_logs=[log], direct_web_clients=True)
            self.assertIn("port = 80,443", host.f.path(JAIL).read_text())
            self.assertIn(("fail2ban-client", "status", "server-guard-nginx-bots"), host.r.calls)
            confirm_fixture(host)
            host.f.path(log).chmod(0o666)
            self.assertTrue(any("Nginx log" in item["detail"] for item in silent(manager.scan)["findings"]))

    def test_effective_all_address_ban_exemption_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            original = host.r.run
            def ignores_everyone(*args, **kwargs):
                result = original(*args, **kwargs)
                if args[:2] == ("fail2ban-client", "get") and args[-1] == "ignoreip":
                    result.stdout += " 0.0.0.0/0"
                return result
            with patch.object(host.r, "run", side_effect=ignores_everyone), self.assertRaisesRegex(GuardError, "all-address"):
                enable(manager)
            self.assertFalse(host.f.path(CONFIG).exists())

    def test_existing_health_check_reports_the_enabled_defense_profile(self):
        from server_guard.health import HealthChecker
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            enable(manager)
            confirm_fixture(host)
            silent(manager.scan)
            checker = HealthChecker(host)
            checker.defenses()
            self.assertTrue(any(row["name"] == "Automatic defense findings" and row["status"] == "PASS" for row in checker.results))

    def test_scan_runs_without_access_lock_and_never_accepts_or_repairs_drift(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            enable(manager)
            confirm_fixture(host)
            host.f.write("/etc/sudoers", "Unexpected sudo access")
            original_baseline = host.f.path(BASELINE).read_bytes()
            host.r.calls.clear()
            with host.f.path("/run/server-guard/management.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                silent(execute_locked, host, parser().parse_args(["defense", "scan"]))
            report = json.loads(host.f.path(RESULTS + "/latest.json").read_text())
            self.assertEqual(report["status"], "CRITICAL")
            self.assertEqual(host.f.path(BASELINE).read_bytes(), original_baseline)
            self.assertEqual(host.f.path("/etc/sudoers").read_text(), "Unexpected sudo access")
            self.assertFalse(any(call[0] == "systemctl" and call[1] not in {"is-active", "is-enabled"} for call in host.r.calls))
            self.assertEqual(silent(manager.scan)["status"], "CRITICAL")

    def test_clean_scan_pending_warning_stopped_service_and_missing_jail(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            enable(manager)
            self.assertEqual(silent(manager.scan)["status"], "WARN")
            confirm_fixture(host)
            self.assertEqual(silent(manager.scan)["status"], "PASS")
            host.r.active.discard("fail2ban")
            host.r.missing_jail = "sshd"
            report = silent(manager.scan, scheduled=True)
            self.assertEqual(report["status"], "WARN")
            self.assertTrue(report["scheduled"])
            self.assertTrue(any("ban jail" in item["detail"] for item in report["findings"]))

    def test_live_firewall_counters_do_not_alert_but_policy_changes_do(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            enable(manager)
            confirm_fixture(host)
            host.r.firewall["nftables"][-1]["rule"]["expr"][0]["counter"]["packets"] += 100
            host.r.firewall["nftables"][-1]["rule"]["handle"] = 90
            self.assertEqual(silent(manager.scan)["status"], "PASS")
            host.r.firewall["nftables"][-1]["rule"]["expr"].append({"drop": None})
            self.assertEqual(silent(manager.scan)["status"], "CRITICAL")

    def test_baseline_preview_and_reenable_cannot_silently_accept_existing_drift(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            enable(manager)
            confirm_fixture(host)
            before = host.f.path(BASELINE).read_bytes()
            host.f.write("/etc/sudoers", "# reviewed admin change")
            silent(manager.baseline)
            self.assertEqual(host.f.path(BASELINE).read_bytes(), before)
            with self.assertRaisesRegex(GuardError, "Existing security drift"):
                enable(manager)
            silent(manager.baseline, yes=True)
            self.assertEqual(silent(manager.scan)["status"], "PASS")

    def test_missing_baseline_is_unknown_and_is_never_created_by_scan(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            enable(manager)
            confirm_fixture(host)
            host.f.path(BASELINE).unlink()
            self.assertEqual(silent(manager.scan)["status"], "UNKNOWN")
            self.assertFalse(host.f.path(BASELINE).exists())

    def test_corrupt_baseline_is_unknown_and_alert_history_is_private_and_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            enable(manager)
            confirm_fixture(host)
            host.f.write(BASELINE, "[]")
            self.assertEqual(silent(manager.scan)["status"], "UNKNOWN")
            self.assertEqual(host.f.path(BASELINE).read_text(), "[]")
            manager.reports.retention = 2
            for _ in range(3):
                silent(manager.scan)
            reports = list(host.f.path(RESULTS + "/history").glob("*.json"))
            self.assertEqual(len(reports), 2)
            self.assertTrue(all(file.stat().st_mode & 0o777 == 0o600 for file in reports))

    def test_disable_keeps_basic_ssh_bans_and_application_data_with_rollback_available(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            enable(manager)
            confirm_fixture(host)
            silent(manager.disable, yes=True)
            self.assertFalse(DefensePolicy.load(host.f).enabled)
            self.assertIn("[sshd]\nenabled = true", host.f.path(JAIL).read_text())
            self.assertNotIn("bantime.increment = true", host.f.path(JAIL).read_text())
            self.assertIsNotNone(host.tx.pending())
            silent(host.tx.rollback)
            self.assertTrue(DefensePolicy.load(host.f).enabled)
            self.assertIn("server-guard-defense.timer", host.r.active)

    def test_explicit_unban_remains_available_for_access_recovery_and_validates_address(self):
        with tempfile.TemporaryDirectory() as root:
            host, manager = fixture(root)
            host.f.write(PENDING, "{}")
            silent(manager.unban, "sshd", "2001:db8::5", yes=True)
            self.assertIn(("fail2ban-client", "set", "sshd", "unbanip", "2001:db8::5"), host.r.calls)
            with self.assertRaises(GuardError):
                silent(manager.unban, "custom-shell;id", "203.0.113.1", yes=True)
            with self.assertRaises(GuardError):
                silent(manager.unban, "sshd", "203.0.113.1;id", yes=True)


if __name__ == "__main__":
    unittest.main()
