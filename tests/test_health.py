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
from unittest.mock import Mock, patch

from server_guard.cli import execute_locked, parser
from server_guard.core import Files, GuardError
from server_guard.health import (HEALTH_CONFIG, MONITOR_TIMER, MONITOR_UNIT, REPORTS,
    HealthChecker, HealthMonitor, HealthView, LinuxResources, ReportStore, thresholds)
from server_guard.host import Host


def proc_stat(pid=42, ticks=100, start="1000", rss=16):
    fields = ["S"] + ["0"] * 21
    fields[11], fields[12], fields[16], fields[19], fields[21] = str(ticks), "0", "0", start, str(rss)
    return f"{pid} (worker with ) space) " + " ".join(fields)


class ResourceTests(unittest.TestCase):
    def fixture(self, root, reused=False):
        files = Files(root)
        files.write("/proc/stat", "cpu 100 0 50 800 20 0 0 30 99 99\ncpu0 100 0 50 800 20 0 0 30\n")
        files.write("/proc/meminfo", "MemTotal: 1000 kB\nMemFree: 20 kB\nMemAvailable: 600 kB\nSwapTotal: 400 kB\nSwapFree: 100 kB\n")
        files.write("/proc/net/dev", "header\nheader\neth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n")
        files.write("/proc/loadavg", "0.5 0.6 0.7 1/2 42")
        files.write("/proc/uptime", "3600 3000")
        files.write("/proc/42/stat", proc_stat())
        files.write("/proc/pressure/cpu", "some avg10=1.00 avg60=2.00 avg300=3.00 total=10\n")
        def advance(seconds):
            files.write("/proc/stat", "cpu 130 0 60 840 30 0 0 40 999 999\ncpu0 130 0 60 840 30 0 0 40\n")
            files.write("/proc/42/stat", proc_stat(ticks=200, start="2000" if reused else "1000"))
            files.write("/proc/net/dev", "header\nheader\neth0: 2024 0 0 0 0 0 0 0 4048 0 0 0 0 0 0 0\n")
        return LinuxResources(files, advance, Mock(side_effect=[10.0, 11.0]))

    def test_sample_uses_interval_counters_available_memory_and_one_core_process_cpu(self):
        with tempfile.TemporaryDirectory() as root:
            resources = self.fixture(root)
            result = resources.sample()
            self.assertEqual(result["cpu_percent"], 40.0)
            self.assertEqual(result["iowait_percent"], 10.0)
            self.assertEqual(result["steal_percent"], 10.0)
            self.assertEqual(result["memory_percent"], 40.0)
            self.assertEqual(result["memory_available"], 600 * 1024)
            self.assertEqual(result["swap_used"], 300 * 1024)
            self.assertEqual(result["network"][0]["rx_bytes_s"], 1024)
            self.assertEqual(result["top_cpu"][0]["cpu_percent"], 100 / os.sysconf("SC_CLK_TCK") * 100)
            self.assertEqual(result["top_cpu"][0]["name"], "worker with ) space")
            self.assertNotIn("cmdline", json.dumps(result))

    def test_reused_pid_has_no_cpu_attribution_from_old_process(self):
        with tempfile.TemporaryDirectory() as root:
            result = self.fixture(root, reused=True).sample()
            self.assertIsNone(result["top_cpu"][0]["cpu_percent"])

    def test_reset_cpu_counters_fail_without_reporting_fake_utilization(self):
        with tempfile.TemporaryDirectory() as root:
            resources = self.fixture(root)
            resources.sleep = lambda seconds: resources.f.write("/proc/stat", "cpu 0 0 0 0 0 0 0 0\ncpu0 0 0 0 0 0 0 0 0\n")
            with self.assertRaises(GuardError):
                resources.sample()

    def test_disk_usage_uses_available_space_and_decodes_mount_path(self):
        with tempfile.TemporaryDirectory() as root:
            files = Files(root)
            files.path("/var/data space").mkdir(parents=True)
            files.write("/proc/self/mountinfo", "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n2 1 8:2 / /var/data\\040space rw - ext4 /dev/vdb1 rw\n3 1 0:1 / /proc rw - proc proc rw\n")
            info = Mock(f_blocks=100, f_bfree=20, f_bavail=10, f_frsize=1024,
                        f_files=100, f_ffree=30, f_flag=0)
            with patch("server_guard.health.os.statvfs", return_value=info):
                result = LinuxResources(files).disks()
            self.assertEqual([row["mount"] for row in result], ["/", "/var/data space"])
            self.assertEqual(result[0]["percent"], 88.9)
            self.assertEqual(result[0]["inode_percent"], 70.0)


class HealthRunner:
    def __init__(self, missing=False):
        self.calls, self.missing = [], missing

    def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.missing:
            raise FileNotFoundError("not installed")
        output = ""
        if args[:2] == ("sshd", "-T"):
            output = "passwordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin no\n"
        if args[0] == "nft":
            output = "table inet server_guard { chain input { type filter hook input priority filter; policy drop; } }"
        if args[:2] == ("systemctl", "is-active"):
            output = "active"
        if args[0] == "timedatectl":
            output = "yes"
        if args[0] == "ss":
            output = "tcp LISTEN 0 128 127.0.0.1:27017 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:*\n"
        return subprocess.CompletedProcess(args, 0, output, "")


class ProbeTests(unittest.TestCase):
    def resources(self):
        return Mock(sample=Mock(return_value={"cpu_percent": 95, "memory_percent": 40,
            "steal_percent": 15, "iowait_percent": 0, "pressure": {}}),
            disks=Mock(return_value=[{"mount": "/", "percent": 96, "inode_percent": 99, "readonly": False}]))

    def test_progress_and_findings_distinguish_capacity_pressure_and_private_binding(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), HealthRunner())
            progress = []
            report = HealthChecker(host, self.resources()).check(lambda *args: progress.append(args))
            self.assertEqual([args[:2] for args in progress], [(i, 13) for i in range(1, 14)])
            findings = {row["name"]: row for row in report["checks"]}
            self.assertEqual(findings["CPU busy"]["status"], "WARN")
            self.assertEqual(findings["CPU steal"]["status"], "WARN")
            self.assertEqual(findings["/ inodes"]["status"], "CRITICAL")
            self.assertEqual(findings["Inbound firewall"]["status"], "PASS")
            self.assertIn("8443", findings["Private-service binding"]["detail"])
            self.assertNotIn("27017", findings["Non-loopback listeners"]["detail"])
            self.assertEqual(report["status"], "CRITICAL")
            self.assertTrue(all(options.get("timeout") == 8 for _, options in host.r.calls))

    def test_missing_security_tools_are_unknown_not_pass(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), HealthRunner(missing=True))
            report = HealthChecker(host, self.resources()).check()
            findings = {row["name"]: row["status"] for row in report["checks"]}
            self.assertEqual(findings["Inbound firewall"], "UNKNOWN")
            self.assertEqual(findings["SSH policy"], "UNKNOWN")
            self.assertEqual(findings["Security update timer"], "UNKNOWN")
            host.r.run = Mock(return_value=subprocess.CompletedProcess([], 1, "", "permission denied"))
            report = HealthChecker(host, self.resources()).check()
            firewall = next(row for row in report["checks"] if row["name"] == "Inbound firewall")
            self.assertEqual(firewall["status"], "UNKNOWN")

    def test_resource_failure_leaves_security_evidence_available(self):
        with tempfile.TemporaryDirectory() as root:
            resources = self.resources()
            resources.sample.side_effect = FileNotFoundError("/proc missing")
            report = HealthChecker(Host(Files(root), HealthRunner()), resources).check()
            self.assertNotIn("resources", report["metrics"])
            self.assertTrue(any(row["name"] == "SSH policy" and row["status"] == "PASS" for row in report["checks"]))
            self.assertGreater(report["counts"]["UNKNOWN"], 0)

    def test_resource_only_frame_does_not_claim_security_was_rechecked(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), HealthRunner())
            report = HealthChecker(host, self.resources()).check(security=False)
            self.assertEqual(report["scope"], "resources only")
            self.assertEqual(host.r.calls, [])

    def test_reports_are_private_bounded_and_latest_is_readable(self):
        with tempfile.TemporaryDirectory() as root:
            files = Files(root)
            store = ReportStore(files)
            for number in range(205):
                store.save({"id": f"{number:020d}", "time": number})
            self.assertEqual(len(list(files.path(REPORTS).glob("*.json"))), 200)
            self.assertEqual(store.latest()["time"], 204)
            self.assertEqual(files.path(REPORTS).stat().st_mode & 0o777, 0o700)
            self.assertEqual(next(files.path(REPORTS).glob("*.json")).stat().st_mode & 0o777, 0o600)

    def test_threshold_validation_and_scheduler_refuse_pending_access(self):
        with self.assertRaises(GuardError):
            thresholds({"disk": 101})
        with self.assertRaises(GuardError):
            thresholds({"memory": True})
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), HealthRunner())
            host.f.write("/var/lib/server-guard/pending.json", '{"id":"pending"}')
            with self.assertRaises(GuardError):
                HealthMonitor(host).enable()
            self.assertFalse(host.f.path(MONITOR_TIMER).exists())

    def test_scheduler_has_local_read_only_job_and_configurable_thresholds(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), HealthRunner())
            with contextlib.redirect_stdout(io.StringIO()):
                HealthMonitor(host).enable(10, {"disk": 80})
            self.assertEqual(json.loads(host.f.path(HEALTH_CONFIG).read_text())["thresholds"]["disk"], 80)
            self.assertIn("OnUnitInactiveSec=10min", host.f.path(MONITOR_TIMER).read_text())
            unit = host.f.path(MONITOR_UNIT).read_text()
            self.assertIn("health check --record --json", unit)
            self.assertNotIn("--yes", unit)
            # Mount-remapping sandboxes would report their read-only/private
            # mounts as host storage state; this observer needs the host view.
            self.assertNotIn("ProtectSystem=", unit)
            self.assertNotIn("PrivateTmp=", unit)

    def test_live_checks_do_not_hold_access_management_lock_even_with_pending_transaction(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), HealthRunner())
            host.f.path("/run/server-guard").mkdir(parents=True)
            host.f.write("/var/lib/server-guard/pending.json", '{"id":"pending"}')
            lockpath = host.f.path("/run/server-guard/management.lock")
            def check(*args, **kwargs):
                with lockpath.open("a") as stream:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return {"id": "example"}
            with patch("server_guard.cli.HealthChecker.check", side_effect=check), patch("server_guard.cli.HealthView.show"), patch("server_guard.cli.ReportStore.save"):
                execute_locked(host, ["health", "check"])

    def test_json_stdout_is_parseable_and_progress_is_separate(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), HealthRunner())
            report = HealthChecker(host, self.resources()).check()
            output, errors = io.StringIO(), io.StringIO()
            def check(progress):
                progress(1, 3, "sampling")
                return report
            with patch("server_guard.cli.HealthChecker.check", side_effect=check), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                execute_locked(host, ["health", "check", "--json", "--no-record"])
            self.assertEqual(json.loads(output.getvalue())["status"], report["status"])
            self.assertIn("[1/3] sampling", errors.getvalue())

    def test_watch_is_bounded_when_requested_and_refreshes_resources_after_first_frame(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), HealthRunner())
            with patch("server_guard.cli.HealthChecker.check", return_value={"id": "sample"}) as check, patch("server_guard.cli.HealthView.show"), patch("server_guard.cli.ReportStore.save"), patch("server_guard.cli.time.sleep"), contextlib.redirect_stdout(io.StringIO()):
                execute_locked(host, ["health", "watch", "--count", "2"])
            self.assertEqual([call.kwargs["security"] for call in check.call_args_list], [True, False])


if __name__ == "__main__":
    unittest.main()
