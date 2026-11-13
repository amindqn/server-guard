"""Reproduce delayed socket/jail initialization without sleeping or host services."""
import contextlib
import io
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from server_guard.core import Files, GuardError, PolicyStore, defaults
from server_guard.fail2ban import Fail2BanService
from server_guard.defense_config import CONFIG, JAIL, DefensePolicy
from server_guard.transactions import PENDING


class Clock:
    def __init__(self):
        self.value, self.pauses = 0.0, []

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.pauses.append(seconds)
        self.value += seconds


class StartingService:
    def __init__(self, clock, socket_at=2, jail_at=3, state="active"):
        self.clock, self.socket_at, self.jail_at, self.state = clock, socket_at, jail_at, state
        self.calls = []

    def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        code, output, error = 0, "", ""
        if args[:2] == ("fail2ban-client", "ping"):
            code = int(self.clock.now() < self.socket_at)
            error = "Failed to access socket path" if code else ""
        elif args[:2] == ("fail2ban-client", "status"):
            code = int(self.clock.now() < self.jail_at)
            error = "Jail does not exist yet" if code else ""
        elif args[:2] == ("systemctl", "show"):
            output = self.state
        return subprocess.CompletedProcess(args, code, output, error)


class Fail2BanReadinessTests(unittest.TestCase):
    def service(self, runner, clock, timeout=4):
        return Fail2BanService(runner, clock=clock.now, pause=clock.sleep, timeout=timeout)

    def test_restart_waits_for_socket_and_then_jails_even_while_unit_is_active(self):
        clock = Clock()
        runner = StartingService(clock)
        self.service(runner, clock).restart(("sshd", "server-guard-nginx-auth"))
        self.assertEqual(clock.now(), 3)
        restarts = [args for args, _ in runner.calls if args[:2] == ("systemctl", "restart")]
        self.assertEqual(restarts, [("systemctl", "restart", "fail2ban")])
        self.assertTrue(all(kwargs.get("check") is False and 0 < kwargs["timeout"] <= 2
                            for args, kwargs in runner.calls if args[0] == "fail2ban-client"))

    def test_ready_service_does_not_sleep_or_restart(self):
        clock = Clock()
        runner = StartingService(clock, 0, 0)
        self.service(runner, clock).wait(("sshd",))
        self.assertEqual(clock.pauses, [])
        self.assertEqual([args for args, _ in runner.calls], [("fail2ban-client", "ping"), ("fail2ban-client", "status", "sshd")])

    def test_missing_socket_has_a_finite_budget_and_actionable_diagnostics(self):
        clock = Clock()
        runner = StartingService(clock, 100, 100)
        with self.assertRaises(GuardError) as caught:
            self.service(runner, clock, 1).restart(("sshd",))
        self.assertEqual(clock.now(), 1)
        self.assertIn("journalctl -u fail2ban", str(caught.exception))
        self.assertIn("Failed to access socket path", str(caught.exception))
        self.assertIn("fail2ban-client -t", str(caught.exception))

    def test_responding_socket_alone_does_not_mean_required_jail_is_ready(self):
        clock = Clock()
        runner = StartingService(clock, 0, 100)
        with self.assertRaisesRegex(GuardError, "status sshd"):
            self.service(runner, clock, 1).wait(("sshd",))
        self.assertEqual(clock.now(), 1)

    def test_failed_or_inactive_service_fails_fast_without_restart_loops(self):
        for state in ["failed", "inactive"]:
            with self.subTest(state=state):
                clock = Clock()
                runner = StartingService(clock, state=state)
                with self.assertRaisesRegex(GuardError, "service: " + state):
                    self.service(runner, clock).restart(("sshd",))
                self.assertEqual(clock.pauses, [])

    def test_hung_client_probe_is_limited_to_remaining_time(self):
        clock = Clock()
        runner = StartingService(clock)
        def hung(*args, **kwargs):
            self.assertEqual(kwargs["timeout"], 1)
            clock.sleep(kwargs["timeout"])
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        with patch.object(runner, "run", side_effect=hung), self.assertRaisesRegex(GuardError, "probe timed out"):
            self.service(runner, clock, 1).wait()
        self.assertEqual(clock.now(), 1)

    def test_missing_client_fails_without_waiting(self):
        clock = Clock()
        runner = StartingService(clock)
        with patch.object(runner, "run", side_effect=FileNotFoundError()), self.assertRaisesRegex(GuardError, "client is missing"):
            self.service(runner, clock).wait()
        self.assertEqual(clock.pauses, [])


class DefenseStartupRegressionTests(unittest.TestCase):
    def test_baseline_apply_rolls_back_if_fail2ban_never_becomes_ready(self):
        from test_guard import FakeRunner
        from server_guard.host import Host
        with tempfile.TemporaryDirectory() as root, contextlib.redirect_stdout(io.StringIO()):
            files, runner = Files(root), FakeRunner()
            PolicyStore(files).save(defaults())
            files.write("/etc/ssh/sshd_config", "# original SSH settings\n")
            files.write("/etc/pam.d/sshd", "# original PAM\n")
            host = Host(files, runner)
            with patch.object(host, "check_admin"), patch.object(host, "check_effective_ssh"), \
                 patch("server_guard.host.Fail2BanService") as service:
                service.return_value.restart.side_effect = GuardError("Fail2Ban readiness failed")
                with self.assertRaisesRegex(GuardError, "readiness failed"):
                    host.apply()
            self.assertEqual(files.path("/etc/ssh/sshd_config").read_text(), "# original SSH settings\n")
            self.assertFalse(files.path(PENDING).exists())

    def exercise(self, root, *, never_ready=False, fail_restore=False):
        from test_defense import enable, fixture
        host, manager = fixture(root)
        clock, restarts, queries_too_early = Clock(), [], []
        original = host.r.run
        def native(*args, **kwargs):
            result = original(*args, **kwargs)
            if args == ("systemctl", "restart", "fail2ban"):
                restarts.append(clock.now())
            elif args[:2] == ("systemctl", "show"):
                result.stdout = "active"
            elif restarts and args[0] == "fail2ban-client":
                elapsed = clock.now() - restarts[-1]
                unavailable = (never_ready and (fail_restore or len(restarts) == 1))
                socket_ready = not unavailable and elapsed >= 0.5
                jail_ready = socket_ready and elapsed >= 1
                if args[1] == "ping" and not socket_ready or args[1] == "status" and not jail_ready:
                    result.returncode, result.stderr = 1, "Failed to access socket path; server not ready"
                elif args[1] == "get" and not jail_ready:
                    queries_too_early.append(args)
                    raise AssertionError("Effective jail settings were queried before readiness")
            return result
        factory = lambda runner: Fail2BanService(runner, timeout=2, clock=clock.now, pause=clock.sleep)
        with patch.object(host.r, "run", side_effect=native), \
             patch("server_guard.defense.Fail2BanService", side_effect=factory), \
             patch("server_guard.transactions.Fail2BanService", side_effect=factory):
            if never_ready:
                with self.assertRaisesRegex(GuardError, "Fail2Ban is not ready"):
                    enable(manager)
            else:
                enable(manager)
        return host, restarts, queries_too_early

    def test_delayed_socket_does_not_undo_a_valid_defense_installation(self):
        with tempfile.TemporaryDirectory() as root:
            host, restarts, early = self.exercise(root)
            self.assertTrue(DefensePolicy.load(host.f).enabled)
            self.assertTrue(host.f.path(PENDING).exists())  # fresh-login confirmation still required
            self.assertEqual(len(restarts), 1)
            self.assertEqual(early, [])

    def test_real_readiness_failure_rolls_back_and_awaits_restored_daemon(self):
        with tempfile.TemporaryDirectory() as root, contextlib.redirect_stdout(io.StringIO()):
            host, restarts, early = self.exercise(root, never_ready=True)
            self.assertFalse(host.f.path(CONFIG).exists())
            self.assertEqual(host.f.path(JAIL).read_text(), "# previous SSH bans\n")
            self.assertFalse(host.f.path(PENDING).exists())
            self.assertEqual(len(restarts), 2)
            self.assertEqual(early, [])

    def test_failed_restore_keeps_pending_snapshot_for_recovery(self):
        with tempfile.TemporaryDirectory() as root, contextlib.redirect_stdout(io.StringIO()):
            host, _, _ = self.exercise(root, never_ready=True, fail_restore=True)
            self.assertTrue(host.f.path(PENDING).exists())
            self.assertFalse(list(host.f.path("/var/lib/server-guard/history").glob("*-rolled-back.json")))


if __name__ == "__main__":
    unittest.main()
