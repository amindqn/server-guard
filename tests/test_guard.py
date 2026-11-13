import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from server_guard.core import (Files, FirewallBuilder, GuardError, POLICY, PolicyStore,
    SSHBuilder, V2RayBuilder, defaults, domain, network, port, public_key, username,
    validate, write_user_key)
from server_guard.host import Host
from server_guard.pam_sessions import admit, process_token
from server_guard.services import checksum
from server_guard.transactions import PENDING, Transactions, verified_login


class ValidationTests(unittest.TestCase):
    def test_ports_reject_injection_and_boundaries(self):
        for value in [0, 65536, -1, "22; reboot", "22\nflush ruleset", None]:
            with self.subTest(value=value), self.assertRaises(GuardError):
                port(value)
        self.assertEqual(port("65535"), 65535)

    def test_usernames_reject_root_path_and_option_injection(self):
        for value in ["root", "-a", "../bob", "Bob", "bob\nMatch all", "a" * 32]:
            with self.subTest(value=value), self.assertRaises(GuardError):
                username(value)

    def test_networks_are_canonical_and_cannot_inject(self):
        self.assertEqual(network("203.0.113.5/24"), "203.0.113.0/24")
        self.assertEqual(network("2001:db8::1/64"), "2001:db8::/64")
        with self.assertRaises(GuardError):
            network("any accept; flush ruleset")

    def test_domain_rejects_nginx_injection(self):
        for value in ["example.com;", "https://example.com", "example.com/a", "x\n}", "-a.com"]:
            with self.subTest(value=value), self.assertRaises(GuardError):
                domain(value)
        self.assertEqual(domain("VPN.Example.com"), "vpn.example.com")

    def test_checksums_are_full_pins(self):
        self.assertEqual(checksum("A" * 64), "a" * 64)
        for value in ["latest", "ab12", "g" * 64, "a" * 64 + "\n"]:
            with self.subTest(value=value), self.assertRaises(GuardError):
                checksum(value)

    def test_key_options_and_private_keys_rejected(self):
        for value in ['command="id" ssh-ed25519 YWJj', '-----BEGIN OPENSSH PRIVATE KEY-----',
                      'ssh-ed25519 ####', 'ssh-ed25519 YWJj\nssh-ed25519 YWJj']:
            with self.subTest(value=value), self.assertRaises(GuardError):
                public_key(value)

    def test_key_type_must_match_wire_type(self):
        name = b"ssh-ed25519"
        blob = len(name).to_bytes(4, "big") + name + b"payload"
        encoded = base64.b64encode(blob).decode()
        self.assertTrue(public_key("ssh-ed25519 " + encoded).endswith("server-guard\n"))
        with self.assertRaises(GuardError):
            public_key("ssh-rsa " + encoded)

    def test_invalid_policy_cannot_persist(self):
        with tempfile.TemporaryDirectory() as root:
            store = PolicyStore(Files(root))
            state = defaults()
            state["ports"] = [{"port": 80, "protocol": "tcp; accept", "source": "any"}]
            with self.assertRaises(GuardError):
                store.save(state)
            self.assertFalse(Files(root).path(POLICY).exists())

    def test_empty_ssh_sources_rejected(self):
        state = defaults()
        state["ssh"]["sources"] = []
        with self.assertRaises(GuardError):
            validate(state)

    def test_admin_keeps_room_for_confirmation_connection(self):
        state = defaults()
        state["users"]["admin"] = {"role": "admin", "sessions": 1}
        with self.assertRaises(GuardError):
            validate(state)


class RenderingTests(unittest.TestCase):
    def test_default_has_no_public_panel_database_or_web(self):
        nft = FirewallBuilder.build(defaults())
        self.assertIn("table inet server_guard", nft)
        self.assertIn("policy drop", nft)
        self.assertIn("tcp dport 22 counter accept", nft)
        for n in [80, 443, 8443, 8888, 3306, 5432, 6379, 10000]:
            self.assertNotIn(f"dport {n} counter accept", nft)
        self.assertNotIn("flush ruleset", nft)

    def test_both_source_families_and_udp(self):
        state = defaults()
        state["ssh"]["sources"] = ["203.0.113.1/32", "2001:db8::/64"]
        state["ports"] = [{"port": 443, "protocol": "udp", "source": "any"}]
        nft = FirewallBuilder.build(state)
        self.assertIn("ip saddr 203.0.113.1/32 tcp dport 22", nft)
        self.assertIn("ip6 saddr 2001:db8::/64 tcp dport 22", nft)
        self.assertIn("udp dport 443 counter accept", nft)

    def test_dhcp_pmtu_and_ipv6_neighbor_discovery_retained(self):
        nft = FirewallBuilder.build(defaults())
        self.assertIn("ipv6-icmp", nft)
        self.assertIn("udp sport 67 udp dport 68", nft)
        self.assertIn("udp sport 547 udp dport 546", nft)

    def test_table_replacement_is_atomic_and_scoped(self):
        nft = FirewallBuilder.batch("table inet server_guard {}\n", True)
        self.assertTrue(nft.startswith("delete table inet server_guard\n"))
        self.assertNotIn("flush ruleset", nft)

    def test_sshd_main_edit_is_repeatable_and_preserves_unrelated_settings(self):
        old = "# hello\nPort 2200\nListenAddress 0.0.0.0\nSubsystem sftp internal-sftp\n"
        once = SSHBuilder.main_config(old)
        self.assertEqual(SSHBuilder.main_config(once), once)
        self.assertEqual(once.count("Include /etc/ssh/server-guard.conf"), 1)
        self.assertIn("ListenAddress 0.0.0.0", once)
        self.assertNotIn("Port 2200", once)
        self.assertTrue(once.startswith("Include /etc/ssh/server-guard.conf"))

    def test_sftp_has_chroot_and_no_shell(self):
        state = defaults()
        state["users"]["upload"] = {"role": "sftp", "sessions": 2}
        ssh = SSHBuilder.user_config(state)
        self.assertIn("ChrootDirectory /srv/sftp/upload", ssh)
        self.assertIn("ForceCommand internal-sftp -d /upload", ssh)
        self.assertIn("DisableForwarding yes", ssh)

    def test_v2ray_loopback_aead_private_blocking(self):
        state = defaults()
        state["v2ray"].update(domain="vpn.example.com", path="/abcdefgh12345678")
        state["v2ray"]["clients"]["phone"] = "d64baac8-cd9a-4278-9e43-833bd850e4b3"
        obj = V2RayBuilder.config(state)
        inbound = obj["inbounds"][0]
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["settings"]["clients"][0]["alterId"], 0)
        self.assertIn("geoip:private", obj["routing"]["rules"][0]["ip"])

    def test_client_link_requires_tls_and_matches_backend(self):
        state = defaults()
        state["v2ray"].update(domain="vpn.example.com", path="/abcdefgh12345678")
        state["v2ray"]["clients"]["phone"] = "test-uuid"
        link = V2RayBuilder.link(state, "phone")
        obj = json.loads(base64.b64decode(link[len("vmess://"):]))
        self.assertEqual(obj["tls"], "tls")
        self.assertEqual(obj["port"], "443")
        self.assertEqual(obj["path"], state["v2ray"]["path"])
        self.assertNotIn("allowInsecure", obj)
        with self.assertRaises(GuardError):
            V2RayBuilder.link(state, "unknown")


class SessionAdmissionTests(unittest.TestCase):
    def test_real_file_lock_serializes_simultaneous_admission(self):
        # Exercise the actual helper and flock across processes, with only its
        # host paths/identity/proc lookup redirected into an unprivileged fixture.
        driver = '''
import os, pathlib, sys
from server_guard import pam_sessions as hook
root = pathlib.Path(sys.argv[1])
hook.Path = lambda name: root / str(name).lstrip('/')
hook.os.geteuid = lambda: 0
hook.os.getppid = os.getpid
def live(pid):
    try:
        os.kill(pid, 0)
        return str(pid)
    except ProcessLookupError:
        return None
hook.process_token = live
# admit's default lookup was bound at definition time.
original = hook.admit
hook.admit = lambda *a, **kw: original(*a, lookup=live, **kw)
hook.syslog.syslog = lambda *a: None
os.environ.update(PAM_TYPE='open_session', PAM_SERVICE='sshd', PAM_USER='alice')
print(hook.main(), flush=True)
sys.stdin.readline()
'''
        with tempfile.TemporaryDirectory() as root:
            f = Files(root)
            f.write("/etc/server-guard/sshd-sessions.json", '{"alice": 3}')
            f.path("/run").mkdir()
            children = [subprocess.Popen([sys.executable, "-c", driver, root], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(8)]
            try:
                results = [int(child.stdout.readline().strip()) for child in children]
                self.assertEqual(results.count(0), 3)
                self.assertEqual(results.count(1), 5)
                ledger = json.loads(f.path("/run/server-guard/sessions.json").read_text())
                self.assertEqual(len(ledger), 3)
            finally:
                for child in children:
                    child.communicate("\n", timeout=10)

    def test_limit_across_transports_without_utmp(self):
        live = {10: "100", 11: "110", 12: "120"}
        ledger = []
        allowed, ledger = admit(ledger, "alice", 10, "100", 2, live.get)
        self.assertTrue(allowed)
        allowed, ledger = admit(ledger, "alice", 11, "110", 2, live.get)
        self.assertTrue(allowed)
        allowed, ledger = admit(ledger, "alice", 12, "120", 2, live.get)
        self.assertFalse(allowed)
        self.assertEqual(len(ledger), 2)

    def test_other_users_do_not_consume_allowance(self):
        ledger = [{"user": "bob", "pid": 10, "token": "100"}]
        allowed, ledger = admit(ledger, "alice", 11, "110", 1, {10: "100", 11: "110"}.get)
        self.assertTrue(allowed)

    def test_dead_and_reused_pids_do_not_consume_allowance(self):
        ledger = [{"user": "alice", "pid": 10, "token": "old"},
                  {"user": "alice", "pid": 11, "token": "dead"}]
        allowed, ledger = admit(ledger, "alice", 12, "new", 1, {10: "reused", 12: "new"}.get)
        self.assertTrue(allowed)
        self.assertEqual([r["pid"] for r in ledger], [12])

    def test_repeated_open_and_close_are_idempotent(self):
        live = {10: "100"}.get
        _, ledger = admit([], "alice", 10, "100", 1, live)
        allowed, ledger = admit(ledger, "alice", 10, "100", 1, live)
        self.assertTrue(allowed)
        self.assertEqual(len(ledger), 1)
        _, ledger = admit(ledger, "alice", 10, "100", 1, live, closing=True)
        self.assertEqual(ledger, [])

    def test_proc_parser_handles_spaces_and_parentheses(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "1"
            p.mkdir()
            fields = ["S"] + ["0"] * 18 + ["12345"]
            (p / "stat").write_text("1 (name with ) parentheses) " + " ".join(fields))
            self.assertEqual(process_token(1, Path(root)), "12345")
            self.assertIsNone(process_token(2, Path(root)))


class FileSafetyTests(unittest.TestCase):
    def test_atomic_private_state_and_no_symlink_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            f = Files(root)
            PolicyStore(f).save(defaults())
            self.assertEqual(f.path(POLICY).stat().st_mode & 0o777, 0o600)
            victim = Path(root) / "victim"
            victim.write_text("safe")
            f.path("/bad").symlink_to(victim)
            with self.assertRaises(GuardError):
                f.write("/bad", "bad")
            self.assertEqual(victim.read_text(), "safe")

    def test_user_controlled_ssh_symlink_cannot_redirect_root_write(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / "home"
            home.mkdir()
            victim = Path(root) / "victim"
            victim.mkdir()
            (victim / "authorized_keys").write_text("safe")
            (home / ".ssh").symlink_to(victim)
            with self.assertRaises(OSError):
                write_user_key(home, "bad", os.getuid(), os.getgid())
            self.assertEqual((victim / "authorized_keys").read_text(), "safe")


class FakeRunner:
    def __init__(self, *, timer=True):
        self.calls = []
        self.timer = timer

    def run(self, *args, check=True, input=None, capture=True, timeout=None):
        self.calls.append((args, input))
        code, stdout = 0, ""
        if args[:2] == ("nft", "list"):
            stdout = "table inet server_guard { }\n"
        if args[:2] == ("systemctl", "is-active"):
            code = 0 if args[-1] == "server-guard-rollback.timer" and self.timer else 3
        if args[:2] == ("systemctl", "is-enabled"):
            code = 1
        if args[0] == "sysctl":
            stdout = "0\n"
        if check and code:
            raise GuardError("injected failure")
        return subprocess.CompletedProcess(args, code, stdout=stdout, stderr="")


class RecoveryTests(unittest.TestCase):
    def test_apply_failure_restores_ssh_and_pam_immediately(self):
        with tempfile.TemporaryDirectory() as root:
            f, runner = Files(root), FakeRunner()
            state = defaults()
            state["users"]["admin"] = {"role": "admin", "sessions": 3}
            PolicyStore(f).save(state)
            f.write("/etc/ssh/sshd_config", "# existing ssh\n")
            f.write("/etc/pam.d/sshd", "session required pam_unix.so\n", 0o644)
            h = Host(f, runner)
            with patch.object(h, "check_admin"), patch.object(h, "check_effective_ssh", side_effect=GuardError("bad SSH policy")):
                with self.assertRaisesRegex(GuardError, "bad SSH policy"):
                    h.apply()
            self.assertEqual(f.path("/etc/ssh/sshd_config").read_text(), "# existing ssh\n")
            self.assertEqual(f.path("/etc/pam.d/sshd").read_text(), "session required pam_unix.so\n")
            self.assertFalse(f.path("/etc/ssh/server-guard.conf").exists())
            self.assertIsNone(h.tx.pending())

    def test_failed_restore_retains_durable_snapshot(self):
        with tempfile.TemporaryDirectory() as root:
            f, runner = Files(root), FakeRunner()
            tx = Transactions(f, runner)
            tx.begin()
            original = runner.run
            def failure(*args, **kwargs):
                if args[:2] == ("sshd", "-t"):
                    raise GuardError("restore validation failed")
                return original(*args, **kwargs)
            with patch.object(runner, "run", side_effect=failure):
                with self.assertRaises(GuardError):
                    tx.rollback()
            self.assertIsNotNone(tx.pending())

    def test_timer_is_persistent_and_has_no_ssh_lifetime_dependency(self):
        with tempfile.TemporaryDirectory() as root:
            f, runner = Files(root), FakeRunner()
            tx = Transactions(f, runner)
            tx.begin()
            timer = f.path("/etc/systemd/system/server-guard-rollback.timer").read_text()
            self.assertIn("OnActiveSec=10min", timer)
            self.assertIn("WantedBy=timers.target", timer)
            self.assertTrue(any(args == ("systemctl", "enable", "--now", "server-guard-rollback.timer")
                                for args, _ in runner.calls))

    def test_restores_content_modes_and_removes_new_files(self):
        with tempfile.TemporaryDirectory() as root:
            f, runner = Files(root), FakeRunner()
            f.write("/etc/ssh/sshd_config", "original\n", 0o640)
            tx = Transactions(f, runner)
            txid = tx.begin()
            f.write("/etc/ssh/sshd_config", "broken\n")
            f.write("/etc/ssh/server-guard.conf", "new\n")
            tx.rollback()
            self.assertEqual(f.path("/etc/ssh/sshd_config").read_text(), "original\n")
            self.assertEqual(f.path("/etc/ssh/sshd_config").stat().st_mode & 0o777, 0o640)
            self.assertFalse(f.path("/etc/ssh/server-guard.conf").exists())
            self.assertFalse(f.path(PENDING).exists())
            self.assertTrue(f.path(f"/var/lib/server-guard/history/{txid}-rolled-back.json").exists())
            nft_calls = [data for args, data in runner.calls if args[:2] == ("nft", "-f")]
            self.assertIn("delete table inet server_guard", nft_calls[0])

    def test_overlapping_changes_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            tx = Transactions(Files(root), FakeRunner())
            tx.begin()
            with self.assertRaises(GuardError):
                tx.begin()

    def test_timer_failure_does_not_leave_pending_marker(self):
        with tempfile.TemporaryDirectory() as root:
            tx = Transactions(Files(root), FakeRunner(timer=False))
            with self.assertRaises(GuardError):
                tx.begin()
            self.assertFalse(tx.pending())

    def test_cannot_confirm_from_original_connection(self):
        with tempfile.TemporaryDirectory() as root:
            f = Files(root)
            tx = Transactions(f, FakeRunner())
            txid = tx.begin()
            with patch("server_guard.transactions.verified_login", return_value={"time": 0, "user": "admin"}):
                with self.assertRaises(GuardError):
                    tx.confirm(txid)
            self.assertIsNotNone(tx.pending())

    def test_new_admin_login_confirms_and_cancels_timer(self):
        with tempfile.TemporaryDirectory() as root:
            f, runner = Files(root), FakeRunner()
            state = defaults()
            state["users"]["admin"] = {"role": "admin", "sessions": 3}
            PolicyStore(f).save(state)
            tx = Transactions(f, runner)
            txid = tx.begin()
            proof = {"time": time.time() + 1, "user": "admin"}
            with patch("server_guard.transactions.verified_login", return_value=proof):
                tx.confirm(txid)
            self.assertIsNone(tx.pending())
            self.assertTrue(any(args == ("systemctl", "disable", "--now", "server-guard-rollback.timer")
                                for args, _ in runner.calls))

    def test_password_login_cannot_supply_key_login_proof(self):
        runner = FakeRunner()
        env = {"SUDO_USER": "admin", "SSH_CONNECTION": "203.0.113.1 50000 192.0.2.1 22"}
        with patch.dict(os.environ, env, clear=True), self.assertRaises(GuardError):
            verified_login(runner)

    def test_key_login_proof_matches_exact_connection(self):
        message = {"MESSAGE": "Accepted publickey for admin from 203.0.113.1 port 50000 ssh2: ED25519 SHA256:test",
                   "_UID": "0", "_COMM": "sshd",
                   "__REALTIME_TIMESTAMP": "1234567890000000"}
        runner = FakeRunner()
        with patch.object(runner, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(message))):
            with patch.dict(os.environ, {"SUDO_USER": "admin", "SSH_CONNECTION": "203.0.113.1 50000 192.0.2.1 22"}, clear=True):
                self.assertEqual(verified_login(runner)["user"], "admin")
            with patch.dict(os.environ, {"SUDO_USER": "admin", "SSH_CONNECTION": "203.0.113.1 50001 192.0.2.1 22"}, clear=True):
                with self.assertRaises(GuardError):
                    verified_login(runner)


@unittest.skipUnless(Path("/usr/sbin/sshd").exists() and shutil.which("ssh-keygen"), "OpenSSH tools required")
class RealOpenSSHTests(unittest.TestCase):
    def test_real_parser_effective_roles_and_auth(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            key = root / "hostkey"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            state = defaults()
            state["users"] = {"admin": {"role": "admin", "sessions": 3},
                              "dev": {"role": "developer", "sessions": 2},
                              "upload": {"role": "sftp", "sessions": 1}}
            global_path, users_path = root / "global.conf", root / "users.conf"
            global_path.write_text(SSHBuilder.global_config(state))
            users_path.write_text(SSHBuilder.user_config(state))
            main = root / "sshd_config"
            main.write_text(f"Include {global_path}\nHostKey {key}\nSubsystem sftp internal-sftp\nInclude {users_path}\n")
            for user, forwarding in [("root", "no"), ("admin", "local"), ("dev", "no"), ("upload", "no")]:
                run = subprocess.run(["/usr/sbin/sshd", "-T", "-f", str(main), "-C",
                                      f"user={user},host=localhost,addr=203.0.113.1"], capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stderr)
                config = dict(line.split(" ", 1) for line in run.stdout.splitlines() if " " in line)
                self.assertEqual(config["passwordauthentication"], "no")
                self.assertEqual(config["permitrootlogin"], "no")
                self.assertEqual(config["maxsessions"], "1")
                self.assertEqual(config["allowtcpforwarding"], forwarding)
                if user == "upload":
                    self.assertEqual(config["forcecommand"], "internal-sftp -d /upload")


if __name__ == "__main__":
    unittest.main()
