import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from server_guard.core import GuardError, public_key, write_user_key
from server_guard.ssh_access import SSHLoginInspector


class SSHInspectionTests(unittest.TestCase):
    ENV = {"SUDO_USER": "admin", "SSH_CONNECTION": "203.0.113.1 50000 192.0.2.1 22"}

    def row(self, method="publickey", **changes):
        result = {"_UID": "0", "_COMM": "sshd",
                  "MESSAGE": f"Accepted {method} for admin from 203.0.113.1 port 50000 ssh2",
                  "__REALTIME_TIMESTAMP": "1794000000000000"}
        result.update(changes)
        return json.dumps(result)

    def inspector(self, *lines):
        runner = Mock()
        runner.run.return_value = subprocess.CompletedProcess([], 0, "\n".join(lines), "")
        return SSHLoginInspector(runner)

    def test_password_and_interactive_logins_explain_reconnect_requirement(self):
        for method in ["password", "keyboard-interactive/pam"]:
            with self.subTest(method=method), patch.dict(os.environ, self.ENV, clear=True):
                inspector = self.inspector(self.row(method))
                self.assertEqual(inspector.inspect()["method"], method)
                with self.assertRaisesRegex(GuardError, "Reconnect from your computer"):
                    inspector.verified()

    def test_newer_password_record_cannot_reuse_old_publickey_proof(self):
        with patch.dict(os.environ, self.ENV, clear=True):
            inspector = self.inspector(self.row(), self.row("password"))
            with self.assertRaises(GuardError):
                inspector.verified()

    def test_unprivileged_logger_cannot_forge_a_successful_key_record(self):
        with patch.dict(os.environ, self.ENV, clear=True):
            for change in [{"_UID": "1000"}, {"_COMM": "logger"}]:
                with self.subTest(change=change), self.assertRaises(GuardError):
                    self.inspector(self.row(**change)).verified()

    def test_daemon_variants_and_ipv4_mapped_peer_are_supported(self):
        env = dict(self.ENV, SSH_CONNECTION="::ffff:203.0.113.1 50000 192.0.2.1 22")
        with patch.dict(os.environ, env, clear=True):
            for daemon in SSHLoginInspector.DAEMONS:
                with self.subTest(daemon=daemon):
                    self.assertEqual(self.inspector(self.row(_COMM=daemon)).verified()["user"], "admin")

    def test_malformed_and_other_transport_records_do_not_verify(self):
        with patch.dict(os.environ, self.ENV, clear=True):
            lines = ["not json", "[]", self.row(__REALTIME_TIMESTAMP=None),
                     self.row(MESSAGE="Accepted publickey for admin from 203.0.113.1 port 50001 ssh2")]
            with self.assertRaises(GuardError):
                self.inspector(*lines).verified()

    def test_root_or_missing_connection_has_actionable_guidance(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(GuardError, "new non-root administrator SSH login"):
                self.inspector().verified()


def key(seed):
    kind = b"ssh-ed25519"
    blob = len(kind).to_bytes(4, "big") + kind + (32).to_bytes(4, "big") + bytes([seed]) * 32
    return public_key("ssh-ed25519 " + base64.b64encode(blob).decode())


class AppendKeyTests(unittest.TestCase):
    def test_add_retains_existing_keys_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            write_user_key(home, key(1), os.getuid(), os.getgid())
            write_user_key(home, key(2), os.getuid(), os.getgid(), append=True)
            path = home / ".ssh/authorized_keys"
            before = path.read_text()
            self.assertEqual(before, key(1) + key(2))
            write_user_key(home, key(2), os.getuid(), os.getgid(), append=True)
            self.assertEqual(path.read_text(), before)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_existing_symlink_or_fifo_cannot_redirect_or_block_privileged_read(self):
        for kind in ["symlink", "fifo"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as root:
                home = Path(root)
                (home / ".ssh").mkdir()
                path = home / ".ssh/authorized_keys"
                if kind == "symlink":
                    path.symlink_to(home / "victim")
                else:
                    os.mkfifo(path)
                with self.assertRaises((OSError, GuardError)):
                    write_user_key(home, key(1), os.getuid(), os.getgid(), append=True)
                self.assertFalse((home / "victim").exists())

    def test_custom_authorized_key_options_are_preserved_on_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            (home / ".ssh").mkdir()
            path = home / ".ssh/authorized_keys"
            before = 'command="/usr/bin/true" ' + key(1)
            path.write_text(before)
            with self.assertRaises(GuardError):
                write_user_key(home, key(2), os.getuid(), os.getgid(), append=True)
            self.assertEqual(path.read_text(), before)


if __name__ == "__main__":
    unittest.main()
