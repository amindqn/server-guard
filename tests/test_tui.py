import base64
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
from server_guard.host import Host
from server_guard.services import ManagedServices
from server_guard.tui import Cancelled, SetupWizard, TerminalApp, TerminalConsole


class SilentRunner:
    def __init__(self):
        self.calls = []

    def run(self, *args, **kwargs):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")


def test_key():
    kind = b"ssh-ed25519"
    data = len(kind).to_bytes(4, "big") + kind + (32).to_bytes(4, "big") + bytes(range(32))
    return "ssh-ed25519 " + base64.b64encode(data).decode()


class TerminalFormTests(unittest.TestCase):
    def console(self, answers):
        answers = iter(answers)
        output = io.StringIO()
        return TerminalConsole(reader=lambda prompt: next(answers), stream=output, color=False), output

    def test_invalid_field_is_explained_and_can_be_corrected(self):
        console, output = self.console(["nonsense", "2222"])
        from server_guard.core import port
        self.assertEqual(console.ask("Port", validate=port), 2222)
        self.assertIn("Error: Port must be an integer", output.getvalue())

    def test_defaults_and_cancel_are_predictable(self):
        console, _ = self.console(["", ":back"])
        self.assertEqual(console.ask("Port", 22), "22")
        with self.assertRaises(Cancelled):
            console.ask("Username")

    def test_mutation_confirmation_defaults_to_no(self):
        console, _ = self.console([""])
        self.assertFalse(console.yes("Apply?"))

    def test_no_color_and_control_characters_are_supported(self):
        class TTY(io.StringIO):
            def isatty(self):
                return True
        output = TTY()
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            console = TerminalConsole(stream=output)
        console.say("Error: \033[2Jbad", "error")
        self.assertNotIn("\033", output.getvalue())
        self.assertIn("Error:", output.getvalue())

    def test_public_key_form_rejects_private_key_and_accepts_public_key(self):
        self.assertTrue(TerminalApp.key_input(test_key()).startswith("ssh-ed25519 "))
        with self.assertRaises(GuardError):
            TerminalApp.key_input("-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_source_allowlist_cannot_accidentally_include_any(self):
        with self.assertRaises(GuardError):
            TerminalApp.source_list("any 203.0.113.1")
        self.assertEqual(TerminalApp.source_list("203.0.113.1 2001:db8::/64"),
                         ["203.0.113.1/32", "2001:db8::/64"])


class TerminalWorkflowTests(unittest.TestCase):
    def fixture(self, root, answers, initialized=True):
        host = Host(Files(root), SilentRunner())
        host.f.path("/run/server-guard").mkdir(parents=True)
        if initialized:
            state = defaults()
            state["users"]["admin"] = {"role": "admin", "sessions": 3, "disabled": False}
            PolicyStore(host.f).save(state)
            host.f.write("/var/lib/server-guard/prepared.json", "{}")
        responses = iter(answers)
        output = io.StringIO()
        console = TerminalConsole(reader=lambda prompt: next(responses), stream=output, color=False)
        calls = []
        def execute(args):
            # All submitted form results must also pass the actual CLI grammar.
            parsed = parser().parse_args(args)
            calls.append(args)
            if parsed.command == "prepare":
                host.f.write("/var/lib/server-guard/prepared.json", "{}")
            if parsed.command == "init":
                PolicyStore(host.f).save(defaults(parsed.ssh_port))
            if parsed.command == "user" and parsed.action == "add":
                state = host.store.load()
                state["users"][parsed.name] = {"role": parsed.role, "sessions": parsed.sessions}
                PolicyStore(host.f).save(state)
            if parsed.command == "apply":
                host.f.write("/var/lib/server-guard/pending.json", '{"id":"new-change"}')
        return TerminalApp(host, execute, console), calls, output

    def test_cancelled_ssh_form_never_submits_a_command(self):
        with tempfile.TemporaryDirectory() as root:
            app, calls, _ = self.fixture(root, [":back"])
            with self.assertRaises(Cancelled):
                app.ssh_port()
            self.assertEqual(calls, [])

    def test_ctrl_c_at_top_level_exits_without_commands(self):
        with tempfile.TemporaryDirectory() as root:
            app, calls, _ = self.fixture(root, [])
            with patch.object(app.c, "choose", side_effect=KeyboardInterrupt):
                app.run()
            self.assertEqual(calls, [])

    def test_corrupt_policy_still_allows_menu_exit(self):
        with tempfile.TemporaryDirectory() as root:
            app, calls, output = self.fixture(root, ["0"])
            app.h.f.write(POLICY, "broken json")
            app.run()
            self.assertEqual(calls, [])
            self.assertIn("Saved state needs review", output.getvalue())

    def test_extra_port_form_submits_validated_source_and_protocol(self):
        with tempfile.TemporaryDirectory() as root:
            app, calls, _ = self.fixture(root, ["9443", "tcp", "203.0.113.7/32", "y"])
            app.port_rule("allow")
            self.assertEqual(calls, [["firewall", "allow", "9443", "--protocol", "tcp", "--source", "203.0.113.7/32"]])

    def test_mongodb_form_scopes_the_application_role(self):
        with tempfile.TemporaryDirectory() as root:
            app, calls, _ = self.fixture(root, ["reports", "myapp", "mongoAdmin", "read", "y"])
            app.mongo_user("user-add")
            self.assertEqual(calls[0], ["mongodb", "user-add", "reports", "--database", "myapp",
                                        "--admin", "mongoAdmin", "--role", "read"])

    def test_secret_export_requires_an_explicit_yes(self):
        with tempfile.TemporaryDirectory() as root:
            app, calls, _ = self.fixture(root, ["phone", "n"])
            app.v2ray_client("export")
            self.assertEqual(calls, [])

    def test_first_root_setup_pauses_before_access_hardening(self):
        with tempfile.TemporaryDirectory() as root:
            answers = ["y", "22", "y", "admin", "3", test_key(), "y"]
            app, calls, output = self.fixture(root, answers, initialized=False)
            with patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 50000 203.0.113.1 22"}, clear=True):
                SetupWizard(app).run()
            self.assertEqual([args[0] for args in calls], ["prepare", "init", "user"])
            self.assertIn("Resume from the new administrator login", output.getvalue())
            self.assertNotIn(["apply"], calls)
            self.assertFalse(app.h.f.path("/etc/server-guard/firewall.nft").exists())

    def test_resume_verifies_login_and_reviews_before_apply(self):
        with tempfile.TemporaryDirectory() as root:
            app, calls, output = self.fixture(root, ["y", "y", "n"])
            with patch.dict(os.environ, {"SUDO_USER": "admin"}, clear=True):
                SetupWizard(app).run()
            self.assertEqual(calls, [["verify-login"], ["plan"], ["apply"]])
            self.assertIn("NEW administrator key login", output.getvalue())
            self.assertNotIn(["confirm", "new-change"], calls)

    def test_pending_change_routes_to_recovery_without_prepare(self):
        with tempfile.TemporaryDirectory() as root:
            app, calls, output = self.fixture(root, ["0"])
            app.h.f.write("/var/lib/server-guard/pending.json", '{"id":"pending-change"}')
            SetupWizard(app).run()
            self.assertEqual(calls, [])
            self.assertIn("awaiting a NEW administrator login", output.getvalue())

    def test_confirm_uses_pending_id_without_auto_applying(self):
        with tempfile.TemporaryDirectory() as root:
            app, calls, _ = self.fixture(root, [])
            app.h.f.write("/var/lib/server-guard/pending.json", '{"id":"pending-change"}')
            app.confirm_pending()
            self.assertEqual(calls, [["confirm", "pending-change"]])

    def test_ui_prompts_do_not_hold_the_management_lock(self):
        with tempfile.TemporaryDirectory() as root:
            app, _, _ = self.fixture(root, [])
            answers = iter(["2222", "y"])
            observed = []
            path = app.h.f.path("/run/server-guard/management.lock")
            def reader(prompt):
                with path.open("a") as stream:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                observed.append("prompt-unlocked")
                return next(answers)
            def dispatch(host, args):
                with path.open("a") as stream:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                observed.append("command-locked")
            app.c.reader = reader
            app.execute = lambda args: execute_locked(app.h, args)
            with patch("server_guard.cli.dispatch", side_effect=dispatch):
                app.ssh_port()
            self.assertEqual(observed, ["prompt-unlocked", "prompt-unlocked", "command-locked"])


class ManagedServiceTests(unittest.TestCase):
    def test_mongodb_cannot_bypass_first_user_bootstrap_via_start(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), SilentRunner())
            host.f.write("/etc/server-guard/mongodb.json", '{"port":27017,"initialized":false}')
            with self.assertRaises(GuardError):
                ManagedServices(host).control("mongodb", "start")
            self.assertEqual(host.r.calls, [])

    def test_optional_service_restart_refuses_pending_access_change(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), SilentRunner())
            host.f.write("/var/lib/server-guard/pending.json", '{"id":"pending"}')
            with self.assertRaises(GuardError):
                ManagedServices(host).control("v2ray", "restart")
            self.assertEqual(host.r.calls, [])

    def test_service_allowlist_excludes_ssh_and_firewall(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), SilentRunner())
            for name in ["ssh", "nftables", "server-guard-firewall"]:
                with self.assertRaises(GuardError):
                    ManagedServices(host).control(name, "stop")
            self.assertEqual(host.r.calls, [])


if __name__ == "__main__":
    unittest.main()
