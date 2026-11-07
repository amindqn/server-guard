import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from server_guard.cli import parser
from server_guard.core import Files, GuardError, PolicyStore, defaults
from server_guard.host import Host
from server_guard.mongodb import (MONGO_CONFIG, MONGO_KEY_FINGERPRINT, MONGO_SOURCE, MONGO_STATE,
    MongoDBBuilder, MongoDBManager, app_database, mongo_name, verify_key_fingerprint)


class MongoRunner:
    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail

    def run(self, *args, check=True, input=None, capture=True):
        self.calls.append((args, input, capture))
        if self.fail and self.fail(args):
            if check:
                raise GuardError("injected MongoDB failure")
            return subprocess.CompletedProcess(args, 1, "", "failure")
        output, code = "", 0
        if args[:2] in {("systemctl", "is-active"), ("systemctl", "is-enabled")}:
            code = 3
        elif args[:2] == ("nft", "list"):
            code = 1
        elif args[0] == "gpg" and "--show-keys" in args:
            output = "pub:::::::::\nfpr:::::::::" + MONGO_KEY_FINGERPRINT + ":\n"
        elif args[0] == "gpg" and "--dearmor" in args:
            Path(args[args.index("--output") + 1]).write_bytes(b"verified-test-key")
        return subprocess.CompletedProcess(args, code, output, "")


class MongoValidationTests(unittest.TestCase):
    def test_names_and_reserved_databases(self):
        self.assertEqual(mongo_name("app-user_1"), "app-user_1")
        for value in ["../app", "app;quit()", 'app"', "-a", "a" * 64]:
            with self.subTest(value=value), self.assertRaises(GuardError):
                mongo_name(value)
        for value in ["admin", "local", "config", "Admin"]:
            with self.subTest(value=value), self.assertRaises(GuardError):
                app_database(value)

    def test_official_signing_key_pin(self):
        output = "pub:::::::::\nfpr:::::::::" + MONGO_KEY_FINGERPRINT + ":\nsub:::::::::\nfpr:::::::::" + "A" * 40 + ":\n"
        verify_key_fingerprint(output)
        for invalid in ["", output.replace(MONGO_KEY_FINGERPRINT, "A" * 40), output + output]:
            with self.assertRaises(GuardError):
                verify_key_fingerprint(invalid)

    def test_config_never_exposes_unauthenticated_public_listener(self):
        config = json.loads(MongoDBBuilder.config(27017))
        self.assertEqual(config["security"]["authorization"], "enabled")
        self.assertEqual(config["net"]["bindIp"], "127.0.0.1")
        self.assertFalse(config["net"]["unixDomainSocket"]["enabled"])
        self.assertEqual(config["storage"]["dbPath"], "/var/lib/mongodb")

    def test_bootstrap_gate_is_owned_root_only_and_port_scoped(self):
        rules = MongoDBBuilder.bootstrap_guard(27018, True)
        self.assertIn("delete table inet server_guard_mongodb_bootstrap", rules)
        self.assertIn("ip daddr 127.0.0.1 tcp dport 27018 meta skuid != 0", rules)
        self.assertNotIn("flush ruleset", rules)
        self.assertNotIn("server_guard {", rules)

    def test_scoped_roles_reject_privilege_escalation(self):
        script = MongoDBBuilder.user_script("add", "appuser", "myapp", "read")
        self.assertIn('role: "read", db: "myapp"', script)
        self.assertNotIn("AnyDatabase", script)
        self.assertIn("passwordPrompt()", script)
        with self.assertRaises(GuardError):
            MongoDBBuilder.user_script("add", "appuser", "myapp", "root")

    def test_cli_has_no_plaintext_password_argument(self):
        args = parser().parse_args(["mongodb", "user-add", "appuser", "--database", "myapp", "--role", "read"])
        self.assertEqual(args.command, "mongodb")
        self.assertEqual(args.role, "read")
        self.assertFalse(hasattr(args, "password"))

    def test_cpu_and_known_kernel_incompatibilities_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            host = Host(Files(root), MongoRunner())
            manager = MongoDBManager(host)
            host.f.write("/proc/cpuinfo", "flags : sse sse2\n")
            with patch("server_guard.mongodb.platform.machine", return_value="x86_64"), self.assertRaises(GuardError):
                manager.check_platform()
            host.f.write("/proc/cpuinfo", "flags : sse avx avx2\n")
            for version in ["6.19.0-generic", "7.0.13-generic"]:
                with self.subTest(version=version), patch("server_guard.mongodb.platform.machine", return_value="x86_64"), \
                     patch("server_guard.mongodb.platform.release", return_value=version), self.assertRaises(GuardError):
                    manager.check_platform()
            with patch("server_guard.mongodb.platform.machine", return_value="x86_64"), \
                 patch("server_guard.mongodb.platform.release", return_value="6.8.0-generic"):
                manager.check_platform()

    @unittest.skipUnless(shutil.which("node"), "Node is used only for a development script-semantics check")
    def test_real_javascript_executes_scoped_user_and_hidden_prompt_logic(self):
        harness = """
const vm = require('node:vm');
const code = JSON.parse(process.argv[1]);
const calls = [];
const context = {print() {}, passwordPrompt() {return 'test-only-password-012345';},
 db: {getSiblingDB(name) { return {createUser(user) {calls.push({database:name, user});}};}}};
vm.runInNewContext(code, context);
process.stdout.write(JSON.stringify(calls));
"""
        script = MongoDBBuilder.user_script("add", "reports", "myapp", "read")
        result = subprocess.run([shutil.which("node"), "-e", harness, json.dumps(script)], check=True, text=True, capture_output=True)
        calls = json.loads(result.stdout)
        self.assertEqual(calls[0]["database"], "myapp")
        self.assertEqual(calls[0]["user"]["roles"], [{"role": "read", "db": "myapp"}])


class MongoLifecycleTests(unittest.TestCase):
    def fixture(self, root, runner=None):
        files = Files(root)
        host = Host(files, runner or MongoRunner())
        PolicyStore(files).save(defaults())
        files.write("/etc/server-guard/firewall.nft", "table inet server_guard {}\n")
        return host, MongoDBManager(host)

    def installed(self, files):
        files.write(MONGO_STATE, json.dumps({"series": "8.0", "port": 27017, "initialized": False}))
        files.write(MONGO_CONFIG, MongoDBBuilder.config(27017), 0o644)

    def test_interactive_shell_cannot_hold_up_pending_access_rollback(self):
        with tempfile.TemporaryDirectory() as root:
            h, manager = self.fixture(root)
            h.f.write("/var/lib/server-guard/pending.json", '{"id": "pending-test"}')
            with self.assertRaises(GuardError):
                manager.shell({"port": 27017}, admin="mongoAdmin")
            self.assertEqual(h.r.calls, [])

    def test_existing_data_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            h, manager = self.fixture(root)
            h.f.path("/var/lib/mongodb").mkdir(parents=True)
            with patch.object(manager, "check_platform"), self.assertRaises(GuardError):
                manager.install(27017)
            self.assertEqual(h.r.calls, [])

    def test_install_is_masked_until_safe_config_written_and_stays_stopped(self):
        with tempfile.TemporaryDirectory() as root:
            h, manager = self.fixture(root)
            def fake_download(runner, url, path):
                path.write_text("test key")
            with patch.object(manager, "check_platform"), patch("server_guard.mongodb.download", side_effect=fake_download):
                manager.install(27017)
            commands = [a for a, _, _ in h.r.calls]
            mask = commands.index(("systemctl", "mask", "mongod.service"))
            install = commands.index(("apt-get", "install", "-y", "mongodb-org"))
            validate = commands.index(("mongod", "--config", MONGO_CONFIG, "--outputConfig"))
            unmask = commands.index(("systemctl", "unmask", "mongod.service"))
            self.assertLess(mask, install)
            self.assertLess(install, validate)
            self.assertLess(validate, unmask)
            self.assertNotIn(("systemctl", "start", "mongod"), commands)
            self.assertFalse(manager.state(initialized=False)["initialized"])
            source = h.f.path(MONGO_SOURCE).read_text()
            self.assertIn("signed-by=", source)
            self.assertIn("noble/mongodb-org/8.0", source)

    def test_install_failure_remasks_service(self):
        with tempfile.TemporaryDirectory() as root:
            runner = MongoRunner(lambda args: args == ("apt-get", "install", "-y", "mongodb-org"))
            h, manager = self.fixture(root, runner)
            with patch.object(manager, "check_platform"), patch("server_guard.mongodb.download", side_effect=lambda r,u,p: p.write_text("key")):
                with self.assertRaises(GuardError):
                    manager.install(27017)
            self.assertIn(("systemctl", "mask", "--now", "mongod.service"), [a for a,_,_ in runner.calls])
            self.assertFalse(h.f.path(MONGO_STATE).exists())

    def test_bootstrap_gate_precedes_start_and_credentials_never_saved(self):
        with tempfile.TemporaryDirectory() as root:
            h, manager = self.fixture(root)
            self.installed(h.f)
            with patch.object(manager, "wait_ready"):
                manager.bootstrap("mongoAdmin")
            commands = [a for a,_,_ in h.r.calls]
            self.assertLess(commands.index(("nft", "-f", "-")), commands.index(("systemctl", "start", "mongod")))
            self.assertIn(("systemctl", "enable", "mongod"), commands)
            self.assertEqual(manager.state()["admin"], "mongoAdmin")
            self.assertNotIn("password", h.f.path(MONGO_STATE).read_text().lower())
            scripts = [a for a,_,_ in h.r.calls if a[0] == "mongosh"]
            self.assertIn("passwordPrompt()", scripts[0][-1])

    def test_failed_bootstrap_stops_before_removing_guard(self):
        with tempfile.TemporaryDirectory() as root:
            h, manager = self.fixture(root)
            self.installed(h.f)
            with patch.object(manager, "wait_ready"), patch.object(manager, "shell", side_effect=GuardError("bad password")):
                with self.assertRaises(GuardError):
                    manager.bootstrap("mongoAdmin")
            commands = [a for a,_,_ in h.r.calls]
            stop = commands.index(("systemctl", "stop", "mongod"))
            remove = commands.index(("nft", "delete", "table", "inet", "server_guard_mongodb_bootstrap"))
            self.assertLess(stop, remove)
            self.assertFalse(manager.state(initialized=False)["initialized"])

    def test_failed_stop_retains_first_user_guard(self):
        with tempfile.TemporaryDirectory() as root:
            runner = MongoRunner(lambda args: args == ("systemctl", "stop", "mongod"))
            h, manager = self.fixture(root, runner)
            self.installed(h.f)
            with patch.object(manager, "wait_ready", side_effect=GuardError("failed startup")):
                with self.assertRaises(GuardError):
                    manager.bootstrap("mongoAdmin")
            self.assertNotIn(("nft", "delete", "table", "inet", "server_guard_mongodb_bootstrap"), [a for a,_,_ in runner.calls])

    def test_authentication_recovery_uses_password_prompt(self):
        with tempfile.TemporaryDirectory() as root:
            h, manager = self.fixture(root)
            self.installed(h.f)
            with patch.object(manager, "wait_ready"):
                manager.bootstrap("mongoAdmin", authenticate=True)
            commands = [a for a,_,_ in h.r.calls if a[0] == "mongosh"]
            self.assertEqual(commands[0][-1], "--password")
            self.assertNotIn("createUser", commands[0][commands[0].index("--eval") + 1])

    def test_changed_bootstrap_config_is_rejected_before_start(self):
        with tempfile.TemporaryDirectory() as root:
            h, manager = self.fixture(root)
            self.installed(h.f)
            config = json.loads(h.f.path(MONGO_CONFIG).read_text())
            config["net"]["bindIp"] = "0.0.0.0"
            h.f.write(MONGO_CONFIG, json.dumps(config))
            with self.assertRaises(GuardError):
                manager.bootstrap("mongoAdmin")
            self.assertEqual(h.r.calls, [])


if __name__ == "__main__":
    unittest.main()
