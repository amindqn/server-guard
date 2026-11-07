"""Keyboard-driven terminal views and controllers, independent of host mutations."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile
import textwrap

from . import __version__
from .core import GuardError, POLICY, domain, network, port, public_key, username
from .mongodb import app_database, mongo_name
from .services import checksum


class Cancelled(Exception):
    """Return to the previous menu without submitting a form."""


@dataclass(frozen=True)
class MenuItem:
    key: str
    label: str
    action: object


class TerminalConsole:
    """View adapter: readable without color, cursor control or external packages."""
    def __init__(self, reader=None, stream=None, color=None):
        self.reader = reader or input
        self.stream = stream or sys.stdout
        tty = getattr(self.stream, "isatty", lambda: False)()
        self.color = (tty and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb") if color is None else color

    @staticmethod
    def clean(value):
        return "".join(c for c in str(value) if c in "\n\t" or ord(c) >= 32 and ord(c) != 127)

    def say(self, value="", style=None):
        value = self.clean(value)
        colors = {"title": "36;1", "ok": "32", "error": "31;1", "note": "33"}
        if self.color and style in colors:
            value = f"\033[{colors[style]}m{value}\033[0m"
        print(value, file=self.stream, flush=True)

    def heading(self, title, subtitle=None):
        width = max(30, min(shutil.get_terminal_size((80, 24)).columns - 2, 78))
        self.say()
        self.say("=" * width, "title")
        self.say(f"SERVER GUARD {__version__}  /  {title}", "title")
        self.say("=" * width, "title")
        if subtitle:
            for line in textwrap.wrap(subtitle, width):
                self.say(line)

    def ask(self, label, default=None, validate=None):
        suffix = f" [{default}]" if default is not None else ""
        while True:
            value = self.reader(f"{label}{suffix}: ").strip()
            if value == ":back":
                raise Cancelled()
            if not value and default is not None:
                value = str(default)
            if not value:
                self.say("Error: a value is required. Enter :back to cancel.", "error")
                continue
            try:
                return validate(value) if validate else value
            except (GuardError, ValueError) as exc:
                self.say(f"Error: {exc}", "error")

    def yes(self, label, default=False):
        while True:
            value = self.reader(f"{label} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
            if value == ":back":
                raise Cancelled()
            if not value:
                return default
            if value in {"y", "yes"}:
                return True
            if value in {"n", "no"}:
                return False
            self.say("Enter y or n, or :back to cancel.", "error")

    def choose(self, title, items, subtitle=None, back="Back"):
        self.heading(title, subtitle)
        actions = {item.key: item.action for item in items}
        for item in items:
            self.say(f"  {item.key:>2}  {item.label}")
        self.say(f"   0  {back}")
        while True:
            value = self.reader("Select: ").strip()
            if value in {"0", "q", ":back"}:
                return None
            if value in actions:
                return actions[value]
            self.say("Error: choose one of the numbers shown above.", "error")


def bounded_number(minimum=1, maximum=100):
    def validate(value):
        try:
            result = int(value)
        except ValueError:
            raise GuardError("Enter a whole number.") from None
        if not minimum <= result <= maximum:
            raise GuardError(f"Enter {minimum}..{maximum}.")
        return result
    return validate


class TerminalApp:
    """Controller: forms collect values; an injected Command adapter performs work."""
    def __init__(self, host, execute, console=None):
        self.h = host
        self.execute = execute
        self.c = console or TerminalConsole()

    def run_command(self, *args):
        self.c.say("Running: server-guard " + shlex.join(str(a) for a in args), "note")
        self.execute([str(a) for a in args])

    def operation(self, *args, prompt="Continue?"):
        self.c.say("Review: server-guard " + shlex.join(str(a) for a in args))
        if self.c.yes(prompt):
            self.run_command(*args)
            return True
        self.c.say("No changes submitted.")
        return False

    def page(self, title, items, subtitle=None):
        while True:
            action = self.c.choose(title, items, subtitle)
            if action is None:
                return
            try:
                action()
            except (Cancelled, KeyboardInterrupt):
                self.c.say("Cancelled. Completed commands were retained.", "note")
            except (GuardError, OSError, ValueError, KeyError) as exc:
                self.c.say(f"Error: {exc}", "error")

    def policy(self):
        return self.h.store.load()

    def summary(self):
        try:
            pending = self.h.tx.pending()
            if pending:
                return f"ACTION NEEDED: confirm change {pending['id']} from a new SSH key login, or roll back."
            if not self.h.f.path(POLICY).exists():
                return "First run: start Guided setup. Enter a number; :back cancels a form."
            state = self.policy()
            root = "key only" if state["ssh"]["root_login"] else "disabled"
            baseline = "saved" if self.h.f.path("/etc/server-guard/firewall.nft").exists() else "not applied"
            return (f"Policy: SSH {state['ssh']['port']} | root SSH {root} | "
                    f"{len(state['users'])} users | firewall config {baseline}. :back cancels a form.")
        except (GuardError, OSError, ValueError, KeyError) as exc:
            return f"Saved state needs review: {exc}. Status, recovery and Exit remain available."

    def run(self):
        items = [MenuItem("1", "Guided first-time setup / resume", self.setup),
                 MenuItem("2", "SSH access and root login", self.ssh_menu),
                 MenuItem("3", "Linux users and session limits", self.users_menu),
                 MenuItem("4", "Firewall and public web ports", self.firewall_menu),
                 MenuItem("5", "CloudPanel / aaPanel", self.panel_menu),
                 MenuItem("6", "MongoDB database and users", self.mongodb_menu),
                 MenuItem("7", "V2Ray service and clients", self.v2ray_menu),
                 MenuItem("8", "Status, updates and security audit", self.maintenance_menu),
                 MenuItem("9", "Review, apply, confirm or roll back", self.access_menu)]
        while True:
            try:
                action = self.c.choose("Management", items, self.summary(), back="Exit")
                if action is None:
                    return
                action()
            except KeyboardInterrupt:
                self.c.say("Leaving the management menu. Pending rollback protection stays active.")
                return
            except Cancelled:
                self.c.say("Cancelled. Returning to the management menu.", "note")
            except (GuardError, OSError, ValueError, KeyError) as exc:
                self.c.say(f"Error: {exc}", "error")

    def setup(self):
        try:
            SetupWizard(self).run()
        except (Cancelled, KeyboardInterrupt):
            self.c.say("Setup paused. Run sudo server-guard setup to resume.", "note")
        except (GuardError, OSError, ValueError, KeyError) as exc:
            self.c.say(f"Setup error: {exc}", "error")
            self.c.say("Completed steps were retained. Correct the error and resume Guided setup.")

    def create_user(self, administrator=False):
        self.c.heading("Create administrator" if administrator else "Create Linux user",
                       "Enter :back to cancel. Paste only a public SSH key; keep the private key on your computer.")
        if administrator:
            self.c.say("If you do not have a key yet, run on YOUR COMPUTER:")
            self.c.say("ssh-keygen -t ed25519 -a 100 -f ~/.ssh/server_guard_admin")
            self.c.say("Paste the contents of ~/.ssh/server_guard_admin.pub below.")
        name = self.c.ask("Linux username", "admin" if administrator else None, username)
        role = "admin"
        if not administrator:
            role = self.c.ask("Role (admin / developer / sftp)", "developer", self.role)
        sessions = self.c.ask("Concurrent SSH transports", 3 if role == "admin" else 2,
                              bounded_number(2 if role == "admin" else 1))
        key = self.c.ask("Public key OR .pub file path on THIS server", validate=self.key_input)
        self.c.say(f"User: {name} | role: {role} | session limit: {sessions}")
        if role == "admin":
            self.c.say("Next, passwd will ask for a local sudo password. SSH will use your public key.")
        if not self.c.yes("Create this user?"):
            return
        with tempfile.TemporaryDirectory(prefix="server-guard-ui-key-") as temp:
            path = Path(temp) / "key.pub"
            path.write_text(key)
            path.chmod(0o600)
            self.run_command("user", "add", name, "--role", role, "--sessions", sessions, "--key-file", path)

    @staticmethod
    def role(value):
        if value not in {"admin", "developer", "sftp"}:
            raise GuardError("Choose admin, developer or sftp.")
        return value

    @staticmethod
    def key_input(value):
        if value.startswith(("ssh-", "ecdsa-", "sk-")):
            return public_key(value)
        path = Path(value).expanduser()
        if not path.is_file():
            raise GuardError("Paste an OpenSSH public key or enter an existing .pub file path.")
        return public_key(path.read_text())

    def users_menu(self):
        self.page("Linux users", [
            MenuItem("1", "List managed users", lambda: self.run_command("user", "list")),
            MenuItem("2", "Create admin / developer / SFTP user", self.create_user),
            MenuItem("3", "Adopt an existing panel-created account", self.adopt_user),
            MenuItem("4", "Change concurrent SSH session limit", self.user_limit),
            MenuItem("5", "Replace SSH public key", self.user_key),
            MenuItem("6", "Disable a user", self.disable_user)])

    def managed_user(self):
        names = sorted(self.policy()["users"])
        if not names:
            raise GuardError("Create an administrator first using Guided setup.")
        def check(value):
            if value not in names:
                raise GuardError("Choose a managed username: " + ", ".join(names))
            return value
        return self.c.ask("Managed username (" + ", ".join(names) + ")", validate=check)

    def adopt_user(self):
        name = self.c.ask("Existing Linux/site username", validate=username)
        count = self.c.ask("Concurrent SSH transports", 2, bounded_number())
        self.operation("user", "adopt", name, "--role", "developer", "--sessions", count)

    def user_limit(self):
        name = self.managed_user()
        minimum = 2 if self.policy()["users"][name]["role"] == "admin" else 1
        count = self.c.ask("New session limit", validate=bounded_number(minimum))
        self.operation("user", "limit", name, count)

    def user_key(self):
        name = self.managed_user()
        key = self.c.ask("New public key OR .pub file", validate=self.key_input)
        self.c.say("This immediately replaces the user's current authorized key. Keep recovery access open.", "note")
        if self.c.yes("Replace this SSH key now?"):
            with tempfile.TemporaryDirectory(prefix="server-guard-ui-key-") as temp:
                path = Path(temp) / "key.pub"
                path.write_text(key)
                self.run_command("user", "key", name, "--key-file", path)

    def disable_user(self):
        name = self.managed_user()
        self.operation("user", "disable", name, prompt="Expire this account and block new logins now?")

    def ssh_menu(self):
        self.page("SSH access", [
            MenuItem("1", "Verify this administrator key login", lambda: self.run_command("verify-login")),
            MenuItem("2", "Change SSH port", self.ssh_port),
            MenuItem("3", "Restrict allowed source IPs/networks", self.ssh_sources),
            MenuItem("4", "Disable root SSH login", lambda: self.operation("ssh", "root", "disable")),
            MenuItem("5", "Allow root SSH with a key only", lambda: self.operation("ssh", "root", "key-only")),
            MenuItem("6", "Review and apply staged settings", self.review_apply)],
            "SSH/root/source changes are staged. Review and apply them, then confirm using a new key login.")

    def ssh_port(self):
        value = self.c.ask("New SSH port", self.policy()["ssh"]["port"], port)
        self.c.say("Allow the new port in the provider firewall first. Socket activation may need console migration.", "note")
        self.operation("ssh", "port", value)

    @staticmethod
    def source_list(value):
        sources = value.replace(",", " ").split()
        if not sources:
            raise GuardError("Enter any, an IP, or space-separated CIDR networks.")
        if "any" in sources and len(sources) > 1:
            raise GuardError("Use any alone, or provide only the IP/CIDR allowlist.")
        return ["any" if item == "any" else network(item) for item in sources]

    def ssh_sources(self):
        sources = self.c.ask("Allowed SSH sources (any / IP / CIDRs)", "any", self.source_list)
        self.operation("ssh", "sources", *sources)

    def firewall_menu(self):
        self.page("Firewall", [
            MenuItem("1", "List staged public-port rules", lambda: self.run_command("firewall", "list")),
            MenuItem("2", "Enable public HTTP + HTTPS (80 / 443)", lambda: self.operation("web", "enable")),
            MenuItem("3", "Disable public HTTP + HTTPS", lambda: self.operation("web", "disable")),
            MenuItem("4", "Allow an extra port", lambda: self.port_rule("allow")),
            MenuItem("5", "Remove an exact port allow rule", lambda: self.port_rule("deny")),
            MenuItem("6", "Review and apply staged settings", self.review_apply)],
            "Panel, database and backend ports remain private. Rules take effect after apply and new-login confirmation.")

    def port_rule(self, action):
        number = self.c.ask("Port", validate=port)
        def protocol(value):
            if value not in {"tcp", "udp"}:
                raise GuardError("Choose tcp or udp.")
            return value
        proto = self.c.ask("Protocol", "tcp", protocol)
        source = self.c.ask("Source IP/CIDR or any", "any", lambda s: s if s == "any" else network(s))
        self.operation("firewall", action, number, "--protocol", proto, "--source", source)

    def review_apply(self):
        self.run_command("plan")
        if not self.c.yes("Apply this plan with the 10-minute rollback timer?"):
            return
        replace = self.c.yes("Replace an existing UFW policy with this plan?", default=False)
        self.run_command("apply", *(["--replace-ufw"] if replace else []))
        pending = self.h.tx.pending()
        if pending:
            self.c.say("Reconnect with a NEW administrator key login, then run:", "note")
            self.c.say(f"sudo --preserve-env=SSH_CONNECTION server-guard confirm {pending['id']}")

    def access_menu(self):
        self.page("Access changes", [
            MenuItem("1", "Review staged plan", lambda: self.run_command("plan")),
            MenuItem("2", "Apply plan with rollback protection", self.review_apply),
            MenuItem("3", "Confirm pending change from this new login", self.confirm_pending),
            MenuItem("4", "Roll back pending change", lambda: self.operation("rollback"))],
            "Keep the original SSH session open until a new key login succeeds.")

    def confirm_pending(self):
        pending = self.h.tx.pending()
        if not pending:
            raise GuardError("There is no pending access change.")
        self.run_command("confirm", pending["id"])

    def panel_menu(self):
        self.page("Web control panel", [
            MenuItem("1", "Download / install CloudPanel (recommended)", lambda: self.install_panel("cloudpanel")),
            MenuItem("2", "Download / install aaPanel", lambda: self.install_panel("aapanel")),
            MenuItem("3", "Show private panel access / SSH tunnel", lambda: self.run_command("panel", "info"))],
            "Install one panel on a fresh server, after confirming the baseline. Add MongoDB afterward.")

    def install_panel(self, provider):
        self.c.say("The vendor installer runs as root. Keep its management port closed in the provider firewall.", "note")
        if self.c.yes(f"Download {provider}'s installer for review?", default=True):
            self.run_command("panel", "download", provider)
        self.c.say(f"Review: /var/lib/server-guard/downloads/{provider}.sh")
        digest = self.c.ask("Approved installer SHA-256 (:back to install later)", validate=checksum)
        args = ["panel", "install", provider, "--sha256", digest]
        if provider == "cloudpanel":
            engines = {"MYSQL_8.4", "MYSQL_8.0", "MARIADB_11.4", "MARIADB_10.11"}
            def engine(value):
                if value not in engines:
                    raise GuardError("Choose " + ", ".join(sorted(engines)))
                return value
            args += ["--db-engine", self.c.ask("Database engine", "MYSQL_8.4", engine)]
        self.operation(*args, prompt="Run this approved vendor installer now?")

    def mongodb_menu(self):
        self.page("MongoDB", [
            MenuItem("1", "Install local MongoDB 8.0", self.install_mongodb),
            MenuItem("2", "Create first MongoDB administrator", self.bootstrap_mongodb),
            MenuItem("3", "Add application database user", lambda: self.mongo_user("user-add")),
            MenuItem("4", "Change application database password", lambda: self.mongo_user("password")),
            MenuItem("5", "Revoke application database user", lambda: self.mongo_user("user-revoke")),
            MenuItem("6", "MongoDB service status", lambda: self.run_command("mongodb", "status")),
            MenuItem("7", "Recover an interrupted first-user setup", lambda: self.bootstrap_mongodb(True)),
            MenuItem("8", "Start MongoDB", lambda: self.operation("service", "mongodb", "start")),
            MenuItem("9", "Restart MongoDB", lambda: self.operation("service", "mongodb", "restart")),
            MenuItem("10", "Stop MongoDB", lambda: self.operation("service", "mongodb", "stop"))],
            "MongoDB stays on localhost. Passwords are requested by hidden MongoDB shell prompts.")

    def install_mongodb(self):
        number = self.c.ask("Local MongoDB port", 27017, port)
        self.operation("mongodb", "install", "--port", number)

    def bootstrap_mongodb(self, authenticate=False):
        admin = self.c.ask("MongoDB administrator name", "mongoAdmin", mongo_name)
        self.operation("mongodb", "bootstrap", "--admin", admin,
                       *(["--authenticate"] if authenticate else []))

    def mongo_user(self, action):
        name = self.c.ask("Application database username", validate=mongo_name)
        database = self.c.ask("Application database", validate=app_database)
        admin = self.c.ask("MongoDB administrator name", "mongoAdmin", mongo_name)
        args = ["mongodb", action, name, "--database", database, "--admin", admin]
        if action == "user-add":
            def role(value):
                if value not in {"read", "readWrite"}:
                    raise GuardError("Choose read or readWrite.")
                return value
            args += ["--role", self.c.ask("Permissions (read / readWrite)", "readWrite", role)]
        self.operation(*args)

    def v2ray_menu(self):
        self.page("V2Ray", [
            MenuItem("1", "Install pinned V2Ray v5", self.install_v2ray),
            MenuItem("2", "Configure HTTPS WebSocket backend", self.configure_v2ray),
            MenuItem("3", "List client names", lambda: self.run_command("v2ray", "list")),
            MenuItem("4", "Add a client", lambda: self.v2ray_client("add")),
            MenuItem("5", "Export a secret VMess link", lambda: self.v2ray_client("export")),
            MenuItem("6", "Revoke a client", lambda: self.v2ray_client("revoke")),
            MenuItem("7", "Show Nginx HTTPS location block", lambda: self.run_command("v2ray", "nginx")),
            MenuItem("8", "Start V2Ray", lambda: self.operation("service", "v2ray", "start")),
            MenuItem("9", "Restart V2Ray", lambda: self.operation("service", "v2ray", "restart")),
            MenuItem("10", "Stop V2Ray", lambda: self.operation("service", "v2ray", "stop")),
            MenuItem("11", "V2Ray service status", lambda: self.run_command("service", "v2ray", "status"))],
            "V2Ray listens on localhost behind the panel's HTTPS site. Exported links are credentials.")

    def install_v2ray(self):
        def version(value):
            import re
            if not re.fullmatch(r"v5\.\d+\.\d+", value):
                raise GuardError("Enter a stable v5.X.Y version from the official release page.")
            return value
        tag = self.c.ask("Official release tag (v5.X.Y)", validate=version)
        digest = self.c.ask("Official Linux x86_64 ZIP SHA-256", validate=checksum)
        self.operation("v2ray", "install", "--version", tag, "--sha256", digest)

    def configure_v2ray(self):
        hostname = self.c.ask("HTTPS hostname", validate=domain)
        number = self.c.ask("Private WebSocket backend port", 10000, port)
        self.operation("v2ray", "configure", "--domain", hostname, "--local-port", number)

    def v2ray_client(self, action):
        name = self.c.ask("Client name", validate=username)
        if action == "export":
            if self.c.yes("Display this secret connection link in the terminal?"):
                self.run_command("v2ray", action, name)
        else:
            self.operation("v2ray", action, name)

    def maintenance_menu(self):
        self.page("Status and maintenance", [
            MenuItem("1", "Listening ports and security service status", lambda: self.run_command("status")),
            MenuItem("2", "Run Lynis security audit", lambda: self.run_command("audit")),
            MenuItem("3", "Install / repair base dependencies", lambda: self.operation("prepare")),
            MenuItem("4", "Review and install package updates", lambda: self.operation("update"))])


class SetupWizard:
    """Resumable workflow derived from saved host state, without a global UI lock."""
    def __init__(self, app):
        self.app, self.c, self.h = app, app.c, app.h

    def run(self):
        self.c.heading("Guided setup", "Existing accounts and settings are retained. Enter :back at a form to pause.")
        if self.h.tx.pending():
            self.c.say("An access change is awaiting a NEW administrator login. Confirm or roll back before continuing.", "note")
            self.app.access_menu()
            return
        if not self.h.f.path("/var/lib/server-guard/prepared.json").exists():
            self.c.say("Step 1 / 4: Install Ubuntu security and management dependencies.")
            if not self.app.operation("prepare", prompt="Install the required packages?"):
                return
        if not self.h.f.path(POLICY).exists():
            self.c.say("Step 2 / 4: Create an initial policy using the CURRENT SSH port.")
            connection = os.environ.get("SSH_CONNECTION", "").split()
            current_port = connection[3] if len(connection) == 4 else 22
            number = self.c.ask("Current SSH port", current_port, port)
            if not self.app.operation("init", "--ssh-port", number):
                return
        state = self.app.policy()
        admins = [name for name, item in state["users"].items()
                  if item["role"] == "admin" and not item.get("disabled")]
        if not admins:
            self.c.say("Step 3 / 4: Create a non-root administrator with your public SSH key.")
            self.app.create_user(administrator=True)
            state = self.app.policy()
            admins = [name for name, item in state["users"].items()
                      if item["role"] == "admin" and not item.get("disabled")]
            if not admins:
                return
        if not self.h.f.path("/etc/server-guard/firewall.nft").exists():
            self.c.say("Step 4 / 4: Verify a second administrator key login, then apply protection.")
            self.c.say("Keep this SSH connection open. In a NEW terminal on your computer run:", "note")
            self.c.say(f"ssh -o IdentitiesOnly=yes -i ~/.ssh/server_guard_admin -p {state['ssh']['port']} {admins[0]}@SERVER_IP")
            self.c.say("Then, inside that new SSH connection:")
            self.c.say("sudo --preserve-env=SSH_CONNECTION server-guard setup")
            if os.environ.get("SUDO_USER") not in admins:
                self.c.say("Setup saved. Resume from the new administrator login; root/password access has not been disabled.", "ok")
                return
            if not self.c.yes("Verify THIS new key login and review the security plan?"):
                return
            self.app.run_command("verify-login")
            self.app.review_apply()
            return
        self.c.say("Baseline configuration saved. Choose optional services next.", "ok")
        self.c.say("Recommended order: web panel, public HTTP/HTTPS, optional MongoDB, optional V2Ray.")
        self.app.page("Optional services", [
            MenuItem("1", "Install CloudPanel / aaPanel", self.app.panel_menu),
            MenuItem("2", "Configure public web ports", self.app.firewall_menu),
            MenuItem("3", "Install / configure MongoDB", self.app.mongodb_menu),
            MenuItem("4", "Install / configure V2Ray", self.app.v2ray_menu)])
