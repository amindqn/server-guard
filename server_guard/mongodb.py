"""Optional MongoDB Community service with authenticated, local-only access."""
from __future__ import annotations

import json
from pathlib import Path
import platform
import re
import tempfile
import time

from .core import GuardError, port
from .services import download


MONGO_STATE = "/etc/server-guard/mongodb.json"
MONGO_CONFIG = "/etc/mongod.conf"
MONGO_SERIES = "8.0"
# Primary fingerprint of https://pgp.mongodb.com/server-8.0.asc, checked 2026-11-07.
MONGO_KEY_FINGERPRINT = "4B0752C1BCA238C0B4EE14DC41DE058A4E7DCA05"
MONGO_KEYRING = "/usr/share/keyrings/server-guard-mongodb-8.0.gpg"
MONGO_SOURCE = "/etc/apt/sources.list.d/server-guard-mongodb-8.0.list"


def mongo_name(value):
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,62}", value):
        raise GuardError("MongoDB names must start with a letter and contain only letters, digits, _ or - (max 63).")
    return value


def app_database(value):
    mongo_name(value)
    if value.lower() in {"admin", "local", "config"}:
        raise GuardError("Choose an application database, not admin, local or config.")
    return value


def verify_key_fingerprint(output):
    primaries = []
    waiting = False
    for line in output.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            waiting = True
        elif fields[0] == "sub":
            waiting = False
        elif fields[0] == "fpr" and waiting:
            if len(fields) < 10:
                raise GuardError("Malformed MongoDB signing-key information.")
            primaries.append(fields[9].upper())
            waiting = False
    if primaries != [MONGO_KEY_FINGERPRINT]:
        raise GuardError("MongoDB signing key fingerprint changed. Verify the publisher key before updating the tool.")


class MongoDBBuilder:
    """Builder: JSON is valid YAML and needs no third-party parser to maintain."""
    @staticmethod
    def config(listen_port):
        return json.dumps({
            "storage": {"dbPath": "/var/lib/mongodb"},
            "systemLog": {"destination": "file", "logAppend": True,
                          "path": "/var/log/mongodb/mongod.log"},
            "net": {"port": port(listen_port), "bindIp": "127.0.0.1",
                    "unixDomainSocket": {"enabled": False}},
            "security": {"authorization": "enabled"},
        }, indent=2) + "\n"

    @staticmethod
    def bootstrap_guard(listen_port, exists):
        prefix = "delete table inet server_guard_mongodb_bootstrap\n" if exists else ""
        return prefix + f"""table inet server_guard_mongodb_bootstrap {{
 chain output {{
  type filter hook output priority -12; policy accept;
  ip daddr 127.0.0.1 tcp dport {port(listen_port)} meta skuid != 0 counter drop
 }}
}}
"""

    @staticmethod
    def password_prompt():
        return """function newPassword() {
  print('Enter a new MongoDB password twice (minimum 16 characters):');
  const first = passwordPrompt();
  const second = passwordPrompt();
  if (first !== second || first.length < 16) {
    throw new Error('Passwords must match and contain at least 16 characters.');
  }
  return first;
}
"""

    @staticmethod
    def bootstrap(admin):
        admin = json.dumps(mongo_name(admin))
        return MongoDBBuilder.password_prompt() + f"""
const target = db.getSiblingDB('admin');
const secret = newPassword();
target.createUser({{user: {admin}, pwd: secret,
                   roles: [{{role: 'userAdminAnyDatabase', db: 'admin'}}]}});
if (!target.auth({admin}, secret)) throw new Error('Administrator authentication failed.');
print('MongoDB user administrator created and authenticated.');
"""

    @staticmethod
    def user_script(action, name, database, role="readWrite"):
        name, database = json.dumps(mongo_name(name)), json.dumps(app_database(database))
        if role not in {"read", "readWrite"}:
            raise GuardError("Application roles are read or readWrite.")
        target = f"const target = db.getSiblingDB({database});\n"
        if action == "add":
            return MongoDBBuilder.password_prompt() + target + (
                f"target.createUser({{user: {name}, pwd: newPassword(), "
                f"roles: [{{role: {json.dumps(role)}, db: {database}}}]}});\n")
        if action == "password":
            return MongoDBBuilder.password_prompt() + target + f"target.changeUserPassword({name}, newPassword());\n"
        if action == "revoke":
            return target + f"if (!target.dropUser({name})) throw new Error('Unknown user in this database.');\n"
        raise GuardError("Unsupported MongoDB user operation.")


class MongoDBManager:
    def __init__(self, host):
        self.h = host

    def state(self, initialized=True):
        try:
            data = json.loads(self.h.f.path(MONGO_STATE).read_text())
        except FileNotFoundError:
            raise GuardError("Install the optional service first: server-guard mongodb install") from None
        port(data["port"])
        if initialized and not data["initialized"]:
            raise GuardError("Run mongodb bootstrap to create/authenticate the first administrator.")
        return data

    def save(self, data):
        self.h.f.write(MONGO_STATE, json.dumps(data, indent=2) + "\n")

    def check_platform(self):
        if platform.machine() != "x86_64":
            raise GuardError("This MongoDB option currently supports Ubuntu 24.04 x86_64 only.")
        cpuinfo = self.h.f.path("/proc/cpuinfo").read_text()
        if not any(line.startswith("flags") and "avx" in line.split() for line in cpuinfo.splitlines()):
            raise GuardError("MongoDB requires an AVX-capable CPU exposed by the VPS hypervisor.")
        match = re.match(r"(\d+)\.(\d+)\.(\d+)", platform.release())
        if match and (6, 19, 0) <= tuple(map(int, match.groups())) <= (7, 0, 13):
            raise GuardError("MongoDB documents an incompatible kernel range 6.19 through 7.0.13; use a supported kernel.")

    def install(self, listen_port):
        self.h.tx.require_clear()
        self.check_platform()
        state = self.h.store.load()
        listen_port = port(listen_port)
        if listen_port in {state["ssh"]["port"], state["v2ray"]["port"], 80, 443}:
            raise GuardError("MongoDB port conflicts with SSH, V2Ray or the web server.")
        if not self.h.f.path("/etc/server-guard/firewall.nft").exists():
            raise GuardError("Apply and confirm the SSH/firewall baseline before installing MongoDB.")
        for path in [MONGO_STATE, MONGO_CONFIG, "/usr/bin/mongod", "/www/server/mongodb", "/var/lib/mongodb"]:
            if self.h.f.path(path).exists():
                raise GuardError("Existing MongoDB installation/data detected. Refusing to replace it; use its owning manager.")
        for service in ["mongod", "mongodb"]:
            if self.h.tx.active(service) or self.h.tx.enabled(service):
                raise GuardError("An existing MongoDB service is configured. Refusing takeover.")
        self.h.r.run("apt-get", "update", capture=False)
        self.h.r.run("apt-get", "install", "-y", "ca-certificates", "curl", "gnupg", capture=False)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key, keyring = root / "server-8.0.asc", root / "mongodb.gpg"
            download(self.h.r, "https://pgp.mongodb.com/server-8.0.asc", key)
            info = self.h.r.run("gpg", "--batch", "--homedir", root, "--show-keys", "--with-colons", key)
            verify_key_fingerprint(info.stdout)
            self.h.r.run("gpg", "--batch", "--homedir", root, "--output", keyring, "--dearmor", key)
            self.h.f.write(MONGO_KEYRING, keyring.read_bytes(), 0o644)
        self.h.f.write(MONGO_SOURCE,
            f"deb [arch=amd64 signed-by={MONGO_KEYRING}] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/{MONGO_SERIES} multiverse\n", 0o644)
        self.h.r.run("apt-get", "update", capture=False)
        # No server startup with the package's default config, even if postinst tries.
        self.h.r.run("systemctl", "mask", "mongod.service")
        try:
            self.h.r.run("apt-get", "install", "-y", "mongodb-org", capture=False)
            self.h.f.write(MONGO_CONFIG, MongoDBBuilder.config(listen_port), 0o644)
            self.h.r.run("mongod", "--config", MONGO_CONFIG, "--outputConfig")
            self.save({"series": MONGO_SERIES, "port": listen_port, "initialized": False})
            self.h.r.run("systemctl", "unmask", "mongod.service")
            self.h.r.run("systemctl", "disable", "mongod.service")
            self.h.r.run("systemctl", "daemon-reload")
        except BaseException:
            self.h.r.run("systemctl", "mask", "--now", "mongod.service", check=False)
            print("MongoDB installation was interrupted. Its service remains masked; do not start it with an unreviewed config.")
            raise
        print("MongoDB 8.0 installed, authentication enabled, bound to 127.0.0.1, service stopped.")
        print("Next: sudo server-guard mongodb bootstrap --admin mongoAdmin")

    def shell(self, data, script=None, admin=None):
        # An interactive shell holds the management lock. Never allow it to
        # delay a pending access rollback timer while waiting for operator input.
        self.h.tx.require_clear()
        args = ["mongosh", "--norc", "--quiet", "--host", "127.0.0.1", "--port", str(data["port"])]
        if script:
            args += ["--eval", script]
        if admin:
            args += ["--username", mongo_name(admin), "--authenticationDatabase", "admin", "--password"]
        return self.h.r.run(*args, capture=False)

    def bootstrap(self, admin, authenticate=False):
        self.h.tx.require_clear()
        mongo_name(admin)
        data = self.state(initialized=False)
        if data["initialized"]:
            raise GuardError("Already initialized. Use mongodb user-add, password or shell instead.")
        config = json.loads(self.h.f.path(MONGO_CONFIG).read_text())
        if config != json.loads(MongoDBBuilder.config(data["port"])):
            raise GuardError("MongoDB config changed before bootstrap. Review/restore the generated local-only config.")
        exists = self.h.r.run("nft", "list", "table", "inet", "server_guard_mongodb_bootstrap", check=False).returncode == 0
        rules = MongoDBBuilder.bootstrap_guard(data["port"], exists)
        self.h.r.run("nft", "--check", "-f", "-", input=rules)
        self.h.r.run("nft", "-f", "-", input=rules)
        safe_to_remove = False
        try:
            self.h.r.run("systemctl", "start", "mongod")
            self.wait_ready(data)
            if authenticate:
                self.shell(data, "if (db.getSiblingDB('admin').getUsers().length === 0) throw new Error('No administrator.');", admin)
            else:
                self.shell(data, MongoDBBuilder.bootstrap(admin))
            safe_to_remove = True  # first-user exception is closed by authenticated credentials
            data.update(initialized=True, admin=admin)
            self.save(data)
            self.h.r.run("systemctl", "enable", "mongod")
        except BaseException:
            # Stop before removing the first-user protection. If stopping fails,
            # preserve that protection and let the operator inspect the failure.
            self.h.r.run("systemctl", "stop", "mongod")
            safe_to_remove = True
            raise
        finally:
            if safe_to_remove:
                self.h.r.run("nft", "delete", "table", "inet", "server_guard_mongodb_bootstrap")
        print("MongoDB initialized. Authentication is required; no public database port was opened.")

    def wait_ready(self, data):
        for _ in range(30):
            uri = f"mongodb://127.0.0.1:{data['port']}/admin?directConnection=true&serverSelectionTimeoutMS=1000&connectTimeoutMS=1000"
            result = self.h.r.run("mongosh", uri, "--norc", "--quiet", "--eval",
                "if (!db.adminCommand({ping: 1}).ok) quit(1);", check=False)
            if result.returncode == 0:
                return
            if not self.h.tx.active("mongod"):
                break
            time.sleep(1)
        raise GuardError("MongoDB did not become ready. Inspect journalctl -u mongod.")

    def user(self, action, name, database, role, admin):
        self.h.tx.require_clear()
        data = self.state()
        self.shell(data, MongoDBBuilder.user_script(action, name, database, role), admin)
        print("MongoDB user operation completed. Other databases were not granted to this application user.")

    def status(self):
        data = self.state(initialized=False)
        print(json.dumps(data, indent=2))
        self.h.r.run("systemctl", "status", "mongod", "--no-pager", check=False, capture=False)
