"""Installer strategies and a non-root, loopback-only V2Ray deployment."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import pwd
import re
import tempfile
import uuid
import zipfile

from .core import GuardError, V2RayBuilder, domain, port, sha256, username


INSTALLERS = {
    "cloudpanel": "https://installer.cloudpanel.io/ce/v2/install.sh",
    "aapanel": "https://www.aapanel.com/script/install_panel_en.sh",
}


class ManagedServices:
    """Command facade for optional services; SSH/firewall services are excluded."""
    UNITS = {"mongodb": "mongod", "v2ray": "server-guard-v2ray"}

    def __init__(self, host):
        self.h = host

    def control(self, name, action):
        if name not in self.UNITS or action not in {"start", "stop", "restart", "status"}:
            raise GuardError("Choose mongodb/v2ray and start/stop/restart/status.")
        unit = self.UNITS[name]
        if action == "status":
            self.h.r.run("systemctl", "status", unit, "--no-pager", check=False, capture=False)
            return
        self.h.tx.require_clear()
        if action in {"start", "restart"}:
            if name == "mongodb":
                from .mongodb import MongoDBManager
                MongoDBManager(self.h).state()
            elif not self.h.f.path("/etc/server-guard-v2ray/config.json").exists():
                raise GuardError("Configure V2Ray before starting its service.")
        self.h.r.run("systemctl", action, unit, capture=False)


def checksum(value):
    if not re.fullmatch(r"[a-fA-F0-9]{64}", value or ""):
        raise GuardError("A full SHA-256 checksum from a trusted source is required.")
    return value.lower()


def download(runner, url, destination):
    runner.run("curl", "--fail", "--show-error", "--location", "--proto", "=https",
               "--proto-redir", "=https", "--tlsv1.2", "--connect-timeout", "20",
               "--max-time", "600", "--output", destination, url, capture=False)


class PanelManager:
    """Strategy: panel-specific installer URLs; common review and verification flow."""
    def __init__(self, host):
        self.h = host

    def download(self, provider):
        self.h.tx.require_clear()
        target = self.h.f.path(f"/var/lib/server-guard/downloads/{provider}.sh")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory() as temp:
            downloaded = Path(temp) / "installer.sh"
            download(self.h.r, INSTALLERS[provider], downloaded)
            self.h.f.write(f"/var/lib/server-guard/downloads/{provider}.sh", downloaded.read_bytes(), 0o600)
        print(f"Downloaded, NOT executed: {target}\nSHA256: {sha256(target)}")
        print("Review the script and compare its checksum with a trusted publisher source.")
        print(f"Execute only after review: sudo server-guard panel install {provider} --sha256 TRUSTED_SHA256")

    def install(self, provider, expected, db_engine):
        self.h.tx.require_clear()
        expected = checksum(expected)
        target = self.h.f.path(f"/var/lib/server-guard/downloads/{provider}.sh")
        if not target.exists() or sha256(target) != expected:
            raise GuardError("Installer checksum mismatch/missing. Download and review it first.")
        if not self.h.f.path("/etc/server-guard/firewall.nft").exists():
            raise GuardError("Apply and confirm the firewall/SSH baseline before installing a panel.")
        for p in ["/www/server/panel", "/usr/bin/clpctl", "/etc/cloudpanel"]:
            if self.h.f.path(p).exists():
                raise GuardError("A panel is already installed. Use its supported update process.")
        for service in ["nginx", "apache2", "mysql", "mariadb", "postgresql", "docker", "mongod", "mongodb"]:
            if self.h.tx.active(service):
                raise GuardError(f"{service} is already running. Panel installation requires an empty server.")
        if self.h.f.path("/etc/server-guard/mongodb.json").exists() or self.h.f.path("/etc/mongod.conf").exists():
            raise GuardError("MongoDB is already installed. Install the panel first on a fresh server, then add MongoDB.")
        print("Running the reviewed vendor installer as root. This step has NO automatic uninstall/rollback.", flush=True)
        try:
            if provider == "cloudpanel":
                self.h.r.run("env", f"DB_ENGINE={db_engine}", "bash", target, capture=False)
            else:
                self.h.r.run("bash", target, capture=False)
        finally:
            # Preserve our deny policy if the vendor changed firewall rules.
            self.h.firewall_load()
        print("Panel installer finished. Its management port is private behind Server Guard.")
        print("Run 'panel info', then configure panel MFA, site users, TLS and remote backups.")
        print("If the installer enabled UFW, review plan and apply --replace-ufw, then confirm a new login.")

    def info(self):
        if self.h.f.path("/www/server/panel/data/port.pl").exists():
            panel_port = port(self.h.f.path("/www/server/panel/data/port.pl").read_text().strip())
            provider = "aaPanel"
        elif self.h.f.path("/usr/bin/clpctl").exists():
            panel_port, provider = 8443, "CloudPanel"
        else:
            raise GuardError("No supported installed panel was detected.")
        ssh_port = self.h.store.load()["ssh"]["port"]
        print(f"{provider} port: {panel_port} (private)")
        print(f"On YOUR COMPUTER: ssh -p {ssh_port} -L 8443:127.0.0.1:{panel_port} admin@SERVER_IP sleep 3600")
        print("Keep that SSH session running, then visit https://127.0.0.1:8443")
        print("Use your actual admin username. Verify any panel certificate fingerprint before trusting it.")
        if provider == "aaPanel":
            print("Run sudo bt 14 on the server to view its security entrance URL.")


V2RAY_SERVICE = """[Unit]
Description=Server Guard V2Ray (VMess WebSocket backend)
After=network-online.target server-guard-firewall.service
Wants=network-online.target
Requires=server-guard-v2ray-egress.service
After=server-guard-v2ray-egress.service
[Service]
Type=exec
User=sg-v2ray
Group=sg-v2ray
Environment=V2RAY_LOCATION_ASSET=/usr/local/share/server-guard-v2ray
ExecStartPre=/usr/local/lib/server-guard-v2ray/v2ray test -c /etc/server-guard-v2ray/config.json
ExecStart=/usr/local/lib/server-guard-v2ray/v2ray run -c /etc/server-guard-v2ray/config.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077
LimitNOFILE=16384
TasksMax=128
MemoryMax=512M
[Install]
WantedBy=multi-user.target
"""


class V2RayManager:
    BINARY = "/usr/local/lib/server-guard-v2ray/v2ray"

    def __init__(self, host):
        self.h = host

    def install(self, version, expected):
        self.h.tx.require_clear()
        if not self.h.f.path("/etc/server-guard/firewall.nft").exists():
            raise GuardError("Apply and confirm the SSH/firewall baseline before installing V2Ray.")
        expected = checksum(expected)
        if not re.fullmatch(r"v5\.\d+\.\d+", version):
            raise GuardError("Specify a pinned stable V2Ray v5 release, e.g. v5.X.Y.")
        arch = {"x86_64": "64", "aarch64": "arm64-v8a"}.get(platform.machine())
        if not arch:
            raise GuardError("Only x86_64/aarch64 are supported.")
        if self.h.tx.active("server-guard-v2ray"):
            raise GuardError("Stop V2Ray before replacing its binary: systemctl stop server-guard-v2ray")
        url = f"https://github.com/v2fly/v2ray-core/releases/download/{version}/v2ray-linux-{arch}.zip"
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "v2ray.zip"
            download(self.h.r, url, archive)
            if sha256(archive) != expected:
                raise GuardError("V2Ray archive checksum mismatch. Nothing was installed.")
            with zipfile.ZipFile(archive) as z:
                # Never extract arbitrary archive paths, links, or executable helpers.
                for member, target, mode in [
                    ("v2ray", self.BINARY, 0o755),
                    ("geoip.dat", "/usr/local/share/server-guard-v2ray/geoip.dat", 0o644),
                    ("geosite.dat", "/usr/local/share/server-guard-v2ray/geosite.dat", 0o644)]:
                    item = z.getinfo(member)
                    if item.file_size > 200 * 1024 * 1024:
                        raise GuardError("Unexpectedly large archive member.")
                    self.h.f.write(target, z.read(member), mode)
        try:
            account = pwd.getpwnam("sg-v2ray")
            if account.pw_uid == 0 or account.pw_shell != "/usr/sbin/nologin":
                raise GuardError("Existing sg-v2ray account has unsafe permissions.")
        except KeyError:
            self.h.r.run("useradd", "--system", "--user-group", "--no-create-home",
                         "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "sg-v2ray")
            account = pwd.getpwnam("sg-v2ray")
        self.h.f.path("/etc/server-guard-v2ray").mkdir(mode=0o750, exist_ok=True)
        os.chown(self.h.f.path("/etc/server-guard-v2ray"), 0, account.pw_gid)
        self.h.f.write("/etc/systemd/system/server-guard-v2ray.service", V2RAY_SERVICE, 0o644)
        self.h.f.write("/etc/systemd/system/server-guard-v2ray-egress.service", """[Unit]
Description=Prevent V2Ray access to local networks and cloud metadata
DefaultDependencies=no
After=local-fs.target server-guard-firewall.service
Before=network-pre.target server-guard-v2ray.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/server-guard v2ray-egress-load
""", 0o644)
        self.h.r.run("systemctl", "daemon-reload")
        self.h.r.run(self.BINARY, "version", capture=False)
        print("Pinned V2Ray binary installed. Configure it next; no public port was opened.")

    def egress_load(self):
        uid = pwd.getpwnam("sg-v2ray").pw_uid
        if uid == 0:
            raise GuardError("Refusing root V2Ray UID.")
        exists = self.h.r.run("nft", "list", "table", "inet", "server_guard_v2ray", check=False).returncode == 0
        rules = ("delete table inet server_guard_v2ray\n" if exists else "") + f"""table inet server_guard_v2ray {{
 chain output {{
  type filter hook output priority -11; policy accept;
  ct state established,related accept
  meta skuid {uid} ip daddr {{ 127.0.0.53, 127.0.0.54 }} udp dport 53 accept
  meta skuid {uid} ip daddr {{ 127.0.0.53, 127.0.0.54 }} tcp dport 53 accept
  meta skuid {uid} ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }} counter drop
  meta skuid {uid} ip6 daddr {{ ::/128, ::1/128, ::ffff:0:0/96, fc00::/7, fe80::/10, ff00::/8 }} counter drop
  meta skuid {uid} tcp dport {{ 25, 465, 587 }} counter drop
 }}
}}
"""
        self.h.r.run("nft", "--check", "-f", "-", input=rules)
        self.h.r.run("nft", "-f", "-", input=rules)

    def configure(self, hostname, local_port):
        self.h.tx.require_clear()
        if not self.h.f.path(self.BINARY).exists():
            raise GuardError("Install a pinned V2Ray binary first.")
        state = self.h.store.load()
        state["v2ray"].update(domain=domain(hostname), port=port(local_port))
        if not state["v2ray"]["path"]:
            state["v2ray"]["path"] = "/" + uuid.uuid4().hex
        self.save(state)

    def save(self, state):
        v = state["v2ray"]
        if not v["domain"]:
            raise GuardError("Run v2ray configure first.")
        from .core import validate
        validate(state)
        account = pwd.getpwnam("sg-v2ray")
        config_path = "/etc/server-guard-v2ray/config.json"
        old = self.h.f.path(config_path).read_bytes() if self.h.f.path(config_path).exists() else None
        content = json.dumps(V2RayBuilder.config(state), indent=2) + "\n"
        self.h.f.write(config_path, content, 0o640)
        os.chown(self.h.f.path(config_path), 0, account.pw_gid)
        try:
            self.h.r.run("env", "V2RAY_LOCATION_ASSET=/usr/local/share/server-guard-v2ray",
                         self.BINARY, "test", "-c", config_path)
            # Enforce network isolation before the process can accept clients.
            self.egress_load()
            self.h.r.run("systemctl", "start", "server-guard-v2ray-egress")
            self.h.r.run("systemctl", "enable", "server-guard-v2ray")
            self.h.r.run("systemctl", "restart", "server-guard-v2ray")
            self.h.r.run("systemctl", "is-active", "--quiet", "server-guard-v2ray")
            self.h.store.save(state)
        except BaseException:
            if old is None:
                self.h.f.path(config_path).unlink(missing_ok=True)
                self.h.r.run("systemctl", "disable", "--now", "server-guard-v2ray", check=False)
            else:
                self.h.f.write(config_path, old, 0o640)
                os.chown(self.h.f.path(config_path), 0, account.pw_gid)
                self.h.r.run("systemctl", "restart", "server-guard-v2ray", check=False)
            raise
        self.h.f.write("/etc/server-guard-v2ray/nginx-location.conf", V2RayBuilder.nginx(state), 0o600)
        print("V2Ray configured on 127.0.0.1 only. No public port was opened.")
        print("Add nginx-location.conf inside the panel's HTTPS site, validate Nginx and reload it.")

    def client(self, action, name):
        self.h.tx.require_clear()
        name = username(name)
        state = self.h.store.load()
        clients = state["v2ray"]["clients"]
        if action == "add":
            if name in clients:
                raise GuardError("Client already exists. Use export or revoke it.")
            clients[name] = str(uuid.uuid4())
        elif action == "revoke":
            if name not in clients:
                raise GuardError("Unknown client.")
            del clients[name]
        self.save(state)
        print("Client added. Use 'v2ray export NAME' to display its secret link." if action == "add"
              else "Client revoked. Restart closed existing V2Ray connections.")
