"""Facade coordinating system adapters without hiding destructive operations."""
from __future__ import annotations

import grp
import json
import os
from pathlib import Path
import pwd
import time

from .core import (FirewallBuilder, GuardError, POLICY, PolicyStore, SSHBuilder,
                   defaults, port, public_key, username, write_user_key)
from .transactions import Transactions, verified_login
from .defense_config import AUTOMATIC_UPDATES, DefensePolicy, fail2ban_config
from .fail2ban import Fail2BanService
from . import __version__


FIREWALL_SERVICE = """[Unit]
Description=Server Guard IPv4 and IPv6 firewall
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/server-guard firewall-load
ExecReload=/usr/local/sbin/server-guard firewall-load
[Install]
WantedBy=multi-user.target
"""

SYSCTL = """# Server Guard: conservative host settings; no IPv6 disabling or routing changes.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
"""


class Host:
    def __init__(self, files, runner):
        self.f, self.r = files, runner
        self.store = PolicyStore(files)
        self.tx = Transactions(files, runner)

    def preflight(self):
        if os.geteuid() != 0:
            raise GuardError("Run with sudo/root on the Ubuntu server.")
        release = self.f.path("/etc/os-release").read_text()
        facts = dict(line.split("=", 1) for line in release.splitlines() if "=" in line)
        if facts.get("ID", "").strip('"') != "ubuntu" or facts.get("VERSION_ID", "").strip('"') != "24.04":
            raise GuardError("This release targets Ubuntu 24.04 LTS. Do not run it on another OS.")
        if not self.f.path("/run/systemd/system").exists():
            raise GuardError("A systemd Ubuntu VM/bare-metal host is required, not an ordinary container.")

    def prepare(self):
        self.tx.require_clear()
        self.r.run("apt-get", "update", capture=False)
        self.r.run("apt-get", "install", "-y", "openssh-server", "sudo", "nftables", "fail2ban",
                   "unattended-upgrades", "python3-systemd", "ca-certificates", "curl",
                   "apparmor-utils", "auditd", "lynis", capture=False)
        self.f.write("/var/lib/server-guard/prepared.json", json.dumps({"version": __version__, "time": time.time()}))
        print("Dependencies installed. Existing packages were not upgraded; run 'server-guard update' to do so.")

    def init(self, ssh_port):
        self.tx.require_clear()
        if self.f.path(POLICY).exists():
            raise GuardError("Already initialized. Use the configuration commands to change it.")
        self.store.save(defaults(ssh_port))
        print("Policy created. Create an admin, test SSH key login, then run plan and apply.")

    def add_user(self, name, role, sessions, key_path):
        self.tx.require_clear()
        name = username(name)
        state = self.store.load()
        if name in state["users"]:
            raise GuardError("Managed user exists. Use user limit/key/disable instead.")
        if not 1 <= sessions <= 100:
            raise GuardError("Session limit must be 1..100.")
        if role == "admin" and sessions < 2:
            raise GuardError("Administrators need at least two sessions for access confirmation.")
        key = public_key(Path(key_path).read_text())
        # Ask OpenSSH to validate the full key, including its cryptographic payload.
        with __import__('tempfile').TemporaryDirectory() as temp:
            p = Path(temp) / "key.pub"
            p.write_text(key)
            self.r.run("ssh-keygen", "-l", "-f", p)
        try:
            pwd.getpwnam(name)
        except KeyError:
            pass
        else:
            raise GuardError("Account already exists. Refusing to take ownership of an existing account.")
        shell = "/bin/bash" if role in {"admin", "developer"} else "/usr/sbin/nologin"
        home = f"/home/{name}"
        self.r.run("useradd", "--create-home", "--user-group", "--shell", shell, name)
        account = pwd.getpwnam(name)
        self.f.path(home).chmod(0o750)
        write_user_key(self.f.path(home), key, account.pw_uid, account.pw_gid)
        if role == "admin":
            self.r.run("usermod", "--append", "--groups", "sudo", name)
            print("Set a LOCAL password for sudo (SSH passwords will be disabled at apply):", flush=True)
            try:
                self.r.run("passwd", name, capture=False)
            except BaseException:
                # Never leave an untracked sudo account when password setup is interrupted.
                self.r.run("gpasswd", "--delete", name, "sudo", check=False)
                self.r.run("usermod", "--expiredate", "1", name, check=False)
                raise
        if role == "sftp":
            jail = self.f.path(f"/srv/sftp/{name}")
            jail.mkdir(parents=True, mode=0o755)
            jail.chmod(0o755)
            for component in [self.f.path("/srv"), self.f.path("/srv/sftp"), jail]:
                s = component.lstat()
                if component.is_symlink() or s.st_uid != 0 or s.st_mode & 0o022:
                    self.r.run("usermod", "--expiredate", "1", name, check=False)
                    raise GuardError(f"Unsafe SFTP chroot component: {component}. Account was expired.")
            upload = jail / "upload"
            upload.mkdir(mode=0o750)
            os.chown(upload, account.pw_uid, account.pw_gid)
        state["users"][name] = {"role": role, "sessions": sessions, "disabled": False}
        self.store.save(state)
        print(f"Created {name} ({role}). Run plan and apply to activate SSH role/session restrictions.")

    def check_admin(self, state):
        available = []
        for name, user in state["users"].items():
            if user["role"] == "admin" and not user.get("disabled"):
                account = pwd.getpwnam(name)
                if "sudo" not in [g.gr_name for g in grp.getgrall() if name in g.gr_mem]:
                    raise GuardError(f"{name} is no longer in the sudo group.")
                key_path = self.f.path(f"{account.pw_dir}/.ssh/authorized_keys")
                self.r.run("ssh-keygen", "-l", "-f", key_path)
                available.append(name)
        if not available:
            raise GuardError("An enabled managed admin with an SSH public key and sudo access is required.")
        proof_path = self.f.path("/var/lib/server-guard/login-proof.json")
        if not proof_path.exists():
            raise GuardError("First test the new admin with SSH key login and sudo, then run verify-login there.")
        proof = json.loads(proof_path.read_text())
        if proof["user"] not in available or time.time() - proof["time"] > 3600:
            raise GuardError("Admin login proof is stale. Run verify-login from a fresh admin SSH key login.")

    def verify_login(self):
        login = verified_login(self.r)
        state = self.store.load()
        if state["users"].get(login["user"], {}).get("role") != "admin":
            raise GuardError("Login verification requires a managed administrator.")
        self.f.write("/var/lib/server-guard/login-proof.json", json.dumps(login))
        print("Verified this administrator's SSH key login and sudo access (valid for one hour).")

    def plan(self):
        state = self.store.load()
        print("SSH port:", state["ssh"]["port"], "sources:", ", ".join(state["ssh"]["sources"]))
        print("Root SSH:", "key only" if state["ssh"]["root_login"] else "disabled")
        print("SSH password authentication: disabled; MaxSessions per connection: 1")
        print("Managed users:", json.dumps(state["users"], indent=2))
        print("Additional inbound ports:", json.dumps(state["ports"]))
        print("Panel/DB/app backend ports are private unless explicitly allowed.")
        print("Forwarded traffic: DROP (Docker bridges, routing and Kubernetes are unsupported).")
        print("Outbound traffic: allowed. IPv4/IPv6 ICMP and DHCP replies remain available.")
        print("Unconfirmed changes roll back after 10 minutes; packages/users are retained.")
        if DefensePolicy.load(self.f).enabled:
            print("Automatic defenses remain enabled. SSH bans follow the applied port. After confirming intentional changes, review defense scan and explicitly update its trusted baseline.")
        print("\nProposed nftables table:\n" + FirewallBuilder.build(state))

    def firewall_load(self):
        rules = self.f.path("/etc/server-guard/firewall.nft").read_text()
        exists = self.r.run("nft", "list", "table", "inet", "server_guard", check=False).returncode == 0
        batch = FirewallBuilder.batch(rules, exists)
        self.r.run("nft", "--check", "-f", "-", input=batch)
        self.r.run("nft", "-f", "-", input=batch)

    def check_effective_ssh(self, state):
        self.r.run("sshd", "-t")
        conn = os.environ.get("SSH_CONNECTION", "127.0.0.1 0 127.0.0.1 22").split()
        address = conn[0]
        for name in ["root"] + list(state["users"]):
            result = self.r.run("sshd", "-T", "-C", f"user={name},host=localhost,addr={address}")
            actual = dict(line.split(" ", 1) for line in result.stdout.splitlines() if " " in line)
            expected = {"passwordauthentication": "no", "kbdinteractiveauthentication": "no",
                        "pubkeyauthentication": "yes", "authenticationmethods": "publickey",
                        "usepam": "yes", "maxsessions": "1", "permitrootlogin":
                        "prohibit-password" if state["ssh"]["root_login"] else "no"}
            if name in state["users"]:
                user = state["users"][name]
                expected["allowtcpforwarding"] = "local" if user["role"] == "admin" else "no"
                if user["role"] == "sftp":
                    expected["chrootdirectory"] = f"/srv/sftp/{name}"
                    expected["forcecommand"] = "internal-sftp -d /upload"
            for key, value in expected.items():
                # OpenSSH may print the historical synonym 'without-password'.
                got = actual.get(key)
                if key == "permitrootlogin" and got == "without-password":
                    got = "prohibit-password"
                if got != value:
                    raise GuardError(f"Existing SSH policy overrides {key} for {name}: {got!r}, expected {value!r}.")
            ports = [line for line in result.stdout.splitlines() if line.startswith("port ")]
            if ports != [f"port {state['ssh']['port']}"]:
                raise GuardError("Existing Port directives add other listeners. Remove them before apply.")

    def apply(self, replace_ufw=False):
        self.tx.require_clear()
        state = self.store.load()
        self.check_admin(state)
        if self.tx.active("firewalld") or self.tx.enabled("firewalld"):
            raise GuardError("firewalld is active/enabled. Migrate its rules from the provider console before using this tool.")
        ufw_active = self.r.run("ufw", "status", check=False) if self.f.path("/usr/sbin/ufw").exists() else None
        ufw_active = bool(ufw_active and "Status: active" in ufw_active.stdout)
        if ufw_active and not replace_ufw:
            raise GuardError("UFW is active. Review plan, then use apply --replace-ufw to replace its policy.")
        for service in ["docker", "docker.socket", "containerd", "kubelet", "libvirtd"]:
            if self.tx.active(service) or self.tx.enabled(service):
                raise GuardError(f"{service} is active/enabled. This host-only firewall blocks forwarding; use a separate host.")
        if self.tx.active("nftables") or self.tx.enabled("nftables"):
            raise GuardError("nftables.service is active/enabled and may flush our table. Migrate it from the provider console first.")
        # Ubuntu 24.04 uses socket activation. Keep its existing SSH port, or first
        # switch to service mode using the documented console procedure.
        if self.tx.active("ssh.socket"):
            listening = self.r.run("sshd", "-T").stdout.splitlines()
            if [s for s in listening if s.startswith("port ")] != [f"port {state['ssh']['port']}"]:
                raise GuardError("SSH socket activation is active. Keep the existing port, or follow docs/OPERATIONS.md.")
        txid = self.tx.begin()
        try:
            self.f.write("/etc/ssh/server-guard.conf", SSHBuilder.global_config(state))
            self.f.write("/etc/ssh/server-guard-users.conf", SSHBuilder.user_config(state))
            original = self.f.path("/etc/ssh/sshd_config").read_text()
            self.f.write("/etc/ssh/sshd_config", SSHBuilder.main_config(original))
            limits = {u: info["sessions"] for u, info in state["users"].items()}
            self.f.write("/etc/server-guard/sshd-sessions.json", json.dumps(limits))
            pam_path = self.f.path("/etc/pam.d/sshd")
            pam = pam_path.read_text()
            self.f.write("/etc/pam.d/sshd", SSHBuilder.pam_config(pam), 0o644)
            self.check_effective_ssh(state)
            self.f.write("/etc/server-guard/firewall.nft", FirewallBuilder.build(state))
            self.f.write("/etc/systemd/system/server-guard-firewall.service", FIREWALL_SERVICE, 0o644)
            self.r.run("systemctl", "daemon-reload")
            self.firewall_load()
            self.r.run("systemctl", "enable", "--now", "server-guard-firewall")
            if ufw_active:
                self.r.run("ufw", "disable")
                self.r.run("systemctl", "disable", "ufw")
                self.firewall_load()
            self.f.write("/etc/fail2ban/jail.d/90-server-guard.local", fail2ban_config(state["ssh"]["port"], DefensePolicy.load(self.f)))
            self.r.run("fail2ban-client", "-t")
            self.r.run("systemctl", "enable", "--now", "fail2ban")
            Fail2BanService(self.r).restart(("sshd",))
            self.f.write("/etc/sysctl.d/90-server-guard.conf", SYSCTL, 0o644)
            self.r.run("sysctl", "-p", "/etc/sysctl.d/90-server-guard.conf")
            self.f.write("/etc/apt/apt.conf.d/90-server-guard", AUTOMATIC_UPDATES, 0o644)
            self.f.write("/etc/systemd/journald.conf.d/90-server-guard.conf", """[Journal]
Storage=persistent
SystemMaxUse=512M
MaxRetentionSec=30day
""", 0o644)
            self.r.run("systemctl", "restart", "systemd-journald")
            self.r.run("systemctl", "enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer")
            self.r.run("systemctl", "reload", "ssh")
        except BaseException:
            self.tx.rollback()
            raise
        print(f"Applied change {txid}. RECONNECT with a NEW admin SSH key session within 10 minutes.")
        print(f"In that session: sudo --preserve-env=SSH_CONNECTION server-guard confirm {txid}")
        print("Keep your original SSH session open until the new login works. Otherwise changes roll back.")

    def status(self):
        for args in [("ss", "-lntup"), ("nft", "list", "table", "inet", "server_guard"),
                     ("fail2ban-client", "status", "sshd"), ("aa-status", "--enabled"),
                     ("systemctl", "is-active", "auditd", "server-guard-firewall", "apt-daily-upgrade.timer"),
                     ("timedatectl", "show", "-p", "NTPSynchronized")]:
            print("\n$ " + " ".join(args), flush=True)
            self.r.run(*args, check=False, capture=False)
        if self.f.path("/var/run/reboot-required").exists():
            print("A reboot is required. Schedule it after confirming access.")
        print("Pending change:", (self.tx.pending() or {}).get("id", "none"))
