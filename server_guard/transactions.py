"""Memento: persistent, serialized rollback for access-affecting configuration."""
from __future__ import annotations

import base64
import json
import os
import stat
import time
from pathlib import Path

from .core import FirewallBuilder, GuardError, POLICY


PENDING = "/var/lib/server-guard/pending.json"
TIMER = "server-guard-rollback.timer"
MANAGED = [POLICY, "/etc/ssh/sshd_config", "/etc/ssh/server-guard.conf",
           "/etc/ssh/server-guard-users.conf", "/etc/pam.d/sshd",
           "/etc/server-guard/sshd-sessions.json", "/etc/server-guard/firewall.nft",
           "/etc/systemd/system/server-guard-firewall.service",
           "/etc/fail2ban/jail.d/90-server-guard.local",
           "/etc/sysctl.d/90-server-guard.conf",
           "/etc/apt/apt.conf.d/90-server-guard",
           "/etc/systemd/journald.conf.d/90-server-guard.conf", "/etc/ufw/ufw.conf"]


class Transactions:
    def __init__(self, files, runner):
        self.f, self.r = files, runner

    def pending(self):
        p = self.f.path(PENDING)
        return json.loads(p.read_text()) if p.exists() else None

    def require_clear(self):
        if self.pending():
            raise GuardError("An access change is pending. Confirm it from a new SSH login, or rollback.")

    def active(self, service):
        return self.r.run("systemctl", "is-active", "--quiet", service, check=False).returncode == 0

    def enabled(self, service):
        return self.r.run("systemctl", "is-enabled", "--quiet", service, check=False).returncode == 0

    def begin(self, minutes=10):
        self.require_clear()
        txid = str(time.time_ns())
        backup = {}
        for name in MANAGED:
            p = self.f.path(name)
            if p.is_symlink():
                raise GuardError(f"Refusing managed symlink: {p}")
            if p.exists():
                s = p.stat()
                backup[name] = {"data": base64.b64encode(p.read_bytes()).decode(),
                                "mode": stat.S_IMODE(s.st_mode), "uid": s.st_uid, "gid": s.st_gid}
            else:
                backup[name] = None
        nft = self.r.run("nft", "list", "table", "inet", "server_guard", check=False)
        data = {"id": txid, "created": time.time(), "files": backup,
                "nft": nft.stdout if nft.returncode == 0 else None,
                "services": {name: {"active": self.active(name), "enabled":
                    self.r.run("systemctl", "is-enabled", "--quiet", name, check=False).returncode == 0}
                    for name in ["ufw", "server-guard-firewall", "fail2ban"]},
                "sysctls": {}}
        ufw = self.r.run("ufw", "status", check=False) if self.f.path("/usr/sbin/ufw").exists() else None
        data["ufw_active"] = bool(ufw and "Status: active" in ufw.stdout)
        for key in ["net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects",
                    "net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects",
                    "net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.default.accept_source_route",
                    "net.ipv6.conf.all.accept_redirects", "net.ipv6.conf.default.accept_redirects",
                    "net.ipv4.tcp_syncookies", "kernel.kptr_restrict", "kernel.dmesg_restrict",
                    "fs.protected_hardlinks", "fs.protected_symlinks"]:
            result = self.r.run("sysctl", "-n", key, check=False)
            if result.returncode == 0:
                data["sysctls"][key] = result.stdout.strip()
        # The pending marker is also the durable backup; retained in history on confirm/rollback.
        self.f.write(PENDING, json.dumps(data, indent=2))
        self.f.write("/etc/systemd/system/server-guard-rollback.service", """[Unit]
Description=Restore unconfirmed Server Guard access settings
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/server-guard rollback
""", 0o644)
        self.f.write("/etc/systemd/system/server-guard-rollback.timer", f"""[Unit]
Description=Rollback unconfirmed Server Guard settings
[Timer]
OnActiveSec={minutes}min
AccuracySec=1s
Unit=server-guard-rollback.service
[Install]
WantedBy=timers.target
""", 0o644)
        self.r.run("systemctl", "daemon-reload")
        self.r.run("systemctl", "enable", "--now", TIMER)
        if not self.active(TIMER):
            self.f.path(PENDING).unlink()
            raise GuardError("Rollback timer did not start; no access settings were changed.")
        return txid

    def archive(self, data, suffix):
        self.f.write(f"/var/lib/server-guard/history/{data['id']}-{suffix}.json", json.dumps(data))
        self.f.path(PENDING).unlink(missing_ok=True)
        self.r.run("systemctl", "disable", "--now", TIMER, check=False)

    def rollback(self):
        data = self.pending()
        if not data:
            print("No pending change.")
            return
        for name, saved in data["files"].items():
            if saved is None:
                self.f.path(name).unlink(missing_ok=True)
            else:
                self.f.write(name, base64.b64decode(saved["data"]), saved["mode"])
                os.chown(self.f.path(name), saved["uid"], saved["gid"])
        exists = self.r.run("nft", "list", "table", "inet", "server_guard", check=False).returncode == 0
        rules = FirewallBuilder.batch(data["nft"] or "", exists)
        if rules:
            self.r.run("nft", "-f", "-", input=rules)
        self.r.run("systemctl", "daemon-reload")
        self.r.run("sshd", "-t")
        self.r.run("systemctl", "reload", "ssh")
        for key, value in data["sysctls"].items():
            self.r.run("sysctl", "-q", "-w", f"{key}={value}", check=False)
        for name, status in data["services"].items():
            # Firewall oneshot has no ExecStop: stopping does not delete restored rules.
            self.r.run("systemctl", "enable" if status["enabled"] else "disable", name, check=status["enabled"])
            self.r.run("systemctl", "restart" if status["active"] else "stop", name, check=status["active"])
        if data.get("ufw_active"):
            self.r.run("ufw", "--force", "enable")
        self.r.run("systemctl", "try-restart", "systemd-journald", check=False)
        self.archive(data, "rolled-back")
        print(f"Rolled back access change {data['id']}. User creation and package installs were retained.")

    def confirm(self, txid):
        data = self.pending()
        if not data or data["id"] != txid:
            raise GuardError("No pending change with that ID.")
        login = verified_login(self.r)
        if login["time"] <= data["created"]:
            raise GuardError("Reconnect using a NEW SSH login after apply, then confirm with sudo.")
        state = json.loads(self.f.path(POLICY).read_text())
        if state["users"].get(login["user"], {}).get("role") != "admin":
            raise GuardError("Confirmation requires a managed administrator.")
        self.archive(data, "confirmed")
        print("Confirmed. Automatic rollback cancelled.")


def verified_login(runner):
    from .ssh_access import SSHLoginInspector
    return SSHLoginInspector(runner).verified()
