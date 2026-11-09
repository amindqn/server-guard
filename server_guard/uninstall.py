"""Remove the manager while preserving working access and installed applications."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import uuid

from .core import GuardError
from .health import MONITOR_TIMER, MONITOR_UNIT


RETAINED = "/usr/local/lib/server-guard-retained"
LAUNCHER = "/usr/local/sbin/server-guard"
PROGRAM = "/opt/server-guard"
STATE = "/var/lib/server-guard"
CONFIG = "/etc/server-guard"
DOCS = "/usr/local/share/doc/server-guard"
PAM = "/etc/pam.d/sshd"
OLD_HELPER = PROGRAM + "/server_guard/pam_sessions.py"
FW_UNIT = "/etc/systemd/system/server-guard-firewall.service"
EGRESS_UNIT = "/etc/systemd/system/server-guard-v2ray-egress.service"
ROLLBACK_UNITS = ["/etc/systemd/system/server-guard-rollback.timer",
                  "/etc/systemd/system/server-guard-rollback.service"]


NATIVE_FIREWALL = r'''#!/bin/bash
# Retained security runtime. No Server Guard manager/package imports are needed.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
case "${1:-}:${2:-}" in
  server_guard:/etc/server-guard/firewall.nft|server_guard_v2ray:/usr/local/lib/server-guard-retained/v2ray-egress.nft) ;;
  *) echo 'Unsupported retained firewall table/path.' >&2; exit 1 ;;
esac
exec 9>/run/server-guard-retained-firewall.lock
flock -x 9
present=0
if nft list table inet "$1" >/dev/null 2>&1; then present=1; fi
batch() {
  if [[ $present == 1 ]]; then printf 'delete table inet %s\n' "$1"; fi
  cat -- "$2"
}
batch "$1" "$2" | nft --check -f -
batch "$1" "$2" | nft -f -
'''


class UninstallManager:
    """Facade: inspect -> back up -> detach runtime -> validate -> remove manager.

    It never purges packages, users, keys, databases, panels or running services.
    Active hardening is retained, rather than guessing pre-install SSH defaults.
    """
    def __init__(self, host):
        self.h, self.f, self.r = host, host.f, host.r

    def _text(self, path):
        p = self.f.path(path)
        if p.is_symlink():
            raise GuardError(f"Review managed symlink before uninstall: {path}")
        return p.read_text() if p.is_file() else ""

    def integration_files(self):
        result = set()
        for folder, pattern in [("/etc/pam.d", "*"), ("/etc/ssh", "*.conf"),
                                ("/etc/systemd/system", "*.service"),
                                ("/etc/systemd/system", "*.timer")]:
            directory = self.f.path(folder)
            if directory.exists():
                for file in directory.rglob(pattern):
                    if file.is_symlink() and any(value in str(file.readlink()) for value in [PROGRAM, LAUNCHER]):
                        raise GuardError(f"Custom integration links to manager files: {file}. Detach it before uninstall.")
                    if file.is_file() and not file.is_symlink():
                        result.add("/" + str(file.relative_to(self.f.root)))
        result.add("/etc/ssh/sshd_config")
        return sorted(result)

    def plan(self, purge=False):
        self.h.tx.require_clear()
        paths = [PAM, FW_UNIT, EGRESS_UNIT, "/etc/ssh/server-guard.conf",
                 "/etc/ssh/server-guard-users.conf", CONFIG + "/firewall.nft",
                 CONFIG + "/sshd-sessions.json", CONFIG + "/mongodb.json",
                 "/etc/systemd/system/server-guard-v2ray.service", MONITOR_UNIT, MONITOR_TIMER]
        contents = {name: self._text(name) for name in paths}
        for name in self.integration_files():
            contents.setdefault(name, self._text(name))
        pam_hook = OLD_HELPER in contents[PAM]
        retained_pam = RETAINED + "/pam_sessions.py" in contents[PAM]
        firewall = bool(contents[FW_UNIT])
        egress = bool(contents[EGRESS_UNIT])
        protection = pam_hook or retained_pam or firewall or egress or any(contents[p] for p in
            ["/etc/ssh/server-guard.conf", "/etc/ssh/server-guard-users.conf", CONFIG + "/firewall.nft",
             CONFIG + "/sshd-sessions.json"])
        if (pam_hook or retained_pam) and not contents[CONFIG + "/sshd-sessions.json"]:
            raise GuardError("SSH session policy is missing. Repair it before removing its manager.")
        if firewall and not contents[CONFIG + "/firewall.nft"]:
            raise GuardError("The active firewall service has no saved rules. Repair it before uninstalling.")
        if purge and (protection or self.f.path(CONFIG + "/mongodb.json").exists() or
                      self.f.path("/etc/systemd/system/server-guard-v2ray.service").exists()):
            raise GuardError("--purge is available only before hardening/optional-service configuration. "
                             "Use normal uninstall to keep working protection and application data.")
        known = {PAM, FW_UNIT, EGRESS_UNIT, MONITOR_UNIT, MONITOR_TIMER, *ROLLBACK_UNITS}
        for name, text in contents.items():
            if name not in known and (PROGRAM + "/" in text or LAUNCHER in text):
                raise GuardError(f"Custom integration still calls the manager: {name}. Detach it before uninstall.")
        if contents[PAM].count(OLD_HELPER) > 1:
            raise GuardError("Multiple custom PAM hooks found; review /etc/pam.d/sshd before uninstall.")
        for path, verb in [(FW_UNIT, "firewall-load"), (EGRESS_UNIT, "v2ray-egress-load")]:
            text = contents[path]
            if text and LAUNCHER in text and LAUNCHER + " " + verb not in text:
                raise GuardError(f"Unexpected service command in {path}; review it before uninstall.")
        fingerprint = hashlib.sha256(json.dumps(contents, sort_keys=True).encode()).hexdigest()
        return {"purge": purge, "protection": protection, "pam": pam_hook,
                "firewall": firewall, "egress": egress, "fingerprint": fingerprint,
                "contents": contents,
                "installed": self.f.path(PROGRAM).exists() or self.f.path(LAUNCHER).exists()}

    def describe(self, plan):
        print("UNINSTALL PLAN")
        print("Remove: Server Guard command, Python management package, installed guide and management history.")
        if plan["protection"]:
            print("Keep: current SSH settings, session limits and firewall rules using independent runtime helpers.")
        print("Keep: Linux users/keys, packages, web panels, MongoDB/V2Ray and all application/database data.")
        print("Configuration:", "remove unused Server Guard configuration" if plan["purge"] else "retain for recovery/reinstall")
        print("Create: private recovery backup under /var/backups/server-guard/ before making changes.")
        print("SSH and application services will not be restarted or have their access settings reset.")
        print("Scheduled Server Guard health checks will be stopped and removed; runtime CPU weights expire at reboot.")

    def _backup(self, plan):
        name = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
        destination = self.f.path("/var/backups/server-guard/" + name)
        destination.mkdir(parents=True, mode=0o700)
        destination.chmod(0o700)
        from .transactions import MANAGED
        targets = sorted(set([PROGRAM, LAUNCHER, STATE, CONFIG, DOCS, RETAINED, PAM, FW_UNIT,
                              EGRESS_UNIT, MONITOR_UNIT, MONITOR_TIMER, *ROLLBACK_UNITS, *MANAGED]))
        # Directory backups already include their children.
        targets = [p for p in targets if not any(p.startswith(parent + "/") for parent in targets)]
        for path in targets:
            source = self.f.path(path)
            if source.exists() or source.is_symlink():
                target = destination / path.lstrip("/")
                target.parent.mkdir(parents=True, exist_ok=True)
                if source.is_dir() and not source.is_symlink():
                    shutil.copytree(source, target, symlinks=True)
                else:
                    shutil.copy2(source, target, follow_symlinks=False)
        (destination / "plan.json").write_text(json.dumps({k: v for k, v in plan.items() if k != "contents"}, indent=2))
        return destination

    def _restore_changed(self, before):
        for path, saved in before.items():
            if saved is None:
                self.f.path(path).unlink(missing_ok=True)
            else:
                content, mode, uid, gid = saved
                self.f.write(path, content, mode)
                os.chown(self.f.path(path), uid, gid)
        self.r.run("systemctl", "daemon-reload", check=False)

    def remove(self, purge=False, expected=None):
        plan = self.plan(purge)
        if expected and expected != plan["fingerprint"]:
            raise GuardError("Configuration changed during review. Run uninstall again to review the current plan.")
        if not plan["installed"]:
            print("Server Guard manager is already removed. Retained security settings and applications were left in place.")
            return None
        backup = self._backup(plan)
        before = {}
        def write(path, value, mode=0o644):
            if path not in before:
                target = self.f.path(path)
                if target.is_symlink():
                    raise GuardError(f"Refusing uninstall write through symlink: {path}")
                if target.exists():
                    s = target.stat()
                    before[path] = (target.read_bytes(), s.st_mode & 0o7777, s.st_uid, s.st_gid)
                else:
                    before[path] = None
            self.f.write(path, value, mode)
        try:
            if plan["pam"]:
                source = self.f.path(OLD_HELPER)
                if not source.is_file():
                    source = Path(__file__).with_name("pam_sessions.py")
                write(RETAINED + "/pam_sessions.py", source.read_bytes(), 0o755)
                write(PAM, plan["contents"][PAM].replace(OLD_HELPER, RETAINED + "/pam_sessions.py"))
            if plan["firewall"] or plan["egress"]:
                write(RETAINED + "/firewall-load", NATIVE_FIREWALL, 0o755)
                self.r.run("bash", "-n", self.f.path(RETAINED + "/firewall-load"))
            if plan["firewall"]:
                rules = plan["contents"][CONFIG + "/firewall.nft"]
                exists = self.r.run("nft", "list", "table", "inet", "server_guard", check=False).returncode == 0
                self.r.run("nft", "--check", "-f", "-", input=("delete table inet server_guard\n" if exists else "") + rules)
                command = RETAINED + "/firewall-load server_guard " + CONFIG + "/firewall.nft"
                write(FW_UNIT, plan["contents"][FW_UNIT].replace(LAUNCHER + " firewall-load", command))
            if plan["egress"]:
                from .services import V2RayManager
                rules = V2RayManager.egress_rules()
                write(RETAINED + "/v2ray-egress.nft", rules, 0o600)
                exists = self.r.run("nft", "list", "table", "inet", "server_guard_v2ray", check=False).returncode == 0
                self.r.run("nft", "--check", "-f", "-", input=("delete table inet server_guard_v2ray\n" if exists else "") + rules)
                command = RETAINED + "/firewall-load server_guard_v2ray " + RETAINED + "/v2ray-egress.nft"
                write(EGRESS_UNIT, plan["contents"][EGRESS_UNIT].replace(LAUNCHER + " v2ray-egress-load", command))
            if plan["protection"]:
                self.r.run("sshd", "-t")
            for name in [PAM, FW_UNIT, EGRESS_UNIT]:
                text = self._text(name)
                if PROGRAM + "/" in text or LAUNCHER in text:
                    raise GuardError(f"A manager dependency remains in {name}; nothing will be deleted.")
            self.r.run("systemctl", "daemon-reload")
        except BaseException:
            self._restore_changed(before)
            print(f"Uninstall stopped; runtime changes restored. Recovery backup: {backup}")
            raise
        # Pending transactions were excluded while holding the management lock.
        if self.f.path(MONITOR_TIMER).exists():
            self.r.run("systemctl", "disable", "--now", "server-guard-health.timer")
        if self.f.path(MONITOR_UNIT).exists():
            self.r.run("systemctl", "stop", "server-guard-health.service")
        if self.f.path(ROLLBACK_UNITS[0]).exists():
            self.r.run("systemctl", "disable", "--now", "server-guard-rollback.timer")
        if self.f.path(ROLLBACK_UNITS[1]).exists():
            self.r.run("systemctl", "stop", "server-guard-rollback.service")
        for path in [*ROLLBACK_UNITS, MONITOR_TIMER, MONITOR_UNIT]:
            self.f.path(path).unlink(missing_ok=True)
        self.r.run("systemctl", "daemon-reload")
        # Access no longer depends on the manager. Delete only its owned paths.
        for path in [PROGRAM, DOCS, STATE]:
            target = self.f.path(path)
            if target.is_symlink():
                target.unlink()
            elif target.exists():
                shutil.rmtree(target)
        self.f.path(LAUNCHER).unlink(missing_ok=True)
        if purge and self.f.path(CONFIG).exists():
            shutil.rmtree(self.f.path(CONFIG))
        manifest = {"backup": str(backup), "protection_retained": plan["protection"],
                    "configuration_retained": not purge, "removed_at": time.time()}
        self.f.write("/var/backups/server-guard/last-uninstall.json", json.dumps(manifest, indent=2))
        print(f"Server Guard manager removed. Recovery backup: {backup}")
        if plan["protection"]:
            print(f"Current protection remains active through {RETAINED}; keep this directory and retained configuration.")
        print("Users, SSH keys, installed applications, packages and database data were preserved.")
        return backup
