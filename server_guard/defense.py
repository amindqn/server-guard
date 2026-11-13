"""Facade for guarded ban-policy changes and read-only scheduled intrusion checks."""
from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import stat
import subprocess
import time

from .core import GuardError
from .defense_config import (AUTOMATIC_UPDATES, BASELINE, CONFIG, DATABASE, JAIL, JAILS, RESULTS, SERVICE, TIMER, UNIT,
                             DefensePolicy, client_address, fail2ban_config, timer)
from .integrity import IntegrityMonitor, opened
from .health import ReportStore
from .fail2ban import Fail2BanService


class DefenseManager:
    def __init__(self, host):
        self.h, self.f, self.r = host, host.f, host.r
        self.reports = ReportStore(self.f, RESULTS + "/history", 200)

    def verify_jail(self, jail, policy):
        self.r.run("fail2ban-client", "status", jail)
        for setting, expected in [("maxretry", "5"), ("findtime", "600"), ("bantime", "3600")]:
            result = self.r.run("fail2ban-client", "get", jail, setting, timeout=5)
            if result.stdout.strip() != expected:
                raise GuardError(f"Another Fail2Ban setting overrides {jail} {setting}; review its effective configuration.")
        actions = self.r.run("fail2ban-client", "get", jail, "actions", timeout=5).stdout
        if "nftables" not in actions:
            raise GuardError(f"The effective {jail} action is not an nftables action. Review conflicting jail configuration.")
        output = self.r.run("fail2ban-client", "get", jail, "ignoreip", timeout=5).stdout
        ignored = set()
        for token in re.split(r"[\s,\[\]\"'|`]+", output):
            try:
                address = ipaddress.ip_network(token.lstrip("-"), strict=False)
            except ValueError:
                continue
            if not address.prefixlen:
                raise GuardError("An effective all-address Fail2Ban exemption disables attack blocking; review conflicting configuration.")
            ignored.add(str(address))
        required = {"127.0.0.0/8", "::1/128", *(policy.trusted if policy.enabled else [])}
        if not required.issubset(ignored):
            raise GuardError(f"The effective {jail} ban exemptions differ from the reviewed policy.")

    def verify_updates(self):
        output = self.r.run("apt-config", "shell", "SG_PERIODIC", "APT::Periodic::Enable",
                            "SG_LISTS", "APT::Periodic::Update-Package-Lists",
                            "SG_UPGRADES", "APT::Periodic::Unattended-Upgrade", "SG_REBOOT",
                            "Unattended-Upgrade::Automatic-Reboot", timeout=5).stdout
        settings = dict(token.split("=", 1) for token in shlex.split(output) if "=" in token)
        if (settings.get("SG_PERIODIC") != "1" or settings.get("SG_LISTS") != "1" or settings.get("SG_UPGRADES") != "1"
                or settings.get("SG_REBOOT", "").lower() not in {"false", "0", "no"}):
            raise GuardError("Effective APT settings override daily automatic updates or disable the no-reboot policy; review later APT configuration.")

    def require_clear(self):
        if self.f.path("/var/lib/server-guard/pending.json").exists():
            raise GuardError("Confirm or roll back the pending access change before changing automatic defenses.")

    def proposed(self, trusted=(), nginx_logs=(), minutes=15, direct_web_clients=False):
        addresses = list(trusted)
        connection = os.environ.get("SSH_CONNECTION", "").split()
        if connection:
            if len(connection) != 4:
                raise GuardError("Invalid SSH_CONNECTION; preserve the genuine connection environment or use the provider console.")
            addresses.append(client_address(connection[0]))
        policy = DefensePolicy(True, addresses, list(nginx_logs), minutes)
        if policy.nginx_logs and not direct_web_clients:
            raise GuardError("Web bans require --direct-web-clients: only use them when clients connect directly, without a CDN/reverse proxy.")
        return policy

    def _logs(self, policy):
        for name in policy.nginx_logs:
            with opened(self.f, name) as descriptor:
                info = os.fstat(descriptor)
                owner = 0 if str(self.f.root) == "/" else os.geteuid()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
                    raise GuardError("Nginx logs must be root-owned regular files without group/world write access: " + name)

    def firewall_state(self):
        result = self.r.run("nft", "-j", "list", "table", "inet", "server_guard", timeout=5)
        data = json.loads(result.stdout)
        def stable(value):
            if isinstance(value, dict):
                return {key: stable(item) for key, item in value.items() if key not in {"handle", "index", "position", "packets", "bytes"}}
            if isinstance(value, list):
                return [stable(item) for item in value]
            return value
        entries = [stable(item) for item in data["nftables"] if "metainfo" not in item]
        chains = {item["chain"]["name"]: item["chain"] for item in entries if "chain" in item}
        if any(chains.get(name, {}).get("policy") != "drop" for name in ["input", "forward"]):
            raise GuardError("The running Server Guard firewall does not have the expected default-drop chains.")
        return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()

    def snapshot(self):
        snapshot = IntegrityMonitor(self.h).capture()
        IntegrityMonitor.require_complete(snapshot)
        snapshot["firewall_sha256"] = self.firewall_state()
        return snapshot

    def trusted_snapshot(self):
        path = self.f.path(BASELINE)
        if path.is_symlink() or path.stat().st_size > 2 * 1024 ** 2:
            raise GuardError("Refusing linked/oversized integrity baseline.")
        saved = json.loads(path.read_text())
        if (not isinstance(saved, dict) or saved.get("schema") != 1 or not isinstance(saved.get("entries"), dict)
                or not saved["entries"] or not isinstance(saved.get("watches"), dict) or len(saved["watches"]) > 500
                or set(saved["watches"]) != set(saved["entries"])
                or any(not isinstance(name, str) or type(kind) is not bool for name, kind in saved["watches"].items())
                or not re.fullmatch(r"[a-f0-9]{64}", str(saved.get("firewall_sha256", "")))):
            raise GuardError("Invalid or incomplete integrity baseline.")
        return saved

    @staticmethod
    def describe(policy):
        print("AUTOMATIC DEFENSE PLAN")
        print("SSH: five failures/10 minutes; 1-hour bans escalate for repeat attackers, capped at 24 hours.")
        print("Ban exemptions (these do not open firewall ports):", ", ".join(policy.trusted) or "loopback only")
        print("Nginx auth/bot-search logs:", ", ".join(policy.nginx_logs) or "disabled; configure exact trusted logs separately")
        print(f"Security-file drift and defense-service checks: every {policy.minutes} minutes, plus boot.")
        print("Ubuntu automatic security update timers: enabled; automatic reboot: disabled.")
        print("Uses existing SSH/firewall policy and a 10-minute rollback. No website/database data is deleted.")
        print("Drift produces local alerts; it never silently approves changes, kills processes or deletes files.")

    def enable(self, policy, yes=False):
        self.describe(policy)
        if not yes:
            print("Preview only. Use --yes to install this profile.")
            return
        self.require_clear()
        state = self.h.store.load()
        if not self.f.path("/etc/server-guard/firewall.nft").is_file():
            raise GuardError("Apply and confirm the existing SSH/firewall baseline first; use Guided setup.")
        self.h.check_effective_ssh(state)
        self._logs(policy)
        # Dependencies are installed by prepare; this profile never installs third-party agents.
        self.r.run("fail2ban-client", "--version")
        self.r.run("systemctl", "cat", "apt-daily-upgrade.timer")
        return self._change(state, policy)

    def disable(self, yes=False):
        print("Disable escalating/web jails and scheduled intrusion checks. Keep basic SSH bans, firewall, key-only SSH and security updates.")
        if not yes:
            print("Preview only. Use --yes to change the profile.")
            return
        self.require_clear()
        policy = DefensePolicy.load(self.f)
        if not policy.enabled:
            print("Automatic defense profile is already disabled.")
            return
        policy.enabled = False
        return self._change(self.h.store.load(), policy)

    def _change(self, state, policy):
        if policy.enabled and DefensePolicy.load(self.f).enabled:
            try:
                saved = self.trusted_snapshot()
                drift = IntegrityMonitor.compare(saved, IntegrityMonitor(self.h).capture(saved))
                if drift or saved.get("firewall_sha256") != self.firewall_state():
                    raise GuardError("Existing security drift must be reviewed before changing defenses. Use defense scan, then explicitly accept only explained changes with defense baseline --yes.")
            except (OSError, ValueError, KeyError) as exc:
                raise GuardError("Repair/review the existing integrity baseline before changing defenses.") from exc
        if self.h.tx.active("fail2ban"):
            Fail2BanService(self.r).wait()
        age = self.r.run("fail2ban-client", "get", "dbpurgeage", check=False, timeout=5)
        try:
            retention = max(604800, int(age.stdout.strip())) if age.returncode == 0 else 604800
        except ValueError:
            retention = 604800
        txid = self.h.tx.begin()
        try:
            self.f.write(CONFIG, policy.serialize())
            self.f.write(JAIL, fail2ban_config(state["ssh"]["port"], policy))
            self.f.write(DATABASE, f"[Definition]\ndbpurgeage = {retention}\n")
            self.r.run("fail2ban-client", "-t")
            if policy.enabled:
                self.f.path(RESULTS).mkdir(parents=True, mode=0o700, exist_ok=True)
                self.f.write(UNIT, SERVICE, 0o644)
                self.f.write(TIMER, timer(policy.minutes), 0o644)
                self.f.write("/etc/apt/apt.conf.d/90-server-guard", AUTOMATIC_UPDATES, 0o644)
                self.verify_updates()
                self.r.run("systemctl", "daemon-reload")
                self.r.run("systemctl", "enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer")
            self.r.run("systemctl", "enable", "--now", "fail2ban")
            jails = JAILS if policy.enabled and policy.nginx_logs else JAILS[:1]
            Fail2BanService(self.r).restart(jails)
            # Prove the jails are actually running rather than only parsing configuration.
            for jail in jails:
                self.verify_jail(jail, policy)
            if policy.enabled:
                database = self.r.run("fail2ban-client", "get", "dbfile", timeout=5).stdout.strip().strip("'\"")
                if not database or database.lower() == "none" or database == ":memory:":
                    raise GuardError("A persistent Fail2Ban database is required for repeat-attack history; review its native configuration.")
                # OnBootSec may already have elapsed on an existing VPS: make
                # the complete baseline available before activating the timer.
                snapshot = self.snapshot()
                self.f.write(BASELINE, json.dumps(snapshot))
                self.r.run("systemctl", "enable", "--now", "server-guard-defense.timer")
                if not self.h.tx.active("server-guard-defense.timer"):
                    raise GuardError("Automatic defense timer did not become active.")
            else:
                self.r.run("systemctl", "disable", "--now", "server-guard-defense.timer")
        except BaseException:
            self.h.tx.rollback()
            raise
        print(f"Defense change {txid} is pending. Reconnect with a NEW admin SSH key login within 10 minutes, then run:")
        print(f"sudo --preserve-env=SSH_CONNECTION server-guard confirm {txid}")
        return txid

    def baseline(self, yes=False):
        print("Accept CURRENT security files as trusted. First review defense alerts and explain every change; this cannot certify a clean server.")
        if not yes:
            print("Preview only. Use --yes after review.")
            return
        self.require_clear()
        if not DefensePolicy.load(self.f).enabled:
            raise GuardError("Enable the automatic defense profile first.")
        snapshot = self.snapshot()
        self.f.write(BASELINE, json.dumps(snapshot))
        print(f"Accepted {len(snapshot['entries'])} security paths. No application files were modified.")

    def scan(self, scheduled=False):
        policy = DefensePolicy.load(self.f)
        if not policy.enabled:
            raise GuardError("Automatic defense profile is disabled. Use defense enable to review it.")
        self.f.path(RESULTS).mkdir(parents=True, mode=0o700, exist_ok=True)
        with self.f.path(RESULTS + "/scan.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print("Another defense scan is running; no scan or policy change was submitted.")
                return
            return self._scan(policy, scheduled)

    def _scan(self, policy, scheduled):
        findings = []
        def finding(status, detail, path=""):
            findings.append({"status": status, "path": path, "detail": detail})
        try:
            saved = self.trusted_snapshot()
            findings.extend(IntegrityMonitor.compare(saved, IntegrityMonitor(self.h).capture(saved)))
            if self.firewall_state() != saved.get("firewall_sha256"):
                finding("CRITICAL", "Running firewall rules changed since the trusted baseline; counters and handles are excluded.")
        except (OSError, ValueError, TypeError, KeyError, GuardError, subprocess.TimeoutExpired) as exc:
            finding("UNKNOWN", "Integrity coverage could not be verified: " + str(exc))
        for unit in ["server-guard-firewall", "fail2ban", "auditd", "apt-daily.timer", "apt-daily-upgrade.timer", "server-guard-defense.timer"]:
            try:
                result = self.r.run("systemctl", "is-active", "--quiet", unit, check=False, timeout=3)
                if result.returncode:
                    finding("WARN", "Required defense is not active: " + unit)
                if self.r.run("systemctl", "is-enabled", "--quiet", unit, check=False, timeout=3).returncode:
                    finding("WARN", "Required defense is not enabled at boot: " + unit)
            except (OSError, GuardError, subprocess.TimeoutExpired):
                finding("UNKNOWN", "Could not inspect defense: " + unit)
        for jail in JAILS if policy.nginx_logs else JAILS[:1]:
            try:
                if self.r.run("fail2ban-client", "status", jail, check=False, timeout=5).returncode:
                    finding("WARN", "Expected ban jail is not running: " + jail)
            except (OSError, GuardError, subprocess.TimeoutExpired):
                finding("UNKNOWN", "Could not inspect ban jail: " + jail)
        try:
            self._logs(policy)
        except (OSError, GuardError):
            finding("WARN", "An opted-in Nginx log is missing or no longer trusted. Review log rotation, ownership and permissions.")
        try:
            self.verify_updates()
        except (OSError, GuardError, ValueError, subprocess.TimeoutExpired):
            finding("WARN", "Effective automatic-update/no-reboot settings could not be verified. Review APT configuration.")
        try:
            if self.r.run("aa-status", "--enabled", check=False, timeout=3).returncode:
                finding("WARN", "AppArmor is not enabled. Review the host's packaged profiles; no untested profile was forced on your applications.")
        except (OSError, GuardError, subprocess.TimeoutExpired):
            finding("UNKNOWN", "Could not inspect AppArmor.")
        if self.f.path("/var/lib/server-guard/pending.json").exists():
            finding("WARN", "Access change pending; review drift after confirming or rolling back. Do not accept a new baseline yet.")
        status = next((level for level in ["CRITICAL", "UNKNOWN", "WARN"] if any(f["status"] == level for f in findings)), "PASS")
        report = {"schema": 1, "id": str(time.time_ns()), "time": time.time(), "status": status, "findings": findings, "scheduled": scheduled,
                  "scope": "selected security files, owned firewall table and defense services"}
        self.f.write(RESULTS + "/latest.json", json.dumps(report, indent=2))
        self.reports.save(report)
        self.show(report)
        return report

    @staticmethod
    def show(report):
        print("AUTOMATIC DEFENSE | " + time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(report["time"])) + " | " + report["status"])
        for finding in report["findings"]:
            print(f"[{finding['status']}] " + json.dumps(finding["path"]) + " " + finding["detail"])
        if report["status"] == "PASS":
            print("No drift or stopped defenses found in the checked scope; this is not proof the server is uncompromised.")
        else:
            print("Review these alerts and the SSH/system journal. No files, processes, baselines or firewall policy were automatically changed.")

    def status(self):
        policy = DefensePolicy.load(self.f)
        print("Automatic defense profile:", "enabled" if policy.enabled else "disabled")
        print("Trusted ban exemptions:", ", ".join(policy.trusted) or "loopback only")
        print("Nginx error logs:", ", ".join(policy.nginx_logs) or "none")
        for args in [("systemctl", "status", "server-guard-defense.timer", "--no-pager"), ("fail2ban-client", "status")]:
            self.r.run(*args, check=False, capture=False, timeout=10)
        latest = self.f.path(RESULTS + "/latest.json")
        if latest.is_file():
            report = json.loads(latest.read_text())
            self.show(report)
            if policy.enabled and time.time() - report["time"] > policy.minutes * 120 + 180:
                print("[WARN] The last security report is stale. Inspect the defense timer/service and its journal.")
        else:
            print("No scheduled defense report yet. Run defense scan.")

    def history(self):
        reports = self.reports.history()
        for report in reports:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(report["time"]))
            print(f"{stamp} | {report['status']} | {len(report['findings'])} findings | {report['id']}")
        if not reports:
            print("No defense history yet. Run defense scan.")

    def unban(self, jail, address, yes=False):
        if jail not in JAILS:
            raise GuardError("Select a Server Guard jail.")
        address = client_address(address)
        print(f"Unban {address} from {jail}; active protections can ban it again after new failures.")
        if yes:
            self.r.run("fail2ban-client", "set", jail, "unbanip", address)
        else:
            print("Preview only. Use --yes to unban.")
