"""Read-only Linux health probes, explicit findings and bounded local monitoring."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

from .core import GuardError
from .defense_config import CONFIG as DEFENSE_CONFIG, RESULTS as DEFENSE_RESULTS, DefensePolicy


REPORTS = "/var/lib/server-guard/health"
HEALTH_CONFIG = "/etc/server-guard/health.json"
MONITOR_UNIT = "/etc/systemd/system/server-guard-health.service"
MONITOR_TIMER = "/etc/systemd/system/server-guard-health.timer"
DEFAULT_THRESHOLDS = {"cpu": 90, "memory": 90, "disk": 85, "inodes": 85}


def clean(value):
    return "".join(c if c.isprintable() else "?" for c in str(value))


def size(value):
    value = float(value)
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if abs(value) < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"
        value /= 1024


def utc(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def thresholds(value):
    result = dict(DEFAULT_THRESHOLDS, **value)
    if set(result) != set(DEFAULT_THRESHOLDS) or any(type(n) is not int or not 50 <= n <= 99 for n in result.values()):
        raise GuardError("CPU, memory, disk and inode warning thresholds must be integers from 50 to 99 percent.")
    return result


class LinuxResources:
    """Adapter: procfs reads plus statvfs; no process arguments or environments."""
    def __init__(self, files, sleeper=time.sleep, clock=time.monotonic):
        self.f, self.sleep, self.clock = files, sleeper, clock

    def text(self, path):
        return self.f.path(path).read_text()

    def snapshot(self):
        lines = self.text("/proc/stat").splitlines()
        cpu = [int(n) for n in lines[0].split()[1:9]]
        if len(cpu) != 8 or any(n < 0 for n in cpu):
            raise GuardError("Invalid Linux CPU counters.")
        memory = {}
        for line in self.text("/proc/meminfo").splitlines():
            key, value = line.split(":", 1)
            memory[key] = int(value.split()[0]) * 1024
        processes, skipped = {}, 0
        for folder in self.f.path("/proc").iterdir():
            if not folder.name.isdigit():
                continue
            if len(processes) >= 8192:
                skipped += 1
                continue
            try:
                text = (folder / "stat").read_text()
                start, end = text.index("("), text.rindex(")")
                values = text[end + 2:].split()
                processes[int(folder.name)] = {
                    "pid": int(folder.name), "name": clean(text[start + 1:end])[:80],
                    "state": values[0], "ticks": int(values[11]) + int(values[12]),
                    "start": values[19], "nice": int(values[16]),
                    "rss": max(0, int(values[21])) * os.sysconf("SC_PAGE_SIZE"),
                    "uid": folder.stat().st_uid}
            except (OSError, ValueError, IndexError):
                skipped += 1
        network = {}
        for line in self.text("/proc/net/dev").splitlines()[2:]:
            name, values = line.split(":", 1)
            values = values.split()
            if name.strip() != "lo":
                network[clean(name.strip())] = {"rx": int(values[0]), "tx": int(values[8])}
        return {"time": self.clock(), "cpu": cpu, "cpus": sum(bool(re.match(r"cpu\d+ ", l)) for l in lines) or 1,
                "memory": memory, "processes": processes, "skipped": skipped, "network": network}

    def sample(self, seconds=1):
        before = self.snapshot()
        self.sleep(seconds)
        after = self.snapshot()
        elapsed = after["time"] - before["time"]
        delta = [b - a for a, b in zip(before["cpu"], after["cpu"])]
        total = sum(delta)
        if elapsed <= 0 or total <= 0 or any(n < 0 for n in delta):
            raise GuardError("CPU counters changed/reset during sampling; retry the check.")
        memory = after["memory"]
        available = memory.get("MemAvailable", memory.get("MemFree", 0))
        mem_total = memory["MemTotal"]
        if mem_total <= 0:
            raise GuardError("Linux did not report a valid memory total.")
        processes = []
        for pid, item in after["processes"].items():
            old = before["processes"].get(pid)
            cpu = None
            if old and old["start"] == item["start"] and item["ticks"] >= old["ticks"]:
                cpu = (item["ticks"] - old["ticks"]) / os.sysconf("SC_CLK_TCK") / elapsed * 100
            processes.append({k: v for k, v in item.items() if k != "ticks"} | {"cpu_percent": cpu})
        network = []
        for name, counters in after["network"].items():
            previous = before["network"].get(name)
            if previous and all(counters[k] >= previous[k] for k in ["rx", "tx"]):
                network.append({"interface": name, "rx_bytes_s": (counters["rx"] - previous["rx"]) / elapsed,
                                "tx_bytes_s": (counters["tx"] - previous["tx"]) / elapsed})
        pressure = {}
        for resource in ["cpu", "memory", "io"]:
            try:
                pressure[resource] = {row.split()[0]: {k: float(v) for k, v in
                    (part.split("=") for part in row.split()[1:] if part.startswith("avg"))}
                    for row in self.text("/proc/pressure/" + resource).splitlines()}
            except (OSError, ValueError, IndexError):
                pressure[resource] = None
        return {"sample_seconds": round(elapsed, 3), "cpus": after["cpus"],
                "cpu_percent": round(max(0, total - delta[3] - delta[4] - delta[7]) / total * 100, 1),
                "iowait_percent": round(delta[4] / total * 100, 1), "steal_percent": round(delta[7] / total * 100, 1),
                "load": [float(n) for n in self.text("/proc/loadavg").split()[:3]],
                "uptime_seconds": float(self.text("/proc/uptime").split()[0]),
                "memory_total": mem_total, "memory_available": available,
                "memory_estimated": "MemAvailable" not in memory,
                "memory_percent": round((mem_total - available) / mem_total * 100, 1),
                "swap_total": memory.get("SwapTotal", 0),
                "swap_used": memory.get("SwapTotal", 0) - memory.get("SwapFree", 0),
                "pressure": pressure, "network": network,
                "processes_skipped": after["skipped"],
                "top_cpu": sorted(processes, key=lambda p: p["cpu_percent"] or 0, reverse=True)[:10],
                "top_memory": sorted(processes, key=lambda p: p["rss"], reverse=True)[:10]}

    def disks(self):
        excluded = {"proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs", "debugfs",
                    "tracefs", "pstore", "mqueue", "hugetlbfs", "configfs", "fusectl", "squashfs", "autofs"}
        mounts = {"/": "root"}
        for line in self.text("/proc/self/mountinfo").splitlines():
            left, right = line.split(" - ", 1)
            fields, fs = left.split(), right.split()[0]
            mount = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])
            if fs not in excluded and (mount == "/" or mount.startswith(("/var", "/home", "/srv", "/www", "/mnt", "/media", "/boot"))):
                mounts[mount] = fs
        result = []
        for mount, fs in sorted(mounts.items()):
            try:
                info = os.statvfs(self.f.path(mount))
                used = (info.f_blocks - info.f_bfree) * info.f_frsize
                free = info.f_bavail * info.f_frsize
                result.append({"mount": clean(mount), "filesystem": fs, "used": used, "available": free,
                    "percent": round(used / max(1, used + free) * 100, 1),
                    "inode_percent": round((info.f_files - info.f_ffree) / info.f_files * 100, 1) if info.f_files else None,
                    "readonly": bool(info.f_flag & getattr(os, "ST_RDONLY", 1))})
            except OSError as exc:
                result.append({"mount": clean(mount), "error": clean(exc)})
        return result


class ReportStore:
    """Bounded private snapshots shared by CLI, terminal and scheduled checks."""
    def __init__(self, files, directory=REPORTS, retention=200):
        self.f = files
        self.directory, self.retention = directory, retention

    def save(self, report):
        folder = self.f.path(self.directory)
        folder.mkdir(parents=True, mode=0o700, exist_ok=True)
        with (folder / ".lock").open("a") as lock:
            os.chmod(folder / ".lock", 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.f.write(self.directory + "/" + report["id"] + ".json", json.dumps(report, indent=2))
            for old in sorted(folder.glob("*.json"), reverse=True)[self.retention:]:
                old.unlink()

    def history(self, limit=20):
        folder = self.f.path(self.directory)
        result = []
        for file in sorted(folder.glob("*.json"), reverse=True)[:limit]:
            try:
                result.append(json.loads(file.read_text()))
            except (OSError, ValueError):
                continue
        return result

    def latest(self):
        reports = self.history(1)
        if not reports:
            raise GuardError("No saved health report. Run health check first.")
        return reports[0]


class HealthChecker:
    """Composite workflow: independently reported probes; missing evidence is UNKNOWN."""
    def __init__(self, host, resources=None):
        self.h, self.f, self.r = host, host.f, host.r
        self.resources = resources or LinuxResources(self.f)
        self.results = []
        self.progress, self.step, self.total = None, 2, 13

    def finding(self, name, status, detail, action=""):
        self.results.append({"name": name, "status": status, "detail": clean(detail), "action": clean(action)})

    def command(self, *args):
        self.step += 1
        if self.progress:
            self.progress(self.step, self.total, "Security: " + " ".join(str(arg) for arg in args))
        try:
            result = self.r.run(*args, check=False, timeout=8)
            return result.returncode, (result.stdout or "").strip()
        except (OSError, subprocess.TimeoutExpired):
            return None, "Command unavailable or timed out"

    def config(self):
        file = self.f.path(HEALTH_CONFIG)
        if not file.exists():
            return dict(DEFAULT_THRESHOLDS)
        config = json.loads(file.read_text())
        if not isinstance(config, dict) or not isinstance(config.get("thresholds", {}), dict):
            raise GuardError("Invalid health configuration; review " + HEALTH_CONFIG)
        return thresholds(config.get("thresholds", {}))

    def security(self):
        code, output = self.command("sshd", "-T")
        settings = dict(line.split(" ", 1) for line in output.splitlines() if " " in line) if code == 0 else {}
        if not settings:
            self.finding("SSH policy", "UNKNOWN", "Effective SSH configuration could not be read.", "Use Accounts / SSH diagnostics.")
        else:
            weak = [key + "=" + settings.get(key, "unknown") for key, expected in
                    [("passwordauthentication", "no"), ("kbdinteractiveauthentication", "no"), ("permitrootlogin", "no")]
                    if settings.get(key) != expected]
            self.finding("SSH policy", "WARN" if weak else "PASS", "; ".join(weak) or "Global effective root/password login disabled.",
                         "Review per-user Match overrides and test a new key login before changing SSH." if weak else "Global check; does not evaluate every Match context.")
        code, output = self.command("nft", "list", "table", "inet", "server_guard")
        drop = code == 0 and re.search(r"hook input\b[^;]*;\s*policy drop\s*;", output) is not None
        self.finding("Inbound firewall", "PASS" if drop else "CRITICAL" if code == 0 else "UNKNOWN",
                     "Owned input chain has policy drop." if drop else "Owned default-deny input policy was not found." if code == 0 else "The owned firewall table could not be inspected (absent, permissions or tool failure).",
                     "Review plan/apply and the provider firewall; this check is not an external port scan.")
        for label, unit in [("SSH brute-force protection", "fail2ban.service"),
                            ("Security update timer", "apt-daily-upgrade.timer"), ("Audit service", "auditd.service")]:
            code, output = self.command("systemctl", "is-active", unit)
            self.finding(label, "PASS" if code == 0 else "UNKNOWN" if code is None else "WARN", output or "not active",
                         "Use security service status; review package/setup failures before repair.")
        code, output = self.command("fail2ban-client", "status", "sshd")
        self.finding("SSH ban jail", "PASS" if code == 0 else "UNKNOWN" if code is None else "WARN",
                     "sshd jail responds." if code == 0 else "sshd jail did not respond.", "Review fail2ban-client status sshd.")
        code, _ = self.command("aa-status", "--enabled")
        self.finding("AppArmor", "PASS" if code == 0 else "UNKNOWN" if code is None else "WARN",
                     "Enabled (application coverage still needs review)." if code == 0 else "Not verified enabled.")
        code, output = self.command("timedatectl", "show", "-p", "NTPSynchronized", "--value")
        self.finding("Time synchronization", "PASS" if code == 0 and output == "yes" else "WARN" if code == 0 else "UNKNOWN",
                     output or "not verified", "Check NTP/chrony; correct time is required for TLS and VMess.")
        code, output = self.command("ss", "-H", "-lntup")
        listeners = []
        if code == 0:
            for line in output.splitlines():
                fields = line.split()
                if len(fields) >= 5:
                    address = fields[4]
                    if address.startswith(("127.", "[::1]:", "::1:")):
                        continue
                    listeners.append({"protocol": fields[0], "address": clean(address)})
        self.finding("Non-loopback listeners", "INFO" if code == 0 else "UNKNOWN",
                     "; ".join(f"{p['protocol']} {p['address']}" for p in listeners[:30]) if listeners else
                     "None reported." if code == 0 else "Could not inspect sockets.",
                     "Listening does not prove public reachability. Check provider rules and both IP families.")
        private_ports = {27017, 3306, 5432, 6379, 10000, 8443}
        risky = [row["address"] for row in listeners if row["address"].rsplit(":", 1)[-1].isdigit()
                 and int(row["address"].rsplit(":", 1)[-1]) in private_ports]
        if risky:
            self.finding("Private-service binding", "WARN", "; ".join(risky),
                         "Review DB/backend/panel bindings. The firewall may still block them; use localhost/tunnels and verify externally.")
        self.finding("Reboot", "WARN" if self.f.path("/var/run/reboot-required").exists() else "PASS",
                     "Reboot required." if self.f.path("/var/run/reboot-required").exists() else "No Ubuntu reboot-required marker.",
                     "Schedule after confirming access; no automatic reboot is performed.")
        code, output = self.command("apt-get", "--simulate", "upgrade")
        updates = sum(line.startswith("Inst ") for line in output.splitlines())
        self.finding("Pending package upgrades", "UNKNOWN" if code != 0 else "WARN" if updates else "PASS",
                     "Could not simulate upgrades." if code != 0 else f"{updates} upgrades in currently cached APT metadata.",
                     "Refresh package metadata and review updates; this count does not prove security patch freshness.")
        code, output = self.command("systemctl", "--failed", "--no-legend", "--plain", "--no-pager")
        self.finding("Failed system services", "UNKNOWN" if code != 0 else "WARN" if output else "PASS",
                     output[:1200] if code == 0 and output else "None reported." if code == 0 else "Could not inspect failed units.",
                     "Inspect the named service before restarting it; intentional stops are not failures.")
        if self.h.tx.pending():
            self.finding("Access change", "WARN", "A rollback-protected access change is pending.", "Confirm from a new administrator key login or roll back.")
        if self.f.path(DEFENSE_CONFIG).exists():
            self.defenses()

    def defenses(self):
        code, output = self.command("systemctl", "is-active", "server-guard-defense.timer")
        try:
            policy = DefensePolicy.load(self.f)
            if not policy.enabled:
                self.finding("Automatic defense profile", "INFO", "Extra profile disabled; basic SSH/firewall checks remain above.")
                return
            self.finding("Automatic defense timer", "PASS" if code == 0 else "UNKNOWN" if code is None else "WARN",
                         output or "not active", "Inspect defense status and journalctl -u server-guard-defense.service.")
            report = json.loads(self.f.path(DEFENSE_RESULTS + "/latest.json").read_text())
            stale = time.time() - report["time"] > policy.minutes * 120 + 180
            status = "WARN" if stale else report["status"]
            if status not in {"PASS", "WARN", "CRITICAL", "UNKNOWN"}:
                raise GuardError("Invalid defense report status.")
            self.finding("Automatic defense findings", status, "Last report is stale." if stale else
                         f"{len(report['findings'])} findings from selected security files/firewall/services.",
                         "Use defense status/history to review; accept only explained changes with defense baseline --yes.")
        except (OSError, ValueError, TypeError, KeyError, GuardError):
            self.finding("Automatic defense findings", "UNKNOWN", "No valid defense report/configuration available yet.", "Run defense scan and inspect its journal; missing evidence does not mean secure.")

    def check(self, progress=None, security=True):
        self.results = []
        report = {"schema": 1, "id": f"{time.time_ns():020d}-{uuid.uuid4().hex[:8]}", "time": time.time(), "metrics": {}}
        phases = [("Sampling CPU, RAM, swap, pressure, processes and network", self.resources.sample),
                  ("Checking mounted storage and inode usage", self.resources.disks)]
        total = 13 + int(self.f.path(DEFENSE_CONFIG).exists()) if security else 2
        self.progress, self.step, self.total = progress, 2, total
        limits = self.config()
        for i, (label, probe) in enumerate(phases, 1):
            if progress:
                progress(i, total, label)
            try:
                data = probe()
                report["metrics"]["resources" if i == 1 else "disks"] = data
            except (OSError, ValueError, KeyError, GuardError) as exc:
                self.finding(label, "UNKNOWN", str(exc), "Check Linux /proc availability and mount permissions.")
        resource = report["metrics"].get("resources", {})
        if resource.get("memory_estimated"):
            self.finding("RAM availability method", "UNKNOWN", "MemAvailable was not reported; RAM usage uses MemFree as an estimate.",
                         "Inspect kernel memory reporting before treating the RAM percentage as reclaim pressure.")
        for field, key, label in [("cpu_percent", "cpu", "CPU busy"), ("memory_percent", "memory", "RAM usage")]:
            if field in resource:
                value = resource[field]
                self.finding(label, "WARN" if value >= limits[key] else "PASS", f"{value}% (warning at {limits[key]}%).",
                             "Inspect top processes and pressure; compare several samples before tuning.")
        if resource.get("steal_percent", 0) >= 10:
            self.finding("CPU steal", "WARN", f"{resource['steal_percent']}% unavailable to this VM.", "Check host contention or resize/migrate with your provider.")
        if resource.get("iowait_percent", 0) >= 15:
            self.finding("I/O wait", "WARN", f"{resource['iowait_percent']}% sampled wait (approximate).", "Inspect disk workload and available storage; CPU priority may not help.")
        for name, rows in resource.get("pressure", {}).items():
            row = (rows or {}).get("some" if name == "cpu" else "full", {})
            if row.get("avg60", 0) >= 10:
                self.finding(name + " pressure", "WARN", f"{row['avg60']}% stalls over 60 seconds.", "Reduce competing workload or increase the constrained resource.")
        for disk in report["metrics"].get("disks", []):
            if "error" in disk:
                self.finding("Storage " + disk["mount"], "UNKNOWN", disk["error"])
                continue
            for field, key, label in [("percent", "disk", "space"), ("inode_percent", "inodes", "inodes")]:
                value = disk[field]
                self.finding(disk["mount"] + " " + label, "UNKNOWN" if value is None else "CRITICAL" if value >= 95 else "WARN" if value >= limits[key] else "PASS",
                             "Not reported." if value is None else f"{value}% used (warning at {limits[key]}%).",
                             "Use Storage explorer; review cleanup candidates and application retention.")
            if disk["readonly"]:
                self.finding(disk["mount"] + " mount", "WARN", "Mounted read-only.", "Check whether intentional; inspect kernel/storage errors before remounting.")
        if security:
            try:
                self.security()
            except (OSError, ValueError, GuardError) as exc:
                self.finding("Security probe coverage", "UNKNOWN", str(exc), "Review the failed probe and rerun the check.")
                if progress:
                    progress(total, total, "Finished with incomplete security coverage; review UNKNOWN findings")
        report["checks"], report["thresholds"] = self.results, limits
        counts = Counter(item["status"] for item in self.results)
        report["counts"] = dict(counts)
        report["status"] = next((s for s in ["CRITICAL", "WARN", "UNKNOWN"] if counts[s]), "PASS")
        report["scope"] = "resources and security" if security else "resources only"
        return report


class HealthView:
    @staticmethod
    def show(report, stream=None):
        import sys
        stream = stream or sys.stdout
        def say(text=""):
            print(text, file=stream, flush=True)
        say(f"SERVER HEALTH | {utc(report['time'])} | {report['status']} | {report['scope']}")
        r = report["metrics"].get("resources", {})
        if r:
            say(f"CPU {r['cpu_percent']}% / {r['cpus']} cores | load {' / '.join(str(n) for n in r['load'])} | I/O wait {r['iowait_percent']}% | steal {r['steal_percent']}%")
            say(f"RAM {r['memory_percent']}% used | available {size(r['memory_available'])} / {size(r['memory_total'])} | swap {size(r['swap_used'])} / {size(r['swap_total'])}")
            say(f"Uptime {r['uptime_seconds'] / 3600:.1f} hours | sample {r['sample_seconds']}s")
            for name, rows in r.get("pressure", {}).items():
                row = (rows or {}).get("some" if name == "cpu" else "full", {})
                say(f"PRESSURE {name}: " + (" / ".join(f"{row.get(key, 0)}%" for key in ["avg10", "avg60", "avg300"]) + " (10/60/300s)" if row else "unavailable"))
            for item in r["network"]:
                say(f"NET {item['interface']}: receive {size(item['rx_bytes_s'])}/s | send {size(item['tx_bytes_s'])}/s")
            for label, key in [("Top CPU (100% = one core)", "top_cpu"), ("Top RAM (RSS; shared memory may overlap)", "top_memory")]:
                say(label + ": PID | UID | CPU% | RSS | name")
                for item in r[key][:5]:
                    cpu = "new" if item['cpu_percent'] is None else f"{item['cpu_percent']:.1f}"
                    say(f"  {item['pid']:>7} {item['uid']:>6} {cpu:>6} {size(item['rss']):>12}  {clean(item['name'])}")
            if r["processes_skipped"]:
                say(f"Process coverage: {r['processes_skipped']} entries inaccessible, exited or beyond the sampling cap.")
        for item in report["metrics"].get("disks", []):
            if "error" not in item:
                say(f"DISK {item['mount']}: {item['percent']}% | free {size(item['available'])} | inodes {item['inode_percent']}%")
        say("Findings (PASS is a checked condition, not a security guarantee):")
        for item in report["checks"]:
            say(f"[{item['status']}] {clean(item['name'])}: {clean(item['detail'])}")
            if item["status"] in {"WARN", "CRITICAL", "UNKNOWN"} and item["action"]:
                say("  Next: " + clean(item["action"]))


class HealthMonitor:
    """Systemd scheduler; reports only, never automatic remediation or messaging."""
    def __init__(self, host):
        self.h = host

    def enable(self, minutes=5, limits=None):
        self.h.tx.require_clear()
        if not 1 <= minutes <= 1440:
            raise GuardError("Monitoring interval must be 1..1440 minutes.")
        limits = thresholds(limits or {})
        self.h.f.write(HEALTH_CONFIG, json.dumps({"thresholds": limits, "minutes": minutes}, indent=2))
        self.h.f.write(MONITOR_UNIT, """[Unit]
Description=Server Guard health report (no automatic changes)
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/server-guard health check --record --json
TimeoutStartSec=120
Nice=10
IOSchedulingClass=idle
NoNewPrivileges=true
UMask=0077
""", 0o644)
        self.h.f.write(MONITOR_TIMER, f"""[Unit]
Description=Server Guard periodic health sampling
[Timer]
OnBootSec=2min
OnUnitInactiveSec={minutes}min
AccuracySec=30s
[Install]
WantedBy=timers.target
""", 0o644)
        self.h.r.run("systemctl", "daemon-reload")
        self.h.r.run("systemctl", "enable", "--now", "server-guard-health.timer")
        print(f"Health monitoring enabled every {minutes} minutes after each completed check. Local reports only; no automatic cleanup.")

    def disable(self):
        self.h.tx.require_clear()
        self.h.r.run("systemctl", "disable", "--now", "server-guard-health.timer")
        self.h.r.run("systemctl", "stop", "server-guard-health.service")
        print("Scheduled checks stopped. Saved reports retained.")

    def status(self):
        self.h.r.run("systemctl", "status", "server-guard-health.timer", "server-guard-health.service", "--no-pager", check=False, capture=False)
