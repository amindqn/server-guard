"""Commands stage policy explicitly; apply validates it and arms rollback."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import sys
import time
import subprocess

from . import __version__
from .core import Files, GuardError, Runner, V2RayBuilder, network, port, public_key, username, write_user_key
from .host import Host
from .services import DB_ENGINES, ManagedServices, PanelManager, V2RayManager
from .mongodb import MongoDBManager, app_database, mongo_name
from .uninstall import UninstallManager
from .health import DEFAULT_THRESHOLDS, HealthChecker, HealthMonitor, HealthView, ReportStore, utc
from .maintenance import APPLICATION_UNITS, MaintenanceActions, StorageManager, absolute_path
from .updater import UpdateManager
from .defense import DefenseManager
from .defense_config import JAILS, client_address, nginx_log, trusted_network


def parser():
    p = argparse.ArgumentParser(description="Ubuntu 24.04 server management with guarded access changes.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command")
    for name in ["prepare", "plan", "apply", "status", "audit", "update", "rollback", "verify-login", "menu", "setup"]:
        c = sub.add_parser(name)
        if name == "apply":
            c.add_argument("--replace-ufw", action="store_true", help="replace active UFW with the reviewed policy")
    c = sub.add_parser("self-update", help="update Server Guard code/docs while preserving configuration and application data")
    c.add_argument("--check", action="store_true", help="inspect the selected source without changing installed files")
    c.add_argument("--repo", help="GitHub OWNER/REPOSITORY; defaults to the recorded installation source")
    c.add_argument("--ref", help="branch/tag/commit; defaults to the recorded installation ref")
    c.add_argument("--sha256", help="expected GitHub source archive SHA-256")
    c.add_argument("--allow-downgrade", action="store_true")
    c = sub.add_parser("defense", help="automatic attack blocking, integrity checks and local security alerts")
    ds = c.add_subparsers(dest="action", required=True)
    c = ds.add_parser("enable")
    c.add_argument("--trusted", nargs="*", default=[], type=trusted_network)
    c.add_argument("--nginx-log", action="append", default=[], type=nginx_log)
    c.add_argument("--direct-web-clients", action="store_true")
    c.add_argument("--minutes", type=int, default=15)
    c.add_argument("--yes", action="store_true")
    for name in ["disable", "baseline"]:
        ds.add_parser(name).add_argument("--yes", action="store_true")
    ds.add_parser("status")
    ds.add_parser("history")
    ds.add_parser("scan").add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    c = ds.add_parser("unban")
    c.add_argument("jail", choices=JAILS)
    c.add_argument("address", type=client_address)
    c.add_argument("--yes", action="store_true")
    c = sub.add_parser("init")
    c.add_argument("--ssh-port", type=port, default=22)
    c = sub.add_parser("confirm")
    c.add_argument("id")
    c = sub.add_parser("user")
    us = c.add_subparsers(dest="action", required=True)
    c = us.add_parser("add")
    c.add_argument("name", type=username)
    c.add_argument("--role", choices=["admin", "developer", "sftp"], required=True)
    c.add_argument("--sessions", type=int, default=2)
    c.add_argument("--key-file", required=True)
    c = us.add_parser("adopt", help="apply SSH role/session policy to an existing panel-created shell account")
    c.add_argument("name", type=username)
    c.add_argument("--role", choices=["admin", "developer"], default="developer")
    c.add_argument("--sessions", type=int, default=2)
    for action in ["limit", "key", "disable", "list"]:
        c = us.add_parser(action)
        if action != "list":
            c.add_argument("name", type=username)
        if action == "limit":
            c.add_argument("count", type=int)
        if action == "key":
            c.add_argument("--key-file", required=True)
            c.add_argument("--append", action="store_true", help="add the new key while retaining existing plain public keys")
    c = sub.add_parser("ssh")
    ss = c.add_subparsers(dest="action", required=True)
    c = ss.add_parser("port")
    c.add_argument("port", type=port)
    c = ss.add_parser("sources")
    c.add_argument("sources", nargs="+")
    c = ss.add_parser("root")
    c.add_argument("mode", choices=["disable", "key-only"])
    ss.add_parser("diagnose", help="explain this SSH transport's authentication method without changing settings")
    c = sub.add_parser("firewall")
    fs = c.add_subparsers(dest="action", required=True)
    for action in ["allow", "deny", "list"]:
        c = fs.add_parser(action)
        if action != "list":
            c.add_argument("port", type=port)
            c.add_argument("--protocol", choices=["tcp", "udp"], default="tcp")
            c.add_argument("--source", default="any")
    c = sub.add_parser("web")
    c.add_argument("action", choices=["enable", "disable"])
    c = sub.add_parser("panel")
    ps = c.add_subparsers(dest="action", required=True)
    ps.add_parser("info")
    for action in ["download", "install"]:
        c = ps.add_parser(action)
        c.add_argument("provider", choices=["cloudpanel", "aapanel"])
        if action == "install":
            approval = c.add_mutually_exclusive_group(required=True)
            approval.add_argument("--sha256")
            approval.add_argument("--official-checksum", action="store_true", help="compare CloudPanel with its official installation guide")
            c.add_argument("--db-engine", choices=DB_ENGINES, default="MYSQL_8.4")
    c = sub.add_parser("v2ray")
    vs = c.add_subparsers(dest="action", required=True)
    c = vs.add_parser("install")
    c.add_argument("--version", required=True)
    c.add_argument("--sha256", required=True)
    c = vs.add_parser("configure")
    c.add_argument("--domain", required=True)
    c.add_argument("--local-port", type=port, default=10000)
    for action in ["add", "revoke", "export", "list", "nginx"]:
        c = vs.add_parser(action)
        if action in {"add", "revoke", "export"}:
            c.add_argument("name", type=username)
    c = sub.add_parser("mongodb", help="optional local MongoDB 8.0 service and database users")
    ms = c.add_subparsers(dest="action", required=True)
    c = ms.add_parser("install")
    c.add_argument("--port", type=port, default=27017)
    c = ms.add_parser("bootstrap")
    c.add_argument("--admin", type=mongo_name, default="mongoAdmin")
    c.add_argument("--authenticate", action="store_true", help="recover interrupted bootstrap using an existing MongoDB admin")
    ms.add_parser("status")
    for action in ["user-add", "user-revoke", "password", "shell"]:
        c = ms.add_parser(action)
        c.add_argument("--admin", type=mongo_name, default="mongoAdmin")
        if action != "shell":
            c.add_argument("name", type=mongo_name)
            c.add_argument("--database", type=app_database, required=True)
        if action == "user-add":
            c.add_argument("--role", choices=["read", "readWrite"], default="readWrite")
    c = sub.add_parser("service", help="manage the optional MongoDB or V2Ray service")
    c.add_argument("name", choices=["mongodb", "v2ray"])
    c.add_argument("action", choices=["start", "stop", "restart", "status"])
    c = sub.add_parser("uninstall", help="remove the manager while keeping access protection and application data")
    c.add_argument("--yes", action="store_true", help="execute after reviewing the removal plan")
    c.add_argument("--dry-run", action="store_true", help="show the removal plan without changes")
    c.add_argument("--purge", action="store_true", help="also remove unused config; permitted only before hardening")
    c.add_argument("--expected", help=argparse.SUPPRESS)
    c = sub.add_parser("health", help="progress checks, live/local monitoring, reviewed cleanup and CPU scheduling")
    hs = c.add_subparsers(dest="action", required=True)
    c = hs.add_parser("check", help="sample server resources and inspect security controls")
    c.add_argument("--json", action="store_true")
    c.add_argument("--record", action="store_true", help="save report (also the default)")
    c.add_argument("--no-record", action="store_true")
    c = hs.add_parser("watch", help="live resources; full security check in the first frame")
    c.add_argument("--interval", type=int, default=5)
    c.add_argument("--count", type=int, default=0, help="0 keeps watching until Ctrl+C")
    c = hs.add_parser("show", help="show the latest saved report")
    c.add_argument("--json", action="store_true")
    c = hs.add_parser("history", help="recent local results and resource trends")
    c.add_argument("--limit", type=int, default=20)
    c = hs.add_parser("files", help="bounded large-file inventory; never deletes")
    c.add_argument("path", nargs="?", default="/var", type=absolute_path)
    c.add_argument("--min-mib", type=int, default=100)
    c.add_argument("--limit", type=int, default=20)
    c.add_argument("--max-entries", type=int, default=100000, help="maximum inspected directory/file entries (up to 10000000)")
    c.add_argument("--max-seconds", type=int, default=30, help="cooperative scan time budget (up to 3600 seconds)")
    c = hs.add_parser("delete", help="review one inventory item; --yes permanently deletes it")
    c.add_argument("scan_id")
    c.add_argument("item", type=int)
    c.add_argument("--yes", action="store_true")
    c = hs.add_parser("cleanup", help="preview named cache/log cleanup; --yes executes it")
    c.add_argument("target", choices=["apt-cache", "journal"])
    c.add_argument("--days", type=int, default=14)
    c.add_argument("--yes", action="store_true")
    c = hs.add_parser("cpu-weight", help="reversible runtime scheduling priority for application services")
    c.add_argument("service", choices=sorted(APPLICATION_UNITS))
    group = c.add_mutually_exclusive_group(required=True)
    group.add_argument("--weight", type=int)
    group.add_argument("--reset", action="store_true")
    c.add_argument("--yes", action="store_true")
    c = hs.add_parser("monitor", help="configure periodic local health reports; no automatic fixes")
    c.add_argument("mode", choices=["enable", "disable", "status"])
    c.add_argument("--minutes", type=int, default=5)
    for key, value in DEFAULT_THRESHOLDS.items():
        c.add_argument("--" + key, type=int, default=value)
    c.add_argument("--yes", action="store_true")
    sub.add_parser("firewall-load", help="reload the applied firewall (internal systemd helper)")
    sub.add_parser("v2ray-egress-load", help="reload proxy isolation (internal systemd helper)")
    return p


def user_command(h, a):
    if a.action == "add":
        return h.add_user(a.name, a.role, a.sessions, a.key_file)
    state = h.store.load()
    if a.action == "list":
        print(json.dumps(state["users"], indent=2))
        return
    h.tx.require_clear()
    if a.action == "adopt":
        if a.name in state["users"]:
            raise GuardError("Already managed. Use user limit/key/disable.")
        account = pwd.getpwnam(a.name)
        if account.pw_uid < 1000 or account.pw_shell not in {"/bin/bash", "/bin/sh", "/usr/bin/bash", "/bin/zsh", "/usr/bin/zsh"}:
            raise GuardError("Only ordinary existing shell accounts can be adopted.")
        import grp
        groups = {g.gr_name for g in grp.getgrall() if a.name in g.gr_mem or g.gr_gid == account.pw_gid}
        if a.role == "admin" and "sudo" not in groups:
            raise GuardError("An adopted administrator must already have sudo access.")
        if a.role == "developer" and groups & {"sudo", "admin", "docker", "lxd", "disk", "root"}:
            raise GuardError("This account has privileged groups; review them before assigning the developer role.")
        if not 1 <= a.sessions <= 100:
            raise GuardError("Session count must be 1..100.")
        state["users"][a.name] = {"role": a.role, "sessions": a.sessions, "disabled": False}
        h.store.save(state)
        print("Existing account adopted without changing its home, keys, password or groups. Run plan/apply.")
        return
    if a.name not in state["users"]:
        raise GuardError("Unknown managed user.")
    info = state["users"][a.name]
    if a.action == "limit":
        if not 1 <= a.count <= 100:
            raise GuardError("Session count must be 1..100.")
        info["sessions"] = a.count
    elif a.action == "key":
        key = public_key(Path(a.key_file).read_text())
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "key.pub"
            p.write_text(key)
            h.r.run("ssh-keygen", "-l", "-f", p)
        user = pwd.getpwnam(a.name)
        write_user_key(user.pw_dir, key, user.pw_uid, user.pw_gid, append=a.append)
        h.f.path("/var/lib/server-guard/login-proof.json").unlink(missing_ok=True)
        print("Key added; existing keys retained." if a.append else "Key replaced immediately.")
        print("Test a fresh key login before applying any access change.")
    elif a.action == "disable":
        admins = [u for u, i in state["users"].items()
                  if i["role"] == "admin" and not i.get("disabled") and u != a.name]
        if info["role"] == "admin" and not admins:
            raise GuardError("Cannot disable the last managed administrator.")
        if a.name == os.environ.get("SUDO_USER"):
            raise GuardError("Use another administrator to disable your own account.")
        # Expiration blocks SSH key login too; password locking alone does not.
        h.r.run("usermod", "--expiredate", "1", "--lock", a.name)
        info["disabled"] = True
        print("Account disabled immediately. Existing processes were retained; use loginctl terminate-user if needed.")
    h.store.save(state)
    if a.action == "limit":
        print("Session policy staged. Run plan and apply; existing sessions are not terminated.")


def stage(h, a):
    h.tx.require_clear()
    state = h.store.load()
    if a.command == "ssh":
        if a.action == "port":
            state["ssh"]["port"] = a.port
        elif a.action == "root":
            state["ssh"]["root_login"] = a.mode == "key-only"
        elif a.action == "sources":
            state["ssh"]["sources"] = list(dict.fromkeys(
                "any" if s == "any" else network(s) for s in a.sources))
    elif a.command == "web":
        for n in [80, 443]:
            rule = {"port": n, "protocol": "tcp", "source": "any"}
            state["ports"] = [r for r in state["ports"] if r != rule]
            if a.action == "enable":
                state["ports"].append(rule)
    else:
        if a.action == "list":
            print(json.dumps(state["ports"], indent=2))
            return
        source = "any" if a.source == "any" else network(a.source)
        if a.port == state["ssh"]["port"] and a.protocol == "tcp":
            raise GuardError("Manage SSH access with 'ssh port/sources', not extra firewall rules.")
        rule = {"port": a.port, "protocol": a.protocol, "source": source}
        state["ports"] = [r for r in state["ports"] if r != rule]
        if a.action == "allow":
            state["ports"].append(rule)
    h.store.save(state)
    print("Policy staged. Run 'server-guard plan', then 'server-guard apply'.")


def dispatch(h, a):
    cmd = a.command
    if cmd == "prepare":
        h.prepare()
    elif cmd == "init":
        h.init(a.ssh_port)
    elif cmd == "plan":
        h.plan()
    elif cmd == "apply":
        h.apply(a.replace_ufw)
    elif cmd == "verify-login":
        h.verify_login()
    elif cmd == "confirm":
        h.tx.confirm(a.id)
    elif cmd == "rollback":
        h.tx.rollback()
    elif cmd == "status":
        h.status()
    elif cmd == "health":
        health_command(h, a)
    elif cmd == "user":
        user_command(h, a)
    elif cmd == "ssh" and a.action == "diagnose":
        from .ssh_access import SSHLoginInspector
        SSHLoginInspector(h.r).describe()
    elif cmd in {"ssh", "firewall", "web"}:
        stage(h, a)
    elif cmd == "firewall-load":
        h.firewall_load()
    elif cmd == "v2ray-egress-load":
        V2RayManager(h).egress_load()
    elif cmd == "mongodb":
        mongo = MongoDBManager(h)
        if a.action == "install":
            mongo.install(a.port)
        elif a.action == "bootstrap":
            mongo.bootstrap(a.admin, a.authenticate)
        elif a.action == "status":
            mongo.status()
        elif a.action == "shell":
            mongo.shell(mongo.state(), admin=a.admin)
        else:
            operation = {"user-add": "add", "user-revoke": "revoke", "password": "password"}[a.action]
            mongo.user(operation, a.name, a.database, getattr(a, "role", "readWrite"), a.admin)
    elif cmd == "service":
        ManagedServices(h).control(a.name, a.action)
    elif cmd == "uninstall":
        manager = UninstallManager(h)
        plan = manager.plan(a.purge)
        manager.describe(plan)
        if a.dry_run:
            return
        if not a.yes:
            raise GuardError("Review with uninstall --dry-run, then use uninstall --yes or the interactive menu.")
        manager.remove(a.purge, a.expected)
    elif cmd == "audit":
        h.r.run("lynis", "audit", "system", "--quick", capture=False)
    elif cmd == "update":
        h.tx.require_clear()
        h.r.run("apt-get", "update", capture=False)
        h.r.run("apt-get", "upgrade", capture=False)
        print("Review reboot requirements using status. Update the panel and V2Ray separately.")
    elif cmd == "defense":
        manager = DefenseManager(h)
        if a.action == "enable":
            manager.enable(manager.proposed(a.trusted, a.nginx_log, a.minutes, a.direct_web_clients), a.yes)
        elif a.action in {"disable", "baseline"}:
            getattr(manager, a.action)(a.yes)
        elif a.action == "scan":
            manager.scan(a.scheduled)
        elif a.action == "unban":
            manager.unban(a.jail, a.address, a.yes)
        elif a.action == "history":
            manager.history()
        else:
            manager.status()
    elif cmd == "self-update":
        UpdateManager(h).run(check=a.check, repository=a.repo, ref=a.ref, expected=a.sha256,
                             allow_downgrade=a.allow_downgrade)
    elif cmd == "panel":
        panel = PanelManager(h)
        if a.action == "info":
            panel.info()
        elif a.action == "download":
            panel.download(a.provider)
        else:
            panel.install(a.provider, a.sha256, a.db_engine, a.official_checksum)
    elif cmd == "v2ray":
        v = V2RayManager(h)
        if a.action == "install":
            v.install(a.version, a.sha256)
        elif a.action == "configure":
            v.configure(a.domain, a.local_port)
        elif a.action in {"add", "revoke"}:
            v.client(a.action, a.name)
        elif a.action == "list":
            print("\n".join(h.store.load()["v2ray"]["clients"]))
        elif a.action == "export":
            print(V2RayBuilder.link(h.store.load(), a.name))
        else:
            state = h.store.load()
            if not state["v2ray"]["domain"]:
                raise GuardError("Configure V2Ray first.")
            print(V2RayBuilder.nginx(state))


def health_command(h, a):
    store = ReportStore(h.f)
    if a.action == "check":
        report = HealthChecker(h).check(lambda i, n, label: print(f"[{i}/{n}] {label}", file=sys.stderr, flush=True))
        if not a.no_record:
            store.save(report)
        print(json.dumps(report, indent=2)) if a.json else HealthView.show(report)
    elif a.action == "watch":
        if not 2 <= a.interval <= 3600 or not 0 <= a.count <= 10000:
            raise GuardError("Watch interval must be 2..3600 seconds; count 0..10000 (0 = until Ctrl+C).")
        print("Live health: Ctrl+C returns to the menu. First frame includes security; later frames show current resources. Reports are retained locally.")
        frame = 0
        try:
            while a.count == 0 or frame < a.count:
                started = time.monotonic()
                report = HealthChecker(h).check(security=frame == 0)
                store.save(report)
                HealthView.show(report)
                frame += 1
                if a.count and frame >= a.count:
                    break
                time.sleep(max(0, a.interval - (time.monotonic() - started)))
        except KeyboardInterrupt:
            print("Live monitoring stopped. Saved results retained.")
    elif a.action == "show":
        report = store.latest()
        print(json.dumps(report, indent=2)) if a.json else HealthView.show(report)
    elif a.action == "history":
        if not 1 <= a.limit <= 200:
            raise GuardError("History limit must be 1..200.")
        reports = store.history(a.limit)
        if not reports:
            raise GuardError("No health history yet. Run health check.")
        print("UTC time | result | CPU% | RAM% | highest disk% | WARN/CRITICAL/UNKNOWN | scope")
        for report in reports:
            r = report["metrics"].get("resources", {})
            disks = [d["percent"] for d in report["metrics"].get("disks", []) if "percent" in d]
            counts = report["counts"]
            print(f"{utc(report['time'])} | {report['status']} | {r.get('cpu_percent', '?')} | {r.get('memory_percent', '?')} | {max(disks) if disks else '?'} | {counts.get('WARN', 0)}/{counts.get('CRITICAL', 0)}/{counts.get('UNKNOWN', 0)} | {report['scope']}")
    elif a.action == "files":
        storage = StorageManager(h)
        print(f"Scanning {a.path}: one filesystem, up to {a.max_entries} entries/{a.max_seconds} seconds; no files will be deleted.", flush=True)
        report = storage.scan(a.path, a.min_mib, a.limit, lambda n, seconds: print(f"[scan] {n} entries checked, {seconds:.1f}s elapsed", flush=True),
                              max_entries=a.max_entries, max_seconds=a.max_seconds)
        storage.show(report)
    elif a.action == "delete":
        StorageManager(h).delete(a.scan_id, a.item, a.yes)
    elif a.action == "cleanup":
        MaintenanceActions(h).cleanup(a.target, a.days, a.yes)
    elif a.action == "cpu-weight":
        MaintenanceActions(h).cpu_weight(a.service, a.weight, a.reset, a.yes)
    elif a.action == "monitor":
        monitor = HealthMonitor(h)
        if a.mode == "status":
            monitor.status()
        elif not a.yes:
            print(f"Preview: {a.mode} scheduled local health reports; interval {a.minutes} minutes. Use --yes to change the scheduler. No automatic cleanup or external alerts.")
        elif a.mode == "enable":
            monitor.enable(a.minutes, {key: getattr(a, key) for key in DEFAULT_THRESHOLDS})
        else:
            monitor.disable()


def execute_locked(h, args):
    """Command adapter shared by CLI and terminal UI; lock only submitted work."""
    parsed = parser().parse_args(args) if isinstance(args, list) else args
    if parsed.command == "self-update" or parsed.command == "defense" and parsed.action in {"scan", "status", "history"}:
        # Network inspection is unlocked; the installer locks/rechecks only publication.
        dispatch(h, parsed)
        return
    if parsed.command == "health" and (parsed.action in {"check", "watch", "show", "history", "files"} or not getattr(parsed, "yes", False)):
        # Probes, filesystem scans and live-view sleeps must not stall rollback.
        dispatch(h, parsed)
        return
    with h.f.path("/run/server-guard/management.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        dispatch(h, parsed)


def menu(h, setup=False):
    from .tui import TerminalApp
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise GuardError("The terminal UI needs an interactive terminal. Run sudo --preserve-env=SSH_CONNECTION server-guard setup in SSH, or use CLI commands.")
    ui = TerminalApp(h, lambda args: execute_locked(h, args))
    try:
        if setup:
            ui.setup()
        ui.run()
        if ui.restart_requested:
            os.execv("/usr/local/sbin/server-guard", ["server-guard", "menu"])
    except EOFError:
        return


def interactive_uninstall(h, a):
    """Review without holding the management lock, then revalidate under it."""
    manager = UninstallManager(h)
    plan = manager.plan(a.purge)
    manager.describe(plan)
    if input("Type UNINSTALL to remove the manager (Enter cancels): ").strip() != "UNINSTALL":
        print("Uninstall cancelled. Nothing removed.")
        return
    a.yes, a.expected = True, plan["fingerprint"]
    execute_locked(h, a)


def main():
    os.umask(0o077)
    p = parser()
    try:
        a = p.parse_args()
        if not a.command:
            if not sys.stdin.isatty():
                p.print_help()
                return 0
            a.command = "menu"
        h = Host(Files(), Runner())
        h.preflight()
        lockdir = Path("/run/server-guard")
        lockdir.mkdir(mode=0o700, exist_ok=True)
        # Never hold this lock across an interactive menu: rollback must remain runnable.
        if a.command in {"firewall-load", "v2ray-egress-load"}:
            # These systemd helpers are invoked synchronously by locked commands.
            # They replace only an owned table in a single nft transaction.
            dispatch(h, a)
        elif a.command == "uninstall" and not a.yes and not a.dry_run:
            if not sys.stdin.isatty():
                raise GuardError("Use uninstall --dry-run to review or uninstall --yes for a noninteractive removal.")
            interactive_uninstall(h, a)
        elif a.command in {"menu", "setup"}:
            menu(h, setup=a.command == "setup")
        else:
            execute_locked(h, a)
        return 0
    except (GuardError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted. A pending access change will roll back unless confirmed.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
