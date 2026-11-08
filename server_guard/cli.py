"""Commands stage policy explicitly; apply validates it and arms rollback."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import sys

from . import __version__
from .core import Files, GuardError, Runner, V2RayBuilder, network, port, public_key, username, write_user_key
from .host import Host
from .services import DB_ENGINES, ManagedServices, PanelManager, V2RayManager
from .mongodb import MongoDBManager, app_database, mongo_name
from .uninstall import UninstallManager


def parser():
    p = argparse.ArgumentParser(description="Ubuntu 24.04 server management with guarded access changes.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command")
    for name in ["prepare", "plan", "apply", "status", "audit", "update", "rollback", "verify-login", "menu", "setup"]:
        c = sub.add_parser(name)
        if name == "apply":
            c.add_argument("--replace-ufw", action="store_true", help="replace active UFW with the reviewed policy")
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


def execute_locked(h, args):
    """Command adapter shared by CLI and terminal UI; lock only submitted work."""
    parsed = parser().parse_args(args) if isinstance(args, list) else args
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
    except (GuardError, OSError, ValueError, KeyError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted. A pending access change will roll back unless confirmed.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
