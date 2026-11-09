"""Host adapters, validated policy and pure configuration builders."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


class GuardError(Exception):
    pass


def username(value):
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", value) or value == "root":
        raise GuardError("Use a non-root Linux username (lowercase letters, digits, _ or -).")
    return value


def port(value):
    try:
        n = int(value)
    except (ValueError, TypeError):
        raise GuardError("Port must be an integer.") from None
    if not 1 <= n <= 65535:
        raise GuardError("Port must be 1..65535.")
    return n


def network(value):
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise GuardError("Source must be an IPv4/IPv6 address or CIDR, or 'any'.") from None


def domain(value):
    if len(value) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", value
    ):
        raise GuardError("Use a DNS hostname, without scheme, port or path.")
    return value.lower()


def public_key(value):
    # Deliberately no authorized_keys options, command=, multiline or private keys.
    fields = value.strip().split()
    if len(fields) < 2 or fields[0] not in {
        "ssh-ed25519", "sk-ssh-ed25519@openssh.com", "ecdsa-sha2-nistp256",
        "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-rsa"
    } or "\n" in value.strip() or "\r" in value:
        raise GuardError("Supply one OpenSSH public key, without key options.")
    try:
        blob = base64.b64decode(fields[1], validate=True)
        size = int.from_bytes(blob[:4], "big")
        if not 0 < size < len(blob) or blob[4:4 + size].decode() != fields[0]:
            raise ValueError()
    except (ValueError, UnicodeError):
        raise GuardError("Malformed OpenSSH public key.") from None
    return f"{fields[0]} {fields[1]} server-guard\n"


def defaults(ssh_port=22):
    return {"schema": 1, "ssh": {"port": port(ssh_port), "sources": ["any"],
            "root_login": False}, "users": {}, "ports": [],
            "v2ray": {"domain": None, "port": 10000, "path": None, "clients": {}}}


def validate(state):
    if state.get("schema") != 1:
        raise GuardError("Unsupported policy schema.")
    port(state["ssh"]["port"])
    if type(state["ssh"]["root_login"]) is not bool:
        raise GuardError("root_login must be true or false.")
    if not state["ssh"]["sources"]:
        raise GuardError("At least one SSH source is required.")
    for src in state["ssh"]["sources"]:
        if src != "any":
            network(src)
    for name, user in state["users"].items():
        username(name)
        if user["role"] not in {"admin", "developer", "sftp"}:
            raise GuardError("Unknown role.")
        if type(user["sessions"]) is not int or not 1 <= user["sessions"] <= 100:
            raise GuardError("Session limit must be 1..100.")
        if user["role"] == "admin" and user["sessions"] < 2:
            raise GuardError("Administrators need at least two sessions for a fresh-login rollback confirmation.")
    for rule in state["ports"]:
        port(rule["port"])
        if rule["protocol"] not in {"tcp", "udp"}:
            raise GuardError("Protocol must be tcp or udp.")
        if rule["source"] != "any":
            network(rule["source"])
    v = state["v2ray"]
    port(v["port"])
    if v["port"] == state["ssh"]["port"]:
        raise GuardError("V2Ray backend and SSH ports must differ.")
    if v["domain"]:
        domain(v["domain"])
        if not re.fullmatch(r"/[a-zA-Z0-9_-]{8,100}", v["path"] or ""):
            raise GuardError("Invalid WebSocket path.")
    return state


class Runner:
    """Adapter: no shell evaluation and a fixed, root-owned executable search path."""
    def run(self, *args, check=True, input=None, capture=True, timeout=None):
        env = dict(os.environ, PATH="/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL="C")
        result = subprocess.run([str(x) for x in args], input=input, text=True,
                                capture_output=capture, env=env, check=False, timeout=timeout)
        if check and result.returncode:
            raise GuardError(f"Command failed: {args[0]} {args[1] if len(args) > 1 else ''}\n"
                             f"{(result.stderr or '')[-3000:]}")
        return result


class Files:
    def __init__(self, root=Path("/")):
        self.root = Path(root)

    def path(self, path):
        return self.root / str(path).lstrip("/")

    def write(self, path, content, mode=0o600):
        target = self.path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            raise GuardError(f"Refusing symbolic link: {target}")
        fd, tmp = tempfile.mkstemp(prefix=".guard-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content.encode() if isinstance(content, str) else content)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), mode)
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


def write_user_key(home, key, uid, gid, append=False):
    """Pin directory descriptors so a user cannot redirect a root write via symlinks."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    homefd = os.open(home, flags)
    sshfd = None
    temp_name = ".guard-key-" + __import__('secrets').token_hex(12)
    try:
        try:
            os.mkdir(".ssh", mode=0o700, dir_fd=homefd)
        except FileExistsError:
            pass
        sshfd = os.open(".ssh", flags, dir_fd=homefd)
        os.fchown(sshfd, uid, gid)
        os.fchmod(sshfd, 0o700)
        if append:
            try:
                oldfd = os.open("authorized_keys", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=sshfd)
            except FileNotFoundError:
                old = ""
            else:
                import stat
                with os.fdopen(oldfd, "r") as oldfile:
                    info = os.fstat(oldfile.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                        raise GuardError("Existing authorized_keys must be a small regular file.")
                    old = oldfile.read()
                # Append is intentionally limited to the plain public-key format
                # used by this manager, not custom command=/environment= policies.
                existing = [public_key(line) for line in old.splitlines()
                            if line.strip() and not line.lstrip().startswith("#")]
                if key in existing:
                    return
            key = old.rstrip() + ("\n" if old.strip() else "") + key
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=sshfd)
        with os.fdopen(fd, "w") as stream:
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchown(stream.fileno(), uid, gid)
        os.replace(temp_name, "authorized_keys", src_dir_fd=sshfd, dst_dir_fd=sshfd)
    finally:
        if sshfd is not None:
            try:
                os.unlink(temp_name, dir_fd=sshfd)
            except FileNotFoundError:
                pass
            os.close(sshfd)
        os.close(homefd)


POLICY = "/etc/server-guard/policy.json"


class PolicyStore:
    def __init__(self, files):
        self.files = files

    def load(self):
        try:
            return validate(json.loads(self.files.path(POLICY).read_text()))
        except FileNotFoundError:
            raise GuardError("Run 'server-guard init' first.") from None

    def save(self, state):
        self.files.write(POLICY, json.dumps(validate(state), indent=2) + "\n")


class FirewallBuilder:
    """Builder: owns one inet table; never flushes third-party firewall rules."""
    @staticmethod
    def build(state):
        validate(state)
        lines = ["table inet server_guard {", " chain input {",
                 "  type filter hook input priority -10; policy drop;",
                 "  iifname lo accept", "  ct state invalid drop",
                 "  ct state established,related accept",
                 "  meta l4proto { icmp, ipv6-icmp } accept",
                 "  udp sport 67 udp dport 68 accept",
                 "  ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept"]
        rules = [{"protocol": "tcp", "port": state["ssh"]["port"], "source": s}
                 for s in state["ssh"]["sources"]] + state["ports"]
        for r in rules:
            prefix = ""
            if r["source"] != "any":
                src = network(r["source"])
                family = "ip6" if ":" in src else "ip"
                prefix = f"{family} saddr {src} "
            lines.append(f"  {prefix}{r['protocol']} dport {port(r['port'])} counter accept")
        lines += ["  limit rate 3/second burst 10 packets log prefix \"guard-drop: \"",
                  "  counter drop", " }", " chain forward {",
                  "  type filter hook forward priority -10; policy drop;", " }", "}"]
        return "\n".join(lines) + "\n"

    @staticmethod
    def batch(rules, exists):
        return ("delete table inet server_guard\n" if exists else "") + rules


class SSHBuilder:
    @staticmethod
    def pam_config(original):
        """Reclaim a retained runtime on reinstall; never stack duplicate hooks."""
        hook = "session required pam_exec.so quiet /opt/server-guard/server_guard/pam_sessions.py"
        retained = "session required pam_exec.so quiet /usr/local/lib/server-guard-retained/pam_sessions.py"
        lines = [line for line in original.splitlines() if line.strip() not in {hook, retained}]
        return "\n".join(lines).rstrip() + "\n" + hook + "\n"

    @staticmethod
    def global_config(state):
        return f"""# Managed by server-guard. Use its CLI to change this file.
Port {state['ssh']['port']}
PermitRootLogin {'prohibit-password' if state['ssh']['root_login'] else 'no'}
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AuthenticationMethods publickey
UsePAM yes
MaxAuthTries 3
LoginGraceTime 30
MaxStartups 10:30:60
MaxSessions 1
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
"""

    @staticmethod
    def user_config(state):
        lines = ["# Managed by server-guard."]
        for name, user in sorted(state["users"].items()):
            lines += [f"Match User {username(name)}", "    MaxSessions 1"]
            if user["role"] == "admin":
                # Match directives override global values, but remain least privilege.
                lines += ["    AllowTcpForwarding local"]
            elif user["role"] == "sftp":
                lines += [f"    ChrootDirectory /srv/sftp/{name}",
                          "    ForceCommand internal-sftp -d /upload",
                          "    DisableForwarding yes", "    PermitTTY no"]
        lines += ["Match all"]
        return "\n".join(lines) + "\n"

    @staticmethod
    def main_config(original):
        first = "Include /etc/ssh/server-guard.conf"
        last = "Include /etc/ssh/server-guard-users.conf"
        body = "\n".join(line for line in original.splitlines()
                         if line.strip() not in {first, last}
                         and not re.match(r"^\s*Port\s+", line, re.IGNORECASE))
        return first + "\n" + body.rstrip() + "\n" + last + "\n"


class V2RayBuilder:
    @staticmethod
    def config(state):
        v = state["v2ray"]
        return {"log": {"loglevel": "warning"}, "inbounds": [{
            "tag": "vmess-ws", "listen": "127.0.0.1", "port": v["port"],
            "protocol": "vmess", "settings": {"clients": [
                {"id": uid, "alterId": 0, "email": name + "@guard.invalid"}
                for name, uid in sorted(v["clients"].items())]},
            "streamSettings": {"network": "ws", "wsSettings": {"path": v["path"]}}}],
            "outbounds": [{"protocol": "freedom", "tag": "internet"},
                          {"protocol": "blackhole", "tag": "blocked"}],
            "routing": {"domainStrategy": "IPOnDemand", "rules": [
                {"type": "field", "ip": ["geoip:private", "169.254.169.254/32",
                 "100.64.0.0/10", "0.0.0.0/8", "::/128", "ff00::/8", "224.0.0.0/4"],
                 "outboundTag": "blocked"},
                {"type": "field", "port": "25,465,587", "outboundTag": "blocked"}]}}

    @staticmethod
    def nginx(state):
        v = state["v2ray"]
        return f"""# Add INSIDE the aaPanel Nginx HTTPS server for {v['domain']}.
# Keep the site's TLS certificate, TLS 1.2/1.3 and renewal settings enabled.
location = {v['path']} {{
    proxy_pass http://127.0.0.1:{v['port']};
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 300s;
    proxy_send_timeout 300s;
    proxy_buffering off;
}}
"""

    @staticmethod
    def link(state, name):
        v = state["v2ray"]
        if name not in v["clients"]:
            raise GuardError("Unknown V2Ray client.")
        obj = {"v": "2", "ps": name, "add": v["domain"], "port": "443",
               "id": v["clients"][name], "aid": "0", "scy": "auto", "net": "ws",
               "type": "none", "host": v["domain"], "path": v["path"],
               "tls": "tls", "sni": v["domain"]}
        return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
