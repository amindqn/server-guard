"""Validated policy and native service builders for automatic defenses."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import ipaddress
import json
import re

from .core import GuardError, port

CONFIG = "/etc/server-guard/defense.json"
BASELINE = "/var/lib/server-guard/defense-baseline.json"
RESULTS = "/var/lib/server-guard/defense"
UNIT = "/etc/systemd/system/server-guard-defense.service"
TIMER = "/etc/systemd/system/server-guard-defense.timer"
JAIL = "/etc/fail2ban/jail.d/90-server-guard.local"
DATABASE = "/etc/fail2ban/fail2ban.d/90-server-guard.local"
JAILS = ("sshd", "server-guard-nginx-auth", "server-guard-nginx-bots")
AUTOMATIC_UPDATES = '''APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "false";
'''


def trusted_network(value):
    try:
        address = ipaddress.ip_network(value, strict=False)
        if not address.prefixlen or address.is_multicast or address.is_unspecified:
            raise ValueError()
        return str(address)
    except ValueError:
        raise GuardError("Use a specific trusted IP/CIDR, never 'any' or an all-address network.") from None


def client_address(value):
    try:
        address = ipaddress.ip_address(value)
        return str(address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address)
    except ValueError:
        raise GuardError("Use a single IPv4/IPv6 address.") from None


def nginx_log(value):
    if (not isinstance(value, str) or not re.fullmatch(r"/(?:var/log|www/wwwlogs|home)/[A-Za-z0-9_./-]+", value)
            or ".." in value.split("/") or not value.endswith(".log")):
        raise GuardError("Use an exact .log path under /var/log, /www/wwwlogs or /home; no glob/space/interpolation.")
    return value


@dataclass
class DefensePolicy:
    enabled: bool = False
    trusted: list[str] = field(default_factory=list)
    nginx_logs: list[str] = field(default_factory=list)
    minutes: int = 15
    schema: int = 1

    def __post_init__(self):
        if self.schema != 1 or type(self.enabled) is not bool or type(self.minutes) is not int or not 5 <= self.minutes <= 1440:
            raise GuardError("Invalid defense policy; interval must be 5..1440 minutes.")
        if not isinstance(self.trusted, list) or len(self.trusted) > 32 or not isinstance(self.nginx_logs, list) or len(self.nginx_logs) > 8:
            raise GuardError("At most 32 trusted networks and 8 Nginx logs are supported.")
        self.trusted = sorted(set(trusted_network(value) for value in self.trusted))
        self.nginx_logs = sorted(set(nginx_log(value) for value in self.nginx_logs))

    @classmethod
    def load(cls, files):
        path = files.path(CONFIG)
        if path.is_symlink():
            raise GuardError("Refusing linked defense policy.")
        if not path.exists():
            return cls()
        try:
            return cls(**json.loads(path.read_text()))
        except (TypeError, ValueError):
            raise GuardError("Invalid saved defense policy.") from None

    def serialize(self):
        return json.dumps(asdict(self), indent=2) + "\n"


def fail2ban_config(ssh_port, policy=None):
    policy = policy or DefensePolicy()
    common = "banaction = nftables-multiport\nusedns = no\nignoreself = true\nignoreip = 127.0.0.1/8 ::1"
    if policy.enabled:
        common += " " + " ".join(policy.trusted)
        common += "\nbantime.increment = true\nbantime.maxtime = 1d\nbantime.overalljails = false"
    config = (f"# Managed by Server Guard.\n[sshd]\nenabled = true\nbackend = systemd\n"
              "journalmatch = _UID=0 _COMM=sshd + _UID=0 _COMM=sshd-session\n"
              f"port = {port(ssh_port)}\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n{common}\n")
    for name, filter_name in zip(JAILS[1:], ["nginx-http-auth", "nginx-botsearch"]):
        active = policy.enabled and bool(policy.nginx_logs)
        config += f"\n[{name}]\nenabled = {'true' if active else 'false'}\n"
        if active:
            config += (f"filter = {filter_name}\nbackend = polling\nport = 80,443\nmaxretry = 5\n"
                       f"findtime = 10m\nbantime = 1h\n{common}\nlogpath = " + "\n          ".join(policy.nginx_logs) + "\n")
    return config


SERVICE = f"""[Unit]
Description=Server Guard security drift and defense checks
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/server-guard defense scan --scheduled
TimeoutStartSec=90
Nice=19
IOSchedulingClass=idle
CPUQuota=20%
MemoryMax=192M
TasksMax=32
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths={RESULTS}
RestrictAddressFamilies=AF_UNIX AF_NETLINK
UMask=0077
"""


def timer(minutes):
    return f"""[Unit]
Description=Server Guard periodic security checks
[Timer]
OnBootSec=5min
OnUnitInactiveSec={minutes}min
RandomizedDelaySec=60s
AccuracySec=30s
[Install]
WantedBy=timers.target
"""
