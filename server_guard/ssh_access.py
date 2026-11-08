"""Read-only authentication evidence and client instructions for a fresh SSH login."""
from __future__ import annotations

import ipaddress
import json
import os
import re

from .core import GuardError, port, username


def normalized_ip(value):
    result = ipaddress.ip_address(value)
    return result.ipv4_mapped if isinstance(result, ipaddress.IPv6Address) and result.ipv4_mapped else result


class SSHLoginInspector:
    DAEMONS = {"sshd", "sshd-session", "sshd-auth"}
    ACCEPTED = re.compile(r"^Accepted (?P<method>[a-zA-Z0-9@._/-]+) for (?P<user>\S+) "
                          r"from (?P<peer>\S+) port (?P<port>\d+)\b")

    def __init__(self, runner):
        self.r = runner

    def inspect(self):
        user = os.environ.get("SUDO_USER", "")
        conn = os.environ.get("SSH_CONNECTION", "").split()
        result = {"user": user or "root/direct shell", "connection": conn, "method": None, "time": None}
        if not user or user == "root" or len(conn) != 4:
            result["reason"] = "Run sudo --preserve-env=SSH_CONNECTION from a new non-root administrator SSH login."
            return result
        try:
            username(user)
            peer, local = normalized_ip(conn[0]), normalized_ip(conn[2])
            peer_port, local_port = port(conn[1]), port(conn[3])
        except (ValueError, GuardError):
            result["reason"] = "SSH_CONNECTION is invalid. Reconnect directly over SSH and preserve it through sudo."
            return result
        # Trusted journal fields work across unit aliases/socket activation and
        # cannot be supplied by an unprivileged logger -t sshd command.
        journal = self.r.run("journalctl", "--boot", "--since", "-1 hour", "-o", "json", "--no-pager",
                             "_UID=0", "_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth", check=False)
        if journal.returncode:
            result["reason"] = "SSH journal could not be read. Check journald and reconnect after fixing logging."
            return result
        for line in reversed(journal.stdout.splitlines()):
            try:
                row = json.loads(line)
                if str(row.get("_UID")) != "0" or row.get("_COMM") not in self.DAEMONS:
                    continue
                match = self.ACCEPTED.match(row.get("MESSAGE", ""))
                if not match or match["user"] != user:
                    continue
                if normalized_ip(match["peer"]) != peer or int(match["port"]) != peer_port:
                    continue
                timestamp = int(row["__REALTIME_TIMESTAMP"]) / 1_000_000
                if timestamp <= 0:
                    continue
            except (ValueError, TypeError, KeyError, AttributeError):
                continue
            result.update(method=match["method"], time=timestamp)
            if result["method"] != "publickey":
                result["reason"] = (f"This connection authenticated with {result['method']}, not a public key. "
                                    "Reconnect from your computer with the matching private key; changing users with su/sudo does not create a key login.")
            return result
        result["reason"] = ("No matching SSH authentication record for this transport in the current boot/last hour. "
                            "Reconnect with a key and ControlPath=none, then try again. Run ssh diagnose for details.")
        return result

    def verified(self):
        result = self.inspect()
        if result["method"] != "publickey":
            raise GuardError(result["reason"])
        return {"user": result["user"], "connection": result["connection"], "time": result["time"]}

    def describe(self):
        result = self.inspect()
        print("Current sudo identity:", result["user"])
        print("SSH transport:", " ".join(result["connection"]) or "not available")
        print("Authentication:", result["method"] or "not verified")
        if result.get("reason"):
            print("Next step:", result["reason"])
        else:
            print("This transport has public-key evidence. Run verify-login to record it for setup.")


def client_command(user="admin", ssh_port=22, hostname="SERVER_IP", key="~/.ssh/server_guard_admin"):
    username(user)
    return ("ssh -o IdentitiesOnly=yes -o ControlPath=none "
            "-o PreferredAuthentications=publickey -o PasswordAuthentication=no "
            f"-o KbdInteractiveAuthentication=no -i {key} -p {port(ssh_port)} {user}@{hostname}")
