# Automatic attack protection

Server Guard 1.6.0 adds an optional automatic defense profile for an already configured Ubuntu 24.04 server. It combines native attack blocking with security-file/firewall drift detection. It cannot guarantee protection from every attack, establish that an existing machine is clean, or replace application security and upstream DDoS filtering.

## Enable on an existing server

Update the manager using the README's `self-update` or legacy bootstrap instructions. Updating management code preserves your settings and **does not enable this profile automatically**. Complete and confirm Guided setup first; the profile refuses an unapplied firewall baseline, a pending access change, or staged SSH settings that differ from the effective configuration.

From your normal administrator SSH connection:

```bash
# Read the plan; no settings change without --yes.
sudo --preserve-env=SSH_CONNECTION server-guard defense enable

# Install the reviewed profile and create its first trusted baseline.
sudo --preserve-env=SSH_CONNECTION server-guard defense enable --yes
```

Keep that connection open. Enabling changes ban policy, so it arms the same **10-minute rollback** used for access changes. Open a **new administrator SSH connection using your key**, then run the printed command with its actual ID:

```bash
sudo --preserve-env=SSH_CONNECTION server-guard confirm CHANGE_ID
```

If the new login/confirmation does not work, the configuration and selected service states roll back. Run `sudo server-guard rollback` from the original session/provider console to recover sooner. Caught installation/validation errors also trigger rollback. Package installation, application/database data and Linux users/keys are not reset. Native Fail2Ban dynamic ban history is not part of the access snapshot: transient bans and accumulated history can remain after a configuration rollback.

After confirmation, protection runs through Fail2Ban, Ubuntu timers and the security-check timer, including after reboot. The first scan is scheduled relative to five minutes after boot; on an already running VPS it may run immediately when enabled. The trusted baseline is created before timer activation. Subsequent runs default to fifteen minutes after completion plus up to sixty seconds of randomized delay. Run an immediate check with `defense scan`.

## Automatic blocking

- **SSH:** five recorded authentication failures within ten minutes trigger a one-hour ban. Repeated bans increase in duration, capped at one day, using Fail2Ban's persistent ban database. The managed database-retention setting is at least seven days and preserves a longer running retention value. SSH uses the applied port, not a hard-coded port 22. Later `plan/apply` changes rebuild the same jail through a shared builder.
- **Trusted journal inputs:** the managed SSH jail accepts root-origin journal messages from `sshd`/`sshd-session`. `_UID` is journal metadata rather than a user-supplied syslog tag. This narrows opportunities for an unprivileged local account to forge authentication messages that trigger bans. Check real authentication logging on the target Ubuntu package before relying on it.
- **Administration exemptions:** loopback and the current SSH client's address, when `SSH_CONNECTION` is preserved, are exempt from these managed bans. You can add stable administration IPs/CIDRs with `--trusted`. Exemptions do not open firewall ports or bypass SSH key authentication. Shared NAT/trusted networks also exempt their other users from these particular bans; keep the list narrow. All-address exemptions are rejected.
- **Optional Nginx:** packaged `nginx-http-auth` and `nginx-botsearch` filters can ban repeated HTTP Basic authentication failures and selected bot-search patterns. These jails affect TCP 80/443. They do not ban every 404, inspect all HTTP traffic, or recognize an application's own login failures automatically.
- **Security patches:** Ubuntu's automatic update timers are enabled and automatic reboot is disabled. The tool retains packaged origin policy; this does not establish coverage of panel repositories, standalone V2Ray binaries or every application dependency. Security updates can restart affected services according to package behavior.

The tool validates native Fail2Ban configuration before restarting it, then checks the expected running jails, basic retry/time settings, nftables action names and required ban exemptions. It also requires a persistent native ban database and verifies effective APT periodic/update/no-reboot settings. A detected conflicting override stops the change and rolls back. These checks are not proof that a future packet was dropped; verify actual bans externally on a disposable VM.

Example with an additional stable administration address and a 30-minute check interval:

```bash
sudo --preserve-env=SSH_CONNECTION server-guard defense enable \
  --trusted YOUR_STABLE_ADMIN_IP --minutes 30 --yes
```

Changing an already enabled profile refuses pre-existing drift. Review it and explicitly approve explained changes before changing the profile. Enabling on a trusted server, or re-enabling a disabled profile, establishes a fresh baseline from the current system; this is an operator trust decision, not a malware-cleanliness test.

## Optional web bans

Use only with **directly connected clients**, without a CDN, load balancer or upstream reverse proxy. Firewall blocking at an origin cannot enforce a ban against an end-user address carried only in a proxy header, and banning shared proxy addresses can deny many legitimate users. Proxy/CDN deployments need protection at the proxy/application layer with properly trusted client-address handling.

Choose the exact Nginx **error log** for your deployment. Examples are `/var/log/nginx/error.log` or a panel's `/www/wwwlogs/nginx_error.log`; verify the real file rather than assuming either path exists. An empty new log is allowed, so you must subsequently test that actual events use the supported format.

```bash
sudo --preserve-env=SSH_CONNECTION server-guard defense enable \
  --nginx-log /var/log/nginx/error.log --direct-web-clients --yes
```

Repeat `--nginx-log` for up to eight exact files. The tool rejects globs/interpolation, symlinks and logs that are not root-owned regular files or are group/world writable. Rotation must retain trusted ownership/permissions; later checks warn when it does not. Do not change a panel's ownership merely to bypass this check. Configure a trusted logging arrangement or leave these optional jails disabled. The tool does not edit/reload your Nginx or panel configuration.

Application WAF rules, SQL injection/XSS defenses, login-specific rate limits, CSRF/session controls and API authorization require application/proxy integration. This profile does not silently install an incompatible Nginx module or third-party root agent into aaPanel/CloudPanel.

## Scheduled intrusion and defense checks

```bash
sudo server-guard defense scan
sudo server-guard defense status
sudo server-guard defense history
sudo journalctl -u server-guard-defense.service --since today
```

Checks include:

- SHA-256, type/presence, owner/group and permission comparisons for selected SSH/PAM/sudo/account/cron/APT/manager configuration, managed user keys and selected MongoDB/V2Ray configuration. Immediate entries in curated security directories are inventoried; this is not a recursive scan of every executable, site or database.
- A normalized fingerprint of the running `inet server_guard` firewall table, excluding counters, handles and metadata. Unexpected rule changes and loss of default-drop input/forward chains are reported. Other firewall tables, provider rules and external reachability are outside this fingerprint.
- Active/enabled state of expected firewall, Fail2Ban, audit and update/check timers; expected ban-jail availability; opted-in log trust; and AppArmor availability. AppArmor availability does not prove your custom panel/applications have enforced profiles.
- Pending access changes, incomplete coverage and missing/corrupt trusted baselines. Unknown evidence is reported as `UNKNOWN`, never as a clean result. The existing `health check` also includes the configured profile's timer and latest/stale report.

The scanner refuses symlink traversal and FIFOs, caps files at 2 MiB each, directories at 128 immediate entries, inventory at 500 paths and total hashed bytes/time at 20 MiB/20 seconds. It uses a separate nonblocking scan lock, so waiting at a menu or running a scan does not hold up access rollback. Its systemd unit limits CPU, memory and runtime, restricts socket families and uses a read-only filesystem except its private report directory. These sandbox/resource controls still require actual Ubuntu service validation.

Only hashes/metadata and findings are stored, not security-file contents or database records. The trusted baseline is `/var/lib/server-guard/defense-baseline.json`; the profile is `/etc/server-guard/defense.json`. Latest and up to **200** private historical reports are under `/var/lib/server-guard/defense/`. Scheduled output is also in the local system journal. No email, webhook, external telemetry or notification recipient is configured. To receive alerts away from the server, connect your own external monitoring/log delivery; stopping the host or its scheduler can stop local reporting.

## Review changes and recover from false bans

Legitimate package/panel/account/key/firewall/manager changes may alter monitored files. Review the reported paths, actual diffs, package/change history and running rules before accepting a new baseline. Confirm or roll back any pending access change first:

```bash
sudo server-guard defense baseline         # review reminder only
sudo server-guard defense baseline --yes   # explicitly trust the reviewed current state
```

Scanning never accepts a changed file automatically, overwrites unexpected settings, deletes suspected files or kills processes. A root compromise can alter both files and their local baseline or stop checks; use off-server logs/backups and a separate recovery process.

For a false ban, from an existing session or the provider console:

```bash
sudo server-guard defense unban sshd CLIENT_IP             # preview
sudo server-guard defense unban sshd CLIENT_IP --yes       # recover access
```

The other managed jail names are `server-guard-nginx-auth` and `server-guard-nginx-bots`. Unbanning is available during a pending access change for recovery. It does not add a permanent exemption or clear every jail/history entry; new failures can cause a new ban.

To disable the extra profile while retaining basic key-only SSH, the closed firewall, basic SSH Fail2Ban and automatic security updates:

```bash
sudo server-guard defense disable --yes
```

Reconnect and confirm this change too. Native Fail2Ban database/history and selected configuration remain; no app/database files are removed. Uninstalling the **manager** stops/removes the security-check timer/service before removing its code/history, while keeping native Fail2Ban and Ubuntu protection configured.

## Sources and verification boundaries

Reviewed **13 November 2026**. Settings use upstream and Ubuntu interfaces rather than downloaded blocklists or arbitrary root agents:

- [Ubuntu 24.04 Fail2Ban configuration](https://manpages.ubuntu.com/manpages/noble/man5/jail.conf.5.html) and [client commands](https://manpages.ubuntu.com/manpages/noble/man1/fail2ban-client.1.html) describe local overrides, jails, ban configuration and recovery commands. [Upstream jail settings](https://github.com/fail2ban/fail2ban/blob/1.0.2/config/jail.conf) document increasing/capped bans and trusted addresses.
- [Trusted journal metadata](https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html) distinguishes journal-added `_UID`/`_COMM` from user-supplied syslog fields.
- [Nginx authentication filter](https://github.com/fail2ban/fail2ban/blob/1.0.2/config/filter.d/nginx-http-auth.conf) and [bot-search filter](https://github.com/fail2ban/fail2ban/blob/1.0.2/config/filter.d/nginx-botsearch.conf) define the deliberately limited web-log patterns. They are not general-purpose WAFs.
- [Ubuntu automatic updates](https://ubuntu.com/server/docs/how-to/software/automatic-updates/) and [security features](https://documentation.ubuntu.com/security/security-features/) explain packaged updates and layered platform controls.
- [CrowdSec firewall remediation](https://docs.crowdsec.net/u/bouncers/firewall/) distinguishes network blocking from application-layer protection. It was researched but is not installed by this profile; adding a second enforcement agent needs a reviewed deployment/proxy plan.
- [systemd execution controls](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) describe service sandbox options. No claim of production validation follows from generating a unit file.

Local tests use isolated files and native-command adapters. Upstream Fail2Ban 1.0.2 configuration/filter parsing was also exercised without starting a daemon or changing host firewall rules. Live journal acquisition, increasing bans, IPv4/IPv6 blocking, SSH reconnect/rollback, update timers, scanner sandboxing and reboot behavior remain on the [Ubuntu validation checklist](VALIDATION.md).
