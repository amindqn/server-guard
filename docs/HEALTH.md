# Server health, monitoring and maintenance

Open `sudo server-guard` → **6 Server health, monitoring and maintenance**. All previous security-status, audit, package-update and SSH-help actions remain under **8 Security details, audits and updates** in that menu.

## Check now and monitor results

```bash
sudo server-guard health check
sudo server-guard health watch --interval 5
sudo server-guard health show
sudo server-guard health history --limit 20
```

Check shows numbered progress for 13 probe steps. Resource sampling takes about one second; each external security command has an eight-second timeout. Results distinguish PASS, WARN, CRITICAL, UNKNOWN and informational observations. A PASS describes a checked condition, not a claim that the server is safe from every attack. Missing tools, inaccessible counters and failed probes remain UNKNOWN rather than becoming zero or passing silently. Findings include a suggested next step.

Metrics include aggregate CPU busy time, load averages, I/O wait, VM CPU steal, available RAM, swap, resource pressure, mounted storage/inodes, read-only mounts, uptime, network receive/send rates and top processes by CPU and resident RAM. Process names/PIDs/UIDs are shown; command-line arguments, environment variables and file contents are not collected. CPU for a process uses **100% = one core**, so a multi-core process can exceed 100%. Aggregate CPU uses all reported cores. New/reused PIDs have no inferred CPU percentage. RSS can overlap shared pages across processes.

RAM uses Linux `MemAvailable`, which accounts for reclaimable memory; cached RAM is not treated as automatically wasted. CPU steal points to VM-host contention. I/O wait is approximate; CPU/RAM/I/O pressure helps distinguish sustained contention from a busy sample. Disk percentages use space available to normal users and include inode exhaustion. Separate data/boot mounts are inspected; unsupported/unreadable mounts are reported separately. These measurements follow the [Linux procfs documentation](https://docs.kernel.org/filesystems/proc.html) and [pressure-stall interface](https://docs.kernel.org/accounting/psi.html).

Security probes inspect global effective SSH root/password settings, the owned nftables input policy, Fail2Ban and its SSH jail, the security-update timer, auditd, AppArmor, time synchronization, non-loopback listeners, known private-service ports, reboot-required state, pending APT upgrades using cached metadata, failed systemd services and pending access changes. Global SSH settings do not evaluate every per-user Match override. Listener/firewall checks are not an external reachability scan, and cached APT counts do not establish patch freshness. Existing Lynis/status commands provide further inspection.

Live viewing performs a full security check in its first frame and resource-only refreshes afterward, with the scope printed in each frame. **Ctrl+C returns to the menu**. For a finite command, use `health watch --interval 5 --count 12`. No public monitoring port or additional web dashboard is installed. Progress, scans and live-view sleeps do not hold the access-management lock or block rollback.

Reports are private JSON files in `/var/lib/server-guard/health`, limited to the latest **200** samples. The timestamp and scope are always shown; `health show` displays a saved result, not a fresh probe. History shows CPU/RAM/disk values and warning/critical/unknown counts. Use `health check --json` for structured output; progress goes to stderr. `--no-record` skips saving that check. Report collection does not change access or application settings.

## Optional scheduled checks

```bash
sudo server-guard health monitor enable --minutes 5 --cpu 90 --memory 90 --disk 85 --inodes 85
# The command above previews. After review:
sudo server-guard health monitor enable --minutes 5 --cpu 90 --memory 90 --disk 85 --inodes 85 --yes
sudo server-guard health monitor status
sudo server-guard health monitor disable --yes
```

The terminal menu collects the interval and warning thresholds with a final confirmation. Intervals range from 1 to 1440 minutes; warning thresholds range from 50 to 99 percent. Defaults are CPU/RAM 90%, storage/inodes 85%; storage/inode usage at 95% or higher is critical. CPU, steal, I/O wait and pressure are samples/trends requiring diagnosis, not reasons for an automatic restart. Thresholds are saved in `/etc/server-guard/health.json` and also used by manual checks.

`server-guard-health.timer` runs a full check after boot and after each configured inactive interval, with normal timer scheduling tolerance. Jobs use lower scheduling priority and a timeout. They read the host mount namespace rather than a private/read-only remapping, which would distort storage observations. Results appear in local history and the service journal. This follows [Ubuntu 24.04 systemd timer behavior](https://manpages.ubuntu.com/manpages/noble/man5/systemd.timer.5.html). This is local monitoring: it does not send email/messages, remediate findings, or provide external availability checks while the server is down. No monitoring is enabled until you explicitly configure it. Uninstall stops/removes the health timer/service and backs up saved state.

## Find and remove a large file

```bash
sudo server-guard health files /var --min-mib 100 --limit 20
sudo server-guard health files /home --min-mib 500
sudo server-guard health files / --min-mib 100 --limit 50 --max-entries 1000000 --max-seconds 120
# Replace SCAN_ID and ITEM with the values printed by an inventory:
sudo server-guard health delete SCAN_ID ITEM
sudo server-guard health delete SCAN_ID ITEM --yes
```

Inventory is read-only. It stays on one filesystem, skips symlinks/pseudo-filesystems, and defaults to 100,000 entries or approximately 30 seconds with a partial-coverage notice. `--max-entries` and `--max-seconds` increase those budgets, up to 10,000,000 entries and 3600 seconds. The terminal offers Quick and Extended presets. Backup-named folders and likely backup roots are visited before large package/application trees; this improves bounded searches without claiming full coverage. Progress appears every 1000 entries, including small files that do not match the size filter.

Files are ranked by **allocated bytes**, with logical size alongside it, so sparse files are not assumed to occupy their full logical size. The limits are cooperative; a stalled underlying filesystem can still delay a read. Inventories show errors/skipped areas and sample skipped paths; absence from a partial inventory does not prove a file does not exist. If an empty scan hits a limit, scan likely locations such as `/var/backups`, `/www/backup`, `/root` or `/home` directly and consider lowering the size threshold. A directory may contain many smaller backups even when no individual file meets that threshold. Scan mounted data directories separately. Ten private inventories are retained; deletion requires an inventory less than one hour old.

Deletion is offered for reviewed regular files in `/home`, `/root`, `/srv`, `/tmp`, `/var/tmp`, `/var/backups`, `/www/backup` and `/var/log`. System/package directories, SSH/GPG directories, Server Guard recovery files, journals, known database directories and common database-file formats are inspect-only. This does not identify every possible application data format: review the exact path, purpose and backup yourself. Nothing is selected for deletion just because it is large.

The delete command previews one exact path and size; `--yes` is required to remove it. The terminal performs that preview before asking for final confirmation. Parent paths are walked without following symlinks; device/inode/size/timestamps/ownership/link count are rechecked. Open files and hard links are refused. Incomplete open-handle inspection is also refused. A private staging directory prevents a concurrent filename swap from causing deletion of an unexpected object; a mismatch leaves it for recovery at the printed path. File operations remain subject to concurrent application activity, so use the application's own retention/backup tools for live data.

Deletion is permanent and cannot be restored by SSH rollback. Space recovery may be delayed by new open handles, snapshots or filesystem behavior; **rerun `health check`** to verify the result. There is no recursive delete or truncate-active-log command.

## Clean known caches and logs

```bash
sudo server-guard health cleanup apt-cache
sudo server-guard health cleanup apt-cache --yes
sudo server-guard health cleanup journal --days 14
sudo server-guard health cleanup journal --days 14 --yes
```

The default command previews the action. APT cleanup removes downloaded package archives, leaving installed packages. Journal cleanup deletes archived journal files older than the selected retention (minimum seven days); active journals may keep additional space. It permanently removes historical diagnostic/security evidence. The behavior follows [Ubuntu's journalctl manual](https://manpages.ubuntu.com/manpages/noble/man1/journalctl.1.html). No database, application cache, `/tmp` tree, kernel package or security setting is automatically removed. Mutations refuse a pending SSH/firewall transaction.

## Relieve CPU contention

First compare several samples, top processes, CPU steal and pressure. A large load average can reflect I/O rather than CPU saturation. Low available RAM may require fewer application workers, a memory-leak fix or a larger server. This tool does not drop Linux caches, disable security controls, kill arbitrary processes or promise a universal CPU speedup.

For an application workload competing with others:

```bash
sudo server-guard health cpu-weight v2ray --weight 25
sudo server-guard health cpu-weight v2ray --weight 25 --yes
sudo server-guard health cpu-weight v2ray --reset --yes
```

Supported names are `v2ray`, `mongodb`, `nginx`, `mysql` and `mariadb`, when their units exist. SSH/firewall/system services are excluded. Lowering a weight gives peer workloads more CPU opportunity **under contention**; it is not a hard cap and does not increase hardware capacity. [Ubuntu's CPUWeight documentation](https://manpages.ubuntu.com/manpages/noble/man5/systemd.resource-control.5.html) describes the cgroup hierarchy and baseline weight of 100. CPU controls require a working systemd CPU controller.

Changes use `systemctl set-property --runtime`, without restarting the application. The original value is recorded once per boot and can be restored with `--reset`. Reboot clears runtime settings; snapshots from a previous boot are never reapplied as a reset. CPU settings retained when uninstalling expire at reboot; the private recovery backup includes their original-value record. Monitor application latency after any change. Existing optional-service start/stop/restart controls remain under Applications/MongoDB and V2Ray for deliberate lifecycle management.

## Validation scope

Temporary-filesystem and fake-command tests verify sampling math, PID reuse, report retention, findings/progress, scheduling definitions, nonblocking inspection, cleanup review and file-identity safeguards. Tests actually delete only disposable test fixtures. Full Ubuntu systemd/cgroup/procfs/network checks and application latency/reboot behavior still require the [disposable-VM validation checklist](VALIDATION.md).
