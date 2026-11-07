# Terminal setup and management

## Quick install

Run in a root Bash shell on Ubuntu 24.04, using the repository's `master` branch:

```bash
bash <(curl -fsSL --proto '=https' --proto-redir '=https' https://raw.githubusercontent.com/amindqn/server-guard/master/bootstrap.sh) --ref master
```

The command uses the same short-installer and persistent management-menu workflow that motivated the [3x-ui reference](https://github.com/MHSanaei/3x-ui#quick-start). Server Guard's menus configure the services described in this repository; no 3x-ui code or panel is installed by this command.

`bootstrap.sh` opens `server-guard setup` after its local installer exits and releases the management lock. It reconnects input to `/dev/tty`, so prompts can work even when the downloaded script was supplied through a pipe or process substitution. With `--no-ui`, or without a usable terminal, installation finishes and prints the setup command instead. The command requires curl; install `ca-certificates curl` through APT first if absent.

## The four setup steps

1. **Dependencies.** Review and install Ubuntu security/management packages. Successful preparation is recorded, so resuming the wizard skips that completed step. Use Status/maintenance to explicitly rerun preparation if repairing packages.
2. **Initial policy.** Confirm the server's current SSH port. The wizard uses `SSH_CONNECTION` as a suggested value when available. It initializes policy only if no policy exists.
3. **Administrator.** Enter a Linux username and an SSH public key, either pasted as one line or read from an existing `.pub` file on the server. Private keys stay on your computer. Choose the concurrency limit (administrators need at least two), review the account, then set its local sudo password through the native hidden passwd prompt.
4. **Verify, apply and confirm.** The wizard prints a second-terminal SSH command. Reconnect as the new administrator and run `sudo --preserve-env=SSH_CONNECTION server-guard setup`. It verifies the actual key login/sudo identity, displays the plan and asks before applying it. Reconnect once more to confirm the new access policy within ten minutes. The wizard never confirms its own change from the original connection.

You can leave between steps and resume with the same setup command. Existing policy/accounts remain. A pending access change routes setup to the confirmation/recovery menu. If you cancel while a backend command is already running, completed effects may remain; the UI reports that rather than claiming to undo them. Existing access rollback semantics still apply.

## Management menu

Run `sudo server-guard` or `sudo server-guard menu`:

```text
==============================================================================
SERVER GUARD 1.2.0  /  Management
==============================================================================
Policy: SSH 22 | root SSH disabled | 1 users | firewall config saved.
   1  Guided first-time setup / resume
   2  SSH access and root login
   3  Linux users and session limits
   4  Firewall and public web ports
   5  CloudPanel / aaPanel
   6  MongoDB database and users
   7  V2Ray service and clients
   8  Status, updates and security audit
   9  Review, apply, confirm or roll back
   0  Exit
Select:
```

The summary describes the saved policy/files, not proof that every running service matches that policy. Use Status to inspect actual listening ports and service state.

| Menu | Actions |
| --- | --- |
| SSH | Verify this key login, stage the SSH port/source allowlist/root setting, review/apply |
| Users | List, create admin/developer/SFTP user, adopt a site account, change session cap, rotate key, disable account |
| Firewall | Stage HTTP/HTTPS, add/remove a port/protocol/source rule, review/apply |
| Panel | Download a vendor installer, request its approved checksum, choose CloudPanel's DB engine, install, show private tunnel access |
| MongoDB | Install locally, bootstrap/recover the admin, create/rotate/revoke scoped app users, inspect/start/restart/stop |
| V2Ray | Install a pinned binary, configure domain/local WS port, add/export/revoke clients, show Nginx block, inspect/start/restart/stop |
| Maintenance | Status, Lynis audit, repair dependencies, review package upgrades |
| Access changes | Plan, apply, confirm pending ID from a new login, roll back |

Optional service controls operate only on MongoDB and V2Ray. They cannot stop SSH or the firewall through this interface. Starting MongoDB requires successful first-user bootstrap. New port/session/SSH policies remain staged until apply; database/client/account/key/package operations retain their documented immediate behavior.

## Input and secrets

- Enter a numbered choice; `0` returns to the parent menu or exits the top-level menu. `q` also leaves a menu.
- Press Enter to use the displayed default. Invalid values show a text error and request the same field again.
- Enter `:back` to cancel a form. Ctrl+C cancels the current operation/menu action where practical; Ctrl+D exits when input closes.
- Action summaries appear before submitting mutations. The final confirmation defaults to No.
- SSH public keys may be pasted; private keys are rejected. Passwords are collected by passwd/mongosh hidden prompts, not logged UI fields. V2Ray export requests explicit permission before displaying a secret link.
- All prompts occur outside the management lock. Only submitted commands acquire it; a user sitting at a menu/form cannot stall a pending rollback timer.
- Color is used only on capable interactive output and respects `NO_COLOR`/`TERM=dumb`. Text labels carry status/error meaning. The UI uses line input and ASCII separators for ordinary SSH terminals, rather than cursor-dependent full-screen rendering.

## Preview without root or server changes

From a local source checkout:

```bash
python3 scripts/preview_terminal.py
```

The preview renders the real menus and forms using temporary synthetic policy files. All submitted host commands are disabled. It does not install packages, create system users, bind ports or change the host's SSH/firewall. Actual Ubuntu service installation still requires the validation checklist.
