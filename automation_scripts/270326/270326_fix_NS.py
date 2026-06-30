#!/usr/bin/env python3
"""
Fix Script - Plugin 270326
Cisco IOS Software CLI DoS (Buffer Overflow)
CVE-2025-20149 | Bug ID: CSCwm86360

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Audit all local user accounts and privilege levels
  4. Check CLI privilege restrictions (parser views)
  5. Check SSH access restriction (limits remote CLI access)
  6. Generate account hardening recommendations
  7. Generate remediation report

KEY NOTES:
  - AV:L — LOCAL access only (physical, console, or SSH session)
  - Requires AUTHENTICATED low-privileged account
  - Attacker must craft specific CLI commands to overflow buffer
  - EPSS 0.0002 — LOWEST on device (0.02% exploitation probability)
  - No remote/unauthenticated attack vector
  - Mitigation: remove unnecessary accounts, restrict CLI privilege
  - Full fix = IOS upgrade per CSCwm86360
  - Published 2025/10/14 — most recently published plugin on device
"""

from netmiko import ConnectHandler
import datetime
import sys

# ─── CONFIGURATION ────────────────────────────────────────────────
DEVICE = {
    "device_type": "cisco_ios",
    "host": "192.168.1.1",        # <-- Replace with device IP
    "username": "admin",           # <-- Replace with username
    "password": "yourpassword",    # <-- Replace with password
    "secret": "yourenable",        # <-- Replace with enable secret
    "port": 22,
    "timeout": 30,
}

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_270326_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_270326_{DEVICE['host']}_{TIMESTAMP}.txt"
    with open(backup_file, "w") as f:
        f.write(config)
    log(f"Config backed up to: {backup_file}")

def collect_ios_version(connection):
    log("── STEP 2: IOS Version Collection ──")
    output = connection.send_command("show version")
    for line in output.splitlines():
        if "Cisco IOS Software" in line or "Version" in line:
            log(f"  {line.strip()}")
    log("  Installed: 15.4(3)M5 (from Nessus output)")
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-cli-EB7cZ6yO")

def audit_local_accounts(connection):
    log("── STEP 3: Local User Account Audit ──")
    log("  CVE-2025-20149 requires a valid low-privileged LOCAL account.")
    log("  Auditing all local accounts and privilege levels...")

    # All local users
    users_cfg = connection.send_command("show running-config | include username")
    log("  Local user accounts:")
    log(users_cfg if users_cfg.strip() else "  No local users configured.")

    # Parse privilege levels
    priv_issues = []
    for line in users_cfg.splitlines():
        parts = line.strip().split()
        if "username" in parts and len(parts) >= 2:
            username = parts[1]
            # Determine privilege level
            if "privilege" in parts:
                priv_idx = parts.index("privilege")
                priv_level = int(parts[priv_idx + 1]) if priv_idx + 1 < len(parts) else 1
            else:
                priv_level = 1  # Default is 1 if not specified

            # Mask password
            log(f"  User: {username} | Privilege: {priv_level} | [password redacted]")

            if 1 <= priv_level <= 14:
                priv_issues.append((username, priv_level))
                log(f"    ℹ️  Low-privilege user '{username}' (priv {priv_level})")
                log(f"    → Could potentially use crafted CLI commands for CVE-2025-20149.")

            if priv_level == 15:
                log(f"    ✅ Priv-15 admin — not the target of this CVE (low-priv required).")

    if priv_issues:
        log(f"  ⚠️  {len(priv_issues)} low-privilege account(s) found.")
        log("  Audit each to determine if they are still needed.")
    else:
        log("  ✅ No low-privilege accounts found.")
        log("  CVE-2025-20149 attack path may not be feasible on this device.")

    return priv_issues

def check_parser_views(connection):
    log("── STEP 4: Parser View (CLI Restriction) Configuration ──")

    # Parser view config
    view_cfg = connection.send_command("show running-config | section parser view")
    if view_cfg.strip():
        log("  Parser views configured (CLI restriction in use):")
        log(view_cfg[:400] if len(view_cfg) > 400 else view_cfg)
        log("  ✅ Parser views restrict CLI command access — good practice.")
    else:
        log("  No parser views configured.")
        log("  ℹ️  Consider parser views to restrict which commands low-priv users can run.")
        log("  Example:")
        log("    parser view ReadOnly")
        log("    secret 5 <hashed-password>")
        log("    commands exec include show")
        log("    exit")

    # Privilege exec commands
    priv_cmds = connection.send_command(
        "show running-config | include privilege exec level"
    )
    if priv_cmds.strip():
        log("  Custom privilege level command restrictions:")
        log(priv_cmds)
    else:
        log("  No custom privilege exec level commands configured.")

def check_vty_and_console_access(connection):
    log("── STEP 5: VTY/Console Access Controls ──")

    vty_cfg = connection.send_command("show running-config | section line vty")
    log("  VTY configuration:")
    log(vty_cfg if vty_cfg.strip() else "  No VTY config found.")

    # VTY access-class
    if "access-class" in vty_cfg:
        log("  ✅ VTY access-class configured — SSH restricted to management hosts.")
        log("  Limits who can attempt CLI-based exploit remotely.")
    else:
        log("  ⚠️  No VTY access-class — any host with valid creds can access CLI.")
        log("  Apply SSH ACL (Plugin 165676 mitigation) to restrict remote CLI access.")

    # Console config
    console_cfg = connection.send_command("show running-config | section line con")
    if console_cfg.strip():
        log("  Console line config:")
        log(console_cfg)
        if "exec-timeout" in console_cfg:
            log("  ✅ Console exec-timeout configured — idle sessions terminate.")
        else:
            log("  ⚠️  No console exec-timeout — idle console sessions never terminate.")

def check_aaa_config(connection):
    log("── STEP 6: AAA Authentication Configuration ──")

    aaa_cfg = connection.send_command("show running-config | section aaa")
    if aaa_cfg.strip():
        log("  AAA configuration:")
        log(aaa_cfg[:400] if len(aaa_cfg) > 400 else aaa_cfg)
        log("  ℹ️  AAA in use — privilege assignment may come from RADIUS/TACACS+.")
        log("  Verify external auth server does not grant unnecessary low-priv accounts.")
    else:
        log("  No AAA configuration — using local authentication only.")

def generate_hardening_recommendations(priv_issues):
    log("── STEP 7: CLI Hardening Recommendations ──")
    log("")
    log("  To reduce CVE-2025-20149 exposure:")
    log("")
    log("  1. Remove unnecessary low-privilege accounts:")
    if priv_issues:
        for user, priv in priv_issues:
            log(f"     Review: 'username {user}' (priv {priv}) — still needed?")
            log(f"     Remove: 'no username {user}'")
    else:
        log("     ✅ No low-priv accounts found — no action needed.")

    log("")
    log("  2. Apply parser views to restrict CLI commands for low-priv users:")
    log("     parser view <ViewName>")
    log("     secret 5 <hash>")
    log("     commands exec include show version")
    log("     commands exec include show interfaces")
    log("     exit")
    log("     username <user> view <ViewName>")

    log("")
    log("  3. Apply privilege exec level restrictions:")
    log("     privilege exec level 7 show running-config")
    log("     (limits which commands priv-7 users can run)")

    log("")
    log("  4. Restrict remote CLI access via VTY ACL (Plugin 165676):")
    log("     access-list 97 permit <management-ip>")
    log("     line vty 0 4")
    log("     access-class 97 in")

    log("")
    log("  5. Enable AAA accounting for CLI commands (audit trail):")
    log("     aaa accounting commands 1 default start-stop group tacacs+")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 270326 - CVE-2025-20149 - Cisco IOS CLI DoS")
    log("")
    log("ATTACK CONSTRAINTS (all must be true):")
    log("  1. Attacker has LOCAL access (physical console OR SSH session)")
    log("  2. Attacker has valid low-privilege IOS account credentials")
    log("  3. Attacker knows specific crafted CLI commands to overflow buffer")
    log("  → Extremely constrained — lowest practical risk on device")
    log("")
    log("EPSS 0.0002 — 0.02% exploitation probability — LOWEST on device")
    log("AV:L — Local attack vector only")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCwm86360")
    log("Installed: 15.4(3)M5")
    log("")
    log("Upgrade steps (manual):")
    log("  1. Download fixed IOS image from Cisco.com")
    log("  2. Transfer: 'copy tftp: flash:' or 'copy scp: flash:'")
    log("  3. Verify: 'verify /md5 flash:<image>'")
    log("  4. Set boot: 'boot system flash:<image>'")
    log("  5. Save: 'write memory'")
    log("  6. Reload: 'reload'")
    log("  7. Confirm: 'show version'")
    log("  8. Re-scan Nessus with valid credentials")

def main():
    log("="*65)
    log("Fix Script - Plugin 270326 - Cisco IOS CLI DoS")
    log("CVE-2025-20149 | CSCwm86360 | AV:L | Auth Low-Priv Required")
    log("LOWEST EPSS (0.0002) on device — lowest practical risk")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        priv_issues = audit_local_accounts(connection)
        check_parser_views(connection)
        check_vty_and_console_access(connection)
        check_aaa_config(connection)
        generate_hardening_recommendations(priv_issues)
        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()