#!/usr/bin/env python3
"""
Fix Script - Plugin 137630
Cisco IOS and IOS XE Software Tcl Arbitrary Code Execution
CVE-2020-3204 | Bug ID: CSCvq05584

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Audit privileged EXEC accounts (attack surface)
  4. Check Tcl privilege restrictions
  5. Audit active Tcl/EEM usage
  6. Generate hardening recommendations
  7. Generate remediation report

KEY NOTES:
  - ARBITRARY CODE EXECUTION with ROOT PRIVILEGES on underlying OS
  - AV:L — Local access required
  - PR:H — High privilege required (privileged EXEC)
  - CVSS C:H/I:H/A:H — FULL TRIAD IMPACT at High level
  - VPR 5.9 — HIGHEST of all local-access plugins on device
  - Different from Plugin 137407 (Tcl DoS only):
    137407 = DoS only | 137630 = RCE with root OS access
  - THIRD RCE capability on this device:
    Plugin 266454 (SNMP RCE) + 183215 (GET VPN RCE) + THIS
  - Full fix = IOS upgrade per CSCvq05584
"""

from netmiko import ConnectHandler
import datetime
import sys

DEVICE = {
    "device_type": "cisco_ios",
    "host": "192.168.1.1",
    "username": "admin",
    "password": "yourpassword",
    "secret": "yourenable",
    "port": 22,
    "timeout": 30,
}

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_137630_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_137630_{DEVICE['host']}_{TIMESTAMP}.txt"
    with open(backup_file, "w") as f:
        f.write(config)
    log(f"Config backed up to: {backup_file}")

def collect_ios_version(connection):
    log("── STEP 2: IOS Version Collection ──")
    output = connection.send_command("show version")
    for line in output.splitlines():
        if "Cisco IOS Software" in line or "Version" in line:
            log(f"  {line.strip()}")
    log("  Installed: 15.4(3)M5")
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tcl-ace-C9KuVKmm")
    log("")
    log("  ⚠️  This is an ARBITRARY CODE EXECUTION vulnerability.")
    log("  Successful exploit = root OS access = full device compromise.")
    log("  HIGHEST severity Tcl plugin on this device.")

def audit_priv_exec_accounts(connection):
    log("── STEP 3: Privileged EXEC Account Audit ──")
    log("  CVE-2020-3204 requires PRIVILEGED EXEC (priv-15) access.")
    log("  Auditing all high-privilege accounts...")

    users_cfg = connection.send_command("show running-config | include username")

    priv15_users = []
    for line in users_cfg.splitlines():
        parts = line.strip().split()
        if "username" in parts and len(parts) >= 2:
            username = parts[1]
            if "privilege" in parts:
                priv_idx = parts.index("privilege")
                priv = int(parts[priv_idx + 1]) if priv_idx + 1 < len(parts) else 1
            else:
                priv = 1

            if priv >= 15:
                priv15_users.append(username)
                log(f"  ⚠️  Priv-15 user: '{username}' [password redacted]")
                log(f"     → Can run tclsh with root OS code execution capability")
            elif priv >= 10:
                log(f"  ℹ️  Priv-{priv} user: '{username}' — elevated but below 15")

    if not priv15_users:
        log("  ✅ No local priv-15 accounts found.")
        log("  Tcl ACE attack requires priv-15 — local accounts do not expose it.")
        log("  Check AAA/RADIUS/TACACS+ for priv-15 assignment.")
    else:
        log(f"  ⚠️  {len(priv15_users)} priv-15 account(s) — strict vetting required.")
        log("  Each account is a potential Tcl ACE attacker if credentials compromised.")

    # Check enable secret (also priv-15)
    enable_cfg = connection.send_command(
        "show running-config | include enable secret|enable password"
    )
    if enable_cfg.strip():
        log("  Enable secret/password configured (priv-15 path via 'enable').")
        for line in enable_cfg.splitlines():
            parts = line.strip().split()
            log(f"  {parts[0]} {parts[1]} [redacted]" if len(parts) >= 3 else line)

    return priv15_users

def check_tcl_privilege_restrictions(connection):
    log("── STEP 4: Tcl Interpreter Privilege Restrictions ──")

    # Custom privilege level for tclsh
    tclsh_priv = connection.send_command(
        "show running-config | include privilege exec level.*tclsh"
    )
    if tclsh_priv.strip():
        log("  Custom tclsh privilege restriction:")
        log(tclsh_priv)
        log("  ✅ Tcl access is explicitly privilege-restricted.")
    else:
        log("  ⚠️  No explicit tclsh privilege restriction.")
        log("  Default: tclsh accessible to privileged EXEC (priv-15) users.")
        log("  Recommendation: 'privilege exec level 15 tclsh'")
        log("  (Already priv-15 by default — just makes restriction explicit)")

    # Parser views
    view_cfg = connection.send_command("show running-config | section parser view")
    if view_cfg.strip():
        log("  Parser views configured — additional CLI restriction in use:")
        log(view_cfg[:300] if len(view_cfg) > 300 else view_cfg)
    else:
        log("  No parser views configured.")

def audit_tcl_eem_active(connection):
    log("── STEP 5: Tcl/EEM Active Usage Assessment ──")

    # EEM Tcl policies
    eem_tcl = connection.send_command(
        "show running-config | include event manager policy"
    )
    if eem_tcl.strip():
        log("  EEM Tcl policies (Tcl actively used for automation):")
        log(eem_tcl)
        log("  ℹ️  Legitimate Tcl usage exists — do not disable Tcl globally.")
    else:
        log("  No EEM Tcl policies — Tcl may not be in active automation use.")

    # Tcl files in flash
    tcl_files = connection.send_command("dir flash: | include .tcl")
    if tcl_files.strip():
        log("  Tcl script files in flash:")
        log(tcl_files)

    # Show tclsh availability
    tclsh_check = connection.send_command(
        "show running-config | include tclsh"
    )
    if tclsh_check.strip():
        log(f"  Tcl config: {tclsh_check.strip()}")

def generate_hardening_recommendations(priv15_users):
    log("── STEP 6: Hardening Recommendations ──")
    log("")
    log("  To reduce CVE-2020-3204 (Tcl ACE) attack surface:")
    log("")
    log("  1. Minimize priv-15 accounts:")
    if priv15_users:
        for user in priv15_users:
            log(f"     Review: '{user}' — is priv-15 access required?")
    else:
        log("     ✅ No local priv-15 accounts — attack surface minimal.")

    log("")
    log("  2. Use AAA accounting to audit priv-15 command execution:")
    log("     aaa accounting commands 15 default start-stop group tacacs+")
    log("     (Creates audit trail of tclsh usage)")

    log("")
    log("  3. Restrict remote access to priv-15 via VTY ACL:")
    log("     access-list 97 permit <jump-server-ip>")
    log("     line vty 0 4")
    log("     access-class 97 in")

    log("")
    log("  4. Consider TACACS+ command authorization to restrict tclsh:")
    log("     aaa authorization commands 15 default group tacacs+ local")
    log("     (TACACS+ can deny 'tclsh' execution for specific accounts)")

    log("")
    log("  5. Enforce console exec-timeout:")
    log("     line console 0")
    log("     exec-timeout 5 0")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 137630 - CVE-2020-3204 - Cisco IOS Tcl Arbitrary Code Execution")
    log("")
    log("⚠️  ARBITRARY CODE EXECUTION WITH ROOT OS PRIVILEGES")
    log("  CVSS: 6.7 | C:H/I:H/A:H — Full triad at High level")
    log("  VPR: 5.9 — Highest of all local-access plugins on device")
    log("")
    log("THIS IS THE THIRD RCE CAPABILITY ON THIS DEVICE:")
    log("  Plugin 266454 (CVE-2025-20352) — SNMP RCE          [CISA KEV]")
    log("  Plugin 183215 (CVE-2023-20109) — GET VPN OOB Write  [CISA KEV]")
    log("  Plugin 137630 (CVE-2020-3204)  — Tcl ACE root OS    ← THIS")
    log("")
    log("Comparison with Plugin 137407 (Tcl DoS):")
    log("  Plugin 137407 (CVE-2020-3201) — Tcl DoS only (A:H impact)")
    log("  Plugin 137630 (CVE-2020-3204) — Tcl ACE (C:H/I:H/A:H, root OS)")
    log("  Both require AV:L + PR:H | 137630 is significantly more severe")
    log("  Both resolved by same IOS upgrade")
    log("")
    log("Attack constraints (both required):")
    log("  1. Local access (physical/SSH)")
    log("  2. Privileged EXEC credentials (priv-15)")
    log("  → Only malicious insider or compromised admin")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvq05584")
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
    log("Fix Script - Plugin 137630 - Cisco IOS Tcl ACE (Root OS)")
    log("CVE-2020-3204 | CSCvq05584 | CVSS 6.7 | C:H/I:H/A:H | RCE")
    log("VPR 5.9 — 3rd RCE capability on this device")
    log("="*65)

    try:
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        backup_config(connection)
        collect_ios_version(connection)
        priv15_users = audit_priv_exec_accounts(connection)
        check_tcl_privilege_restrictions(connection)
        audit_tcl_eem_active(connection)
        generate_hardening_recommendations(priv15_users)
        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()