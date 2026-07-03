#!/usr/bin/env python3
"""
Fix Script - Plugin 137407
Cisco IOS Tcl DoS Vulnerability
CVE-2020-3201 | Bug ID: CSCvq28110

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Audit Tcl interpreter access and privilege levels
  4. Check active Tcl scripts/configurations
  5. Generate privilege restriction recommendations
  6. Generate remediation report

KEY NOTES:
  - AV:L — Local access required
  - PR:H — HIGH privilege required (not low-priv like Plugin 270326)
  - Attacker needs priv-15 or high-priv account + local access
  - Practically: only malicious insider or compromised admin
  - EPSS 0.0013 — very low exploitation probability
  - Similar to Plugin 270326 (CLI DoS) but requires higher privilege
  - Tcl interpreter used for scripting on IOS devices
  - Full fix = IOS upgrade per CSCvq28110
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
LOG_FILE = f"fix_137407_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_137407_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tcl-dos-MAZQUnMF")

def audit_tcl_access(connection):
    log("── STEP 3: Tcl Interpreter Access Audit ──")
    log("  CVE-2020-3201 requires: AV:L (local) + PR:H (high privilege)")
    log("  Attack vector: authenticated high-priv user runs crafted Tcl args")
    log("")

    # Check Tcl-related config
    tcl_cfg = connection.send_command("show running-config | include tcl")
    if tcl_cfg.strip():
        log("  Tcl-related configuration:")
        log(tcl_cfg)
    else:
        log("  No Tcl-specific config lines found.")
        log("  Tcl interpreter is built-in — available to priv-15 users by default.")

    # Privilege level for tclsh
    tclsh_priv = connection.send_command(
        "show running-config | include privilege exec level.*tclsh"
    )
    if tclsh_priv.strip():
        log("  Custom Tcl privilege restriction found:")
        log(tclsh_priv)
        for line in tclsh_priv.splitlines():
            parts = line.strip().split()
            if "level" in parts:
                idx = parts.index("level")
                if idx + 1 < len(parts):
                    level = parts[idx + 1]
                    log(f"  Tcl access restricted to privilege level {level}+")
    else:
        log("  ℹ️  No explicit tclsh privilege restriction configured.")
        log("  Default: tclsh accessible to priv-15 users.")
        log("  Recommendation: 'privilege exec level 15 tclsh' (restrict to priv-15)")

def audit_high_priv_accounts(connection):
    log("── STEP 4: High-Privilege Account Audit (PR:H Attack Surface) ──")
    log("  CVE-2020-3201 requires HIGH PRIVILEGE (PR:H) — not low-priv like Plugin 270326.")

    users_cfg = connection.send_command("show running-config | include username")

    high_priv = []
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
                high_priv.append((username, priv))
                log(f"  High-priv user: '{username}' (priv {priv}) [password redacted]")
            elif priv >= 10:
                log(f"  ℹ️  Medium-priv user: '{username}' (priv {priv})")

    if high_priv:
        log(f"  ⚠️  {len(high_priv)} high-privilege account(s) — potential Tcl attackers.")
        log("  Audit each: are they legitimate admins?")
        log("  A malicious priv-15 user could exploit CVE-2020-3201.")
    else:
        log("  ✅ No local high-privilege accounts found.")
        log("  Tcl DoS attack path may require AAA/RADIUS-assigned privileges.")

def check_tcl_scripts(connection):
    log("── STEP 5: Active Tcl Script Usage ──")

    # EEM Tcl policies
    eem_tcl = connection.send_command("show running-config | include event manager policy")
    if eem_tcl.strip():
        log("  EEM (Embedded Event Manager) Tcl policies:")
        log(eem_tcl)
        log("  ℹ️  Tcl is actively used for EEM automation on this device.")
    else:
        log("  No EEM Tcl policies configured.")

    # Check flash for .tcl files
    tcl_files = connection.send_command("dir flash: | include .tcl")
    if tcl_files.strip():
        log("  Tcl script files in flash:")
        log(tcl_files)
    else:
        log("  No .tcl files found in flash.")
        log("  ✅ Tcl scripting may not be actively used on this device.")

def compare_with_270326():
    log("── STEP 6: Comparison with Plugin 270326 (CLI DoS) ──")
    log("")
    log("  Two local-access CLI/interpreter DoS plugins on this device:")
    log("")
    log("  Plugin 270326 (CVE-2025-20149) — CLI Buffer Overflow")
    log("    AV:L | PR:L (Low privilege) | CVSS 6.5 | EPSS 0.0002")
    log("    Attack: Low-priv local account + crafted CLI commands")
    log("")
    log("  Plugin 137407 (CVE-2020-3201)  — Tcl Interpreter DoS")
    log("    AV:L | PR:H (High privilege) | CVSS 6.0 | EPSS 0.0013")
    log("    Attack: HIGH-priv local account + crafted Tcl arguments")
    log("")
    log("  Both require LOCAL access — neither is remotely exploitable.")
    log("  Plugin 137407 requires HIGHER privilege than Plugin 270326.")
    log("  Both resolved by same IOS upgrade.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 137407 - CVE-2020-3201 - Cisco IOS Tcl DoS")
    log("")
    log("ATTACK REQUIREMENTS:")
    log("  1. LOCAL access (physical console or SSH session)")
    log("  2. HIGH PRIVILEGE (priv-15 or near-priv-15 account)")
    log("  3. Execute crafted Tcl arguments via tclsh")
    log("  → Only malicious insider or compromised admin can exploit")
    log("  → Extremely constrained attack path")
    log("")
    log("Mitigation options:")
    log("  1. Restrict tclsh to priv-15 explicitly:")
    log("     privilege exec level 15 tclsh")
    log("  2. Monitor/audit Tcl script execution via AAA accounting:")
    log("     aaa accounting commands 15 default start-stop group tacacs+")
    log("  3. Limit who has priv-15 accounts")
    log("  4. Apply VTY ACL to restrict remote high-priv access")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvq28110")
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
    log("Fix Script - Plugin 137407 - Cisco IOS Tcl DoS")
    log("CVE-2020-3201 | CSCvq28110 | AV:L | PR:H | EPSS 0.0013")
    log("Requires LOCAL + HIGH-PRIVILEGE access — very constrained")
    log("="*65)

    try:
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        backup_config(connection)
        collect_ios_version(connection)
        audit_tcl_access(connection)
        audit_high_priv_accounts(connection)
        check_tcl_scripts(connection)
        compare_with_270326()
        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()