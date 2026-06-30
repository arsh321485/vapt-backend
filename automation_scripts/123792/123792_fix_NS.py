#!/usr/bin/env python3
"""
Fix Script - Plugin 123792
Cisco IOS Software HSRP Information Leak
CVE-2019-1761 | Bug ID: CSCvj98575

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check HSRP configuration (v1 vs v2)
  4. Enumerate HSRP groups and authentication
  5. Document HSRP neighbor state
  6. Generate HSRP hardening recommendations

KEY NOTES:
  - Risk Factor: LOW
  - VPR: 1.4 — ABSOLUTE LOWEST on entire device
  - CVSS v3.0: 4.3 (C:L only — partial confidentiality info leak)
  - AV:A — Adjacent attack only (must be on same HSRP segment)
  - A:N — No availability impact
  - Only HSRPv2 is affected (NOT HSRPv1)
  - Mitigation: HSRP MD5 authentication (best practice anyway)
  - Full fix = IOS upgrade per CSCvj98575
  - LOWEST priority plugin on device — address last
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

# HSRP MD5 authentication key
# ⚠️  Must match on ALL HSRP group members
HSRP_AUTH_KEY = "HsrpK3y2024!"   # <-- Replace with strong key

# Set True to apply HSRP MD5 authentication
# ⚠️  Coordinate with all HSRP peer routers first
APPLY_HSRP_AUTH = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_123792_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_123792_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-ios-infoleak")

def check_hsrp_config(connection):
    log("── STEP 3: Checking HSRP Configuration ──")

    # HSRP config lines
    hsrp_cfg = connection.send_command("show running-config | include standby")
    log("  HSRP (standby) config lines:")
    log(hsrp_cfg if hsrp_cfg.strip() else "  No HSRP config found.")

    hsrp_configured = bool(hsrp_cfg.strip())

    if not hsrp_configured:
        log("  ✅ HSRP not configured — CVE-2019-1761 not applicable.")
        log("  Mark as 'Not Applicable'.")
        return False, False

    # Check HSRPv1 vs HSRPv2
    hsrp_version_cfg = connection.send_command(
        "show running-config | include standby version"
    )
    hsrpv2_configured = False

    if "standby version 2" in hsrp_version_cfg:
        log("  ⚠️  HSRPv2 is configured — CVE-2019-1761 APPLIES.")
        log("  Uninitialized memory in HSRPv2 packets leaks sensitive info.")
        hsrpv2_configured = True
    elif "standby version 1" in hsrp_version_cfg:
        log("  ✅ HSRPv1 only — CVE-2019-1761 does NOT affect HSRPv1.")
        log("  Plugin may be a false positive for this device.")
    else:
        log("  ⚠️  No explicit HSRP version set — default is HSRPv1.")
        log("  If HSRPv2 not explicitly configured: likely not affected.")
        log("  Check 'show standby' for active version.")

    return hsrp_configured, hsrpv2_configured

def check_hsrp_groups(connection):
    log("── STEP 4: HSRP Group Enumeration ──")

    hsrp_status = connection.send_command("show standby")
    if hsrp_status.strip():
        log("  HSRP group status:")
        log(hsrp_status[:600] if len(hsrp_status) > 600 else hsrp_status)

        # Count groups
        active_count = hsrp_status.count("Active")
        standby_count = hsrp_status.count("Standby")
        log(f"  Active HSRP roles: {active_count}")
        log(f"  Standby HSRP roles: {standby_count}")
    else:
        log("  No HSRP group status output.")

    # HSRP brief
    hsrp_brief = connection.send_command("show standby brief")
    if hsrp_brief.strip():
        log("  HSRP brief:")
        log(hsrp_brief)

def check_hsrp_authentication(connection):
    log("── STEP 5: HSRP Authentication Audit ──")

    # Auth in config
    hsrp_auth = connection.send_command(
        "show running-config | include standby.*authentication"
    )
    if hsrp_auth.strip():
        log("  HSRP authentication configured:")
        log(hsrp_auth)
        if "md5" in hsrp_auth.lower():
            log("  ✅ HSRP MD5 authentication active.")
            log("  Information leakage mitigation in place.")
        elif "text" in hsrp_auth.lower():
            log("  ⚠️  HSRP using plaintext authentication — upgrade to MD5.")
        else:
            log("  ℹ️  HSRP auth type unclear.")
    else:
        log("  ⚠️  No HSRP authentication configured.")
        log("  CVE-2019-1761 memory leak exploitable by adjacent attacker.")
        log("  Apply HSRP MD5 authentication as mitigation.")

    return bool(hsrp_auth.strip() and "md5" in hsrp_auth.lower())

def get_hsrp_interfaces(connection):
    """Parse interfaces with HSRP configured"""
    output = connection.send_command("show standby brief")
    interfaces = []
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].startswith(
            ("GigabitEthernet", "FastEthernet", "Vlan", "Serial")
        ):
            interfaces.append(parts[0])
    return list(set(interfaces))  # Deduplicate

def apply_hsrp_md5_auth(connection):
    log("── STEP 6: Applying HSRP MD5 Authentication ──")
    log("  ⚠️  All HSRP peers must use identical key.")

    # Get HSRP groups from config
    hsrp_cfg = connection.send_command("show running-config | include standby")
    commands = []

    # Parse group numbers per interface
    full_cfg = connection.send_command("show running-config")
    current_iface = None
    hsrp_groups = {}  # {interface: [group_numbers]}

    for line in full_cfg.splitlines():
        if line.startswith("interface "):
            current_iface = line.split("interface ")[1].strip()
        elif "standby" in line and current_iface:
            parts = line.strip().split()
            if len(parts) >= 2:
                # standby <group> <command>
                try:
                    grp = int(parts[1])
                    if current_iface not in hsrp_groups:
                        hsrp_groups[current_iface] = set()
                    hsrp_groups[current_iface].add(grp)
                except ValueError:
                    pass  # 'standby preempt' etc.

    if not hsrp_groups:
        log("  Could not parse HSRP groups — apply authentication manually.")
        return

    for iface, groups in hsrp_groups.items():
        commands.append(f"interface {iface}")
        for grp in sorted(groups):
            commands.append(
                f"standby {grp} authentication md5 key-string {HSRP_AUTH_KEY}"
            )
            log(f"  Configuring MD5 auth: {iface} group {grp}")

    if commands:
        output = connection.send_config_set(commands)
        log(output)
        save = connection.send_command("write memory")
        log(f"  Config saved: {save}")
        log("  ✅ HSRP MD5 authentication applied.")
        log("  Memory leak attack surface reduced.")
        log("  ⚠️  Verify HSRP adjacencies immediately: 'show standby brief'")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 123792 - CVE-2019-1761 - Cisco IOS HSRP Information Leak")
    log("")
    log("LOWEST PRIORITY on entire device:")
    log("  Risk Factor: LOW")
    log("  CVSS v3.0:  4.3  (C:L/I:N/A:N — confidentiality only)")
    log("  VPR:        1.4  — ABSOLUTE LOWEST on device")
    log("  EPSS:     0.0007 — Very low exploitation probability")
    log("  AV:A            — Adjacent only (same L2 segment)")
    log("  A:N             — Zero availability impact")
    log("  Only HSRPv2 affected (not HSRPv1)")
    log("")
    log("Attack outcome: Partial memory leak in HSRP packets")
    log("  NOT DoS, NOT RCE — information disclosure only")
    log("  Attacker must be on same L2 segment as HSRP group")
    log("")
    log("Mitigation: HSRP MD5 authentication (best practice regardless)")
    log("  standby <group> authentication md5 key-string <key>")
    log("  Must match on all HSRP group members")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvj98575")
    log("Installed: 15.4(3)M5")
    log("")
    log("Address ONLY after all 31 other plugins are resolved.")
    log("IOS upgrade (planned for all critical plugins) fixes this too.")

def main():
    log("="*65)
    log("Fix Script - Plugin 123792 - Cisco IOS HSRP Info Leak")
    log("CVE-2019-1761 | CSCvj98575 | VPR 1.4 — ABSOLUTE LOWEST")
    log("Risk Factor: LOW | Adjacent only | HSRPv2 only")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        hsrp_configured, hsrpv2_configured = check_hsrp_config(connection)

        if hsrp_configured:
            check_hsrp_groups(connection)
            auth_ok = check_hsrp_authentication(connection)

            if APPLY_HSRP_AUTH and not auth_ok:
                log("⚠️  APPLY_HSRP_AUTH=True — applying MD5 auth.")
                log("   Ensure all HSRP peers have same key configured first.")
                apply_hsrp_md5_auth(connection)
            elif auth_ok:
                log("✅ HSRP MD5 auth already configured — no action needed.")
            else:
                log("── STEP 6: Skipped (APPLY_HSRP_AUTH=False) ──")
                log("   Set APPLY_HSRP_AUTH=True after coordinating with HSRP peers.")
        else:
            log("HSRP not configured — mark Plugin 123792 as 'Not Applicable'.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()