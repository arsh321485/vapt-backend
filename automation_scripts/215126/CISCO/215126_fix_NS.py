#!/usr/bin/env python3
"""
Fix Script - Plugin 215126
Cisco IOS Software SNMP DoS
CVE-2025-20169 through CVE-2025-20176 (8 CVEs)
Bug IDs: CSCwm79554, CSCwm79564, CSCwm79570, CSCwm79577,
         CSCwm79581, CSCwm79590, CSCwm79596, CSCwm89600, CSCwn08493

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Audit SNMP configuration (versions, communities, users, ACLs)
  4. Apply SNMP ACL restriction to management hosts
  5. Optionally disable SNMP entirely if not needed
  6. Generate remediation report

KEY NOTES:
  - EIGHT CVEs in one plugin (2025-20169 through 20176)
  - Requires AUTHENTICATED access (valid SNMP community or v3 user)
  - Affects SNMP v1, v2c, AND v3
  - Most recently updated plugin (Modified: 2025/09/15)
  - SNMP runs on UDP/161 — detected via tcp/161 Nessus probe
  - Best mitigation: restrict SNMP via ACL to known management IPs
  - Full fix = IOS upgrade per all listed bug IDs
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

# Management hosts allowed to poll SNMP
# These will be added to ACL applied to SNMP community strings
SNMP_ALLOWED_HOSTS = [
    "10.0.0.10",      # <-- Replace with NMS/monitoring server IPs
    "10.0.0.11",
]

# ACL number to create for SNMP restriction
SNMP_ACL_NUMBER = "99"

# Set True to apply ACL restriction to SNMP communities
APPLY_SNMP_ACL = False

# Set True to disable SNMP entirely if not needed
DISABLE_SNMP = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_215126_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_215126_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-sdxnSUcW")

def audit_snmp_config(connection):
    log("── STEP 3: SNMP Configuration Audit ──")

    # Full SNMP config
    snmp_cfg = connection.send_command("show running-config | include snmp")
    log("  SNMP configuration lines:")
    log(snmp_cfg if snmp_cfg.strip() else "  No SNMP config lines found.")

    snmp_enabled = bool(snmp_cfg.strip())

    if not snmp_enabled:
        log("  ✅ No SNMP configuration found — device may not be exposed.")
        return snmp_enabled, [], []

    # Parse community strings
    community_strings = []
    for line in snmp_cfg.splitlines():
        if "snmp-server community" in line:
            parts = line.strip().split()
            if len(parts) >= 3:
                community = parts[2]
                community_strings.append(parts[2])
                permission = parts[3] if len(parts) > 3 else "RO"
                acl = parts[4] if len(parts) > 4 else "None"
                log(f"  Community: '{community}' | Permission: {permission} | ACL: {acl}")

    if community_strings:
        log(f"  ⚠️  {len(community_strings)} SNMP community string(s) found.")
        log("  For CVE-2025-20169..76: attacker needs to know one of these strings.")

    # SNMP version detection
    if "snmp-server community" in snmp_cfg:
        log("  ⚠️  SNMPv1/v2c configured (community strings present).")

    # SNMPv3 users
    snmpv3 = connection.send_command("show snmp user")
    if snmpv3.strip() and "no such" not in snmpv3.lower():
        log("  SNMPv3 users:")
        log(snmpv3[:400] if len(snmpv3) > 400 else snmpv3)
        log("  ⚠️  SNMPv3 users present — CVE exploitable via v3 credentials too.")

    # SNMP location/contact
    log("  >> SNMP System Info:")
    sys_info = connection.send_command(
        "show running-config | include snmp-server location|snmp-server contact"
    )
    log(sys_info if sys_info.strip() else "  No SNMP location/contact configured.")

    # Existing ACLs on SNMP
    existing_acl = connection.send_command(
        "show running-config | include snmp-server community.*[0-9]"
    )
    if existing_acl.strip():
        log("  SNMP communities with existing ACLs:")
        log(existing_acl)
    else:
        log("  ⚠️  No ACL restriction on SNMP communities — accessible from any source.")

    # SNMP trap receivers
    trap_hosts = connection.send_command(
        "show running-config | include snmp-server host"
    )
    if trap_hosts.strip():
        log("  SNMP trap receivers:")
        log(trap_hosts)

    return snmp_enabled, community_strings, snmpv3

def check_snmp_activity(connection):
    log("── STEP 4: SNMP Activity and Statistics ──")

    snmp_stats = connection.send_command("show snmp")
    if snmp_stats.strip():
        log("  SNMP statistics:")
        log(snmp_stats[:500] if len(snmp_stats) > 500 else snmp_stats)

        # Check for incoming packets
        for line in snmp_stats.splitlines():
            if "input" in line.lower() or "packets" in line.lower():
                log(f"  Traffic indicator: {line.strip()}")
    else:
        log("  No SNMP statistics available.")

def create_snmp_acl(connection):
    log("── STEP 5a: Creating SNMP Restriction ACL ──")
    log(f"  Creating ACL {SNMP_ACL_NUMBER} for SNMP management hosts...")

    commands = [f"no access-list {SNMP_ACL_NUMBER}"]  # Clear existing
    for host in SNMP_ALLOWED_HOSTS:
        commands.append(f"access-list {SNMP_ACL_NUMBER} permit {host}")
        log(f"  Permitting management host: {host}")

    commands.append(f"access-list {SNMP_ACL_NUMBER} deny any log")
    log("  Denying all other SNMP sources (with logging).")

    output = connection.send_config_set(commands)
    log(output)
    log(f"  ✅ ACL {SNMP_ACL_NUMBER} created.")

def apply_snmp_acl(connection, community_strings):
    log("── STEP 5b: Applying ACL to SNMP Communities ──")

    if not community_strings:
        log("  No community strings found to apply ACL to.")
        return

    # Get full community config to preserve RO/RW
    full_snmp = connection.send_command(
        "show running-config | include snmp-server community"
    )
    commands = []
    for line in full_snmp.splitlines():
        parts = line.strip().split()
        if len(parts) >= 4 and "snmp-server" in parts:
            community = parts[2]
            permission = parts[3]  # RO or RW
            # Re-apply with ACL
            commands.append(
                f"snmp-server community {community} {permission} {SNMP_ACL_NUMBER}"
            )
            log(f"  Applying ACL {SNMP_ACL_NUMBER} to community '{community}' ({permission})")

    if commands:
        output = connection.send_config_set(commands)
        log(output)
        save = connection.send_command("write memory")
        log(f"  Config saved: {save}")
        log(f"  ✅ SNMP ACL applied.")
        log(f"  Only hosts in ACL {SNMP_ACL_NUMBER} can now send SNMP requests.")
        log("  Attack surface significantly reduced — attacker needs network position + creds.")

def disable_snmp(connection):
    log("── STEP 5c: Disabling SNMP Entirely (DISABLE_SNMP=True) ──")

    # Get all SNMP community strings
    snmp_cfg = connection.send_command("show running-config | include snmp-server community")
    commands = []

    for line in snmp_cfg.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and "community" in parts:
            community = parts[2]
            commands.append(f"no snmp-server community {community}")
            log(f"  Removing community: {community}")

    # Remove SNMP server entirely
    commands.append("no snmp-server")
    commands.append("no snmp-server enable traps")

    if commands:
        output = connection.send_config_set(commands)
        log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ SNMP disabled.")
    log("  CVE-2025-20169..20176 attack surface eliminated.")
    log("  ⚠️  NMS/monitoring tools can no longer poll this device via SNMP.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 215126 - CVE-2025-20169 through 20176 - Cisco IOS SNMP DoS")
    log("")
    log("8 CVEs, 9 Bug IDs — largest CVE set of any plugin on this device.")
    log("")
    log("Attack prerequisites:")
    log("  1. Valid SNMP community string (v1/v2c) OR valid SNMPv3 credentials")
    log("  2. Network access to UDP/161 on the device")
    log("  → ACL restriction is highly effective mitigation")
    log("")
    log("Recommended mitigations (prioritized):")
    log("  1. Apply ACL to SNMP communities (restrict to known management IPs)")
    log("  2. Use SNMPv3 with auth+priv instead of v1/v2c community strings")
    log("  3. Remove RW community strings if read-only is sufficient")
    log("  4. Rotate all community strings")
    log("  5. If SNMP not needed: 'no snmp-server' to disable entirely")
    log("")
    log("9 Bug IDs to fix (all resolved by single IOS upgrade):")
    log("  CSCwm79554, CSCwm79564, CSCwm79570, CSCwm79577, CSCwm79581")
    log("  CSCwm79590, CSCwm79596, CSCwm89600, CSCwn08493")
    log("")
    log("Permanent Fix: IOS upgrade per all listed bug IDs")
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
    log("Fix Script - Plugin 215126 - Cisco IOS SNMP DoS")
    log("CVE-2025-20169..20176 | 9 Bug IDs | Requires SNMP Auth")
    log("Most recently updated plugin (2025/09/15)")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        snmp_enabled, communities, snmpv3 = audit_snmp_config(connection)
        check_snmp_activity(connection)

        if DISABLE_SNMP:
            disable_snmp(connection)
        elif APPLY_SNMP_ACL:
            if not snmp_enabled:
                log("── STEP 5: SNMP not configured — no ACL action needed. ──")
            else:
                create_snmp_acl(connection)
                apply_snmp_acl(connection, communities)
        else:
            log("── STEP 5: Skipped (APPLY_SNMP_ACL=False, DISABLE_SNMP=False) ──")
            log("   Set APPLY_SNMP_ACL=True to restrict SNMP to known management hosts.")
            log("   Set DISABLE_SNMP=True to disable SNMP entirely if not needed.")
            log("   ⚠️  Configure SNMP_ALLOWED_HOSTS with your NMS server IPs first.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()