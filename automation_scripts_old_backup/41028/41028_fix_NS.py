#!/usr/bin/env python3
"""
Fix Script - Plugin 41028
SNMP Agent Default Community Name (public)
CVE-1999-0517

CRITICAL NOTES:
  - EPSS 0.9243 — HIGHEST on entire device (92% exploitation probability)
  - Nessus ACTIVELY confirmed 'public' community responds on UDP/161
  - This is a CONFIG issue — fix does NOT require IOS upgrade
  - Fix is immediate: remove 'public', add strong community string
  - This fix also reduces attack surface for Plugins 215126 and 266454
    (both require valid SNMP credentials — 'public' provides that)
  
BEFORE RUNNING:
  ⚠️  Update all NMS/monitoring tools to new community string FIRST
  ⚠️  Coordinate with network operations team before executing
  
Actions:
  1. Backup running config
  2. Audit all SNMP community strings
  3. Remove 'public' (and 'private' if present)
  4. Apply replacement community string
  5. Apply SNMP ACL restriction
  6. Save and verify
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

# ─── NEW COMMUNITY STRING SETTINGS ────────────────────────────────
# Replace with a strong, unique community string
# Format: alphanumeric + special chars, minimum 12 characters
NEW_RO_COMMUNITY = "S3cur3R0_2024!"   # <-- Replace with your chosen RO string
NEW_RO_PERMISSION = "RO"

# Set True to also configure a new RW community (if needed)
CONFIGURE_RW_COMMUNITY = False
NEW_RW_COMMUNITY = "S3cur3RW_2024!"  # <-- Replace if RW is needed

# Management hosts allowed to poll SNMP
SNMP_ALLOWED_HOSTS = [
    "10.0.0.10",      # <-- Replace with NMS/monitoring server IPs
    "10.0.0.11",
]

SNMP_ACL_NUMBER = "96"  # Dedicated ACL for this fix

# Set True to apply the fix
APPLY_FIX = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_41028_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_41028_{DEVICE['host']}_{TIMESTAMP}.txt"
    with open(backup_file, "w") as f:
        f.write(config)
    log(f"Config backed up to: {backup_file}")

def audit_snmp_communities(connection):
    log("── STEP 2: Auditing SNMP Community Strings ──")

    snmp_cfg = connection.send_command("show running-config | include snmp-server community")
    log("  Current SNMP community configuration:")
    log(snmp_cfg if snmp_cfg.strip() else "  No SNMP community strings configured.")

    communities = {}
    for line in snmp_cfg.splitlines():
        parts = line.strip().split()
        if "snmp-server" in parts and "community" in parts:
            idx = parts.index("community")
            if idx + 1 < len(parts):
                community = parts[idx + 1]
                permission = parts[idx + 2] if idx + 2 < len(parts) else "?"
                acl = parts[idx + 3] if idx + 3 < len(parts) else None
                communities[community] = {
                    "permission": permission,
                    "acl": acl
                }

    log(f"  Found {len(communities)} community string(s):")
    for comm, details in communities.items():
        acl_str = f"ACL: {details['acl']}" if details['acl'] else "NO ACL"
        masked = comm if comm not in ["public", "private"] else f"'{comm}' ❌ DEFAULT"
        log(f"    Community: {masked} | {details['permission']} | {acl_str}")

    # Flag critical issues
    if "public" in communities:
        perm = communities["public"]["permission"]
        if "RW" in perm:
            log("  ❌❌ CRITICAL: 'public' is READ-WRITE — immediate config change risk!")
        else:
            log("  ❌  'public' RO community confirmed — information disclosure risk.")
        log("  This community was confirmed responding by Nessus (EPSS: 0.9243).")

    if "private" in communities:
        log("  ❌  Default 'private' community also found — remove immediately.")

    return communities

def create_snmp_acl(connection):
    log("── STEP 3a: Creating SNMP ACL ──")
    commands = [f"no access-list {SNMP_ACL_NUMBER}"]
    for host in SNMP_ALLOWED_HOSTS:
        commands.append(f"access-list {SNMP_ACL_NUMBER} permit {host}")
        log(f"  Permitting NMS host: {host}")
    commands.append(f"access-list {SNMP_ACL_NUMBER} deny any log")

    output = connection.send_config_set(commands)
    log(output)
    log(f"  ✅ SNMP ACL {SNMP_ACL_NUMBER} created.")

def remove_default_communities_and_apply_new(connection, communities):
    log("── STEP 3b: Removing Default Communities & Applying New ──")

    commands = []

    # Remove 'public'
    if "public" in communities:
        commands.append("no snmp-server community public")
        log("  Removing 'public' community string.")

    # Remove 'private'
    if "private" in communities:
        commands.append("no snmp-server community private")
        log("  Removing 'private' community string.")

    # Add new RO community with ACL
    commands.append(
        f"snmp-server community {NEW_RO_COMMUNITY} {NEW_RO_PERMISSION} {SNMP_ACL_NUMBER}"
    )
    log(f"  Adding new RO community with ACL {SNMP_ACL_NUMBER}.")

    # Optionally add RW community
    if CONFIGURE_RW_COMMUNITY:
        commands.append(
            f"snmp-server community {NEW_RW_COMMUNITY} RW {SNMP_ACL_NUMBER}"
        )
        log(f"  Adding new RW community with ACL {SNMP_ACL_NUMBER}.")

    # Apply ACL to any remaining non-default communities
    for comm, details in communities.items():
        if comm not in ["public", "private"] and not details["acl"]:
            commands.append(
                f"snmp-server community {comm} {details['permission']} {SNMP_ACL_NUMBER}"
            )
            log(f"  Applying ACL to existing community: '{comm}'")

    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")

    log("  ✅ Default community strings removed.")
    log("  ✅ New community string applied with ACL restriction.")
    log("  ⚠️  Update all NMS/monitoring tools to the new community string.")
    log(f"  New RO community: [configured — stored in device running config]")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 41028 - CVE-1999-0517 - SNMP Default Community 'public'")
    log("")
    log("⚠️  EPSS 0.9243 — HIGHEST on entire device — 92% exploitation probability")
    log("⚠️  Nessus ACTIVELY CONFIRMED 'public' community responds (udp/161)")
    log("⚠️  'public' is the credential needed for Plugins 215126 and 266454")
    log("")
    log("Impact of 'public' community being exposed:")
    log("  - Information disclosure: full device config, routing tables, ARP, etc.")
    log("  - If RW: configuration changes via SNMP SET operations")
    log("  - Enables SNMP-based CVE exploitation (Plugins 215126, 266454)")
    log("")
    log("Fix (no IOS upgrade needed):")
    log("  1. 'no snmp-server community public'")
    log("  2. 'snmp-server community <strong_string> RO <ACL>'")
    log("  3. Update all NMS tools to new community string")
    log("  4. Verify old 'public' no longer responds:")
    log("     snmpwalk -v2c -c public <device-ip> system")
    log("")
    log("Plugins 215126 and 266454 also require SNMP credentials:")
    log("  Removing 'public' eliminates the default credential for those attacks too.")
    log("")
    log("This fix does NOT require IOS upgrade.")
    log("IOS upgrade still needed for Plugins 215126 and 266454 (code-level fix).")

def main():
    log("="*65)
    log("Fix Script - Plugin 41028 - SNMP Default Community 'public'")
    log("CVE-1999-0517 | EPSS 0.9243 — HIGHEST ON DEVICE")
    log("CONFIRMED ACTIVE FINDING — No IOS upgrade needed for this fix")
    log("="*65)

    log("")
    log("⚠️  PRE-FLIGHT CHECKLIST:")
    log("   □ NMS/monitoring team notified of community string change")
    log("   □ All monitoring tools identified that use 'public'")
    log("   □ New community string communicated to NMS team")
    log("   □ SNMP_ALLOWED_HOSTS configured with management IPs")
    log("   □ NEW_RO_COMMUNITY set to a strong unique string")
    log("   □ APPLY_FIX set to True when ready to proceed")
    log("")

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        communities = audit_snmp_communities(connection)

        if APPLY_FIX:
            if NEW_RO_COMMUNITY in ["S3cur3R0_2024!", "changeme", "public", "private"]:
                log("❌ ERROR: NEW_RO_COMMUNITY is still a placeholder or default value.")
                log("   Set a unique strong community string before running fix.")
                sys.exit(1)

            if not SNMP_ALLOWED_HOSTS or SNMP_ALLOWED_HOSTS == ["10.0.0.10", "10.0.0.11"]:
                log("⚠️  WARNING: SNMP_ALLOWED_HOSTS contains placeholder IPs.")
                log("   Update with actual NMS server IPs before applying.")

            create_snmp_acl(connection)
            remove_default_communities_and_apply_new(connection, communities)
        else:
            log("── FIX: Skipped (APPLY_FIX=False) ──")
            log("   Complete pre-flight checklist above.")
            log("   Set APPLY_FIX=True when ready to proceed.")
            log("   ⚠️  EPSS 0.9243 — fix this immediately after NMS coordination.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()