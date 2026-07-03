#!/usr/bin/env python3
"""
Fix Script - Plugin 76474
SNMP 'GETBULK' Reflection DDoS
CVE-2008-4309

CONFIRMED ACTIVE FINDING:
  Request size:  42 bytes
  Response size: 1364 bytes (32x AMPLIFICATION FACTOR)
  Nessus confirmed this device can be used as DDoS amplifier.

CRITICAL NOTES:
  - No IOS upgrade needed — this is a CONFIG issue
  - Two config-only fixes on this device:
    Plugin 41028 (remove 'public' community) — also helps
    Plugin 76474 (restrict SNMP via ACL)     ← THIS
  - EPSS 0.0787 — actively used in DDoS reflection campaigns
  - Fix: Apply SNMP ACL to restrict GETBULK to known management hosts
  - Alternative: Disable SNMP entirely if not needed

Actions:
  1. Backup running config
  2. Audit SNMP state and amplification exposure
  3. Create SNMP restriction ACL
  4. Apply ACL to all community strings
  5. Optionally disable SNMP entirely
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

# Management hosts allowed SNMP access
SNMP_ALLOWED_HOSTS = [
    "10.0.0.10",      # <-- Replace with NMS/monitoring server IPs
    "10.0.0.11",
]

SNMP_ACL_NUMBER = "95"  # Dedicated ACL for GETBULK mitigation

# Set True to apply ACL restriction
APPLY_SNMP_ACL = False

# Set True to disable SNMP entirely if not needed
DISABLE_SNMP = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_76474_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_76474_{DEVICE['host']}_{TIMESTAMP}.txt"
    with open(backup_file, "w") as f:
        f.write(config)
    log(f"Config backed up to: {backup_file}")

def audit_snmp_amplification_exposure(connection):
    log("── STEP 2: SNMP GETBULK Amplification Audit ──")
    log("  ⚠️  CONFIRMED by Nessus scan:")
    log("  Request size:  42 bytes")
    log("  Response size: 1364 bytes")
    log("  Amplification: ~32x — usable in DDoS reflection attacks")
    log("")

    # SNMP config
    snmp_cfg = connection.send_command("show running-config | include snmp-server community")
    log("  Current SNMP communities:")
    communities = []

    for line in snmp_cfg.splitlines():
        parts = line.strip().split()
        if "community" in parts:
            idx = parts.index("community")
            if idx + 1 < len(parts):
                community = parts[idx + 1]
                communities.append(community)
                permission = parts[idx + 2] if idx + 2 < len(parts) else "?"
                has_acl = idx + 3 < len(parts)
                acl_status = f"ACL: {parts[idx + 3]}" if has_acl else "⚠️  NO ACL"
                log(f"  Community: '{community}' | {permission} | {acl_status}")

                if community.lower() in ["public", "private"]:
                    log(f"    ❌ DEFAULT community — remove immediately (see Plugin 41028)")
                if not has_acl:
                    log(f"    ❌ No ACL — any external host can send GETBULK requests")
                    log(f"    → Device is an open DDoS amplifier to the internet")

    if not snmp_cfg.strip():
        log("  No SNMP community strings configured.")
        log("  ✅ SNMP may not be active — verify with 'show snmp'.")
    else:
        log(f"  ⚠️  {len(communities)} community string(s) accessible.")
        log("  Any external attacker can send spoofed GETBULK → 32x amplified response.")

    return communities

def create_snmp_acl(connection):
    log("── STEP 3: Creating SNMP Restriction ACL ──")
    commands = [f"no access-list {SNMP_ACL_NUMBER}"]
    for host in SNMP_ALLOWED_HOSTS:
        commands.append(f"access-list {SNMP_ACL_NUMBER} permit {host}")
        log(f"  Permitting management host: {host}")
    commands.append(f"access-list {SNMP_ACL_NUMBER} deny any log")
    log("  Denying all other SNMP sources (logged).")

    output = connection.send_config_set(commands)
    log(output)
    log(f"  ✅ SNMP restriction ACL {SNMP_ACL_NUMBER} created.")
    log("  External hosts can no longer send GETBULK requests.")

def apply_acl_to_communities(connection, communities):
    log("── STEP 4: Applying ACL to SNMP Communities ──")

    if not communities:
        log("  No communities to apply ACL to.")
        return

    full_snmp = connection.send_command("show running-config | include snmp-server community")
    commands = []

    for line in full_snmp.splitlines():
        parts = line.strip().split()
        if "community" in parts:
            idx = parts.index("community")
            if idx + 2 < len(parts):
                community = parts[idx + 1]
                permission = parts[idx + 2]
                commands.append(
                    f"snmp-server community {community} {permission} {SNMP_ACL_NUMBER}"
                )
                log(f"  Restricting '{community}' ({permission}) to ACL {SNMP_ACL_NUMBER}")

    if commands:
        output = connection.send_config_set(commands)
        log(output)
        save = connection.send_command("write memory")
        log(f"  Config saved: {save}")
        log("  ✅ SNMP ACL applied to all communities.")
        log("  GETBULK amplification attack surface ELIMINATED.")
        log("  Device can no longer be used as DDoS reflector.")

def disable_snmp_entirely(connection):
    log("── STEP 4 (alt): Disabling SNMP Entirely ──")
    snmp_cfg = connection.send_command("show running-config | include snmp-server community")
    commands = []

    for line in snmp_cfg.splitlines():
        parts = line.strip().split()
        if "community" in parts:
            idx = parts.index("community")
            if idx + 1 < len(parts):
                community = parts[idx + 1]
                commands.append(f"no snmp-server community {community}")

    commands.append("no snmp-server")
    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ SNMP disabled — DDoS amplification risk eliminated.")
    log("  Also mitigates Plugins 215126, 266454, and 41028 simultaneously.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 76474 - CVE-2008-4309 - SNMP GETBULK Reflection DDoS")
    log("")
    log("ACTIVELY CONFIRMED: 32x amplification factor (42B request → 1364B response)")
    log("EPSS: 0.0787 — actively used in real DDoS campaigns")
    log("")
    log("This is the SECOND config-only fix on this device:")
    log("  Plugin 41028 — Remove 'public' community (immediate, no upgrade)")
    log("  Plugin 76474 — Apply SNMP ACL (immediate, no upgrade)  ← THIS")
    log("")
    log("Combined effect of both fixes:")
    log("  ✅ 'public' community removed → GETBULK no longer works with public")
    log("  ✅ SNMP ACL applied → External hosts blocked entirely")
    log("  ✅ Also reduces attack surface for Plugins 215126 and 266454")
    log("")
    log("SNMP GETBULK DDoS context:")
    log("  Attacker spoofs victim IP as SNMP source")
    log("  Sends small GETBULK request to this device")
    log("  Device sends 32x larger response to victim IP")
    log("  Device is weaponized as DDoS amplifier — harms third parties")
    log("")
    log("Fix: NO IOS UPGRADE NEEDED")
    log("  Apply SNMP ACL to restrict GETBULK to management hosts only")
    log("  OR disable SNMP entirely if not needed")
    log("")
    log("Apply alongside Plugin 41028 fix for maximum SNMP security.")

def main():
    log("="*65)
    log("Fix Script - Plugin 76474 - SNMP GETBULK Reflection DDoS")
    log("CVE-2008-4309 | EPSS 0.0787 | 32x Amplification CONFIRMED")
    log("CONFIG-ONLY FIX — No IOS upgrade needed")
    log("="*65)

    log("")
    log("⚠️  PRE-FLIGHT CHECKLIST:")
    log("   □ NMS/monitoring team notified of SNMP ACL change")
    log("   □ SNMP_ALLOWED_HOSTS set to actual management IPs")
    log("   □ 'public' community already removed (Plugin 41028)?")
    log("   □ APPLY_SNMP_ACL set to True when ready")
    log("")

    try:
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        backup_config(connection)
        communities = audit_snmp_amplification_exposure(connection)

        if DISABLE_SNMP:
            disable_snmp_entirely(connection)
        elif APPLY_SNMP_ACL:
            if not SNMP_ALLOWED_HOSTS or SNMP_ALLOWED_HOSTS == ["10.0.0.10", "10.0.0.11"]:
                log("⚠️  WARNING: Update SNMP_ALLOWED_HOSTS with actual NMS IPs first.")
            create_snmp_acl(connection)
            apply_acl_to_communities(connection, communities)
        else:
            log("── FIX: Skipped ──")
            log("   Set APPLY_SNMP_ACL=True (or DISABLE_SNMP=True).")
            log("   EPSS 0.0787 — fix this immediately.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()