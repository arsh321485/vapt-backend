#!/usr/bin/env python3
"""
Fix Script - Plugin 91854
Cisco IOS Zone-Based Firewall Security Bypass
CVE-2014-2146 | Bug ID: CSCun94946

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check Zone-Based Firewall configuration
  4. Enumerate zones, zone-pairs, and policy-maps
  5. Assess ZBF traffic policy impact
  6. Optionally disable ZBF (Cisco-recommended workaround)
  7. Generate remediation report

KEY NOTES:
  - Cisco advisory EXPLICITLY mentions disabling ZBF as workaround
  - ZBF NOT default — requires explicit zone/zone-pair/policy config
  - Attack: spoofed traffic matching existing sessions bypasses ZBF
  - UI:R — User Interaction Required element
  - C:H — bypassing firewall exposes protected resources
  - A:N — No availability impact
  - 'Fix releases: See solution' — verify current fixed release
  - Full fix = IOS upgrade per CSCun94946
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

# Set True ONLY if ZBF is confirmed not the primary security control
# WARNING: Disabling ZBF removes ALL zone-based traffic inspection
DISABLE_ZBF = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_91854_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_91854_{DEVICE['host']}_{TIMESTAMP}.txt"
    with open(backup_file, "w") as f:
        f.write(config)
    log(f"Config backed up to: {backup_file}")

def collect_ios_version(connection):
    log("── STEP 2: IOS Version Collection ──")
    output = connection.send_command("show version")
    for line in output.splitlines():
        if "Cisco IOS Software" in line or "Version" in line:
            log(f"  {line.strip()}")
    log("  Installed: 15.4(3)M5 | Plugin output: 'Fix releases: See solution'")
    log("  Advisory: https://tools.cisco.com/security/center/viewAlert.x?alertId=39129")

def check_zbf_config(connection):
    log("── STEP 3: Checking Zone-Based Firewall Configuration ──")

    # Zone security definitions
    zones = connection.send_command("show running-config | section zone security")
    if zones.strip():
        log("  Security zones defined:")
        log(zones)
        log("  ⚠️  ZBF is configured — CVE-2014-2146 firewall bypass applicable.")
    else:
        log("  ✅ No 'zone security' sections found.")
        log("  ZBF not configured — CVE-2014-2146 not applicable.")
        log("  Mark as 'Not Applicable'.")

    # Zone-pair config
    zone_pair = connection.send_command(
        "show running-config | section zone-pair security"
    )
    if zone_pair.strip():
        log("  Zone-pairs configured:")
        log(zone_pair[:500] if len(zone_pair) > 500 else zone_pair)

    # Zone members (interface assignments)
    zone_members = connection.send_command(
        "show running-config | include zone-member security"
    )
    if zone_members.strip():
        log("  Zone member interfaces:")
        log(zone_members)

    zbf_configured = bool(zones.strip())
    return zbf_configured

def check_zone_runtime(connection):
    log("── STEP 4: ZBF Runtime State ──")

    # Show zone security runtime
    zone_runtime = connection.send_command("show zone security")
    if zone_runtime.strip() and "%" not in zone_runtime:
        log("  Zone security runtime:")
        log(zone_runtime[:600] if len(zone_runtime) > 600 else zone_runtime)

        # Count zones
        zone_count = zone_runtime.count("Zone-Name")
        log(f"  Security zones active: {zone_count}")
    else:
        log("  No 'show zone security' output — ZBF may not be active.")

    # Zone-pair stats
    zone_pair_stats = connection.send_command("show zone-pair security")
    if zone_pair_stats.strip() and "%" not in zone_pair_stats:
        log("  Zone-pair summary:")
        log(zone_pair_stats[:400] if len(zone_pair_stats) > 400 else zone_pair_stats)

def enumerate_zbf_policies(connection):
    log("── STEP 5: ZBF Policy-Map Enumeration ──")

    # Service-policy in zone-pairs
    policy_cfg = connection.send_command(
        "show running-config | include service-policy type inspect"
    )
    if policy_cfg.strip():
        log("  ZBF inspect policy-maps applied:")
        log(policy_cfg)

    # Inspect policy-maps
    inspect_policies = connection.send_command(
        "show running-config | section policy-map type inspect"
    )
    if inspect_policies.strip():
        log("  ZBF inspect policy-map definitions:")
        log(inspect_policies[:600] if len(inspect_policies) > 600 else inspect_policies)
        log("  ⚠️  Active ZBF inspection policy — disabling ZBF removes this protection.")

    # Class-maps
    class_maps = connection.send_command(
        "show running-config | section class-map type inspect"
    )
    if class_maps.strip():
        log("  ZBF class-map definitions:")
        log(class_maps[:400] if len(class_maps) > 400 else class_maps)

def assess_zbf_impact(connection):
    log("── STEP 6: ZBF Disable Impact Assessment ──")
    log("  ⚠️  WARNING: Disabling ZBF removes ALL zone-based security policy.")
    log("")

    # Check if any ACLs provide backup security
    acls = connection.send_command("show running-config | include ip access-group")
    if acls.strip():
        log("  Interface ACLs found (backup security layer):")
        log(acls)
        log("  ✅ Interface ACLs exist — some security remains if ZBF disabled.")
    else:
        log("  ⚠️  NO interface ACLs found.")
        log("  Disabling ZBF without ACLs leaves interfaces UNPROTECTED.")
        log("  Apply interface ACLs before disabling ZBF.")

    # Check zone-self for device protection
    self_zone = connection.send_command(
        "show running-config | include zone-pair.*self"
    )
    if self_zone.strip():
        log("  Zone-pair with 'self' zone found — ZBF protects device itself:")
        log(self_zone)
        log("  ⚠️  Disabling ZBF removes protection of device management plane.")

def disable_zbf(connection):
    log("── STEP 7: Disabling Zone-Based Firewall (DISABLE_ZBF=True) ──")
    log("  ⚠️⚠️  WARNING: This removes ALL ZBF security policy.")
    log("  Cisco advisory confirms this as the workaround for CVE-2014-2146.")

    # Get zone-pair names to remove
    zone_pair_cfg = connection.send_command(
        "show running-config | include zone-pair security"
    )
    commands = []

    # Remove zone-pair assignments
    for line in zone_pair_cfg.splitlines():
        parts = line.strip().split()
        if "zone-pair" in parts and "security" in parts:
            idx = parts.index("security")
            if idx + 1 < len(parts):
                zp_name = parts[idx + 1]
                commands.append(f"no zone-pair security {zp_name}")
                log(f"  Removing zone-pair: {zp_name}")

    # Remove zone-member from interfaces
    zone_members = connection.send_command(
        "show running-config | include zone-member security"
    )
    # Get parent interface context
    full_cfg = connection.send_command("show running-config")
    current_iface = None
    for line in full_cfg.splitlines():
        if line.startswith("interface "):
            current_iface = line.split("interface ")[1].strip()
        elif "zone-member security" in line and current_iface:
            commands.append(f"interface {current_iface}")
            commands.append("no zone-member security")
            log(f"  Removing zone-member from: {current_iface}")

    # Remove zone definitions
    zones_cfg = connection.send_command("show running-config | section zone security")
    for line in zones_cfg.splitlines():
        parts = line.strip().split()
        if parts and parts[0] == "zone" and "security" in parts:
            idx = parts.index("security")
            if idx + 1 < len(parts):
                zone_name = parts[idx + 1]
                commands.append(f"no zone security {zone_name}")
                log(f"  Removing zone: {zone_name}")

    if commands:
        output = connection.send_config_set(commands)
        log(output)
        save = connection.send_command("write memory")
        log(f"  Config saved: {save}")
        log("  ✅ Zone-Based Firewall disabled.")
        log("  CVE-2014-2146 bypass attack surface eliminated.")
        log("  ⚠️  Verify traffic still controlled via interface ACLs.")
        log("  ⚠️  Plan IOS upgrade to re-enable ZBF with fixed code.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 91854 - CVE-2014-2146 - Cisco IOS ZBF Security Bypass")
    log("")
    log("Attack: Spoofed traffic matching existing sessions bypasses ZBF inspection")
    log("  Attacker gains access to resources behind the firewall")
    log("  No authentication required — but UI:R (user interaction element)")
    log("  C:H — complete bypass of firewall protection")
    log("  A:N — no availability impact")
    log("")
    log("CISCO ADVISORY WORKAROUND: Disable Zone-Based Firewall")
    log("  'no zone security <name>'")
    log("  'no zone-pair security <name>'")
    log("  Remove zone-member from all interfaces")
    log("")
    log("⚠️  CRITICAL IMPACT WARNING:")
    log("  ZBF IS a security control — disabling it removes protection")
    log("  Apply interface ACLs before disabling ZBF")
    log("  Only disable if ZBF is not the primary security mechanism")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCun94946")
    log("  Plugin output: 'Fix releases: See solution'")
    log("  Verify specific fixed release at Cisco advisory link")
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
    log("  8. Re-enable ZBF with fixed code if needed")
    log("  9. Re-scan Nessus with valid credentials")

def main():
    log("="*65)
    log("Fix Script - Plugin 91854 - Cisco IOS ZBF Security Bypass")
    log("CVE-2014-2146 | CSCun94946 | CVSS 6.5 | C:H firewall bypass")
    log("Cisco workaround: Disable ZBF (assess impact first)")
    log("="*65)

    try:
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        backup_config(connection)
        collect_ios_version(connection)
        zbf_configured = check_zbf_config(connection)

        if zbf_configured:
            check_zone_runtime(connection)
            enumerate_zbf_policies(connection)
            assess_zbf_impact(connection)

            if DISABLE_ZBF:
                log("⚠️  DISABLE_ZBF=True — proceeding to remove ZBF configuration.")
                disable_zbf(connection)
            else:
                log("── STEP 7: Skipped (DISABLE_ZBF=False) ──")
                log("   Assess ZBF traffic impact before setting DISABLE_ZBF=True.")
                log("   Cisco advisory confirms this as the documented workaround.")
        else:
            log("ZBF not configured — mark Plugin 91854 as 'Not Applicable'.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()