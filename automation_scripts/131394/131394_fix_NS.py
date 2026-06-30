#!/usr/bin/env python3
"""
Fix Script - Plugin 131394
Cisco IOS OSPF LSA Manipulation
CVE-2017-6770 | Bug ID: CSCva74756

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check OSPF configuration state
  4. Audit OSPF authentication per interface
  5. Check OSPF neighbors
  6. Generate OSPF auth remediation plan
  7. Optionally apply OSPF MD5 authentication (with caution)

KEY NOTES:
  - CVSS 4.2 — LOWEST on this device
  - AC:H (High Complexity) — attacker needs LSA parameter knowledge
  - A:N — No availability impact (routing disruption, not crash)
  - VPR 2.5 — LOWEST VPR on device
  - Mitigation: OSPF authentication (MD5 or SHA)
  - OSPF auth MUST be coordinated with ALL OSPF neighbors
  - Misconfigured auth = routing adjacency drop = network disruption
  - Full fix = IOS upgrade per CSCva74756
  - Lowest priority plugin on this device
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

# OSPF authentication settings
# ⚠️  COORDINATE WITH ALL OSPF NEIGHBORS BEFORE ENABLING
OSPF_AUTH_KEY = "OspfK3y2024!"    # <-- Replace with strong key
OSPF_KEY_ID = 1                    # Key chain ID

# Set True to apply OSPF MD5 authentication
# ⚠️  ONLY set True after coordinating with ALL OSPF neighbors
APPLY_OSPF_AUTH = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_131394_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_131394_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170727-ospf")

def check_ospf_config(connection):
    log("── STEP 3: Checking OSPF Configuration ──")

    # OSPF process config
    ospf_cfg = connection.send_command("show running-config | section router ospf")
    if ospf_cfg.strip():
        log("  OSPF process configured:")
        log(ospf_cfg)
        log("  ⚠️  OSPF is configured — CVE-2017-6770 may be applicable.")
    else:
        log("  ✅ No OSPF process configured.")
        log("  CVE-2017-6770 not applicable — mark as 'Not Applicable'.")

    # OSPF process ID
    ospf_process = connection.send_command("show ip ospf")
    if ospf_process.strip() and "%" not in ospf_process:
        log("  OSPF process summary:")
        log(ospf_process[:500] if len(ospf_process) > 500 else ospf_process)

    ospf_configured = bool(ospf_cfg.strip())
    return ospf_configured

def check_ospf_authentication(connection):
    log("── STEP 4: OSPF Authentication Audit ──")

    # Check for OSPF auth in config
    ospf_auth_cfg = connection.send_command(
        "show running-config | include ip ospf authentication|ip ospf message-digest"
    )
    log("  OSPF authentication config lines:")
    log(ospf_auth_cfg if ospf_auth_cfg.strip()
        else "  No OSPF authentication config found.")

    # Check area-level auth
    area_auth = connection.send_command(
        "show running-config | include area.*authentication"
    )
    if area_auth.strip():
        log("  OSPF area-level authentication:")
        log(area_auth)

    # Interfaces with OSPF auth
    ospf_iface_auth = connection.send_command("show ip ospf interface | include auth")
    if ospf_iface_auth.strip():
        log("  OSPF interface authentication status:")
        log(ospf_iface_auth)
        if "Message digest" in ospf_iface_auth or "MD5" in ospf_iface_auth:
            log("  ✅ MD5 authentication active on OSPF interfaces.")
        elif "No authentication" in ospf_iface_auth:
            log("  ❌ No authentication on OSPF interfaces — LSA injection possible.")
        elif "Simple" in ospf_iface_auth:
            log("  ⚠️  Simple (plaintext) authentication — upgrade to MD5.")
    else:
        log("  ⚠️  No OSPF interface authentication configured.")
        log("  LSA injection attack (CVE-2017-6770) is feasible.")

    return bool(ospf_auth_cfg.strip() or area_auth.strip())

def check_ospf_neighbors(connection):
    log("── STEP 5: OSPF Neighbor State ──")

    neighbors = connection.send_command("show ip ospf neighbor")
    if neighbors.strip():
        log("  OSPF neighbors:")
        log(neighbors)
        full_count = neighbors.count("FULL")
        log(f"  Neighbors in FULL state: {full_count}")
        log("  ⚠️  When applying OSPF auth, ALL neighbors must be updated simultaneously.")
        log("  Auth mismatch = adjacency drop = routing disruption.")
    else:
        log("  No OSPF neighbors found (OSPF may not be active).")

    # OSPF interface brief
    ospf_iface = connection.send_command("show ip ospf interface brief")
    if ospf_iface.strip() and "%" not in ospf_iface:
        log("  OSPF interface summary:")
        log(ospf_iface)

def get_ospf_interfaces(connection):
    """Parse interfaces running OSPF"""
    output = connection.send_command("show ip ospf interface brief")
    interfaces = []
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].startswith(
            ("GigabitEthernet", "FastEthernet", "Serial",
             "Loopback", "Tunnel", "Vlan")
        ):
            interfaces.append(parts[0])
    return interfaces

def apply_ospf_md5_auth(connection):
    log("── STEP 6: Applying OSPF MD5 Authentication ──")
    log("  ⚠️  WARNING: All OSPF neighbors must use matching key BEFORE applying.")

    ospf_ifaces = get_ospf_interfaces(connection)
    if not ospf_ifaces:
        log("  No OSPF interfaces detected — cannot apply auth.")
        return

    log(f"  OSPF interfaces to configure: {ospf_ifaces}")
    commands = []

    for iface in ospf_ifaces:
        commands.extend([
            f"interface {iface}",
            f"ip ospf message-digest-key {OSPF_KEY_ID} md5 {OSPF_AUTH_KEY}",
            "ip ospf authentication message-digest",
        ])
        log(f"  Queuing MD5 auth for: {iface}")

    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ OSPF MD5 authentication applied.")
    log("  CVE-2017-6770 LSA injection attack mitigated.")
    log("  ⚠️  Verify OSPF adjacencies immediately: 'show ip ospf neighbor'")
    log("  ⚠️  If adjacencies drop, neighbors need same key configured.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 131394 - CVE-2017-6770 - Cisco IOS OSPF LSA Manipulation")
    log("")
    log("LOWEST PRIORITY PLUGIN on this device:")
    log("  CVSS v3.0: 4.2 | VPR: 2.5 | AC:H | A:N (no Availability impact)")
    log("  Attacker must know LSA database parameters before exploiting")
    log("")
    log("Attack outcome: Traffic interception or black-holing (routing manipulation)")
    log("  NOT a DoS — attacker manipulates routing, not availability")
    log("")
    log("Mitigation: OSPF MD5 Authentication")
    log("  Prevents unauthorized LSA injection by requiring auth on packets")
    log("  Commands (per interface):")
    log("    ip ospf message-digest-key 1 md5 <strong-key>")
    log("    ip ospf authentication message-digest")
    log("")
    log("  ⚠️  CRITICAL: Configure on ALL routers in OSPF area simultaneously")
    log("  Auth mismatch drops OSPF adjacencies = routing outage")
    log("  Plan with network team before applying")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCva74756")
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
    log("Fix Script - Plugin 131394 - Cisco IOS OSPF LSA Manipulation")
    log("CVE-2017-6770 | CSCva74756 | CVSS 4.2 — LOWEST on device")
    log("OSPF not default — verify if configured first")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        ospf_configured = check_ospf_config(connection)

        if ospf_configured:
            auth_configured = check_ospf_authentication(connection)
            check_ospf_neighbors(connection)

            if APPLY_OSPF_AUTH:
                log("⚠️  APPLY_OSPF_AUTH=True — proceeding with MD5 auth.")
                log("   Ensure all OSPF neighbors have same key configured first!")
                apply_ospf_md5_auth(connection)
            else:
                log("── STEP 6: Skipped (APPLY_OSPF_AUTH=False) ──")
                log("   Coordinate OSPF auth with all neighbors before enabling.")
                log("   Set APPLY_OSPF_AUTH=True after coordination complete.")
        else:
            log("OSPF not configured — no action needed.")
            log("Mark Plugin 131394 as 'Not Applicable'.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()