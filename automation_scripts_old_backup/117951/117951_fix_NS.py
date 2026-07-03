#!/usr/bin/env python3
"""
Fix Script - Plugin 117951
Cisco IOS Software OSPFv3 DoS Vulnerability
CVE-2018-0466 | Bug ID: CSCuy82806

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check OSPFv3 configuration state
  4. Audit OSPFv3 authentication
  5. Check OSPFv3 neighbors
  6. Generate remediation report

KEY NOTES:
  - AV:A — Adjacent attack only (same network segment)
  - OSPFv3 = OSPF for IPv6 (distinct from OSPFv2 for IPv4)
  - OSPFv3 NOT common on standard branch routers
  - OSPFv3 authentication uses IPsec (NOT MD5 like OSPFv2)
  - Detection is VERSION-BASED ONLY
  - Full fix = IOS upgrade per CSCuy82806
  - Also see Plugin 131394 (OSPFv2 LSA) — different OSPF protocol
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
LOG_FILE = f"fix_117951_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_117951_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-ospfv3-dos")

def check_ospfv3_config(connection):
    log("── STEP 3: Checking OSPFv3 Configuration ──")

    # OSPFv3 process
    ospfv3_cfg = connection.send_command("show running-config | section ipv6 router ospf")
    if ospfv3_cfg.strip():
        log("  OSPFv3 process configured:")
        log(ospfv3_cfg)
        log("  ⚠️  OSPFv3 active — CVE-2018-0466 may apply.")
    else:
        log("  No 'ipv6 router ospf' section found.")

    # Also check for ospfv3 keyword
    ospfv3_alt = connection.send_command("show running-config | include ospfv3|ipv6 ospf")
    if ospfv3_alt.strip():
        log("  Additional OSPFv3 config lines:")
        log(ospfv3_alt)

    ospfv3_configured = bool(ospfv3_cfg.strip() or ospfv3_alt.strip())

    if not ospfv3_configured:
        log("  ✅ OSPFv3 not configured.")
        log("  CVE-2018-0466 not applicable — mark as 'Not Applicable'.")
    else:
        log("  ⚠️  OSPFv3 is active — adjacent attacker could cause DoS.")

    return ospfv3_configured

def check_ospfv3_process(connection):
    log("── STEP 4: OSPFv3 Process State ──")
    ospfv3_process = connection.send_command("show ipv6 ospf")
    if ospfv3_process.strip() and "%" not in ospfv3_process:
        log("  OSPFv3 process info:")
        log(ospfv3_process[:500] if len(ospfv3_process) > 500 else ospfv3_process)
    else:
        log("  No OSPFv3 process output — may not be running.")

def check_ospfv3_authentication(connection):
    log("── STEP 5: OSPFv3 Authentication Audit ──")
    log("  Note: OSPFv3 uses IPsec for authentication (different from OSPFv2 MD5)")

    # OSPFv3 uses area encryption/authentication
    auth_cfg = connection.send_command(
        "show running-config | include area.*encryption|area.*authentication|ipv6 ospf authentication"
    )
    if auth_cfg.strip():
        log("  OSPFv3 authentication/encryption config:")
        log(auth_cfg)
        if "ipsec" in auth_cfg.lower() or "sha" in auth_cfg.lower() or "md5" in auth_cfg.lower():
            log("  ✅ OSPFv3 IPsec authentication configured.")
        else:
            log("  ⚠️  Auth config present but type unclear.")
    else:
        log("  ⚠️  No OSPFv3 authentication configured.")
        log("  OSPFv3 DoS attack (CVE-2018-0466) feasible from adjacent attacker.")
        log("")
        log("  To add OSPFv3 IPsec authentication:")
        log("  ipv6 router ospf <process-id>")
        log("    area <area-id> authentication ipsec spi <value> sha1 <key>")

def check_ospfv3_neighbors(connection):
    log("── STEP 6: OSPFv3 Neighbor State ──")
    neighbors = connection.send_command("show ipv6 ospf neighbor")
    if neighbors.strip() and "%" not in neighbors:
        log("  OSPFv3 neighbors:")
        log(neighbors)
        full_count = neighbors.count("FULL")
        log(f"  Neighbors in FULL state: {full_count}")
        log("  ⚠️  Adjacent neighbors are potential attack sources.")
    else:
        log("  ✅ No OSPFv3 neighbors — protocol isolated or not active.")

def check_ipv6_routing(connection):
    log("── STEP 7: IPv6 Routing Context ──")
    ipv6_routes = connection.send_command("show ipv6 route ospf")
    if ipv6_routes.strip() and "%" not in ipv6_routes:
        log("  OSPFv3 IPv6 routes in table:")
        lines = ipv6_routes.splitlines()[:10]
        log("\n".join(lines))
        log(f"  OSPFv3 contributing to IPv6 routing table.")
    else:
        log("  No OSPFv3 routes in IPv6 routing table.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 117951 - CVE-2018-0466 - Cisco IOS OSPFv3 DoS")
    log("")
    log("Context:")
    log("  - AV:A — Adjacent only (same network segment)")
    log("  - OSPFv3 = IPv6 OSPF (less common than OSPFv2)")
    log("  - Not default on standard branch routers")
    log("  - VPR 3.6 — moderate priority")
    log("")
    log("OSPF plugins on this device:")
    log("  Plugin 131394 (CVE-2017-6770) — OSPFv2 LSA Manipulation")
    log("    → IPsec routing manipulation, C:L/I:L, very low risk")
    log("  Plugin 117951 (CVE-2018-0466) — OSPFv3 DoS")
    log("    → DoS via adjacent attack, A:H, this plugin")
    log("  Both resolved by same IOS upgrade.")
    log("")
    log("Mitigation: OSPFv3 IPsec authentication")
    log("  ipv6 router ospf <id>")
    log("    area <id> authentication ipsec spi <value> sha1 <key>")
    log("  Must match on all OSPFv3 neighbors")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCuy82806")
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
    log("Fix Script - Plugin 117951 - Cisco IOS OSPFv3 DoS")
    log("CVE-2018-0466 | CSCuy82806 | AV:A | VPR 3.6")
    log("OSPFv3 (IPv6 OSPF) — verify if configured")
    log("="*65)

    try:
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        backup_config(connection)
        collect_ios_version(connection)
        ospfv3_configured = check_ospfv3_config(connection)

        if ospfv3_configured:
            check_ospfv3_process(connection)
            check_ospfv3_authentication(connection)
            check_ospfv3_neighbors(connection)
            check_ipv6_routing(connection)
        else:
            log("OSPFv3 not configured — mark as 'Not Applicable'.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()