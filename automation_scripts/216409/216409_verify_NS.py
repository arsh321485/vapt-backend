#!/usr/bin/env python3
"""
Verify Script - Plugin 216409
Cisco IOS Software IS-IS DoS
CVE-2024-20312 | Bug ID: CSCwf54007

Checks:
  1. IOS version vs known vulnerable releases
  2. IS-IS process state (running or removed)
  3. IS-IS neighbor adjacencies
  4. IS-IS LSDB health post-upgrade
  5. Routing table integrity after changes
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

VULNERABLE_VERSIONS = [
    "15.4(3)M5", "15.4(3)M4", "15.4(3)M3",
    "15.4(2)T4", "15.3(3)M8", "15.2(4)M10",
    "15.6(1)T", "15.5(3)M", "15.7(3)M",
    "16.9.1", "16.12.1", "17.3.1", "17.6.1",
]

LOG_FILE = f"verify_216409_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def check_ios_version(connection):
    log("─── CHECK 1: IOS Version ───")
    output = connection.send_command("show version")
    detected = None
    for line in output.splitlines():
        if "Version" in line and ("IOS" in line or "Software" in line):
            detected = line.strip()
            log(f"Detected: {detected}")
            break

    if detected:
        is_vuln = any(v in detected for v in VULNERABLE_VERSIONS)
        if is_vuln:
            log("❌ FAIL: Running a KNOWN VULNERABLE IOS version.")
            log("   Upgrade required per Cisco Bug CSCwf54007.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-isis-sGjyOUHX")

def check_isis_process_state(connection):
    log("─── CHECK 2: IS-IS Process State ───")
    isis_cfg = connection.send_command("show running-config | section router isis")

    if not isis_cfg.strip():
        log("✅ PASS: No IS-IS process configured.")
        log("   CVE-2024-20312 attack surface not applicable.")
        return False

    log("IS-IS process found in config:")
    log(isis_cfg)
    log("⚠️  IS-IS is configured — upgrade IOS to fix CVE-2024-20312.")
    return True

def check_isis_neighbors(connection):
    log("─── CHECK 3: IS-IS Neighbor Adjacencies ───")
    output = connection.send_command("show isis neighbors")

    if not output.strip() or "no neighbors" in output.lower():
        log("✅ No active IS-IS adjacencies.")
        log("   Without adjacency, CVE-2024-20312 cannot be exploited.")
        return

    log("IS-IS neighbors:")
    log(output)

    up_count = sum(1 for line in output.splitlines() if "UP" in line)
    init_count = sum(1 for line in output.splitlines() if "Init" in line)

    if up_count > 0:
        log(f"  ⚠️  {up_count} UP adjacency(ies) — attack conditions met for those neighbors.")
    if init_count > 0:
        log(f"  ℹ️  {init_count} neighbor(s) in Init state.")

    log("  Post-upgrade: Verify adjacencies reform and reach UP state.")

def check_isis_lsdb(connection):
    log("─── CHECK 4: IS-IS LSDB Health ───")
    output = connection.send_command("show isis database")

    if not output.strip() or "ISIS" not in output:
        log("✅ No IS-IS LSDB entries — IS-IS not actively exchanging topology.")
        return

    entry_count = len([l for l in output.splitlines() if "." in l and "LSP" not in l])
    log(f"  IS-IS LSDB has approximately {entry_count} entries.")

    # Check for overload bit
    overload = connection.send_command("show isis database | include Overload")
    if overload.strip():
        log(f"  ⚠️  Overload bit set: {overload.strip()}")
        log("  Device is advertising overload — may indicate recovery or config issue.")
    else:
        log("  ✅ No overload bit detected — IS-IS topology healthy.")

def check_routing_table_health(connection):
    log("─── CHECK 5: Routing Table Health ───")

    # Total route count
    route_sum = connection.send_command("show ip route summary")
    if route_sum.strip():
        log("IPv4 route summary:")
        log(route_sum)

    # IS-IS specific routes
    isis_routes = connection.send_command("show ip route isis")
    if isis_routes.strip() and "%" not in isis_routes:
        lines = isis_routes.splitlines()
        log(f"  IS-IS routes in table: {len(lines)} lines")
        log(f"  (First 10 lines shown)")
        log("\n".join(lines[:10]))
        log("  ✅ IS-IS routes present — adjacencies and LSDB exchange working.")
    else:
        log("  No IS-IS routes in IPv4 routing table.")

def main():
    log("="*65)
    log("Verify Script - Plugin 216409 - Cisco IOS IS-IS DoS")
    log("CVE-2024-20312 | CSCwf54007 | AV:Adjacent + Adjacency required")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        isis_present = check_isis_process_state(connection)
        if isis_present:
            check_isis_neighbors(connection)
            check_isis_lsdb(connection)
            check_routing_table_health(connection)
        else:
            log("IS-IS not configured — skipping neighbor/LSDB/route checks.")

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: No IS-IS configured, OR IOS upgraded per CSCwf54007")
        log("  ⚠️  PARTIAL: IS-IS disabled as mitigation but IOS not yet upgraded")
        log("  ❌ FAIL: IS-IS active + neighbors UP + vulnerable IOS version")
        log("")
        log("  ATTACK CONSTRAINTS (both required):")
        log("  1. L2-adjacent to device")
        log("  2. IS-IS adjacency formed with device")
        log("  → Very low practical exploitation risk")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()