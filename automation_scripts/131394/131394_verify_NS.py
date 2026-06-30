#!/usr/bin/env python3
"""
Verify Script - Plugin 131394
Cisco IOS OSPF LSA Manipulation
CVE-2017-6770 | Bug ID: CSCva74756

Checks:
  1. IOS version vs known vulnerable releases
  2. OSPF configured state
  3. OSPF authentication per interface
  4. OSPF neighbor adjacency health
  5. OSPF database integrity indicators
  6. Priority context — lowest priority plugin on device
"""

from netmiko import ConnectHandler
import datetime
import sys

# ─── CONFIGURATION ────────────────────────────────────────────────
DEVICE = {
    "device_type": "cisco_ios",
    "host": "192.168.1.1",
    "username": "admin",
    "password": "yourpassword",
    "secret": "yourenable",
    "port": 22,
    "timeout": 30,
}

VULNERABLE_VERSIONS = [
    "15.4(3)M5", "15.4(3)M4", "15.4(3)M3",
    "15.4(2)T4", "15.3(3)M8", "15.2(4)M10",
    "15.6(1)T", "15.5(3)M",
]

LOG_FILE = f"verify_131394_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per Cisco Bug CSCva74756.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170727-ospf")

def check_ospf_state(connection):
    log("─── CHECK 2: OSPF Configured State ───")
    ospf_cfg = connection.send_command("show running-config | section router ospf")

    if not ospf_cfg.strip():
        log("✅ PASS: OSPF not configured on this device.")
        log("   CVE-2017-6770 not applicable.")
        log("   Mark as 'Not Applicable'.")
        return False

    log("OSPF is configured:")
    log(ospf_cfg[:400] if len(ospf_cfg) > 400 else ospf_cfg)
    return True

def check_ospf_auth_state(connection):
    log("─── CHECK 3: OSPF Authentication Status ───")

    # Interface-level auth
    ospf_iface = connection.send_command("show ip ospf interface | include auth|Interface")
    if ospf_iface.strip():
        log("OSPF interface auth details:")
        log(ospf_iface[:600] if len(ospf_iface) > 600 else ospf_iface)

        if "Message digest" in ospf_iface:
            log("✅ MD5 authentication active — LSA injection mitigated.")
            return True
        elif "SHA" in ospf_iface:
            log("✅ SHA authentication active — strong OSPF security.")
            return True
        elif "Simple" in ospf_iface:
            log("⚠️  Simple (plaintext) auth — upgrade to MD5 or SHA.")
            return False
        elif "No authentication" in ospf_iface:
            log("❌ No OSPF authentication — CVE-2017-6770 LSA injection feasible.")
            return False
    else:
        log("⚠️  No OSPF interface auth data returned.")
        log("   Verify 'show ip ospf interface' output manually.")
        return False

def check_ospf_neighbors(connection):
    log("─── CHECK 4: OSPF Neighbor Health ───")
    neighbors = connection.send_command("show ip ospf neighbor")

    if not neighbors.strip():
        log("  No OSPF neighbors — OSPF may be isolated or not active.")
        return

    log("OSPF neighbor table:")
    log(neighbors)

    full = neighbors.count("FULL")
    two_way = neighbors.count("2WAY")
    exstart = neighbors.count("EXSTART")
    exchange = neighbors.count("EXCHANGE")

    log(f"  FULL adjacencies: {full}")
    if two_way or exstart or exchange:
        log(f"  ⚠️  Non-FULL states: 2WAY={two_way}, EXSTART={exstart}, EXCHANGE={exchange}")

    if full > 0:
        log("  ✅ OSPF adjacencies healthy — routing operational.")
    else:
        log("  ⚠️  No FULL adjacencies — investigate OSPF convergence.")

def check_ospf_database(connection):
    log("─── CHECK 5: OSPF Database Summary ───")
    output = connection.send_command("show ip ospf database summary")
    if output.strip() and "%" not in output:
        log("OSPF LSDB summary:")
        log(output[:400] if len(output) > 400 else output)
        log("  ℹ️  Review for unexpected/external LSA injections if suspicious.")
    else:
        log("  No OSPF LSDB data available.")

def priority_context():
    log("─── CHECK 6: Priority Context — Lowest Priority Plugin ───")
    log("")
    log("  Plugin 131394 is the LOWEST PRIORITY on this device:")
    log("")
    log("  CVSS v3.0: 4.2  (vs highest 8.8 on device)")
    log("  VPR:        2.5  (vs highest 7.4 on device)")
    log("  EPSS:     0.0052 (vs highest 0.9243 on device)")
    log("  AC:H            (attacker needs LSA parameter knowledge)")
    log("  A:N             (no availability/DoS impact — routing only)")
    log("  UI:R            (user interaction required for some scenarios)")
    log("")
    log("  Address only AFTER all other 28 plugins are resolved.")
    log("  IOS upgrade (planned for other critical plugins) also fixes this.")

def main():
    log("="*65)
    log("Verify Script - Plugin 131394 - Cisco IOS OSPF LSA Manipulation")
    log("CVE-2017-6770 | CSCva74756 | CVSS 4.2 | LOWEST priority on device")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        ospf_active = check_ospf_state(connection)

        if ospf_active:
            check_ospf_auth_state(connection)
            check_ospf_neighbors(connection)
            check_ospf_database(connection)
        else:
            log("OSPF not configured — skipping auth/neighbor/database checks.")

        priority_context()

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS (best): IOS upgraded per CSCva74756")
        log("  ✅ PASS (mitigation): OSPF MD5/SHA auth configured on all interfaces")
        log("  ✅ PASS (alt): OSPF not configured — Not Applicable")
        log("  ❌ FAIL: OSPF active + no auth + vulnerable IOS version")
        log("")
        log("  LOWEST CVSS/VPR/EPSS on device — address last")
        log("  IOS upgrade (planned for critical plugins) resolves this too")
        log("  OSPF auth requires neighbor coordination — plan carefully")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()