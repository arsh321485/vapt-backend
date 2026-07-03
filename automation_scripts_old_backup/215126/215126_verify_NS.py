#!/usr/bin/env python3
"""
Verify Script - Plugin 215126
Cisco IOS Software SNMP DoS
CVE-2025-20169 through CVE-2025-20176 (8 CVEs)
Bug IDs: CSCwm79554-CSCwn08493 (9 total)

Checks:
  1. IOS version vs known vulnerable releases
  2. SNMP community string ACL restriction
  3. SNMPv3 configuration
  4. SNMP traffic statistics
  5. Best practice SNMP hardening status
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
    "15.6(1)T", "15.5(3)M", "15.7(3)M",
    "16.9.1", "16.12.1", "17.3.1", "17.6.1",
]

LOG_FILE = f"verify_215126_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per 9 Cisco Bug IDs (CSCwm79554..CSCwn08493).")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-sdxnSUcW")

def check_snmp_acl_restriction(connection):
    log("─── CHECK 2: SNMP Community ACL Restriction ───")
    snmp_cfg = connection.send_command("show running-config | include snmp-server community")

    if not snmp_cfg.strip():
        log("✅ No SNMP community strings configured.")
        log("   SNMPv1/v2c attack vector not present.")
        return

    all_have_acl = True
    for line in snmp_cfg.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            community = parts[2]
            if len(parts) >= 5:
                log(f"  ✅ Community '{community}': ACL '{parts[4]}' applied.")
            elif len(parts) == 4:
                log(f"  ⚠️  Community '{community}': No ACL — accessible from any source.")
                all_have_acl = False
            else:
                log(f"  ⚠️  Community '{community}': Minimal config — verify ACL.")
                all_have_acl = False

    if all_have_acl:
        log("  ✅ All SNMP communities have ACL restriction.")
        log("  Attack requires network position + valid community string.")
    else:
        log("  ❌ Some communities lack ACL — SNMP open to any source on network.")
        log("  Apply: 'snmp-server community <string> <RO/RW> <ACL>'")

def check_snmpv3(connection):
    log("─── CHECK 3: SNMPv3 Configuration ───")
    users = connection.send_command("show snmp user")

    if not users.strip() or "no such" in users.lower():
        log("  No SNMPv3 users configured.")
        log("  ℹ️  Consider migrating from v1/v2c to SNMPv3 auth+priv.")
        return

    log("  SNMPv3 users:")
    log(users[:400] if len(users) > 400 else users)

    # Check auth+priv (most secure)
    if "priv" in users.lower():
        log("  ✅ SNMPv3 users with privacy (encryption) configured.")
    elif "auth" in users.lower():
        log("  ⚠️  SNMPv3 auth-only (no encryption) — upgrade to auth+priv.")
    else:
        log("  ⚠️  SNMPv3 noauth configured — weakest SNMPv3 mode.")

def check_snmp_stats(connection):
    log("─── CHECK 4: SNMP Traffic Statistics ───")
    output = connection.send_command("show snmp")

    if output.strip():
        log(output[:500] if len(output) > 500 else output)
        # Look for bad community inputs (potential attack indicator)
        for line in output.splitlines():
            if "bad" in line.lower() or "unknown" in line.lower():
                log(f"  ℹ️  {line.strip()}")
    else:
        log("  No SNMP statistics available.")

def check_snmp_hardening(connection):
    log("─── CHECK 5: SNMP Hardening Best Practice Status ───")

    snmp_cfg = connection.send_command("show running-config | include snmp")

    checks = {
        "View-based access control": "snmp-server view" in snmp_cfg,
        "Group-based access control": "snmp-server group" in snmp_cfg,
        "Contact configured": "snmp-server contact" in snmp_cfg,
        "Location configured": "snmp-server location" in snmp_cfg,
        "Trap receiver configured": "snmp-server host" in snmp_cfg,
        "RW community present": "RW" in snmp_cfg or "read-write" in snmp_cfg.lower(),
    }

    for check, result in checks.items():
        status = "✅" if result else "ℹ️ "
        log(f"  {status} {check}: {'Yes' if result else 'No'}")

    if checks["RW community present"]:
        log("  ⚠️  Read-Write SNMP community detected — remove if not required.")
        log("     RW community allows config changes via SNMP.")

    # Check for default/weak community strings
    if "public" in snmp_cfg.lower() or "private" in snmp_cfg.lower():
        log("  ❌ Default community string 'public' or 'private' detected!")
        log("     Change immediately — default strings are widely known.")

def main():
    log("="*65)
    log("Verify Script - Plugin 215126 - Cisco IOS SNMP DoS")
    log("CVE-2025-20169..20176 | 8 CVEs | 9 Bug IDs")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_snmp_acl_restriction(connection)
        check_snmpv3(connection)
        check_snmp_stats(connection)
        check_snmp_hardening(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS (best): IOS upgraded per all 9 bug IDs")
        log("  ✅ PASS (mitigation): SNMP disabled OR all communities ACL-restricted")
        log("  ⚠️  PARTIAL: ACL applied but IOS not yet upgraded")
        log("  ❌ FAIL: SNMP open + vulnerable IOS + default/no community ACLs")
        log("")
        log("  Requires AUTHENTICATED SNMP access — ACL restriction highly effective")
        log("  8 CVEs / 9 Bug IDs — largest CVE set on this device")
        log("  Most recently updated (2025/09/15) — check for new fixed releases")
        log("  Remove default community strings ('public'/'private') immediately")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()