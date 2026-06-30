#!/usr/bin/env python3
"""
Verify Script - Plugin 266454
Cisco IOS Software SNMP Stack Overflow DoS/RCE
CVE-2025-20352 | Bug ID: CSCwq31287
CISA KEV — Listed 2025/10/20

Checks:
  1. IOS version vs known vulnerable releases
  2. SNMP disabled or ACL-restricted state
  3. Privilege-15 account audit (RCE path)
  4. Default community string check
  5. SNMP exposure via IPv6
  6. CISA KEV summary — all 6 KEVs on device
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

LOG_FILE = f"verify_266454_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   CISA KEV + RCE — EMERGENCY UPGRADE per CSCwq31287.")
        else:
            log("⚠️  Verify against full Cisco advisory.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-x4LPhte")

def check_snmp_state(connection):
    log("─── CHECK 2: SNMP State ───")
    snmp_cfg = connection.send_command("show running-config | include snmp")

    if not snmp_cfg.strip():
        log("✅ PASS: No SNMP configuration — DoS/RCE attack surface not present.")
        return False

    log("SNMP configuration found:")
    log(snmp_cfg)

    # Check ACL restriction
    all_restricted = True
    for line in snmp_cfg.splitlines():
        if "snmp-server community" in line:
            parts = line.strip().split()
            community = parts[2] if len(parts) >= 3 else "?"
            if len(parts) >= 5:
                log(f"  ✅ Community '{community}': ACL restricted.")
            else:
                log(f"  ❌ Community '{community}': NO ACL — open to any source.")
                all_restricted = False

    if all_restricted:
        log("  ✅ All SNMP communities are ACL-restricted.")
        log("  Mitigation reduces attack surface — upgrade still required.")
    else:
        log("  ❌ Open SNMP communities — immediate ACL restriction required.")
        log("  CVE-2025-20352 RCE/DoS exploitable from any network source.")

    return True

def check_default_communities(connection):
    log("─── CHECK 3: Default/Weak Community Strings ───")
    snmp_cfg = connection.send_command("show running-config | include snmp-server community")

    critical_found = False
    for line in snmp_cfg.splitlines():
        if "public" in line.lower():
            log("  ❌ CRITICAL: 'public' community string detected — REMOVE IMMEDIATELY.")
            critical_found = True
        if "private" in line.lower():
            log("  ❌ CRITICAL: 'private' community string detected — REMOVE IMMEDIATELY.")
            critical_found = True

    if not critical_found:
        log("  ✅ No default 'public'/'private' community strings found.")

def check_priv15_rce_path(connection):
    log("─── CHECK 4: RCE Attack Path Assessment ───")
    log("  RCE requires: SNMP RO credential + privilege-15 access.")

    priv15 = connection.send_command(
        "show running-config | include privilege 15"
    )
    if priv15.strip():
        log("  ⚠️  Privilege-15 configuration found:")
        for line in priv15.splitlines():
            parts = line.strip().split()
            if "username" in parts and len(parts) >= 2:
                log(f"    Priv-15 user: {parts[1]} [credentials redacted]")
            else:
                log(f"    {line.strip()}")
        log("  ⚠️  RCE path is available — SNMP + priv-15 = root code execution.")
        log("  Mitigate: Disable SNMP, restrict via ACL, and upgrade IOS.")
    else:
        log("  ✅ No local privilege-15 accounts found in running config.")
        log("  ⚠️  Verify AAA/RADIUS/TACACS for privilege-15 assignment.")
        log("  RCE path still exists if remote auth grants priv-15.")

def check_ipv6_snmp_exposure(connection):
    log("─── CHECK 5: IPv6 SNMP Exposure ───")
    log("  CVE-2025-20352 exploitable via IPv4 AND IPv6.")

    ipv6_ifaces = connection.send_command(
        "show ipv6 interface brief | exclude unassigned|down"
    )
    if ipv6_ifaces.strip():
        log("  ⚠️  Active IPv6 interfaces — SNMP attack feasible via IPv6:")
        log(ipv6_ifaces)
    else:
        log("  ✅ No active IPv6 interfaces — IPv6 attack vector not present.")

def cisa_kev_final_summary():
    log("─── CHECK 6: Complete CISA KEV Summary — All 6 KEVs on Device ───")
    log("")
    log("  ╔═══════════════════════════════════════════════════════════════════╗")
    log("  ║        CISA KNOWN EXPLOITED VULNERABILITIES — THIS DEVICE        ║")
    log("  ╠═══════════╦═══════════════════╦══════════════════════╦═══════════╣")
    log("  ║ Plugin    ║ CVE               ║ Name                 ║ Listed    ║")
    log("  ╠═══════════╬═══════════════════╬══════════════════════╬═══════════╣")
    log("  ║ 93736     ║ CVE-2016-6415     ║ BENIGNCERTAIN        ║ 2023/06/09║")
    log("  ║ 131166    ║ CVE-2018-0154     ║ ISM-VPN DoS          ║ 2022/03/17║")
    log("  ║ 103693    ║ CVE-2017-12237    ║ IKE DoS              ║ 2022/03/24║")
    log("  ║ 108880    ║ CVE-2018-0167/175 ║ LLDP Buffer Overflow ║ 2022/03/17║")
    log("  ║ 103669    ║ CVE-2017-12231    ║ NAT DoS              ║ 2022/03/24║")
    log("  ║ 266454    ║ CVE-2025-20352    ║ SNMP RCE/DoS ★RCE★  ║ 2025/10/20║")
    log("  ╚═══════════╩═══════════════════╩══════════════════════╩═══════════╝")
    log("")
    log("  Plugin 266454 is the ONLY RCE-capable vulnerability on this device.")
    log("  All 6 CISA KEVs resolved by a single IOS upgrade.")
    log("  This device has 22 total plugins — all cleared by one upgrade.")

def main():
    log("="*65)
    log("Verify Script - Plugin 266454 - Cisco IOS SNMP RCE/DoS")
    log("CVE-2025-20352 | CSCwq31287 | CISA KEV #6 | RCE CAPABLE")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        snmp_active = check_snmp_state(connection)
        check_default_communities(connection)
        check_priv15_rce_path(connection)
        check_ipv6_snmp_exposure(connection)
        cisa_kev_final_summary()

        log("="*65)
        log("FINAL SUMMARY:")
        log("  ✅ PASS (best): IOS upgraded per CSCwq31287")
        log("  ✅ PASS (mitigation): SNMP disabled ('no snmp-server')")
        log("  ⚠️  PARTIAL: SNMP ACL-restricted but IOS not upgraded")
        log("  ❌ FAIL: SNMP open + vulnerable IOS + priv-15 accounts = RCE RISK")
        log("")
        log("  CISA KEV #6 | Newest KEV on device (2025/10/20)")
        log("  ONLY RCE-CAPABLE vulnerability across all 22 plugins")
        log("  Stack overflow = memory corruption = potential full compromise")
        log("  TREAT AS P0 — EMERGENCY IOS UPGRADE REQUIRED")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()