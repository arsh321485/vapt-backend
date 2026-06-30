#!/usr/bin/env python3
"""
Verify Script - Plugin 183215
Cisco IOS Software GET VPN Out of Bounds Write
CVE-2023-20109 | Bug IDs: CSCwe14195, CSCwe24118, CSCwf49531
CISA KEV — Listed 2023/10/31

Checks:
  1. IOS version vs known vulnerable releases
  2. GET VPN/GDOI configured state
  3. Device role (key server vs group member)
  4. GDOI rekey health post-upgrade
  5. CISA KEV final summary — all 7 KEVs on device
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

VULNERABLE_VERSIONS = [
    "15.4(3)M5", "15.4(3)M4", "15.4(3)M3",
    "15.4(2)T4", "15.3(3)M8", "15.2(4)M10",
    "15.6(1)T", "15.5(3)M", "15.7(3)M",
    "16.9.1", "16.12.1", "17.3.1",
]

LOG_FILE = f"verify_183215_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("❌ FAIL: Vulnerable IOS version.")
            log("   CISA KEV — Upgrade IMMEDIATELY per CSCwe14195/CSCwe24118/CSCwf49531.")
        else:
            log("⚠️  Verify against full Cisco advisory.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-getvpn-rce-g8qR68sx")

def check_getvpn_state(connection):
    log("─── CHECK 2: GET VPN / GDOI State ───")
    gdoi_cfg = connection.send_command("show running-config | include gdoi")
    if not gdoi_cfg.strip():
        log("✅ No GDOI/GET VPN configuration found.")
        log("   CVE-2023-20109 not applicable — mark as 'Not Applicable'.")
        return False
    log("⚠️  GDOI/GET VPN configured:")
    log(gdoi_cfg)
    return True

def check_device_role(connection):
    log("─── CHECK 3: GET VPN Device Role ───")
    full_cfg = connection.send_command("show running-config | section crypto gdoi group")
    if "server local" in full_cfg:
        log("⚠️  KEY SERVER role — highest priority for upgrade in GET VPN topology.")
        log("   Key server compromise enables attacks on ALL group members.")
    elif "server" in full_cfg:
        log("  GROUP MEMBER role — attack requires compromised/attacker-controlled KS.")
    else:
        log("  Role undetermined — review GDOI group config.")

def check_gdoi_health(connection):
    log("─── CHECK 4: GDOI Post-Upgrade Health ───")
    gdoi = connection.send_command("show crypto gdoi")
    if gdoi.strip() and "%" not in gdoi:
        log("GDOI runtime state:")
        log(gdoi[:400] if len(gdoi) > 400 else gdoi)
        if "REGISTERED" in gdoi or "Active" in gdoi:
            log("✅ GDOI operational post-upgrade.")
        else:
            log("⚠️  GDOI state unclear — investigate rekey operations.")
    else:
        log("No GDOI runtime output — GET VPN may not be active.")

def final_kev_summary():
    log("─── CHECK 5: COMPLETE CISA KEV SUMMARY — ALL 7 KEVs ───")
    log("")
    log("  ╔══════════════════════════════════════════════════════════════════════╗")
    log("  ║      ALL CISA KNOWN EXPLOITED VULNERABILITIES — THIS DEVICE         ║")
    log("  ╠═══════════╦════════════════════╦═════════════════════╦══════════════╣")
    log("  ║ Plugin    ║ CVE                ║ Name                ║ KEV Listed   ║")
    log("  ╠═══════════╬════════════════════╬═════════════════════╬══════════════╣")
    log("  ║ 93736     ║ CVE-2016-6415      ║ BENIGNCERTAIN       ║ 2023/06/09   ║")
    log("  ║ 131166    ║ CVE-2018-0154      ║ ISM-VPN DoS         ║ 2022/03/17   ║")
    log("  ║ 103693    ║ CVE-2017-12237     ║ IKE DoS             ║ 2022/03/24   ║")
    log("  ║ 108880    ║ CVE-2018-0167/0175 ║ LLDP Buffer OvFlow  ║ 2022/03/17   ║")
    log("  ║ 103669    ║ CVE-2017-12231     ║ NAT DoS             ║ 2022/03/24   ║")
    log("  ║ 266454    ║ CVE-2025-20352     ║ SNMP RCE/DoS        ║ 2025/10/20   ║")
    log("  ║ 183215    ║ CVE-2023-20109     ║ GET VPN OOB Write   ║ 2023/10/31   ║")
    log("  ╚═══════════╩════════════════════╩═════════════════════╩══════════════╝")
    log("")
    log("  All 7 CISA KEVs resolved by a SINGLE IOS upgrade.")
    log("  TWO plugins with RCE potential: 266454 (SNMP) and 183215 (GET VPN)")

def main():
    log("="*65)
    log("Verify Script - Plugin 183215 - Cisco IOS GET VPN OOB Write")
    log("CVE-2023-20109 | CISA KEV #7 | VPR 7.4 | RCE Potential")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        getvpn_active = check_getvpn_state(connection)
        if getvpn_active:
            check_device_role(connection)
            check_gdoi_health(connection)
        final_kev_summary()

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: IOS upgraded per CSCwe14195/CSCwe24118/CSCwf49531")
        log("  ✅ PASS (alt): GET VPN not configured — Not Applicable")
        log("  ❌ FAIL: GET VPN active + vulnerable IOS + no upgrade")
        log("")
        log("  CISA KEV #7 | VPR 7.4 | RCE via OOB Write")
        log("  GET VPN not default — first confirm if deployed")
        log("  Key server role = highest priority for upgrade")
        log("  Re-scan with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()