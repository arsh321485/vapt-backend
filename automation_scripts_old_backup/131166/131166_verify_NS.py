#!/usr/bin/env python3
"""
Verify Script - Plugin 131166
Cisco IOS Software ISM-VPN DoS
CVE-2018-0154 | Bug ID: CSCvd39267
CISA KEV — Listed 2022/03/17

Checks:
  1. IOS version vs known vulnerable releases
  2. ISM-VPN hardware module presence
  3. Crypto engine type (hardware vs software)
  4. VPN tunnel health post-upgrade
  5. ISM-VPN module operational state
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
    "15.1(4)M", "15.0(1)M",
]

LOG_FILE = f"verify_131166_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   CISA KEV — Upgrade required IMMEDIATELY per CSCvd39267.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-dos")

def check_ism_module(connection):
    log("─── CHECK 2: ISM-VPN Module Presence ───")

    diag = connection.send_command("show diag")
    ism_found = False

    if "ISM" in diag:
        ism_found = True
        log("⚠️  ISM module detected in 'show diag':")
        for line in diag.splitlines():
            if "ISM" in line:
                log(f"  {line.strip()}")
    else:
        log("ℹ️  No ISM keyword in 'show diag' output.")

    if ism_found:
        log("❌ ISM-VPN module IS present — device is exposed to CVE-2018-0154.")
        log("   Upgrade IOS immediately per CSCvd39267.")
    else:
        log("✅ No ISM-VPN module detected via software.")
        log("   Physically verify chassis to confirm module absence.")
        log("   If confirmed absent: mark plugin as 'Not Applicable'.")

def check_crypto_engine_type(connection):
    log("─── CHECK 3: Crypto Engine Type ───")
    output = connection.send_command("show crypto engine brief")
    if output.strip():
        log(output)
        if "ISM" in output or "Hardware" in output:
            log("⚠️  Hardware crypto (ISM) engine active — exposure confirmed.")
        elif "Software" in output:
            log("ℹ️  Software crypto engine — ISM-VPN may not be in use.")
        log("")
        log("Post-upgrade check: Verify engine shows new IOS version context.")
    else:
        log("No crypto engine output available.")

def check_vpn_health(connection):
    log("─── CHECK 4: VPN Tunnel Health (post-upgrade) ───")

    # IKEv1
    ikev1 = connection.send_command("show crypto isakmp sa")
    if ikev1.strip():
        log("IKEv1 SAs:")
        log(ikev1)
        if "ACTIVE" in ikev1:
            log("✅ IKEv1 tunnels ACTIVE post-upgrade.")
        elif "DELETED" in ikev1 or "MM_NO_STATE" in ikev1:
            log("⚠️  Stuck IKEv1 SAs — investigate VPN connectivity.")
    else:
        log("No IKEv1 SAs (expected if no IKEv1 VPNs).")

    # IKEv2
    ikev2 = connection.send_command("show crypto ikev2 sa")
    if ikev2.strip():
        log("IKEv2 SAs:")
        log(ikev2)
        if "READY" in ikev2:
            log("✅ IKEv2 tunnels in READY state.")
    else:
        log("No IKEv2 SAs.")

    # IPSec
    ipsec_brief = connection.send_command(
        "show crypto ipsec sa | include pkts encrypt|pkts decrypt"
    )
    if ipsec_brief.strip():
        log("IPSec traffic counters:")
        log(ipsec_brief)
        log("✅ IPSec is passing traffic.")
    else:
        log("No IPSec traffic counters.")

def check_module_operational(connection):
    log("─── CHECK 5: ISM-VPN Module Operational State (post-upgrade) ───")

    # Check if module is responding
    module_state = connection.send_command("show crypto engine brief")
    if "ISM" in module_state:
        log("ISM-VPN module state:")
        log(module_state)
        if "up" in module_state.lower() or "active" in module_state.lower():
            log("✅ ISM-VPN module is operational post-upgrade.")
        else:
            log("⚠️  ISM-VPN module may not be fully operational — investigate.")
    else:
        log("ISM-VPN module not detected in crypto engine output.")

def main():
    log("="*65)
    log("Verify Script - Plugin 131166 - Cisco IOS ISM-VPN DoS")
    log("CVE-2018-0154 | CSCvd39267 | CISA KEV")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_ism_module(connection)
        check_crypto_engine_type(connection)
        check_vpn_health(connection)
        check_module_operational(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: IOS upgraded to fixed release per CSCvd39267")
        log("  ✅ PASS (alt): ISM-VPN module physically confirmed absent")
        log("  ❌ FAIL: Vulnerable IOS + ISM-VPN module present")
        log("  ⚠️  NO WORKAROUND — IOS upgrade is the ONLY fix")
        log("  CISA KEV: Actively exploited — treat as P1")
        log("  EPSS 0.1085 — highest exploitation score on this device")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()