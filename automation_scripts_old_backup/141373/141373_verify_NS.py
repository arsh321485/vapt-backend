#!/usr/bin/env python3
"""
Verify Script - Plugin 141373
Cisco IOS Software ISDN Q.931 DoS
CVE-2020-3511 | Bug ID: CSCvr57760

Checks:
  1. IOS version vs known vulnerable releases
  2. ISDN interface state (up/shutdown)
  3. ISDN Layer 1/2/3 status
  4. Active ISDN calls
  5. Q.931 switch type config
  6. Cross-reference Plugin 129812 status
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
    "16.9.1", "16.12.1",
]

LOG_FILE = f"verify_141373_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per Cisco Bug CSCvr57760.")
            log("   Same upgrade also fixes Plugin 129812 (CSCuz74957).")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-isdn-q931-dos-67eUZBTf")

def check_isdn_interface_state(connection):
    log("─── CHECK 2: ISDN Interface State ───")
    output = connection.send_command("show ip interface brief | include BRI")

    if not output.strip():
        log("✅ No BRI interfaces found — ISDN Q.931 exposure not applicable.")
        return

    log("BRI interfaces:")
    log(output)

    all_shutdown = True
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 6:
            iface = parts[0]
            if "administratively" in line:
                log(f"  ✅ {iface}: Administratively shut down.")
            else:
                log(f"  ⚠️  {iface}: ACTIVE — exposed to CVE-2020-3511 adjacent attack.")
                all_shutdown = False

    if all_shutdown:
        log("✅ All ISDN interfaces shut down — attack surface eliminated.")
        log("   Also covers Plugin 129812 (CVE-2019-1752) mitigation.")

def check_isdn_layer_status(connection):
    log("─── CHECK 3: ISDN Layer Status ───")
    output = connection.send_command("show isdn status")
    if output.strip():
        log(output)
        if "MULTIPLE_FRAME_ESTABLISHED" in output:
            log("  ⚠️  Active ISDN D-channel — device is processing Q.931 messages.")
        elif "DEACTIVATED" in output or not output.strip():
            log("  ✅ ISDN appears deactivated.")
    else:
        log("✅ No ISDN status output — ISDN not active.")

def check_active_calls(connection):
    log("─── CHECK 4: Active ISDN Calls ───")
    output = connection.send_command("show isdn active")
    if output.strip() and "No Active" not in output:
        log("⚠️  Active calls found:")
        log(output)
    else:
        log("✅ No active ISDN calls.")

def check_q931_switch_type(connection):
    log("─── CHECK 5: Q.931 Switch Type ───")
    output = connection.send_command(
        "show running-config | include isdn switch-type"
    )
    if output.strip():
        log(f"ISDN switch type config: {output.strip()}")
        log("  ℹ️  Switch type determines Q.931 message format.")
        log("  All switch types are affected by CVE-2020-3511.")
    else:
        log("No ISDN switch-type configured.")
        log("✅ ISDN may not be active on this device.")

def cross_reference_129812(connection):
    log("─── CHECK 6: Cross-reference Plugin 129812 (CVE-2019-1752) ───")
    log("  Both Plugin 129812 and 141373 affect the ISDN subsystem.")
    log("  Mitigation (interface shutdown) covers BOTH CVEs.")
    log("  IOS upgrade (CSCuz74957 + CSCvr57760) covers BOTH CVEs.")
    log("")

    # Check if 129812 mitigation was already applied
    bri_output = connection.send_command("show ip interface brief | include BRI")
    if not bri_output.strip():
        log("  ✅ No BRI interfaces — both ISDN vulnerabilities not applicable.")
    else:
        admin_down_count = sum(1 for l in bri_output.splitlines()
                               if "administratively" in l)
        total_bri = len([l for l in bri_output.splitlines() if l.strip()])
        log(f"  BRI interfaces: {total_bri} total, {admin_down_count} shut down.")
        if admin_down_count == total_bri and total_bri > 0:
            log("  ✅ All BRI interfaces shut — both ISDN plugins mitigated.")
        else:
            log("  ⚠️  Some BRI interfaces still active.")

def main():
    log("="*65)
    log("Verify Script - Plugin 141373 - Cisco IOS ISDN Q.931 DoS")
    log("CVE-2020-3511 | CSCvr57760 | Attack Vector: Adjacent")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_isdn_interface_state(connection)
        check_isdn_layer_status(connection)
        check_active_calls(connection)
        check_q931_switch_type(connection)
        cross_reference_129812(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: All ISDN interfaces shut, OR no ISDN configured,")
        log("           OR IOS upgraded to fixed release per CSCvr57760")
        log("  ❌ FAIL: ISDN interfaces active + vulnerable IOS version")
        log("  ⚠️  ADJACENT ONLY: Attacker needs physical/L2 ISDN access")
        log("  This fix also covers Plugin 129812 (CVE-2019-1752)")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()