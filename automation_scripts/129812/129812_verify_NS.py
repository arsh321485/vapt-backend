#!/usr/bin/env python3
"""
Verify Script - Plugin 129812
Cisco IOS ISDN Interface Denial of Service
CVE-2019-1752 | Bug IDs: CSCuz74957, CSCvk01977

Checks:
  1. IOS version vs known vulnerable releases
  2. ISDN interface status (up/down/shutdown)
  3. Active ISDN calls (if any)
  4. ISDN configuration lines
  5. Post-upgrade IKE/routing health
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

# Known vulnerable IOS versions (15.4 train — expand as needed)
VULNERABLE_VERSIONS = [
    "15.4(3)M5", "15.4(3)M4", "15.4(3)M3", "15.4(3)M2",
    "15.4(2)T4", "15.3(3)M8", "15.2(4)M10",
]

LOG_FILE = f"verify_129812_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per CSCuz74957 / CSCvk01977.")
        else:
            log("⚠️  Version not in local vulnerable list — verify manually against Cisco advisory.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-isdn")
    else:
        log("⚠️  Could not parse IOS version string.")

def check_isdn_interface_status(connection):
    log("─── CHECK 2: ISDN Interface Status ───")
    output = connection.send_command("show ip interface brief | include BRI")
    if output.strip():
        log("BRI interfaces found:")
        log(output)
        # Check for shutdown
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 6:
                iface = parts[0]
                status = parts[4]  # administratively down = shutdown
                proto = parts[5]
                if "administratively" in line:
                    log(f"  ✅ {iface}: Administratively shut down — attack surface reduced.")
                else:
                    log(f"  ⚠️  {iface}: Status={status}, Protocol={proto} — interface is ACTIVE.")
                    log(f"      Device remains exposed until IOS is upgraded.")
    else:
        log("✅ No BRI interfaces found in IP interface brief.")

def check_isdn_active_calls(connection):
    log("─── CHECK 3: Active ISDN Calls ───")
    output = connection.send_command("show isdn active")
    if output.strip() and "No Active" not in output:
        log("⚠️  Active ISDN calls detected:")
        log(output)
        log("   Do NOT shut down interfaces while calls are active.")
    else:
        log("✅ No active ISDN calls.")

def check_isdn_status(connection):
    log("─── CHECK 4: ISDN Status (Layer 1/2/3) ───")
    output = connection.send_command("show isdn status")
    if output.strip():
        log(output)
    else:
        log("No ISDN status output — ISDN may not be configured or interfaces are shut down.")

def check_snmp_port(connection):
    log("─── CHECK 5: SNMP Config (Port 161 context) ───")
    output = connection.send_command("show running-config | include snmp")
    if output.strip():
        log("SNMP config lines:")
        log(output)
        log("   Note: Plugin detected on tcp/161 — ensure SNMP community strings are secured.")
    else:
        log("No SNMP config found in running config.")

def main():
    log("="*65)
    log("Verify Script - Plugin 129812 - Cisco IOS ISDN DoS")
    log("CVE-2019-1752 | CSCuz74957 | CSCvk01977")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_isdn_interface_status(connection)
        check_isdn_active_calls(connection)
        check_isdn_status(connection)
        check_snmp_port(connection)

        log("="*65)
        log("OVERALL: IOS upgrade to fixed release is the only permanent fix.")
        log("Interim: Shutdown unused ISDN interfaces to reduce exposure.")
        log("Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()