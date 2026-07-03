#!/usr/bin/env python3
"""
Verify Script - Plugin 99028
Cisco IOS L2TP Parsing DoS
CVE-2017-3857 | Bug ID: CSCuy82078

Checks:
  1. IOS version vs known vulnerable releases
  2. VPDN/L2TP enabled state
  3. Active L2TP sessions
  4. VPDN tunnel summary
  5. Post-upgrade service health
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
    "15.6(1)T", "15.5(3)M", "15.5(2)T",
]

LOG_FILE = f"verify_99028_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per Cisco Bug CSCuy82078.")
        else:
            log("⚠️  Version not in local list — verify manually against Cisco advisory.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-l2tp")
    else:
        log("⚠️  Could not parse IOS version.")

def check_vpdn_enabled(connection):
    log("─── CHECK 2: VPDN/L2TP Enabled State ───")
    vpdn_cfg = connection.send_command("show running-config | include vpdn")

    if "no vpdn enable" in vpdn_cfg:
        log("✅ PASS: 'no vpdn enable' is explicitly set — L2TP disabled.")
        log("   CVE-2017-3857 attack surface eliminated on this device.")
    elif "vpdn enable" in vpdn_cfg:
        log("⚠️  VPDN is ENABLED — device can process L2TP packets.")
        log("   Exposed until IOS upgrade is completed.")
    else:
        log("ℹ️  No 'vpdn enable' line found — L2TP likely not configured.")
        log("   Default state = disabled. Device may not be exposed.")
        log("   Confirm by checking: 'show vpdn'")

def check_active_sessions(connection):
    log("─── CHECK 3: Active L2TP/VPDN Sessions ───")
    output = connection.send_command("show vpdn session")
    if output.strip() and "No active" not in output:
        log("Active sessions found:")
        log(output)
    else:
        log("✅ No active VPDN/L2TP sessions.")

def check_vpdn_tunnel(connection):
    log("─── CHECK 4: VPDN Tunnel Summary ───")
    output = connection.send_command("show vpdn tunnel")
    if output.strip() and "No active" not in output:
        log("Active VPDN tunnels:")
        log(output)
        log("⚠️  Tunnels are up — L2TP is actively in use. Upgrade urgently.")
    else:
        log("✅ No active VPDN tunnels.")

def check_interface_health(connection):
    log("─── CHECK 5: Interface Health (post-change check) ───")
    output = connection.send_command("show ip interface brief | exclude unassigned")
    log(output if output.strip() else "No interface output.")

def main():
    log("="*65)
    log("Verify Script - Plugin 99028 - Cisco IOS L2TP Parsing DoS")
    log("CVE-2017-3857 | CSCuy82078")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_vpdn_enabled(connection)
        check_active_sessions(connection)
        check_vpdn_tunnel(connection)
        check_interface_health(connection)

        log("="*65)
        log("SUMMARY:")
        log("  - If 'no vpdn enable' confirmed → attack surface eliminated (interim fix)")
        log("  - If vpdn still enabled → upgrade IOS per CSCuy82078 urgently")
        log("  - Re-scan Nessus with valid credentials after upgrade")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()