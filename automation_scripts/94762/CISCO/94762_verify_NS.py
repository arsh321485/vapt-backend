#!/usr/bin/env python3
"""
Verify Script - Plugin 94762
Cisco IOS IKEv1 Fragmentation DoS
Checks:
  1. IKEv1 fragmentation is disabled in running config
  2. IKE SA table is healthy (no stuck/deleted states)
  3. IOS version is reported (for manual upgrade tracking)
"""

from netmiko import ConnectHandler
import datetime
import sys

# ─── CONFIGURATION ────────────────────────────────────────────────
DEVICE = {
    "device_type": "cisco_ios",
    "host": "192.168.1.1",        # <-- Replace with your device IP
    "username": "admin",           # <-- Replace with your username
    "password": "yourpassword",    # <-- Replace with your password
    "secret": "yourenable",        # <-- Replace with enable secret
    "port": 22,
    "timeout": 30,
}

LOG_FILE = "verify_94762_log.txt"

def log(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def check_fragmentation(connection):
    log("─── CHECK 1: IKEv1 Fragmentation Config ───")
    output = connection.send_command("show running-config | include fragmentation")
    log(f"Raw output: '{output.strip()}'")

    if "no crypto isakmp fragmentation" in output:
        log("✅ PASS: IKEv1 fragmentation is explicitly DISABLED.")
        return True
    elif "crypto isakmp fragmentation" in output and "no" not in output:
        log("❌ FAIL: IKEv1 fragmentation is explicitly ENABLED — fix not applied.")
        return False
    else:
        log("⚠️  WARNING: No fragmentation line found in config.")
        log("   Default behavior depends on IOS version. Recommend verifying manually.")
        log("   Apply 'no crypto isakmp fragmentation' to be explicit.")
        return False

def check_ike_sa(connection):
    log("─── CHECK 2: IKE SA Table ───")
    output = connection.send_command("show crypto isakmp sa")
    log(output if output.strip() else "No IKE SAs found (expected if no active VPNs).")

    if "DELETED" in output or "MM_NO_STATE" in output:
        log("⚠️  WARNING: Some IKE SAs appear stuck/deleted — investigate VPN tunnels.")
    else:
        log("✅ IKE SA table looks healthy.")

def check_ios_version(connection):
    log("─── CHECK 3: IOS Version (for manual upgrade tracking) ───")
    output = connection.send_command("show version | include Version")
    log(output.strip())
    log("   ℹ️  Manual action required: Upgrade to fixed IOS release per Cisco Bug CSCuy47382.")
    log("   Fixed trains: 15.2M&T, 15.4M&T, 15.5T, 15.6T and later.")

def main():
    log("="*60)
    log("Verify Script - Plugin 94762 - Cisco IKEv1 Fragmentation DoS")
    log("="*60)

    try:
        log(f"Connecting to device: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        frag_ok = check_fragmentation(connection)
        check_ike_sa(connection)
        check_ios_version(connection)

        log("="*60)
        if frag_ok:
            log("OVERALL: Workaround APPLIED. Schedule IOS upgrade for full remediation.")
        else:
            log("OVERALL: Workaround NOT confirmed. Re-run fix script and investigate.")
        log("="*60)

        connection.disconnect()

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()