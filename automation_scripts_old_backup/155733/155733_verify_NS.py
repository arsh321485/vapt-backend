#!/usr/bin/env python3
"""
Verify Script - Plugin 155733
Cisco IOS Software IKEv2 AutoReconnect Feature DoS
CVE-2021-1620 | Bug ID: CSCvw25564

Checks:
  1. IOS version vs known vulnerable releases
  2. IKEv2 AutoReconnect config in profiles
  3. IP local pool state and utilization
  4. Active IKEv2 SA count
  5. Pool exhaustion indicators
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
    "15.6(3)M", "15.7(3)M", "15.8(3)M",
    "16.9.1", "16.12.1", "17.3.1", "17.6.1",
]

LOG_FILE = f"verify_155733_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per Cisco Bug CSCvw25564.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ikev2-ebFrwMPr")

def check_autoreconnect_config(connection):
    log("─── CHECK 2: IKEv2 AutoReconnect Config ───")
    profiles = connection.send_command("show running-config | section crypto ikev2 profile")

    if not profiles.strip():
        log("✅ No IKEv2 profiles configured — AutoReconnect not applicable.")
        return

    log("IKEv2 profiles found:")
    log(profiles)

    if "reconnect" in profiles.lower():
        log("⚠️  AutoReconnect keyword detected in IKEv2 profile(s).")
        log("   CVE-2021-1620 is exploitable on this device.")
        log("   Disable AutoReconnect or upgrade IOS.")
    else:
        log("ℹ️  AutoReconnect keyword not explicitly found.")
        log("   May still be enabled via aaa group authorization — verify manually.")

def check_pool_state(connection):
    log("─── CHECK 3: IP Local Pool State ───")
    pool_output = connection.send_command("show ip local pool")
    if pool_output.strip():
        log("Pool utilization:")
        log(pool_output)

        # Look for exhaustion signs
        for line in pool_output.splitlines():
            if "In use" in line or "Free" in line:
                log(f"  {line.strip()}")
                if "Free" in line:
                    parts = line.split()
                    try:
                        free_count = int(parts[-1])
                        if free_count < 5:
                            log("  ❌ CRITICAL: Pool nearly exhausted (<5 free addresses)!")
                            log("     Possible active pool exhaustion attack or capacity issue.")
                        elif free_count < 20:
                            log("  ⚠️  WARNING: Pool running low on free addresses.")
                        else:
                            log(f"  ✅ Pool has {free_count} free addresses — healthy.")
                    except (ValueError, IndexError):
                        pass
    else:
        log("✅ No IP local pools configured — pool exhaustion not applicable.")

def check_ikev2_sa_count(connection):
    log("─── CHECK 4: IKEv2 SA Count ───")
    output = connection.send_command("show crypto ikev2 sa")
    if output.strip():
        sa_lines = [l for l in output.splitlines()
                    if "READY" in l or "ESTABLISHED" in l or "CREATED" in l]
        log(f"  Active IKEv2 SAs: {len(sa_lines)}")
        log(output[:500] if len(output) > 500 else output)

        if len(sa_lines) > 50:
            log("  ⚠️  High IKEv2 SA count — monitor for abnormal reconnect exhaustion.")
    else:
        log("✅ No active IKEv2 SAs.")

def check_ikev2_stats(connection):
    log("─── CHECK 5: IKEv2 Statistics ───")
    output = connection.send_command("show crypto ikev2 stats")
    if output.strip():
        log(output)
        # Look for reconnect-specific counters
        for line in output.splitlines():
            if "reconnect" in line.lower() or "autoreconnect" in line.lower():
                log(f"  ℹ️  Reconnect counter: {line.strip()}")
    else:
        log("No IKEv2 stats available.")

def main():
    log("="*65)
    log("Verify Script - Plugin 155733 - IKEv2 AutoReconnect DoS")
    log("CVE-2021-1620 | CSCvw25564")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_autoreconnect_config(connection)
        check_pool_state(connection)
        check_ikev2_sa_count(connection)
        check_ikev2_stats(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS conditions:")
        log("     - AutoReconnect disabled in all IKEv2 profiles, OR")
        log("     - No IKEv2 profiles / no IP local pools configured, OR")
        log("     - IOS upgraded to fixed release per CSCvw25564")
        log("  ❌ FAIL: AutoReconnect active + local pools + vulnerable IOS version")
        log("  NOTE: Requires authenticated attacker — lowest priority on this device")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()