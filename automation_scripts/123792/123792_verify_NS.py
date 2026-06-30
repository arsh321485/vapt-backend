#!/usr/bin/env python3
"""
Verify Script - Plugin 123792
Cisco IOS HSRP Information Leak
CVE-2019-1761 | Bug ID: CSCvj98575

Checks:
  1. IOS version
  2. HSRP configured and version
  3. HSRP authentication state
  4. HSRP group health
  5. Complete priority context summary
"""

from netmiko import ConnectHandler
import datetime

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
    "15.4(2)T4", "15.3(3)M8",
]

LOG_FILE = f"verify_123792_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def check_ios_version(connection):
    log("─── CHECK 1: IOS Version ───")
    output = connection.send_command("show version")
    for line in output.splitlines():
        if "Version" in line and ("IOS" in line or "Software" in line):
            detected = line.strip()
            log(f"Detected: {detected}")
            is_vuln = any(v in detected for v in VULNERABLE_VERSIONS)
            if is_vuln:
                log("❌ Vulnerable version — upgrade per CSCvj98575.")
            else:
                log("⚠️  Verify against full Cisco advisory.")
            break

def check_hsrp_version(connection):
    log("─── CHECK 2: HSRP Version ───")
    version_cfg = connection.send_command(
        "show running-config | include standby version"
    )

    if "standby version 2" in version_cfg:
        log("⚠️  HSRPv2 configured — CVE-2019-1761 applicable.")
    elif "standby version 1" in version_cfg:
        log("✅ HSRPv1 — CVE-2019-1761 does NOT affect v1.")
    else:
        standby_cfg = connection.send_command(
            "show running-config | include standby"
        )
        if standby_cfg.strip():
            log("ℹ️  HSRP configured without explicit version — default is v1.")
            log("✅ Likely not affected by CVE-2019-1761.")
        else:
            log("✅ HSRP not configured — Not Applicable.")

def check_hsrp_auth(connection):
    log("─── CHECK 3: HSRP Authentication ───")
    auth_cfg = connection.send_command(
        "show running-config | include standby.*authentication"
    )
    if "md5" in auth_cfg.lower():
        log("✅ HSRP MD5 authentication configured.")
        log("  Information leak mitigation in place.")
    elif auth_cfg.strip():
        log("⚠️  HSRP auth present but not MD5:")
        log(f"  {auth_cfg.strip()}")
    else:
        log("⚠️  No HSRP authentication.")
        log("  Apply 'standby <group> authentication md5 key-string <key>'")

def check_hsrp_health(connection):
    log("─── CHECK 4: HSRP Group Health ───")
    brief = connection.send_command("show standby brief")
    if brief.strip():
        log("HSRP group summary:")
        log(brief)
    else:
        log("No HSRP group output — HSRP inactive or not configured.")

def priority_final_summary():
    log("─── CHECK 5: FINAL PRIORITY SUMMARY ───")
    log("")
    log("  Plugin 123792 — THE LOWEST PRIORITY FINDING ON THIS DEVICE:")
    log("")
    log("  VPR:      1.4   ← Absolute lowest")
    log("  CVSS:     4.3   ← Lowest CVSS v3 on device")
    log("  EPSS:   0.0007  ← Near-zero exploitation probability")
    log("  Impact: C:L only — minor info leak, no DoS, no RCE")
    log("  AV: Adjacent — attacker must be on same L2 HSRP segment")
    log("  Only HSRPv2 affected")
    log("")
    log("  Resolve ALL 31 other plugins before addressing this.")
    log("  IOS upgrade (planned for critical issues) fixes this automatically.")

def main():
    log("="*65)
    log("Verify - Plugin 123792 - HSRP Info Leak")
    log("CVE-2019-1761 | VPR 1.4 | ABSOLUTE LOWEST PRIORITY")
    log("="*65)

    try:
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_hsrp_version(connection)
        check_hsrp_auth(connection)
        check_hsrp_health(connection)
        priority_final_summary()

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: IOS upgraded OR HSRPv2 not configured OR MD5 auth applied")
        log("  ❌ FAIL: HSRPv2 active + no auth + vulnerable IOS")
        log("  LOWEST VPR (1.4) — absolute last priority on device")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")

if __name__ == "__main__":
    main()