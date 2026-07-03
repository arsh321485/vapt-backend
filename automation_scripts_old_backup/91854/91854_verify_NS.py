#!/usr/bin/env python3
"""
Verify Script - Plugin 91854
Cisco IOS Zone-Based Firewall Security Bypass
CVE-2014-2146 | Bug ID: CSCun94946
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
    "15.4(2)T4", "15.3(3)M8", "15.2(4)M10",
]

LOG_FILE = f"verify_91854_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            if any(v in detected for v in VULNERABLE_VERSIONS):
                log("❌ Vulnerable — upgrade per CSCun94946.")
            else:
                log("⚠️  Verify — 'Fix releases: See solution' in plugin output.")
            break

def check_zbf_disabled(connection):
    log("─── CHECK 2: ZBF Configuration State ───")
    zones = connection.send_command("show running-config | section zone security")

    if not zones.strip():
        log("✅ PASS: No zone security configuration found.")
        log("  ZBF disabled — CVE-2014-2146 bypass not applicable.")
        return False

    log("⚠️  ZBF zones still configured:")
    log(zones[:300] if len(zones) > 300 else zones)
    log("  Zone-based firewall bypass (CVE-2014-2146) possible.")
    log("  Apply workaround or upgrade IOS.")
    return True

def check_zone_runtime(connection):
    log("─── CHECK 3: ZBF Runtime ───")
    output = connection.send_command("show zone security")
    if output.strip() and "%" not in output:
        log("ZBF zones active:")
        log(output[:400] if len(output) > 400 else output)
        log("⚠️  ZBF is actively inspecting traffic — bypass attack possible.")
    else:
        log("✅ No ZBF zones active — bypass attack not possible.")

def check_backup_acls(connection):
    log("─── CHECK 4: Backup Interface ACLs ───")
    acls = connection.send_command("show running-config | include ip access-group")
    if acls.strip():
        log("Interface ACLs in place:")
        log(acls)
        log("✅ Interface ACLs provide security layer alongside/instead of ZBF.")
    else:
        log("⚠️  No interface ACLs found.")
        log("  If ZBF is the only security mechanism — disabling it is high risk.")

def zbf_bypass_context():
    log("─── CHECK 5: ZBF Bypass Context ───")
    log("")
    log("  CVE-2014-2146 — ZBF Zone Checking Bypass:")
    log("  Attack: Spoofed packets matching existing sessions bypass zone policy")
    log("  Impact: Attacker gains access to resources behind firewall")
    log("")
    log("  Cisco-recommended workaround: Disable ZBF")
    log("  (Only workaround = remove the security control itself)")
    log("")
    log("  ⚠️  This is an unusual CVE: the workaround REMOVES the firewall.")
    log("  Assess whether ACLs or other controls provide equivalent protection.")
    log("  IOS upgrade is strongly preferred over disabling ZBF.")

def main():
    log("="*65)
    log("Verify - Plugin 91854 - Cisco IOS ZBF Security Bypass")
    log("CVE-2014-2146 | CSCun94946 | CVSS 6.5 | Firewall Bypass")
    log("="*65)

    try:
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        zbf_active = check_zbf_disabled(connection)
        if zbf_active:
            check_zone_runtime(connection)
        check_backup_acls(connection)
        zbf_bypass_context()

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: IOS upgraded OR ZBF disabled OR ZBF not configured")
        log("  ❌ FAIL: ZBF active + vulnerable IOS version")
        log("  ⚠️  Workaround = disable ZBF (impacts security posture)")
        log("  IOS upgrade is preferred — restores ZBF with secure code")
        log("  'Fix releases: See solution' — verify at Cisco advisory")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")

if __name__ == "__main__":
    main()