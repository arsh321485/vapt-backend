#!/usr/bin/env python3
"""
Verify Script - Plugin 132723
Cisco IOS Software NAT64 DoS Vulnerability
CVE-2019-1751 | Bug ID: CSCvk61580

Checks:
  1. IOS version vs known vulnerable releases
  2. NAT64 configuration state
  3. Active NAT64 sessions
  4. Interface queue health (wedge detection)
  5. Cross-reference with Plugin 103669 (standard NAT)
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
    "16.9.1", "16.12.1", "17.3.1",
]

LOG_FILE = f"verify_132723_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per Cisco Bug CSCvk61580.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-nat64")

def check_nat64_state(connection):
    log("─── CHECK 2: NAT64 Configuration State ───")
    nat64_cfg = connection.send_command("show running-config | include nat64")

    if not nat64_cfg.strip():
        log("✅ PASS: No NAT64 configuration found.")
        log("   CVE-2019-1751 not applicable — NAT64 not deployed.")
        log("   Mark as 'Not Applicable' after physical verification.")
        return False

    log("⚠️  NAT64 configuration present:")
    log(nat64_cfg)
    log("   Device is exposed to CVE-2019-1751.")
    log("   Disable NAT64 or upgrade IOS per CSCvk61580.")
    return True

def check_nat64_translations(connection):
    log("─── CHECK 3: NAT64 Active Sessions ───")
    output = connection.send_command("show ip nat64 translations")

    if not output.strip() or "%" in output:
        log("✅ No active NAT64 translations.")
        return

    entries = [l for l in output.splitlines()
               if l.strip() and "Proto" not in l and "---" not in l]
    log(f"  Active NAT64 sessions: {len(entries)}")
    if entries:
        log("  ⚠️  NAT64 is actively translating traffic.")
        log(output[:400] if len(output) > 400 else output)

def check_interface_queue_health(connection):
    log("─── CHECK 4: Interface Queue Health (Wedge Detection) ───")
    log("  CVE-2019-1751 can cause interface queue wedge (silent traffic drop).")

    output = connection.send_command(
        "show interfaces | include input queue|output queue|Total output drops"
    )
    if output.strip():
        log("  Interface queue stats:")
        log(output)

        high_drops = False
        for line in output.splitlines():
            for token in line.split():
                try:
                    val = int(token.replace(",", ""))
                    if val > 1000:
                        log(f"  ⚠️  High queue value: {line.strip()}")
                        high_drops = True
                        break
                except ValueError:
                    continue

        if not high_drops:
            log("  ✅ No abnormal queue drops detected.")
            log("  No active queue wedge condition observed.")
    else:
        log("  No interface queue data.")

def cross_reference_nat(connection):
    log("─── CHECK 5: Cross-Reference — NAT64 vs Standard NAT ───")
    log("")
    log("  Two NAT-related plugins on this device:")
    log("")
    log("  Plugin 103669 (CVE-2017-12231) — Standard IPv4 NAT/PAT")
    log("    Feature: ip nat inside/outside with ip nat source")
    log("    Attack: Stops ALL traffic processing")
    log("    CISA KEV: YES (2022/03/24)")

    standard_nat = connection.send_command(
        "show running-config | include ip nat inside|ip nat outside"
    )
    if standard_nat.strip():
        log("    Status: ⚠️  ACTIVE — Plugin 103669 exposure confirmed")
    else:
        log("    Status: ✅ Not configured")

    log("")
    log("  Plugin 132723 (CVE-2019-1751) — NAT64 (IPv6-to-IPv4)")
    log("    Feature: nat64 enable on interfaces")
    log("    Attack: Interface queue wedge OR device reload")
    log("    CISA KEV: NO")

    nat64 = connection.send_command("show running-config | include nat64")
    if nat64.strip():
        log("    Status: ⚠️  ACTIVE — Plugin 132723 exposure confirmed")
    else:
        log("    Status: ✅ Not configured")

def main():
    log("="*65)
    log("Verify Script - Plugin 132723 - Cisco IOS NAT64 DoS")
    log("CVE-2019-1751 | CSCvk61580")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        nat64_present = check_nat64_state(connection)
        check_nat64_translations(connection)
        check_interface_queue_health(connection)
        cross_reference_nat(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS (best): IOS upgraded to fixed release per CSCvk61580")
        log("  ✅ PASS (mitigation): NAT64 confirmed not configured")
        log("  ⚠️  PARTIAL: NAT64 disabled but IOS not yet upgraded")
        log("  ❌ FAIL: NAT64 active + vulnerable IOS version")
        log("")
        log("  NAT64 NOT default — if never deployed: Not Applicable")
        log("  Attack can wedge interface OR reload device")
        log("  See also Plugin 103669 (standard NAT) on this device")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()