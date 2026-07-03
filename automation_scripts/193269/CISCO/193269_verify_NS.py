#!/usr/bin/env python3
"""
Verify Script - Plugin 193269
Cisco IOS Software LISP DoS Vulnerability
CVE-2024-20311 | Bug ID: CSCwf36266

Checks:
  1. IOS version vs known vulnerable releases
  2. LISP process state (configured or removed)
  3. LISP map cache (active forwarding check)
  4. LISP runtime show output
  5. IPv6 transport exposure
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
    "16.9.1", "16.12.1", "17.3.1", "17.6.1",
]

LOG_FILE = f"verify_193269_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per Cisco Bug CSCwf36266.")
            log("   Note: 'Fixed release: See vendor advisory' — check advisory for exact train.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-lisp-3gYXs3qP")

def check_lisp_configured(connection):
    log("─── CHECK 2: LISP Process State ───")
    lisp_cfg = connection.send_command("show running-config | section router lisp")

    if not lisp_cfg.strip():
        log("✅ PASS: No LISP process configured.")
        log("   CVE-2024-20311 not applicable — LISP disabled/not deployed.")
        log("   Mark as 'Not Applicable' if physically confirmed not in use.")
        return False

    log("⚠️  LISP process found in config:")
    log(lisp_cfg[:400] if len(lisp_cfg) > 400 else lisp_cfg)
    log("   Device is exposed to CVE-2024-20311.")
    log("   Disable LISP or upgrade IOS per CSCwf36266.")
    return True

def check_lisp_map_cache(connection):
    log("─── CHECK 3: LISP Map Cache (Forwarding State) ───")
    output = connection.send_command("show lisp map-cache")

    if not output.strip() or "%" in output:
        log("✅ No LISP map cache — LISP not actively forwarding.")
        return

    entry_count = len([l for l in output.splitlines()
                       if "/" in l and not l.startswith("LISP")])
    log(f"  LISP map cache has {entry_count} EID entries.")
    log(output[:400] if len(output) > 400 else output)

    if entry_count > 0:
        log("  ⚠️  LISP is actively forwarding traffic.")
        log("  Do NOT disable without SD-Access migration plan.")

def check_lisp_runtime(connection):
    log("─── CHECK 4: LISP Runtime Status ───")
    output = connection.send_command("show lisp")

    if not output.strip() or "%" in output or "Invalid" in output:
        log("✅ 'show lisp' returned no output — LISP process not running.")
        return

    log("LISP runtime output:")
    log(output[:500] if len(output) > 500 else output)

    if "Instance" in output or "EID" in output:
        log("⚠️  LISP instances/EID tables are active.")
        log("   Upgrade IOS to fix CVE-2024-20311.")

def check_ipv6_exposure(connection):
    log("─── CHECK 5: IPv6 Transport Exposure ───")
    log("  CVE-2024-20311 is exploitable via IPv4 AND IPv6.")

    ipv6 = connection.send_command(
        "show ipv6 interface brief | exclude unassigned|down"
    )
    if ipv6.strip():
        log("  Active IPv6 interfaces:")
        log(ipv6)
        log("  ⚠️  IPv6 active — LISP attack exploitable via both transports.")
    else:
        log("  ✅ No active IPv6 interfaces — attack limited to IPv4 only.")

def main():
    log("="*65)
    log("Verify Script - Plugin 193269 - Cisco IOS LISP DoS")
    log("CVE-2024-20311 | CSCwf36266")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        lisp_present = check_lisp_configured(connection)

        if lisp_present:
            check_lisp_map_cache(connection)
            check_lisp_runtime(connection)
        else:
            log("LISP not configured — skipping map cache and runtime checks.")

        check_ipv6_exposure(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS (best): IOS upgraded to fixed release per CSCwf36266")
        log("  ✅ PASS (mitigation): LISP confirmed not configured on device")
        log("  ⚠️  PARTIAL: LISP disabled but IOS not yet upgraded")
        log("  ❌ FAIL: LISP active + vulnerable IOS version")
        log("")
        log("  LISP is NOT default — if never deployed, mark Not Applicable")
        log("  Exploitable via IPv4 AND IPv6")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()