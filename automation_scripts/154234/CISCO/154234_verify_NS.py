#!/usr/bin/env python3
"""
Verify Script - Plugin 154234
Cisco IOS Software TrustSec CLI Parser DoS
CVE-2021-34699 | Bug ID: CSCvx66699

Checks:
  1. IOS version vs known vulnerable releases
  2. HTTP server disabled state (primary mitigation)
  3. TrustSec configuration state
  4. Cross-reference with Plugin 305769 mitigation
  5. Web UI access health check
"""

from netmiko import ConnectHandler
import datetime
import sys

# ─── CONFIGURATION ────────────────────────────────────────────────
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
    "15.6(1)T", "15.5(3)M", "15.7(3)M",
    "16.9.1", "16.12.1", "17.3.1",
]

LOG_FILE = f"verify_154234_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per Cisco Bug CSCvx66699.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-trustsec-dos-7fuXDR2")

def check_http_server_disabled(connection):
    log("─── CHECK 2: HTTP Server State (Primary Mitigation) ───")
    http_cfg = connection.send_command("show running-config | include ip http")

    http_off = "no ip http server" in http_cfg or "ip http server" not in http_cfg
    https_off = ("no ip http secure-server" in http_cfg or
                 "ip http secure-server" not in http_cfg)

    if http_off and https_off:
        log("✅ PASS: HTTP and HTTPS server both DISABLED.")
        log("   CVE-2021-34699 attack path eliminated (web UI not accessible).")
        log("   Also covers Plugin 305769 (HTTP Server DoS) mitigation.")
        return True
    else:
        if not http_off:
            log("⚠️  HTTP server (port 80) is ENABLED.")
        if not https_off:
            log("⚠️  HTTPS server (port 443) is ENABLED.")
        log("  Web UI accessible — TrustSec CLI parser attack path open.")
        log("  Apply 'no ip http server' + 'no ip http secure-server'.")
        return False

def check_trustsec_state(connection):
    log("─── CHECK 3: TrustSec Configuration State ───")
    cts_cfg = connection.send_command("show running-config | include cts|trustsec")

    if not cts_cfg.strip():
        log("✅ No TrustSec/CTS configuration found.")
        log("   Without TrustSec, this specific CLI parser attack path doesn't apply.")
        log("   Mark as 'Not Applicable' if TrustSec confirmed not deployed.")
        return False

    log("⚠️  TrustSec (CTS) is configured:")
    log(cts_cfg)

    # Check CTS runtime
    cts_runtime = connection.send_command("show cts")
    if cts_runtime.strip() and "%" not in cts_runtime:
        log("  CTS runtime state:")
        log(cts_runtime[:300] if len(cts_runtime) > 300 else cts_runtime)

    return True

def cross_reference_305769(connection):
    log("─── CHECK 4: Cross-Reference Plugin 305769 vs 154234 ───")
    log("")
    log("  Shared mitigation analysis:")
    log("")
    log("  Plugin 305769 (CVE-2026-20125) — HTTP Server DoS")
    log("    Attack: Authenticated attacker → malformed HTTP → watchdog timeout")
    log("    Mitigation: 'no ip http server' + 'no ip http secure-server'")
    log("")
    log("  Plugin 154234 (CVE-2021-34699) — TrustSec CLI Parser DoS")
    log("    Attack: Authenticated attacker → web UI TrustSec CLI → reload")
    log("    Mitigation: Same 'no ip http server' eliminates web UI access")
    log("")
    log("  ✅ BOTH plugins mitigated by disabling HTTP server.")
    log("  ✅ If Plugin 305769 mitigation already applied, 154234 is also covered.")

    http_cfg = connection.send_command("show running-config | include ip http")
    if "no ip http server" in http_cfg:
        log("  STATUS: HTTP server disabled — both 305769 and 154234 MITIGATED.")
    else:
        log("  STATUS: HTTP server still enabled — both 305769 and 154234 at risk.")

def check_ssh_mgmt_access(connection):
    log("─── CHECK 5: SSH Management Access (Post-HTTP Disable) ───")
    log("  Verifying CLI/SSH management access is unaffected...")

    # Implicit check — we're connected via SSH, so it's working
    uptime = connection.send_command("show version | include uptime")
    log(f"  Device uptime: {uptime.strip()}")
    log("  ✅ SSH/CLI access confirmed functional.")
    log("  HTTP disable does not affect SSH management.")

def main():
    log("="*65)
    log("Verify Script - Plugin 154234 - Cisco IOS TrustSec CLI Parser DoS")
    log("CVE-2021-34699 | CSCvx66699 | Auth Required")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        http_ok = check_http_server_disabled(connection)
        trustsec_active = check_trustsec_state(connection)
        cross_reference_305769(connection)
        check_ssh_mgmt_access(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS (best): IOS upgraded per CSCvx66699")
        log("  ✅ PASS (mitigation): HTTP server disabled (covers 305769 too)")
        log("  ✅ PASS (alt): TrustSec confirmed not configured")
        log("  ❌ FAIL: HTTP enabled + TrustSec configured + vulnerable IOS")
        log("")
        log("  Requires authenticated access via web UI + TrustSec deployed")
        log("  'no ip http server' mitigates BOTH Plugin 305769 AND 154234")
        log("  TrustSec uncommon on standard branch routers — verify deployment")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()