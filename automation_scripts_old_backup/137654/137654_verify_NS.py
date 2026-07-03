#!/usr/bin/env python3
"""
Verify Script - Plugin 137654
Cisco IOS SXP DoS Vulnerability
CVE-2020-3228 | Bug IDs: CSCvd71220, CSCvp96954, CSCvt30182

Checks:
  1. IOS version vs known vulnerable releases
  2. SXP enabled state
  3. Active SXP connections
  4. SGT binding table (SXP activity indicator)
  5. Cross-reference with Plugin 154234 (TrustSec CLI)
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

LOG_FILE = f"verify_137654_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per CSCvd71220/CSCvp96954/CSCvt30182.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sxp-68TEVzR")

def check_sxp_enabled(connection):
    log("─── CHECK 2: SXP Enabled State ───")
    sxp_cfg = connection.send_command("show running-config | include cts sxp enable")

    if "no cts sxp enable" in sxp_cfg:
        log("✅ PASS: 'no cts sxp enable' confirmed — SXP explicitly DISABLED.")
        log("   CVE-2020-3228 attack surface eliminated.")
        return False
    elif "cts sxp enable" in sxp_cfg:
        log("⚠️  'cts sxp enable' found — SXP is ENABLED.")
        log("   Device exposed to CVE-2020-3228 until IOS upgrade.")
        return True
    else:
        log("ℹ️  No explicit 'cts sxp enable' line found.")
        # Check if SXP is default-off
        sxp_all_cfg = connection.send_command("show running-config | include cts sxp")
        if sxp_all_cfg.strip():
            log("  SXP config present but enable state unclear:")
            log(sxp_all_cfg)
        else:
            log("  ✅ No SXP config at all — SXP not deployed.")
            log("  Mark as 'Not Applicable' if physically confirmed.")
        return False

def check_sxp_connections(connection):
    log("─── CHECK 3: Active SXP Connections ───")
    output = connection.send_command("show cts sxp connections")

    if not output.strip() or "%" in output:
        log("✅ No SXP connection output — SXP not active.")
        return

    log("SXP connection table:")
    log(output[:500] if len(output) > 500 else output)

    active = output.count(" On")
    inactive = output.count(" Off")
    log(f"  Summary: {active} active, {inactive} inactive SXP sessions.")

    if active > 0:
        log("  ⚠️  Active SXP sessions — SXP is propagating SGT data.")
        log("  Disable SXP or upgrade IOS to remediate.")
    else:
        log("  ✅ No active SXP sessions currently.")

def check_sgt_bindings(connection):
    log("─── CHECK 4: SGT Binding Table (SXP Activity Indicator) ───")
    output = connection.send_command("show cts sxp sgt-map")

    if not output.strip() or "%" in output:
        log("✅ No SGT-to-IP bindings in SXP map.")
        log("   SXP is not actively propagating SGT data.")
        return

    binding_count = len([l for l in output.splitlines()
                         if l.strip() and "Total" not in l and "IP" not in l])
    log(f"  SGT binding entries: {binding_count}")
    log(output[:400] if len(output) > 400 else output)

    if binding_count > 0:
        log("  ⚠️  SXP is actively distributing SGT policy.")
        log("  Disabling SXP will stop these bindings — assess impact first.")

def cross_reference_154234(connection):
    log("─── CHECK 5: TrustSec Plugin Cross-Reference ───")
    log("")
    log("  Two TrustSec-related plugins on this device:")
    log("")
    log("  Plugin 154234 (CVE-2021-34699) — TrustSec CLI Parser DoS")
    log("    Feature: TrustSec + HTTP web UI")
    log("    Attack: Authenticated → CLI via web UI → reload")

    # HTTP server state (154234 mitigation)
    http_cfg = connection.send_command("show running-config | include ip http server")
    if "no ip http server" in http_cfg or "ip http server" not in http_cfg:
        log("    Status: ✅ HTTP disabled — Plugin 154234 mitigated")
    else:
        log("    Status: ⚠️  HTTP enabled — Plugin 154234 exposed")

    log("")
    log("  Plugin 137654 (CVE-2020-3228) — SXP DoS")
    log("    Feature: SXP protocol")
    log("    Attack: Unauthenticated → crafted SXP packet → reload")

    sxp_cfg = connection.send_command("show running-config | include cts sxp")
    if sxp_cfg.strip():
        log("    Status: ⚠️  SXP configured — Plugin 137654 exposed")
    else:
        log("    Status: ✅ SXP not configured — Plugin 137654 Not Applicable")

    log("")
    log("  Both TrustSec plugins resolved by a single IOS upgrade.")

def main():
    log("="*65)
    log("Verify Script - Plugin 137654 - Cisco IOS SXP DoS")
    log("CVE-2020-3228 | CSCvd71220/CSCvp96954/CSCvt30182 | CVSS 8.6")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        sxp_active = check_sxp_enabled(connection)
        check_sxp_connections(connection)
        check_sgt_bindings(connection)
        cross_reference_154234(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS (best): IOS upgraded per CSCvd71220/CSCvp96954/CSCvt30182")
        log("  ✅ PASS (mitigation): 'no cts sxp enable' confirmed")
        log("  ✅ PASS (alt): SXP confirmed not configured (Not Applicable)")
        log("  ❌ FAIL: SXP enabled + vulnerable IOS version")
        log("")
        log("  SXP NOT default — first confirm if deployed in TrustSec environment")
        log("  Unauthenticated attack — CVSS 8.6 (tied 2nd highest on device)")
        log("  Related to Plugin 154234 (TrustSec CLI) — same IOS upgrade fixes both")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()