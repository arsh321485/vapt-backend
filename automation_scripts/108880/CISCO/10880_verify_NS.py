#!/usr/bin/env python3
"""
Verify Script - Plugin 108880
Cisco IOS Software LLDP Buffer Overflow Vulnerabilities
CVE-2018-0167 | CVE-2018-0175
Bug IDs: CSCvd73487, CSCvd73664
CISA KEV — Listed 2022/03/17

Checks:
  1. IOS version vs known vulnerable releases
  2. LLDP global disabled state
  3. LLDP neighbor table (confirms no active processing)
  4. Per-interface LLDP state
  5. CDP state (alternative discovery protocol health)
  6. CISA KEV summary — all 4 KEVs on device
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
    "16.3.1", "16.6.1", "16.9.1", "16.12.1",
]

LOG_FILE = f"verify_108880_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   CISA KEV — Upgrade required IMMEDIATELY per CSCvd73487/CSCvd73664.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-lldp")

def check_lldp_disabled(connection):
    log("─── CHECK 2: LLDP Global State ───")

    lldp_status = connection.send_command("show lldp")
    lldp_cfg = connection.send_command(
        "show running-config | include no lldp run|lldp run"
    )

    if "LLDP is not enabled" in lldp_status or "not enabled" in lldp_status.lower():
        log("✅ PASS: LLDP is DISABLED globally.")
        log("   CVE-2018-0167 — MITIGATED.")
        log("   CVE-2018-0175 — MITIGATED.")
        return True
    elif "no lldp run" in lldp_cfg:
        log("✅ PASS: 'no lldp run' confirmed in running config.")
        log("   LLDP processing disabled — attack surface eliminated.")
        return True
    else:
        log("❌ FAIL: LLDP appears to be ENABLED.")
        log("   Buffer overflow attack surface is ACTIVE.")
        log("   Apply 'no lldp run' or upgrade IOS immediately.")
        log("   CISA KEV + CVSS 8.8 — highest risk on device.")
        log(f"   LLDP status output: {lldp_status[:200]}")
        return False

def check_lldp_neighbors(connection):
    log("─── CHECK 3: LLDP Neighbor Table ───")
    output = connection.send_command("show lldp neighbors")

    if "not enabled" in output.lower() or not output.strip():
        log("✅ No LLDP neighbor data — LLDP not processing packets.")
    else:
        neighbor_count = len([l for l in output.splitlines()
                              if l.strip() and "Device" not in l
                              and "---" not in l and "Total" not in l
                              and "Capability" not in l])
        if neighbor_count > 0:
            log(f"⚠️  {neighbor_count} LLDP neighbor(s) still visible.")
            log("   LLDP may still be active — verify 'show lldp' state.")
            log(output)
        else:
            log("✅ No LLDP neighbors in table.")

def check_lldp_per_interface(connection):
    log("─── CHECK 4: Per-Interface LLDP State ───")
    output = connection.send_command("show lldp interface")

    if "not enabled" in output.lower() or not output.strip():
        log("✅ LLDP not enabled on any interface.")
    else:
        log("LLDP interface states:")
        log(output[:400] if len(output) > 400 else output)
        # Check for interfaces still transmitting
        tx_enabled = [l for l in output.splitlines() if "Tx: enabled" in l]
        rx_enabled = [l for l in output.splitlines() if "Rx: enabled" in l]
        if tx_enabled or rx_enabled:
            log(f"  ⚠️  {len(tx_enabled)} interface(s) with LLDP Tx enabled.")
            log(f"  ⚠️  {len(rx_enabled)} interface(s) with LLDP Rx enabled.")
            log("  Apply 'no lldp run' globally to disable all at once.")

def check_cdp_state(connection):
    log("─── CHECK 5: CDP State (Alternative Discovery Protocol) ───")
    cdp = connection.send_command("show cdp")
    if cdp.strip() and "not enabled" not in cdp.lower():
        log("  CDP (Cisco Discovery Protocol) is active:")
        log(cdp)
        log("  ✅ CDP can substitute for LLDP if device discovery is needed.")
        log("  CDP is Cisco-proprietary and not affected by LLDP CVEs.")
    else:
        log("  CDP is disabled or not available.")
        log("  Note: If device discovery is needed, consider enabling CDP instead of LLDP.")

def cisa_kev_summary():
    log("─── CHECK 6: CISA KEV Summary — All 4 KEVs on This Device ───")
    log("")
    log("  This device has FOUR CISA Known Exploited Vulnerabilities:")
    log("")
    log("  ┌──────────────────────────────────────────────────────────────────┐")
    log("  │ Plugin │ CVE(s)                  │ Name              │ Listed    │")
    log("  ├──────────────────────────────────────────────────────────────────┤")
    log("  │ 93736  │ CVE-2016-6415           │ BENIGNCERTAIN     │ 2023/06/09│")
    log("  │ 131166 │ CVE-2018-0154           │ ISM-VPN DoS       │ 2022/03/17│")
    log("  │ 103693 │ CVE-2017-12237          │ IKE DoS           │ 2022/03/24│")
    log("  │ 108880 │ CVE-2018-0167/0175      │ LLDP Buf Overflow │ 2022/03/17│")
    log("  └──────────────────────────────────────────────────────────────────┘")
    log("")
    log("  All four resolved by a SINGLE IOS upgrade.")
    log("  Plugin 108880 has the HIGHEST CVSS (8.8) and VPR (7.4) on this device.")

def main():
    log("="*65)
    log("Verify Script - Plugin 108880 - Cisco IOS LLDP Buffer Overflow")
    log("CVE-2018-0167 | CVE-2018-0175 | CISA KEV #4 | CVSS 8.8")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        lldp_ok = check_lldp_disabled(connection)
        check_lldp_neighbors(connection)
        check_lldp_per_interface(connection)
        check_cdp_state(connection)
        cisa_kev_summary()

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: LLDP confirmed disabled, OR IOS upgraded per CSCvd73487/CSCvd73664")
        log("  ❌ FAIL: LLDP still enabled on vulnerable IOS version")
        log("")
        log("  CISA KEV | CVSS 8.8 | VPR 7.4 — HIGHEST on device")
        log("  RCE potential (C:H/I:H/A:H) — treat as P0 alongside IOS upgrade")
        log("  Adjacent attack — attacker sends malformed LLDP on same L2 segment")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()