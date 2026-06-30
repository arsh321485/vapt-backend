#!/usr/bin/env python3
"""
Verify Script - Plugin 127049
Cisco IOS Software PnP Certificate Validation
CVE-2019-1748 | Bug IDs: CSCvf36269, CSCvg01089

Checks:
  1. IOS version vs known vulnerable releases
  2. PnP agent state (active/idle/disabled)
  3. PnP profile configuration
  4. PnP session status
  5. Certificate validation context
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

LOG_FILE = f"verify_127049_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per CSCvf36269 / CSCvg01089.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-pnp-cert")

def check_pnp_agent_status(connection):
    log("─── CHECK 2: PnP Agent State ───")
    output = connection.send_command("show pnp status")

    if not output.strip() or "%" in output:
        log("  'show pnp status' not available — may not be configured.")
        # Fall back to config check
        pnp_cfg = connection.send_command("show running-config | include pnp")
        if not pnp_cfg.strip():
            log("  ✅ No PnP config found — agent likely inactive.")
        else:
            log(f"  PnP config present: {pnp_cfg.strip()}")
        return

    log("PnP agent status:")
    log(output)

    if "Disabled" in output or "disabled" in output:
        log("✅ PASS: PnP agent is DISABLED.")
        log("   CVE-2019-1748 attack surface eliminated.")
    elif "Idle" in output or "IDLE" in output:
        log("⚠️  PnP agent is IDLE.")
        log("   Not actively communicating — lower immediate risk.")
        log("   Upgrade IOS to permanently fix certificate validation.")
    elif "Active" in output or "active" in output:
        log("❌ PnP agent is ACTIVE — MitM attack currently feasible.")
        log("   Disable PnP or upgrade IOS immediately.")

def check_pnp_profile(connection):
    log("─── CHECK 3: PnP Profile Configuration ───")
    output = connection.send_command("show running-config | section pnp")

    if not output.strip():
        log("✅ No PnP profile configuration found.")
        log("   PnP not explicitly configured — reduced exposure.")
    else:
        log("PnP configuration section:")
        log(output)
        if "transport" in output.lower():
            log("  ℹ️  PnP transport configured — active provisioning setup.")
        if "https" in output.lower():
            log("  Certificate validation is relevant — HTTPS in use.")

def check_pnp_sessions(connection):
    log("─── CHECK 4: PnP Session Status ───")
    output = connection.send_command("show pnp session")

    if not output.strip() or "%" in output:
        log("✅ No active PnP sessions.")
        log("   No active provisioning — MitM risk window currently closed.")
        return

    log("Active PnP sessions:")
    log(output)
    log("⚠️  Active PnP session — MitM attack is currently feasible.")
    log("   Disable PnP or upgrade IOS to fix certificate validation.")

def check_trustpool_certs(connection):
    log("─── CHECK 5: Certificate Trustpool Context ───")
    log("  CVE-2019-1748 = insufficient certificate VALIDATION in PnP agent.")
    log("  Not a missing certificate — the validation logic itself is flawed.")
    log("  Only IOS upgrade fixes the validation code.")

    # Check trustpool
    trustpool = connection.send_command("show crypto pki trustpool | count")
    log(f"  PKI trustpool entry count: {trustpool.strip()}")

    # Check trustpoint
    trustpoint = connection.send_command(
        "show running-config | include crypto pki trustpoint"
    )
    if trustpoint.strip():
        log("  Configured PKI trustpoints:")
        log(trustpoint)
    else:
        log("  No explicit PKI trustpoints configured.")

    log("")
    log("  Note: Even with valid certificates, PnP agent's validation logic")
    log("  is flawed in this IOS version — upgrade is the only full fix.")

def main():
    log("="*65)
    log("Verify Script - Plugin 127049 - Cisco IOS PnP Cert Validation")
    log("CVE-2019-1748 | CSCvf36269 | CSCvg01089")
    log("MitM vulnerability — C:H/I:H")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_pnp_agent_status(connection)
        check_pnp_profile(connection)
        check_pnp_sessions(connection)
        check_trustpool_certs(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS (best): IOS upgraded per CSCvf36269/CSCvg01089")
        log("  ✅ PASS (mitigation): PnP agent disabled/idle, no active sessions")
        log("  ❌ FAIL: PnP agent active + vulnerable IOS + provisioning in progress")
        log("")
        log("  UNIQUE: Only non-DoS plugin on this device (MitM, C:H/I:H)")
        log("  On fully provisioned production devices: PnP likely idle — lower risk")
        log("  Certificate validation bypass = unauthorized config push risk")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()