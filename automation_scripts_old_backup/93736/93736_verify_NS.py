#!/usr/bin/env python3
"""
Verify Script - Plugin 93736
Cisco IOS IKEv1 BENIGNCERTAIN Information Disclosure
CVE-2016-6415 | Bug ID: CSCvb29204

Checks:
  1. IOS version — confirms if upgraded to patched release
  2. IKEv1 policy presence — documents attack surface
  3. IKE SA table — confirms no stuck/broken sessions post-upgrade
  4. Nessus credential note — reminds to re-scan with valid creds
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

# ── Known VULNERABLE releases (partial list for 15.4 train) ──────
# Add more from Cisco advisory as needed
VULNERABLE_VERSIONS = [
    "15.4(3)M5", "15.4(3)M4", "15.4(3)M3",
    "15.4(2)T", "15.3(3)M", "15.2(4)M",
]

LOG_FILE = f"verify_93736_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def check_ios_version(connection):
    log("─── CHECK 1: IOS Version vs Known Vulnerable Releases ───")
    output = connection.send_command("show version")
    detected_version = None

    for line in output.splitlines():
        if "Version" in line and "Cisco IOS" in line:
            detected_version = line.strip()
            log(f"Detected: {detected_version}")
            break

    if detected_version:
        vuln_found = any(v in detected_version for v in VULNERABLE_VERSIONS)
        if vuln_found:
            log("❌ FAIL: Device is running a KNOWN VULNERABLE IOS version.")
            log("   ACTION: Upgrade immediately per Cisco Bug CSCvb29204.")
        else:
            log("⚠️  MANUAL CHECK REQUIRED: Version not in local vulnerable list.")
            log("   Verify against full Cisco advisory fixed release table.")
            log("   URL: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160916-ikev1")
    else:
        log("⚠️  Could not parse IOS version — check output manually.")

    return detected_version

def check_ikev1_policies(connection):
    log("─── CHECK 2: IKEv1 Policy Configuration ───")
    output = connection.send_command("show crypto isakmp policy")
    if output.strip():
        log("IKEv1 policies present on device:")
        log(output)
        log("⚠️  IKEv1 is in use — device remains exposed until IOS is upgraded.")
    else:
        log("✅ No IKEv1 policies configured. Attack surface reduced.")
        log("   Note: Even without explicit policies, IKEv1 may still be active.")

def check_ike_sa_table(connection):
    log("─── CHECK 3: IKE SA Table (Post-upgrade tunnel health) ───")
    output = connection.send_command("show crypto isakmp sa")
    if output.strip():
        log(output)
        if "DELETED" in output or "MM_NO_STATE" in output:
            log("⚠️  WARNING: Stuck or deleted IKE SAs detected — investigate VPN tunnels.")
        else:
            log("✅ IKE SA table appears healthy.")
    else:
        log("No active IKE SAs found (expected if no active VPN tunnels).")

def check_ipsec_sa(connection):
    log("─── CHECK 4: IPSec SA Table ───")
    output = connection.send_command("show crypto ipsec sa | include pkts")
    log(output if output.strip() else "No IPSec SA stats found.")

def nessus_rescan_reminder():
    log("─── REMINDER: Nessus Re-scan ───")
    log("Plugin output noted: Valid credentials were NOT provided during last scan.")
    log("After IOS upgrade:")
    log("  1. Configure Nessus scan with valid SSH credentials for this device.")
    log("  2. Re-run scan to confirm Plugin 93736 no longer fires.")
    log("  3. Also check Plugin 94762 (IKEv1 Fragmentation DoS) — same device.")

def main():
    log("="*65)
    log("Verify Script - Plugin 93736 - Cisco IOS BENIGNCERTAIN")
    log("CVE-2016-6415 | CISA KEV | Cisco Bug CSCvb29204")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_ikev1_policies(connection)
        check_ike_sa_table(connection)
        check_ipsec_sa(connection)
        nessus_rescan_reminder()

        log("="*65)
        log("Verification complete. Review all CHECK results above.")
        log("OVERALL: No automated fix possible — IOS upgrade is mandatory.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()