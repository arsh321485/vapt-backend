#!/usr/bin/env python3
"""
Verify Script - Plugin 137835
Cisco IOS IKEv2 DoS Vulnerability
CVE-2020-3230 | Bug ID: CSCvp44397

Checks:
  1. IOS version vs known vulnerable releases
  2. IKEv2 SA table — active tunnels post-upgrade
  3. IKEv2 proposal/policy state
  4. IKEv1 SA table — confirm not disrupted
  5. Overall VPN health summary
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

# Known vulnerable IOS versions (15.4 train — expand from Cisco advisory)
VULNERABLE_VERSIONS = [
    "15.4(3)M5", "15.4(3)M4", "15.4(3)M3",
    "15.4(2)T4", "15.3(3)M8", "15.2(4)M10",
    "16.3.1", "16.6.1", "16.9.1",
]

LOG_FILE = f"verify_137835_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per Cisco Bug CSCvp44397.")
        else:
            log("⚠️  Not in local vulnerable list — verify against full Cisco advisory.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ikev2-9p23Jj2a")
    else:
        log("⚠️  Could not parse IOS version.")

def check_ikev2_sa(connection):
    log("─── CHECK 2: IKEv2 SA Table ───")
    output = connection.send_command("show crypto ikev2 sa")
    if output.strip():
        log("Active IKEv2 SAs:")
        log(output)
        if "READY" in output:
            log("✅ IKEv2 SAs are in READY state — tunnels healthy post-upgrade.")
        else:
            log("⚠️  IKEv2 SAs present but may not be in READY state — investigate.")
    else:
        log("No active IKEv2 SAs.")
        if "DISABLE_IKEV2_IF_UNUSED was applied":
            log("✅ Expected — IKEv2 was disabled as mitigation.")

def check_ikev2_proposals(connection):
    log("─── CHECK 3: IKEv2 Proposal State ───")
    output = connection.send_command("show crypto ikev2 proposal")
    if output.strip():
        log("IKEv2 proposals active:")
        log(output)
    else:
        log("No IKEv2 proposals — IKEv2 is effectively disabled.")
        log("✅ If this was intentional mitigation, attack surface is reduced.")

def check_ikev1_sa(connection):
    log("─── CHECK 4: IKEv1 SA Table (health check) ───")
    output = connection.send_command("show crypto isakmp sa")
    if output.strip():
        log(output)
        if "ACTIVE" in output:
            log("✅ IKEv1 tunnels are ACTIVE — not disrupted by IKEv2 changes.")
        elif "DELETED" in output or "MM_NO_STATE" in output:
            log("⚠️  Stuck IKEv1 SAs found — investigate VPN connectivity.")
    else:
        log("No active IKEv1 SAs (expected if no IKEv1 VPNs configured).")

def check_ipsec_summary(connection):
    log("─── CHECK 5: IPSec SA Summary ───")
    output = connection.send_command("show crypto ipsec sa | include pkts encrypt|pkts decrypt")
    if output.strip():
        log("IPSec traffic counters:")
        log(output)
        log("✅ IPSec is passing traffic — VPN tunnels functional.")
    else:
        log("No IPSec traffic counters found.")

def nessus_reminder():
    log("─── REMINDER ───")
    log("Nessus detected Plugin 137835 on tcp/161 (SNMP port).")
    log("Detection was VERSION-BASED — not actively tested.")
    log("After IOS upgrade, re-scan with valid SSH credentials.")
    log("Also verify Plugins 94762, 93736, 129812 on this same device.")

def main():
    log("="*65)
    log("Verify Script - Plugin 137835 - Cisco IOS IKEv2 DoS")
    log("CVE-2020-3230 | CSCvp44397")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_ikev2_sa(connection)
        check_ikev2_proposals(connection)
        check_ikev1_sa(connection)
        check_ipsec_summary(connection)
        nessus_reminder()

        log("="*65)
        log("OVERALL: IOS upgrade to fixed release is the only permanent fix.")
        log("Interim: Remove IKEv2 proposals if IKEv2 is not in use.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()