#!/usr/bin/env python3
"""
Fix Script - Plugin 93736
Cisco IOS IKEv1 BENIGNCERTAIN Information Disclosure
CVE-2016-6415 | Bug ID: CSCvb29204

NOTE: No CLI workaround exists for this vulnerability.
      The ONLY fix is upgrading IOS to a patched release.
      This script performs pre-upgrade audit and documentation.
"""

from netmiko import ConnectHandler
import datetime
import sys
import os

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

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_93736_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_93736_{DEVICE['host']}_{TIMESTAMP}.txt"
    with open(backup_file, "w") as f:
        f.write(config)
    log(f"Config saved to: {backup_file}")
    return backup_file

def collect_ios_version(connection):
    log("── STEP 2: Collecting IOS Version ──")
    output = connection.send_command("show version")
    log(output)

    # Extract version line
    for line in output.splitlines():
        if "Cisco IOS Software" in line or "Version" in line:
            log(f"Detected: {line.strip()}")
            break

    log("ACTION REQUIRED: Compare above version against Cisco Bug CSCvb29204 fixed releases.")
    log("Fixed releases available at: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160916-ikev1")

def collect_ikev1_policy(connection):
    log("── STEP 3: Collecting IKEv1 Policy (crypto isakmp policy) ──")
    output = connection.send_command("show crypto isakmp policy")
    if output.strip():
        log(output)
        log("IKEv1 policies are configured on this device.")
    else:
        log("No IKEv1 policies found in configuration.")

def collect_isakmp_config(connection):
    log("── STEP 4: Checking ISAKMP-related running config ──")
    output = connection.send_command("show running-config | section crypto isakmp")
    log(output if output.strip() else "No crypto isakmp section found.")

def generate_remediation_note():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 93736 - BENIGNCERTAIN (CVE-2016-6415)")
    log("CISA Known Exploited Vulnerability — Priority remediation required.")
    log("")
    log("There is NO CLI workaround for this vulnerability.")
    log("Required action: Upgrade Cisco IOS to a fixed release per Bug ID CSCvb29204.")
    log("")
    log("Upgrade steps (manual):")
    log("  1. Download fixed IOS image from Cisco.com (CCO account required).")
    log("  2. Transfer image to device via TFTP or SCP.")
    log("  3. Verify image MD5: 'verify /md5 flash:<image>'")
    log("  4. Set boot variable: 'boot system flash:<image>'")
    log("  5. Save config: 'write memory'")
    log("  6. Reload device: 'reload'")
    log("  7. Confirm new version: 'show version'")
    log("  8. Re-run Nessus scan with valid credentials to confirm remediation.")

def main():
    log("="*65)
    log("Fix Script - Plugin 93736 - Cisco IOS BENIGNCERTAIN")
    log("CVE-2016-6415 | CISA KEV | Cisco Bug CSCvb29204")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        collect_ikev1_policy(connection)
        collect_isakmp_config(connection)
        generate_remediation_note()

        connection.disconnect()
        log(f"Audit complete. Full log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()