#!/usr/bin/env python3
"""
Fix Script - Plugin 137835
Cisco IOS IKEv2 DoS Vulnerability
CVE-2020-3230 | Bug ID: CSCvp44397

Actions:
  1. Backup running config
  2. Collect IOS version for upgrade tracking
  3. Enumerate IKEv2 policies, proposals, profiles
  4. Optionally remove IKEv2 proposals if IKEv2 is confirmed unused
  5. Generate remediation handoff report

NOTE: Only remove IKEv2 config if confirmed NOT in use for active VPNs.
      Full fix = IOS upgrade to patched release per CSCvp44397.
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

# Set True ONLY if IKEv2 is confirmed NOT in use for any VPN tunnels
# This removes default IKEv2 proposals as an interim mitigation
DISABLE_IKEV2_IF_UNUSED = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_137835_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_137835_{DEVICE['host']}_{TIMESTAMP}.txt"
    with open(backup_file, "w") as f:
        f.write(config)
    log(f"Config backed up to: {backup_file}")

def collect_ios_version(connection):
    log("── STEP 2: IOS Version Collection ──")
    output = connection.send_command("show version")
    for line in output.splitlines():
        if "Cisco IOS Software" in line or "Version" in line:
            log(f"  {line.strip()}")
    log("  Installed: 15.4(3)M5 (from Nessus plugin output)")
    log("  ACTION: Verify fixed release for 15.4M train at:")
    log("  https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ikev2-9p23Jj2a")

def collect_ikev2_config(connection):
    log("── STEP 3: Enumerating IKEv2 Configuration ──")

    # IKEv2 proposals
    log("  >> IKEv2 Proposals:")
    proposals = connection.send_command("show crypto ikev2 proposal")
    log(proposals if proposals.strip() else "  No IKEv2 proposals configured.")

    # IKEv2 policies
    log("  >> IKEv2 Policies:")
    policies = connection.send_command("show crypto ikev2 policy")
    log(policies if policies.strip() else "  No IKEv2 policies configured.")

    # IKEv2 profiles
    log("  >> IKEv2 Profiles:")
    profiles = connection.send_command("show crypto ikev2 profile")
    log(profiles if profiles.strip() else "  No IKEv2 profiles configured.")

    # Running config IKEv2 section
    log("  >> Running config IKEv2 section:")
    ikev2_cfg = connection.send_command("show running-config | section ikev2")
    log(ikev2_cfg if ikev2_cfg.strip() else "  No IKEv2 config section found.")

    return proposals

def collect_ikev2_sa(connection):
    log("── STEP 4: Active IKEv2 SA Table ──")
    output = connection.send_command("show crypto ikev2 sa")
    if output.strip():
        log("Active IKEv2 SAs found:")
        log(output)
        log("  ⚠️  IKEv2 is actively in use — do NOT disable IKEv2 without VPN migration plan.")
    else:
        log("  No active IKEv2 SAs found.")
        log("  IKEv2 may be safe to disable if no VPN tunnels depend on it.")

def disable_ikev2_proposals(connection):
    """
    Interim mitigation: Remove IKEv2 default proposals.
    This prevents IKEv2 SA-Init negotiation from completing.
    Only apply if IKEv2 is confirmed unused.
    """
    log("── STEP 5: Disabling IKEv2 (DISABLE_IKEV2_IF_UNUSED=True) ──")
    log("  Removing default IKEv2 proposal to block SA-Init processing...")

    commands = [
        "no crypto ikev2 proposal default",
    ]
    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"Config saved: {save}")
    log("  ✅ Default IKEv2 proposal removed.")
    log("  Note: Re-add with 'crypto ikev2 proposal default' if needed.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 137835 - CVE-2020-3230 - Cisco IOS IKEv2 DoS")
    log("")
    log("Permanent Fix: Upgrade IOS to patched release per CSCvp44397.")
    log("Installed: 15.4(3)M5")
    log("")
    log("Upgrade steps (manual):")
    log("  1. Download patched IOS image from Cisco.com")
    log("  2. Transfer: 'copy tftp: flash:' or 'copy scp: flash:'")
    log("  3. Verify MD5: 'verify /md5 flash:<image>'")
    log("  4. Set boot: 'boot system flash:<image>'")
    log("  5. Save config: 'write memory'")
    log("  6. Reload: 'reload'")
    log("  7. Confirm: 'show version'")
    log("  8. Re-scan with Nessus using valid credentials")

def main():
    log("="*65)
    log("Fix Script - Plugin 137835 - Cisco IOS IKEv2 DoS")
    log("CVE-2020-3230 | CSCvp44397")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        collect_ikev2_config(connection)
        collect_ikev2_sa(connection)

        if DISABLE_IKEV2_IF_UNUSED:
            log("⚠️  DISABLE_IKEV2_IF_UNUSED=True — proceeding with IKEv2 proposal removal.")
            disable_ikev2_proposals(connection)
        else:
            log("── STEP 5: Skipped (DISABLE_IKEV2_IF_UNUSED=False) ──")
            log("   Set True only if IKEv2 is confirmed unused and no active SAs exist.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()