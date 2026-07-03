#!/usr/bin/env python3
"""
Fix Script - Plugin 155733
Cisco IOS Software IKEv2 AutoReconnect Feature DoS
CVE-2021-1620 | Bug ID: CSCvw25564

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check IKEv2 profile configuration for AutoReconnect
  4. Check IP local pool configuration and utilization
  5. Check active IKEv2 sessions
  6. Optionally disable AutoReconnect per IKEv2 profile
  7. Generate remediation report

KEY NOTES:
  - Requires AUTHENTICATED attacker — lower exploitability
  - Only vulnerable if IKEv2 AutoReconnect is enabled (not default)
  - Only affects devices with IP local pools configured (FlexVPN/AnyConnect)
  - Full fix = IOS upgrade per CSCvw25564
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

# Set True to disable AutoReconnect on all IKEv2 profiles
# Only apply if AutoReconnect is confirmed not needed by VPN clients
DISABLE_AUTORECONNECT = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_155733_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_155733_{DEVICE['host']}_{TIMESTAMP}.txt"
    with open(backup_file, "w") as f:
        f.write(config)
    log(f"Config backed up to: {backup_file}")

def collect_ios_version(connection):
    log("── STEP 2: IOS Version Collection ──")
    output = connection.send_command("show version")
    for line in output.splitlines():
        if "Cisco IOS Software" in line or "Version" in line:
            log(f"  {line.strip()}")
    log("  Installed: 15.4(3)M5 (from Nessus output)")
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ikev2-ebFrwMPr")

def check_ikev2_profiles(connection):
    log("── STEP 3: Checking IKEv2 Profile Configuration ──")

    # Full IKEv2 profile section
    profiles = connection.send_command("show running-config | section crypto ikev2 profile")
    if profiles.strip():
        log("  IKEv2 profiles configured:")
        log(profiles)

        # Check for AutoReconnect
        if "reconnect" in profiles.lower() or "autoreconnect" in profiles.lower():
            log("  ⚠️  AutoReconnect appears to be configured in IKEv2 profile(s).")
            log("  CVE-2021-1620 exposure CONFIRMED — device is vulnerable.")
        else:
            log("  ℹ️  AutoReconnect keyword not found in IKEv2 profiles.")
            log("  Device may not have AutoReconnect enabled.")
            log("  Verify manually: look for 'aaa authorization group' with reconnect settings.")
    else:
        log("  No IKEv2 profiles configured.")
        log("  ✅ AutoReconnect exposure likely not applicable.")

    # Parse profile names for later use
    profile_names = []
    for line in profiles.splitlines():
        if line.strip().startswith("crypto ikev2 profile"):
            parts = line.strip().split()
            if len(parts) >= 4:
                profile_names.append(parts[3])

    log(f"  Found IKEv2 profile names: {profile_names if profile_names else 'None'}")
    return profile_names

def check_ip_pools(connection):
    log("── STEP 4: Checking IP Local Pool Configuration ──")

    # IP local pools
    pools = connection.send_command("show running-config | include ip local pool")
    if pools.strip():
        log("  IP local pools configured:")
        log(pools)
        log("  ⚠️  Local pools present — AutoReconnect exhaustion attack is feasible.")
    else:
        log("  No IP local pools configured.")
        log("  ✅ Pool exhaustion attack not applicable without local pools.")

    # Pool utilization
    log("  >> Current IP pool utilization:")
    pool_usage = connection.send_command("show ip local pool")
    log(pool_usage if pool_usage.strip() else "  No pool utilization data available.")

    return bool(pools.strip())

def check_active_ikev2_sessions(connection):
    log("── STEP 5: Active IKEv2 Sessions ──")
    output = connection.send_command("show crypto ikev2 sa")
    if output.strip():
        log("  Active IKEv2 SAs:")
        log(output)
        # Count sessions
        session_count = len([l for l in output.splitlines()
                             if "READY" in l or "ESTABLISHED" in l])
        log(f"  Active session count: ~{session_count}")
        if session_count > 0:
            log("  ⚠️  Active IKEv2 sessions — check if AutoReconnect clients exist.")
    else:
        log("  No active IKEv2 SAs.")

def check_flexvpn_config(connection):
    log("── STEP 5b: Checking FlexVPN / Virtual-Template Config ──")
    vt_cfg = connection.send_command("show running-config | section virtual-template")
    if vt_cfg.strip():
        log("  Virtual-template config (FlexVPN indicator):")
        log(vt_cfg)
        log("  ℹ️  FlexVPN detected — IKEv2 AutoReconnect more likely to be in use.")
    else:
        log("  No virtual-template config found.")

def disable_autoreconnect(connection, profile_names):
    log("── STEP 6: Disabling AutoReconnect (DISABLE_AUTORECONNECT=True) ──")

    if not profile_names:
        log("  No IKEv2 profiles found — nothing to modify.")
        return

    commands = []
    for profile in profile_names:
        log(f"  Processing profile: {profile}")
        commands.append(f"crypto ikev2 profile {profile}")
        # Disable AutoReconnect within the profile
        commands.append("no aaa authorization group cert list")
        # Note: exact command depends on how AutoReconnect was configured
        # May need to remove specific reconnect-related aaa commands

    log("  ⚠️  NOTE: AutoReconnect disable command varies by config.")
    log("  The exact 'no' command depends on how AutoReconnect was enabled.")
    log("  Common approaches:")
    log("    - Remove 'aaa authorization group' statements in IKEv2 profile")
    log("    - Remove reconnect-specific aaa method lists")
    log("  Review IKEv2 profile config and apply appropriate 'no' commands manually.")
    log("  Consult: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_conn_ikevpn/configuration/xe-16/sec-ike-v2-xe-16-book.html")

    # Apply what we can programmatically
    if commands:
        output = connection.send_config_set(commands)
        log(output)
        save = connection.send_command("write memory")
        log(f"  Config saved: {save}")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 155733 - CVE-2021-1620 - Cisco IOS IKEv2 AutoReconnect DoS")
    log("")
    log("Risk Context:")
    log("  - Requires AUTHENTICATED attacker (lower exploitability)")
    log("  - Only affects devices with IKEv2 AutoReconnect + IP local pools")
    log("  - Lowest priority plugin on this device (Risk Factor: Low)")
    log("")
    log("Mitigation: Disable IKEv2 AutoReconnect feature in IKEv2 profiles")
    log("  (if not required for VPN client reconnect functionality)")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvw25564")
    log("Installed: 15.4(3)M5")
    log("")
    log("Upgrade steps (manual):")
    log("  1. Download fixed IOS image from Cisco.com")
    log("  2. Transfer: 'copy tftp: flash:' or 'copy scp: flash:'")
    log("  3. Verify: 'verify /md5 flash:<image>'")
    log("  4. Set boot: 'boot system flash:<image>'")
    log("  5. Save: 'write memory'")
    log("  6. Reload: 'reload'")
    log("  7. Confirm: 'show version'")
    log("  8. Re-scan Nessus with valid credentials")

def main():
    log("="*65)
    log("Fix Script - Plugin 155733 - Cisco IOS IKEv2 AutoReconnect DoS")
    log("CVE-2021-1620 | CSCvw25564")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        profile_names = check_ikev2_profiles(connection)
        pools_present = check_ip_pools(connection)
        check_active_ikev2_sessions(connection)
        check_flexvpn_config(connection)

        if DISABLE_AUTORECONNECT:
            if not profile_names:
                log("── STEP 6: No IKEv2 profiles found — AutoReconnect not applicable. ──")
            else:
                disable_autoreconnect(connection, profile_names)
        else:
            log("── STEP 6: Skipped (DISABLE_AUTORECONNECT=False) ──")
            log("   Set DISABLE_AUTORECONNECT=True if AutoReconnect is confirmed unused.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()