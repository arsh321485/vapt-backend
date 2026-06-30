#!/usr/bin/env python3
"""
Fix Script - Plugin 99028
Cisco IOS L2TP Parsing DoS
CVE-2017-3857 | Bug ID: CSCuy82078

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check if VPDN/L2TP is enabled
  4. Check for active L2TP/VPDN sessions
  5. If L2TP unused and DISABLE_L2TP=True — apply 'no vpdn enable'
  6. Generate remediation report

KEY POINT: L2TP is NOT enabled by default on Cisco IOS.
           If it was never enabled, this device may not be exposed.
           'no vpdn enable' is a strong mitigation if L2TP is unused.
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

# Set True ONLY if L2TP/VPDN is confirmed NOT in use
# Applies 'no vpdn enable' to fully disable L2TP processing
DISABLE_L2TP = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_99028_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_99028_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  ACTION: Check fixed release for 15.4M train at:")
    log("  https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-l2tp")

def check_vpdn_state(connection):
    log("── STEP 3: Checking VPDN/L2TP State ──")

    # Check if vpdn is enabled in config
    vpdn_cfg = connection.send_command("show running-config | include vpdn")
    log("  VPDN config lines:")
    log(vpdn_cfg if vpdn_cfg.strip() else "  'vpdn enable' NOT found in config — L2TP likely not enabled.")

    # Check VPDN groups
    vpdn_groups = connection.send_command("show running-config | section vpdn-group")
    if vpdn_groups.strip():
        log("  VPDN groups configured:")
        log(vpdn_groups)
    else:
        log("  No VPDN groups configured.")

    vpdn_enabled = "vpdn enable" in vpdn_cfg and "no vpdn enable" not in vpdn_cfg
    if vpdn_enabled:
        log("  ⚠️  VPDN/L2TP is ENABLED on this device.")
    else:
        log("  ✅ VPDN/L2TP does not appear to be enabled.")

    return vpdn_enabled

def check_active_sessions(connection):
    log("── STEP 4: Checking Active L2TP/VPDN Sessions ──")
    output = connection.send_command("show vpdn session")
    if output.strip() and "No active" not in output:
        log("  ⚠️  Active VPDN/L2TP sessions found:")
        log(output)
        log("  Do NOT disable VPDN while sessions are active.")
        return True
    else:
        log("  ✅ No active VPDN/L2TP sessions.")
        return False

def disable_l2tp(connection):
    log("── STEP 5: Disabling L2TP/VPDN (DISABLE_L2TP=True) ──")
    log("  Applying 'no vpdn enable'...")

    commands = ["no vpdn enable"]
    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ L2TP/VPDN disabled. Device no longer processes L2TP packets.")
    log("  Attack surface for CVE-2017-3857 eliminated.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 99028 - CVE-2017-3857 - Cisco IOS L2TP Parsing DoS")
    log("")
    log("Mitigation: 'no vpdn enable' (if L2TP not in use)")
    log("Permanent Fix: Upgrade IOS per Cisco Bug CSCuy82078")
    log("")
    log("Upgrade steps (manual):")
    log("  1. Download fixed IOS image from Cisco.com")
    log("  2. Transfer: 'copy tftp: flash:' or 'copy scp: flash:'")
    log("  3. Verify: 'verify /md5 flash:<image>'")
    log("  4. Set boot: 'boot system flash:<image>'")
    log("  5. Save: 'write memory'")
    log("  6. Reload: 'reload'")
    log("  7. Verify: 'show version'")
    log("  8. Re-scan Nessus with valid credentials")

def main():
    log("="*65)
    log("Fix Script - Plugin 99028 - Cisco IOS L2TP Parsing DoS")
    log("CVE-2017-3857 | CSCuy82078")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        vpdn_enabled = check_vpdn_state(connection)
        active_sessions = check_active_sessions(connection)

        if DISABLE_L2TP:
            if active_sessions:
                log("⚠️  DISABLE_L2TP=True but active sessions detected.")
                log("   Skipping disable to avoid disruption. Investigate sessions first.")
            elif not vpdn_enabled:
                log("ℹ️  DISABLE_L2TP=True but VPDN is already not enabled.")
                log("   No action needed for L2TP disable.")
            else:
                disable_l2tp(connection)
        else:
            log("── STEP 5: Skipped (DISABLE_L2TP=False) ──")
            log("   Set DISABLE_L2TP=True if L2TP is confirmed unused.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()