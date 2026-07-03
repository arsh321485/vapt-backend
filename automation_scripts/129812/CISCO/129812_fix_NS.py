#!/usr/bin/env python3
"""
Fix Script - Plugin 129812
Cisco IOS ISDN Interface Denial of Service
CVE-2019-1752 | Bug IDs: CSCuz74957, CSCvk01977

Actions:
  1. Backup running config
  2. Collect IOS version for upgrade planning
  3. Enumerate ISDN interfaces (BRI/PRI)
  4. Optionally shutdown unused ISDN interfaces to reduce attack surface
  5. Generate remediation report

NOTE: Full fix requires IOS upgrade to patched release.
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

# Set to True ONLY if ISDN interfaces are confirmed unused
# Setting True will shutdown all detected BRI/PRI interfaces
SHUTDOWN_UNUSED_ISDN = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_129812_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_129812_{DEVICE['host']}_{TIMESTAMP}.txt"
    with open(backup_file, "w") as f:
        f.write(config)
    log(f"Config backed up to: {backup_file}")

def collect_ios_version(connection):
    log("── STEP 2: Collecting IOS Version ──")
    output = connection.send_command("show version")
    for line in output.splitlines():
        if "Cisco IOS Software" in line or "Version" in line:
            log(f"  {line.strip()}")
    log("  ACTION: Compare against Cisco fixed releases for CSCuz74957 / CSCvk01977")
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-isdn")

def collect_isdn_interfaces(connection):
    log("── STEP 3: Enumerating ISDN Interfaces (BRI/PRI) ──")
    output = connection.send_command("show interfaces | include BRI|Serial|PRI|isdn")
    if output.strip():
        log("ISDN-related interfaces found:")
        log(output)
    else:
        log("No BRI/PRI interfaces found in 'show interfaces' output.")

    # Check config for ISDN
    isdn_config = connection.send_command("show running-config | include isdn|BRI|PRI")
    if isdn_config.strip():
        log("ISDN config lines:")
        log(isdn_config)
    else:
        log("No ISDN-specific config lines found.")

    return output

def get_isdn_interface_list(connection):
    """Parse BRI interfaces from show interfaces summary"""
    output = connection.send_command("show ip interface brief | include BRI")
    interfaces = []
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].startswith("BRI"):
            interfaces.append(parts[0])
    return interfaces

def shutdown_isdn_interfaces(connection):
    log("── STEP 4: Shutting down ISDN interfaces (SHUTDOWN_UNUSED_ISDN=True) ──")
    isdn_interfaces = get_isdn_interface_list(connection)

    if not isdn_interfaces:
        log("No BRI interfaces detected to shut down.")
        return

    log(f"Found ISDN interfaces: {isdn_interfaces}")
    commands = []
    for iface in isdn_interfaces:
        commands.append(f"interface {iface}")
        commands.append("shutdown")

    log(f"Applying shutdown to: {isdn_interfaces}")
    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"Config saved: {save}")
    log("✅ ISDN interfaces shut down. Attack surface reduced.")
    log("   Verify no active ISDN services were disrupted.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 129812 - CVE-2019-1752 - Cisco IOS ISDN DoS")
    log("")
    log("Permanent Fix: Upgrade IOS to patched release.")
    log("  Bug IDs: CSCuz74957, CSCvk01977")
    log("  Installed: 15.4(3)M5 — verify if this train has a fixed release.")
    log("")
    log("Upgrade steps (manual):")
    log("  1. Download fixed IOS image from Cisco.com")
    log("  2. Transfer image via TFTP/SCP: 'copy tftp: flash:'")
    log("  3. Verify MD5: 'verify /md5 flash:<image>'")
    log("  4. Set boot: 'boot system flash:<image>'")
    log("  5. Save: 'write memory'")
    log("  6. Reload: 'reload'")
    log("  7. Confirm version: 'show version'")
    log("  8. Re-run Nessus with valid credentials")

def main():
    log("="*65)
    log("Fix Script - Plugin 129812 - Cisco IOS ISDN DoS")
    log("CVE-2019-1752 | CSCuz74957 | CSCvk01977")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        collect_isdn_interfaces(connection)

        if SHUTDOWN_UNUSED_ISDN:
            log("⚠️  SHUTDOWN_UNUSED_ISDN is True — proceeding with interface shutdown.")
            shutdown_isdn_interfaces(connection)
        else:
            log("── STEP 4: Skipped (SHUTDOWN_UNUSED_ISDN=False) ──")
            log("   Set SHUTDOWN_UNUSED_ISDN=True if ISDN interfaces are confirmed unused.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()