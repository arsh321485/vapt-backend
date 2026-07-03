#!/usr/bin/env python3
"""
Fix Script - Plugin 141373
Cisco IOS Software ISDN Q.931 DoS
CVE-2020-3511 | Bug ID: CSCvr57760

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Enumerate ISDN BRI/PRI interfaces
  4. Check active ISDN calls
  5. Optionally shutdown unused ISDN interfaces
  6. Generate remediation report

KEY NOTES:
  - Attack vector is ADJACENT (AV:A) — attacker must be on same ISDN segment
  - Not remotely exploitable over the internet
  - This is a SECOND ISDN Q.931 vulnerability on this device
    (Plugin 129812 = CSCuz74957 is the first — different bug, same fix: IOS upgrade)
  - Shutting ISDN interfaces eliminates attack surface for BOTH ISDN plugins
  - Full fix = IOS upgrade per CSCvr57760
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

# Set True ONLY if ISDN interfaces are confirmed unused
# This will shutdown all BRI/PRI interfaces found
# NOTE: Same flag logic as Plugin 129812 fix — if already applied there, skip here
SHUTDOWN_ISDN_INTERFACES = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_141373_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_141373_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-isdn-q931-dos-67eUZBTf")
    log("  NOTE: Also resolves Plugin 129812 (CSCuz74957) — same IOS upgrade covers both ISDN bugs.")

def get_isdn_interfaces(connection):
    """Parse BRI and PRI interfaces from show ip interface brief"""
    output = connection.send_command("show ip interface brief")
    interfaces = []
    for line in output.splitlines():
        parts = line.split()
        if parts and (parts[0].startswith("BRI") or
                      parts[0].startswith("Serial") and ":" in parts[0]):
            interfaces.append(parts[0])
    return interfaces

def check_isdn_interfaces(connection):
    log("── STEP 3: Enumerating ISDN Interfaces ──")

    # BRI interfaces
    bri_output = connection.send_command("show ip interface brief | include BRI")
    log("  BRI interfaces:")
    log(bri_output if bri_output.strip() else "  No BRI interfaces found.")

    # PRI/Serial interfaces with ISDN
    isdn_cfg = connection.send_command(
        "show running-config | include isdn|BRI|pri-group"
    )
    log("  ISDN-related config lines:")
    log(isdn_cfg if isdn_cfg.strip() else "  No ISDN-specific config lines.")

    # Interface brief for BRI state
    interfaces = get_isdn_interfaces(connection)
    if interfaces:
        log(f"  Detected ISDN interfaces: {interfaces}")
        for iface in interfaces:
            state = connection.send_command(f"show interface {iface} | include line protocol")
            log(f"  {iface}: {state.strip()}")
            if "administratively down" in state:
                log(f"    ✅ {iface} already shut down.")
            elif "up" in state:
                log(f"    ⚠️  {iface} is UP — potential exposure to CVE-2020-3511.")
    else:
        log("  ✅ No BRI interfaces detected in IP interface brief.")
        log("  ISDN Q.931 exposure may be minimal or not applicable.")

    return interfaces

def check_active_isdn_calls(connection):
    log("── STEP 4: Checking Active ISDN Calls ──")

    active = connection.send_command("show isdn active")
    if active.strip() and "No Active" not in active:
        log("  ⚠️  Active ISDN calls detected:")
        log(active)
        log("  Do NOT shutdown ISDN interfaces while calls are active.")
        return True
    else:
        log("  ✅ No active ISDN calls.")
        return False

def check_isdn_status(connection):
    log("── STEP 4b: ISDN Status (Layer 1/2/3) ──")
    output = connection.send_command("show isdn status")
    if output.strip():
        log(output)
        if "MULTIPLE_FRAME_ESTABLISHED" in output:
            log("  ⚠️  ISDN Layer 2 is established — active ISDN link present.")
        elif "TEI_ASSIGNED" in output:
            log("  ℹ️  ISDN TEI assigned — D-channel is active.")
    else:
        log("  No ISDN status output — ISDN may not be active.")

def check_q931_config(connection):
    log("── STEP 4c: Q.931 Specific Configuration ──")

    # Check for specific Q.931 timer or variant config
    q931_cfg = connection.send_command(
        "show running-config | include q931|isdn switch-type|isdn protocol-emulate"
    )
    if q931_cfg.strip():
        log("  Q.931/ISDN protocol config:")
        log(q931_cfg)
        if "isdn switch-type" in q931_cfg:
            for line in q931_cfg.splitlines():
                if "isdn switch-type" in line:
                    log(f"  ISDN switch type: {line.strip()}")
                    log("  ℹ️  Switch type determines Q.931 variant in use.")
    else:
        log("  No Q.931 specific config found.")

def shutdown_isdn_interfaces(connection, interfaces):
    log("── STEP 5: Shutting Down ISDN Interfaces (SHUTDOWN_ISDN_INTERFACES=True) ──")

    if not interfaces:
        log("  No ISDN interfaces found to shut down.")
        return

    commands = []
    for iface in interfaces:
        log(f"  Queuing shutdown: {iface}")
        commands.append(f"interface {iface}")
        commands.append("shutdown")
        commands.append("description DISABLED-CVE-2020-3511-CSCvr57760")

    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ ISDN interfaces shut down.")
    log("  CVE-2020-3511 (Plugin 141373) attack surface eliminated.")
    log("  CVE-2019-1752 (Plugin 129812) attack surface also eliminated.")
    log("  ⚠️  Verify no active voice/data services were disrupted.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 141373 - CVE-2020-3511 - Cisco IOS ISDN Q.931 DoS")
    log("")
    log("Attack Vector: ADJACENT (AV:A) — attacker must be on same ISDN segment")
    log("Risk: Lower than remote-exploitable vulns on this device")
    log("")
    log("Mitigation: Shutdown unused ISDN BRI/PRI interfaces")
    log("  Also mitigates Plugin 129812 (CVE-2019-1752) simultaneously")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvr57760")
    log("  Also fixes: CSCuz74957 (Plugin 129812)")
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
    log("Fix Script - Plugin 141373 - Cisco IOS ISDN Q.931 DoS")
    log("CVE-2020-3511 | CSCvr57760 | Attack Vector: Adjacent")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        interfaces = check_isdn_interfaces(connection)
        active_calls = check_active_isdn_calls(connection)
        check_isdn_status(connection)
        check_q931_config(connection)

        if SHUTDOWN_ISDN_INTERFACES:
            if active_calls:
                log("⚠️  Active ISDN calls found — skipping shutdown to avoid disruption.")
                log("   Re-run after calls complete or during maintenance window.")
            elif not interfaces:
                log("── STEP 5: No ISDN interfaces found — nothing to shut down. ──")
            else:
                shutdown_isdn_interfaces(connection, interfaces)
        else:
            log("── STEP 5: Skipped (SHUTDOWN_ISDN_INTERFACES=False) ──")
            log("   Set SHUTDOWN_ISDN_INTERFACES=True if ISDN is confirmed unused.")
            log("   Note: If Plugin 129812 fix already shut these interfaces, skip here.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()