#!/usr/bin/env python3
"""
Fix Script - Plugin 127049
Cisco IOS Software Network PnP Agent Certificate Validation
CVE-2019-1748 | Bug IDs: CSCvf36269, CSCvg01089

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check PnP agent configuration and state
  4. Check PnP profile and transport config
  5. Optionally disable PnP agent
  6. Generate remediation report

KEY NOTES:
  - MitM vulnerability — C:H/I:H (data interception/modification risk)
  - NOT a DoS — this affects CONFIDENTIALITY and INTEGRITY
  - Different risk profile from all other plugins on this device
  - PnP is typically only active during initial provisioning
  - Production devices may already have PnP idle/unconfigured
  - Detection is VERSION-BASED ONLY — Nessus did not actively test
  - Full fix = IOS upgrade per CSCvf36269/CSCvg01089
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

# Set True to disable PnP agent if confirmed not needed for provisioning
DISABLE_PNP = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_127049_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_127049_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-pnp-cert")

def check_pnp_config(connection):
    log("── STEP 3: Checking PnP Agent Configuration ──")

    # PnP in running config
    pnp_cfg = connection.send_command("show running-config | include pnp")
    log("  PnP config lines:")
    log(pnp_cfg if pnp_cfg.strip() else "  No 'pnp' config lines found.")

    pnp_configured = bool(pnp_cfg.strip())

    if pnp_configured:
        log("  ⚠️  PnP is configured on this device.")
        log("  CVE-2019-1748 MitM attack surface may be active.")
    else:
        log("  ✅ No explicit PnP configuration found.")
        log("  PnP agent may still be running in background on some IOS versions.")

    # PnP profile section
    pnp_profile = connection.send_command(
        "show running-config | section pnp"
    )
    if pnp_profile.strip():
        log("  PnP profile/section config:")
        log(pnp_profile)

    # PnP startup VLAN
    pnp_vlan = connection.send_command(
        "show running-config | include pnp startup-vlan"
    )
    if pnp_vlan.strip():
        log(f"  PnP startup VLAN: {pnp_vlan.strip()}")

    return pnp_configured

def check_pnp_agent_state(connection):
    log("── STEP 4: PnP Agent Runtime State ──")

    # PnP agent status
    pnp_status = connection.send_command("show pnp status")
    if pnp_status.strip() and "%" not in pnp_status:
        log("  PnP agent status:")
        log(pnp_status)

        if "Idle" in pnp_status or "IDLE" in pnp_status:
            log("  ✅ PnP agent is IDLE — not actively communicating.")
            log("  Certificate validation attack only possible during active PnP sessions.")
        elif "Active" in pnp_status or "ACTIVE" in pnp_status:
            log("  ⚠️  PnP agent is ACTIVE — MitM attack currently feasible.")
        elif "Disabled" in pnp_status or "disabled" in pnp_status:
            log("  ✅ PnP agent is DISABLED.")
    else:
        log("  'show pnp status' not available or no output.")
        log("  Check PnP agent state manually.")

    # PnP session info
    pnp_session = connection.send_command("show pnp session")
    if pnp_session.strip() and "%" not in pnp_session:
        log("  PnP session info:")
        log(pnp_session)
    else:
        log("  No active PnP sessions.")

def check_pnp_transport(connection):
    log("── STEP 5: PnP Transport Configuration ──")

    # Transport method (HTTP/HTTPS to PnP server)
    transport_cfg = connection.send_command(
        "show running-config | section pnp profile"
    )
    if transport_cfg.strip():
        log("  PnP transport/profile config:")
        log(transport_cfg)

        if "https" in transport_cfg.lower():
            log("  PnP using HTTPS transport.")
            log("  Certificate validation bypass is the key risk here.")
        elif "http" in transport_cfg.lower():
            log("  ⚠️  PnP using plain HTTP — no TLS, but MitM trivially possible.")

    # Check for DNA Center / PnP Connect server
    pnp_server = connection.send_command(
        "show running-config | include pnp.*server|transport.*pnp"
    )
    if pnp_server.strip():
        log(f"  PnP server config: {pnp_server.strip()}")

def disable_pnp(connection):
    log("── STEP 6: Disabling PnP Agent (DISABLE_PNP=True) ──")

    commands = []

    # Remove PnP profiles
    pnp_profiles = connection.send_command(
        "show running-config | include pnp profile"
    )
    for line in pnp_profiles.splitlines():
        if "pnp profile" in line.strip():
            profile_name = line.strip().split("pnp profile")[-1].strip()
            if profile_name:
                commands.append(f"no pnp profile {profile_name}")
                log(f"  Removing PnP profile: {profile_name}")

    # Disable PnP startup VLAN
    commands.append("no pnp startup-vlan")

    # Stop PnP agent
    commands.append("pnp agent stop")

    if commands:
        output = connection.send_config_set(commands)
        log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ PnP agent disabled.")
    log("  CVE-2019-1748 MitM attack surface eliminated.")
    log("  ⚠️  PnP zero-touch provisioning no longer available.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 127049 - CVE-2019-1748 - Cisco IOS PnP Certificate Validation")
    log("")
    log("UNIQUE RISK PROFILE — Different from all other plugins on this device:")
    log("  All other plugins = DoS (Availability impact)")
    log("  This plugin = MitM (Confidentiality + Integrity impact)")
    log("  CVSS C:H/I:H/A:N — data interception/modification, not service disruption")
    log("")
    log("Attack scenario:")
    log("  Attacker intercepts PnP provisioning session")
    log("  Presents forged certificate that IOS does not properly validate")
    log("  Decrypts and modifies configuration data sent to device")
    log("  Could result in unauthorized config push to device")
    log("")
    log("PnP lifecycle on production devices:")
    log("  - Active: Only during initial zero-touch provisioning")
    log("  - Idle: After provisioning complete (most production devices)")
    log("  - If device already configured: PnP likely idle — reduced risk")
    log("")
    log("Mitigation: 'no pnp profile' + 'pnp agent stop'")
    log("  Safe on fully provisioned production devices")
    log("")
    log("Permanent Fix: IOS upgrade per CSCvf36269 / CSCvg01089")
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
    log("Fix Script - Plugin 127049 - Cisco IOS PnP Certificate Validation")
    log("CVE-2019-1748 | CSCvf36269 | CSCvg01089")
    log("MitM vulnerability — C:H/I:H (unique on this device)")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        pnp_configured = check_pnp_config(connection)
        check_pnp_agent_state(connection)
        check_pnp_transport(connection)

        if DISABLE_PNP:
            disable_pnp(connection)
        else:
            log("── STEP 6: Skipped (DISABLE_PNP=False) ──")
            log("   Set DISABLE_PNP=True if PnP is confirmed unused on this device.")
            log("   Safe to disable on production devices that are already configured.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()