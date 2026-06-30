#!/usr/bin/env python3
"""
Fix Script - Plugin 131166
Cisco IOS Software ISM-VPN DoS
CVE-2018-0154 | Bug ID: CSCvd39267
CISA Known Exploited Vulnerability — Listed 2022/03/17

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Detect ISM-VPN hardware module presence
  4. Check crypto engine state
  5. Document VPN config and active sessions
  6. Generate remediation handoff report

KEY NOTES:
  - NO CLI WORKAROUND EXISTS
  - CISA KEV — actively exploited in the wild
  - EPSS 0.1085 — highest exploitation probability on this device
  - Requires ISM-VPN hardware module to be installed
  - If no ISM-VPN module present, device may not be exposed
  - Full fix = IOS upgrade per CSCvd39267
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

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_131166_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_131166_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-dos")
    log("  CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

def check_ism_vpn_module(connection):
    log("── STEP 3: Detecting ISM-VPN Hardware Module ──")
    log("  ⚠️  CRITICAL: This vulnerability ONLY affects devices with ISM-VPN module installed.")

    # Check show diag for ISM-VPN
    diag_output = connection.send_command("show diag")
    if "ISM" in diag_output or "VPN" in diag_output.upper():
        log("  ⚠️  ISM/VPN-related hardware detected in 'show diag':")
        for line in diag_output.splitlines():
            if "ISM" in line or "VPN" in line.upper() or "PVDM" in line:
                log(f"    {line.strip()}")
    else:
        log("  ✅ No ISM or VPN module keyword found in 'show diag'.")
        log("  Device may not have ISM-VPN module — confirm physically.")

    # Check hardware module status
    hw_module = connection.send_command("show hw-module all")
    if hw_module.strip() and "Invalid" not in hw_module:
        log("  Hardware module summary:")
        log(hw_module[:600] if len(hw_module) > 600 else hw_module)
    else:
        log("  'show hw-module all' not supported or no output.")

    # Check platform-specific module info
    platform = connection.send_command("show platform")
    if platform.strip() and "Invalid" not in platform:
        log("  Platform info (excerpt):")
        lines = platform.splitlines()[:15]
        log("\n".join(lines))

def check_crypto_engine(connection):
    log("── STEP 4: Crypto Engine State ──")

    # Crypto engine brief
    engine = connection.send_command("show crypto engine brief")
    if engine.strip():
        log("  Crypto engines:")
        log(engine)
        if "ISM" in engine or "hardware" in engine.lower():
            log("  ⚠️  Hardware crypto engine (ISM-VPN) detected.")
            log("  CVE-2018-0154 exposure CONFIRMED.")
        elif "Software" in engine:
            log("  ℹ️  Software crypto engine only — ISM-VPN may not be present.")
            log("  Verify physically whether ISM-VPN module is installed.")
    else:
        log("  No crypto engine output.")

    # Crypto engine accelerator stats
    accel = connection.send_command("show crypto engine accelerator statistic")
    if accel.strip() and "Invalid" not in accel:
        log("  Crypto accelerator stats (ISM indicator):")
        log(accel[:400] if len(accel) > 400 else accel)

def check_vpn_sessions(connection):
    log("── STEP 5: Documenting VPN Sessions ──")

    # IPSec SA
    ipsec = connection.send_command("show crypto ipsec sa | include pkts encrypt|pkts decrypt|local ident|remote ident")
    if ipsec.strip():
        log("  Active IPSec SAs (summary):")
        log(ipsec[:600] if len(ipsec) > 600 else ipsec)
        log("  ⚠️  Active VPN sessions will be disrupted during IOS upgrade/reload.")
    else:
        log("  No active IPSec SAs found.")

    # IKEv1
    ikev1 = connection.send_command("show crypto isakmp sa")
    log("  IKEv1 SA table:")
    log(ikev1 if ikev1.strip() else "  No IKEv1 SAs.")

    # IKEv2
    ikev2 = connection.send_command("show crypto ikev2 sa")
    log("  IKEv2 SA table:")
    log(ikev2 if ikev2.strip() else "  No IKEv2 SAs.")

def check_vpn_config(connection):
    log("── STEP 5b: VPN Configuration Summary ──")

    # Crypto map
    crypto_map = connection.send_command("show running-config | section crypto map")
    if crypto_map.strip():
        log("  Crypto map config:")
        log(crypto_map[:500] if len(crypto_map) > 500 else crypto_map)
    else:
        log("  No crypto map configured.")

    # Tunnel interfaces
    tunnels = connection.send_command("show ip interface brief | include Tunnel")
    if tunnels.strip():
        log("  Tunnel interfaces:")
        log(tunnels)
    else:
        log("  No tunnel interfaces found.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 131166 - CVE-2018-0154 - Cisco IOS ISM-VPN DoS")
    log("⚠️  CISA KNOWN EXPLOITED VULNERABILITY — ACTIVELY EXPLOITED IN WILD")
    log("⚠️  NO CLI WORKAROUND EXISTS")
    log("")
    log("Conditions for exposure:")
    log("  1. Running vulnerable IOS version (15.4(3)M5 confirmed)")
    log("  2. ISM-VPN hardware module physically installed in device")
    log("  Both conditions must be true for device to be vulnerable")
    log("")
    log("Immediate actions:")
    log("  1. Physically verify if ISM-VPN module is installed")
    log("  2. If installed: prioritize IOS upgrade IMMEDIATELY")
    log("  3. If not installed: document as not applicable after verification")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvd39267")
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
    log("Fix Script - Plugin 131166 - Cisco IOS ISM-VPN DoS")
    log("CVE-2018-0154 | CSCvd39267")
    log("CISA KEV | EPSS 0.1085 | NO WORKAROUND")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        check_ism_vpn_module(connection)
        check_crypto_engine(connection)
        check_vpn_sessions(connection)
        check_vpn_config(connection)
        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()