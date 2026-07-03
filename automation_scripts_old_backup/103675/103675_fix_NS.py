#!/usr/bin/env python3
"""
Fix Script - Plugin 103675
Cisco IOS Software PnP PKI API Certificate Validation
CVE-2017-12228 | Bug ID: CSCvc33171

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check PnP agent state
  4. Audit PKI trustpool configuration
  5. Cross-reference Plugin 127049 mitigation status
  6. Optionally disable PnP agent
  7. Generate remediation report

KEY NOTES:
  - CVE-2017-12228 — PnP PKI API cert validation
  - CVE-2019-1748 — PnP MitM cert validation (Plugin 127049)
  - BOTH are PnP certificate validation issues
  - BOTH mitigated by same command: disable PnP agent
  - If Plugin 127049 already mitigated → THIS IS ALSO MITIGATED
  - AC:H — High complexity attack
  - C:H — High confidentiality impact (A:N — no availability)
  - tcp/0 detection (version-based, not service-specific)
  - Modified: 2025/11/19 — recently updated
  - Full fix = IOS upgrade per CSCvc33171
"""

from netmiko import ConnectHandler
import datetime
import sys

DEVICE = {
    "device_type": "cisco_ios",
    "host": "192.168.1.1",
    "username": "admin",
    "password": "yourpassword",
    "secret": "yourenable",
    "port": 22,
    "timeout": 30,
}

# Set True to disable PnP agent (mitigates both 103675 and 127049)
DISABLE_PNP = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_103675_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_103675_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-pnp")
    log("  Modified: 2025/11/19 — recently updated advisory")

def check_pnp_state(connection):
    log("── STEP 3: PnP Agent State ──")

    pnp_cfg = connection.send_command("show running-config | include pnp")
    log("  PnP config lines:")
    log(pnp_cfg if pnp_cfg.strip() else "  No PnP config found.")

    # PnP status
    pnp_status = connection.send_command("show pnp status")
    if pnp_status.strip() and "%" not in pnp_status:
        log("  PnP status:")
        log(pnp_status)

        if "Disabled" in pnp_status or "disabled" in pnp_status:
            log("  ✅ PnP agent is DISABLED — CVE-2017-12228 mitigated.")
        elif "Idle" in pnp_status:
            log("  ℹ️  PnP agent is IDLE — low risk on production device.")
        elif "Active" in pnp_status:
            log("  ⚠️  PnP agent is ACTIVE — PKI API exposure confirmed.")
    else:
        log("  'show pnp status' not available or no output.")
        log("  PnP state unclear — check 'show running-config | include pnp'.")

    return bool(pnp_cfg.strip())

def check_pki_trustpool(connection):
    log("── STEP 4: PKI Trustpool Audit ──")
    log("  CVE-2017-12228 is specifically about the PnP PKI API.")

    # PKI trustpool
    trustpool = connection.send_command("show crypto pki trustpool | count")
    log(f"  PKI trustpool entries: {trustpool.strip()}")

    # Trustpoints
    trustpoints = connection.send_command(
        "show running-config | include crypto pki trustpoint"
    )
    if trustpoints.strip():
        log("  PKI trustpoints configured:")
        log(trustpoints)
    else:
        log("  No explicit PKI trustpoints configured.")

    # PKI certificates
    pki_cert = connection.send_command("show crypto pki certificates")
    if pki_cert.strip() and "%" not in pki_cert:
        cert_count = pki_cert.count("Certificate")
        log(f"  PKI certificates present: ~{cert_count}")
    else:
        log("  No PKI certificates found.")

def check_127049_mitigation_status(connection):
    log("── STEP 5: Cross-Reference Plugin 127049 (CVE-2019-1748) ──")
    log("  Both Plugin 103675 and 127049 are PnP certificate validation issues.")
    log("  Disabling PnP mitigates BOTH simultaneously.")
    log("")

    pnp_cfg = connection.send_command("show running-config | include pnp")
    pnp_status = connection.send_command("show pnp status")

    already_disabled = (
        "no pnp" in pnp_cfg.lower() or
        "Disabled" in pnp_status or
        (not pnp_cfg.strip() and "not enabled" in pnp_status.lower())
    )

    log("  Plugin 103675 (CVE-2017-12228) — PnP PKI API cert validation")
    log("  Plugin 127049 (CVE-2019-1748)  — PnP MitM cert validation")
    log("")

    if already_disabled:
        log("  ✅ PnP agent appears disabled — BOTH 103675 and 127049 mitigated.")
    else:
        log("  ⚠️  PnP agent active — BOTH plugins exposed.")
        log("  Disabling PnP: 'pnp agent stop' + 'no pnp profile <name>'")

    return already_disabled

def disable_pnp_agent(connection):
    log("── STEP 6: Disabling PnP Agent (DISABLE_PNP=True) ──")

    # Get profile names
    pnp_profiles = connection.send_command(
        "show running-config | include pnp profile"
    )
    commands = []

    for line in pnp_profiles.splitlines():
        if "pnp profile" in line.strip():
            profile_name = line.strip().split("pnp profile")[-1].strip()
            if profile_name:
                commands.append(f"no pnp profile {profile_name}")
                log(f"  Removing PnP profile: {profile_name}")

    commands.append("pnp agent stop")
    commands.append("no pnp startup-vlan")

    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ PnP agent disabled.")
    log("  Both CVE-2017-12228 (Plugin 103675) and CVE-2019-1748 (Plugin 127049) mitigated.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 103675 - CVE-2017-12228 - Cisco IOS PnP PKI API")
    log("")
    log("PnP plugins on this device:")
    log("  Plugin 103675 (CVE-2017-12228) — PnP PKI API cert validation")
    log("    CVSS: 5.9 | C:H/I:N/A:N | AC:H | tcp/0")
    log("  Plugin 127049 (CVE-2019-1748) — PnP MitM cert validation")
    log("    CVSS: 7.4 | C:H/I:H/A:N | AC:H | tcp/161")
    log("")
    log("  SHARED MITIGATION: Disabling PnP agent fixes BOTH")
    log("  'pnp agent stop' + 'no pnp profile <name>'")
    log("")
    log("  If Plugin 127049 already mitigated → 103675 is ALSO mitigated")
    log("")
    log("Context:")
    log("  - AC:H — attacker needs specific conditions to exploit")
    log("  - C:H — confidentiality impact (credential/data exposure)")
    log("  - A:N — no availability impact")
    log("  - PnP typically idle on production devices after deployment")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvc33171")
    log("Installed: 15.4(3)M5 | Modified: 2025/11/19")
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
    log("Fix Script - Plugin 103675 - Cisco IOS PnP PKI API")
    log("CVE-2017-12228 | CSCvc33171 | CVSS 5.9 | C:H/A:N")
    log("Shares mitigation with Plugin 127049 (CVE-2019-1748)")
    log("="*65)

    try:
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        backup_config(connection)
        collect_ios_version(connection)
        pnp_active = check_pnp_state(connection)
        check_pki_trustpool(connection)
        already_mitigated = check_127049_mitigation_status(connection)

        if already_mitigated:
            log("── STEP 6: Already mitigated (PnP disabled) — no action needed. ──")
        elif DISABLE_PNP:
            disable_pnp_agent(connection)
        else:
            log("── STEP 6: Skipped (DISABLE_PNP=False) ──")
            log("   Set DISABLE_PNP=True to disable PnP agent.")
            log("   This mitigates both Plugin 103675 AND Plugin 127049.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()