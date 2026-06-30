#!/usr/bin/env python3
"""
Fix Script - Plugin 108880
Cisco IOS Software LLDP Buffer Overflow Vulnerabilities
CVE-2018-0167 | CVE-2018-0175
Bug IDs: CSCvd73487, CSCvd73664
CISA Known Exploited Vulnerability — Listed 2022/03/17

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check LLDP global state
  4. Document LLDP neighbors (pre-disable snapshot)
  5. Check LLDP per-interface state
  6. Optionally disable LLDP globally with 'no lldp run'
  7. Generate remediation report

KEY NOTES:
  - CISA KEV #4 on this device — actively exploited in the wild
  - CVSS 8.8 — HIGHEST on device (C:H/I:H/A:H = potential RCE)
  - Attack vector: ADJACENT (L2 segment) — attacker sends malformed LLDP
  - 'no lldp run' is a STRONG mitigation — disables all LLDP processing
  - VPR 7.4 — highest VPR score on this device
  - Full fix = IOS upgrade per CSCvd73487/CSCvd73664
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

# Set True if LLDP is confirmed NOT needed for network management
# Applies 'no lldp run' to disable LLDP globally
DISABLE_LLDP = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_108880_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_108880_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-lldp")
    log("  CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

def check_lldp_global_state(connection):
    log("── STEP 3: Checking LLDP Global State ──")

    # LLDP global status
    lldp_status = connection.send_command("show lldp")
    log("  LLDP global status:")
    log(lldp_status if lldp_status.strip() else "  No LLDP output (may be disabled).")

    # LLDP in running config
    lldp_cfg = connection.send_command("show running-config | include lldp")
    log("  LLDP config lines:")
    log(lldp_cfg if lldp_cfg.strip() else "  No LLDP config lines found.")

    # Determine state
    lldp_enabled = False
    if lldp_status.strip():
        if "LLDP is not enabled" in lldp_status or "not enabled" in lldp_status.lower():
            log("  ✅ LLDP is already DISABLED globally.")
        else:
            log("  ⚠️  LLDP is ENABLED globally.")
            log("  CVE-2018-0167 and CVE-2018-0175 attack surface ACTIVE.")
            lldp_enabled = True
    elif "no lldp run" in lldp_cfg:
        log("  ✅ 'no lldp run' found in config — LLDP disabled.")
    else:
        log("  ℹ️  LLDP state unclear — verify manually with 'show lldp'.")
        lldp_enabled = True  # Assume enabled if unclear

    return lldp_enabled

def document_lldp_neighbors(connection):
    log("── STEP 4: Documenting LLDP Neighbors (pre-disable snapshot) ──")

    # LLDP neighbors brief
    neighbors = connection.send_command("show lldp neighbors")
    if neighbors.strip() and "not enabled" not in neighbors.lower():
        log("  Current LLDP neighbors:")
        log(neighbors)

        # Count neighbors
        neighbor_lines = [l for l in neighbors.splitlines()
                         if l.strip() and not l.startswith("Capability")
                         and "Device ID" not in l and "---" not in l
                         and "Total" not in l]
        log(f"  LLDP neighbor count: ~{len(neighbor_lines)}")
        if neighbor_lines:
            log("  ⚠️  Active LLDP neighbors — verify management tools don't rely on this data.")
    else:
        log("  No LLDP neighbors found or LLDP not active.")

    # LLDP neighbors detail
    detail = connection.send_command("show lldp neighbors detail")
    if detail.strip() and "not enabled" not in detail.lower() and len(detail) > 50:
        log("  LLDP neighbor details (first 500 chars):")
        log(detail[:500])

def check_lldp_interfaces(connection):
    log("── STEP 5: LLDP Per-Interface State ──")

    # LLDP interface config
    iface_cfg = connection.send_command(
        "show running-config | include lldp transmit|lldp receive|lldp"
    )
    if iface_cfg.strip():
        log("  Per-interface LLDP config:")
        log(iface_cfg[:400] if len(iface_cfg) > 400 else iface_cfg)
    else:
        log("  No per-interface LLDP overrides — global setting applies to all.")

    # LLDP interface summary
    lldp_iface = connection.send_command("show lldp interface")
    if lldp_iface.strip() and "not enabled" not in lldp_iface.lower():
        log("  LLDP interface summary:")
        lines = lldp_iface.splitlines()[:20]
        log("\n".join(lines))
    else:
        log("  No LLDP interface data (LLDP may be disabled).")

def disable_lldp(connection):
    log("── STEP 6: Disabling LLDP Globally (DISABLE_LLDP=True) ──")
    log("  Applying 'no lldp run'...")

    commands = ["no lldp run"]
    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ LLDP disabled globally.")
    log("  CVE-2018-0167 (buffer overflow) — MITIGATED.")
    log("  CVE-2018-0175 (buffer overflow) — MITIGATED.")
    log("  ⚠️  LLDP neighbor discovery no longer active on any interface.")
    log("  ⚠️  Verify management/monitoring tools that use LLDP neighbor data.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 108880 - CVE-2018-0167 + CVE-2018-0175 - LLDP Buffer Overflow")
    log("⚠️  CISA KNOWN EXPLOITED VULNERABILITY — 2022/03/17")
    log("⚠️  CVSS 8.8 — HIGHEST on this device | C:H/I:H/A:H | Potential RCE")
    log("⚠️  VPR 7.4 — HIGHEST VPR on this device")
    log("")
    log("This is CISA KEV #4 on this device:")
    log("  1. Plugin 93736  — CVE-2016-6415 (BENIGNCERTAIN)")
    log("  2. Plugin 131166 — CVE-2018-0154 (ISM-VPN DoS)")
    log("  3. Plugin 103693 — CVE-2017-12237 (IKE DoS)")
    log("  4. Plugin 108880 — CVE-2018-0167/0175 (LLDP Buffer Overflow) ← THIS")
    log("")
    log("Mitigation: 'no lldp run' — disables all LLDP processing")
    log("  Clean and safe if LLDP not required for management")
    log("  CDP (Cisco Discovery Protocol) can substitute for device discovery")
    log("")
    log("Permanent Fix: IOS upgrade per CSCvd73487 / CSCvd73664")
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
    log("Fix Script - Plugin 108880 - Cisco IOS LLDP Buffer Overflow")
    log("CVE-2018-0167 | CVE-2018-0175 | CSCvd73487 | CSCvd73664")
    log("CISA KEV #4 | CVSS 8.8 (HIGHEST) | VPR 7.4 (HIGHEST)")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        lldp_enabled = check_lldp_global_state(connection)
        document_lldp_neighbors(connection)
        check_lldp_interfaces(connection)

        if DISABLE_LLDP:
            if not lldp_enabled:
                log("── STEP 6: LLDP already disabled — no action needed. ──")
            else:
                disable_lldp(connection)
        else:
            log("── STEP 6: Skipped (DISABLE_LLDP=False) ──")
            log("   Set DISABLE_LLDP=True if LLDP is confirmed not needed.")
            log("   ⚠️  CISA KEV + CVSS 8.8 — prioritize this immediately.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()