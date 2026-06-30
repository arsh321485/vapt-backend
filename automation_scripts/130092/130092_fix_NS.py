#!/usr/bin/env python3
"""
Fix Script - Plugin 130092
Cisco IOS Software IP SLA DoS Vulnerability
CVE-2019-1737 | Bug ID: CSCvf37838

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check IP SLA responder state
  4. Check active IP SLA operations and schedules
  5. Optionally disable IP SLA responder
  6. Generate remediation report

KEY NOTES:
  - Unauthenticated attacker — higher risk than auth-required vulns
  - CVSS 8.6 — HIGHEST scoring plugin on this device
  - Attack causes interface wedge (not just reload) — harder to recover
  - 'no ip sla responder' is a clean, safe mitigation if SLA unused
  - Full fix = IOS upgrade per CSCvf37838
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

# Set True if IP SLA responder is confirmed NOT used by any monitoring system
# Applies 'no ip sla responder' to fully disable SLA packet processing
DISABLE_IPSLA_RESPONDER = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_130092_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_130092_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-ipsla-dos")

def check_ipsla_responder(connection):
    log("── STEP 3: Checking IP SLA Responder State ──")

    # Check responder in config
    sla_cfg = connection.send_command("show running-config | include ip sla responder")
    log("  IP SLA responder config lines:")
    log(sla_cfg if sla_cfg.strip() else "  No 'ip sla responder' config found.")

    responder_enabled = ("ip sla responder" in sla_cfg and
                         "no ip sla responder" not in sla_cfg)

    if responder_enabled:
        log("  ⚠️  IP SLA responder is ENABLED.")
        log("  CVE-2019-1737 attack surface CONFIRMED.")
        log("  Unauthenticated attacker can send crafted SLA packets.")
    else:
        log("  ✅ 'ip sla responder' does NOT appear to be explicitly enabled.")
        log("  Verify with 'show ip sla responder' for runtime state.")

    # Show runtime responder state
    responder_runtime = connection.send_command("show ip sla responder")
    log("  IP SLA responder runtime state:")
    log(responder_runtime if responder_runtime.strip()
        else "  No runtime responder info (may not be active).")

    return responder_enabled

def check_ipsla_operations(connection):
    log("── STEP 4: Checking Active IP SLA Operations ──")

    # SLA operations configured
    sla_ops = connection.send_command("show ip sla configuration")
    if sla_ops.strip() and "No SLA" not in sla_ops:
        log("  Active IP SLA operations:")
        log(sla_ops[:800] if len(sla_ops) > 800 else sla_ops)
        log("  ℹ️  SLA operations are configured on this device.")
        log("  This device is SOURCING SLA probes (separate from responder role).")
    else:
        log("  No IP SLA operations configured on this device.")

    # SLA schedule
    sla_schedule = connection.send_command("show ip sla schedule")
    if sla_schedule.strip() and "No" not in sla_schedule:
        log("  IP SLA schedules:")
        log(sla_schedule)
    else:
        log("  No IP SLA schedules found.")

    # SLA summary stats
    sla_stats = connection.send_command("show ip sla summary")
    if sla_stats.strip():
        log("  IP SLA summary:")
        log(sla_stats[:500] if len(sla_stats) > 500 else sla_stats)

def check_interface_wedge_indicators(connection):
    log("── STEP 5: Checking for Interface Wedge Indicators ──")
    log("  (Interface wedge = interface stays up but drops all traffic)")

    # Input/output queue drops on interfaces
    output = connection.send_command("show interfaces | include input queue|output queue|drops")
    if output.strip():
        log("  Interface queue/drop stats:")
        log(output)

        # Flag high drop counts
        for line in output.splitlines():
            if "drop" in line.lower():
                parts = line.split()
                for i, part in enumerate(parts):
                    try:
                        val = int(part.replace(",", ""))
                        if val > 100:
                            log(f"  ⚠️  High drop count detected: {line.strip()}")
                            log("  This could indicate an active interface wedge condition.")
                            break
                    except ValueError:
                        continue
    else:
        log("  No interface queue/drop data found.")

    # Check for interfaces in wedged state (up/up but no traffic)
    brief = connection.send_command("show ip interface brief | exclude unassigned|down")
    log("  Interface state summary:")
    log(brief if brief.strip() else "  No interface data.")

def disable_ipsla_responder(connection):
    log("── STEP 6: Disabling IP SLA Responder (DISABLE_IPSLA_RESPONDER=True) ──")
    log("  Applying 'no ip sla responder'...")

    commands = ["no ip sla responder"]
    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ IP SLA responder disabled.")
    log("  CVE-2019-1737 attack surface eliminated.")
    log("  ⚠️  Confirm no monitoring systems lost SLA probe responses.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 130092 - CVE-2019-1737 - Cisco IOS IP SLA DoS")
    log("HIGHEST CVSS ON THIS DEVICE: 8.6")
    log("")
    log("Mitigation: 'no ip sla responder' (if responder not required)")
    log("")
    log("Risk: Interface WEDGE (not just reload)")
    log("  A wedged interface stays operationally up but drops all traffic.")
    log("  Recovery requires interface shutdown/no shutdown or device reload.")
    log("  This makes it more disruptive than a simple reload attack.")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvf37838")
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
    log("Fix Script - Plugin 130092 - Cisco IOS IP SLA DoS")
    log("CVE-2019-1737 | CSCvf37838 | CVSS 8.6 — HIGHEST on device")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        responder_enabled = check_ipsla_responder(connection)
        check_ipsla_operations(connection)
        check_interface_wedge_indicators(connection)

        if DISABLE_IPSLA_RESPONDER:
            if responder_enabled:
                disable_ipsla_responder(connection)
            else:
                log("── STEP 6: IP SLA responder not enabled — no action needed. ──")
        else:
            log("── STEP 6: Skipped (DISABLE_IPSLA_RESPONDER=False) ──")
            log("   Set DISABLE_IPSLA_RESPONDER=True if IP SLA responder is unused.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()