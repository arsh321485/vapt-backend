#!/usr/bin/env python3
"""
Fix Script - Plugin 137654
Cisco IOS SXP (Security Group Tag Exchange Protocol) DoS
CVE-2020-3228 | Bug IDs: CSCvd71220, CSCvp96954, CSCvt30182

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check SXP configuration and runtime state
  4. Enumerate active SXP connections
  5. Optionally disable SXP
  6. Generate remediation report

KEY NOTES:
  - SXP NOT enabled by default — verify before escalating
  - SXP = propagates IP-to-SGT mappings in TrustSec environments
  - Attack = unauthenticated crafted SXP packets → device reload
  - CVSS 8.6 + C:C — tied second-highest with Plugins 130092 and 141170
  - Related to Plugin 154234 (TrustSec CLI) — both need IOS upgrade
  - Common only in ISE/TrustSec policy environments
  - Uncommon on standard branch/ISR routers
  - Full fix = IOS upgrade per CSCvd71220/CSCvp96954/CSCvt30182
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

# Set True ONLY if SXP is confirmed NOT in use for SGT propagation
DISABLE_SXP = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_137654_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_137654_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sxp-68TEVzR")

def check_sxp_config(connection):
    log("── STEP 3: Checking SXP Configuration ──")

    # SXP enable check
    sxp_cfg = connection.send_command("show running-config | include cts sxp")
    log("  SXP config lines:")
    log(sxp_cfg if sxp_cfg.strip() else "  No 'cts sxp' config lines found.")

    sxp_configured = bool(sxp_cfg.strip())

    if sxp_configured:
        log("  ⚠️  SXP is configured on this device.")
        log("  CVE-2020-3228 attack surface ACTIVE.")

        # SXP enable state
        if "cts sxp enable" in sxp_cfg:
            log("  ⚠️  'cts sxp enable' found — SXP is globally enabled.")
        elif "no cts sxp enable" in sxp_cfg:
            log("  ✅ 'no cts sxp enable' found — SXP disabled.")

        # SXP connections configured
        sxp_conn = connection.send_command(
            "show running-config | include cts sxp connection"
        )
        if sxp_conn.strip():
            log("  SXP peer connections configured:")
            log(sxp_conn)
        else:
            log("  No SXP peer connections explicitly configured.")

        # SXP password
        sxp_pass = connection.send_command(
            "show running-config | include cts sxp default password"
        )
        if sxp_pass.strip():
            log("  SXP default password configured.")
        else:
            log("  No SXP default password (connections may use no-auth).")

        # Reconcile period
        sxp_reconcile = connection.send_command(
            "show running-config | include cts sxp reconciliation"
        )
        if sxp_reconcile.strip():
            log(f"  SXP reconciliation: {sxp_reconcile.strip()}")

    else:
        log("  ✅ No SXP configuration found.")
        log("  CVE-2020-3228 likely not applicable on this device.")
        log("  Mark as 'Not Applicable' if physically confirmed.")

    return sxp_configured

def check_sxp_runtime(connection):
    log("── STEP 4: SXP Runtime State ──")

    # SXP connections runtime
    sxp_conn_status = connection.send_command("show cts sxp connections")
    if sxp_conn_status.strip() and "%" not in sxp_conn_status:
        log("  SXP connection status:")
        log(sxp_conn_status[:500] if len(sxp_conn_status) > 500
            else sxp_conn_status)

        # Count active connections
        on_count = sxp_conn_status.count("On")
        off_count = sxp_conn_status.count("Off")
        log(f"  Active SXP connections: {on_count} On, {off_count} Off")

        if on_count > 0:
            log("  ⚠️  Active SXP sessions — disabling will break SGT propagation.")
        else:
            log("  ✅ No active SXP connections — safe to disable.")
    else:
        log("  ✅ 'show cts sxp connections' returned no output.")
        log("  SXP may not be running on this device.")

    # SXP statistics
    sxp_stats = connection.send_command("show cts sxp statistics")
    if sxp_stats.strip() and "%" not in sxp_stats:
        log("  SXP statistics:")
        log(sxp_stats[:400] if len(sxp_stats) > 400 else sxp_stats)

def check_trustsec_relationship(connection):
    log("── STEP 5: TrustSec/SXP Ecosystem Check ──")
    log("  SXP is a component of TrustSec — also check Plugin 154234.")

    # CTS credentials
    cts_creds = connection.send_command("show cts credentials")
    if cts_creds.strip() and "%" not in cts_creds:
        log("  CTS credentials:")
        log(cts_creds[:200] if len(cts_creds) > 200 else cts_creds)
        log("  ⚠️  TrustSec credentials present — full TrustSec deployment detected.")
    else:
        log("  No CTS credentials found.")

    # SGT bindings (SXP IP-to-SGT map)
    sgt_bindings = connection.send_command("show cts sxp sgt-map")
    if sgt_bindings.strip() and "%" not in sgt_bindings:
        log("  Active SGT-to-IP bindings (SXP is propagating tags):")
        log(sgt_bindings[:400] if len(sgt_bindings) > 400 else sgt_bindings)
        log("  ⚠️  Disabling SXP will stop propagating these bindings.")
    else:
        log("  No SGT-to-IP bindings in SXP map — SXP may be idle.")

def disable_sxp(connection):
    log("── STEP 6: Disabling SXP (DISABLE_SXP=True) ──")
    log("  Applying 'no cts sxp enable'...")

    commands = ["no cts sxp enable"]
    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ SXP disabled.")
    log("  CVE-2020-3228 attack surface eliminated.")
    log("  ⚠️  SGT propagation via SXP is now stopped.")
    log("  ⚠️  Verify TrustSec policy enforcement still working.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 137654 - CVE-2020-3228 - Cisco IOS SXP DoS")
    log("")
    log("Key facts:")
    log("  - CVSS 8.6 — C:C (tied 2nd highest on device)")
    log("  - Unauthenticated attack — no credentials needed")
    log("  - SXP NOT default — verify if actually deployed")
    log("  - Common in: Cisco ISE/TrustSec SGT-tagging environments")
    log("  - Uncommon in: Standard enterprise branch/SMB deployments")
    log("")
    log("TrustSec plugins on this device:")
    log("  Plugin 154234 (CVE-2021-34699) — TrustSec CLI Parser DoS")
    log("  Plugin 137654 (CVE-2020-3228)  — SXP DoS ← THIS PLUGIN")
    log("  Both resolved by a single IOS upgrade.")
    log("")
    log("Mitigation: 'no cts sxp enable' — if SXP not required")
    log("")
    log("Permanent Fix: IOS upgrade per CSCvd71220 / CSCvp96954 / CSCvt30182")
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
    log("Fix Script - Plugin 137654 - Cisco IOS SXP DoS")
    log("CVE-2020-3228 | CSCvd71220/CSCvp96954/CSCvt30182 | CVSS 8.6")
    log("SXP not default — verify if actually configured")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        sxp_configured = check_sxp_config(connection)
        check_sxp_runtime(connection)
        check_trustsec_relationship(connection)

        if DISABLE_SXP:
            if not sxp_configured:
                log("── STEP 6: SXP not configured — nothing to disable. ──")
                log("   Mark as 'Not Applicable' if confirmed.")
            else:
                disable_sxp(connection)
        else:
            log("── STEP 6: Skipped (DISABLE_SXP=False) ──")
            if sxp_configured:
                log("   Set DISABLE_SXP=True if SXP/SGT propagation is not required.")
            else:
                log("   SXP not detected — likely Not Applicable.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()