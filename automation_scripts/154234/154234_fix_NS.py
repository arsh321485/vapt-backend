#!/usr/bin/env python3
"""
Fix Script - Plugin 154234
Cisco IOS Software TrustSec CLI Parser DoS
CVE-2021-34699 | Bug ID: CSCvx66699

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check TrustSec configuration state
  4. Check HTTP/web UI server state
  5. Optionally disable HTTP server (eliminates attack path)
  6. Generate remediation report

KEY NOTES:
  - Requires AUTHENTICATED access (valid web UI credentials)
  - Attack requires BOTH: TrustSec configured + HTTP server enabled
  - Disabling EITHER eliminates this specific attack path
  - If Plugin 305769 ('no ip http server') already applied → ALREADY MITIGATED
  - TrustSec not common on standard branch/ISR routers
  - Detection is VERSION-BASED ONLY — Nessus did not actively test
  - Full fix = IOS upgrade per CSCvx66699
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

# Set True to disable HTTP server (eliminates attack path)
# NOTE: If Plugin 305769 fix already applied, HTTP is already disabled
DISABLE_HTTP_SERVER = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_154234_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_154234_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-trustsec-dos-7fuXDR2")

def check_trustsec_config(connection):
    log("── STEP 3: Checking TrustSec Configuration ──")

    # CTS (Cisco TrustSec) config
    cts_cfg = connection.send_command("show running-config | include cts|trustsec")
    log("  TrustSec/CTS config lines:")
    log(cts_cfg if cts_cfg.strip() else "  No TrustSec/CTS config lines found.")

    trustsec_configured = bool(cts_cfg.strip())

    if trustsec_configured:
        log("  ⚠️  TrustSec (CTS) is configured on this device.")
        log("  TrustSec attack vector ACTIVE (if HTTP also enabled).")

        # CTS credentials
        cts_creds = connection.send_command("show cts credentials")
        if cts_creds.strip() and "%" not in cts_creds:
            log("  CTS credentials:")
            log(cts_creds[:200] if len(cts_creds) > 200 else cts_creds)

        # SGT/SGACL config
        sgt_cfg = connection.send_command(
            "show running-config | include role-based|cts sgt|ip access-list role"
        )
        if sgt_cfg.strip():
            log("  SGT/RBACL config:")
            log(sgt_cfg[:400] if len(sgt_cfg) > 400 else sgt_cfg)

        # CTS interface
        cts_iface = connection.send_command(
            "show running-config | section interface.*\ncts"
        )
        if cts_iface.strip():
            log("  Interfaces with CTS config:")
            log(cts_iface[:300] if len(cts_iface) > 300 else cts_iface)

    else:
        log("  ✅ No TrustSec/CTS configuration found.")
        log("  Without TrustSec, CVE-2021-34699 attack path requires BOTH features.")
        log("  If TrustSec confirmed absent, mark as 'Not Applicable'.")

    # CTS runtime state
    cts_status = connection.send_command("show cts")
    if cts_status.strip() and "%" not in cts_status:
        log("  CTS runtime status:")
        log(cts_status[:400] if len(cts_status) > 400 else cts_status)

    return trustsec_configured

def check_http_server_state(connection):
    log("── STEP 4: HTTP/Web UI Server State ──")

    http_cfg = connection.send_command("show running-config | include ip http")
    log("  HTTP server config lines:")
    log(http_cfg if http_cfg.strip() else "  No 'ip http' config lines found.")

    http_enabled = ("ip http server" in http_cfg and
                    "no ip http server" not in http_cfg)
    https_enabled = ("ip http secure-server" in http_cfg and
                     "no ip http secure-server" not in http_cfg)

    if not http_enabled and not https_enabled:
        log("  ✅ HTTP AND HTTPS server both DISABLED.")
        log("  ✅ CVE-2021-34699 attack path ALREADY ELIMINATED.")
        log("  (Web UI required for the TrustSec CLI parser attack)")
        log("  Note: Plugin 305769 mitigation may already cover this.")
    else:
        if http_enabled:
            log("  ⚠️  HTTP server (port 80) is ENABLED.")
        if https_enabled:
            log("  ⚠️  HTTPS server (port 443) is ENABLED.")
        log("  ⚠️  Web UI active — TrustSec CLI parser attack path is open.")

    return http_enabled or https_enabled

def check_plugin_305769_status(connection):
    log("── STEP 4b: Cross-Reference Plugin 305769 (HTTP Server DoS) ──")
    log("  Plugin 305769 mitigation: 'no ip http server' + 'no ip http secure-server'")
    log("  If Plugin 305769 fix was already applied, this plugin is ALSO mitigated.")

    http_cfg = connection.send_command("show running-config | include ip http")

    if "no ip http server" in http_cfg and "no ip http secure-server" in http_cfg:
        log("  ✅ CONFIRMED: Plugin 305769 mitigation already applied.")
        log("  ✅ This automatically mitigates Plugin 154234 as well.")
        log("  No additional action needed for this plugin.")
        return True
    else:
        log("  ⚠️  Plugin 305769 mitigation NOT fully applied.")
        log("  Apply 'no ip http server' + 'no ip http secure-server' to")
        log("  simultaneously mitigate both Plugin 305769 AND Plugin 154234.")
        return False

def disable_http_server(connection):
    log("── STEP 5: Disabling HTTP Server (DISABLE_HTTP_SERVER=True) ──")
    log("  Applying 'no ip http server' + 'no ip http secure-server'...")

    commands = [
        "no ip http server",
        "no ip http secure-server",
    ]
    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ HTTP/HTTPS server disabled.")
    log("  CVE-2021-34699 (Plugin 154234) attack path eliminated.")
    log("  CVE-2026-20125 (Plugin 305769) attack path also eliminated.")
    log("  ⚠️  Verify CLI/SSH access still functional.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 154234 - CVE-2021-34699 - Cisco IOS TrustSec CLI Parser DoS")
    log("")
    log("ATTACK REQUIREMENTS (both must be true):")
    log("  1. TrustSec (CTS) is configured on the device")
    log("  2. HTTP/web UI server is enabled")
    log("  → Disabling EITHER eliminates this attack path")
    log("")
    log("SHARED MITIGATION WITH PLUGIN 305769:")
    log("  'no ip http server' + 'no ip http secure-server'")
    log("  Mitigates BOTH Plugin 154234 (TrustSec) AND Plugin 305769 (HTTP DoS)")
    log("  If Plugin 305769 fix already applied → Plugin 154234 is ALREADY FIXED")
    log("")
    log("TrustSec context:")
    log("  - Used in Cisco ISE environments for SGT-based policy")
    log("  - Uncommon on standard branch/ISR/SMB routers")
    log("  - If TrustSec not deployed: mark as 'Not Applicable'")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvx66699")
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
    log("Fix Script - Plugin 154234 - Cisco IOS TrustSec CLI Parser DoS")
    log("CVE-2021-34699 | CSCvx66699 | Auth Required | Web UI + TrustSec")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        trustsec_configured = check_trustsec_config(connection)
        http_enabled = check_http_server_state(connection)
        p305769_mitigated = check_plugin_305769_status(connection)

        if p305769_mitigated:
            log("── STEP 5: SKIPPED — Plugin 305769 mitigation already covers this. ──")
        elif DISABLE_HTTP_SERVER:
            if not http_enabled:
                log("── STEP 5: HTTP already disabled — no action needed. ──")
            else:
                disable_http_server(connection)
        else:
            log("── STEP 5: Skipped (DISABLE_HTTP_SERVER=False) ──")
            if http_enabled and trustsec_configured:
                log("   ❌ BOTH conditions present — attack path is ACTIVE.")
                log("   Set DISABLE_HTTP_SERVER=True to mitigate.")
            elif http_enabled and not trustsec_configured:
                log("   ℹ️  HTTP enabled but TrustSec not configured.")
                log("   Attack path may not be active — verify TrustSec status.")
            elif not http_enabled:
                log("   ✅ HTTP disabled — attack path not available.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()