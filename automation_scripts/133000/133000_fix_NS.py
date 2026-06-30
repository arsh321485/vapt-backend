#!/usr/bin/env python3
"""
Fix Script - Plugin 133000
Cisco IOS Web UI Cross-Site Request Forgery (CSRF)
CVE-2019-16009 | Bug ID: CSCvq66030

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check HTTP/web UI server state
  4. Check for existing HTTP mitigations (Plugins 305769/154234)
  5. Disable HTTP server (Cisco-recommended workaround)
  6. Generate remediation report

KEY NOTES:
  - CVSS 8.8 — C:H/I:H/A:H (full triad — config alter, command exec, reload)
  - Attack = social engineering: trick admin user with malicious link
  - Requires victim to be authenticated to web UI when clicking link
  - Cisco advisory explicitly mentions disabling web UI as workaround
  - Disabling HTTP server mitigates THREE plugins simultaneously:
    Plugin 305769 (HTTP DoS) + Plugin 154234 (TrustSec) + Plugin 133000 (CSRF)
  - If Plugins 305769/154234 already mitigated → THIS IS ALSO MITIGATED
  - Full fix = IOS upgrade per CSCvq66030
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

# Set True to apply Cisco-recommended workaround (disable web UI)
DISABLE_HTTP_SERVER = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_133000_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_133000_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200108-ios-csrf")
    log("  NOTE: Cisco advisory explicitly mentions 'no ip http server' as workaround.")

def check_http_state(connection):
    log("── STEP 3: HTTP/Web UI Server State ──")

    http_cfg = connection.send_command("show running-config | include ip http")
    log("  HTTP configuration lines:")
    log(http_cfg if http_cfg.strip() else "  No 'ip http' config found.")

    http_on = ("ip http server" in http_cfg and
               "no ip http server" not in http_cfg)
    https_on = ("ip http secure-server" in http_cfg and
                "no ip http secure-server" not in http_cfg)

    if not http_on and not https_on:
        log("  ✅ HTTP and HTTPS servers both DISABLED.")
        log("  ✅ CSRF attack surface eliminated — no web UI accessible.")
        log("  This also mitigates Plugins 305769 and 154234.")
        return False

    if http_on:
        log("  ⚠️  HTTP server (port 80) ACTIVE — CSRF exploitable.")
    if https_on:
        log("  ⚠️  HTTPS server (port 443) ACTIVE — CSRF exploitable.")

    log("")
    log("  CSRF attack scenario:")
    log("  1. Admin logs into Cisco IOS web UI")
    log("  2. Attacker tricks admin to click malicious link while authenticated")
    log("  3. Browser silently sends forged request to router web UI")
    log("  4. Router executes request at admin's privilege level")
    log("  5. If admin = priv-15: config changes, command exec, device reload")

    # Check HTTP access controls
    if "ip http access-class" in http_cfg:
        log("  ℹ️  HTTP access-class configured — restricts web UI by ACL.")
        log("  Reduces CSRF risk but doesn't eliminate it.")
    else:
        log("  ⚠️  No HTTP access-class — web UI accessible from any source.")

    return True

def check_existing_http_mitigations(connection):
    log("── STEP 4: Checking Existing HTTP Mitigations (305769/154234) ──")
    log("  Disabling HTTP server mitigates THREE plugins simultaneously:")
    log("  Plugin 305769 (CVE-2026-20125) — HTTP Server DoS")
    log("  Plugin 154234 (CVE-2021-34699) — TrustSec CLI Parser DoS")
    log("  Plugin 133000 (CVE-2019-16009) — CSRF ← THIS PLUGIN")

    http_cfg = connection.send_command("show running-config | include ip http")

    if ("no ip http server" in http_cfg and
            "no ip http secure-server" in http_cfg):
        log("  ✅ All three HTTP-related plugins already mitigated!")
        log("  HTTP server is disabled — no further action needed.")
        return True
    else:
        log("  ⚠️  HTTP server still active.")
        log("  Apply 'no ip http server' to mitigate all three HTTP-related plugins.")
        return False

def check_admin_users(connection):
    log("── STEP 5: Admin User Audit (CSRF Impact Assessment) ──")
    log("  CSRF impact severity depends on victim's privilege level.")
    log("  Priv-15 victim = full device compromise via CSRF.")

    priv15 = connection.send_command(
        "show running-config | include username.*privilege 15"
    )
    if priv15.strip():
        log("  ⚠️  Privilege-15 local accounts found:")
        for line in priv15.splitlines():
            parts = line.strip().split()
            if "username" in parts and len(parts) >= 2:
                log(f"    Admin user: {parts[1]} [priv-15]")
        log("  If any of these admins access web UI → high CSRF impact.")
    else:
        log("  No local privilege-15 accounts detected in running config.")
        log("  Check AAA/RADIUS/TACACS for privilege assignment.")

def disable_http_server(connection):
    log("── STEP 6: Disabling HTTP Server (Cisco-Recommended Workaround) ──")
    log("  This is the workaround mentioned in the Cisco advisory.")

    commands = [
        "no ip http server",
        "no ip http secure-server",
    ]
    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ HTTP/HTTPS server disabled.")
    log("  CSRF attack surface ELIMINATED.")
    log("  THREE plugins mitigated simultaneously:")
    log("    ✅ Plugin 133000 (CVE-2019-16009) — CSRF")
    log("    ✅ Plugin 305769 (CVE-2026-20125) — HTTP DoS")
    log("    ✅ Plugin 154234 (CVE-2021-34699) — TrustSec DoS")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 133000 - CVE-2019-16009 - Cisco IOS Web UI CSRF")
    log("")
    log("CVSS 8.8 — C:H/I:H/A:H (full triad impact):")
    log("  Confidentiality: Config/credentials exposed")
    log("  Integrity: Configuration altered, commands executed")
    log("  Availability: Device reload possible")
    log("")
    log("ATTACK CHAIN:")
    log("  1. Admin authenticates to Cisco IOS web UI")
    log("  2. Attacker sends phishing link to admin")
    log("  3. Admin clicks link while authenticated")
    log("  4. Browser auto-sends CSRF request to router")
    log("  5. Router executes at admin's privilege level")
    log("  → If admin = priv-15: arbitrary config/commands/reload")
    log("")
    log("CISCO-RECOMMENDED WORKAROUND: Disable web UI")
    log("  'no ip http server'")
    log("  'no ip http secure-server'")
    log("")
    log("TRIPLE MITIGATION — One command mitigates THREE plugins:")
    log("  Plugin 133000 — CSRF (this plugin)")
    log("  Plugin 305769 — HTTP Server DoS")
    log("  Plugin 154234 — TrustSec CLI Parser DoS")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvq66030")
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
    log("Fix Script - Plugin 133000 - Cisco IOS Web UI CSRF")
    log("CVE-2019-16009 | CSCvq66030 | CVSS 8.8 | C:H/I:H/A:H")
    log("Cisco workaround: Disable HTTP server (also fixes 305769, 154234)")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        http_active = check_http_state(connection)
        already_mitigated = check_existing_http_mitigations(connection)
        check_admin_users(connection)

        if already_mitigated:
            log("── STEP 6: Already mitigated — no action needed. ──")
        elif DISABLE_HTTP_SERVER:
            if not http_active:
                log("── STEP 6: HTTP already disabled — no action needed. ──")
            else:
                disable_http_server(connection)
        else:
            log("── STEP 6: Skipped (DISABLE_HTTP_SERVER=False) ──")
            log("   Set DISABLE_HTTP_SERVER=True to apply Cisco-recommended workaround.")
            log("   This mitigates Plugins 133000 + 305769 + 154234 simultaneously.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()