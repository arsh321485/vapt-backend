#!/usr/bin/env python3
"""
Fix Script - Plugin 305769
Cisco IOS Software HTTP Server DoS
CVE-2026-20125 | Bug ID: CSCwq14981

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check HTTP server state (http server + http secure-server)
  4. Check HTTP access-class and authentication config
  5. Optionally disable HTTP and HTTPS server
  6. Generate remediation report

KEY NOTES:
  - Attacker must be AUTHENTICATED — reduces risk vs unauthenticated vulns
  - Disabling HTTP server is best practice on network devices anyway
  - If web UI/REST API is required, upgrade IOS immediately instead
  - Full fix = IOS upgrade per CSCwq14981
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

# Set True if HTTP server is confirmed NOT needed for management
# Disables both 'ip http server' and 'ip http secure-server'
DISABLE_HTTP_SERVER = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_305769_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_305769_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-http-dos-sbv8XRpL")

def check_http_state(connection):
    log("── STEP 3: Checking HTTP Server State ──")

    # Full HTTP config section
    http_cfg = connection.send_command("show running-config | include ip http")
    log("  HTTP-related config lines:")
    log(http_cfg if http_cfg.strip() else "  No 'ip http' config found.")

    # Parse states
    http_enabled = ("ip http server" in http_cfg and
                    "no ip http server" not in http_cfg)
    https_enabled = ("ip http secure-server" in http_cfg and
                     "no ip http secure-server" not in http_cfg)

    if http_enabled:
        log("  ⚠️  'ip http server' (HTTP port 80) is ENABLED.")
    else:
        log("  ✅ 'ip http server' (HTTP) is NOT enabled.")

    if https_enabled:
        log("  ⚠️  'ip http secure-server' (HTTPS port 443) is ENABLED.")
    else:
        log("  ✅ 'ip http secure-server' (HTTPS) is NOT enabled.")

    # HTTP access-class
    if "ip http access-class" in http_cfg:
        log("  ℹ️  HTTP access-class is configured — restricts HTTP access by ACL.")
        log("  This reduces exposure but does NOT fix CVE-2026-20125.")
    else:
        log("  ⚠️  No HTTP access-class — HTTP server accessible without ACL restriction.")

    # HTTP authentication
    if "ip http authentication" in http_cfg:
        log("  ℹ️  HTTP authentication configured.")
    else:
        log("  ℹ️  No explicit HTTP auth config (may use default local auth).")

    return http_enabled, https_enabled

def check_http_timeout(connection):
    log("── STEP 4: Checking HTTP Server Timeout Config ──")
    timeout_cfg = connection.send_command("show running-config | include ip http timeout")
    if timeout_cfg.strip():
        log(f"  HTTP timeout config: {timeout_cfg.strip()}")
    else:
        log("  No custom HTTP timeout configured (using IOS default).")

    # Check active HTTP connections
    http_conn = connection.send_command("show ip http server connection")
    if http_conn.strip():
        log("  Active HTTP connections:")
        log(http_conn)
    else:
        log("  No active HTTP server connections.")

def check_http_users(connection):
    log("── STEP 5: Checking HTTP Authentication / Local Users ──")
    users = connection.send_command("show running-config | include username")
    if users.strip():
        log("  Local user accounts (potential HTTP auth accounts):")
        # Mask passwords in log
        for line in users.splitlines():
            parts = line.split()
            if "password" in parts or "secret" in parts:
                log(f"  username {parts[1] if len(parts) > 1 else '?'} [password redacted]")
            else:
                log(f"  {line.strip()}")
    else:
        log("  No local user accounts found.")

    # AAA config
    aaa = connection.send_command("show running-config | section aaa")
    if aaa.strip():
        log("  AAA config (HTTP auth source):")
        log(aaa)

def disable_http_server(connection, http_enabled, https_enabled):
    log("── STEP 6: Disabling HTTP Server (DISABLE_HTTP_SERVER=True) ──")
    commands = []

    if http_enabled:
        commands.append("no ip http server")
        log("  Queuing: no ip http server")

    if https_enabled:
        commands.append("no ip http secure-server")
        log("  Queuing: no ip http secure-server")

    if not commands:
        log("  HTTP server already disabled — no action needed.")
        return

    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ HTTP server disabled.")
    log("  CVE-2026-20125 attack surface eliminated.")
    log("  ⚠️  Verify CLI/SSH access is still functional.")
    log("  ⚠️  Confirm no management tools relied on HTTP access.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 305769 - CVE-2026-20125 - Cisco IOS HTTP Server DoS")
    log("")
    log("Mitigation: Disable HTTP server if not required for management")
    log("  'no ip http server'")
    log("  'no ip http secure-server'")
    log("")
    log("Note: Attacker requires VALID CREDENTIALS — lower risk than unauthenticated vulns.")
    log("  Mitigation priority: Restrict HTTP access via ACL if disabling is not possible:")
    log("  'ip http access-class <ACL_NUMBER> in'")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCwq14981")
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
    log("Fix Script - Plugin 305769 - Cisco IOS HTTP Server DoS")
    log("CVE-2026-20125 | CSCwq14981")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        http_enabled, https_enabled = check_http_state(connection)
        check_http_timeout(connection)
        check_http_users(connection)

        if DISABLE_HTTP_SERVER:
            disable_http_server(connection, http_enabled, https_enabled)
        else:
            log("── STEP 6: Skipped (DISABLE_HTTP_SERVER=False) ──")
            log("   Set DISABLE_HTTP_SERVER=True if HTTP server is confirmed unused.")
            log("   Alternatively apply ACL: 'ip http access-class <ACL> in'")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()