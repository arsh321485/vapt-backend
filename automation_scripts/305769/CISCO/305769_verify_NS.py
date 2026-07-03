#!/usr/bin/env python3
"""
Verify Script - Plugin 305769
Cisco IOS Software HTTP Server DoS
CVE-2026-20125 | Bug ID: CSCwq14981

Checks:
  1. IOS version vs known vulnerable releases
  2. HTTP server enabled state (http + secure-server)
  3. HTTP access-class restriction
  4. Active HTTP connections
  5. Post-change CLI access health
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

# Plugin published 2026/04/09 — add versions as Cisco updates advisory
VULNERABLE_VERSIONS = [
    "15.4(3)M5", "15.4(3)M4", "15.4(3)M3",
    "15.6(3)M", "15.7(3)M", "15.8(3)M",
    "16.12.1", "17.3.1", "17.6.1",
]

LOG_FILE = f"verify_305769_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def check_ios_version(connection):
    log("─── CHECK 1: IOS Version ───")
    output = connection.send_command("show version")
    detected = None
    for line in output.splitlines():
        if "Version" in line and ("IOS" in line or "Software" in line):
            detected = line.strip()
            log(f"Detected: {detected}")
            break

    if detected:
        is_vuln = any(v in detected for v in VULNERABLE_VERSIONS)
        if is_vuln:
            log("❌ FAIL: Running a KNOWN VULNERABLE IOS version.")
            log("   Upgrade required per Cisco Bug CSCwq14981.")
        else:
            log("⚠️  Verify against full Cisco advisory (published 2026/04/09 — check for updates).")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-http-dos-sbv8XRpL")

def check_http_server(connection):
    log("─── CHECK 2: HTTP Server State ───")
    http_cfg = connection.send_command("show running-config | include ip http")

    http_on = "ip http server" in http_cfg and "no ip http server" not in http_cfg
    https_on = "ip http secure-server" in http_cfg and "no ip http secure-server" not in http_cfg

    if not http_on and not https_on:
        log("✅ PASS: Both HTTP and HTTPS servers are DISABLED.")
        log("   CVE-2026-20125 attack surface eliminated.")
    else:
        if http_on:
            log("⚠️  'ip http server' (port 80) is ENABLED.")
        if https_on:
            log("⚠️  'ip http secure-server' (port 443) is ENABLED.")
        log("   Device exposed to CVE-2026-20125 until IOS upgrade or HTTP disabled.")

    # Access-class check
    if "ip http access-class" in http_cfg:
        log("  ℹ️  HTTP access-class configured — exposure is ACL-restricted.")
        log("  Extract ACL and confirm it limits access to trusted management hosts only.")
    else:
        log("  ⚠️  No HTTP access-class — HTTP accessible from any source.")

def check_http_connections(connection):
    log("─── CHECK 3: Active HTTP Connections ───")
    output = connection.send_command("show ip http server connection")
    if output.strip():
        log("Active HTTP connections found:")
        log(output)
        log("⚠️  HTTP server is actively in use — do not disable without redirect plan.")
    else:
        log("✅ No active HTTP connections.")

def check_http_stats(connection):
    log("─── CHECK 4: HTTP Server Statistics ───")
    output = connection.send_command("show ip http server statistics")
    if output.strip():
        log(output)
    else:
        log("No HTTP server statistics available (may not be enabled or supported).")

def check_cli_access(connection):
    log("─── CHECK 5: CLI / SSH Access Health ───")
    # Verify we can still run a command (implicit check by being connected)
    uptime = connection.send_command("show version | include uptime")
    log(f"Device uptime: {uptime.strip()}")
    log("✅ SSH/CLI access confirmed functional post-change.")

def main():
    log("="*65)
    log("Verify Script - Plugin 305769 - Cisco IOS HTTP Server DoS")
    log("CVE-2026-20125 | CSCwq14981")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_http_server(connection)
        check_http_connections(connection)
        check_http_stats(connection)
        check_cli_access(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: Both HTTP/HTTPS disabled, OR IOS upgraded to fixed release")
        log("  ⚠️  PARTIAL: HTTP disabled but IOS not yet upgraded")
        log("  ❌ FAIL: HTTP still enabled on vulnerable IOS version")
        log("  NOTE: Requires authenticated attacker — lower urgency than unauthenticated vulns")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()