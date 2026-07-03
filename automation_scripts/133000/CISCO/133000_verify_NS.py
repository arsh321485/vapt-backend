#!/usr/bin/env python3
"""
Verify Script - Plugin 133000
Cisco IOS Web UI CSRF
CVE-2019-16009 | Bug ID: CSCvq66030

Checks:
  1. IOS version vs known vulnerable releases
  2. HTTP server disabled state (primary/Cisco-recommended mitigation)
  3. Privilege-15 admin account audit (CSRF impact severity)
  4. HTTP access controls (secondary mitigation)
  5. Triple-plugin HTTP mitigation summary
"""

from netmiko import ConnectHandler
import datetime
import sys

# ─── CONFIGURATION ────────────────────────────────────────────────
DEVICE = {
    "device_type": "cisco_ios",
    "host": "192.168.1.1",
    "username": "admin",
    "password": "yourpassword",
    "secret": "yourenable",
    "port": 22,
    "timeout": 30,
}

VULNERABLE_VERSIONS = [
    "15.4(3)M5", "15.4(3)M4", "15.4(3)M3",
    "15.4(2)T4", "15.3(3)M8", "15.2(4)M10",
    "15.6(1)T", "15.5(3)M", "15.7(3)M",
    "16.9.1", "16.12.1", "17.3.1",
]

LOG_FILE = f"verify_133000_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per Cisco Bug CSCvq66030.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200108-ios-csrf")

def check_http_server_state(connection):
    log("─── CHECK 2: HTTP Server State (Cisco Workaround) ───")
    http_cfg = connection.send_command("show running-config | include ip http")

    http_off = ("no ip http server" in http_cfg or
                "ip http server" not in http_cfg)
    https_off = ("no ip http secure-server" in http_cfg or
                 "ip http secure-server" not in http_cfg)

    if http_off and https_off:
        log("✅ PASS: HTTP and HTTPS server DISABLED.")
        log("   CSRF attack surface eliminated (Cisco-recommended workaround applied).")
        log("   Also mitigates Plugin 305769 (HTTP DoS) and Plugin 154234 (TrustSec).")
        return True
    else:
        if not http_off:
            log("❌ HTTP server (port 80) ENABLED — CSRF exploitable.")
        if not https_off:
            log("❌ HTTPS server (port 443) ENABLED — CSRF exploitable.")
        log("   Apply Cisco workaround: 'no ip http server' + 'no ip http secure-server'")
        return False

def check_priv15_csrf_impact(connection):
    log("─── CHECK 3: Privilege-15 Admin Impact Assessment ───")
    log("  CSRF impact = victim's privilege level.")

    priv15 = connection.send_command(
        "show running-config | include privilege 15"
    )
    if priv15.strip():
        log("  ⚠️  Privilege-15 accounts found:")
        for line in priv15.splitlines():
            parts = line.strip().split()
            if "username" in parts and len(parts) >= 2:
                log(f"    {parts[1]} (priv-15)")
        log("  ⚠️  If any priv-15 admin uses web UI → CSRF = full device compromise.")
    else:
        log("  ✅ No local priv-15 accounts in config.")
        log("  Verify AAA/RADIUS/TACACS for privilege assignment.")

def check_http_acl(connection):
    log("─── CHECK 4: HTTP Access Controls (Secondary Hardening) ───")
    http_cfg = connection.send_command("show running-config | include ip http")

    if "ip http access-class" in http_cfg:
        log("  ✅ HTTP access-class configured:")
        for line in http_cfg.splitlines():
            if "access-class" in line:
                log(f"    {line.strip()}")
        log("  Restricts web UI access by source IP — reduces CSRF exposure.")
        log("  Note: ACL reduces risk but doesn't eliminate CSRF — disable HTTP instead.")
    else:
        log("  ⚠️  No HTTP access-class configured.")
        log("  Web UI accessible from any network source if HTTP is enabled.")

def triple_plugin_http_summary(connection):
    log("─── CHECK 5: Triple-Plugin HTTP Mitigation Status ───")
    log("")
    log("  THREE plugins share the same HTTP server mitigation:")
    log("")

    http_cfg = connection.send_command("show running-config | include ip http")
    http_disabled = ("no ip http server" in http_cfg or
                     "ip http server" not in http_cfg)

    plugins = [
        ("305769", "CVE-2026-20125", "HTTP Server DoS"),
        ("154234", "CVE-2021-34699", "TrustSec CLI Parser DoS"),
        ("133000", "CVE-2019-16009", "Web UI CSRF ← THIS"),
    ]

    for plugin, cve, name in plugins:
        status = "✅ MITIGATED" if http_disabled else "❌ EXPOSED"
        log(f"  {status} — Plugin {plugin} ({cve}) — {name}")

    log("")
    if http_disabled:
        log("  ✅ All three HTTP-related plugins mitigated by HTTP server disable.")
    else:
        log("  ❌ All three HTTP-related plugins exposed.")
        log("  One command fixes all three: 'no ip http server'")

def main():
    log("="*65)
    log("Verify Script - Plugin 133000 - Cisco IOS Web UI CSRF")
    log("CVE-2019-16009 | CSCvq66030 | CVSS 8.8 | VPR 5.9")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        http_ok = check_http_server_state(connection)
        check_priv15_csrf_impact(connection)
        check_http_acl(connection)
        triple_plugin_http_summary(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS (best): IOS upgraded per CSCvq66030")
        log("  ✅ PASS (Cisco workaround): HTTP server disabled")
        log("  ❌ FAIL: HTTP enabled + vulnerable IOS + admin users accessing web UI")
        log("")
        log("  CVSS 8.8 — C:H/I:H/A:H — full triad impact via social engineering")
        log("  Cisco advisory explicitly recommends disabling web UI as workaround")
        log("  'no ip http server' simultaneously mitigates 3 web UI-related plugins")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()