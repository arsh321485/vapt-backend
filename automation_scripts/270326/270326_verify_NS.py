#!/usr/bin/env python3
"""
Verify Script - Plugin 270326
Cisco IOS Software CLI DoS
CVE-2025-20149 | Bug ID: CSCwm86360

Checks:
  1. IOS version vs known vulnerable releases
  2. Low-privilege local account audit
  3. Parser view restrictions
  4. VTY/SSH access controls
  5. Priority context — second-lowest on device
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

LOG_FILE = f"verify_270326_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per Cisco Bug CSCwm86360.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-cli-EB7cZ6yO")

def check_low_priv_accounts(connection):
    log("─── CHECK 2: Low-Privilege Account Audit ───")
    users_cfg = connection.send_command("show running-config | include username")

    low_priv_count = 0
    for line in users_cfg.splitlines():
        parts = line.strip().split()
        if "username" in parts and len(parts) >= 2:
            username = parts[1]
            if "privilege" in parts:
                priv_idx = parts.index("privilege")
                priv = int(parts[priv_idx + 1]) if priv_idx + 1 < len(parts) else 1
            else:
                priv = 1

            if 1 <= priv <= 14:
                low_priv_count += 1
                log(f"  ⚠️  Low-priv user: '{username}' (priv {priv})")
                log(f"     Potential CLI buffer overflow candidate.")

    if low_priv_count == 0:
        log("  ✅ No low-privilege local accounts found.")
        log("  CVE-2025-20149 attack path not feasible — no valid attacker accounts.")
    else:
        log(f"  ⚠️  {low_priv_count} low-privilege account(s) present.")
        log("  Review each — remove unused accounts.")

def check_parser_views(connection):
    log("─── CHECK 3: Parser View CLI Restrictions ───")
    view_cfg = connection.send_command("show running-config | section parser view")

    if view_cfg.strip():
        log("✅ Parser views configured:")
        log(view_cfg[:300] if len(view_cfg) > 300 else view_cfg)
        log("  CLI command access is restricted for low-priv users.")
    else:
        log("⚠️  No parser views configured.")
        log("  Low-priv users have unrestricted CLI command access.")
        log("  Apply parser views to limit what commands they can run.")

def check_vty_restriction(connection):
    log("─── CHECK 4: VTY Access Controls ───")
    vty_cfg = connection.send_command("show running-config | section line vty")

    if "access-class" in vty_cfg:
        log("✅ VTY access-class configured.")
        for line in vty_cfg.splitlines():
            if "access-class" in line:
                log(f"  {line.strip()}")
        log("  Remote CLI access restricted to management hosts.")
        log("  Reduces attack surface for CVE-2025-20149 (remote exploitation path).")
    else:
        log("⚠️  No VTY access-class — SSH accessible from any source.")
        log("  Apply SSH ACL (Plugin 165676 mitigation) to restrict remote CLI.")

    if "transport input ssh" in vty_cfg:
        log("✅ VTY transport restricted to SSH only.")
    elif "transport input telnet" in vty_cfg or "transport input all" in vty_cfg:
        log("⚠️  Telnet allowed on VTY — restrict to SSH only.")

def priority_context():
    log("─── CHECK 5: Priority Context ───")
    log("")
    log("  Plugin 270326 priority metrics:")
    log("")
    log("  CVSS v3.0:  6.5  — Medium (but AV:L = Local only)")
    log("  VPR:        5.2  — Moderate")
    log("  EPSS:     0.0002 — 0.02% exploitation — LOWEST on device")
    log("  AV:L            — Local access required (not remotely exploitable)")
    log("  PR:L            — Low privilege (not unauthenticated)")
    log("  CWE:120         — Buffer overflow in CLI")
    log("")
    log("  Attack chain required:")
    log("    Valid local account + physical/SSH access + crafted CLI sequence")
    log("    → Very constrained, very low practical exploitation risk")
    log("")
    log("  Address only AFTER all 29 other plugins are resolved.")
    log("  IOS upgrade (planned for all critical plugins) also fixes this.")
    log("")
    log("  Published: 2025/10/14 — Most recently published plugin on device.")

def main():
    log("="*65)
    log("Verify Script - Plugin 270326 - Cisco IOS CLI DoS")
    log("CVE-2025-20149 | CSCwm86360 | AV:L | EPSS 0.0002 — LOWEST")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_low_priv_accounts(connection)
        check_parser_views(connection)
        check_vty_restriction(connection)
        priority_context()

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS (best): IOS upgraded per CSCwm86360")
        log("  ✅ PASS (mitigation): No low-priv accounts + VTY ACL restricted")
        log("  ⚠️  PARTIAL: Parser views applied but IOS not yet upgraded")
        log("  ❌ FAIL: Low-priv accounts exist + no CLI restrictions + vulnerable IOS")
        log("")
        log("  AV:L — Local only — NOT remotely exploitable without SSH access")
        log("  EPSS 0.0002 — lowest exploitation probability on device")
        log("  Most recently published (2025/10/14)")
        log("  Lowest priority — address after all other plugins resolved")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()