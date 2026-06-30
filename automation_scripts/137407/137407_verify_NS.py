#!/usr/bin/env python3
"""
Verify Script - Plugin 137407
Cisco IOS Tcl DoS
CVE-2020-3201 | Bug ID: CSCvq28110
"""

from netmiko import ConnectHandler
import datetime

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
    "15.4(2)T4", "15.3(3)M8",
]

LOG_FILE = f"verify_137407_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def check_ios_version(connection):
    log("─── CHECK 1: IOS Version ───")
    output = connection.send_command("show version")
    for line in output.splitlines():
        if "Version" in line and ("IOS" in line or "Software" in line):
            detected = line.strip()
            log(f"Detected: {detected}")
            if any(v in detected for v in VULNERABLE_VERSIONS):
                log("❌ Vulnerable — upgrade per CSCvq28110.")
            else:
                log("⚠️  Verify against full Cisco advisory.")
            break

def check_tcl_privilege(connection):
    log("─── CHECK 2: Tcl Access Privilege Level ───")
    tclsh_priv = connection.send_command(
        "show running-config | include privilege exec level.*tclsh"
    )
    if tclsh_priv.strip():
        log("Tcl privilege restriction:")
        log(tclsh_priv)
        if "15" in tclsh_priv:
            log("✅ tclsh restricted to priv-15 — only trusted admins can run Tcl.")
        else:
            log("ℹ️  Custom Tcl privilege level configured.")
    else:
        log("ℹ️  No explicit tclsh privilege restriction.")
        log("  Default: tclsh available to priv-15 users.")
        log("  Apply: 'privilege exec level 15 tclsh' (already priv-15 by default).")

def check_high_priv_accounts(connection):
    log("─── CHECK 3: High-Privilege Accounts (PR:H Attack Surface) ───")
    users = connection.send_command("show running-config | include username")
    priv15_count = 0
    for line in users.splitlines():
        parts = line.strip().split()
        if "username" in parts and "privilege" in parts:
            priv_idx = parts.index("privilege")
            priv = int(parts[priv_idx + 1]) if priv_idx + 1 < len(parts) else 1
            if priv >= 15:
                priv15_count += 1
                log(f"  Priv-15 user: {parts[1]} [password redacted]")

    if priv15_count == 0:
        log("  ✅ No local priv-15 accounts — Tcl DoS attack path very constrained.")
    else:
        log(f"  ℹ️  {priv15_count} priv-15 account(s) — can run tclsh.")
        log("  Verify all are legitimate trusted admins.")

def check_tcl_eem_usage(connection):
    log("─── CHECK 4: Tcl/EEM Active Usage ───")
    eem = connection.send_command("show running-config | include event manager policy")
    if eem.strip():
        log("EEM Tcl policies in use:")
        log(eem)
        log("ℹ️  Tcl is actively used — do not disable.")
    else:
        log("✅ No EEM Tcl policies — Tcl not actively used.")

def local_dos_plugin_summary():
    log("─── CHECK 5: Local DoS Plugin Summary ───")
    log("")
    log("  Local-access DoS/exploitation plugins on this device:")
    log("")
    log("  Plugin 270326 (CVE-2025-20149) — CLI Buffer Overflow")
    log("    PR:L (low priv) | AV:L | CVSS 6.5")
    log("")
    log("  Plugin 137407 (CVE-2020-3201)  — Tcl DoS")
    log("    PR:H (high priv) | AV:L | CVSS 6.0")
    log("")
    log("  Both: lowest practical risk (local access required)")
    log("  Both: resolved by same IOS upgrade")
    log("  Neither: remotely exploitable without SSH access first")

def main():
    log("="*65)
    log("Verify - Plugin 137407 - Cisco IOS Tcl DoS")
    log("CVE-2020-3201 | CSCvq28110 | AV:L | PR:H")
    log("="*65)

    try:
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_tcl_privilege(connection)
        check_high_priv_accounts(connection)
        check_tcl_eem_usage(connection)
        local_dos_plugin_summary()

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: IOS upgraded OR no high-priv local accounts")
        log("  ❌ FAIL: High-priv local accounts + Tcl access + vulnerable IOS")
        log("  AV:L + PR:H — only malicious insider or compromised admin")
        log("  Lowest practical risk alongside Plugin 270326")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")

if __name__ == "__main__":
    main()