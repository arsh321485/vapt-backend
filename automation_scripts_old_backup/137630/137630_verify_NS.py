#!/usr/bin/env python3
"""
Verify Script - Plugin 137630
Cisco IOS Tcl Arbitrary Code Execution
CVE-2020-3204 | Bug ID: CSCvq05584
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

LOG_FILE = f"verify_137630_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
                log("❌ Vulnerable — upgrade per CSCvq05584.")
                log("   Tcl ACE allows root OS code execution via priv-15.")
            else:
                log("⚠️  Verify against full Cisco advisory.")
            break

def check_priv15_accounts(connection):
    log("─── CHECK 2: Privileged EXEC (Priv-15) Accounts ───")
    users = connection.send_command("show running-config | include username")
    priv15_count = 0

    for line in users.splitlines():
        parts = line.strip().split()
        if "username" in parts and len(parts) >= 2:
            username = parts[1]
            if "privilege" in parts:
                priv_idx = parts.index("privilege")
                priv = int(parts[priv_idx + 1]) if priv_idx + 1 < len(parts) else 1
                if priv >= 15:
                    priv15_count += 1
                    log(f"  Priv-15: '{username}' — can run tclsh ACE exploit")

    if priv15_count == 0:
        log("✅ No local priv-15 accounts — Tcl ACE local attack path constrained.")
    else:
        log(f"⚠️  {priv15_count} priv-15 account(s) — verify all are trusted admins.")
        log("  Any compromised priv-15 account = potential Tcl ACE exploit.")

def check_tcl_restrictions(connection):
    log("─── CHECK 3: Tcl Access Restrictions ───")
    tclsh_priv = connection.send_command(
        "show running-config | include privilege exec level.*tclsh"
    )
    if tclsh_priv.strip():
        log("✅ Explicit tclsh privilege restriction:")
        log(tclsh_priv)
    else:
        log("ℹ️  No explicit tclsh restriction — default priv-15 access applies.")
        log("  Apply AAA command authorization to audit/restrict tclsh usage.")

def check_aaa_accounting(connection):
    log("─── CHECK 4: AAA Command Accounting ───")
    aaa = connection.send_command(
        "show running-config | include aaa accounting commands 15"
    )
    if aaa.strip():
        log("✅ AAA command accounting for level 15 configured:")
        log(aaa)
        log("  Tcl command execution is being audited.")
    else:
        log("ℹ️  No AAA command accounting for level 15.")
        log("  Apply: 'aaa accounting commands 15 default start-stop group tacacs+'")
        log("  Creates audit trail of tclsh usage by priv-15 accounts.")

def rce_plugin_summary():
    log("─── CHECK 5: All RCE Capabilities on Device ───")
    log("")
    log("  THREE Remote/Local Code Execution vulnerabilities on this device:")
    log("")
    log("  Plugin 266454 (CVE-2025-20352) — SNMP Stack Overflow RCE")
    log("    AV:N | Auth Required | CISA KEV | EPSS 0.0018")
    log("    Attack: Remote, authenticated SNMP + priv-15 = root exec")
    log("")
    log("  Plugin 183215 (CVE-2023-20109) — GET VPN OOB Write RCE")
    log("    AV:N | AC:H | CISA KEV | EPSS 0.0076")
    log("    Attack: Compromised key server = group member RCE")
    log("")
    log("  Plugin 137630 (CVE-2020-3204)  — Tcl Interpreter ACE")
    log("    AV:L | PR:H | VPR 5.9 | EPSS 0.0006")
    log("    Attack: Local priv-15 + crafted Tcl = root OS exec")
    log("")
    log("  All three resolved by a single IOS upgrade.")

def main():
    log("="*65)
    log("Verify - Plugin 137630 - Cisco IOS Tcl ACE")
    log("CVE-2020-3204 | CSCvq05584 | C:H/I:H/A:H | RCE ROOT OS")
    log("="*65)

    try:
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_priv15_accounts(connection)
        check_tcl_restrictions(connection)
        check_aaa_accounting(connection)
        rce_plugin_summary()

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: IOS upgraded per CSCvq05584")
        log("  ❌ FAIL: Priv-15 local accounts + Tcl access + vulnerable IOS")
        log("  AV:L + PR:H — insider/compromised admin threat only")
        log("  CVSS C:H/I:H/A:H — full triad at High if exploited")
        log("  VPR 5.9 — highest of all local-access plugins")
        log("  THIS IS THE 3RD RCE CAPABILITY ON THIS DEVICE")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")

if __name__ == "__main__":
    main()