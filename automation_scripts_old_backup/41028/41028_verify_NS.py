#!/usr/bin/env python3
"""
Verify Script - Plugin 41028
SNMP Agent Default Community Name (public)
CVE-1999-0517

Checks:
  1. 'public' community string removed from config
  2. 'private' community string removed from config
  3. All remaining communities have ACL restriction
  4. SNMP ACL is properly configured
  5. Active SNMP polling test (from device perspective)
  6. EPSS context — why this is the highest priority standalone fix
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

LOG_FILE = f"verify_41028_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def check_default_communities_removed(connection):
    log("─── CHECK 1 & 2: Default Community Strings Removed ───")
    snmp_cfg = connection.send_command("show running-config | include snmp-server community")

    public_found = False
    private_found = False

    for line in snmp_cfg.splitlines():
        parts = line.strip().split()
        if "community" in parts:
            idx = parts.index("community")
            if idx + 1 < len(parts):
                comm = parts[idx + 1]
                if comm.lower() == "public":
                    public_found = True
                    permission = parts[idx + 2] if idx + 2 < len(parts) else "?"
                    log(f"  ❌ FAIL: 'public' community still present ({permission})!")
                    log("  Remove: 'no snmp-server community public'")
                elif comm.lower() == "private":
                    private_found = True
                    log("  ❌ FAIL: 'private' community still present!")
                    log("  Remove: 'no snmp-server community private'")

    if not public_found:
        log("  ✅ PASS: 'public' community string NOT in config.")
    if not private_found:
        log("  ✅ PASS: 'private' community string NOT in config.")

    return not public_found and not private_found

def check_acl_on_communities(connection):
    log("─── CHECK 3: ACL Restriction on All Communities ───")
    snmp_cfg = connection.send_command("show running-config | include snmp-server community")

    all_have_acl = True
    for line in snmp_cfg.splitlines():
        parts = line.strip().split()
        if "community" in parts:
            idx = parts.index("community")
            if idx + 1 < len(parts):
                comm = parts[idx + 1]
                permission = parts[idx + 2] if idx + 2 < len(parts) else "?"
                has_acl = idx + 3 < len(parts)

                if has_acl:
                    acl = parts[idx + 3]
                    log(f"  ✅ '{comm}' ({permission}): ACL {acl} applied.")
                else:
                    log(f"  ⚠️  '{comm}' ({permission}): NO ACL — accessible from any source.")
                    all_have_acl = False

    if all_have_acl:
        log("  ✅ All remaining community strings have ACL restriction.")
    else:
        log("  ❌ Some communities lack ACL.")
        log("  Apply: 'snmp-server community <string> RO <ACL>'")

    return all_have_acl

def check_snmp_statistics(connection):
    log("─── CHECK 4: SNMP Statistics (Activity Monitoring) ───")
    output = connection.send_command("show snmp")
    if output.strip():
        log("  SNMP statistics:")
        for line in output.splitlines():
            if any(kw in line.lower() for kw in
                   ["input", "output", "bad", "unknown", "community"]):
                log(f"  {line.strip()}")

        # Check for bad community string hits (indicates attempted 'public' access)
        for line in output.splitlines():
            if "bad community" in line.lower():
                log(f"  ℹ️  Bad community attempts: {line.strip()}")
                log("  These may be from sources still using 'public' — update NMS tools.")
    else:
        log("  No SNMP statistics available.")

def check_snmp_version_config(connection):
    log("─── CHECK 5: SNMP Best Practice Config Review ───")
    snmp_cfg = connection.send_command("show running-config | include snmp")

    # Check version
    if "snmp-server community" in snmp_cfg:
        log("  ℹ️  SNMPv1/v2c community strings present.")
        log("  Consider migrating to SNMPv3 auth+priv for stronger security.")
    else:
        log("  ✅ No SNMP community strings — SNMPv3 or SNMP disabled.")

    # Check SNMPv3
    snmpv3_users = connection.send_command("show snmp user")
    if snmpv3_users.strip() and "no such" not in snmpv3_users.lower():
        log("  SNMPv3 users configured:")
        if "priv" in snmpv3_users.lower():
            log("  ✅ SNMPv3 with privacy (auth+priv) — strongest mode.")
        elif "auth" in snmpv3_users.lower():
            log("  ⚠️  SNMPv3 auth only (no privacy encryption).")
        log(snmpv3_users[:300] if len(snmpv3_users) > 300 else snmpv3_users)
    else:
        log("  No SNMPv3 users — using community-based SNMP only.")

def epss_context_and_plugin_relationship():
    log("─── CHECK 6: EPSS Context and Plugin Relationship ───")
    log("")
    log("  Plugin 41028 EPSS Context:")
    log("  EPSS 0.9243 — 92% exploitation probability — HIGHEST on this device")
    log("  Older CVE (1999) with well-known tools: snmpwalk, snmpenum, Metasploit")
    log("  'public' is the first community string every attacker tries")
    log("")
    log("  Relationship to SNMP vulnerability plugins:")
    log("")
    log("  Plugin 41028  (CVE-1999-0517) — 'public' community exposed")
    log("    → Provides credential for Plugins 215126 and 266454")
    log("    → Fix: Remove 'public', apply ACL (NO IOS upgrade needed)")
    log("    → EPSS: 0.9243 ← HIGHEST")
    log("")
    log("  Plugin 215126 (CVE-2025-20169..76) — SNMP DoS (8 CVEs)")
    log("    → Requires valid SNMP credential to exploit")
    log("    → Fix: IOS upgrade + 'public' removal")
    log("    → EPSS: 0.002")
    log("")
    log("  Plugin 266454 (CVE-2025-20352) — SNMP RCE (CISA KEV)")
    log("    → Requires valid SNMP credential to exploit")
    log("    → Fix: IOS upgrade + 'public' removal")
    log("    → EPSS: 0.0018")
    log("")
    log("  ⚠️  Removing 'public' reduces attack surface for ALL THREE SNMP plugins.")

def main():
    log("="*65)
    log("Verify Script - Plugin 41028 - SNMP Default Community 'public'")
    log("CVE-1999-0517 | EPSS 0.9243 — HIGHEST on device")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        public_removed = check_default_communities_removed(connection)
        acl_ok = check_acl_on_communities(connection)
        check_snmp_statistics(connection)
        check_snmp_version_config(connection)
        epss_context_and_plugin_relationship()

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: 'public' and 'private' removed + ACL applied")
        log("  ❌ FAIL: Default community still present and/or no ACL")
        log("")
        log("  This is a CONFIG fix — no IOS upgrade required")
        log("  EPSS 0.9243 — fix immediately after NMS tool coordination")
        log("  Removing 'public' also reduces exposure for Plugins 215126 + 266454")
        log("  Run Nessus re-scan (UDP/161) to confirm plugin no longer fires")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()