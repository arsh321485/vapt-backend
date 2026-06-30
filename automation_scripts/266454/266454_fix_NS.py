#!/usr/bin/env python3
"""
Fix Script - Plugin 266454
Cisco IOS Software SNMP DoS / RCE (Stack Overflow)
CVE-2025-20352 | Bug ID: CSCwq31287
CISA Known Exploited Vulnerability — Listed 2025/10/20

TWO ATTACK PATHS:
  PATH 1 (DoS): SNMPv2c RO community OR SNMPv3 user → device reload
  PATH 2 (RCE): SNMPv1/v2c RO + priv-15 credentials → root code execution

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Audit SNMP config (communities, users, ACLs)
  4. Audit privilege-15 accounts (RCE attack surface)
  5. Apply SNMP ACL restriction / disable SNMP
  6. Generate emergency remediation report

CRITICAL NOTES:
  - CISA KEV #6 on this device — most recently listed (2025/10/20)
  - ONLY plugin on this device with confirmed RCE potential
  - Stack overflow in SNMP subsystem — memory corruption, not just DoS
  - Affects ALL SNMP versions (v1, v2c, v3)
  - Exploitable via IPv4 AND IPv6
  - VPR 6.0 — highest SNMP-related VPR on device
  - Full fix = IOS upgrade per CSCwq31287 — EMERGENCY PRIORITY
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

# Management hosts allowed SNMP access
SNMP_ALLOWED_HOSTS = [
    "10.0.0.10",      # <-- Replace with NMS/monitoring server IPs
    "10.0.0.11",
]

SNMP_ACL_NUMBER = "98"  # Use different ACL from Plugin 215126's ACL 99

# Set True to apply ACL restriction to SNMP communities
APPLY_SNMP_ACL = False

# Set True to disable SNMP entirely — STRONGLY RECOMMENDED if not needed
DISABLE_SNMP = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_266454_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_266454_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  ⚠️  EMERGENCY: Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-x4LPhte")
    log("  CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

def audit_snmp_config(connection):
    log("── STEP 3: SNMP Configuration Audit (RCE Context) ──")

    snmp_cfg = connection.send_command("show running-config | include snmp")
    log("  SNMP configuration:")
    log(snmp_cfg if snmp_cfg.strip() else "  No SNMP config — may not be exposed.")

    snmp_enabled = bool(snmp_cfg.strip())
    communities = []

    if snmp_enabled:
        log("")
        log("  ⚠️  SNMP IS CONFIGURED — CVE-2025-20352 attack surface ACTIVE.")
        log("  Stack overflow vulnerability — potential RCE on root level.")

        # Parse communities
        for line in snmp_cfg.splitlines():
            if "snmp-server community" in line:
                parts = line.strip().split()
                if len(parts) >= 3:
                    community = parts[2]
                    communities.append(community)
                    permission = parts[3] if len(parts) > 3 else "?"
                    has_acl = len(parts) >= 5
                    acl_status = f"ACL: {parts[4]}" if has_acl else "⚠️  NO ACL"
                    log(f"  Community: '{community}' | {permission} | {acl_status}")

                    if "RW" in permission or "read-write" in permission.lower():
                        log(f"    ❌ RW community '{community}' — remove if not required.")

        if "public" in snmp_cfg.lower():
            log("  ❌ CRITICAL: Default 'public' community string found — REMOVE IMMEDIATELY.")
        if "private" in snmp_cfg.lower():
            log("  ❌ CRITICAL: Default 'private' community string found — REMOVE IMMEDIATELY.")

    # SNMPv3 users
    log("  >> SNMPv3 Users:")
    snmpv3 = connection.send_command("show snmp user")
    if snmpv3.strip() and "no such" not in snmpv3.lower():
        log(snmpv3[:400] if len(snmpv3) > 400 else snmpv3)
    else:
        log("  No SNMPv3 users configured.")

    return snmp_enabled, communities

def audit_privilege15_accounts(connection):
    log("── STEP 4: Privilege-15 Account Audit (RCE Path) ──")
    log("  RCE path requires: SNMP RO community + priv-15 credentials.")
    log("  Auditing privilege-15 accounts to assess RCE feasibility...")

    # Local privilege-15 users
    priv15_cfg = connection.send_command(
        "show running-config | include username.*privilege 15|username.*priv 15"
    )
    if priv15_cfg.strip():
        log("  ⚠️  Privilege-15 local accounts:")
        for line in priv15_cfg.splitlines():
            # Show username but mask password
            parts = line.strip().split()
            if "username" in parts and len(parts) >= 2:
                log(f"    Username: {parts[1]} [privilege 15 — password redacted]")
        log("  ⚠️  Priv-15 accounts exist — RCE attack path is available.")
        log("  Audit whether these accounts use strong passwords.")
    else:
        log("  No local privilege-15 accounts found.")
        log("  ✅ RCE path requires priv-15 — local accounts do not provide it.")
        log("  ⚠️  Check AAA/RADIUS/TACACS+ for privilege-15 assignment.")

    # AAA privilege assignment
    aaa_cfg = connection.send_command("show running-config | section aaa")
    if aaa_cfg.strip():
        log("  AAA configuration (privilege source):")
        log(aaa_cfg[:400] if len(aaa_cfg) > 400 else aaa_cfg)

    # Enable password (also priv-15 path)
    enable_cfg = connection.send_command(
        "show running-config | include enable password|enable secret"
    )
    if enable_cfg.strip():
        log("  Enable password/secret configured:")
        # Mask the actual value
        for line in enable_cfg.splitlines():
            log(f"    {line.split()[0]} {line.split()[1]} [redacted]"
                if len(line.split()) >= 3 else f"    {line.strip()}")

def create_snmp_acl(connection):
    log("── STEP 5a: Creating Emergency SNMP Restriction ACL ──")
    log(f"  Creating ACL {SNMP_ACL_NUMBER} — EMERGENCY restriction for CVE-2025-20352...")

    commands = [f"no access-list {SNMP_ACL_NUMBER}"]
    for host in SNMP_ALLOWED_HOSTS:
        commands.append(f"access-list {SNMP_ACL_NUMBER} permit {host}")
        log(f"  Permitting: {host}")
    commands.append(f"access-list {SNMP_ACL_NUMBER} deny any log")

    output = connection.send_config_set(commands)
    log(output)
    log(f"  ✅ Emergency ACL {SNMP_ACL_NUMBER} created.")

def apply_snmp_acl(connection, communities):
    log("── STEP 5b: Applying ACL to SNMP Communities (Emergency Mitigation) ──")

    full_snmp = connection.send_command(
        "show running-config | include snmp-server community"
    )
    commands = []
    for line in full_snmp.splitlines():
        parts = line.strip().split()
        if len(parts) >= 4 and "community" in parts:
            community = parts[2]
            permission = parts[3]
            commands.append(
                f"snmp-server community {community} {permission} {SNMP_ACL_NUMBER}"
            )
            log(f"  Restricting '{community}' ({permission}) to ACL {SNMP_ACL_NUMBER}")

    if commands:
        output = connection.send_config_set(commands)
        log(output)
        save = connection.send_command("write memory")
        log(f"  Config saved: {save}")
        log("  ✅ Emergency SNMP ACL applied.")
        log("  Attack requires: network position to reach SNMP + valid credentials.")
        log("  RCE path further requires priv-15 credentials.")

def disable_snmp(connection):
    log("── STEP 5c: Disabling SNMP Entirely (STRONGLY RECOMMENDED) ──")

    # Clear community strings
    snmp_cfg = connection.send_command("show running-config | include snmp-server community")
    commands = []
    for line in snmp_cfg.splitlines():
        parts = line.strip().split()
        if "community" in parts and len(parts) >= 3:
            commands.append(f"no snmp-server community {parts[2]}")
            log(f"  Removing community: {parts[2]}")

    commands.extend([
        "no snmp-server",
        "no snmp-server enable traps",
        "no snmp-server host",
    ])

    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ SNMP DISABLED.")
    log("  CVE-2025-20352 DoS AND RCE attack surface ELIMINATED.")
    log("  ⚠️  NMS/monitoring tools can no longer poll device via SNMP.")

def emergency_remediation_notice():
    log("── EMERGENCY REMEDIATION NOTICE ──")
    log("Plugin 266454 - CVE-2025-20352 - Cisco IOS SNMP Stack Overflow")
    log("⚠️⚠️  CISA KEV — LISTED 2025/10/20 — ACTIVELY EXPLOITED ⚠️⚠️")
    log("⚠️⚠️  RCE POTENTIAL — ONLY RCE-CAPABLE PLUGIN ON THIS DEVICE ⚠️⚠️")
    log("")
    log("This is CISA KEV #6 on this device:")
    log("  1. Plugin 93736  — CVE-2016-6415 (BENIGNCERTAIN)")
    log("  2. Plugin 131166 — CVE-2018-0154 (ISM-VPN DoS)")
    log("  3. Plugin 103693 — CVE-2017-12237 (IKE DoS)")
    log("  4. Plugin 108880 — CVE-2018-0167/0175 (LLDP Buffer Overflow)")
    log("  5. Plugin 103669 — CVE-2017-12231 (NAT DoS)")
    log("  6. Plugin 266454 — CVE-2025-20352 (SNMP Stack Overflow RCE) ← THIS")
    log("")
    log("ATTACK PATHS:")
    log("  PATH 1 (DoS): SNMP RO credential → device reload")
    log("  PATH 2 (RCE): SNMP RO credential + priv-15 → root code execution")
    log("  PATH 2 = Full device compromise (config exfil, credential theft, etc.)")
    log("")
    log("IMMEDIATE ACTIONS:")
    log("  1. Disable SNMP NOW: 'no snmp-server'")
    log("  OR restrict via ACL to known management IPs only")
    log("  2. Rotate all SNMP community strings")
    log("  3. Audit privilege-15 accounts")
    log("  4. Plan emergency IOS upgrade")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCwq31287")
    log("  This is EMERGENCY PRIORITY — also resolves all 21 other plugins.")
    log("Installed: 15.4(3)M5")
    log("")
    log("Upgrade steps (manual):")
    log("  1. Download fixed IOS image from Cisco.com")
    log("  2. Transfer: 'copy tftp: flash:' or 'copy scp: flash:'")
    log("  3. Verify: 'verify /md5 flash:<image>'")
    log("  4. Set boot: 'boot system flash:<image>'")
    log("  5. Save: 'write memory'")
    log("  6. Reload: 'reload' — schedule during off-hours")
    log("  7. Confirm: 'show version'")
    log("  8. Re-scan Nessus with valid credentials")

def main():
    log("="*65)
    log("Fix Script - Plugin 266454 - Cisco IOS SNMP Stack Overflow RCE")
    log("CVE-2025-20352 | CSCwq31287")
    log("CISA KEV #6 | RCE POTENTIAL | EMERGENCY PRIORITY")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        snmp_enabled, communities = audit_snmp_config(connection)
        audit_privilege15_accounts(connection)

        if DISABLE_SNMP:
            disable_snmp(connection)
        elif APPLY_SNMP_ACL:
            if not snmp_enabled:
                log("── STEP 5: SNMP not configured — no action needed. ──")
            else:
                create_snmp_acl(connection)
                apply_snmp_acl(connection, communities)
        else:
            log("── STEP 5: Skipped ──")
            log("   ⚠️⚠️  CISA KEV + RCE — DO NOT LEAVE THIS UNMITIGATED.")
            log("   Set DISABLE_SNMP=True OR APPLY_SNMP_ACL=True IMMEDIATELY.")
            log("   Configure SNMP_ALLOWED_HOSTS before applying ACL.")

        emergency_remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()