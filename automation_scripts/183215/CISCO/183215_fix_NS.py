#!/usr/bin/env python3
"""
Fix Script - Plugin 183215
Cisco IOS Software GET VPN Out of Bounds Write
CVE-2023-20109 | Bug IDs: CSCwe14195, CSCwe24118, CSCwf49531
CISA Known Exploited Vulnerability — Listed 2023/10/31

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check GET VPN (GDOI) configuration
  4. Determine role (key server vs group member)
  5. Document GET VPN topology
  6. Generate remediation report

KEY NOTES:
  - CISA KEV #7 on this device — listed 2023/10/31
  - VPR 7.4 — second highest VPR on entire device
  - Out-of-bounds WRITE → RCE/arbitrary code execution potential
  - Requires: admin control of group member OR compromised key server
  - GET VPN NOT default — specialized multicast WAN VPN feature
  - Common in: large enterprise WAN, government networks
  - Uncommon in: standard SMB/branch routers
  - No CLI workaround — IOS upgrade is the only fix
  - Full fix = IOS upgrade per CSCwe14195/CSCwe24118/CSCwf49531
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

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_183215_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_183215_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-getvpn-rce-g8qR68sx")
    log("  CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

def check_getvpn_config(connection):
    log("── STEP 3: Checking GET VPN / GDOI Configuration ──")

    # GDOI config
    gdoi_cfg = connection.send_command("show running-config | include gdoi|crypto map.*gdoi|GETVPN")
    log("  GDOI config lines:")
    log(gdoi_cfg if gdoi_cfg.strip() else "  No GDOI config found.")

    # Crypto map with GETVPN
    crypto_map = connection.send_command(
        "show running-config | section crypto map"
    )
    getvpn_map = [l for l in crypto_map.splitlines() if "gdoi" in l.lower()]
    if getvpn_map:
        log("  GET VPN crypto map entries:")
        for line in getvpn_map:
            log(f"    {line.strip()}")

    getvpn_configured = bool(gdoi_cfg.strip() or getvpn_map)

    if getvpn_configured:
        log("  ⚠️  GET VPN (GDOI) is configured on this device.")
        log("  CVE-2023-20109 RCE/DoS attack surface ACTIVE.")
        log("  CISA KEV — coordinate emergency IOS upgrade.")
    else:
        log("  ✅ No GET VPN/GDOI configuration found.")
        log("  CVE-2023-20109 not applicable — GET VPN not deployed.")
        log("  Mark as 'Not Applicable' after physical verification.")

    return getvpn_configured

def determine_getvpn_role(connection):
    log("── STEP 4: Determining GET VPN Role ──")

    # Key server check
    ks_cfg = connection.send_command(
        "show running-config | include crypto gdoi group.*server"
    )
    full_cfg = connection.send_command("show running-config | section crypto gdoi group")

    is_key_server = False
    is_group_member = False

    if full_cfg.strip():
        log("  GET VPN GDOI group configuration:")
        log(full_cfg[:500] if len(full_cfg) > 500 else full_cfg)

        if "server local" in full_cfg:
            is_key_server = True
            log("  ⚠️  This device is a GET VPN KEY SERVER.")
            log("  Key server compromise = all group members potentially exploitable.")
            log("  CRITICAL: Key server is the highest-value target in GET VPN topology.")
        elif "server address" in full_cfg or "server" in full_cfg:
            is_group_member = True
            log("  ℹ️  This device is a GET VPN GROUP MEMBER.")
            log("  Points to external key server for GDOI rekey operations.")

        # Key server address
        ks_addr = connection.send_command(
            "show running-config | include server address"
        )
        if ks_addr.strip():
            log(f"  Key server address: {ks_addr.strip()}")
            log("  Attacker targeting this key server could exploit this device.")

    # Runtime GDOI state
    gdoi_runtime = connection.send_command("show crypto gdoi")
    if gdoi_runtime.strip() and "%" not in gdoi_runtime:
        log("  GDOI runtime state:")
        log(gdoi_runtime[:400] if len(gdoi_runtime) > 400 else gdoi_runtime)

    return is_key_server, is_group_member

def document_getvpn_topology(connection):
    log("── STEP 5: GET VPN Topology Documentation ──")

    # GDOI groups
    gdoi_groups = connection.send_command("show crypto gdoi group")
    if gdoi_groups.strip() and "%" not in gdoi_groups:
        log("  GDOI groups:")
        log(gdoi_groups[:500] if len(gdoi_groups) > 500 else gdoi_groups)

    # GDOI ks
    gdoi_ks = connection.send_command("show crypto gdoi ks")
    if gdoi_ks.strip() and "%" not in gdoi_ks:
        log("  Key server info:")
        log(gdoi_ks[:400] if len(gdoi_ks) > 400 else gdoi_ks)

    # GDOI gm
    gdoi_gm = connection.send_command("show crypto gdoi gm")
    if gdoi_gm.strip() and "%" not in gdoi_gm:
        log("  Group member info:")
        log(gdoi_gm[:400] if len(gdoi_gm) > 400 else gdoi_gm)

    # Active GDOI connections
    gdoi_conn = connection.send_command("show crypto gdoi ks members")
    if gdoi_conn.strip() and "%" not in gdoi_conn:
        log("  GDOI group members (key server view):")
        log(gdoi_conn[:400] if len(gdoi_conn) > 400 else gdoi_conn)

def remediation_notice(is_key_server, is_group_member):
    log("── EMERGENCY REMEDIATION NOTICE ──")
    log("Plugin 183215 - CVE-2023-20109 - Cisco IOS GET VPN OOB Write")
    log("⚠️  CISA KEV #7 on this device — Listed 2023/10/31")
    log("⚠️  OUT-OF-BOUNDS WRITE → RCE potential")
    log("")

    if is_key_server:
        log("⚠️⚠️  THIS DEVICE IS A GET VPN KEY SERVER ⚠️⚠️")
        log("  Key server compromise = all group members at risk")
        log("  Priority: HIGHEST — upgrade key server FIRST in topology")
    elif is_group_member:
        log("  This device is a GET VPN GROUP MEMBER")
        log("  Attack requires compromising key server or attacker-controlled KS")
        log("  Coordinate upgrade with key server team")
    else:
        log("  GET VPN role undetermined — investigate topology")

    log("")
    log("This is CISA KEV #7 on this device:")
    log("  1. Plugin 93736  — CVE-2016-6415 (BENIGNCERTAIN)")
    log("  2. Plugin 131166 — CVE-2018-0154 (ISM-VPN DoS)")
    log("  3. Plugin 103693 — CVE-2017-12237 (IKE DoS)")
    log("  4. Plugin 108880 — CVE-2018-0167/0175 (LLDP Buffer Overflow)")
    log("  5. Plugin 103669 — CVE-2017-12231 (NAT DoS)")
    log("  6. Plugin 266454 — CVE-2025-20352 (SNMP RCE)")
    log("  7. Plugin 183215 — CVE-2023-20109 (GET VPN RCE) ← THIS")
    log("")
    log("NO CLI WORKAROUND EXISTS")
    log("Permanent Fix: IOS upgrade per CSCwe14195/CSCwe24118/CSCwf49531")
    log("Installed: 15.4(3)M5")
    log("")
    log("Upgrade steps (manual):")
    log("  1. Download fixed IOS image from Cisco.com")
    log("  2. Transfer: 'copy tftp: flash:' or 'copy scp: flash:'")
    log("  3. Verify: 'verify /md5 flash:<image>'")
    log("  4. Set boot: 'boot system flash:<image>'")
    log("  5. Save: 'write memory'")
    log("  6. Reload: 'reload'")
    log("  7. If KEY SERVER: upgrade all group members too")
    log("  8. Confirm: 'show version' + 'show crypto gdoi'")
    log("  9. Re-scan Nessus with valid credentials")

def main():
    log("="*65)
    log("Fix Script - Plugin 183215 - Cisco IOS GET VPN OOB Write")
    log("CVE-2023-20109 | CISA KEV #7 | VPR 7.4 | RCE Potential")
    log("GET VPN not default — verify if configured first")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        getvpn_configured = check_getvpn_config(connection)

        if getvpn_configured:
            is_key_server, is_group_member = determine_getvpn_role(connection)
            document_getvpn_topology(connection)
        else:
            is_key_server = is_group_member = False
            log("GET VPN not configured — mark as 'Not Applicable'.")

        remediation_notice(is_key_server, is_group_member)

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()