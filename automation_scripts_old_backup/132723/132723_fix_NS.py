#!/usr/bin/env python3
"""
Fix Script - Plugin 132723
Cisco IOS Software NAT64 DoS Vulnerability
CVE-2019-1751 | Bug ID: CSCvk61580

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check NAT64 configuration state
  4. Check active NAT64 sessions
  5. Optionally disable NAT64
  6. Generate remediation report

KEY NOTES:
  - NAT64 is NOT enabled by default — verify before escalating
  - Distinct from Plugin 103669 (standard NAT): NAT64 = IPv6-to-IPv4 translation
  - Two attack outcomes: interface QUEUE WEDGE or device RELOAD
  - Queue wedge = same recovery risk as Plugin 130092 (IP SLA)
  - Common in: ISP/carrier networks, IPv6 transition environments
  - Uncommon in: Standard enterprise branch routers
  - Full fix = IOS upgrade per CSCvk61580
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

# Set True ONLY if NAT64 is confirmed NOT in use
# Removes NAT64 configuration to eliminate attack surface
DISABLE_NAT64 = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_132723_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_132723_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-nat64")

def check_nat64_config(connection):
    log("── STEP 3: Checking NAT64 Configuration ──")

    # NAT64 in running config
    nat64_cfg = connection.send_command("show running-config | include nat64")
    log("  NAT64 config lines:")
    log(nat64_cfg if nat64_cfg.strip()
        else "  No 'nat64' config lines found.")

    nat64_configured = bool(nat64_cfg.strip())

    if nat64_configured:
        log("  ⚠️  NAT64 is configured on this device.")
        log("  CVE-2019-1751 attack surface ACTIVE.")
        log("  Attack can cause: interface queue wedge OR device reload.")

        # Detect NAT64 prefix
        prefix = connection.send_command(
            "show running-config | include nat64 prefix"
        )
        if prefix.strip():
            log(f"  NAT64 prefix: {prefix.strip()}")

        # Detect NAT64 v4v6/v6v4 config
        v4v6 = connection.send_command(
            "show running-config | include nat64 v4v6|nat64 v6v4"
        )
        if v4v6.strip():
            log("  NAT64 translation rules:")
            log(v4v6)
    else:
        log("  ✅ NAT64 not configured.")
        log("  CVE-2019-1751 likely not applicable on this device.")
        log("  Mark as 'Not Applicable' if physically confirmed.")

    # Check NAT64 on interfaces
    nat64_iface = connection.send_command(
        "show running-config | include nat64 enable"
    )
    if nat64_iface.strip():
        log("  NAT64 enabled on interfaces:")
        log(nat64_iface)

    return nat64_configured

def check_nat64_sessions(connection):
    log("── STEP 4: Active NAT64 Sessions ──")

    # NAT64 statistics
    nat64_stats = connection.send_command("show ip nat64 statistics")
    if nat64_stats.strip() and "%" not in nat64_stats:
        log("  NAT64 statistics:")
        log(nat64_stats[:500] if len(nat64_stats) > 500 else nat64_stats)
    else:
        log("  No NAT64 statistics available.")

    # NAT64 translation table
    nat64_trans = connection.send_command("show ip nat64 translations")
    if nat64_trans.strip() and "%" not in nat64_trans:
        lines = nat64_trans.splitlines()
        entry_count = len([l for l in lines
                          if l.strip() and "Proto" not in l and "---" not in l])
        log(f"  Active NAT64 translations: {entry_count}")
        if entry_count > 0:
            log("  ⚠️  Active NAT64 sessions — users/services depend on NAT64.")
            log("  Do NOT disable without migration plan.")
            log(nat64_trans[:400] if len(nat64_trans) > 400 else nat64_trans)
        else:
            log("  ✅ No active NAT64 translations.")
    else:
        log("  ✅ No NAT64 translation table output — NAT64 may not be active.")

def check_ipv6_nat64_interfaces(connection):
    log("── STEP 5: NAT64 Interface Configuration ──")

    # Interfaces with nat64 enable
    full_cfg = connection.send_command("show running-config")
    nat64_ifaces = []
    current_iface = None

    for line in full_cfg.splitlines():
        if line.startswith("interface "):
            current_iface = line.strip().split("interface ")[1]
        elif "nat64 enable" in line and current_iface:
            nat64_ifaces.append(current_iface)

    if nat64_ifaces:
        log(f"  NAT64 enabled on interfaces: {nat64_ifaces}")
        log("  ⚠️  These interfaces process NAT64 traffic.")
    else:
        log("  ✅ No interfaces with 'nat64 enable' found.")

    # Check dual-stack (IPv4+IPv6)
    ipv6_ifaces = connection.send_command(
        "show ipv6 interface brief | exclude unassigned|down"
    )
    if ipv6_ifaces.strip():
        log("  Active IPv6 interfaces (NAT64 context):")
        log(ipv6_ifaces)
    else:
        log("  No active IPv6 interfaces — NAT64 may not be in use.")

    return nat64_ifaces

def disable_nat64(connection, nat64_ifaces):
    log("── STEP 6: Disabling NAT64 (DISABLE_NAT64=True) ──")

    # Step 1: Clear NAT64 translations
    log("  Clearing NAT64 translation table...")
    clear = connection.send_command(
        "clear ip nat64 translations *",
        expect_string=r"#"
    )
    log(f"  {clear if clear.strip() else 'NAT64 translations cleared.'}")

    # Step 2: Remove nat64 enable from interfaces
    if nat64_ifaces:
        iface_cmds = []
        for iface in nat64_ifaces:
            iface_cmds.extend([f"interface {iface}", "no nat64 enable"])
            log(f"  Removing nat64 from interface: {iface}")
        output = connection.send_config_set(iface_cmds)
        log(output)

    # Step 3: Remove NAT64 global config
    nat64_cfg = connection.send_command("show running-config | include nat64")
    remove_cmds = []
    for line in nat64_cfg.splitlines():
        if line.strip().startswith("nat64") or line.strip().startswith("ip nat64"):
            remove_cmds.append(f"no {line.strip()}")

    if remove_cmds:
        output = connection.send_config_set(remove_cmds)
        log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ NAT64 disabled.")
    log("  CVE-2019-1751 attack surface eliminated.")
    log("  ⚠️  Verify any IPv6-transition services still functional.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 132723 - CVE-2019-1751 - Cisco IOS NAT64 DoS")
    log("")
    log("NAT64 vs standard NAT (Plugin 103669):")
    log("  Plugin 103669 (CVE-2017-12231) — standard IPv4 NAT/PAT")
    log("  Plugin 132723 (CVE-2019-1751) — NAT64 (IPv6-to-IPv4 translation)")
    log("  Both are on this device. Separate features, separate fixes.")
    log("")
    log("Attack outcomes:")
    log("  - Interface QUEUE WEDGE (silent traffic drop, needs manual recovery)")
    log("  - Device RELOAD (service interruption)")
    log("  Both require device restart to fully recover from queue wedge.")
    log("")
    log("Mitigation: Disable NAT64 if IPv6 transition is not in use")
    log("  NAT64 is uncommon on standard enterprise branch routers.")
    log("  Verify: 'show running-config | include nat64'")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvk61580")
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
    log("Fix Script - Plugin 132723 - Cisco IOS NAT64 DoS")
    log("CVE-2019-1751 | CSCvk61580")
    log("NAT64 not default — verify if actually configured")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        nat64_configured = check_nat64_config(connection)
        check_nat64_sessions(connection)
        nat64_ifaces = check_ipv6_nat64_interfaces(connection)

        if DISABLE_NAT64:
            if not nat64_configured:
                log("── STEP 6: NAT64 not configured — nothing to disable. ──")
                log("   Mark as 'Not Applicable' if confirmed.")
            else:
                disable_nat64(connection, nat64_ifaces)
        else:
            log("── STEP 6: Skipped (DISABLE_NAT64=False) ──")
            log("   Set DISABLE_NAT64=True if NAT64 is confirmed unused.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()