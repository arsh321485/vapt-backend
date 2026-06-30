#!/usr/bin/env python3
"""
Fix Script - Plugin 93899
Cisco IOS Multicast Routing Multiple DoS
CVE-2016-6382 (PIM IPv6 Register) | CVE-2016-6392 (MSDP SA)
Bug IDs: CSCud36767, CSCuy16399

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check PIM multicast state (IPv4 + IPv6)
  4. Check MSDP peer configuration
  5. Optionally disable MSDP peers (CVE-2016-6392 mitigation)
  6. Optionally disable IPv6 PIM on all interfaces (CVE-2016-6382 mitigation)
  7. Generate remediation report

NOTE: Only disable features if confirmed not in active use.
      Full fix = IOS upgrade per cisco-sa-20160928-msdp.
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

# CVE-2016-6392 mitigation: Remove all MSDP peer configs if unused
DISABLE_MSDP = False

# CVE-2016-6382 mitigation: Disable IPv6 PIM on all interfaces if unused
DISABLE_IPV6_PIM = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_93899_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_93899_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-msdp")

def check_pim_state(connection):
    log("── STEP 3: Checking PIM Multicast State ──")

    # IPv4 PIM
    log("  >> IPv4 PIM interfaces:")
    ipv4_pim = connection.send_command("show ip pim interface")
    log(ipv4_pim if ipv4_pim.strip() else "  No IPv4 PIM interfaces found.")

    # IPv4 PIM neighbors
    log("  >> IPv4 PIM neighbors:")
    ipv4_nbr = connection.send_command("show ip pim neighbor")
    log(ipv4_nbr if ipv4_nbr.strip() else "  No IPv4 PIM neighbors.")

    # IPv6 PIM
    log("  >> IPv6 PIM interfaces (CVE-2016-6382 relevant):")
    ipv6_pim = connection.send_command("show ipv6 pim interface")
    log(ipv6_pim if ipv6_pim.strip() else "  No IPv6 PIM interfaces found.")

    # IPv6 PIM neighbors
    log("  >> IPv6 PIM neighbors:")
    ipv6_nbr = connection.send_command("show ipv6 pim neighbor")
    log(ipv6_nbr if ipv6_nbr.strip() else "  No IPv6 PIM neighbors.")

    # RP info
    log("  >> IPv6 PIM RP info:")
    rp_info = connection.send_command("show ipv6 pim rp mapping")
    log(rp_info if rp_info.strip() else "  No IPv6 PIM RP mapping found.")

    ipv6_active = bool(ipv6_pim.strip())
    if ipv6_active:
        log("  ⚠️  IPv6 PIM is active — CVE-2016-6382 exposure confirmed.")
    else:
        log("  ✅ IPv6 PIM not detected — CVE-2016-6382 exposure may be minimal.")

    return ipv6_active

def check_msdp_state(connection):
    log("── STEP 4: Checking MSDP Configuration (CVE-2016-6392) ──")

    # MSDP peers from config
    msdp_cfg = connection.send_command("show running-config | include msdp")
    log("  MSDP config lines:")
    log(msdp_cfg if msdp_cfg.strip() else "  No MSDP config found.")

    # MSDP peer state
    msdp_peers = connection.send_command("show ip msdp peer")
    log("  MSDP peer state:")
    log(msdp_peers if msdp_peers.strip() else "  No MSDP peers configured.")

    # MSDP SA cache
    msdp_sa = connection.send_command("show ip msdp sa-cache")
    if msdp_sa.strip():
        log("  ⚠️  Active MSDP SA cache entries found — MSDP is in use.")
    else:
        log("  No MSDP SA cache entries.")

    msdp_active = bool(msdp_cfg.strip() and "ip msdp peer" in msdp_cfg)

    # Parse peer IPs for removal
    peer_ips = []
    for line in msdp_cfg.splitlines():
        if "ip msdp peer" in line:
            parts = line.strip().split()
            if len(parts) >= 4:
                peer_ips.append(parts[3])

    if msdp_active:
        log(f"  ⚠️  MSDP peers found: {peer_ips}")
        log("  CVE-2016-6392 exposure confirmed.")
    else:
        log("  ✅ No MSDP peers configured — CVE-2016-6392 exposure minimal.")

    return msdp_active, peer_ips

def get_ipv6_pim_interfaces(connection):
    """Parse interfaces with IPv6 PIM enabled"""
    output = connection.send_command("show ipv6 pim interface")
    interfaces = []
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].startswith(("GigabitEthernet", "FastEthernet",
                                           "Serial", "Loopback", "Tunnel")):
            interfaces.append(parts[0])
    return interfaces

def disable_msdp_peers(connection, peer_ips):
    log("── STEP 5a: Disabling MSDP Peers (DISABLE_MSDP=True) ──")
    if not peer_ips:
        log("  No MSDP peers to remove.")
        return

    commands = []
    for peer in peer_ips:
        commands.append(f"no ip msdp peer {peer}")
        log(f"  Removing MSDP peer: {peer}")

    output = connection.send_config_set(commands)
    log(output)
    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ MSDP peers removed — CVE-2016-6392 attack vector eliminated.")

def disable_ipv6_pim(connection):
    log("── STEP 5b: Disabling IPv6 PIM (DISABLE_IPV6_PIM=True) ──")
    interfaces = get_ipv6_pim_interfaces(connection)

    if not interfaces:
        log("  No IPv6 PIM interfaces detected to disable.")
        return

    log(f"  Found IPv6 PIM interfaces: {interfaces}")
    commands = []
    for iface in interfaces:
        commands.append(f"interface {iface}")
        commands.append("no ipv6 pim")

    output = connection.send_config_set(commands)
    log(output)
    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ IPv6 PIM disabled on all interfaces — CVE-2016-6382 attack vector reduced.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 93899 - CVE-2016-6382 + CVE-2016-6392 - Cisco IOS Multicast DoS")
    log("")
    log("Mitigations applied (if flags set):")
    log("  CVE-2016-6382: Disable IPv6 PIM (no ipv6 pim per interface)")
    log("  CVE-2016-6392: Remove MSDP peers (no ip msdp peer <IP>)")
    log("")
    log("Permanent Fix: IOS Upgrade per cisco-sa-20160928-msdp")
    log("  Bug IDs: CSCud36767 (PIM), CSCuy16399 (MSDP)")
    log("")
    log("Upgrade steps (manual):")
    log("  1. Download fixed IOS image from Cisco.com")
    log("  2. Transfer: 'copy tftp: flash:' or 'copy scp: flash:'")
    log("  3. Verify: 'verify /md5 flash:<image>'")
    log("  4. Set boot: 'boot system flash:<image>'")
    log("  5. Save: 'write memory'")
    log("  6. Reload: 'reload'")
    log("  7. Verify: 'show version'")
    log("  8. Re-scan Nessus with valid credentials")

def main():
    log("="*65)
    log("Fix Script - Plugin 93899 - Cisco IOS Multicast Routing DoS")
    log("CVE-2016-6382 (PIM) | CVE-2016-6392 (MSDP)")
    log("Bug IDs: CSCud36767 | CSCuy16399")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        ipv6_active = check_pim_state(connection)
        msdp_active, peer_ips = check_msdp_state(connection)

        # CVE-2016-6392 mitigation
        if DISABLE_MSDP:
            if msdp_active:
                disable_msdp_peers(connection, peer_ips)
            else:
                log("── STEP 5a: No MSDP peers found — nothing to disable. ──")
        else:
            log("── STEP 5a: Skipped (DISABLE_MSDP=False) ──")
            log("   Set DISABLE_MSDP=True if MSDP is confirmed unused.")

        # CVE-2016-6382 mitigation
        if DISABLE_IPV6_PIM:
            if ipv6_active:
                disable_ipv6_pim(connection)
            else:
                log("── STEP 5b: No IPv6 PIM interfaces found — nothing to disable. ──")
        else:
            log("── STEP 5b: Skipped (DISABLE_IPV6_PIM=False) ──")
            log("   Set DISABLE_IPV6_PIM=True if IPv6 multicast is confirmed unused.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()