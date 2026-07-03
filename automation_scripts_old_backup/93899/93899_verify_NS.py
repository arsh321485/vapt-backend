#!/usr/bin/env python3
"""
Verify Script - Plugin 93899
Cisco IOS Multicast Routing Multiple DoS
CVE-2016-6382 (IPv6 PIM) | CVE-2016-6392 (MSDP)
Bug IDs: CSCud36767, CSCuy16399

Checks:
  1. IOS version vs known vulnerable releases
  2. IPv6 PIM interface state (CVE-2016-6382)
  3. MSDP peer state (CVE-2016-6392)
  4. Multicast routing table health
  5. PIM RP mapping
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

VULNERABLE_VERSIONS = [
    "15.4(3)M5", "15.4(3)M4", "15.4(3)M3",
    "15.4(2)T4", "15.3(3)M8", "15.2(4)M10",
    "15.6(1)T", "15.5(3)M",
]

LOG_FILE = f"verify_93899_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per cisco-sa-20160928-msdp.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-msdp")

def check_ipv6_pim(connection):
    log("─── CHECK 2: IPv6 PIM State (CVE-2016-6382) ───")
    output = connection.send_command("show ipv6 pim interface")
    if output.strip():
        log("⚠️  IPv6 PIM is active on interfaces:")
        log(output)
        log("   Device remains exposed to CVE-2016-6382 until IOS upgrade.")
    else:
        log("✅ No IPv6 PIM interfaces active.")
        log("   CVE-2016-6382 attack surface eliminated or not applicable.")

def check_msdp(connection):
    log("─── CHECK 3: MSDP Peer State (CVE-2016-6392) ───")
    peers = connection.send_command("show ip msdp peer")
    if peers.strip():
        log("⚠️  MSDP peers are configured:")
        log(peers)
        log("   Device remains exposed to CVE-2016-6392 until IOS upgrade.")
    else:
        log("✅ No MSDP peers configured.")
        log("   CVE-2016-6392 attack surface eliminated.")

    sa_cache = connection.send_command("show ip msdp sa-cache")
    if sa_cache.strip():
        log("  Active MSDP SA cache entries (MSDP is passing traffic):")
        log(sa_cache)

def check_multicast_routing(connection):
    log("─── CHECK 4: Multicast Routing Table Health ───")
    output = connection.send_command("show ip mroute summary")
    if output.strip():
        log("IPv4 multicast routes:")
        log(output[:500])  # Truncate if large table
    else:
        log("No IPv4 multicast routes.")

    ipv6_mroute = connection.send_command("show ipv6 mroute summary")
    if ipv6_mroute.strip():
        log("IPv6 multicast routes:")
        log(ipv6_mroute[:500])
    else:
        log("No IPv6 multicast routes.")

def check_pim_rp(connection):
    log("─── CHECK 5: PIM RP Mapping ───")
    rp_ipv4 = connection.send_command("show ip pim rp mapping")
    log("IPv4 PIM RP mapping:")
    log(rp_ipv4 if rp_ipv4.strip() else "No IPv4 RP mappings.")

    rp_ipv6 = connection.send_command("show ipv6 pim rp mapping")
    log("IPv6 PIM RP mapping:")
    log(rp_ipv6 if rp_ipv6.strip() else "No IPv6 RP mappings.")

def main():
    log("="*65)
    log("Verify Script - Plugin 93899 - Cisco IOS Multicast Routing DoS")
    log("CVE-2016-6382 | CVE-2016-6392 | CSCud36767 | CSCuy16399")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_ipv6_pim(connection)
        check_msdp(connection)
        check_multicast_routing(connection)
        check_pim_rp(connection)

        log("="*65)
        log("SUMMARY:")
        log("  CVE-2016-6382: ✅ if no IPv6 PIM interfaces / ❌ if IPv6 PIM active")
        log("  CVE-2016-6392: ✅ if no MSDP peers / ❌ if MSDP peers configured")
        log("  Permanent fix: IOS upgrade per cisco-sa-20160928-msdp")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()