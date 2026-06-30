#!/usr/bin/env python3
"""
Verify Script - Plugin 198146
Cisco IOS Software IKEv1 Fragmentation DoS
CVE-2024-20307 | CVE-2024-20308
Bug IDs: CSCwf11183, CSCwh66334

Checks:
  1. IOS version vs known vulnerable releases
  2. IKEv1 fragmentation disabled state
  3. IKEv1 SA health
  4. IPv6 exposure check
  5. Cross-reference with Plugin 94762 mitigation status
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
    "15.6(1)T", "15.5(3)M", "15.7(3)M",
    "16.9.1", "16.12.1", "17.3.1", "17.6.1",
]

LOG_FILE = f"verify_198146_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per CSCwf11183 / CSCwh66334.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ikev1-NO2ccFWz")

def check_fragmentation_disabled(connection):
    log("─── CHECK 2: IKEv1 Fragmentation State ───")
    frag_cfg = connection.send_command(
        "show running-config | include crypto isakmp fragmentation"
    )

    if "no crypto isakmp fragmentation" in frag_cfg:
        log("✅ PASS: 'no crypto isakmp fragmentation' confirmed in running config.")
        log("   CVE-2024-20307 (heap overflow) — MITIGATED.")
        log("   CVE-2024-20308 (heap underflow) — MITIGATED.")
        log("   Also covers Plugin 94762 (CVE-2016-6381) mitigation.")
        return True
    elif "crypto isakmp fragmentation" in frag_cfg and "no" not in frag_cfg:
        log("❌ FAIL: IKEv1 fragmentation is explicitly ENABLED.")
        log("   Heap overflow/underflow attack surface active.")
        return False
    else:
        log("⚠️  No explicit fragmentation config — default state may allow fragmentation.")
        log("   Apply 'no crypto isakmp fragmentation' to be explicit.")
        return False

def check_ikev1_sa_health(connection):
    log("─── CHECK 3: IKEv1 SA Health ───")
    output = connection.send_command("show crypto isakmp sa")
    if output.strip():
        log(output)
        active = [l for l in output.splitlines()
                  if "ACTIVE" in l or "QM_IDLE" in l]
        stuck = [l for l in output.splitlines()
                 if "DELETED" in l or "MM_NO_STATE" in l]
        if active:
            log(f"  ✅ {len(active)} active IKEv1 SA(s) — tunnels functional.")
        if stuck:
            log(f"  ⚠️  {len(stuck)} stuck SA(s) — investigate VPN connectivity.")
    else:
        log("  No IKEv1 SAs (expected if no IKEv1 VPNs or fragmentation disabled).")

def check_ipv6_state(connection):
    log("─── CHECK 4: IPv6 Attack Vector ───")
    log("  Both CVEs are exploitable via IPv4 AND IPv6 UDP.")

    ipv6_ifaces = connection.send_command(
        "show ipv6 interface brief | exclude unassigned|down"
    )
    if ipv6_ifaces.strip():
        log("  IPv6-enabled interfaces:")
        log(ipv6_ifaces)
        log("  ℹ️  Ensure fragmentation mitigation covers IPv6 IKEv1 path.")
    else:
        log("  ✅ No active IPv6 interfaces — IPv6 attack vector not present.")

def cross_reference_94762(connection):
    log("─── CHECK 5: Cross-reference Plugin 94762 (CVE-2016-6381) ───")
    log("  Plugin 94762 and 198146 share the SAME mitigation command:")
    log("  'no crypto isakmp fragmentation'")
    log("")

    frag_cfg = connection.send_command(
        "show running-config | include crypto isakmp fragmentation"
    )

    if "no crypto isakmp fragmentation" in frag_cfg:
        log("  ✅ Mitigation confirmed — covers BOTH Plugin 94762 AND 198146.")
        log("     CVE-2016-6381: MITIGATED")
        log("     CVE-2024-20307: MITIGATED")
        log("     CVE-2024-20308: MITIGATED")
    else:
        log("  ⚠️  Mitigation not confirmed for either plugin.")
        log("  Apply 'no crypto isakmp fragmentation' to cover both.")

def main():
    log("="*65)
    log("Verify Script - Plugin 198146 - IKEv1 Frag Heap DoS")
    log("CVE-2024-20307 + CVE-2024-20308 | CSCwf11183 | CSCwh66334")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        frag_ok = check_fragmentation_disabled(connection)
        check_ikev1_sa_health(connection)
        check_ipv6_state(connection)
        cross_reference_94762(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: 'no crypto isakmp fragmentation' confirmed, OR IOS upgraded")
        log("  ❌ FAIL: Fragmentation enabled/unset on vulnerable IOS version")
        log("")
        log("  CVE-2024-20307: Heap OVERFLOW via fragmented IKEv1 (IPv4/IPv6)")
        log("  CVE-2024-20308: Heap UNDERFLOW via fragmented IKEv1 (IPv4/IPv6)")
        log("  Both: Unauthenticated, remote, more severe than Plugin 94762")
        log("")
        log("  Mitigation also covers Plugin 94762 (CVE-2016-6381)")
        log("  Permanent fix: IOS upgrade per CSCwf11183/CSCwh66334")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()