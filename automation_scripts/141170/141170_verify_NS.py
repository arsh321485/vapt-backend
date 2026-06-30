#!/usr/bin/env python3
"""
Verify Script - Plugin 141170
Cisco IOS Software Split DNS DoS
CVE-2020-3408 | Bug ID: CSCvt78186

Checks:
  1. IOS version vs known vulnerable releases
  2. Split DNS configuration state
  3. DNS name list regex patterns (root cause)
  4. DNS view assignment state
  5. DNS server active state
  6. Cross-reference with Plugin 108956 (DNS Forwarder DoS)
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

LOG_FILE = f"verify_141170_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per Cisco Bug CSCvt78186.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-splitdns-SPWqpdGW")

def check_split_dns_state(connection):
    log("─── CHECK 2: Split DNS Configuration State ───")
    dns_view = connection.send_command("show running-config | section ip dns view")
    dns_namelist = connection.send_command(
        "show running-config | section ip dns name-list"
    )

    if not dns_view.strip() and not dns_namelist.strip():
        log("✅ PASS: No Split DNS configuration found.")
        log("   CVE-2020-3408 not applicable — Split DNS not deployed.")
        log("   Mark as 'Not Applicable' after physical verification.")
        return False

    log("⚠️  Split DNS configuration present:")
    if dns_view.strip():
        log("  DNS Views:")
        log(dns_view[:300] if len(dns_view) > 300 else dns_view)
    if dns_namelist.strip():
        log("  DNS Name Lists:")
        log(dns_namelist[:300] if len(dns_namelist) > 300 else dns_namelist)

    return True

def check_regex_patterns(connection):
    log("─── CHECK 3: DNS Name List Regex Patterns (Root Cause) ───")
    log("  CVE-2020-3408 is triggered by regex patterns in DNS name lists.")

    all_cfg = connection.send_command(
        "show running-config | include ip dns name-list|permit|deny"
    )

    regex_chars = ["\\.", "\\*", ".*", "^", "\\w", "\\d", "[", "(", "\\s", "+", "?"]
    regex_found = []

    for line in all_cfg.splitlines():
        if any(ch in line for ch in regex_chars) and "name-list" not in line:
            regex_found.append(line.strip())

    if regex_found:
        log(f"  ❌ {len(regex_found)} regex pattern(s) detected:")
        for pattern in regex_found:
            log(f"    {pattern}")
        log("  ❌ Regex patterns present — CVE-2020-3408 is EXPLOITABLE.")
        log("  Remove regex or upgrade IOS to remediate.")
    else:
        log("  ✅ No regex patterns detected in DNS name list entries.")
        log("  Exact-match name lists may not trigger the vulnerability.")
        log("  Upgrade IOS to be certain — regex check is best-effort.")

    return bool(regex_found)

def check_dns_view_assignment(connection):
    log("─── CHECK 4: DNS View-List Assignment ───")
    viewlist = connection.send_command(
        "show running-config | include ip dns view-list"
    )

    if viewlist.strip():
        log("  DNS view-list configured (Split DNS active):")
        log(viewlist)
        log("  ⚠️  Split DNS is actively routing DNS queries by domain.")
    else:
        log("  ✅ No DNS view-list assignment found.")
        log("  Even if DNS views exist, Split DNS may not be routing queries.")

def check_dns_server_state(connection):
    log("─── CHECK 5: DNS Server State ───")
    dns_cfg = connection.send_command("show running-config | include ip dns server")

    if "ip dns server" in dns_cfg and "no ip dns server" not in dns_cfg:
        log("  ⚠️  DNS server is ACTIVE.")
        log("  Split DNS requires the DNS server to be running.")
        log("  See also Plugin 108956 (DNS Forwarder DoS — separate vulnerability).")
    else:
        log("  ✅ DNS server not explicitly enabled.")
        log("  Without DNS server, Split DNS cannot process queries.")

def cross_reference_108956(connection):
    log("─── CHECK 6: Cross-Reference — Plugin 108956 vs 141170 ───")
    log("")
    log("  Two DNS-related vulnerabilities on this device:")
    log("")
    log("  Plugin 108956 (CVE-2016-6380) — DNS Forwarder DoS")
    log("    Feature: 'ip dns server' with forwarding")
    log("    Attack: Malformed DNS request → DoS")
    log("    Mitigation: 'no ip dns server'")

    dns_server = connection.send_command("show running-config | include ip dns server")
    if "ip dns server" in dns_server and "no" not in dns_server:
        log("    Status: ⚠️  ACTIVE — Plugin 108956 exposure confirmed")
    else:
        log("    Status: ✅ Not active")

    log("")
    log("  Plugin 141170 (CVE-2020-3408) — Split DNS Regex DoS")
    log("    Feature: DNS views + name lists with regex patterns")
    log("    Attack: Crafted DNS query triggers regex timeout → reload")
    log("    Mitigation: Remove regex from name lists or disable Split DNS")

    dns_view = connection.send_command("show running-config | include ip dns view")
    if dns_view.strip():
        log("    Status: ⚠️  Split DNS configured — investigate regex patterns")
    else:
        log("    Status: ✅ Split DNS not configured")

    log("")
    log("  SHARED MITIGATION: 'no ip dns server' disables BOTH features.")
    log("  If DNS not needed: disable DNS server to mitigate both plugins.")

def main():
    log("="*65)
    log("Verify Script - Plugin 141170 - Cisco IOS Split DNS DoS")
    log("CVE-2020-3408 | CSCvt78186 | CVSS 8.6")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        split_present = check_split_dns_state(connection)
        if split_present:
            check_regex_patterns(connection)
            check_dns_view_assignment(connection)
        else:
            log("Split DNS not configured — skipping regex and view checks.")
        check_dns_server_state(connection)
        cross_reference_108956(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS (best): IOS upgraded per CSCvt78186")
        log("  ✅ PASS (mitigation): Split DNS not configured / removed")
        log("  ✅ PASS (alt mitigation): DNS server disabled (covers 108956 too)")
        log("  ❌ FAIL: Split DNS + regex patterns + vulnerable IOS")
        log("")
        log("  NOT DEFAULT — if never configured: mark Not Applicable")
        log("  Unauthenticated attack — CVSS 8.6 (tied 2nd highest on device)")
        log("  Shared mitigation with Plugin 108956: 'no ip dns server'")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()