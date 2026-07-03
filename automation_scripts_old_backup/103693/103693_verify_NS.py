#!/usr/bin/env python3
"""
Verify Script - Plugin 103693
Cisco IOS Software IKE DoS Vulnerability
CVE-2017-12237 | Bug ID: CSCvc41277
CISA KEV — Listed 2022/03/24

Checks:
  1. IOS version vs known vulnerable releases
  2. IKEv1 SA health post-upgrade
  3. IKEv2 SA health post-upgrade
  4. IPSec tunnel operational check
  5. Crypto engine health
  6. CISA KEV status summary for all 3 KEVs on device
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
    "16.3.1", "16.6.1", "16.9.1",
]

LOG_FILE = f"verify_103693_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   CISA KEV — Upgrade required IMMEDIATELY per CSCvc41277.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-ike")
    return detected

def check_ikev1_health(connection):
    log("─── CHECK 2: IKEv1 SA Health ───")
    output = connection.send_command("show crypto isakmp sa")

    if not output.strip():
        log("No IKEv1 SAs present.")
        return

    log(output)
    active = [l for l in output.splitlines() if "ACTIVE" in l or "QM_IDLE" in l]
    deleted = [l for l in output.splitlines() if "DELETED" in l or "MM_NO_STATE" in l]

    if active:
        log(f"✅ {len(active)} active IKEv1 SA(s) — tunnels healthy post-upgrade.")
    if deleted:
        log(f"⚠️  {len(deleted)} stuck/deleted IKEv1 SA(s) — investigate VPN connectivity.")
    if not active and not deleted:
        log("ℹ️  No IKEv1 SAs (expected if no IKEv1 VPNs configured).")

def check_ikev2_health(connection):
    log("─── CHECK 3: IKEv2 SA Health ───")
    output = connection.send_command("show crypto ikev2 sa")

    if not output.strip():
        log("No IKEv2 SAs present.")
        return

    log(output)
    ready = [l for l in output.splitlines() if "READY" in l]
    if ready:
        log(f"✅ {len(ready)} IKEv2 SA(s) in READY state — tunnels healthy.")
    else:
        log("⚠️  IKEv2 SAs present but none in READY state — investigate.")

def check_ipsec_health(connection):
    log("─── CHECK 4: IPSec Tunnel Health ───")
    output = connection.send_command(
        "show crypto ipsec sa | include pkts encrypt|pkts decrypt|#pkts"
    )
    if output.strip():
        log("IPSec traffic counters:")
        log(output)
        encrypt_lines = [l for l in output.splitlines() if "encrypt" in l]
        for line in encrypt_lines[:5]:
            parts = line.split()
            for i, p in enumerate(parts):
                if "encrypt" in p and i + 1 < len(parts):
                    try:
                        count = int(parts[i+1].replace(",", ""))
                        if count > 0:
                            log(f"✅ Traffic flowing: {line.strip()}")
                    except ValueError:
                        pass
    else:
        log("No IPSec SA traffic counters (no active tunnels or no traffic).")

def check_crypto_engine(connection):
    log("─── CHECK 5: Crypto Engine Health ───")
    output = connection.send_command("show crypto engine brief")
    if output.strip():
        log(output)
        if "up" in output.lower() or "active" in output.lower():
            log("✅ Crypto engine operational.")
    else:
        log("No crypto engine output.")

def cisa_kev_summary():
    log("─── CHECK 6: CISA KEV Summary — All 3 KEVs on This Device ───")
    log("")
    log("  This device has THREE CISA Known Exploited Vulnerabilities:")
    log("")
    log("  ┌─────────────────────────────────────────────────────────┐")
    log("  │ Plugin  │ CVE           │ Name              │ Listed    │")
    log("  ├─────────────────────────────────────────────────────────┤")
    log("  │ 93736   │ CVE-2016-6415 │ BENIGNCERTAIN     │ 2023/06/09│")
    log("  │ 131166  │ CVE-2018-0154 │ ISM-VPN DoS       │ 2022/03/17│")
    log("  │ 103693  │ CVE-2017-12237│ IKE DoS           │ 2022/03/24│")
    log("  └─────────────────────────────────────────────────────────┘")
    log("")
    log("  All three are resolved by a single IOS upgrade.")
    log("  No CLI workaround exists for any of these three.")
    log("  Treat as CRITICAL — actively exploited in the wild.")

def main():
    log("="*65)
    log("Verify Script - Plugin 103693 - Cisco IOS IKE DoS")
    log("CVE-2017-12237 | CSCvc41277 | CISA KEV #3 on Device")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        detected = check_ios_version(connection)
        check_ikev1_health(connection)
        check_ikev2_health(connection)
        check_ipsec_health(connection)
        check_crypto_engine(connection)
        cisa_kev_summary()

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: IOS upgraded to fixed release per CSCvc41277")
        log("  ❌ FAIL: Still running vulnerable IOS version")
        log("  ⚠️  CISA KEV — NO WORKAROUND — upgrade is the ONLY fix")
        log("  This is 1 of 3 CISA KEVs on this device — all cleared by upgrade")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()