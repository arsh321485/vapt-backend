#!/usr/bin/env python3
"""
Verify Script - Plugin 117951
Cisco IOS OSPFv3 DoS
CVE-2018-0466 | CSCuy82806
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

LOG_FILE = f"verify_117951_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
                log("❌ Vulnerable version — upgrade per CSCuy82806.")
            else:
                log("⚠️  Verify against full Cisco advisory.")
            break

def check_ospfv3_state(connection):
    log("─── CHECK 2: OSPFv3 State ───")
    cfg = connection.send_command("show running-config | section ipv6 router ospf")
    if not cfg.strip():
        log("✅ OSPFv3 not configured — Not Applicable.")
        return False
    log("⚠️  OSPFv3 configured:")
    log(cfg[:300] if len(cfg) > 300 else cfg)
    return True

def check_ospfv3_auth(connection):
    log("─── CHECK 3: OSPFv3 Authentication ───")
    auth = connection.send_command(
        "show running-config | include area.*authentication|area.*encryption"
    )
    if auth.strip() and ("ipsec" in auth.lower() or "sha" in auth.lower()):
        log("✅ OSPFv3 IPsec authentication configured.")
        log("  DoS mitigation via authentication in place.")
    elif auth.strip():
        log("⚠️  Auth present but type unclear — verify IPsec.")
    else:
        log("❌ No OSPFv3 authentication — DoS attack feasible from adjacent router.")

def check_ospfv3_neighbors(connection):
    log("─── CHECK 4: OSPFv3 Neighbors ───")
    neighbors = connection.send_command("show ipv6 ospf neighbor")
    if neighbors.strip() and "%" not in neighbors:
        log("OSPFv3 neighbors:")
        log(neighbors)
        log("⚠️  Active neighbors = potential attack sources (adjacent).")
    else:
        log("✅ No OSPFv3 neighbors — isolated or not active.")

def ospf_dual_plugin_summary():
    log("─── CHECK 5: OSPF Dual-Plugin Summary ───")
    log("")
    log("  Two OSPF plugins on this device:")
    log("")
    log("  Plugin 131394 (CVE-2017-6770) — OSPFv2 (IPv4) LSA Manipulation")
    log("    Impact: C:L/I:L routing manipulation, AC:H, VPR 2.5")
    log("    Mitigation: OSPF MD5 authentication")
    log("")
    log("  Plugin 117951 (CVE-2018-0466) — OSPFv3 (IPv6) DoS")
    log("    Impact: A:H DoS, Adjacent, VPR 3.6")
    log("    Mitigation: OSPFv3 IPsec authentication")
    log("")
    log("  Both resolved by a single IOS upgrade.")
    log("  Neither is critical — address after all priority plugins.")

def main():
    log("="*65)
    log("Verify - Plugin 117951 - OSPFv3 DoS")
    log("CVE-2018-0466 | CSCuy82806 | AV:A | VPR 3.6")
    log("="*65)

    try:
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        active = check_ospfv3_state(connection)
        if active:
            check_ospfv3_auth(connection)
            check_ospfv3_neighbors(connection)
        ospf_dual_plugin_summary()

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: IOS upgraded OR OSPFv3 not configured OR IPsec auth applied")
        log("  ❌ FAIL: OSPFv3 active + no auth + vulnerable IOS")
        log("  Adjacent only — lower practical risk than remote-exploitable plugins")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")

if __name__ == "__main__":
    main()