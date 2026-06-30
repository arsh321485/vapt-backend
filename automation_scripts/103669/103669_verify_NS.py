#!/usr/bin/env python3
"""
Verify Script - Plugin 103669
Cisco IOS Software NAT DoS Vulnerability
CVE-2017-12231 | Bug ID: CSCvc57217
CISA KEV — Listed 2022/03/24

Checks:
  1. IOS version vs known vulnerable releases
  2. NAT configuration state
  3. Active NAT translation count
  4. NAT statistics (traffic volume indicator)
  5. Device traffic processing health
  6. CISA KEV summary — all 5 KEVs on device
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

LOG_FILE = f"verify_103669_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   CISA KEV — Upgrade IMMEDIATELY per Cisco Bug CSCvc57217.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-nat")

def check_nat_state(connection):
    log("─── CHECK 2: NAT Configuration State ───")
    nat_cfg = connection.send_command("show running-config | include ip nat")

    if not nat_cfg.strip():
        log("✅ PASS: No NAT configuration found.")
        log("   CVE-2017-12231 attack surface not applicable.")
        log("   Confirm physically that NAT is not required.")
        return False

    log("⚠️  NAT is configured:")
    log(nat_cfg)

    if "overload" in nat_cfg:
        log("  ⚠️  PAT (NAT overload) active — likely internet gateway.")
        log("  HIGH IMPACT to disable — internal hosts lose internet.")
    if "ip nat inside" in nat_cfg or "ip nat outside" in nat_cfg:
        log("  NAT inside/outside interfaces assigned.")

    log("  Device exposed to CVE-2017-12231 until IOS upgrade.")
    return True

def check_nat_translations(connection):
    log("─── CHECK 3: Active NAT Translations ───")

    total = connection.send_command("show ip nat translations total")
    log(f"  Translation table total: {total.strip()}")

    # Check if table is empty (mitigation applied)
    trans = connection.send_command("show ip nat translations")
    if not trans.strip() or "Pro" not in trans:
        log("  ✅ NAT translation table is empty.")
        log("  No active NAT sessions — attack surface reduced.")
    else:
        lines = [l for l in trans.splitlines() if l.strip()
                 and "Pro" not in l and "---" not in l]
        log(f"  ⚠️  {len(lines)} active NAT translation(s).")
        log("  Device is actively NAT-ing traffic.")

def check_nat_statistics(connection):
    log("─── CHECK 4: NAT Statistics ───")
    output = connection.send_command("show ip nat statistics")
    if output.strip():
        log(output[:500] if len(output) > 500 else output)

        for line in output.splitlines():
            if "hits" in line.lower():
                parts = line.split()
                try:
                    hits = int(parts[-1].replace(",", ""))
                    if hits > 0:
                        log(f"  ⚠️  NAT hit counter: {hits} — active NAT processing.")
                    else:
                        log("  ✅ Zero NAT hits — NAT not actively translating.")
                except (ValueError, IndexError):
                    pass
    else:
        log("  No NAT statistics available.")

def check_device_traffic_health(connection):
    log("─── CHECK 5: Device Traffic Processing Health ───")
    log("  CVE-2017-12231 causes device to STOP PROCESSING TRAFFIC.")
    log("  If an attack occurred, device would need restart to recover.")

    # CPU utilization
    cpu = connection.send_command("show processes cpu sorted | head 10")
    if cpu.strip():
        log("  CPU utilization (top processes):")
        log(cpu)
        for line in cpu.splitlines():
            if "CPU utilization" in line:
                log(f"  Overall: {line.strip()}")

    # Interface input/output rate
    intf_rate = connection.send_command(
        "show interfaces | include line protocol|input rate|output rate"
    )
    if intf_rate.strip():
        log("  Interface traffic rates:")
        # Show first 20 lines
        lines = intf_rate.splitlines()[:20]
        log("\n".join(lines))
        log("  ✅ If interfaces show traffic rates, device is processing traffic normally.")

def cisa_kev_summary():
    log("─── CHECK 6: CISA KEV Summary — All 5 KEVs on This Device ───")
    log("")
    log("  This device has FIVE CISA Known Exploited Vulnerabilities:")
    log("")
    log("  ┌─────────────────────────────────────────────────────────────────────┐")
    log("  │ Plugin │ CVE(s)             │ Name                  │ Listed       │")
    log("  ├─────────────────────────────────────────────────────────────────────┤")
    log("  │ 93736  │ CVE-2016-6415      │ BENIGNCERTAIN         │ 2023/06/09   │")
    log("  │ 131166 │ CVE-2018-0154      │ ISM-VPN DoS           │ 2022/03/17   │")
    log("  │ 103693 │ CVE-2017-12237     │ IKE DoS               │ 2022/03/24   │")
    log("  │ 108880 │ CVE-2018-0167/0175 │ LLDP Buffer Overflow  │ 2022/03/17   │")
    log("  │ 103669 │ CVE-2017-12231     │ NAT DoS               │ 2022/03/24   │")
    log("  └─────────────────────────────────────────────────────────────────────┘")
    log("")
    log("  All five resolved by a SINGLE IOS upgrade.")
    log("  Plugin 103669 has HIGHEST EPSS (0.1085) — highest exploitation probability.")
    log("  Plugin 103669 uniquely causes FULL TRAFFIC STOP (not just reload).")

def main():
    log("="*65)
    log("Verify Script - Plugin 103669 - Cisco IOS NAT DoS")
    log("CVE-2017-12231 | CSCvc57217 | CISA KEV #5 | EPSS 0.1085")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        nat_active = check_nat_state(connection)
        check_nat_translations(connection)
        check_nat_statistics(connection)
        check_device_traffic_health(connection)
        cisa_kev_summary()

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS (best): IOS upgraded to fixed release per CSCvc57217")
        log("  ✅ PASS (mitigation): NAT confirmed not configured on device")
        log("  ⚠️  PARTIAL: NAT removed as mitigation but IOS not yet upgraded")
        log("  ❌ FAIL: NAT active + vulnerable IOS version")
        log("")
        log("  UNIQUE RISK: Attack causes FULL TRAFFIC STOP — requires restart")
        log("  CISA KEV + EPSS 0.1085 — highest exploitation probability on device")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()