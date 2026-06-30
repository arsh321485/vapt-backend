#!/usr/bin/env python3
"""
Verify Script - Plugin 108956
Cisco IOS Software DNS Forwarder DoS
CVE-2016-6380 | Bug ID: CSCup90532

Checks:
  1. IOS version vs known vulnerable releases
  2. DNS forwarder enabled state
  3. DNS name-server config
  4. DNS host table (active usage indicator)
  5. Post-change connectivity check
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
    "15.6(1)T", "15.5(3)M", "15.5(2)T",
    "12.4(24)T", "12.4(22)T",
]

LOG_FILE = f"verify_108956_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per Cisco Bug CSCup90532.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-dns")

def check_dns_forwarder_state(connection):
    log("─── CHECK 2: DNS Forwarder State ───")
    dns_cfg = connection.send_command("show running-config | include ip dns")

    if "no ip dns server" in dns_cfg:
        log("✅ PASS: 'no ip dns server' confirmed — DNS forwarder explicitly DISABLED.")
        log("   CVE-2016-6380 attack surface eliminated.")
    elif "ip dns server" in dns_cfg:
        log("⚠️  'ip dns server' is ENABLED — device is acting as DNS forwarder.")
        log("   Exposed to CVE-2016-6380 until IOS upgrade is completed.")
        log("   Consider 'no ip dns server' if DNS forwarding is not required.")
    else:
        log("ℹ️  No explicit 'ip dns server' line found in config.")
        log("   DNS forwarder may be off by default — verify with 'show ip dns view'.")

def check_name_server_config(connection):
    log("─── CHECK 3: Upstream Name Server Config ───")
    output = connection.send_command("show running-config | include ip name-server")
    if output.strip():
        log("Configured upstream name servers:")
        log(output)
        log("ℹ️  These are upstream resolvers — do not indicate DNS forwarding alone.")
    else:
        log("No upstream name servers configured.")

def check_dns_view(connection):
    log("─── CHECK 4: DNS View / Activity ───")
    output = connection.send_command("show ip dns view")
    if output.strip():
        log("DNS view details:")
        log(output)
    else:
        log("No DNS view configured.")

    hosts = connection.send_command("show hosts summary")
    if hosts.strip():
        log("Host table summary (DNS activity indicator):")
        log(hosts)
    else:
        log("✅ No host table entries — no active DNS forwarding detected.")

def check_interface_up(connection):
    log("─── CHECK 5: Interface Status (post-change health) ───")
    output = connection.send_command("show ip interface brief | exclude unassigned")
    log(output if output.strip() else "No interface output.")

def main():
    log("="*65)
    log("Verify Script - Plugin 108956 - Cisco IOS DNS Forwarder DoS")
    log("CVE-2016-6380 | CSCup90532")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_dns_forwarder_state(connection)
        check_name_server_config(connection)
        check_dns_view(connection)
        check_interface_up(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS conditions:")
        log("     - 'no ip dns server' confirmed in running config, OR")
        log("     - IOS upgraded to fixed release per CSCup90532")
        log("  ❌ FAIL conditions:")
        log("     - 'ip dns server' still enabled on vulnerable IOS version")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()