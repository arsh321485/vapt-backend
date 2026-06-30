#!/usr/bin/env python3
"""
Verify Script - Plugin 130092
Cisco IOS Software IP SLA DoS Vulnerability
CVE-2019-1737 | Bug ID: CSCvf37838

Checks:
  1. IOS version vs known vulnerable releases
  2. IP SLA responder runtime state
  3. Interface wedge indicators (queue drops)
  4. Active IP SLA operations (sourcing vs responding)
  5. Post-change SLA probe health
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

LOG_FILE = f"verify_130092_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   CVSS 8.6 — Upgrade required urgently per Cisco Bug CSCvf37838.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-ipsla-dos")

def check_ipsla_responder_state(connection):
    log("─── CHECK 2: IP SLA Responder State ───")

    # Config check
    cfg = connection.send_command("show running-config | include ip sla responder")

    if "no ip sla responder" in cfg:
        log("✅ PASS: 'no ip sla responder' confirmed in running config.")
        log("   CVE-2019-1737 attack surface ELIMINATED.")
    elif "ip sla responder" in cfg:
        log("❌ FAIL: 'ip sla responder' is ENABLED.")
        log("   Device is exposed to CVE-2019-1737.")
        log("   Apply 'no ip sla responder' or upgrade IOS.")
    else:
        log("ℹ️  No explicit SLA responder config line found.")

    # Runtime check
    runtime = connection.send_command("show ip sla responder")
    log("  Runtime state:")
    log(runtime if runtime.strip() else "  No runtime output.")

    if "enabled" in runtime.lower():
        log("  ⚠️  IP SLA responder is ACTIVE at runtime.")
    elif "disabled" in runtime.lower() or not runtime.strip():
        log("  ✅ IP SLA responder appears inactive at runtime.")

def check_interface_drops(connection):
    log("─── CHECK 3: Interface Drop/Wedge Indicators ───")
    output = connection.send_command(
        "show interfaces | include line protocol|input errors|output drops|input queue"
    )
    if output.strip():
        log(output)
        high_drops = False
        for line in output.splitlines():
            for token in line.split():
                try:
                    val = int(token.replace(",", ""))
                    if val > 500:
                        log(f"  ⚠️  High counter value detected: {line.strip()}")
                        high_drops = True
                        break
                except ValueError:
                    continue
        if not high_drops:
            log("  ✅ No abnormal drop counts detected.")
    else:
        log("  No interface error data returned.")

def check_ipsla_active_ops(connection):
    log("─── CHECK 4: IP SLA Active Operations ───")
    output = connection.send_command("show ip sla statistics")
    if output.strip() and "No" not in output:
        log("Active IP SLA statistics:")
        log(output[:600] if len(output) > 600 else output)

        # Check for failures
        for line in output.splitlines():
            if "failures" in line.lower() or "timeout" in line.lower():
                log(f"  ℹ️  {line.strip()}")
    else:
        log("  No active IP SLA statistics.")
        log("  ✅ This device is not actively running SLA probes.")

def check_sla_responder_connections(connection):
    log("─── CHECK 5: IP SLA Responder Connection State ───")
    output = connection.send_command("show ip sla responder")
    if output.strip():
        log(output)
        if "Recent Sources" in output or "Last 25 Sources" in output:
            log("  ℹ️  SLA responder has recent source history.")
            log("  External devices are/were probing this device via IP SLA.")
    else:
        log("  No SLA responder connection data.")
        log("  ✅ No external SLA probes detected.")

def main():
    log("="*65)
    log("Verify Script - Plugin 130092 - Cisco IOS IP SLA DoS")
    log("CVE-2019-1737 | CSCvf37838 | CVSS 8.6")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_ipsla_responder_state(connection)
        check_interface_drops(connection)
        check_ipsla_active_ops(connection)
        check_sla_responder_connections(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: 'no ip sla responder' confirmed, OR IOS upgraded")
        log("  ❌ FAIL: IP SLA responder still enabled on vulnerable IOS")
        log("  ⚠️  INTERFACE WEDGE RISK: Attack doesn't reload device —")
        log("      interfaces wedge silently. Monitor queue drops post-attack.")
        log("  Priority: HIGHEST on this device (CVSS 8.6, unauthenticated)")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()