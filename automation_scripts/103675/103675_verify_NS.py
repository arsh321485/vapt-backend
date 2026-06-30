#!/usr/bin/env python3
"""
Verify Script - Plugin 103675
Cisco IOS PnP PKI API Certificate Validation
CVE-2017-12228 | Bug ID: CSCvc33171
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

LOG_FILE = f"verify_103675_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
                log("❌ Vulnerable — upgrade per CSCvc33171.")
            else:
                log("⚠️  Verify against full advisory (Modified: 2025/11/19).")
            break

def check_pnp_disabled(connection):
    log("─── CHECK 2: PnP Agent State ───")
    status = connection.send_command("show pnp status")

    if "Disabled" in status or "disabled" in status:
        log("✅ PnP agent DISABLED.")
        log("  Both CVE-2017-12228 (103675) and CVE-2019-1748 (127049) mitigated.")
    elif "Idle" in status:
        log("ℹ️  PnP agent IDLE — low risk on production device.")
        log("  Upgrade IOS for permanent fix.")
    elif status.strip():
        log("⚠️  PnP may be active:")
        log(status[:200] if len(status) > 200 else status)
    else:
        pnp_cfg = connection.send_command("show running-config | include pnp")
        if not pnp_cfg.strip():
            log("✅ No PnP config found — agent likely not deployed.")
        else:
            log(f"PnP config: {pnp_cfg.strip()}")

def check_pki_trustpool(connection):
    log("─── CHECK 3: PKI Trustpool ───")
    count = connection.send_command("show crypto pki trustpool | count")
    log(f"  Trustpool entries: {count.strip()}")
    log("  ℹ️  Trustpool validates certificates in PnP PKI API operations.")

def dual_pnp_plugin_summary():
    log("─── CHECK 4: Dual PnP Plugin Summary ───")
    log("")
    log("  Two PnP certificate validation plugins on this device:")
    log("")
    log("  Plugin 103675 (CVE-2017-12228) — PnP PKI API cert validation")
    log("    CVSS: 5.9 | C:H/I:N/A:N | tcp/0")
    log("")
    log("  Plugin 127049 (CVE-2019-1748) — PnP MitM cert validation")
    log("    CVSS: 7.4 | C:H/I:H/A:N | tcp/161")
    log("")
    log("  Both share the same PnP disable mitigation.")
    log("  Both resolved by same IOS upgrade.")
    log("")
    log("  If Plugin 127049 already mitigated → 103675 is also mitigated.")

def main():
    log("="*65)
    log("Verify - Plugin 103675 - Cisco IOS PnP PKI API")
    log("CVE-2017-12228 | CSCvc33171 | CVSS 5.9")
    log("="*65)

    try:
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_pnp_disabled(connection)
        check_pki_trustpool(connection)
        dual_pnp_plugin_summary()

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS: IOS upgraded OR PnP agent disabled")
        log("  ❌ FAIL: PnP active + vulnerable IOS + complex PKI attack")
        log("  If Plugin 127049 mitigated → this one is too")
        log("  Modified: 2025/11/19 — check advisory for updated fixed releases")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")

if __name__ == "__main__":
    main()