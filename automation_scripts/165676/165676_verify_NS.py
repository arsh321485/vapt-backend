#!/usr/bin/env python3
"""
Verify Script - Plugin 165676
Cisco IOS Software SSH DoS Vulnerability
CVE-2022-20920 | Bug ID: CSCvx63027

Checks:
  1. IOS version vs known vulnerable releases
  2. SSH version (v2 only enforcement)
  3. SSH timeout and retry configuration
  4. VTY ACL restriction state
  5. VTY transport and exec-timeout
  6. Active SSH sessions
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
    "16.9.1", "16.12.1", "17.3.1", "17.6.1",
]

LOG_FILE = f"verify_165676_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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
            log("   Upgrade required per Cisco Bug CSCvx63027.")
        else:
            log("⚠️  Verify against full Cisco advisory for this train.")
            log("   https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ssh-excpt-dos-FzOBQTnk")

def check_ssh_version(connection):
    log("─── CHECK 2: SSH Version Enforcement ───")
    ssh_cfg = connection.send_command("show running-config | include ip ssh version")

    if "ip ssh version 2" in ssh_cfg:
        log("✅ SSHv2 only enforced.")
    elif "ip ssh version 1" in ssh_cfg:
        log("❌ SSHv1 configured — upgrade to version 2.")
    else:
        log("⚠️  No explicit SSH version — both v1 and v2 may be accepted.")
        log("   Apply: 'ip ssh version 2'")

    # Show ip ssh
    ssh_status = connection.send_command("show ip ssh")
    log("  SSH status:")
    log(ssh_status if ssh_status.strip() else "  No SSH status output.")

def check_ssh_timeout_retries(connection):
    log("─── CHECK 3: SSH Timeout and Retry Configuration ───")
    ssh_cfg = connection.send_command("show running-config | include ip ssh")

    timeout_ok = False
    retry_ok = False

    for line in ssh_cfg.splitlines():
        if "ip ssh time-out" in line:
            val = int(line.strip().split()[-1])
            if val <= 60:
                log(f"  ✅ SSH timeout: {val}s — acceptable.")
                timeout_ok = True
            else:
                log(f"  ⚠️  SSH timeout: {val}s — reduce to 60 or less.")

        if "ip ssh authentication-retries" in line:
            val = int(line.strip().split()[-1])
            if val <= 3:
                log(f"  ✅ SSH auth retries: {val} — acceptable.")
                retry_ok = True
            else:
                log(f"  ⚠️  SSH auth retries: {val} — reduce to 3.")

    if not timeout_ok:
        log("  ⚠️  No SSH timeout set — default (120s) may be too long.")
        log("   Apply: 'ip ssh time-out 60'")
    if not retry_ok:
        log("  ⚠️  No SSH retry limit set.")
        log("   Apply: 'ip ssh authentication-retries 3'")

def check_vty_acl(connection):
    log("─── CHECK 4: VTY ACL Restriction ───")
    vty_cfg = connection.send_command("show running-config | section line vty")

    if "access-class" in vty_cfg:
        log("✅ VTY access-class (ACL) is configured.")
        for line in vty_cfg.splitlines():
            if "access-class" in line:
                log(f"  {line.strip()}")
        log("  Attack requires network position to reach SSH + valid credentials.")
    else:
        log("❌ NO VTY access-class — SSH accessible from any network source.")
        log("  Apply 'access-class <ACL> in' on all VTY lines.")

def check_vty_transport(connection):
    log("─── CHECK 5: VTY Transport and Timeout ───")
    vty_cfg = connection.send_command("show running-config | section line vty")

    if "transport input ssh" in vty_cfg:
        log("✅ VTY transport restricted to SSH only (Telnet disabled).")
    elif "transport input none" in vty_cfg:
        log("✅ VTY transport set to none — remote access disabled.")
    elif "transport input all" in vty_cfg or "transport input telnet" in vty_cfg:
        log("⚠️  VTY allows Telnet — restrict to 'transport input ssh'.")
    else:
        log("⚠️  VTY transport not explicitly set.")

    if "exec-timeout" in vty_cfg:
        for line in vty_cfg.splitlines():
            if "exec-timeout" in line:
                log(f"  VTY exec-timeout: {line.strip()}")
        log("  ✅ VTY exec-timeout configured.")
    else:
        log("  ⚠️  No VTY exec-timeout — idle sessions never terminate.")
        log("  Apply: 'exec-timeout 10 0'")

def check_active_ssh_sessions(connection):
    log("─── CHECK 6: Active SSH Sessions ───")
    output = connection.send_command("show ssh")
    if output.strip():
        log("Active SSH sessions:")
        log(output)
        session_count = len([l for l in output.splitlines()
                             if "Session" not in l and l.strip()
                             and "---" not in l and "Version" not in l])
        log(f"  Active sessions: ~{session_count}")
    else:
        log("  No active SSH sessions.")

def main():
    log("="*65)
    log("Verify Script - Plugin 165676 - Cisco IOS SSH DoS")
    log("CVE-2022-20920 | CSCvx63027 | Authenticated Attack")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected.")

        check_ios_version(connection)
        check_ssh_version(connection)
        check_ssh_timeout_retries(connection)
        check_vty_acl(connection)
        check_vty_transport(connection)
        check_active_ssh_sessions(connection)

        log("="*65)
        log("SUMMARY:")
        log("  ✅ PASS (best): IOS upgraded per CSCvx63027")
        log("  ✅ PASS (mitigation): SSHv2 + VTY ACL + timeout/retry hardening")
        log("  ⚠️  PARTIAL: Some hardening applied but IOS not yet upgraded")
        log("  ❌ FAIL: No VTY ACL + vulnerable IOS + no SSH hardening")
        log("")
        log("  Authenticated attack — ACL restriction is effective mitigation")
        log("  NEVER disable SSH — use ACL to restrict, not eliminate")
        log("  Re-scan Nessus with valid credentials after upgrade.")
        log("="*65)

        connection.disconnect()
        log(f"Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()