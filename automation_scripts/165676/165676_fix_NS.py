#!/usr/bin/env python3
"""
Fix Script - Plugin 165676
Cisco IOS Software SSH DoS Vulnerability
CVE-2022-20920 | Bug ID: CSCvx63027

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Audit SSH configuration (version, timeout, retries, ACL)
  4. Audit VTY line SSH access controls
  5. Apply SSH hardening (ACL, SSHv2, timeout reduction)
  6. Generate remediation report

KEY NOTES:
  - Requires AUTHENTICATED SSH access — attacker needs valid credentials
  - Attack = continuously connect + send specific SSH requests → reload
  - Do NOT disable SSH — it's the primary management protocol
  - Best mitigation: VTY ACL restricting SSH to management hosts
  - Also enforce SSHv2 only and reduce timeout/retries
  - Full fix = IOS upgrade per CSCvx63027
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

# Management hosts allowed SSH access
# CRITICAL: Verify these are correct before applying — wrong IPs = lockout
SSH_ALLOWED_HOSTS = [
    "10.0.0.10",      # <-- Replace with your management/jump server IPs
    "10.0.0.11",
]

# ACL number for SSH/VTY restriction
SSH_ACL_NUMBER = "97"

# Set True to apply SSH hardening (ACL + SSHv2 + timeout reduction)
APPLY_SSH_HARDENING = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_165676_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_165676_{DEVICE['host']}_{TIMESTAMP}.txt"
    with open(backup_file, "w") as f:
        f.write(config)
    log(f"Config backed up to: {backup_file}")

def collect_ios_version(connection):
    log("── STEP 2: IOS Version Collection ──")
    output = connection.send_command("show version")
    for line in output.splitlines():
        if "Cisco IOS Software" in line or "Version" in line:
            log(f"  {line.strip()}")
    log("  Installed: 15.4(3)M5 (from Nessus output)")
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ssh-excpt-dos-FzOBQTnk")

def audit_ssh_config(connection):
    log("── STEP 3: SSH Configuration Audit ──")

    # SSH global config
    ssh_cfg = connection.send_command("show running-config | include ip ssh")
    log("  SSH configuration lines:")
    log(ssh_cfg if ssh_cfg.strip() else "  No 'ip ssh' config lines found.")

    # SSH version
    if "ip ssh version 2" in ssh_cfg:
        log("  ✅ SSHv2 only — good.")
    elif "ip ssh version 1" in ssh_cfg:
        log("  ❌ SSHv1 configured — upgrade to version 2 immediately.")
    else:
        log("  ⚠️  No explicit SSH version set — both v1 and v2 may be accepted.")
        log("  Apply: 'ip ssh version 2'")

    # SSH timeout
    timeout_val = None
    for line in ssh_cfg.splitlines():
        if "ip ssh time-out" in line:
            parts = line.split()
            if parts:
                timeout_val = parts[-1]
                if int(timeout_val) > 60:
                    log(f"  ⚠️  SSH timeout is {timeout_val}s — reduce to 60 or less.")
                else:
                    log(f"  ✅ SSH timeout: {timeout_val}s — acceptable.")

    if not timeout_val:
        log("  ⚠️  No SSH timeout configured — using IOS default (120s).")
        log("  Apply: 'ip ssh time-out 60'")

    # SSH auth retries
    retry_val = None
    for line in ssh_cfg.splitlines():
        if "ip ssh authentication-retries" in line:
            parts = line.split()
            retry_val = parts[-1]
            if int(retry_val) > 3:
                log(f"  ⚠️  SSH auth retries: {retry_val} — reduce to 3 or less.")
            else:
                log(f"  ✅ SSH auth retries: {retry_val} — acceptable.")

    if not retry_val:
        log("  ⚠️  No SSH retry limit set — using IOS default.")
        log("  Apply: 'ip ssh authentication-retries 3'")

    # SSH source interface
    src_intf = connection.send_command(
        "show running-config | include ip ssh source-interface"
    )
    if src_intf.strip():
        log(f"  SSH source interface: {src_intf.strip()}")

    return ssh_cfg

def audit_vty_config(connection):
    log("── STEP 4: VTY Line Configuration Audit ──")

    # VTY config
    vty_cfg = connection.send_command("show running-config | section line vty")
    log("  VTY line configuration:")
    log(vty_cfg if vty_cfg.strip() else "  No VTY config found.")

    # Check for transport input ssh
    if "transport input ssh" in vty_cfg:
        log("  ✅ VTY transport restricted to SSH only.")
    elif "transport input all" in vty_cfg or "transport input telnet" in vty_cfg:
        log("  ⚠️  VTY allows Telnet — restrict to SSH only: 'transport input ssh'")
    else:
        log("  ⚠️  VTY transport not explicitly configured.")

    # Check for access-class
    if "access-class" in vty_cfg:
        log("  ✅ VTY has access-class (ACL) configured.")
        for line in vty_cfg.splitlines():
            if "access-class" in line:
                log(f"    {line.strip()}")
    else:
        log("  ⚠️  NO VTY access-class — SSH accessible from any source.")
        log("  Apply: 'access-class <ACL> in' under line vty 0 4")

    # Check exec-timeout
    if "exec-timeout" in vty_cfg:
        for line in vty_cfg.splitlines():
            if "exec-timeout" in line:
                log(f"  VTY exec-timeout: {line.strip()}")
    else:
        log("  ⚠️  No VTY exec-timeout — idle sessions never time out.")
        log("  Apply: 'exec-timeout 10 0' under line vty 0 4")

    # Login local or AAA
    if "login local" in vty_cfg:
        log("  ✅ VTY using local authentication ('login local').")
    elif "login authentication" in vty_cfg:
        log("  ✅ VTY using AAA authentication.")
    else:
        log("  ⚠️  VTY authentication method unclear — verify login config.")

def apply_ssh_hardening(connection):
    log("── STEP 5: Applying SSH Hardening (APPLY_SSH_HARDENING=True) ──")
    log("  ⚠️  CRITICAL: Verify SSH_ALLOWED_HOSTS before proceeding.")
    log(f"  Management hosts to be permitted: {SSH_ALLOWED_HOSTS}")

    commands = []

    # Step 5a: Create ACL for SSH
    log("  Creating VTY access ACL...")
    commands.append(f"no access-list {SSH_ACL_NUMBER}")
    for host in SSH_ALLOWED_HOSTS:
        commands.append(f"access-list {SSH_ACL_NUMBER} permit {host}")
        log(f"  Permitting management host: {host}")
    commands.append(f"access-list {SSH_ACL_NUMBER} deny any log")

    # Step 5b: SSH global hardening
    log("  Enforcing SSHv2 only...")
    commands.append("ip ssh version 2")
    log("  Setting SSH timeout to 60s...")
    commands.append("ip ssh time-out 60")
    log("  Setting SSH auth retries to 3...")
    commands.append("ip ssh authentication-retries 3")

    # Step 5c: VTY hardening
    log("  Applying VTY hardening...")
    commands.extend([
        "line vty 0 4",
        f"access-class {SSH_ACL_NUMBER} in",
        "transport input ssh",
        "exec-timeout 10 0",
        "exit",
        "line vty 5 15",
        f"access-class {SSH_ACL_NUMBER} in",
        "transport input ssh",
        "exec-timeout 10 0",
        "exit",
    ])

    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ SSH hardening applied.")
    log("  SSHv2 only | Timeout 60s | Retries 3 | VTY ACL restricted.")
    log("  CVE-2022-20920 attack surface significantly reduced.")
    log("  ⚠️  Immediately verify SSH access from authorized hosts.")
    log("  ⚠️  Console access is the fallback if SSH lockout occurs.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 165676 - CVE-2022-20920 - Cisco IOS SSH DoS")
    log("")
    log("Attack requirements:")
    log("  1. Valid SSH credentials (authenticated attacker)")
    log("  2. Network access to SSH port (TCP/22)")
    log("  3. Continuously send specific SSH requests")
    log("  → VTY ACL restriction is highly effective mitigation")
    log("")
    log("SSH hardening checklist:")
    log("  ✅ SSHv2 only: 'ip ssh version 2'")
    log("  ✅ Timeout: 'ip ssh time-out 60'")
    log("  ✅ Retries: 'ip ssh authentication-retries 3'")
    log("  ✅ VTY ACL: 'access-class <ACL> in' on all VTY lines")
    log("  ✅ Transport: 'transport input ssh' (disable Telnet)")
    log("  ✅ Exec timeout: 'exec-timeout 10 0'")
    log("")
    log("⚠️  NEVER disable SSH — it is the primary management protocol.")
    log("   Disabling SSH leaves only console/Telnet for management.")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvx63027")
    log("Installed: 15.4(3)M5")
    log("")
    log("Upgrade steps (manual):")
    log("  1. Download fixed IOS image from Cisco.com")
    log("  2. Transfer: 'copy tftp: flash:' or 'copy scp: flash:'")
    log("  3. Verify: 'verify /md5 flash:<image>'")
    log("  4. Set boot: 'boot system flash:<image>'")
    log("  5. Save: 'write memory'")
    log("  6. Reload: 'reload'")
    log("  7. Confirm: 'show version' + 'show ip ssh'")
    log("  8. Re-scan Nessus with valid credentials")

def main():
    log("="*65)
    log("Fix Script - Plugin 165676 - Cisco IOS SSH DoS")
    log("CVE-2022-20920 | CSCvx63027 | Authenticated Attack")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        audit_ssh_config(connection)
        audit_vty_config(connection)

        if APPLY_SSH_HARDENING:
            log("⚠️  APPLYING SSH HARDENING — ensure SSH_ALLOWED_HOSTS is correct.")
            apply_ssh_hardening(connection)
        else:
            log("── STEP 5: Skipped (APPLY_SSH_HARDENING=False) ──")
            log("   Configure SSH_ALLOWED_HOSTS with management IPs.")
            log("   Set APPLY_SSH_HARDENING=True to apply.")
            log("   ⚠️  Always verify console access before restricting SSH.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()