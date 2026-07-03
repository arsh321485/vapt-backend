#!/usr/bin/env python3
"""
Fix Script - Plugin 103669
Cisco IOS Software NAT DoS Vulnerability
CVE-2017-12231 | Bug ID: CSCvc57217
CISA Known Exploited Vulnerability — Listed 2022/03/24

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check NAT configuration state
  4. Check active NAT translations
  5. Enumerate NAT rules (static/dynamic/overload)
  6. Optionally disable NAT (remove rules + ip nat inside/outside)
  7. Generate remediation report

KEY NOTES:
  - CISA KEV #5 on this device — actively exploited
  - EPSS 0.1085 — highest on device (tied with Plugin 131166)
  - Attack causes device to STOP PROCESSING TRAFFIC (not just reload)
  - Requires device restart to recover — more severe than simple reload
  - NAT is VERY COMMON on internet-facing IOS routers (PAT/overload)
  - Disabling NAT breaks internet for hosts behind the router
  - Full fix = IOS upgrade per CSCvc57217
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

# Set True ONLY if NAT is confirmed NOT used for any traffic
# WARNING: Removing NAT breaks internet for any hosts using NAT/PAT
DISABLE_NAT = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_103669_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_103669_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-nat")
    log("  CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

def check_nat_config(connection):
    log("── STEP 3: Checking NAT Configuration ──")

    # NAT in running config
    nat_cfg = connection.send_command("show running-config | include ip nat")
    log("  NAT config lines:")
    log(nat_cfg if nat_cfg.strip() else "  No 'ip nat' config lines found.")

    nat_configured = bool(nat_cfg.strip())

    if nat_configured:
        log("  ⚠️  NAT is configured on this device.")
        log("  CVE-2017-12231 attack surface CONFIRMED.")

        # Detect NAT types
        if "ip nat inside source list" in nat_cfg or "ip nat inside source static" in nat_cfg:
            log("  NAT type: Inside source NAT/PAT detected.")
        if "ip nat outside source" in nat_cfg:
            log("  NAT type: Outside source NAT detected.")
        if "overload" in nat_cfg:
            log("  PAT (NAT overload) detected — likely providing internet access.")
            log("  ⚠️  HIGH IMPACT: Disabling NAT will break internet for internal hosts.")
    else:
        log("  ✅ No NAT config found.")
        log("  Device may not be exposed to CVE-2017-12231.")

    # NAT pool config
    nat_pool = connection.send_command("show running-config | include ip nat pool")
    if nat_pool.strip():
        log("  NAT pools configured:")
        log(nat_pool)

    # NAT interfaces
    nat_ifaces = connection.send_command(
        "show running-config | include ip nat inside|ip nat outside"
    )
    if nat_ifaces.strip():
        log("  NAT interface assignments:")
        log(nat_ifaces)

    return nat_configured

def check_nat_translations(connection):
    log("── STEP 4: Active NAT Translations ──")

    # Translation table
    trans = connection.send_command("show ip nat translations total")
    log("  NAT translation count:")
    log(trans if trans.strip() else "  No NAT translation count output.")

    # Sample translations
    trans_sample = connection.send_command("show ip nat translations | head 20")
    if trans_sample.strip():
        log("  Sample NAT translations (first 20):")
        log(trans_sample)
        log("  ⚠️  Active NAT translations — users/hosts are actively using NAT.")
    else:
        log("  No active NAT translations in table.")

    # NAT statistics
    nat_stats = connection.send_command("show ip nat statistics")
    if nat_stats.strip():
        log("  NAT statistics:")
        log(nat_stats[:500] if len(nat_stats) > 500 else nat_stats)

        # Check for hits (active usage)
        for line in nat_stats.splitlines():
            if "hits" in line.lower() or "misses" in line.lower():
                log(f"  Traffic indicator: {line.strip()}")

def check_nat_acls(connection):
    log("── STEP 5: NAT ACL References ──")

    # Find ACLs referenced in NAT rules
    nat_cfg = connection.send_command("show running-config | include ip nat inside source list")
    acl_nums = []
    for line in nat_cfg.splitlines():
        parts = line.split()
        if "list" in parts:
            idx = parts.index("list")
            if idx + 1 < len(parts):
                acl_nums.append(parts[idx + 1])

    if acl_nums:
        log(f"  NAT references ACLs: {acl_nums}")
        for acl in acl_nums:
            acl_output = connection.send_command(f"show ip access-list {acl}")
            log(f"  ACL {acl} content:")
            log(acl_output[:300] if len(acl_output) > 300 else acl_output)
    else:
        log("  No ACL-referenced NAT rules found.")

def disable_nat(connection):
    log("── STEP 6: Disabling NAT (DISABLE_NAT=True) ──")
    log("  ⚠️  WARNING: This will break internet access for hosts using NAT/PAT.")

    # Step 1: Clear NAT translations first
    log("  Step 6a: Clearing NAT translation table...")
    clear_output = connection.send_command(
        "clear ip nat translation *",
        expect_string=r"#"
    )
    log(f"  Clear output: {clear_output if clear_output.strip() else 'done'}")

    # Step 2: Remove NAT inside/outside from interfaces
    log("  Step 6b: Removing NAT from interfaces...")
    nat_ifaces = connection.send_command(
        "show running-config | include ip nat inside|ip nat outside"
    )
    iface_cmds = []
    current_iface = None

    # Parse interface context from running config
    full_cfg = connection.send_command("show running-config")
    current_iface = None
    for line in full_cfg.splitlines():
        if line.startswith("interface "):
            current_iface = line.strip().split("interface ")[1]
        elif "ip nat inside" in line and current_iface:
            iface_cmds.extend([f"interface {current_iface}", "no ip nat inside"])
        elif "ip nat outside" in line and current_iface:
            iface_cmds.extend([f"interface {current_iface}", "no ip nat outside"])

    if iface_cmds:
        output = connection.send_config_set(iface_cmds)
        log(output)
        log("  NAT inside/outside removed from interfaces.")

    # Step 3: Remove NAT rules
    log("  Step 6c: Removing NAT rules from config...")
    nat_rules = connection.send_command("show running-config | include ip nat")
    remove_cmds = []
    for line in nat_rules.splitlines():
        if line.strip().startswith("ip nat"):
            remove_cmds.append(f"no {line.strip()}")

    if remove_cmds:
        output = connection.send_config_set(remove_cmds)
        log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ NAT configuration removed.")
    log("  CVE-2017-12231 attack surface eliminated.")
    log("  ⚠️  Verify internet connectivity for any hosts that used NAT.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 103669 - CVE-2017-12231 - Cisco IOS NAT DoS")
    log("⚠️  CISA KNOWN EXPLOITED VULNERABILITY — 2022/03/24")
    log("⚠️  EPSS 0.1085 — HIGHEST on device (tied with Plugin 131166)")
    log("")
    log("Unique danger: Attack causes device to STOP PROCESSING ALL TRAFFIC")
    log("  (not just reload) — requires manual device restart to recover")
    log("  This is more disruptive than a standard reload-based DoS.")
    log("")
    log("This is CISA KEV #5 on this device:")
    log("  1. Plugin 93736  — CVE-2016-6415 (BENIGNCERTAIN)")
    log("  2. Plugin 131166 — CVE-2018-0154 (ISM-VPN DoS)")
    log("  3. Plugin 103693 — CVE-2017-12237 (IKE DoS)")
    log("  4. Plugin 108880 — CVE-2018-0167/0175 (LLDP Buffer Overflow)")
    log("  5. Plugin 103669 — CVE-2017-12231 (NAT DoS) ← THIS")
    log("")
    log("Mitigation: Remove NAT config — HIGH IMPACT if PAT in use")
    log("  Assess: Is this router the internet gateway for internal hosts?")
    log("  Alternative: Rate-limit/ACL crafted NAT packets at upstream device")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvc57217")
    log("Installed: 15.4(3)M5")
    log("")
    log("Upgrade steps (manual):")
    log("  1. Download fixed IOS image from Cisco.com")
    log("  2. Transfer: 'copy tftp: flash:' or 'copy scp: flash:'")
    log("  3. Verify: 'verify /md5 flash:<image>'")
    log("  4. Set boot: 'boot system flash:<image>'")
    log("  5. Save: 'write memory'")
    log("  6. Reload: 'reload'")
    log("  7. Confirm: 'show version'")
    log("  8. Re-scan Nessus with valid credentials")

def main():
    log("="*65)
    log("Fix Script - Plugin 103669 - Cisco IOS NAT DoS")
    log("CVE-2017-12231 | CSCvc57217")
    log("CISA KEV #5 | EPSS 0.1085 (HIGHEST) | STOPS ALL TRAFFIC")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        nat_configured = check_nat_config(connection)
        check_nat_translations(connection)
        check_nat_acls(connection)

        if DISABLE_NAT:
            if not nat_configured:
                log("── STEP 6: NAT not configured — nothing to disable. ──")
            else:
                disable_nat(connection)
        else:
            log("── STEP 6: Skipped (DISABLE_NAT=False) ──")
            log("   ⚠️  CISA KEV + EPSS 0.1085 — assess NAT dependency urgently.")
            log("   Set DISABLE_NAT=True only if confirmed no hosts rely on NAT.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()