#!/usr/bin/env python3
"""
Fix Script - Plugin 141170
Cisco IOS Software Split DNS DoS
CVE-2020-3408 | Bug ID: CSCvt78186

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check Split DNS configuration state
  4. Enumerate DNS name lists and regex patterns
  5. Optionally remove Split DNS config
  6. Generate remediation report

KEY NOTES:
  - Split DNS is NOT enabled by default
  - Only vulnerable when DNS name lists with REGEX patterns are configured
  - Attack: regex engine timeout → device reload (unauthenticated)
  - CVSS 8.6 — tied with Plugin 130092 for second-highest on device
  - CVSS C:C — Confidentiality impact alongside Availability
  - Uncommon on standard enterprise branch routers
  - Common in: enterprise split-horizon DNS environments
  - Full fix = IOS upgrade per CSCvt78186
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

# Set True ONLY if Split DNS is confirmed not required
# WARNING: Removes DNS name lists and Split DNS view config
DISABLE_SPLIT_DNS = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_141170_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_141170_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-splitdns-SPWqpdGW")

def check_split_dns_config(connection):
    log("── STEP 3: Checking Split DNS Configuration ──")

    # DNS view config (Split DNS uses views)
    dns_view = connection.send_command("show running-config | section ip dns view")
    if dns_view.strip():
        log("  DNS view configuration found:")
        log(dns_view)
        log("  ⚠️  Split DNS is configured — CVE-2020-3408 may be applicable.")
    else:
        log("  No 'ip dns view' section found.")

    # DNS name lists (the key component with regex)
    dns_namelist = connection.send_command(
        "show running-config | section ip dns name-list"
    )
    if dns_namelist.strip():
        log("  DNS name list configuration:")
        log(dns_namelist)
        log("  ⚠️  DNS name lists found — check for regex patterns.")
    else:
        log("  No DNS name lists configured.")

    # Look for regex patterns specifically
    dns_cfg_all = connection.send_command(
        "show running-config | include ip dns name-list|ip dns view|permit|deny"
    )
    regex_indicators = []
    for line in dns_cfg_all.splitlines():
        # Regex typically contains: ., *, +, ?, \, ^, $, [], ()
        if any(ch in line for ch in ["\\.", "\\*", ".*", "^", "\\w", "\\d", "[", "("]):
            regex_indicators.append(line.strip())
            log(f"  ⚠️  Possible regex pattern: {line.strip()}")

    if regex_indicators:
        log(f"  ❌ {len(regex_indicators)} regex pattern(s) found in DNS name lists.")
        log("  These patterns can trigger the CVE-2020-3408 regex timeout.")
    else:
        log("  ✅ No obvious regex patterns detected in DNS name lists.")
        log("  Simple string-match name lists may not trigger the vulnerability.")

    # DNS view list assignment
    view_list = connection.send_command(
        "show running-config | include ip dns view-list"
    )
    if view_list.strip():
        log("  DNS view-list (Split DNS active):")
        log(view_list)

    # Check if split DNS is actually active
    split_dns_active = bool(dns_view.strip() or dns_namelist.strip())
    if not split_dns_active:
        log("  ✅ Split DNS does not appear to be configured.")
        log("  Mark Plugin 141170 as 'Not Applicable' after verification.")

    return split_dns_active, regex_indicators

def check_dns_server_config(connection):
    log("── STEP 4: DNS Server and Forwarder Context ──")
    log("  Note: Plugin 108956 covers DNS Forwarder DoS (separate vulnerability).")
    log("  This plugin specifically targets Split DNS with name list regex.")

    # DNS server status
    dns_cfg = connection.send_command("show running-config | include ip dns server")
    if "ip dns server" in dns_cfg and "no ip dns server" not in dns_cfg:
        log("  ⚠️  DNS server is active (see also Plugin 108956).")
        log("  Split DNS uses DNS server + view config.")
    else:
        log("  ✅ DNS server not explicitly enabled.")
        log("  Split DNS requires 'ip dns server' — may not be active.")

    # DNS view runtime
    dns_view_runtime = connection.send_command("show ip dns view")
    if dns_view_runtime.strip() and "%" not in dns_view_runtime:
        log("  DNS view runtime status:")
        log(dns_view_runtime[:400] if len(dns_view_runtime) > 400
            else dns_view_runtime)
    else:
        log("  No DNS view runtime output.")

def disable_split_dns(connection):
    log("── STEP 5: Disabling Split DNS (DISABLE_SPLIT_DNS=True) ──")
    log("  ⚠️  This removes DNS name lists and view configuration.")

    # Get name list names
    namelist_cfg = connection.send_command(
        "show running-config | include ip dns name-list"
    )
    commands = []
    for line in namelist_cfg.splitlines():
        parts = line.strip().split()
        if "ip" in parts and "dns" in parts and "name-list" in parts:
            # Format: ip dns name-list <number> ...
            idx = parts.index("name-list")
            if idx + 1 < len(parts):
                list_num = parts[idx + 1]
                commands.append(f"no ip dns name-list {list_num}")
                log(f"  Removing DNS name-list: {list_num}")

    # Remove DNS views
    view_cfg = connection.send_command("show running-config | section ip dns view")
    for line in view_cfg.splitlines():
        if line.strip().startswith("ip dns view ") and "list" not in line:
            view_name = line.strip().split("ip dns view ")[-1].strip()
            commands.append(f"no ip dns view {view_name}")
            log(f"  Removing DNS view: {view_name}")

    # Remove view-list
    viewlist_cfg = connection.send_command(
        "show running-config | include ip dns view-list"
    )
    for line in viewlist_cfg.splitlines():
        if "ip dns view-list" in line:
            list_name = line.strip().split("ip dns view-list")[-1].strip()
            commands.append(f"no ip dns view-list {list_name}")
            log(f"  Removing DNS view-list: {list_name}")

    if commands:
        output = connection.send_config_set(commands)
        log(output)
        save = connection.send_command("write memory")
        log(f"  Config saved: {save}")
        log("  ✅ Split DNS configuration removed.")
        log("  CVE-2020-3408 regex timeout attack surface eliminated.")
        log("  ⚠️  Verify DNS resolution for all clients still working.")
    else:
        log("  No Split DNS config found to remove.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 141170 - CVE-2020-3408 - Cisco IOS Split DNS DoS")
    log("")
    log("Key facts:")
    log("  - CVSS 8.6 — tied for second-highest on this device")
    log("  - CVSS C:C — Confidentiality impact alongside Availability")
    log("  - Unauthenticated remote attacker — no credentials needed")
    log("  - Split DNS NOT default — verify if actually deployed")
    log("  - Only vulnerable when regex-based DNS name lists are used")
    log("  - Attack: crafted DNS query triggers regex engine timeout → reload")
    log("")
    log("Conditions for exposure (ALL must be true):")
    log("  1. 'ip dns server' is enabled")
    log("  2. DNS name lists are configured with regex patterns")
    log("  3. DNS views are assigned via view-list")
    log("  If any condition is absent: device may not be exposed.")
    log("")
    log("Mitigation options:")
    log("  1. Remove regex patterns from DNS name lists (use exact match instead)")
    log("  2. Disable Split DNS entirely if not required ('no ip dns view')")
    log("  3. Disable DNS server if not needed ('no ip dns server')")
    log("     Note: 'no ip dns server' also mitigates Plugin 108956")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvt78186")
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
    log("Fix Script - Plugin 141170 - Cisco IOS Split DNS DoS")
    log("CVE-2020-3408 | CSCvt78186 | CVSS 8.6")
    log("Split DNS not default — verify if actually configured")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        split_dns_active, regex_patterns = check_split_dns_config(connection)
        check_dns_server_config(connection)

        if DISABLE_SPLIT_DNS:
            if not split_dns_active:
                log("── STEP 5: Split DNS not configured — nothing to disable. ──")
                log("   Mark as 'Not Applicable' if confirmed.")
            else:
                disable_split_dns(connection)
        else:
            log("── STEP 5: Skipped (DISABLE_SPLIT_DNS=False) ──")
            if split_dns_active and regex_patterns:
                log("   ⚠️  Split DNS WITH regex patterns confirmed — mitigate immediately.")
                log("   Set DISABLE_SPLIT_DNS=True if Split DNS is not required.")
            elif split_dns_active:
                log("   Split DNS configured but no regex patterns detected.")
                log("   May not be vulnerable — verify with Cisco advisory.")
            else:
                log("   Split DNS not detected — may be Not Applicable.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()