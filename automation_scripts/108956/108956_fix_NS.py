#!/usr/bin/env python3
"""
Fix Script - Plugin 108956
Cisco IOS Software DNS Forwarder DoS
CVE-2016-6380 | Bug ID: CSCup90532

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check DNS forwarder state (ip dns server / ip name-server)
  4. Check active DNS traffic/config
  5. Optionally disable DNS forwarder with 'no ip dns server'
  6. Generate remediation report

KEY POINT: Disabling DNS forwarder is a strong mitigation
           but will break DNS for any clients using this router.
           Confirm no dependency before applying.
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

# Set True ONLY if DNS forwarder is confirmed NOT serving any clients
# Applies 'no ip dns server' to fully disable DNS forwarding
DISABLE_DNS_FORWARDER = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_108956_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_108956_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-dns")

def check_dns_state(connection):
    log("── STEP 3: Checking DNS Forwarder State ──")

    # Check dns server config
    dns_cfg = connection.send_command("show running-config | include ip dns|ip name-server")
    log("  DNS-related config lines:")
    log(dns_cfg if dns_cfg.strip() else "  No DNS server/name-server config found.")

    # Full DNS section
    dns_section = connection.send_command("show running-config | section ip dns")
    if dns_section.strip():
        log("  Full DNS config section:")
        log(dns_section)

    # Check if dns server is enabled
    dns_server_enabled = "ip dns server" in dns_cfg and "no ip dns server" not in dns_cfg

    if dns_server_enabled:
        log("  ⚠️  'ip dns server' is ENABLED — DNS forwarder is active.")
        log("  CVE-2016-6380 attack surface CONFIRMED on this device.")
    else:
        log("  ✅ 'ip dns server' does NOT appear to be enabled.")
        log("  Device may not be acting as a DNS forwarder.")

    # Name servers configured
    if "ip name-server" in dns_cfg:
        log("  ℹ️  'ip name-server' entries configured (upstream DNS resolvers).")
        log("  These alone don't enable DNS forwarding — 'ip dns server' is required.")

    return dns_server_enabled

def check_dns_traffic(connection):
    log("── STEP 4: Checking DNS Activity ──")

    # DNS view/hosts
    dns_hosts = connection.send_command("show ip dns view")
    if dns_hosts.strip():
        log("  DNS view config:")
        log(dns_hosts)
    else:
        log("  No DNS view configured.")

    # Check hosts table
    host_table = connection.send_command("show hosts")
    if host_table.strip():
        log("  Host table entries (indicates DNS in use):")
        # Show first 20 lines only
        lines = host_table.splitlines()[:20]
        log("\n".join(lines))
        if len(host_table.splitlines()) > 20:
            log(f"  ... ({len(host_table.splitlines())} total entries)")
    else:
        log("  No host table entries found.")

def disable_dns_forwarder(connection):
    log("── STEP 5: Disabling DNS Forwarder (DISABLE_DNS_FORWARDER=True) ──")
    log("  Applying 'no ip dns server'...")

    commands = ["no ip dns server"]
    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ DNS forwarder disabled.")
    log("  Device will no longer process DNS queries — CVE-2016-6380 attack surface eliminated.")
    log("  ⚠️  Verify no client DNS resolution failures after this change.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 108956 - CVE-2016-6380 - Cisco IOS DNS Forwarder DoS")
    log("")
    log("Mitigation: 'no ip dns server' — disable DNS forwarding if unused")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCup90532")
    log("")
    log("Impact assessment before disabling DNS:")
    log("  - Identify all clients using this router for DNS")
    log("  - Redirect them to a dedicated DNS server before disabling")
    log("  - Common in branch/SMB deployments where router = DNS forwarder")
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
    log("Fix Script - Plugin 108956 - Cisco IOS DNS Forwarder DoS")
    log("CVE-2016-6380 | CSCup90532")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        dns_enabled = check_dns_state(connection)
        check_dns_traffic(connection)

        if DISABLE_DNS_FORWARDER:
            if dns_enabled:
                disable_dns_forwarder(connection)
            else:
                log("── STEP 5: DNS forwarder not enabled — no action needed. ──")
        else:
            log("── STEP 5: Skipped (DISABLE_DNS_FORWARDER=False) ──")
            log("   Set DISABLE_DNS_FORWARDER=True if DNS forwarding is confirmed unused.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()