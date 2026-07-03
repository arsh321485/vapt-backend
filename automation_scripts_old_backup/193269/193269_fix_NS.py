#!/usr/bin/env python3
"""
Fix Script - Plugin 193269
Cisco IOS Software LISP DoS Vulnerability
CVE-2024-20311 | Bug ID: CSCwf36266

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check LISP configuration and process state
  4. Check active LISP sessions/instances
  5. Optionally disable LISP with 'no router lisp'
  6. Generate remediation report

KEY NOTES:
  - LISP is NOT enabled by default on Cisco IOS
  - If never configured, device may not be exposed
  - Common in SD-Access/DNA Center deployments
  - Disabling LISP breaks SD-Access fabric overlays
  - Exploitable via IPv4 AND IPv6
  - Full fix = IOS upgrade per CSCwf36266
  - Plugin note: 'Fixed release: See vendor advisory'
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

# Set True ONLY if LISP is confirmed NOT in use
# Applies 'no router lisp' to disable LISP processing
# WARNING: Breaks SD-Access fabric if LISP is in use
DISABLE_LISP = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_193269_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_193269_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Note: Plugin output says 'Fixed release: See vendor advisory'")
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-lisp-3gYXs3qP")

def check_lisp_state(connection):
    log("── STEP 3: Checking LISP Configuration State ──")

    # LISP in running config
    lisp_cfg = connection.send_command("show running-config | section router lisp")
    if lisp_cfg.strip():
        log("  LISP process configured:")
        log(lisp_cfg[:600] if len(lisp_cfg) > 600 else lisp_cfg)
        log("  ⚠️  LISP is configured — CVE-2024-20311 attack surface ACTIVE.")
    else:
        log("  ✅ No 'router lisp' section in running config.")
        log("  LISP not configured — CVE-2024-20311 likely not applicable.")

    # LISP interface config
    lisp_iface = connection.send_command(
        "show running-config | include ip lisp|lisp mobility|lisp extended"
    )
    if lisp_iface.strip():
        log("  LISP interface config lines:")
        log(lisp_iface)

    lisp_configured = bool(lisp_cfg.strip())
    return lisp_configured

def check_lisp_process(connection):
    log("── STEP 4: LISP Process Runtime State ──")

    # Show lisp
    lisp_show = connection.send_command("show lisp")
    if lisp_show.strip() and "Invalid" not in lisp_show and "%" not in lisp_show:
        log("  LISP runtime state:")
        log(lisp_show)
        log("  ⚠️  LISP process is running.")
    else:
        log("  ✅ 'show lisp' returned no output — LISP process not running.")

    # LISP site
    lisp_site = connection.send_command("show lisp site")
    if lisp_site.strip() and "%" not in lisp_site:
        log("  LISP sites:")
        log(lisp_site[:400] if len(lisp_site) > 400 else lisp_site)

    # LISP instance
    lisp_instance = connection.send_command("show lisp instance-id 0 summary")
    if lisp_instance.strip() and "%" not in lisp_instance:
        log("  LISP instance summary:")
        log(lisp_instance)

def check_lisp_sessions(connection):
    log("── STEP 5: Active LISP Sessions ──")

    # ETR/ITR map cache
    map_cache = connection.send_command("show lisp map-cache")
    if map_cache.strip() and "%" not in map_cache:
        log("  LISP map cache (active LISP data plane sessions):")
        lines = map_cache.splitlines()[:15]
        log("\n".join(lines))
        log(f"  Map cache has {len(map_cache.splitlines())} entries.")
        log("  ⚠️  LISP is actively forwarding traffic — disable with caution.")
    else:
        log("  No LISP map cache entries — LISP not actively forwarding.")

    # LISP database
    lisp_db = connection.send_command("show lisp database")
    if lisp_db.strip() and "%" not in lisp_db:
        log("  LISP database (local EID prefixes):")
        log(lisp_db[:300] if len(lisp_db) > 300 else lisp_db)

def check_sdaccess_context(connection):
    log("── STEP 5b: SD-Access / DNA Center Context Check ──")

    # VXLAN check (common with SD-Access)
    vxlan = connection.send_command("show running-config | include nve|vxlan|overlay")
    if vxlan.strip():
        log("  ⚠️  NVE/VXLAN/Overlay config found — this may be an SD-Access node.")
        log("  Disabling LISP on SD-Access fabric nodes will break fabric overlay.")
        log(vxlan[:300] if len(vxlan) > 300 else vxlan)
    else:
        log("  No NVE/VXLAN/overlay config — likely not an SD-Access fabric node.")
        log("  ✅ Safe to consider disabling LISP if confirmed unused.")

def get_lisp_process_names(connection):
    """Parse LISP router process names from config"""
    output = connection.send_command("show running-config | include ^router lisp")
    names = []
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            names.append(parts[2])
        elif len(parts) == 2:
            names.append("")
    return names if names else [""]

def disable_lisp(connection):
    log("── STEP 6: Disabling LISP (DISABLE_LISP=True) ──")
    log("  ⚠️  WARNING: Will disrupt SD-Access fabric if LISP is in use.")

    names = get_lisp_process_names(connection)
    commands = []

    for name in names:
        cmd = f"no router lisp {name}".strip()
        log(f"  Queuing: {cmd}")
        commands.append(cmd)

    if commands:
        output = connection.send_config_set(commands)
        log(output)
        save = connection.send_command("write memory")
        log(f"  Config saved: {save}")
        log("  ✅ LISP process removed.")
        log("  CVE-2024-20311 attack surface eliminated.")
        log("  ⚠️  Verify no SD-Access or overlay services were disrupted.")
    else:
        log("  No LISP process found to remove.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 193269 - CVE-2024-20311 - Cisco IOS LISP DoS")
    log("")
    log("Key facts:")
    log("  - LISP NOT enabled by default — verify if actually configured")
    log("  - Exploitable via IPv4 AND IPv6")
    log("  - If not configured: mark as 'Not Applicable' after verification")
    log("  - If configured: disable or upgrade immediately")
    log("")
    log("Mitigation: 'no router lisp' — if LISP confirmed unused")
    log("  Common on: SD-Access fabric nodes, LISP pilot deployments")
    log("  Uncommon on: Branch routers, standard ISR/ASR deployments")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCwf36266")
    log("  Note: Plugin says 'Fixed release: See vendor advisory'")
    log("  Verify specific fixed release at:")
    log("  https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-lisp-3gYXs3qP")
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
    log("Fix Script - Plugin 193269 - Cisco IOS LISP DoS")
    log("CVE-2024-20311 | CSCwf36266")
    log("LISP not default — verify if actually configured first")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        lisp_configured = check_lisp_state(connection)
        check_lisp_process(connection)
        check_lisp_sessions(connection)
        check_sdaccess_context(connection)

        if DISABLE_LISP:
            if not lisp_configured:
                log("── STEP 6: LISP not configured — nothing to disable. ──")
                log("   Device may not be exposed — mark as 'Not Applicable' if confirmed.")
            else:
                disable_lisp(connection)
        else:
            log("── STEP 6: Skipped (DISABLE_LISP=False) ──")
            log("   Set DISABLE_LISP=True if LISP confirmed unused.")
            log("   First verify: is LISP actually configured on this device?")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()