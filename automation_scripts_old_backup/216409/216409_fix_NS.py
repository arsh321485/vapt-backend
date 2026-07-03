#!/usr/bin/env python3
"""
Fix Script - Plugin 216409
Cisco IOS Software IS-IS DoS
CVE-2024-20312 | Bug ID: CSCwf54007

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check IS-IS configuration and process state
  4. Enumerate IS-IS neighbors/adjacencies
  5. Check IS-IS route table contribution
  6. Optionally disable IS-IS if unused
  7. Generate remediation report

KEY NOTES:
  - Attack vector: ADJACENT (AV:A)
  - Attacker must ALSO have formed an IS-IS adjacency
  - Extremely constrained — lowest practical risk on this device
  - IS-IS is a routing protocol — disabling it removes routes
  - Full fix = IOS upgrade per CSCwf54007
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

# Set True ONLY if IS-IS is confirmed NOT used for routing
# This will remove the IS-IS process entirely
# WARNING: Will drop all IS-IS-learned routes — verify alternative routing exists
DISABLE_ISIS = False

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_216409_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_216409_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-isis-sGjyOUHX")

def check_isis_config(connection):
    log("── STEP 3: Checking IS-IS Configuration ──")

    # IS-IS process config
    isis_cfg = connection.send_command("show running-config | section router isis")
    if isis_cfg.strip():
        log("  IS-IS process configured:")
        log(isis_cfg)
        log("  ⚠️  IS-IS is configured — CVE-2024-20312 may be applicable.")
    else:
        log("  ✅ No 'router isis' section found in config.")
        log("  IS-IS not configured — CVE-2024-20312 not applicable.")

    # IS-IS interface config
    isis_iface = connection.send_command(
        "show running-config | include ip router isis|ipv6 router isis|isis"
    )
    if isis_iface.strip():
        log("  IS-IS interface/route config lines:")
        log(isis_iface)
    else:
        log("  No IS-IS interface config lines found.")

    isis_configured = bool(isis_cfg.strip())
    return isis_configured

def check_isis_process(connection):
    log("── STEP 4: IS-IS Process State ──")

    # IS-IS summary
    isis_summary = connection.send_command("show isis summary")
    if isis_summary.strip() and "Invalid" not in isis_summary:
        log("  IS-IS summary:")
        log(isis_summary)
    else:
        log("  No IS-IS summary available (process may not be running).")

    # IS-IS database
    isis_db = connection.send_command("show isis database")
    if isis_db.strip() and "ISIS" in isis_db:
        log("  IS-IS LSDB (link-state database) — IS-IS is active:")
        lines = isis_db.splitlines()[:20]
        log("\n".join(lines))
        if len(isis_db.splitlines()) > 20:
            log(f"  ... ({len(isis_db.splitlines())} total LSP entries)")
    else:
        log("  ✅ No IS-IS database entries — IS-IS not actively running.")

def check_isis_neighbors(connection):
    log("── STEP 5: IS-IS Neighbor Adjacencies ──")
    neighbors = connection.send_command("show isis neighbors")

    if neighbors.strip() and "no neighbors" not in neighbors.lower():
        log("  ⚠️  Active IS-IS neighbors found:")
        log(neighbors)
        log("  CVE-2024-20312 is exploitable by any of these neighbors.")
        log("  Adjacency + L2 access = attack conditions met.")

        # Count adjacencies
        adj_count = sum(1 for line in neighbors.splitlines()
                        if "UP" in line or "Init" in line)
        log(f"  Active adjacency count: {adj_count}")
    else:
        log("  ✅ No active IS-IS neighbors.")
        log("  Without adjacency, CVE-2024-20312 cannot be exploited.")

    return bool(neighbors.strip() and "no neighbors" not in neighbors.lower())

def check_isis_routes(connection):
    log("── STEP 6: IS-IS Route Contribution ──")

    # Routes learned via IS-IS
    isis_routes = connection.send_command("show ip route isis | count")
    log(f"  IPv4 IS-IS routes: {isis_routes.strip()}")

    isis_routes_v6 = connection.send_command("show ipv6 route isis | count")
    log(f"  IPv6 IS-IS routes: {isis_routes_v6.strip()}")

    if "0" not in isis_routes and isis_routes.strip():
        log("  ⚠️  IS-IS is contributing routes to the routing table.")
        log("  Disabling IS-IS will drop these routes — verify alternative routing first.")
    else:
        log("  ✅ No IS-IS routes in table — safe to consider disabling IS-IS.")

def get_isis_process_tags(connection):
    """Parse IS-IS process tag names from config"""
    output = connection.send_command("show running-config | include ^router isis")
    tags = []
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            tags.append(parts[2])  # 'router isis <tag>'
        elif len(parts) == 2:
            tags.append("")  # 'router isis' (no tag)
    return tags if tags else [""]

def disable_isis(connection):
    log("── STEP 7: Disabling IS-IS (DISABLE_ISIS=True) ──")
    log("  ⚠️  WARNING: This will remove IS-IS routing process and drop all IS-IS routes.")

    tags = get_isis_process_tags(connection)
    commands = []

    for tag in tags:
        if tag:
            cmd = f"no router isis {tag}"
        else:
            cmd = "no router isis"
        log(f"  Queuing: {cmd}")
        commands.append(cmd)

    if commands:
        output = connection.send_config_set(commands)
        log(output)
        save = connection.send_command("write memory")
        log(f"  Config saved: {save}")
        log("  ✅ IS-IS process removed.")
        log("  CVE-2024-20312 attack surface eliminated.")
        log("  ⚠️  Verify routing table is intact via alternative protocols.")
    else:
        log("  No IS-IS process tags found to remove.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 216409 - CVE-2024-20312 - Cisco IOS IS-IS DoS")
    log("")
    log("Attack constraints (both required):")
    log("  1. Attacker must be Layer 2 ADJACENT to the device")
    log("  2. Attacker must have FORMED an IS-IS adjacency")
    log("  → Lowest practical exploitability of all plugins on this device")
    log("")
    log("Mitigation: 'no router isis' if IS-IS is not in use")
    log("  WARNING: Removes all IS-IS routes — verify alternative routing")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCwf54007")
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
    log("Fix Script - Plugin 216409 - Cisco IOS IS-IS DoS")
    log("CVE-2024-20312 | CSCwf54007 | Attack Vector: Adjacent + Adjacency")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        isis_configured = check_isis_config(connection)
        check_isis_process(connection)
        neighbors_active = check_isis_neighbors(connection)
        check_isis_routes(connection)

        if DISABLE_ISIS:
            if not isis_configured:
                log("── STEP 7: IS-IS not configured — nothing to disable. ──")
            else:
                disable_isis(connection)
        else:
            log("── STEP 7: Skipped (DISABLE_ISIS=False) ──")
            log("   Set DISABLE_ISIS=True only if IS-IS is confirmed unused.")
            log("   Verify routing table impact before proceeding.")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()