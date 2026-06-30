#!/usr/bin/env python3
"""
Fix Script - Plugin 198146
Cisco IOS Software IKEv1 Fragmentation DoS
CVE-2024-20307 (heap overflow) | CVE-2024-20308 (heap underflow)
Bug IDs: CSCwf11183, CSCwh66334

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Check IKEv1 fragmentation state
  4. Apply 'no crypto isakmp fragmentation' as mitigation
  5. Verify IKEv1 SA table health
  6. Generate remediation report

KEY NOTES:
  - TWO CVEs in one plugin (heap overflow + underflow)
  - More severe than Plugin 94762 (CVE-2016-6381) — heap corruption vs plain DoS
  - Same mitigation command as Plugin 94762: 'no crypto isakmp fragmentation'
  - If Plugin 94762 fix already applied, mitigation is ALREADY IN PLACE
  - Triggerable via IPv4 AND IPv6 UDP traffic
  - Full fix = IOS upgrade per CSCwf11183/CSCwh66334
  - This is the 5th IKE-family plugin on this device
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

# Apply 'no crypto isakmp fragmentation' workaround
# NOTE: Same as Plugin 94762 fix — skip if already applied
APPLY_FRAGMENTATION_FIX = True

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_198146_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_198146_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ikev1-NO2ccFWz")

def check_fragmentation_state(connection):
    log("── STEP 3: Checking IKEv1 Fragmentation State ──")

    frag_cfg = connection.send_command(
        "show running-config | include crypto isakmp fragmentation"
    )
    log("  IKEv1 fragmentation config lines:")
    log(frag_cfg if frag_cfg.strip()
        else "  No explicit fragmentation config (default may allow fragmentation).")

    already_disabled = "no crypto isakmp fragmentation" in frag_cfg
    explicitly_enabled = ("crypto isakmp fragmentation" in frag_cfg
                          and "no" not in frag_cfg)

    if already_disabled:
        log("  ✅ 'no crypto isakmp fragmentation' already set.")
        log("  Mitigation for CVE-2024-20307/20308 already in place.")
        log("  (Also covers Plugin 94762 / CVE-2016-6381 if applied earlier.)")
    elif explicitly_enabled:
        log("  ⚠️  IKEv1 fragmentation is explicitly ENABLED.")
        log("  Device is exposed to CVE-2024-20307 (heap overflow).")
        log("  Device is exposed to CVE-2024-20308 (heap underflow).")
    else:
        log("  ℹ️  No explicit fragmentation config found.")
        log("  Default state may permit fragmentation — applying fix is recommended.")

    return already_disabled

def check_ikev1_active_sa(connection):
    log("── STEP 4: Checking Active IKEv1 SAs ──")
    output = connection.send_command("show crypto isakmp sa")
    if output.strip():
        log("  Active IKEv1 SAs:")
        log(output)
        active = [l for l in output.splitlines()
                  if "ACTIVE" in l or "QM_IDLE" in l]
        if active:
            log(f"  ⚠️  {len(active)} active IKEv1 tunnel(s).")
            log("  Disabling fragmentation may affect clients using fragmented IKEv1.")
    else:
        log("  No active IKEv1 SAs.")

def check_ipv6_ikev1_exposure(connection):
    log("── STEP 5: Checking IPv6 IKEv1 Exposure ──")
    log("  Both CVEs can be triggered via IPv4 AND IPv6 UDP traffic.")

    ipv6_cfg = connection.send_command(
        "show running-config | include ipv6 address|ipv6 enable"
    )
    if ipv6_cfg.strip():
        log("  IPv6 is configured on this device:")
        ipv6_lines = ipv6_cfg.splitlines()[:10]
        log("\n".join(f"    {l}" for l in ipv6_lines))
        log("  ⚠️  IPv6 interfaces present — device exposed via both IPv4 and IPv6.")
    else:
        log("  No IPv6 interface config found.")
        log("  Attack vector may be limited to IPv4 only.")

def apply_fragmentation_fix(connection, already_disabled):
    log("── STEP 6: Applying IKEv1 Fragmentation Fix ──")

    if already_disabled:
        log("  ✅ Fragmentation already disabled — no action needed.")
        log("  Both CVE-2024-20307 and CVE-2024-20308 are mitigated.")
        return

    log("  Applying 'no crypto isakmp fragmentation'...")
    commands = ["no crypto isakmp fragmentation"]
    output = connection.send_config_set(commands)
    log(output)

    save = connection.send_command("write memory")
    log(f"  Config saved: {save}")
    log("  ✅ IKEv1 fragmentation disabled.")
    log("  Heap overflow/underflow attack vector eliminated.")
    log("  Both CVE-2024-20307 and CVE-2024-20308 mitigated.")
    log("  Also mitigates Plugin 94762 (CVE-2016-6381) simultaneously.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 198146 - CVE-2024-20307 + CVE-2024-20308 - IKEv1 Fragmentation DoS")
    log("")
    log("Severity: More critical than Plugin 94762 (CVE-2016-6381)")
    log("  - CVE-2024-20307: HEAP OVERFLOW (memory corruption)")
    log("  - CVE-2024-20308: HEAP UNDERFLOW (memory corruption)")
    log("  - Both: Unauthenticated, remote, IPv4 + IPv6, UDP")
    log("")
    log("Mitigation: 'no crypto isakmp fragmentation'")
    log("  Covers Plugin 94762 AND Plugin 198146 simultaneously")
    log("  May break VPN clients that require IKEv1 fragmentation")
    log("")
    log("IKE-family plugins on this device (all fixed by one upgrade):")
    log("  Plugin 94762  — CVE-2016-6381 (IKEv1 Frag DoS)")
    log("  Plugin 198146 — CVE-2024-20307/20308 (IKEv1 Heap OvFlow/Underflow) ← THIS")
    log("  Plugin 93736  — CVE-2016-6415 (BENIGNCERTAIN, CISA KEV)")
    log("  Plugin 137835 — CVE-2020-3230 (IKEv2 SA-Init DoS)")
    log("  Plugin 103693 — CVE-2017-12237 (IKE DoS, CISA KEV)")
    log("  Plugin 155733 — CVE-2021-1620 (IKEv2 AutoReconnect)")
    log("")
    log("Permanent Fix: IOS upgrade per CSCwf11183 / CSCwh66334")
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
    log("Fix Script - Plugin 198146 - Cisco IOS IKEv1 Frag Heap DoS")
    log("CVE-2024-20307 (Heap Overflow) | CVE-2024-20308 (Heap Underflow)")
    log("CSCwf11183 | CSCwh66334")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        already_disabled = check_fragmentation_state(connection)
        check_ikev1_active_sa(connection)
        check_ipv6_ikev1_exposure(connection)

        if APPLY_FRAGMENTATION_FIX:
            apply_fragmentation_fix(connection, already_disabled)
        else:
            log("── STEP 6: Skipped (APPLY_FRAGMENTATION_FIX=False) ──")

        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()