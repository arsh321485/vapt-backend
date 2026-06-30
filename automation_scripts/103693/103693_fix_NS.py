#!/usr/bin/env python3
"""
Fix Script - Plugin 103693
Cisco IOS Software IKE DoS Vulnerability
CVE-2017-12237 | Bug ID: CSCvc41277
CISA Known Exploited Vulnerability — Listed 2022/03/24

Actions:
  1. Backup running config
  2. Collect IOS version
  3. Audit IKEv1 config and SA state
  4. Audit IKEv2 config and SA state
  5. Document all crypto/VPN config
  6. Generate remediation handoff report

KEY NOTES:
  - CISA KEV — actively exploited in the wild
  - NO confirmed CLI workaround per Cisco advisory
  - EPSS 0.0858 — second highest on this device
  - This is the 3rd CISA KEV on this device
    (alongside 93736/CVE-2016-6415 and 131166/CVE-2018-0154)
  - Full fix = IOS upgrade per CSCvc41277
  - Same IOS upgrade clears ALL 14 plugins on this device
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

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"fix_103693_audit_{TIMESTAMP}.txt"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("── STEP 1: Backing up running configuration ──")
    config = connection.send_command("show running-config")
    backup_file = f"backup_103693_{DEVICE['host']}_{TIMESTAMP}.txt"
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
    log("  Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-ike")
    log("  CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

def audit_ikev1(connection):
    log("── STEP 3: IKEv1 (ISAKMP) Audit ──")

    # IKEv1 policy
    log("  >> IKEv1 Policies:")
    policy = connection.send_command("show crypto isakmp policy")
    log(policy if policy.strip() else "  No IKEv1 policies configured.")

    # IKEv1 SA table
    log("  >> IKEv1 SA Table:")
    sa = connection.send_command("show crypto isakmp sa")
    if sa.strip():
        log(sa)
        active = [l for l in sa.splitlines() if "ACTIVE" in l or "QM_IDLE" in l]
        log(f"  Active IKEv1 SAs: {len(active)}")
        if active:
            log("  ⚠️  Active IKEv1 VPN tunnels — will be disrupted on upgrade/reload.")
    else:
        log("  No active IKEv1 SAs.")

    # IKEv1 peers
    log("  >> IKEv1 Peers (from config):")
    peers = connection.send_command(
        "show running-config | include crypto isakmp key|set peer"
    )
    log(peers if peers.strip() else "  No IKEv1 peer config found.")

    # ISAKMP config
    log("  >> Full ISAKMP Config:")
    isakmp_cfg = connection.send_command(
        "show running-config | section crypto isakmp"
    )
    log(isakmp_cfg if isakmp_cfg.strip() else "  No crypto isakmp section.")

def audit_ikev2(connection):
    log("── STEP 4: IKEv2 Audit ──")

    # IKEv2 proposals
    log("  >> IKEv2 Proposals:")
    proposals = connection.send_command("show crypto ikev2 proposal")
    log(proposals if proposals.strip() else "  No IKEv2 proposals.")

    # IKEv2 policies
    log("  >> IKEv2 Policies:")
    policies = connection.send_command("show crypto ikev2 policy")
    log(policies if policies.strip() else "  No IKEv2 policies.")

    # IKEv2 SA table
    log("  >> IKEv2 SA Table:")
    sa = connection.send_command("show crypto ikev2 sa")
    if sa.strip():
        log(sa)
        ready = [l for l in sa.splitlines() if "READY" in l]
        log(f"  READY IKEv2 SAs: {len(ready)}")
        if ready:
            log("  ⚠️  Active IKEv2 VPN tunnels — will be disrupted on upgrade/reload.")
    else:
        log("  No active IKEv2 SAs.")

    # IKEv2 profile
    log("  >> IKEv2 Profiles:")
    profiles = connection.send_command(
        "show running-config | section crypto ikev2 profile"
    )
    log(profiles if profiles.strip() else "  No IKEv2 profiles configured.")

def audit_crypto_map(connection):
    log("── STEP 5: Crypto Map and IPSec Audit ──")

    # Crypto maps
    log("  >> Crypto Maps:")
    cmap = connection.send_command("show running-config | section crypto map")
    log(cmap[:500] if len(cmap) > 500 else cmap if cmap.strip()
        else "  No crypto maps configured.")

    # IPSec SA summary
    log("  >> IPSec SA Summary:")
    ipsec = connection.send_command(
        "show crypto ipsec sa | include local ident|remote ident|pkts encrypt"
    )
    log(ipsec if ipsec.strip() else "  No active IPSec SAs.")

    # Transform sets
    log("  >> Transform Sets:")
    transform = connection.send_command("show crypto ipsec transform-set")
    log(transform if transform.strip() else "  No transform sets configured.")

def cross_reference_check(connection):
    log("── STEP 6: Cross-reference with Related IKE Plugins ──")
    log("  This device has multiple IKE-related vulnerabilities:")
    log("")
    log("  Plugin 94762  (CVE-2016-6381) — IKEv1 Fragmentation DoS")
    log("    Workaround: 'no crypto isakmp fragmentation' (already covered)")
    log("")
    log("  Plugin 137835 (CVE-2020-3230) — IKEv2 SA-Init DoS")
    log("    Workaround: Remove IKEv2 proposals (already covered)")
    log("")
    log("  Plugin 93736  (CVE-2016-6415) — BENIGNCERTAIN (CISA KEV)")
    log("    No workaround — upgrade only")
    log("")
    log("  Plugin 103693 (CVE-2017-12237) — IKE DoS (CISA KEV) ← THIS PLUGIN")
    log("    No workaround — upgrade only")
    log("")
    log("  → Single IOS upgrade resolves ALL four IKE-related plugins.")

def remediation_notice():
    log("── REMEDIATION NOTICE ──")
    log("Plugin 103693 - CVE-2017-12237 - Cisco IOS IKE DoS")
    log("⚠️  CISA KNOWN EXPLOITED VULNERABILITY — 2022/03/24")
    log("⚠️  NO CLI WORKAROUND — IOS upgrade is the ONLY fix")
    log("")
    log("This is the 3rd CISA KEV on this device:")
    log("  1. Plugin 93736  — CVE-2016-6415 (BENIGNCERTAIN)")
    log("  2. Plugin 131166 — CVE-2018-0154 (ISM-VPN)")
    log("  3. Plugin 103693 — CVE-2017-12237 (IKE DoS) ← THIS")
    log("")
    log("Permanent Fix: IOS upgrade per Cisco Bug CSCvc41277")
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
    log("")
    log("One upgrade clears ALL 14 plugins on this device.")

def main():
    log("="*65)
    log("Fix Script - Plugin 103693 - Cisco IOS IKE DoS")
    log("CVE-2017-12237 | CSCvc41277")
    log("CISA KEV #3 on this device | EPSS 0.0858 | NO WORKAROUND")
    log("="*65)

    try:
        log(f"Connecting to: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        backup_config(connection)
        collect_ios_version(connection)
        audit_ikev1(connection)
        audit_ikev2(connection)
        audit_crypto_map(connection)
        cross_reference_check(connection)
        remediation_notice()

        connection.disconnect()
        log(f"Audit complete. Log saved to: {LOG_FILE}")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()