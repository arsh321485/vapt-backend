from netmiko import ConnectHandler
import logging
import datetime
import sys
import re

print("=" * 60)
print("Cisco IOS H.323 DoS Verify — CVE-2016-6384")
print("Plugin 130764 / Bug CSCux04257")
print("=" * 60)

# ─── Configuration ────────────────────────────────────────────────
DEVICE = {
    "device_type": "cisco_ios",
    "host":        "YOUR_CISCO_DEVICE_IP",   # ← change this
    "username":    "YOUR_USERNAME",           # ← change this
    "password":    "YOUR_PASSWORD",           # ← change this
    "secret":      "YOUR_ENABLE_SECRET",      # ← change this
    "port":        22,
    "timeout":     30,
}

# Known fixed releases for CSCux04257
FIXED_RELEASES = [
    "15.6(1)T", "15.6(2)T", "15.7(3)M",
    "15.8(3)M", "16.3.4",   "16.6.1",
    "16.9.1",   "17.1.1"
]

VULNERABLE_RELEASE = "15.4(3)M5"
all_good = True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("cisco_h323_dos_verify")

try:
    log.info("Connecting to Cisco device: %s", DEVICE["host"])
    connection = ConnectHandler(**DEVICE)
    connection.enable()
    log.info("✅ Connected and in enable mode")

    # ─── Check 1: IOS Version ─────────────────────────────────────
    log.info("\n[1] Checking IOS version...")
    version_output = connection.send_command("show version")
    match = re.search(r"Version\s+([\d\.\(\)A-Za-z]+)", version_output)
    if match:
        current_version = match.group(1)
        log.info("   Current IOS version: %s", current_version)
        if current_version == VULNERABLE_RELEASE:
            log.error(
                "❌ Running VULNERABLE version %s — upgrade required!",
                current_version
            )
            all_good = False
        elif any(fixed in current_version for fixed in FIXED_RELEASES):
            log.info("✅ Running FIXED version %s", current_version)
        else:
            log.warning(
                "⚠️ Version %s — verify against Cisco advisory",
                current_version
            )

    # ─── Check 2: H.323 status ────────────────────────────────────
    log.info("\n[2] Checking H.323 configuration status...")
    h323_output = connection.send_command(
        "show running-config | section h323"
    )
    voice_output = connection.send_command(
        "show running-config | section voice service"
    )

    if "no allow-connections h323" in voice_output:
        log.info("✅ H.323 connections disabled in voice service")
    elif h323_output.strip():
        log.warning(
            "⚠️ H.323 still configured — verify CoPP is protecting it"
        )
    else:
        log.info("✅ No H.323 configuration found")

    # ─── Check 3: H.323 NAT ALG ──────────────────────────────────
    log.info("\n[3] Checking H.323 NAT ALG status...")
    nat_output = connection.send_command(
        "show running-config | include nat service H323"
    )
    if "no ip nat service H323" in nat_output:
        log.info("✅ H.323 NAT ALG is disabled")
    elif nat_output.strip():
        log.warning("⚠️ H.323 NAT ALG may be active: %s", nat_output)
    else:
        log.info("✅ H.323 NAT ALG not explicitly configured")

    # ─── Check 4: CoPP H.323 policy ──────────────────────────────
    log.info("\n[4] Checking CoPP H.323 policy on control plane...")
    copp_output = connection.send_command(
        "show policy-map control-plane"
    )
    log.info("   CoPP:\n%s", copp_output[:500])

    if "COPP-H323-POLICY" in copp_output:
        log.info("✅ H.323 CoPP policy is active on control plane")
    else:
        log.error("❌ H.323 CoPP policy NOT found on control plane!")
        all_good = False

    # ─── Check 5: H.323 CoPP ACL ─────────────────────────────────
    log.info("\n[5] Checking H.323 CoPP ACL...")
    acl_output = connection.send_command(
        "show ip access-lists H323-COPP-ACL"
    )
    log.info("   ACL:\n%s", acl_output)
    if "H323-COPP-ACL" in acl_output:
        log.info("✅ H323-COPP-ACL is configured")
    else:
        log.error("❌ H323-COPP-ACL not found!")
        all_good = False

    # ─── Check 6: H.323 protection ACL ───────────────────────────
    log.info("\n[6] Checking H.323 interface protection ACL...")
    protect_acl = connection.send_command(
        "show ip access-lists H323-PROTECT"
    )
    log.info("   Protection ACL:\n%s", protect_acl)
    if "H323-PROTECT" in protect_acl:
        log.info("✅ H323-PROTECT ACL is configured")
    else:
        log.warning("⚠️ H323-PROTECT ACL not found")

    # ─── Check 7: Gatekeeper status ───────────────────────────────
    log.info("\n[7] Checking H.323 Gatekeeper status...")
    gk_output = connection.send_command("show gatekeeper status")
    log.info("   Gatekeeper:\n%s", gk_output[:300])

    # ─── Check 8: Control plane stats ────────────────────────────
    log.info("\n[8] Checking control plane H.323 class stats...")
    cp_stats = connection.send_command(
        "show policy-map control-plane input class H323-CLASS"
    )
    log.info("   Control Plane H.323 Stats:\n%s", cp_stats[:300])

    connection.disconnect()
    log.info("\n✅ Disconnected from device")

except Exception as e:
    log.error("❌ Connection error: %s", e)
    sys.exit(1)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — H.323 DoS workaround confirmed!")
    print("   Re-run Nessus scan to confirm Plugin 130764 resolved.")
    print("   ⚠️  Still recommended to upgrade IOS per CSCux04257")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 130764_CISCO_FIX.py")
    print("   Upgrade IOS per Cisco Bug ID: CSCux04257")
print("=" * 60)