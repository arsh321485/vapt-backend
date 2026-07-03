from netmiko import ConnectHandler
import logging
import datetime
import sys
import re

print("=" * 60)
print("Cisco IOS SIP DoS Verify — CVE-2019-12654")
print("Plugin 129694 / Bug CSCvn00218")
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

# Known fixed releases for CSCvn00218
FIXED_RELEASES = [
    "15.6(3)M7", "15.7(3)M5", "15.8(3)M3",
    "15.9(3)M",  "16.9.4",    "16.12.1",
    "17.1.1"
]

VULNERABLE_RELEASE = "15.4(3)M5"
all_good = True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("cisco_sip_dos_verify")

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

    # ─── Check 2: SIP status ──────────────────────────────────────
    log.info("\n[2] Checking SIP configuration status...")
    sip_output = connection.send_command(
        "show running-config | section sip"
    )
    if "no allow-connections sip" in sip_output:
        log.info("✅ SIP connections disabled")
    elif sip_output.strip():
        log.warning("⚠️ SIP still configured — verify CoPP is protecting it")
    else:
        log.info("✅ No SIP configuration found")

    # ─── Check 3: CoPP SIP policy ────────────────────────────────
    log.info("\n[3] Checking CoPP SIP policy on control plane...")
    copp_output = connection.send_command(
        "show policy-map control-plane"
    )
    log.info("   CoPP:\n%s", copp_output[:500])

    if "COPP-SIP-POLICY" in copp_output:
        log.info("✅ SIP CoPP policy is active on control plane")
    else:
        log.error("❌ SIP CoPP policy NOT found on control plane!")
        all_good = False

    # ─── Check 4: SIP CoPP ACL ───────────────────────────────────
    log.info("\n[4] Checking SIP CoPP ACL...")
    acl_output = connection.send_command(
        "show ip access-lists SIP-COPP-ACL"
    )
    log.info("   ACL:\n%s", acl_output)
    if "SIP-COPP-ACL" in acl_output:
        log.info("✅ SIP-COPP-ACL is configured")
    else:
        log.error("❌ SIP-COPP-ACL not found!")
        all_good = False

    # ─── Check 5: SIP NAT ALG status ─────────────────────────────
    log.info("\n[5] Checking SIP NAT ALG status...")
    nat_output = connection.send_command(
        "show running-config | include nat service sip"
    )
    if "no ip nat service sip" in nat_output:
        log.info("✅ SIP NAT ALG is disabled")
    elif nat_output.strip():
        log.warning("⚠️ SIP NAT ALG may be active: %s", nat_output)
    else:
        log.info("✅ SIP NAT ALG not explicitly configured")

    # ─── Check 6: SIP traffic stats ──────────────────────────────
    log.info("\n[6] Checking SIP traffic statistics...")
    sip_stats = connection.send_command("show sip-ua status")
    log.info("   SIP UA Status:\n%s", sip_stats[:300])

    # ─── Check 7: Control plane stats ────────────────────────────
    log.info("\n[7] Checking control plane SIP class stats...")
    cp_stats = connection.send_command(
        "show policy-map control-plane input class SIP-CLASS"
    )
    log.info("   Control Plane SIP Stats:\n%s", cp_stats[:300])

    connection.disconnect()
    log.info("\n✅ Disconnected from device")

except Exception as e:
    log.error("❌ Connection error: %s", e)
    sys.exit(1)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — SIP DoS workaround confirmed!")
    print("   Re-run Nessus scan to confirm Plugin 129694 resolved.")
    print("   ⚠️  Still recommended to upgrade IOS per CSCvn00218")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 129694_CISCO_FIX.py")
    print("   Upgrade IOS per Cisco Bug ID: CSCvn00218")
print("=" * 60)