from netmiko import ConnectHandler
import logging
import datetime
import sys
import re

print("=" * 60)
print("Cisco IOS DHCP Client DoS Verify — CVE-2017-3864")
print("Plugin 99026 / Bug CSCuu43892")
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

# Known fixed releases for CSCuu43892
FIXED_RELEASES = [
    "15.6(1)T", "15.6(2)T", "15.7(3)M",
    "15.8(3)M", "16.3.5",   "16.6.2",
    "16.9.1",   "17.1.1"
]

VULNERABLE_RELEASE = "15.4(3)M5"
all_good = True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("cisco_dhcpc_dos_verify")

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

    # ─── Check 2: DHCP Client interfaces ─────────────────────────
    log.info("\n[2] Checking DHCP client interfaces...")
    dhcp_client = connection.send_command(
        "show running-config | include ip address dhcp"
    )
    if dhcp_client.strip():
        log.warning(
            "⚠️ DHCP client active on interface(s):\n%s",
            dhcp_client
        )
        log.warning(
            "   Consider static IP if DHCP client not required"
        )
    else:
        log.info("✅ No interfaces using DHCP client")

    # ─── Check 3: CoPP Policy ─────────────────────────────────────
    log.info("\n[3] Checking Control Plane Policing (CoPP)...")
    copp_output = connection.send_command(
        "show policy-map control-plane"
    )
    log.info("   CoPP:\n%s", copp_output[:500])

    if "COPP-DHCP-POLICY" in copp_output:
        log.info("✅ DHCP CoPP policy is active on control plane")
    else:
        log.error("❌ DHCP CoPP policy NOT found on control plane!")
        all_good = False

    # ─── Check 4: DHCP ACL ────────────────────────────────────────
    log.info("\n[4] Checking DHCP protection ACL...")
    acl_output = connection.send_command(
        "show ip access-lists DHCP-CLIENT-PROTECT"
    )
    log.info("   ACL:\n%s", acl_output)
    if "DHCP-CLIENT-PROTECT" in acl_output:
        log.info("✅ DHCP-CLIENT-PROTECT ACL is configured")
    else:
        log.error("❌ DHCP-CLIENT-PROTECT ACL not found!")
        all_good = False

    # ─── Check 5: DHCP client stats ──────────────────────────────
    log.info("\n[5] Checking DHCP client statistics...")
    dhcp_stats = connection.send_command(
        "show dhcp lease"
    )
    log.info("   DHCP Leases:\n%s", dhcp_stats[:300])

    # ─── Check 6: Control plane stats ────────────────────────────
    log.info("\n[6] Checking control plane statistics...")
    cp_stats = connection.send_command(
        "show policy-map control-plane input class DHCP-CLASS"
    )
    log.info("   Control Plane DHCP Stats:\n%s", cp_stats[:300])

    connection.disconnect()
    log.info("\n✅ Disconnected from device")

except Exception as e:
    log.error("❌ Connection error: %s", e)
    sys.exit(1)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — DHCP Client DoS workaround confirmed!")
    print("   Re-run Nessus scan to confirm Plugin 99026 resolved.")
    print("   ⚠️  Still recommended to upgrade IOS per CSCuu43892")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 99026_CISCO_FIX.py")
    print("   Upgrade IOS per Cisco Bug ID: CSCuu43892")
print("=" * 60)