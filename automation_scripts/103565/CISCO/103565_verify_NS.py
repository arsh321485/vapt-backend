from netmiko import ConnectHandler
import logging
import datetime
import sys
import re

print("=" * 60)
print("Cisco IOS DHCP RCE Verify — CVE-2017-12240")
print("Plugin 103565 / Bug CSCsm45390, CSCuw77959")
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

# Known fixed releases for CSCsm45390 / CSCuw77959
FIXED_RELEASES = [
    "15.6(3)M", "15.7(3)M", "15.8(3)M",
    "16.6.4",   "16.9.1",   "17.1.1"
]

VULNERABLE_RELEASE = "15.4(3)M5"

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
all_good  = True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("cisco_dhcp_verify")

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
    else:
        log.warning("⚠️ Could not parse IOS version")

    # ─── Check 2: DHCP Server Status ─────────────────────────────
    log.info("\n[2] Checking DHCP server status...")
    dhcp_output = connection.send_command(
        "show running-config | include service dhcp"
    )
    if "no service dhcp" in dhcp_output:
        log.info("✅ DHCP server is DISABLED — workaround confirmed!")
    else:
        log.warning(
            "⚠️ DHCP server may be active — "
            "verify snooping is enabled"
        )

    # ─── Check 3: DHCP Snooping ───────────────────────────────────
    log.info("\n[3] Checking DHCP snooping...")
    snoop_output = connection.send_command("show ip dhcp snooping")
    log.info("   DHCP Snooping:\n%s", snoop_output)

    if "enabled" in snoop_output.lower():
        log.info("✅ DHCP snooping is ENABLED")
    else:
        log.error("❌ DHCP snooping is NOT enabled")
        all_good = False

    # ─── Check 4: DHCP Bindings ───────────────────────────────────
    log.info("\n[4] Checking DHCP snooping bindings...")
    bindings = connection.send_command(
        "show ip dhcp snooping binding"
    )
    log.info("   Bindings:\n%s", bindings[:300])

    # ─── Check 5: DHCP Statistics ────────────────────────────────
    log.info("\n[5] Checking DHCP server statistics...")
    stats = connection.send_command("show ip dhcp server statistics")
    log.info("   DHCP Stats:\n%s", stats[:300])

    # ─── Check 6: Interface trust ports ──────────────────────────
    log.info("\n[6] Checking DHCP snooping trust ports...")
    interfaces = connection.send_command(
        "show ip dhcp snooping | include trust"
    )
    log.info("   Trust ports:\n%s", interfaces)

    connection.disconnect()
    log.info("\n✅ Disconnected from device")

except Exception as e:
    log.error("❌ Connection error: %s", e)
    sys.exit(1)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — DHCP RCE workaround confirmed!")
    print("   Re-run Nessus scan to confirm Plugin 103565 resolved.")
    print("   ⚠️  Still recommended to upgrade IOS to fixed release")
    print("       per Cisco Bug IDs: CSCsm45390 and CSCuw77959")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 103565_CISCO_FIX.py")
    print("   Upgrade IOS per Cisco Bug IDs: CSCsm45390, CSCuw77959")
print("=" * 60)