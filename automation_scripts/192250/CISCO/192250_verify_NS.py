from netmiko import ConnectHandler
import logging
import datetime
import sys
import re

print("=" * 60)
print("Cisco IOS AAA SCP Bypass Verify — CVE-2023-20186")
print("Plugin 192250 / Bug CSCwe55871")
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

# Known fixed IOS releases for CSCwe55871
# Verify latest from: https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe55871
FIXED_RELEASES = [
    "15.9(3)M", "16.12.8", "17.3.7",
    "17.6.5",   "17.9.3",  "17.12.1"
]

VULNERABLE_RELEASE = "15.4(3)M5"   # from Nessus output

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
all_good  = True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("cisco_verify")

try:
    log.info("Connecting to Cisco device: %s", DEVICE["host"])
    connection = ConnectHandler(**DEVICE)
    connection.enable()
    log.info("✅ Connected and in enable mode")

    # ─── Check 1: IOS Version ─────────────────────────────────────
    log.info("\n[1] Checking IOS version...")
    version_output = connection.send_command("show version")

    # Extract version
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
            log.info(
                "✅ Running FIXED version %s",
                current_version
            )
        else:
            log.warning(
                "⚠️ Version %s — verify against Cisco advisory",
                current_version
            )
    else:
        log.warning("⚠️ Could not parse IOS version")

    # ─── Check 2: SCP Server Status ──────────────────────────────
    log.info("\n[2] Checking SCP server status...")
    scp_output = connection.send_command(
        "show running-config | include ip scp server"
    )
    if "ip scp server enable" in scp_output:
        log.error("❌ SCP server is still ENABLED — workaround not applied!")
        all_good = False
    else:
        log.info("✅ SCP server is DISABLED — workaround confirmed!")

    # ─── Check 3: AAA Configuration ──────────────────────────────
    log.info("\n[3] Checking AAA configuration...")
    aaa_output = connection.send_command(
        "show running-config | section aaa"
    )
    log.info("   AAA Config:\n%s", aaa_output)

    if "aaa authorization" in aaa_output:
        log.info("✅ AAA authorization is configured")
    else:
        log.warning("⚠️ No AAA authorization found — verify manually")

    # ─── Check 4: SNMP Configuration ─────────────────────────────
    log.info("\n[4] Checking SNMP configuration (tcp/161)...")
    snmp_output = connection.send_command(
        "show running-config | section snmp"
    )
    log.info("   SNMP Config:\n%s", snmp_output[:300])
    if snmp_output:
        log.info("✅ SNMP is configured (port 161 active)")
    else:
        log.warning("⚠️ No SNMP config found")

    # ─── Check 5: Privilege Level 15 Users ───────────────────────
    log.info("\n[5] Checking privilege level 15 users...")
    users_output = connection.send_command(
        "show running-config | include username"
    )
    priv15_users = [
        l for l in users_output.splitlines()
        if "privilege 15" in l
    ]
    if priv15_users:
        log.warning(
            "⚠️ %d user(s) with privilege 15 found — "
            "review if all are required:",
            len(priv15_users)
        )
        for u in priv15_users:
            log.warning("   %s", u)
    else:
        log.info("✅ No privilege 15 users found")

    connection.disconnect()
    log.info("\n✅ Disconnected from device")

except Exception as e:
    log.error("❌ Connection error: %s", e)
    sys.exit(1)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — Workaround confirmed!")
    print("   Re-run Nessus scan to confirm Plugin 192250 resolved.")
    print("   ⚠️  Still recommended to upgrade IOS to fixed release")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 192250_CISCO_FIX.py")
    print("   Upgrade IOS per Cisco Bug ID CSCwe55871 advisory")
print("=" * 60)