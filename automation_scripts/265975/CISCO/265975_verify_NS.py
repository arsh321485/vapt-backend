from netmiko import ConnectHandler
import logging
import datetime
import sys
import re
import socket

print("=" * 60)
print("Cisco IOS Web Services RCE Verify — CVE-2025-20363")
print("Plugin 265975 / Bug CSCwo35704")
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

# Known fixed releases for CSCwo35704
FIXED_RELEASES = [
    "17.15.1", "17.12.4", "17.9.6",
    "17.6.7",  "16.12.10"
]

VULNERABLE_RELEASE = "15.4(3)M5"
all_good = True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("cisco_webrce_verify")

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

    # ─── Check 2: HTTP/HTTPS Server Status ────────────────────────
    log.info("\n[2] Checking HTTP/HTTPS web services status...")
    http_output = connection.send_command(
        "show running-config | include ip http"
    )
    log.info("   HTTP Config:\n%s", http_output)

    if "ip http server" not in http_output:
        log.info("✅ HTTP server is DISABLED")
    else:
        log.error("❌ HTTP server is still ENABLED — check ACL restrictions")
        all_good = False

    if "ip http secure-server" not in http_output:
        log.info("✅ HTTPS server is DISABLED")
    else:
        log.error("❌ HTTPS server is still ENABLED — check ACL restrictions")
        all_good = False

    # ─── Check 3: HTTP ACL Restriction ───────────────────────────
    log.info("\n[3] Checking HTTP access-class ACL...")
    acl_output = connection.send_command(
        "show running-config | include http access-class"
    )
    if "access-class" in acl_output:
        log.info("✅ HTTP access-class ACL is configured: %s", acl_output)
    else:
        log.warning("⚠️ No HTTP access-class ACL found")

    # ─── Check 4: Port 80/443 accessibility ──────────────────────
    log.info("\n[4] Checking if HTTP port 80 is accessible...")
    try:
        sock = socket.create_connection(
            (DEVICE["host"], 80), timeout=3
        )
        sock.close()
        log.error("❌ Port 80 is OPEN — HTTP server may still be running!")
        all_good = False
    except (ConnectionRefusedError, socket.timeout, OSError):
        log.info("✅ Port 80 is NOT accessible — HTTP server disabled!")

    log.info("\n[5] Checking if HTTPS port 443 is accessible...")
    try:
        sock = socket.create_connection(
            (DEVICE["host"], 443), timeout=3
        )
        sock.close()
        log.error("❌ Port 443 is OPEN — HTTPS server may still be running!")
        all_good = False
    except (ConnectionRefusedError, socket.timeout, OSError):
        log.info("✅ Port 443 is NOT accessible — HTTPS server disabled!")

    # ─── Check 5: SNMP Status (tcp/161) ──────────────────────────
    log.info("\n[6] Checking SNMP configuration (tcp/161)...")
    snmp_output = connection.send_command(
        "show running-config | section snmp"
    )
    log.info("   SNMP Config:\n%s", snmp_output[:300])

    connection.disconnect()
    log.info("\n✅ Disconnected from device")

except Exception as e:
    log.error("❌ Connection error: %s", e)
    sys.exit(1)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — Web Services RCE workaround confirmed!")
    print("   Re-run Nessus scan to confirm Plugin 265975 resolved.")
    print("   ⚠️  Still recommended to upgrade IOS per CSCwo35704")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 265975_CISCO_FIX.py")
    print("   Upgrade IOS per Cisco Bug ID: CSCwo35704")
print("=" * 60)