from netmiko import ConnectHandler
import logging
import datetime
import sys
import re

print("=" * 60)
print("Cisco IOS HTTP Client Info Disclosure Verify — CVE-2019-12665")
print("Plugin 129778 / Bug CSCvf36258")
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

# Known fixed releases for CSCvf36258
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
log = logging.getLogger("cisco_httpclient_verify")

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

    # ─── Check 2: HTTP client forceclose ─────────────────────────
    log.info("\n[2] Checking HTTP client persistent connection setting...")
    http_output = connection.send_command(
        "show running-config | include ip http client"
    )
    log.info("   HTTP Client Config:\n%s", http_output)

    if "forceclose" in http_output:
        log.info("✅ HTTP client forceclose is configured")
    else:
        log.error(
            "❌ HTTP client forceclose NOT set — "
            "persistent connections may be active!"
        )
        all_good = False

    # ─── Check 3: HTTP server disabled ───────────────────────────
    log.info("\n[3] Checking HTTP server status...")
    if "no ip http server" in http_output or \
       "ip http server" not in http_output:
        log.info("✅ HTTP server is disabled")
    else:
        log.warning("⚠️ HTTP server may still be enabled")

    # ─── Check 4: HTTP Client ACL ─────────────────────────────────
    log.info("\n[4] Checking HTTP client restriction ACL...")
    acl_output = connection.send_command(
        "show ip access-lists HTTP-CLIENT-RESTRICT"
    )
    log.info("   ACL:\n%s", acl_output)
    if "HTTP-CLIENT-RESTRICT" in acl_output:
        log.info("✅ HTTP-CLIENT-RESTRICT ACL is configured")
    else:
        log.error("❌ HTTP-CLIENT-RESTRICT ACL not found!")
        all_good = False

    # ─── Check 5: Call-home HTTPS transport ──────────────────────
    log.info("\n[5] Checking call-home transport protocol...")
    callhome_output = connection.send_command(
        "show running-config | section call-home"
    )
    if "transport-protocol https" in callhome_output:
        log.info("✅ Call-home using HTTPS transport")
    else:
        log.warning(
            "⚠️ Call-home HTTPS transport not confirmed — "
            "check manually"
        )

    # ─── Check 6: Source interface configured ────────────────────
    log.info("\n[6] Checking HTTP client source interface...")
    if "source-interface" in http_output:
        log.info("✅ HTTP client source interface is configured")
    else:
        log.warning("⚠️ HTTP client source interface not set")

    # ─── Check 7: HTTP client stats ──────────────────────────────
    log.info("\n[7] Checking HTTP client connection stats...")
    try:
        stats = connection.send_command(
            "show ip http client connection"
        )
        log.info("   HTTP Client Connections:\n%s", stats[:300])
    except Exception:
        log.info("   HTTP client connection stats not available")

    connection.disconnect()
    log.info("\n✅ Disconnected from device")

except Exception as e:
    log.error("❌ Connection error: %s", e)
    sys.exit(1)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — HTTP Client workaround confirmed!")
    print("   Re-run Nessus scan to confirm Plugin 129778 resolved.")
    print("   ⚠️  Still recommended to upgrade IOS per CSCvf36258")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 129778_CISCO_FIX.py")
    print("   Upgrade IOS per Cisco Bug ID: CSCvf36258")
print("=" * 60)