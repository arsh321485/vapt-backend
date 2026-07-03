from netmiko import ConnectHandler
import logging
import datetime
import sys
import re
import socket

print("=" * 60)
print("Cisco IOS AAA Login DoS Verify — CVE-2016-6393")
print("Plugin 131164 / Bug CSCuy87667")
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

# Known fixed releases for CSCuy87667
FIXED_RELEASES = [
    "15.6(1)T", "15.6(2)T", "15.7(3)M",
    "16.3.1",   "16.6.1",   "17.1.1"
]

VULNERABLE_RELEASE = "15.4(3)M5"
all_good = True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("cisco_aaa_dos_verify")

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

    # ─── Check 2: SSH timeout and retries ────────────────────────
    log.info("\n[2] Checking SSH timeout configuration...")
    ssh_output = connection.send_command(
        "show running-config | include ip ssh"
    )
    log.info("   SSH Config:\n%s", ssh_output)

    if "ip ssh time-out 60" in ssh_output:
        log.info("✅ SSH timeout is configured")
    else:
        log.warning("⚠️ SSH timeout not explicitly configured")

    if "ip ssh authentication-retries 3" in ssh_output:
        log.info("✅ SSH authentication retries limited to 3")
    else:
        log.warning("⚠️ SSH authentication retries not configured")

    # ─── Check 3: Login block-for config ─────────────────────────
    log.info("\n[3] Checking login block-for configuration...")
    login_output = connection.send_command(
        "show running-config | include login"
    )
    log.info("   Login Config:\n%s", login_output)

    if "login block-for" in login_output:
        log.info("✅ Login block-for is configured (DoS protection)")
    else:
        log.error("❌ login block-for NOT configured!")
        all_good = False

    # ─── Check 4: VTY Line restrictions ──────────────────────────
    log.info("\n[4] Checking VTY line configuration...")
    vty_output = connection.send_command(
        "show running-config | section line vty"
    )
    log.info("   VTY Config:\n%s", vty_output)

    if "transport input ssh" in vty_output:
        log.info("✅ VTY restricted to SSH only")
    else:
        log.error("❌ VTY not restricted to SSH — Telnet may be allowed!")
        all_good = False

    if "access-class" in vty_output:
        log.info("✅ VTY access-class ACL is configured")
    else:
        log.error("❌ No access-class ACL on VTY lines!")
        all_good = False

    if "exec-timeout" in vty_output:
        log.info("✅ VTY exec-timeout is configured")
    else:
        log.warning("⚠️ No exec-timeout on VTY lines")

    # ─── Check 5: AAA configuration ──────────────────────────────
    log.info("\n[5] Checking AAA configuration...")
    aaa_output = connection.send_command(
        "show running-config | section aaa"
    )
    log.info("   AAA Config:\n%s", aaa_output)

    if "aaa new-model" in aaa_output:
        log.info("✅ AAA new-model is enabled")
    else:
        log.error("❌ AAA new-model NOT enabled!")
        all_good = False

    if "aaa authentication login" in aaa_output:
        log.info("✅ AAA authentication login is configured")
    else:
        log.error("❌ AAA authentication login NOT configured!")
        all_good = False

    # ─── Check 6: SSH login attempt check ────────────────────────
    log.info("\n[6] Checking login statistics...")
    login_stats = connection.send_command("show login")
    log.info("   Login Stats:\n%s", login_stats)

    connection.disconnect()
    log.info("\n✅ Disconnected from device")

except Exception as e:
    log.error("❌ Connection error: %s", e)
    sys.exit(1)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — AAA Login DoS workaround confirmed!")
    print("   Re-run Nessus scan to confirm Plugin 131164 resolved.")
    print("   ⚠️  Still recommended to upgrade IOS per CSCuy87667")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 131164_CISCO_FIX.py")
    print("   Upgrade IOS per Cisco Bug ID: CSCuy87667")
print("=" * 60)