from netmiko import ConnectHandler
import logging
import datetime
import sys
import re

print("=" * 60)
print("Cisco IOS Web Services RCE Fix — CVE-2025-20363")
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

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"265975_cisco_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("cisco_webrce_fix")

try:
    log.info("Connecting to Cisco device: %s", DEVICE["host"])
    connection = ConnectHandler(**DEVICE)
    connection.enable()
    log.info("✅ Connected and in enable mode")

    # ─── Step 1: Check IOS version ───────────────────────────────
    log.info("\n[1] Checking current IOS version...")
    version_output = connection.send_command("show version")
    log.info(version_output[:500])

    # ─── Step 2: Check HTTP/HTTPS server status ───────────────────
    log.info("\n[2] Checking HTTP/HTTPS web services status...")
    http_output = connection.send_command(
        "show running-config | include ip http"
    )
    log.info("HTTP Config:\n%s", http_output)

    http_enabled  = "ip http server" in http_output
    https_enabled = "ip http secure-server" in http_output

    log.info("   HTTP server enabled  : %s", http_enabled)
    log.info("   HTTPS server enabled : %s", https_enabled)

    # ─── Step 3: Backup running config ───────────────────────────
    log.info("\n[3] Backing up running configuration...")
    running_config = connection.send_command("show running-config")
    backup_file = f"cisco_config_backup_{timestamp}.txt"
    with open(backup_file, "w") as f:
        f.write(running_config)
    log.info("✅ Config backed up to: %s", backup_file)

    # ─── Step 4: Apply workaround ─────────────────────────────────
    log.info("\n[4] Applying CVE-2025-20363 workaround...")
    config_commands = []

    # Primary workaround: Disable HTTP/HTTPS web services
    # if not required for management
    if http_enabled:
        config_commands.append("no ip http server")
        log.info("   → Disabling HTTP server")

    if https_enabled:
        config_commands.append("no ip http secure-server")
        log.info("   → Disabling HTTPS server")

    if not http_enabled and not https_enabled:
        log.info("   ✅ HTTP/HTTPS server already disabled")
    else:
        # Additional hardening — restrict HTTP access via ACL
        config_commands.extend([
            # Restrict HTTP access to management subnet only
            "ip http access-class 99",
            "ip http max-connections 5",
            "ip http timeout-policy idle 60 life 86400 requests 10000",
            # Restrict auth method
            "ip http authentication local",
        ])
        log.info("   → Applying HTTP access restrictions and ACL")

        # Create restrictive ACL for HTTP management access
        config_commands.extend([
            "ip access-list standard 99",
            " permit 192.168.1.0 0.0.0.255",  # ← change to your mgmt subnet
            " deny any log",
        ])
        log.info("   → Creating ACL 99 to restrict HTTP access")

    output = connection.send_config_set(config_commands)
    log.info("Output:\n%s", output)

    # ─── Step 5: Save configuration ──────────────────────────────
    log.info("\n[5] Saving configuration...")
    save_output = connection.save_config()
    log.info("✅ Configuration saved: %s", save_output)

    # ─── Step 6: Verify workaround ───────────────────────────────
    log.info("\n[6] Verifying workaround...")
    verify_http = connection.send_command(
        "show running-config | include ip http"
    )
    log.info("HTTP Config after fix:\n%s", verify_http)

    if "ip http server" not in verify_http:
        log.info("✅ HTTP server disabled — workaround applied!")
    if "ip http secure-server" not in verify_http:
        log.info("✅ HTTPS server disabled — workaround applied!")

    connection.disconnect()
    log.info("✅ Disconnected from device")

except Exception as e:
    log.error("❌ Error: %s", e)
    sys.exit(1)

print("\n" + "=" * 60)
print("✅ Workaround applied!")
print(f"   Backup : {backup_file}")
print(f"   Log    : {log_file}")
print("   ⚠️  Permanent fix: Upgrade IOS per Cisco Bug ID:")
print("       CSCwo35704")
print("   → Run 265975_CISCO_VERIFY.py to confirm")
print("=" * 60)