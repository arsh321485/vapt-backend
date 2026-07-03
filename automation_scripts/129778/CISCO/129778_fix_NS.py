from netmiko import ConnectHandler
import logging
import datetime
import sys
import re

print("=" * 60)
print("Cisco IOS HTTP Client Info Disclosure Fix — CVE-2019-12665")
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

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"129778_cisco_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("cisco_httpclient_fix")

try:
    log.info("Connecting to Cisco device: %s", DEVICE["host"])
    connection = ConnectHandler(**DEVICE)
    connection.enable()
    log.info("✅ Connected and in enable mode")

    # ─── Step 1: Check IOS version ───────────────────────────────
    log.info("\n[1] Checking current IOS version...")
    version_output = connection.send_command("show version")
    log.info(version_output[:500])

    # ─── Step 2: Check HTTP client config ────────────────────────
    log.info("\n[2] Checking HTTP client configuration...")
    http_client = connection.send_command(
        "show running-config | include ip http client"
    )
    log.info("HTTP Client Config:\n%s", http_client)

    # Check if HTTP client is used for any feature
    crypto_pki = connection.send_command(
        "show running-config | section crypto pki"
    )
    log.info("Crypto PKI Config:\n%s", crypto_pki[:300])

    # Check call-home (uses HTTP client)
    call_home = connection.send_command(
        "show running-config | section call-home"
    )
    log.info("Call-Home Config:\n%s", call_home[:300])

    # ─── Step 3: Backup running config ───────────────────────────
    log.info("\n[3] Backing up running configuration...")
    running_config = connection.send_command("show running-config")
    backup_file = f"cisco_config_backup_{timestamp}.txt"
    with open(backup_file, "w") as f:
        f.write(running_config)
    log.info("✅ Config backed up to: %s", backup_file)

    # ─── Step 4: Apply workaround ─────────────────────────────────
    log.info("\n[4] Applying CVE-2019-12665 workaround...")

    # This vulnerability is in the HTTP CLIENT feature
    # The fix is to:
    # 1. Disable HTTP client persistent connections
    # 2. Force HTTPS for all HTTP client operations
    # 3. Restrict HTTP client via ACL
    # 4. Disable HTTP client if not needed

    config_commands = [
        # Disable HTTP client persistent connections
        # (prevents TCP port reuse attack vector)
        "ip http client connection forceclose",

        # Force secure connections only
        "ip http client secure-trustpoint",

        # Set HTTP client source interface to mgmt
        # (restricts outbound HTTP client traffic)
        "ip http client source-interface Loopback0",

        # Restrict HTTP client connections
        "ip http client connection timeout 30",
        "ip http client connection retry 1",

        # Disable HTTP server (separate from client but good practice)
        "no ip http server",

        # Keep HTTPS server if needed for management
        # "no ip http secure-server",  # uncomment if not needed

        # Restrict call-home to use HTTPS only
        "call-home",
        " transport-protocol https",
    ]

    output = connection.send_config_set(config_commands)
    log.info("Output:\n%s", output)

    # ─── Step 5: Restrict outbound HTTP via ACL ───────────────────
    log.info("\n[5] Applying outbound HTTP restriction ACL...")
    acl_commands = [
        # Block outbound plain HTTP (port 80) from device
        "ip access-list extended HTTP-CLIENT-RESTRICT",
        " deny tcp any any eq 80 log",    # Block plain HTTP out
        " permit ip any any",

        # Note: Apply this ACL outbound on management interface
        # interface GigabitEthernet0/0  (← change to your mgmt int)
        #  ip access-group HTTP-CLIENT-RESTRICT out
    ]
    acl_output = connection.send_config_set(acl_commands)
    log.info("ACL Output:\n%s", acl_output)

    # ─── Step 6: Save configuration ──────────────────────────────
    log.info("\n[6] Saving configuration...")
    save_output = connection.save_config()
    log.info("✅ Configuration saved: %s", save_output)

    # ─── Step 7: Verify workaround ───────────────────────────────
    log.info("\n[7] Verifying workaround...")
    verify_http = connection.send_command(
        "show running-config | include ip http"
    )
    verify_acl = connection.send_command(
        "show ip access-lists HTTP-CLIENT-RESTRICT"
    )
    log.info("HTTP Config after fix:\n%s", verify_http)
    log.info("HTTP Client ACL:\n%s", verify_acl)

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
print("       CSCvf36258")
print("   → Run 129778_CISCO_VERIFY.py to confirm")
print("=" * 60)