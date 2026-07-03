from netmiko import ConnectHandler
import logging
import datetime
import sys
import re

print("=" * 60)
print("Cisco IOS AAA Login DoS Fix — CVE-2016-6393")
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

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"131164_cisco_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("cisco_aaa_dos_fix")

try:
    log.info("Connecting to Cisco device: %s", DEVICE["host"])
    connection = ConnectHandler(**DEVICE)
    connection.enable()
    log.info("✅ Connected and in enable mode")

    # ─── Step 1: Check IOS version ───────────────────────────────
    log.info("\n[1] Checking current IOS version...")
    version_output = connection.send_command("show version")
    log.info(version_output[:500])

    # ─── Step 2: Check AAA and SSH config ────────────────────────
    log.info("\n[2] Checking AAA configuration...")
    aaa_output = connection.send_command(
        "show running-config | section aaa"
    )
    log.info("AAA Config:\n%s", aaa_output)

    log.info("\n[3] Checking SSH configuration...")
    ssh_output = connection.send_command(
        "show running-config | section ssh"
    )
    log.info("SSH Config:\n%s", ssh_output)

    # ─── Step 3: Backup running config ───────────────────────────
    log.info("\n[4] Backing up running configuration...")
    running_config = connection.send_command("show running-config")
    backup_file = f"cisco_config_backup_{timestamp}.txt"
    with open(backup_file, "w") as f:
        f.write(running_config)
    log.info("✅ Config backed up to: %s", backup_file)

    # ─── Step 4: Apply workaround ─────────────────────────────────
    log.info("\n[5] Applying CVE-2016-6393 workaround...")

    config_commands = [
        # Workaround 1: Set SSH login timeout to reduce DoS window
        "ip ssh time-out 60",
        "ip ssh authentication-retries 3",

        # Workaround 2: Limit SSH connections per minute via login block
        "login block-for 30 attempts 3 within 60",
        "login quiet-mode access-class 10",
        "login on-failure log",
        "login on-success log",

        # Workaround 3: Restrict SSH access via ACL
        "ip access-list standard 10",
        " permit 192.168.1.0 0.0.0.255",  # ← change to your mgmt subnet
        " deny any log",

        # Workaround 4: Use local AAA as fallback
        "aaa new-model",
        "aaa authentication login default local",
        "aaa authentication login ssh-login local",
        "aaa authorization exec default local",

        # Workaround 5: Apply ACL to VTY lines
        "line vty 0 4",
        " access-class 10 in",
        " login authentication ssh-login",
        " transport input ssh",
        " exec-timeout 10 0",
        "line vty 5 15",
        " access-class 10 in",
        " login authentication ssh-login",
        " transport input ssh",
        " exec-timeout 10 0",
    ]

    output = connection.send_config_set(config_commands)
    log.info("Output:\n%s", output)

    # ─── Step 5: Save configuration ──────────────────────────────
    log.info("\n[6] Saving configuration...")
    save_output = connection.save_config()
    log.info("✅ Configuration saved: %s", save_output)

    # ─── Step 6: Verify workaround ───────────────────────────────
    log.info("\n[7] Verifying workaround...")
    verify_ssh   = connection.send_command(
        "show running-config | include ip ssh"
    )
    verify_login = connection.send_command(
        "show running-config | include login"
    )
    verify_vty   = connection.send_command(
        "show running-config | section line vty"
    )
    log.info("SSH Config after fix:\n%s", verify_ssh)
    log.info("Login Config:\n%s", verify_login)
    log.info("VTY Config:\n%s", verify_vty)

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
print("       CSCuy87667")
print("   → Run 131164_CISCO_VERIFY.py to confirm")
print("=" * 60)