from netmiko import ConnectHandler
import logging
import datetime
import sys

print("=" * 60)
print("Cisco IOS AAA SCP Bypass Fix — CVE-2023-20186")
print("Plugin 192250 / Bug CSCwe55871")
print("=" * 60)

# ─── Configuration ────────────────────────────────────────────────
# ← Update these for your environment
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
log_file  = f"192250_cisco_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("cisco_fix")

try:
    log.info("Connecting to Cisco device: %s", DEVICE["host"])
    connection = ConnectHandler(**DEVICE)
    connection.enable()
    log.info("✅ Connected and in enable mode")

    # ─── Step 1: Check current IOS version ───────────────────────
    log.info("\n[1] Checking current IOS version...")
    version_output = connection.send_command("show version")
    log.info(version_output[:500])

    # ─── Step 2: Check current AAA config ────────────────────────
    log.info("\n[2] Checking current AAA configuration...")
    aaa_output = connection.send_command("show running-config | section aaa")
    log.info(aaa_output)

    # ─── Step 3: Check if SCP server is enabled ──────────────────
    log.info("\n[3] Checking if SCP server is enabled...")
    scp_output = connection.send_command(
        "show running-config | include ip scp server"
    )
    if "ip scp server enable" in scp_output:
        log.warning("⚠️ SCP server is ENABLED — applying workaround...")
        scp_enabled = True
    else:
        log.info("✅ SCP server is not enabled")
        scp_enabled = False

    # ─── Step 4: Backup running config ───────────────────────────
    log.info("\n[4] Backing up running configuration...")
    running_config = connection.send_command("show running-config")
    backup_file = f"cisco_config_backup_{timestamp}.txt"
    with open(backup_file, "w") as f:
        f.write(running_config)
    log.info("✅ Config backed up to: %s", backup_file)

    # ─── Step 5: Apply workaround ─────────────────────────────────
    # Workaround: Disable SCP server if not needed
    # OR restrict AAA authorization for SCP
    log.info("\n[5] Applying CVE-2023-20186 workaround...")

    config_commands = []

    if scp_enabled:
        # Option A: Disable SCP server entirely (recommended if not needed)
        config_commands.append("no ip scp server enable")
        log.info("   → Disabling SCP server (recommended workaround)")
    else:
        # Option B: Add explicit AAA authorization for SCP
        # Restrict SCP access via AAA
        config_commands.extend([
            "aaa authorization exec default local",
            "aaa authorization commands 15 default local",
        ])
        log.info("   → Applying AAA authorization restrictions for SCP")

    # Apply the commands
    output = connection.send_config_set(config_commands)
    log.info("Output:\n%s", output)

    # ─── Step 6: Save configuration ──────────────────────────────
    log.info("\n[6] Saving configuration...")
    save_output = connection.save_config()
    log.info("✅ Configuration saved: %s", save_output)

    # ─── Step 7: Verify workaround applied ───────────────────────
    log.info("\n[7] Verifying workaround...")
    verify_scp = connection.send_command(
        "show running-config | include ip scp server"
    )
    verify_aaa = connection.send_command(
        "show running-config | section aaa"
    )

    if "ip scp server enable" not in verify_scp:
        log.info("✅ SCP server is disabled — workaround applied!")
    else:
        log.warning("⚠️ SCP server still enabled — check manually")

    log.info("\nAAA Configuration:\n%s", verify_aaa)

    connection.disconnect()
    log.info("✅ Disconnected from device")

except Exception as e:
    log.error("❌ Error: %s", e)
    sys.exit(1)

print("\n" + "=" * 60)
print("✅ Workaround applied!")
print(f"   Backup : {backup_file}")
print(f"   Log    : {log_file}")
print("   ⚠️  Permanent fix: Upgrade IOS to fixed release")
print("       per Cisco Bug ID CSCwe55871 advisory")
print("   → Run 192250_CISCO_VERIFY.py to confirm")
print("=" * 60)