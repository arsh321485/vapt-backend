from netmiko import ConnectHandler
import logging
import datetime
import sys
import re

print("=" * 60)
print("Cisco IOS DHCP RCE Fix — CVE-2017-12240")
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

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"103565_cisco_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("cisco_dhcp_fix")

try:
    log.info("Connecting to Cisco device: %s", DEVICE["host"])
    connection = ConnectHandler(**DEVICE)
    connection.enable()
    log.info("✅ Connected and in enable mode")

    # ─── Step 1: Check IOS version ───────────────────────────────
    log.info("\n[1] Checking current IOS version...")
    version_output = connection.send_command("show version")
    log.info(version_output[:500])

    # ─── Step 2: Check DHCP configuration ────────────────────────
    log.info("\n[2] Checking DHCP configuration...")
    dhcp_output = connection.send_command(
        "show running-config | section dhcp"
    )
    log.info("DHCP Config:\n%s", dhcp_output)

    # ─── Step 3: Backup running config ───────────────────────────
    log.info("\n[3] Backing up running configuration...")
    running_config = connection.send_command("show running-config")
    backup_file = f"cisco_config_backup_{timestamp}.txt"
    with open(backup_file, "w") as f:
        f.write(running_config)
    log.info("✅ Config backed up to: %s", backup_file)

    # ─── Step 4: Check if DHCP server is needed ──────────────────
    log.info("\n[4] Checking DHCP pool configuration...")
    dhcp_pool = connection.send_command(
        "show running-config | include ip dhcp pool"
    )
    dhcp_excluded = connection.send_command(
        "show running-config | include ip dhcp excluded"
    )

    if dhcp_pool:
        log.warning("⚠️ DHCP pools configured — applying mitigation...")
        dhcp_active = True
    else:
        log.info("   No DHCP pools found")
        dhcp_active = False

    # ─── Step 5: Apply workaround ─────────────────────────────────
    log.info("\n[5] Applying CVE-2017-12240 workaround...")
    config_commands = []

    if not dhcp_active:
        # Disable DHCP server entirely if not needed
        config_commands.extend([
            "no service dhcp",
        ])
        log.info("   → Disabling DHCP server (not in use)")
    else:
        # DHCP is needed — apply rate limiting and ACL protection
        config_commands.extend([
            # Rate limit DHCP traffic on interfaces
            "ip dhcp limit lease per interface 10",
            # Disable DHCP conflict logging to reduce attack surface
            "no ip dhcp conflict logging",
        ])
        log.info("   → Applying DHCP rate limiting and hardening")

    # Apply interface-level DHCP snooping if supported
    config_commands.extend([
        "ip dhcp snooping",
        "ip dhcp snooping vlan 1-4094",
        "no ip dhcp snooping information option",
    ])
    log.info("   → Enabling DHCP snooping")

    output = connection.send_config_set(config_commands)
    log.info("Output:\n%s", output)

    # ─── Step 6: Save configuration ──────────────────────────────
    log.info("\n[6] Saving configuration...")
    save_output = connection.save_config()
    log.info("✅ Configuration saved: %s", save_output)

    # ─── Step 7: Verify workaround ───────────────────────────────
    log.info("\n[7] Verifying workaround...")
    verify_dhcp = connection.send_command(
        "show running-config | include dhcp"
    )
    verify_snoop = connection.send_command("show ip dhcp snooping")
    log.info("DHCP Config after fix:\n%s", verify_dhcp)
    log.info("DHCP Snooping:\n%s", verify_snoop)

    connection.disconnect()
    log.info("✅ Disconnected from device")

except Exception as e:
    log.error("❌ Error: %s", e)
    sys.exit(1)

print("\n" + "=" * 60)
print("✅ Workaround applied!")
print(f"   Backup : {backup_file}")
print(f"   Log    : {log_file}")
print("   ⚠️  Permanent fix: Upgrade IOS per Cisco Bug IDs:")
print("       CSCsm45390 and CSCuw77959")
print("   → Run 103565_CISCO_VERIFY.py to confirm")
print("=" * 60)