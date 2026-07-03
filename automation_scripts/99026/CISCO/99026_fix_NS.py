from netmiko import ConnectHandler
import logging
import datetime
import sys
import re

print("=" * 60)
print("Cisco IOS DHCP Client DoS Fix — CVE-2017-3864")
print("Plugin 99026 / Bug CSCuu43892")
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
log_file  = f"99026_cisco_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("cisco_dhcpc_dos_fix")

try:
    log.info("Connecting to Cisco device: %s", DEVICE["host"])
    connection = ConnectHandler(**DEVICE)
    connection.enable()
    log.info("✅ Connected and in enable mode")

    # ─── Step 1: Check IOS version ───────────────────────────────
    log.info("\n[1] Checking current IOS version...")
    version_output = connection.send_command("show version")
    log.info(version_output[:500])

    # ─── Step 2: Check DHCP client config ────────────────────────
    log.info("\n[2] Checking DHCP client configuration...")
    dhcp_client = connection.send_command(
        "show running-config | include ip address dhcp"
    )
    log.info("DHCP Client interfaces:\n%s", dhcp_client)

    interfaces_with_dhcp = [
        line.strip() for line in dhcp_client.splitlines()
        if "ip address dhcp" in line.lower()
    ]
    log.info(
        "   Found %d interface(s) using DHCP client",
        len(interfaces_with_dhcp)
    )

    # ─── Step 3: Check interfaces ─────────────────────────────────
    log.info("\n[3] Checking interface details...")
    interfaces_output = connection.send_command("show ip interface brief")
    log.info("Interfaces:\n%s", interfaces_output)

    # ─── Step 4: Backup running config ───────────────────────────
    log.info("\n[4] Backing up running configuration...")
    running_config = connection.send_command("show running-config")
    backup_file = f"cisco_config_backup_{timestamp}.txt"
    with open(backup_file, "w") as f:
        f.write(running_config)
    log.info("✅ Config backed up to: %s", backup_file)

    # ─── Step 5: Apply workaround ─────────────────────────────────
    log.info("\n[5] Applying CVE-2017-3864 workaround...")

    # This vuln affects DHCP CLIENT (not server)
    # Device is a DHCP client receiving malformed packets
    # Workaround: Apply DHCP packet filtering via ACL on
    # interfaces using DHCP client

    config_commands = [
        # Rate limit DHCP client traffic using CoPP
        # (Control Plane Policing)
        "ip access-list extended DHCP-CLIENT-PROTECT",
        " permit udp any any eq 68",   # DHCP client port
        " permit udp any any eq 67",   # DHCP server port
        " deny ip any any",

        # Apply CoPP policy to protect control plane
        "class-map match-all DHCP-CLASS",
        " match access-group name DHCP-CLIENT-PROTECT",

        "policy-map COPP-DHCP-POLICY",
        " class DHCP-CLASS",
        "  police rate 100 pps",       # Limit DHCP to 100 pps

        # Apply to control plane
        "control-plane",
        " service-policy input COPP-DHCP-POLICY",
    ]

    output = connection.send_config_set(config_commands)
    log.info("CoPP Output:\n%s", output)

    # Additional: If DHCP client not needed on any interface
    # offer option to disable it
    if not interfaces_with_dhcp:
        log.info(
            "\n   No interfaces using DHCP client found — "
            "DHCP client appears inactive"
        )
    else:
        log.warning(
            "\n   ⚠️  %d interface(s) use DHCP client — "
            "CoPP rate limiting applied",
            len(interfaces_with_dhcp)
        )
        log.warning(
            "   Consider using static IP if DHCP client "
            "is not required on these interfaces"
        )

    # ─── Step 6: Save configuration ──────────────────────────────
    log.info("\n[6] Saving configuration...")
    save_output = connection.save_config()
    log.info("✅ Configuration saved: %s", save_output)

    # ─── Step 7: Verify workaround ───────────────────────────────
    log.info("\n[7] Verifying workaround...")
    verify_copp = connection.send_command(
        "show policy-map control-plane"
    )
    log.info("CoPP Policy:\n%s", verify_copp[:500])

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
print("       CSCuu43892")
print("   → Run 99026_CISCO_VERIFY.py to confirm")
print("=" * 60)