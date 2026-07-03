from netmiko import ConnectHandler
import logging
import datetime
import sys
import re

print("=" * 60)
print("Cisco IOS SIP DoS Fix — CVE-2019-12654")
print("Plugin 129694 / Bug CSCvn00218")
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
log_file  = f"129694_cisco_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("cisco_sip_dos_fix")

try:
    log.info("Connecting to Cisco device: %s", DEVICE["host"])
    connection = ConnectHandler(**DEVICE)
    connection.enable()
    log.info("✅ Connected and in enable mode")

    # ─── Step 1: Check IOS version ───────────────────────────────
    log.info("\n[1] Checking current IOS version...")
    version_output = connection.send_command("show version")
    log.info(version_output[:500])

    # ─── Step 2: Check SIP configuration ─────────────────────────
    log.info("\n[2] Checking SIP configuration...")
    sip_output = connection.send_command(
        "show running-config | section sip"
    )
    log.info("SIP Config:\n%s", sip_output)

    sip_enabled = (
        "sip" in sip_output.lower() or
        "voice service voip" in sip_output.lower()
    )
    log.info("   SIP appears active: %s", sip_enabled)

    # ─── Step 3: Check voice service config ───────────────────────
    log.info("\n[3] Checking voice service configuration...")
    voice_output = connection.send_command(
        "show running-config | section voice service"
    )
    log.info("Voice Service Config:\n%s", voice_output)

    # ─── Step 4: Backup running config ───────────────────────────
    log.info("\n[4] Backing up running configuration...")
    running_config = connection.send_command("show running-config")
    backup_file = f"cisco_config_backup_{timestamp}.txt"
    with open(backup_file, "w") as f:
        f.write(running_config)
    log.info("✅ Config backed up to: %s", backup_file)

    # ─── Step 5: Apply workaround ─────────────────────────────────
    log.info("\n[5] Applying CVE-2019-12654 workaround...")
    config_commands = []

    if not sip_enabled:
        # SIP not needed — disable entirely
        log.info("   → SIP not in use — disabling SIP ALG and UDP/TCP listeners")
        config_commands.extend([
            "no ip nat service sip tcp port 5060",
            "no ip nat service sip udp port 5060",
            "voice service voip",
            " no allow-connections sip to sip",
            " no supplementary-service sip refer",
            " no supplementary-service sip handle-replaces",
        ])
    else:
        # SIP needed — apply rate limiting and ACL
        log.info("   → SIP in use — applying CoPP and ACL protection")
        config_commands.extend([
            # Restrict SIP access via ACL
            "ip access-list extended SIP-PROTECT",
            " permit udp 192.168.1.0 0.0.0.255 any eq 5060",
            " permit tcp 192.168.1.0 0.0.0.255 any eq 5060",
            " permit udp 192.168.1.0 0.0.0.255 any eq 5061",
            " deny udp any any eq 5060 log",
            " deny tcp any any eq 5060 log",
            " deny udp any any eq 5061 log",
            " permit ip any any",
        ])

    # Apply CoPP to rate limit SIP traffic on control plane
    config_commands.extend([
        "ip access-list extended SIP-COPP-ACL",
        " permit udp any any eq 5060",
        " permit tcp any any eq 5060",
        " permit udp any any eq 5061",

        "class-map match-all SIP-CLASS",
        " match access-group name SIP-COPP-ACL",

        "policy-map COPP-SIP-POLICY",
        " class SIP-CLASS",
        "  police rate 500 pps",

        "control-plane",
        " service-policy input COPP-SIP-POLICY",
    ])

    output = connection.send_config_set(config_commands)
    log.info("Output:\n%s", output)

    # ─── Step 6: Save configuration ──────────────────────────────
    log.info("\n[6] Saving configuration...")
    save_output = connection.save_config()
    log.info("✅ Configuration saved: %s", save_output)

    # ─── Step 7: Verify workaround ───────────────────────────────
    log.info("\n[7] Verifying workaround...")
    verify_copp = connection.send_command(
        "show policy-map control-plane"
    )
    verify_acl = connection.send_command(
        "show ip access-lists SIP-COPP-ACL"
    )
    log.info("CoPP Policy:\n%s", verify_copp[:500])
    log.info("SIP ACL:\n%s", verify_acl)

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
print("       CSCvn00218")
print("   → Run 129694_CISCO_VERIFY.py to confirm")
print("=" * 60)