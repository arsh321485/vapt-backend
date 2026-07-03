from netmiko import ConnectHandler
import logging
import datetime
import sys
import re

print("=" * 60)
print("Cisco IOS H.323 Message Validation DoS Fix — CVE-2016-6384")
print("Plugin 130764 / Bug CSCux04257")
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
log_file  = f"130764_cisco_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("cisco_h323_dos_fix")

try:
    log.info("Connecting to Cisco device: %s", DEVICE["host"])
    connection = ConnectHandler(**DEVICE)
    connection.enable()
    log.info("✅ Connected and in enable mode")

    # ─── Step 1: Check IOS version ───────────────────────────────
    log.info("\n[1] Checking current IOS version...")
    version_output = connection.send_command("show version")
    log.info(version_output[:500])

    # ─── Step 2: Check H.323 configuration ───────────────────────
    log.info("\n[2] Checking H.323 configuration...")
    h323_output = connection.send_command(
        "show running-config | section h323"
    )
    log.info("H.323 Config:\n%s", h323_output)

    # Check gatekeeper config
    gk_output = connection.send_command(
        "show running-config | section gatekeeper"
    )
    log.info("Gatekeeper Config:\n%s", gk_output)

    # Check voice service voip
    voice_output = connection.send_command(
        "show running-config | section voice service"
    )
    log.info("Voice Service Config:\n%s", voice_output)

    h323_active = (
        "h323" in h323_output.lower() or
        "gatekeeper" in gk_output.lower()
    )
    log.info("   H.323 appears active: %s", h323_active)

    # ─── Step 3: Backup running config ───────────────────────────
    log.info("\n[3] Backing up running configuration...")
    running_config = connection.send_command("show running-config")
    backup_file = f"cisco_config_backup_{timestamp}.txt"
    with open(backup_file, "w") as f:
        f.write(running_config)
    log.info("✅ Config backed up to: %s", backup_file)

    # ─── Step 4: Apply workaround ─────────────────────────────────
    log.info("\n[4] Applying CVE-2016-6384 workaround...")
    config_commands = []

    if not h323_active:
        # H.323 not needed — disable entirely
        log.info("   → H.323 not in use — disabling H.323 ALG and listeners")
        config_commands.extend([
            # Disable H.323 via voice service
            "voice service voip",
            " no allow-connections h323 to h323",
            " no allow-connections h323 to sip",
            " no allow-connections sip to h323",
            # Disable H.323 NAT ALG
            "no ip nat service H323",
        ])
    else:
        log.warning(
            "   → H.323 in use — applying CoPP and ACL protection"
        )

    # Apply CoPP to rate limit H.323 traffic on control plane
    # H.323 uses TCP/UDP 1720 (call signaling) and 1719 (RAS)
    config_commands.extend([
        "ip access-list extended H323-COPP-ACL",
        " permit tcp any any eq 1720",   # H.323 call signaling
        " permit udp any any eq 1719",   # H.323 RAS
        " permit tcp any any eq 1719",

        "class-map match-all H323-CLASS",
        " match access-group name H323-COPP-ACL",

        "policy-map COPP-H323-POLICY",
        " class H323-CLASS",
        "  police rate 200 pps",

        "control-plane",
        " service-policy input COPP-H323-POLICY",
    ])

    # Restrict H.323 access via interface ACL
    config_commands.extend([
        "ip access-list extended H323-PROTECT",
        " permit tcp 192.168.1.0 0.0.0.255 any eq 1720",
        " permit udp 192.168.1.0 0.0.0.255 any eq 1719",
        " deny tcp any any eq 1720 log",
        " deny udp any any eq 1719 log",
        " permit ip any any",
    ])

    output = connection.send_config_set(config_commands)
    log.info("Output:\n%s", output)

    # ─── Step 5: Save configuration ──────────────────────────────
    log.info("\n[5] Saving configuration...")
    save_output = connection.save_config()
    log.info("✅ Configuration saved: %s", save_output)

    # ─── Step 6: Verify workaround ───────────────────────────────
    log.info("\n[6] Verifying workaround...")
    verify_copp = connection.send_command(
        "show policy-map control-plane"
    )
    verify_acl = connection.send_command(
        "show ip access-lists H323-COPP-ACL"
    )
    log.info("CoPP Policy:\n%s", verify_copp[:500])
    log.info("H.323 ACL:\n%s", verify_acl)

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
print("       CSCux04257")
print("   → Run 130764_CISCO_VERIFY.py to confirm")
print("=" * 60)