#!/usr/bin/env python3
"""
Fix Script - Plugin 94762
Cisco IOS IKEv1 Fragmentation DoS
Workaround: Disable IKEv1 fragmentation via 'no crypto isakmp fragmentation'
Target: Cisco IOS device (SSH)
"""

from netmiko import ConnectHandler
import datetime
import sys

# ─── CONFIGURATION ────────────────────────────────────────────────
DEVICE = {
    "device_type": "cisco_ios",
    "host": "192.168.1.1",        # <-- Replace with your device IP
    "username": "admin",           # <-- Replace with your username
    "password": "yourpassword",    # <-- Replace with your password
    "secret": "yourenable",        # <-- Replace with enable secret (if needed)
    "port": 22,
    "timeout": 30,
}

LOG_FILE = "fix_94762_log.txt"

def log(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def backup_config(connection):
    log("Taking running config backup...")
    config = connection.send_command("show running-config")
    backup_file = f"backup_config_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(backup_file, "w") as f:
        f.write(config)
    log(f"Config backed up to {backup_file}")

def apply_fix(connection):
    log("Applying fix: 'no crypto isakmp fragmentation'")
    commands = [
        "no crypto isakmp fragmentation"
    ]
    output = connection.send_config_set(commands)
    log("Fix commands output:")
    log(output)

    # Save config
    log("Saving configuration (write memory)...")
    save_output = connection.send_command("write memory")
    log(save_output)

def main():
    log("="*60)
    log("Starting Fix for Plugin 94762 - Cisco IKEv1 Fragmentation DoS")
    log("="*60)

    try:
        log(f"Connecting to device: {DEVICE['host']}")
        connection = ConnectHandler(**DEVICE)
        connection.enable()
        log("Connected and in enable mode.")

        # Step 1: Backup
        backup_config(connection)

        # Step 2: Show current state
        log("Checking current IKEv1 fragmentation state...")
        current = connection.send_command("show running-config | include fragmentation")
        log(f"Current fragmentation config: '{current.strip() or 'not explicitly set (default may be enabled)'}'")

        # Step 3: Apply fix
        apply_fix(connection)

        log("Fix applied successfully.")
        connection.disconnect()
        log("Disconnected from device.")

    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()