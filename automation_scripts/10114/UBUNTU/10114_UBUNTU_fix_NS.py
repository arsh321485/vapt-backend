import subprocess
import os
import shutil
import logging
import sys
import datetime

print("=" * 60)
print("ICMP Timestamp Disclosure Fix — CVE-1999-0524")
print("Plugin 10114 — Ubuntu")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"10114_ubuntu_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("icmp_timestamp_fix")

# ─── Step 1: Backup existing iptables rules ───────────────────────
log.info("\n[1] Backing up existing iptables rules...")
backup_file = f"/etc/iptables_backup_{timestamp}.rules"
try:
    result = subprocess.run(
        ["iptables-save"],
        capture_output=True, text=True
    )
    with open(backup_file, "w") as f:
        f.write(result.stdout)
    log.info("✅ iptables rules backed up to: %s", backup_file)
except Exception as e:
    log.warning("⚠️ Could not backup iptables rules: %s", e)

# ─── Step 2: Block inbound ICMP timestamp requests (type 13) ─────
log.info("\n[2] Blocking inbound ICMP Timestamp Requests (type 13)...")
try:
    subprocess.run([
        "iptables", "-A", "INPUT",
        "-p", "icmp",
        "--icmp-type", "timestamp-request",
        "-j", "DROP"
    ], check=True)
    log.info("✅ Inbound ICMP timestamp requests (type 13) blocked")
except Exception as e:
    log.error("❌ Failed to block inbound ICMP type 13: %s", e)

# ─── Step 3: Block outbound ICMP timestamp replies (type 14) ─────
log.info("\n[3] Blocking outbound ICMP Timestamp Replies (type 14)...")
try:
    subprocess.run([
        "iptables", "-A", "OUTPUT",
        "-p", "icmp",
        "--icmp-type", "timestamp-reply",
        "-j", "DROP"
    ], check=True)
    log.info("✅ Outbound ICMP timestamp replies (type 14) blocked")
except Exception as e:
    log.error("❌ Failed to block outbound ICMP type 14: %s", e)

# ─── Step 4: Make rules persistent ───────────────────────────────
log.info("\n[4] Making iptables rules persistent...")
try:
    # Install iptables-persistent if not present
    subprocess.run([
        "apt-get", "install", "-y", "iptables-persistent"
    ], capture_output=True)

    # Save rules
    subprocess.run([
        "netfilter-persistent", "save"
    ], check=True)
    log.info("✅ Rules saved persistently via netfilter-persistent")
except Exception as e:
    log.warning("⚠️ Could not make persistent via netfilter: %s", e)
    # Fallback: save manually
    try:
        result = subprocess.run(
            ["iptables-save"],
            capture_output=True, text=True
        )
        with open("/etc/iptables/rules.v4", "w") as f:
            f.write(result.stdout)
        log.info("✅ Rules saved to /etc/iptables/rules.v4")
    except Exception as e2:
        log.warning("⚠️ Could not save to rules.v4: %s", e2)

# ─── Step 5: Also apply via ufw if available ─────────────────────
log.info("\n[5] Checking if UFW is available...")
result = subprocess.run(["which", "ufw"], capture_output=True, text=True)
if result.stdout.strip():
    log.info("   UFW found — adding ICMP timestamp block rules...")
    try:
        # UFW doesn't natively support ICMP types
        # Add via before.rules
        ufw_before = "/etc/ufw/before.rules"
        if os.path.exists(ufw_before):
            shutil.copy2(ufw_before,
                        f"{ufw_before}.bak_{timestamp}")

            with open(ufw_before, "r") as f:
                content = f.read()

            icmp_rule = (
                "\n# Block ICMP timestamp requests/replies "
                "- CVE-1999-0524\n"
                "-A ufw-before-input -p icmp "
                "--icmp-type timestamp-request -j DROP\n"
                "-A ufw-before-output -p icmp "
                "--icmp-type timestamp-reply -j DROP\n"
            )

            if "timestamp-request" not in content:
                # Insert before COMMIT line
                content = content.replace(
                    "COMMIT", icmp_rule + "\nCOMMIT"
                )
                with open(ufw_before, "w") as f:
                    f.write(content)
                log.info(
                    "✅ UFW before.rules updated with ICMP block"
                )
                subprocess.run(
                    ["ufw", "reload"], capture_output=True
                )
                log.info("✅ UFW reloaded")
            else:
                log.info(
                    "✅ UFW already has ICMP timestamp rules"
                )
    except Exception as e:
        log.warning("⚠️ UFW update failed: %s", e)
else:
    log.info("   UFW not found — iptables rules applied directly")

# ─── Step 6: Verify rules ─────────────────────────────────────────
log.info("\n[6] Verifying iptables rules...")
result = subprocess.run(
    ["iptables", "-L", "-n", "-v"],
    capture_output=True, text=True
)
icmp_lines = [
    l for l in result.stdout.splitlines()
    if "icmp" in l.lower()
]
for line in icmp_lines:
    log.info("   %s", line)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied! Run 10114_UBUNTU_VERIFY.py to confirm.")
log.info("   Backup: %s", backup_file)
log.info("   Log   : %s", log_file)
log.info("=" * 60)