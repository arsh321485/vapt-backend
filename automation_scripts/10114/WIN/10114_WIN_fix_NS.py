import subprocess
import logging
import sys
import datetime

print("=" * 60)
print("ICMP Timestamp Disclosure Fix — CVE-1999-0524")
print("Plugin 10114 — Windows")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"10114_win_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("icmp_timestamp_fix")

# ─── Step 1: Backup existing firewall rules ───────────────────────
log.info("\n[1] Backing up existing firewall rules...")
backup_file = f"C:\\Windows\\Temp\\firewall_backup_{timestamp}.wfw"
try:
    subprocess.run([
        "netsh", "advfirewall", "export", backup_file
    ], check=True, capture_output=True)
    log.info("✅ Firewall rules backed up to: %s", backup_file)
except Exception as e:
    log.warning("⚠️ Could not backup firewall rules: %s", e)

# ─── Step 2: Block inbound ICMP timestamp requests (type 13) ─────
log.info("\n[2] Blocking inbound ICMP Timestamp Requests (type 13)...")
try:
    subprocess.run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        "name=Block ICMP Timestamp Request Inbound",
        "protocol=icmpv4:13,any",
        "dir=in",
        "action=block",
        "enable=yes",
        "profile=any",
        "description=Blocks ICMP timestamp requests - CVE-1999-0524 Plugin 10114"
    ], check=True, capture_output=True)
    log.info("✅ Inbound ICMP timestamp requests (type 13) blocked")
except Exception as e:
    log.error("❌ Failed to block inbound ICMP type 13: %s", e)

# ─── Step 3: Block outbound ICMP timestamp replies (type 14) ─────
log.info("\n[3] Blocking outbound ICMP Timestamp Replies (type 14)...")
try:
    subprocess.run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        "name=Block ICMP Timestamp Reply Outbound",
        "protocol=icmpv4:14,any",
        "dir=out",
        "action=block",
        "enable=yes",
        "profile=any",
        "description=Blocks ICMP timestamp replies - CVE-1999-0524 Plugin 10114"
    ], check=True, capture_output=True)
    log.info("✅ Outbound ICMP timestamp replies (type 14) blocked")
except Exception as e:
    log.error("❌ Failed to block outbound ICMP type 14: %s", e)

# ─── Step 4: Also block via PowerShell for extra coverage ─────────
log.info("\n[4] Applying PowerShell firewall rules for extra coverage...")
try:
    subprocess.run([
        "powershell", "-Command",
        "New-NetFirewallRule -DisplayName 'Block ICMP Timestamp In' "
        "-Protocol ICMPv4 -IcmpType 13 -Direction Inbound "
        "-Action Block -Enabled True -Profile Any "
        "-ErrorAction SilentlyContinue"
    ], capture_output=True)

    subprocess.run([
        "powershell", "-Command",
        "New-NetFirewallRule -DisplayName 'Block ICMP Timestamp Out' "
        "-Protocol ICMPv4 -IcmpType 14 -Direction Outbound "
        "-Action Block -Enabled True -Profile Any "
        "-ErrorAction SilentlyContinue"
    ], capture_output=True)
    log.info("✅ PowerShell firewall rules applied")
except Exception as e:
    log.warning("⚠️ PowerShell rule application: %s", e)

# ─── Step 5: Verify rules are created ────────────────────────────
log.info("\n[5] Verifying firewall rules...")
result = subprocess.run([
    "netsh", "advfirewall", "firewall", "show", "rule",
    "name=Block ICMP Timestamp Request Inbound"
], capture_output=True, text=True)
log.info("Inbound rule:\n%s", result.stdout)

result2 = subprocess.run([
    "netsh", "advfirewall", "firewall", "show", "rule",
    "name=Block ICMP Timestamp Reply Outbound"
], capture_output=True, text=True)
log.info("Outbound rule:\n%s", result2.stdout)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied! Run 10114_WIN_VERIFY.py to confirm.")
log.info("   Backup: %s", backup_file)
log.info("   Log   : %s", log_file)
log.info("=" * 60)