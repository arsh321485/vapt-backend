import subprocess
import socket
import sys
import logging

print("=" * 60)
print("ICMP Timestamp Disclosure Verify — CVE-1999-0524")
print("Plugin 10114 — Windows")
print("=" * 60)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("icmp_timestamp_verify")
all_good = True

# ─── Check 1: Inbound ICMP type 13 rule exists ───────────────────
log.info("\n[1] Checking inbound ICMP timestamp block rule...")
result = subprocess.run([
    "netsh", "advfirewall", "firewall", "show", "rule",
    "name=Block ICMP Timestamp Request Inbound"
], capture_output=True, text=True)

if "Block" in result.stdout and "Enabled:                              Yes" in result.stdout:
    log.info("✅ Inbound ICMP timestamp request (type 13) rule is ACTIVE")
else:
    log.error("❌ Inbound ICMP type 13 block rule NOT found or not enabled!")
    all_good = False

# ─── Check 2: Outbound ICMP type 14 rule exists ──────────────────
log.info("\n[2] Checking outbound ICMP timestamp reply block rule...")
result2 = subprocess.run([
    "netsh", "advfirewall", "firewall", "show", "rule",
    "name=Block ICMP Timestamp Reply Outbound"
], capture_output=True, text=True)

if "Block" in result2.stdout and "Enabled:                              Yes" in result2.stdout:
    log.info("✅ Outbound ICMP timestamp reply (type 14) rule is ACTIVE")
else:
    log.error("❌ Outbound ICMP type 14 block rule NOT found or not enabled!")
    all_good = False

# ─── Check 3: PowerShell rule verification ───────────────────────
log.info("\n[3] Checking PowerShell firewall rules...")
result3 = subprocess.run([
    "powershell", "-Command",
    "Get-NetFirewallRule | Where-Object {$_.DisplayName -like '*ICMP Timestamp*'} "
    "| Select-Object DisplayName, Enabled, Direction, Action | Format-List"
], capture_output=True, text=True)

if result3.stdout.strip():
    log.info("✅ PowerShell firewall rules found:\n%s", result3.stdout.strip())
else:
    log.warning("⚠️ No PowerShell ICMP timestamp rules found")

# ─── Check 4: Windows Firewall is enabled ────────────────────────
log.info("\n[4] Checking Windows Firewall status...")
result4 = subprocess.run([
    "netsh", "advfirewall", "show", "allprofiles", "state"
], capture_output=True, text=True)
log.info("   Firewall status:\n%s", result4.stdout.strip())

if "ON" in result4.stdout:
    log.info("✅ Windows Firewall is ON")
else:
    log.error("❌ Windows Firewall appears to be OFF!")
    all_good = False

# ─── Check 5: List all ICMP rules ────────────────────────────────
log.info("\n[5] Listing all ICMP-related firewall rules...")
result5 = subprocess.run([
    "powershell", "-Command",
    "Get-NetFirewallRule | Where-Object {$_.DisplayName -like '*ICMP*'} "
    "| Select-Object DisplayName, Enabled, Direction, Action | Format-Table -AutoSize"
], capture_output=True, text=True)
log.info("   ICMP Rules:\n%s", result5.stdout.strip())

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — ICMP timestamp is blocked!")
    print("   Re-run Nessus scan to confirm Plugin 10114 resolved.")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 10114_WIN_FIX.py")
print("=" * 60)