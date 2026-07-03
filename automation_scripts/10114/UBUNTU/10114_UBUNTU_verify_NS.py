import subprocess
import sys
import logging

print("=" * 60)
print("ICMP Timestamp Disclosure Verify — CVE-1999-0524")
print("Plugin 10114 — Ubuntu")
print("=" * 60)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("icmp_timestamp_verify")
all_good = True

# ─── Check 1: iptables INPUT rule for type 13 ────────────────────
log.info("\n[1] Checking iptables INPUT rule for ICMP type 13...")
result = subprocess.run(
    ["iptables", "-L", "INPUT", "-n", "-v"],
    capture_output=True, text=True
)
if "timestamp-request" in result.stdout or "icmp type 13" in result.stdout:
    log.info("✅ INPUT rule blocking ICMP timestamp-request (type 13) found")
else:
    log.error("❌ No INPUT rule for ICMP timestamp-request found!")
    all_good = False

# ─── Check 2: iptables OUTPUT rule for type 14 ───────────────────
log.info("\n[2] Checking iptables OUTPUT rule for ICMP type 14...")
result2 = subprocess.run(
    ["iptables", "-L", "OUTPUT", "-n", "-v"],
    capture_output=True, text=True
)
if "timestamp-reply" in result2.stdout or "icmp type 14" in result2.stdout:
    log.info("✅ OUTPUT rule blocking ICMP timestamp-reply (type 14) found")
else:
    log.error("❌ No OUTPUT rule for ICMP timestamp-reply found!")
    all_good = False

# ─── Check 3: Rules are persistent ───────────────────────────────
log.info("\n[3] Checking if rules are persistent...")
import os
if os.path.exists("/etc/iptables/rules.v4"):
    with open("/etc/iptables/rules.v4", "r") as f:
        content = f.read()
    if "timestamp" in content:
        log.info("✅ ICMP timestamp rules found in /etc/iptables/rules.v4")
    else:
        log.warning("⚠️ ICMP rules not found in persistent rules file")
else:
    log.warning("⚠️ /etc/iptables/rules.v4 not found — rules may not persist reboot")

# ─── Check 4: UFW rules (if applicable) ──────────────────────────
log.info("\n[4] Checking UFW before.rules...")
ufw_before = "/etc/ufw/before.rules"
if os.path.exists(ufw_before):
    with open(ufw_before, "r") as f:
        content = f.read()
    if "timestamp-request" in content:
        log.info("✅ UFW before.rules has ICMP timestamp block rules")
    else:
        log.warning("⚠️ UFW before.rules does not have ICMP timestamp rules")
else:
    log.info("   UFW not configured — skipping")

# ─── Check 5: Full iptables rule list ────────────────────────────
log.info("\n[5] Full ICMP iptables rules...")
result5 = subprocess.run(
    ["iptables", "-L", "-n", "-v", "--line-numbers"],
    capture_output=True, text=True
)
icmp_lines = [
    l for l in result5.stdout.splitlines()
    if "icmp" in l.lower()
]
if icmp_lines:
    for line in icmp_lines:
        log.info("   %s", line)
else:
    log.warning("⚠️ No ICMP rules found in iptables")

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — ICMP timestamp is blocked!")
    print("   Re-run Nessus scan to confirm Plugin 10114 resolved.")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 10114_UBUNTU_FIX.py")
print("=" * 60)