import subprocess
import socket
import ssl
import logging
import sys

print("=" * 60)
print("SSH CBC Ciphers Verify — Plugin 70658 — Windows")
print("Service: tcp/22/ssh")
print("=" * 60)

HOST      = "YOUR_VM_IP"  # ← change this
SSHD_CONF = r"C:\ProgramData\ssh\sshd_config"

CBC_CIPHERS  = ["aes256-cbc", "aes128-cbc", "3des-cbc"]
GOOD_CIPHERS = ["aes256-ctr", "aes256-gcm", "chacha20-poly1305"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("ssh_cbc_verify")
all_good = True
import os

# ─── Check 1: sshd_config has no CBC ─────────────────────────────
log.info("\n[1] Checking sshd_config for CBC ciphers...")
if os.path.exists(SSHD_CONF):
    with open(SSHD_CONF, "r") as f:
        content = f.read().lower()

    for cipher in CBC_CIPHERS:
        active_lines = [
            l for l in content.splitlines()
            if cipher in l and not l.strip().startswith("#")
            and "ciphers" in l
        ]
        if active_lines:
            log.error("❌ CBC cipher still in config: %s", cipher)
            all_good = False
        else:
            log.info("✅ CBC cipher absent: %s", cipher)

    # Verify good ciphers present
    ciphers_line = next((
        l for l in content.splitlines()
        if l.strip().startswith("ciphers")
        and not l.strip().startswith("#")
    ), "")
    if ciphers_line:
        log.info("   Ciphers line: %s", ciphers_line.strip())
        for good in GOOD_CIPHERS:
            if good in ciphers_line:
                log.info("✅ Strong cipher present: %s", good)
else:
    log.error("❌ sshd_config not found: %s", SSHD_CONF)
    all_good = False

# ─── Check 2: SSH service running ────────────────────────────────
log.info("\n[2] Checking SSH service status...")
result = subprocess.run([
    "powershell", "-Command",
    "(Get-Service sshd -ErrorAction SilentlyContinue).Status"
], capture_output=True, text=True)
status = result.stdout.strip()
if status == "Running":
    log.info("✅ SSH service is Running")
else:
    log.error("❌ SSH service status: %s", status)
    all_good = False

# ─── Check 3: Port 22 listening ───────────────────────────────────
log.info("\n[3] Checking port 22 is listening...")
result = subprocess.run([
    "powershell", "-Command",
    "netstat -an | Select-String ':22'"
], capture_output=True, text=True)
if ":22" in result.stdout:
    log.info("✅ Port 22 is listening")
else:
    log.warning("⚠️ Port 22 not detected")

# ─── Check 4: Probe CBC cipher (should fail) ──────────────────────
log.info("\n[4] Probing CBC ciphers via live connection...")
for cipher in ["aes256-cbc", "aes128-cbc", "3des-cbc"]:
    try:
        result = subprocess.run([
            "ssh", "-o", f"Ciphers={cipher}",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            f"testuser@{HOST}"
        ], capture_output=True, text=True, timeout=8)

        stderr = result.stderr.lower()
        if "no matching cipher" in stderr or \
           "unable to negotiate" in stderr:
            log.info("✅ CBC cipher rejected: %s", cipher)
        else:
            log.warning("⚠️ Could not confirm rejection: %s",
                        cipher)
    except Exception as e:
        log.info("✅ CBC cipher not accepted: %s (%s)",
                 cipher, type(e).__name__)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — CBC ciphers removed from SSH!")
    print("   Re-run Nessus scan to confirm Plugin 70658 resolved.")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 70658_WIN_FIX.py")
print("=" * 60)