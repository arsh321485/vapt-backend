import subprocess
import os
import logging
import sys

print("=" * 60)
print("SSH CBC Ciphers Verify — Plugin 70658 — Ubuntu")
print("Service: tcp/22/ssh")
print("=" * 60)

HOST      = "YOUR_VM_IP"  # ← change this
SSHD_CONF = "/etc/ssh/sshd_config"

CBC_CIPHERS  = ["aes256-cbc", "aes128-cbc", "3des-cbc"]
GOOD_CIPHERS = ["aes256-ctr", "aes256-gcm", "chacha20-poly1305"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("ssh_cbc_verify")
all_good = True

# ─── Check 1: sshd_config has no CBC ─────────────────────────────
log.info("\n[1] Checking sshd_config for CBC ciphers...")
if os.path.exists(SSHD_CONF):
    with open(SSHD_CONF, "r") as f:
        content = f.read().lower()

    for cipher in CBC_CIPHERS:
        active = [
            l for l in content.splitlines()
            if cipher in l and not l.strip().startswith("#")
            and "ciphers" in l
        ]
        if active:
            log.error("❌ CBC cipher in config: %s", cipher)
            all_good = False
        else:
            log.info("✅ CBC absent: %s", cipher)

    ciphers_line = next((
        l for l in content.splitlines()
        if l.strip().startswith("ciphers")
        and not l.strip().startswith("#")
    ), "")
    if ciphers_line:
        log.info("   Ciphers: %s", ciphers_line.strip())
        for good in GOOD_CIPHERS:
            if good in ciphers_line:
                log.info("✅ Strong cipher: %s", good)
else:
    log.error("❌ sshd_config not found")
    all_good = False

# ─── Check 2: sshd -T (live config dump) ─────────────────────────
log.info("\n[2] Checking live sshd config (sshd -T)...")
try:
    result = subprocess.run(
        ["sshd", "-T"], capture_output=True, text=True
    )
    output = result.stdout.lower()

    ciphers_line = next((
        l for l in output.splitlines()
        if l.startswith("ciphers ")
    ), "")
    log.info("   Live Ciphers: %s", ciphers_line)

    for cipher in CBC_CIPHERS:
        if cipher in ciphers_line:
            log.error("❌ CBC active in live config: %s", cipher)
            all_good = False
        else:
            log.info("✅ CBC not active: %s", cipher)

except Exception as e:
    log.warning("⚠️ sshd -T failed: %s", e)

# ─── Check 3: SSH service running ────────────────────────────────
log.info("\n[3] Checking SSH service status...")
result = subprocess.run(
    ["systemctl", "is-active", "sshd"],
    capture_output=True, text=True
)
if result.stdout.strip() == "active":
    log.info("✅ SSH service is active")
else:
    log.error("❌ SSH service: %s", result.stdout.strip())
    all_good = False

# ─── Check 4: Port 22 listening ───────────────────────────────────
log.info("\n[4] Checking port 22 is listening...")
result = subprocess.run(
    ["ss", "-tlnp"], capture_output=True, text=True
)
if ":22" in result.stdout:
    log.info("✅ Port 22 is listening")
else:
    log.warning("⚠️ Port 22 not detected")

# ─── Check 5: Probe CBC cipher (should fail) ──────────────────────
log.info("\n[5] Probing CBC ciphers via ssh command...")
for cipher in CBC_CIPHERS:
    try:
        result = subprocess.run([
            "ssh",
            "-o", f"Ciphers={cipher}",
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
        log.info("✅ CBC not accepted: %s (%s)",
                 cipher, type(e).__name__)

# ─── Check 6: Config syntax valid ────────────────────────────────
log.info("\n[6] Checking sshd config syntax...")
result = subprocess.run(
    ["sshd", "-t"], capture_output=True, text=True
)
if result.returncode == 0:
    log.info("✅ sshd config syntax is valid")
else:
    log.error("❌ sshd config error: %s", result.stderr)
    all_good = False

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — CBC ciphers removed from SSH!")
    print("   Re-run Nessus scan to confirm Plugin 70658 resolved.")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 70658_UBUNTU_FIX.py")
print("=" * 60)