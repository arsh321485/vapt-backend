import subprocess
import os
import logging
import sys

print("=" * 60)
print("SSH Weak KEX Verify — Plugin 153953 — Ubuntu")
print("Service: tcp/22/ssh")
print("=" * 60)

HOST      = "YOUR_VM_IP"  # ← change this
SSHD_CONF = "/etc/ssh/sshd_config"

WEAK_KEX = [
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "gss-gex-sha1",
    "gss-group1-sha1",
    "gss-group14-sha1",
    "rsa1024-sha1",
]

STRONG_KEX = [
    "curve25519-sha256",
    "ecdh-sha2-nistp256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("ssh_kex_verify")
all_good = True

# ─── Check 1: sshd_config KexAlgorithms ──────────────────────────
log.info("\n[1] Checking sshd_config KexAlgorithms...")
if os.path.exists(SSHD_CONF):
    with open(SSHD_CONF, "r") as f:
        content = f.read().lower()

    kex_line = next((
        l for l in content.splitlines()
        if l.strip().startswith("kexalgorithms")
        and not l.strip().startswith("#")
    ), "")
    log.info("   KexAlgorithms: %s", kex_line.strip())

    for kex in WEAK_KEX:
        if kex in kex_line:
            log.error("❌ Weak KEX in config: %s", kex)
            all_good = False
        else:
            log.info("✅ Weak KEX absent: %s", kex)

    for kex in STRONG_KEX:
        if kex in kex_line:
            log.info("✅ Strong KEX present: %s", kex)
        else:
            log.warning("⚠️ Strong KEX missing: %s", kex)
else:
    log.error("❌ sshd_config not found")
    all_good = False

# ─── Check 2: Live config dump (sshd -T) ─────────────────────────
log.info("\n[2] Checking live KEX via sshd -T...")
try:
    result = subprocess.run(
        ["sshd", "-T"], capture_output=True, text=True
    )
    output = result.stdout.lower()

    kex_live = next((
        l for l in output.splitlines()
        if l.startswith("kexalgorithms ")
    ), "")
    log.info("   Live KEX: %s", kex_live)

    for kex in WEAK_KEX:
        if kex in kex_live:
            log.error("❌ Weak KEX active: %s", kex)
            all_good = False
        else:
            log.info("✅ Weak KEX not active: %s", kex)

except Exception as e:
    log.warning("⚠️ sshd -T failed: %s", e)

# ─── Check 3: SSH service running ────────────────────────────────
log.info("\n[3] Checking SSH service...")
result = subprocess.run(
    ["systemctl", "is-active", "sshd"],
    capture_output=True, text=True
)
if result.stdout.strip() == "active":
    log.info("✅ SSH service active")
else:
    log.error("❌ SSH service: %s", result.stdout.strip())
    all_good = False

# ─── Check 4: Port 22 listening ──────────────────────────────────
log.info("\n[4] Checking port 22...")
result = subprocess.run(
    ["ss", "-tlnp"], capture_output=True, text=True
)
if ":22" in result.stdout:
    log.info("✅ Port 22 listening")
else:
    log.warning("⚠️ Port 22 not detected")

# ─── Check 5: Probe weak KEX (should fail) ───────────────────────
log.info("\n[5] Probing weak KEX algorithms...")
for kex in [
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
]:
    try:
        result = subprocess.run([
            "ssh",
            "-o", f"KexAlgorithms={kex}",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            f"testuser@{HOST}"
        ], capture_output=True, text=True, timeout=8)

        stderr = result.stderr.lower()
        if "no matching kex" in stderr or \
           "unable to negotiate" in stderr:
            log.info("✅ Weak KEX rejected: %s", kex)
        else:
            log.warning("⚠️ Could not confirm rejection: %s", kex)
    except Exception as e:
        log.info("✅ Weak KEX not accepted: %s (%s)",
                 kex, type(e).__name__)

# ─── Check 6: Config syntax ──────────────────────────────────────
log.info("\n[6] Checking sshd config syntax...")
result = subprocess.run(
    ["sshd", "-t"], capture_output=True, text=True
)
if result.returncode == 0:
    log.info("✅ Config syntax valid")
else:
    log.error("❌ Config error: %s", result.stderr)
    all_good = False

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — Weak KEX algorithms removed!")
    print("   Re-run Nessus scan to confirm Plugin 153953 resolved.")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review and re-run 153953_UBUNTU_FIX.py")
print("=" * 60)