import subprocess
import os
import shutil
import logging
import sys
import datetime

print("=" * 60)
print("SSH CBC Mode Ciphers Fix — Plugin 70658")
print("CVE-2008-5161 — Ubuntu")
print("Service: tcp/22/ssh")
print("Remove: aes256-cbc, aes128-cbc, 3des-cbc")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"70658_ubuntu_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("ssh_cbc_fix")

SSHD_CONF = "/etc/ssh/sshd_config"

# Allowed ciphers — CTR and GCM only, NO CBC
STRONG_CIPHERS = (
    "aes256-ctr,"
    "aes192-ctr,"
    "aes128-ctr,"
    "aes256-gcm@openssh.com,"
    "aes128-gcm@openssh.com,"
    "chacha20-poly1305@openssh.com"
)

STRONG_MACS = (
    "hmac-sha2-512,"
    "hmac-sha2-256,"
    "hmac-sha2-512-etm@openssh.com,"
    "hmac-sha2-256-etm@openssh.com"
)

# ─── Step 1: Check OpenSSH installed ─────────────────────────────
log.info("\n[1] Checking OpenSSH Server...")
result = subprocess.run(
    ["which", "sshd"], capture_output=True, text=True
)
if result.stdout.strip():
    version = subprocess.run(
        ["ssh", "-V"], capture_output=True, text=True
    )
    log.info("✅ OpenSSH: %s",
             version.stderr.strip() or version.stdout.strip())
else:
    log.warning("⚠️ sshd not found — installing...")
    subprocess.run([
        "apt-get", "install", "-y", "openssh-server"
    ], check=True, capture_output=True)
    log.info("✅ OpenSSH installed")

# ─── Step 2: Backup sshd_config ──────────────────────────────────
log.info("\n[2] Backing up sshd_config...")
if os.path.exists(SSHD_CONF):
    backup = f"{SSHD_CONF}.bak_{timestamp}"
    shutil.copy2(SSHD_CONF, backup)
    log.info("✅ Backup saved: %s", backup)
else:
    log.error("❌ sshd_config not found: %s", SSHD_CONF)
    sys.exit(1)

# ─── Step 3: Patch sshd_config ───────────────────────────────────
log.info("\n[3] Patching sshd_config to remove CBC ciphers...")
with open(SSHD_CONF, "r") as f:
    content = f.read()

lines        = content.splitlines(keepends=True)
result_lines = []
replaced     = {"Ciphers": False, "MACs": False}

for line in lines:
    stripped = line.strip()

    if stripped.lower().startswith("ciphers") and \
       not stripped.startswith("#"):
        result_lines.append(f"Ciphers {STRONG_CIPHERS}\n")
        replaced["Ciphers"] = True
        log.info("✅ Replaced Ciphers directive")

    elif stripped.lower().startswith("macs") and \
         not stripped.startswith("#"):
        result_lines.append(f"MACs {STRONG_MACS}\n")
        replaced["MACs"] = True
        log.info("✅ Replaced MACs directive")

    else:
        result_lines.append(line)

# Add if not found
for key, value, was_replaced in [
    ("Ciphers", STRONG_CIPHERS, replaced["Ciphers"]),
    ("MACs",    STRONG_MACS,    replaced["MACs"]),
]:
    if not was_replaced:
        result_lines.append(
            f"\n# Added by 70658_UBUNTU_FIX.py\n{key} {value}\n"
        )
        log.info("✅ Added: %s", key)

with open(SSHD_CONF, "w") as f:
    f.writelines(result_lines)

log.info("✅ sshd_config updated")

# ─── Step 4: Validate config ─────────────────────────────────────
log.info("\n[4] Validating sshd config syntax...")
result = subprocess.run(
    ["sshd", "-t"], capture_output=True, text=True
)
if result.returncode == 0:
    log.info("✅ sshd config is valid")
else:
    log.error("❌ Config invalid: %s", result.stderr)
    log.warning("   Restoring backup...")
    shutil.copy2(backup, SSHD_CONF)
    log.info("   Backup restored")
    sys.exit(1)

# ─── Step 5: Verify no CBC remains ───────────────────────────────
log.info("\n[5] Verifying no CBC ciphers remain in config...")
with open(SSHD_CONF, "r") as f:
    new_content = f.read().lower()

cbc_ciphers = ["aes256-cbc", "aes128-cbc", "3des-cbc"]
for cipher in cbc_ciphers:
    active = [
        l for l in new_content.splitlines()
        if cipher in l and not l.strip().startswith("#")
        and "ciphers" in l
    ]
    if active:
        log.error("❌ CBC still present: %s", cipher)
    else:
        log.info("✅ CBC removed: %s", cipher)

# ─── Step 6: Restart SSH service ─────────────────────────────────
log.info("\n[6] Restarting SSH service...")
try:
    subprocess.run(
        ["systemctl", "restart", "sshd"], check=True
    )
    log.info("✅ SSH service restarted")
except Exception as e:
    log.error("❌ Could not restart SSH: %s", e)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Log: %s", log_file)
log.info("   → Run 70658_UBUNTU_VERIFY.py to confirm")
log.info("=" * 60)