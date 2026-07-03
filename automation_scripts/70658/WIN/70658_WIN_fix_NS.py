import subprocess
import os
import shutil
import logging
import sys
import datetime

print("=" * 60)
print("SSH CBC Mode Ciphers Fix — Plugin 70658")
print("CVE-2008-5161 — Windows")
print("Service: tcp/22/ssh")
print("Remove: aes256-cbc, aes128-cbc, 3des-cbc")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"70658_win_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("ssh_cbc_fix")

# ─── Configuration ────────────────────────────────────────────────
SSHD_CONF = r"C:\ProgramData\ssh\sshd_config"

# Allowed ciphers — CTR and GCM only, no CBC
STRONG_CIPHERS = (
    "aes256-ctr,"
    "aes192-ctr,"
    "aes128-ctr,"
    "aes256-gcm@openssh.com,"
    "aes128-gcm@openssh.com,"
    "chacha20-poly1305@openssh.com"
)

# Strong MACs — no CBC-related
STRONG_MACS = (
    "hmac-sha2-512,"
    "hmac-sha2-256,"
    "hmac-sha2-512-etm@openssh.com,"
    "hmac-sha2-256-etm@openssh.com"
)

# ─── Step 1: Check OpenSSH installed ─────────────────────────────
log.info("\n[1] Checking OpenSSH Server installation...")
result = subprocess.run([
    "powershell", "-Command",
    "Get-WindowsCapability -Online -Name OpenSSH.Server* | "
    "Select-Object State"
], capture_output=True, text=True)
log.info("   OpenSSH Status: %s", result.stdout.strip())

# ─── Step 2: Backup sshd_config ──────────────────────────────────
log.info("\n[2] Backing up sshd_config...")
if not os.path.exists(SSHD_CONF):
    log.warning("⚠️ sshd_config not found — starting SSH to generate...")
    subprocess.run([
        "powershell", "-Command", "Start-Service sshd"
    ], capture_output=True)
    import time; time.sleep(3)

if os.path.exists(SSHD_CONF):
    backup = f"{SSHD_CONF}.bak_{timestamp}"
    shutil.copy2(SSHD_CONF, backup)
    log.info("✅ Backup saved: %s", backup)
else:
    log.error("❌ sshd_config not found: %s", SSHD_CONF)
    sys.exit(1)

# ─── Step 3: Read and patch sshd_config ──────────────────────────
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

# Add missing directives
for key, value, was_replaced in [
    ("Ciphers", STRONG_CIPHERS, replaced["Ciphers"]),
    ("MACs",    STRONG_MACS,    replaced["MACs"]),
]:
    if not was_replaced:
        result_lines.append(
            f"\n# Added by 70658_WIN_FIX.py\n{key} {value}\n"
        )
        log.info("✅ Added: %s", key)

with open(SSHD_CONF, "w") as f:
    f.writelines(result_lines)

log.info("✅ sshd_config updated: %s", SSHD_CONF)

# ─── Step 4: Verify no CBC in config ─────────────────────────────
log.info("\n[4] Verifying no CBC ciphers remain...")
with open(SSHD_CONF, "r") as f:
    new_content = f.read().lower()

cbc_ciphers = ["aes256-cbc", "aes128-cbc", "3des-cbc"]
for cipher in cbc_ciphers:
    lines_with_cbc = [
        l for l in new_content.splitlines()
        if cipher in l and not l.strip().startswith("#")
    ]
    if lines_with_cbc:
        log.error("❌ CBC cipher still present: %s", cipher)
    else:
        log.info("✅ CBC cipher removed: %s", cipher)

# ─── Step 5: Restart SSH service ─────────────────────────────────
log.info("\n[5] Restarting SSH service...")
try:
    subprocess.run([
        "powershell", "-Command",
        "Restart-Service sshd -Force"
    ], check=True, capture_output=True)
    log.info("✅ SSH service restarted")
except Exception as e:
    log.error("❌ Could not restart SSH: %s", e)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Log: %s", log_file)
log.info("   → Run 70658_WIN_VERIFY.py to confirm")
log.info("=" * 60)