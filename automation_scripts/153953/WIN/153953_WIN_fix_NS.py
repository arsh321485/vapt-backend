import subprocess
import os
import shutil
import logging
import sys
import datetime

print("=" * 60)
print("SSH Weak KEX Algorithms Fix — Plugin 153953")
print("Windows — Service: tcp/22/ssh")
print("Remove: diffie-hellman-group-exchange-sha1,")
print("        diffie-hellman-group1-sha1,")
print("        diffie-hellman-group14-sha1,")
print("        diffie-hellman-group-exchange-sha256,")
print("        ecdh-sha2-nistp384, rsa1024-sha1")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"153953_win_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("ssh_kex_fix")

SSHD_CONF = r"C:\ProgramData\ssh\sshd_config"

# ─── Strong KEX algorithms only (RFC9142 compliant) ──────────────
STRONG_KEX = (
    "curve25519-sha256,"
    "curve25519-sha256@libssh.org,"
    "ecdh-sha2-nistp256,"
    "ecdh-sha2-nistp521,"
    "diffie-hellman-group16-sha512,"
    "diffie-hellman-group18-sha512,"
    "diffie-hellman-group-exchange-sha256,"
    "kex-strict-s-v00@openssh.com"
)

# Note: diffie-hellman-group-exchange-sha256 is kept
# as it is NOT in the weak list per RFC9142
# Removed: sha1 variants and group1/group14-sha1

STRONG_CIPHERS = (
    "aes256-ctr,aes192-ctr,aes128-ctr,"
    "aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
    "chacha20-poly1305@openssh.com"
)

STRONG_MACS = (
    "hmac-sha2-512,hmac-sha2-256,"
    "hmac-sha2-512-etm@openssh.com,"
    "hmac-sha2-256-etm@openssh.com"
)

# ─── Step 1: Check OpenSSH ────────────────────────────────────────
log.info("\n[1] Checking OpenSSH Server...")
result = subprocess.run([
    "powershell", "-Command",
    "Get-WindowsCapability -Online -Name OpenSSH.Server* | "
    "Select-Object State"
], capture_output=True, text=True)
log.info("   OpenSSH: %s", result.stdout.strip())

# ─── Step 2: Backup sshd_config ──────────────────────────────────
log.info("\n[2] Backing up sshd_config...")
if not os.path.exists(SSHD_CONF):
    log.warning("⚠️ Starting SSH to generate config...")
    subprocess.run([
        "powershell", "-Command", "Start-Service sshd"
    ], capture_output=True)
    import time; time.sleep(3)

if os.path.exists(SSHD_CONF):
    backup = f"{SSHD_CONF}.bak_{timestamp}"
    shutil.copy2(SSHD_CONF, backup)
    log.info("✅ Backup: %s", backup)
else:
    log.error("❌ sshd_config not found: %s", SSHD_CONF)
    sys.exit(1)

# ─── Step 3: Patch sshd_config ───────────────────────────────────
log.info("\n[3] Patching sshd_config — removing weak KEX algorithms...")
with open(SSHD_CONF, "r") as f:
    content = f.read()

lines        = content.splitlines(keepends=True)
result_lines = []
replaced     = {
    "KexAlgorithms": False,
    "Ciphers":       False,
    "MACs":          False
}

DIRECTIVES = {
    "KexAlgorithms": STRONG_KEX,
    "Ciphers":       STRONG_CIPHERS,
    "MACs":          STRONG_MACS,
}

for line in lines:
    stripped = line.strip()
    matched  = False

    for key, value in DIRECTIVES.items():
        if stripped.lower().startswith(key.lower()) and \
           not stripped.startswith("#"):
            result_lines.append(f"{key} {value}\n")
            replaced[key] = True
            log.info("✅ Replaced: %s", key)
            matched = True
            break

    if not matched:
        result_lines.append(line)

# Add missing directives
for key, value in DIRECTIVES.items():
    if not replaced[key]:
        result_lines.append(
            f"\n# Added by 153953_WIN_FIX.py\n{key} {value}\n"
        )
        log.info("✅ Added: %s", key)

with open(SSHD_CONF, "w") as f:
    f.writelines(result_lines)

log.info("✅ sshd_config updated")

# ─── Step 4: Verify weak KEX removed ─────────────────────────────
log.info("\n[4] Verifying weak KEX algorithms removed...")
weak_kex = [
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "gss-gex-sha1",
    "gss-group1-sha1",
    "rsa1024-sha1",
]
with open(SSHD_CONF, "r") as f:
    new_content = f.read().lower()

for kex in weak_kex:
    active = [
        l for l in new_content.splitlines()
        if kex in l and not l.strip().startswith("#")
        and "kexalgorithms" in l
    ]
    if active:
        log.error("❌ Weak KEX still present: %s", kex)
    else:
        log.info("✅ Weak KEX removed: %s", kex)

# ─── Step 5: Restart SSH ──────────────────────────────────────────
log.info("\n[5] Restarting SSH service...")
try:
    subprocess.run([
        "powershell", "-Command",
        "Restart-Service sshd -Force"
    ], check=True, capture_output=True)
    log.info("✅ SSH service restarted")
except Exception as e:
    log.error("❌ Restart failed: %s", e)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied! Run 153953_WIN_VERIFY.py to confirm.")
log.info("   Log: %s", log_file)
log.info("=" * 60)