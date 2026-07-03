import subprocess
import os
import shutil
from datetime import datetime

print("=" * 60)
print("Terrapin (CVE-2023-48795) Fix Script — Ubuntu")
print("=" * 60)

sshd_conf = "/etc/ssh/sshd_config"
backup_path = f"{sshd_conf}.bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# ─── Check if OpenSSH is installed ───────────────────────────────
result = subprocess.run(["which", "sshd"], capture_output=True, text=True)
if not result.stdout.strip():
    print("❌ OpenSSH server not found. Installing...")
    subprocess.run(["apt-get", "install", "-y", "openssh-server"], check=True)
else:
    print("✅ OpenSSH server is installed.")

# ─── Backup sshd_config ──────────────────────────────────────────
if os.path.exists(sshd_conf):
    shutil.copy2(sshd_conf, backup_path)
    print(f"✅ Backup saved: {backup_path}")
else:
    print("❌ sshd_config not found!")
    exit(1)

# ─── Read existing config ─────────────────────────────────────────
with open(sshd_conf, "r") as f:
    content = f.read()

# ─── Method 1: Try updating OpenSSH to get strict KEX support ────
print("\nChecking OpenSSH version...")
try:
    result = subprocess.run(["ssh", "-V"], capture_output=True, text=True)
    version_output = result.stderr or result.stdout
    print(f"   Current version: {version_output.strip()}")
    
    print("Attempting OpenSSH update...")
    subprocess.run(["apt-get", "update", "-y"], check=True, capture_output=True)
    subprocess.run(["apt-get", "install", "--only-upgrade", "-y", "openssh-server"],
                   check=True, capture_output=True)
    print("✅ OpenSSH updated successfully!")
except Exception as e:
    print(f"⚠️ Could not update OpenSSH: {e}")

# ─── Method 2: Disable vulnerable algorithms in sshd_config ──────
print("\nApplying cipher/MAC hardening to sshd_config...")

# Directives to add/replace
hardening = {
    "Ciphers": (
        "aes128-ctr,aes192-ctr,aes256-ctr,"
        "aes128-gcm@openssh.com,aes256-gcm@openssh.com"
    ),
    "MACs": (
        "hmac-sha2-256,hmac-sha2-512,"
        "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"
    ),
    "KexAlgorithms": (
        "curve25519-sha256,curve25519-sha256@libssh.org,"
        "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
        "diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,"
        "diffie-hellman-group18-sha512,"
        "kex-strict-s-v00@openssh.com"
    ),
}

lines = content.splitlines(keepends=True)
result_lines = []
replaced_keys = set()

for line in lines:
    stripped = line.strip()
    matched = False
    for key in hardening:
        if stripped.lower().startswith(key.lower()) and not stripped.startswith("#"):
            result_lines.append(f"{key} {hardening[key]}\n")
            replaced_keys.add(key)
            print(f"✅ Replaced: {key}")
            matched = True
            break
    if not matched:
        result_lines.append(line)

# Append any keys not already in config
for key, value in hardening.items():
    if key not in replaced_keys:
        result_lines.append(f"\n# Added by 187315_UBUNTU_FIX.py\n{key} {value}\n")
        print(f"✅ Added: {key}")

with open(sshd_conf, "w") as f:
    f.writelines(result_lines)

print("\n✅ sshd_config hardened successfully!")

# ─── Validate config before restarting ───────────────────────────
print("\nValidating sshd config...")
result = subprocess.run(["sshd", "-t"], capture_output=True, text=True)
if result.returncode != 0:
    print(f"❌ Config validation failed: {result.stderr}")
    print("   Restoring backup...")
    shutil.copy2(backup_path, sshd_conf)
    print("   Backup restored. Fix aborted.")
    exit(1)
else:
    print("✅ Config validation passed!")

# ─── Restart SSH service ──────────────────────────────────────────
print("\nRestarting SSH service...")
try:
    subprocess.run(["systemctl", "restart", "sshd"], check=True)
    print("✅ SSH service restarted successfully!")
except subprocess.CalledProcessError as e:
    print(f"❌ Failed to restart SSH: {e}")

print("\n" + "=" * 60)
print("✅ Fix applied! Run 187315_UBUNTU_VERIFY.py to confirm.")
print("=" * 60)