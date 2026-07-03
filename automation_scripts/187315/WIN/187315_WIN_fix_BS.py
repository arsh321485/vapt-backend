import subprocess
import os
import shutil
from datetime import datetime

print("=" * 60)
print("Terrapin (CVE-2023-48795) Fix Script — Windows")
print("=" * 60)

# Windows OpenSSH sshd_config path
sshd_conf = r"C:\ProgramData\ssh\sshd_config"
backup_path = (
    f"C:\\ProgramData\\ssh\\sshd_config.bak_"
    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
)

# ─── Check if OpenSSH is installed ───────────────────────────────
print("\nChecking OpenSSH installation...")
result = subprocess.run(
    ["powershell", "-Command",
     "Get-WindowsCapability -Online -Name OpenSSH.Server*"],
    capture_output=True, text=True
)
if "Installed" in result.stdout:
    print("✅ OpenSSH Server is installed.")
else:
    print("Installing OpenSSH Server...")
    subprocess.run([
        "powershell", "-Command",
        "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
    ], check=True)
    print("✅ OpenSSH Server installed!")

# ─── Check/Create sshd_config ────────────────────────────────────
if not os.path.exists(sshd_conf):
    print(f"⚠️ sshd_config not found at {sshd_conf}")
    print("   Starting SSH service to generate default config...")
    subprocess.run(["powershell", "-Command", "Start-Service sshd"],
                   capture_output=True)

# ─── Backup sshd_config ──────────────────────────────────────────
if os.path.exists(sshd_conf):
    shutil.copy2(sshd_conf, backup_path)
    print(f"✅ Backup saved: {backup_path}")
else:
    print("❌ Could not find or create sshd_config. Aborting.")
    exit(1)

# ─── Try updating OpenSSH via winget ─────────────────────────────
print("\nAttempting OpenSSH update via winget...")
try:
    subprocess.run(
        ["winget", "upgrade", "Microsoft.OpenSSH.Beta", "--silent"],
        check=True, capture_output=True
    )
    print("✅ OpenSSH updated via winget!")
except Exception:
    print("⚠️ winget update not available — applying config hardening...")

# ─── Read and patch sshd_config ──────────────────────────────────
print("\nApplying cipher/MAC hardening to sshd_config...")

with open(sshd_conf, "r") as f:
    content = f.read()

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

for key, value in hardening.items():
    if key not in replaced_keys:
        result_lines.append(f"\n# Added by 187315_WIN_FIX.py\n{key} {value}\n")
        print(f"✅ Added: {key}")

with open(sshd_conf, "w") as f:
    f.writelines(result_lines)

print("\n✅ sshd_config hardened successfully!")

# ─── Restart SSH service ──────────────────────────────────────────
print("\nRestarting OpenSSH service...")
try:
    subprocess.run(["powershell", "-Command", "Restart-Service sshd"],
                   check=True)
    print("✅ SSH service restarted!")
except Exception as e:
    print(f"❌ Failed to restart SSH service: {e}")

# ─── Enable SSH service on boot ───────────────────────────────────
try:
    subprocess.run([
        "powershell", "-Command",
        "Set-Service -Name sshd -StartupType Automatic"
    ], check=True)
    print("✅ SSH service set to start automatically on boot")
except Exception as e:
    print(f"⚠️ Could not set startup type: {e}")

print("\n" + "=" * 60)
print("✅ Fix applied! Run 187315_WIN_VERIFY.py to confirm.")
print("=" * 60)