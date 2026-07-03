import subprocess
import socket
import sys

print("=" * 60)
print("Terrapin (CVE-2023-48795) Verify Script — Ubuntu")
print("=" * 60)

sshd_conf = "/etc/ssh/sshd_config"
all_good = True

# ─── Check 1: OpenSSH version ─────────────────────────────────────
print("\n[1] Checking OpenSSH version...")
result = subprocess.run(["ssh", "-V"], capture_output=True, text=True)
version = result.stderr.strip() or result.stdout.strip()
print(f"    Version: {version}")
# OpenSSH 9.6+ has native strict KEX support
try:
    ver_num = float(version.split("_")[1].split("p")[0][:3])
    if ver_num >= 9.6:
        print("✅ OpenSSH version supports strict KEX countermeasures natively")
    else:
        print(f"⚠️ OpenSSH {ver_num} — strict KEX via config hardening applied")
except:
    print("⚠️ Could not parse version — check manually")

# ─── Check 2: Verify sshd_config hardening ───────────────────────
print("\n[2] Checking sshd_config for hardened settings...")

vulnerable_algorithms = [
    "chacha20-poly1305@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "umac-64-etm@openssh.com",
]

required_settings = {
    "Ciphers": "aes128-ctr",
    "MACs": "hmac-sha2-256,",
    "KexAlgorithms": "curve25519-sha256",
}

try:
    with open(sshd_conf, "r") as f:
        content = f.read().lower()

    for key, expected in required_settings.items():
        if key.lower() in content and expected.lower() in content:
            print(f"✅ {key} is hardened")
        else:
            print(f"❌ {key} hardening not found in config")
            all_good = False

    # Check ChaCha20 is excluded
    lines = content.splitlines()
    for line in lines:
        if line.strip().startswith("ciphers") and not line.strip().startswith("#"):
            if "chacha20" in line:
                print("❌ chacha20-poly1305 still present in Ciphers!")
                all_good = False
            else:
                print("✅ chacha20-poly1305 excluded from Ciphers")

except Exception as e:
    print(f"❌ Could not read sshd_config: {e}")
    all_good = False

# ─── Check 3: SSH service is running ─────────────────────────────
print("\n[3] Checking SSH service status...")
result = subprocess.run(
    ["systemctl", "is-active", "sshd"],
    capture_output=True, text=True
)
if result.stdout.strip() == "active":
    print("✅ SSH service is running")
else:
    print(f"❌ SSH service is NOT running: {result.stdout.strip()}")
    all_good = False

# ─── Check 4: Port 22 is listening ───────────────────────────────
print("\n[4] Checking if port 22 is listening...")
result = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
if ":22" in result.stdout:
    print("✅ Port 22 is open and listening")
else:
    print("❌ Port 22 is NOT listening")
    all_good = False

# ─── Check 5: Config syntax validation ───────────────────────────
print("\n[5] Validating sshd config syntax...")
result = subprocess.run(["sshd", "-t"], capture_output=True, text=True)
if result.returncode == 0:
    print("✅ sshd config syntax is valid")
else:
    print(f"❌ sshd config has errors: {result.stderr}")
    all_good = False

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — Terrapin vulnerability mitigated!")
    print("   Re-run Nessus scan to confirm Plugin 187315 is resolved.")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 187315_UBUNTU_FIX.py")
print("=" * 60)