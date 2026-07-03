import subprocess
import os

print("=" * 60)
print("Terrapin (CVE-2023-48795) Verify Script — Windows")
print("=" * 60)

sshd_conf = r"C:\ProgramData\ssh\sshd_config"
all_good = True

# ─── Check 1: OpenSSH version ─────────────────────────────────────
print("\n[1] Checking OpenSSH version...")
result = subprocess.run(["ssh", "-V"], capture_output=True, text=True)
version = result.stderr.strip() or result.stdout.strip()
print(f"    Version: {version}")
try:
    ver_num = float(version.split("_")[1].split("p")[0][:3])
    if ver_num >= 9.6:
        print("✅ OpenSSH version supports strict KEX natively")
    else:
        print(f"⚠️ OpenSSH {ver_num} — verify config hardening is applied")
except:
    print("⚠️ Could not parse version — check manually")

# ─── Check 2: sshd_config hardening ──────────────────────────────
print("\n[2] Checking sshd_config for hardened settings...")

required_settings = {
    "Ciphers": "aes128-ctr",
    "MACs": "hmac-sha2-256",
    "KexAlgorithms": "curve25519-sha256",
}

if os.path.exists(sshd_conf):
    with open(sshd_conf, "r") as f:
        content = f.read().lower()

    for key, expected in required_settings.items():
        if key.lower() in content and expected.lower() in content:
            print(f"✅ {key} is hardened")
        else:
            print(f"❌ {key} hardening not found")
            all_good = False

    # Verify ChaCha20 excluded
    lines = content.splitlines()
    for line in lines:
        if line.strip().startswith("ciphers") and not line.strip().startswith("#"):
            if "chacha20" in line:
                print("❌ chacha20-poly1305 still present in Ciphers!")
                all_good = False
            else:
                print("✅ chacha20-poly1305 excluded from Ciphers")
else:
    print(f"❌ sshd_config not found at {sshd_conf}")
    all_good = False

# ─── Check 3: SSH service is running ─────────────────────────────
print("\n[3] Checking SSH service status...")
result = subprocess.run(
    ["powershell", "-Command", "(Get-Service sshd).Status"],
    capture_output=True, text=True
)
status = result.stdout.strip()
if status == "Running":
    print(f"✅ SSH service is Running")
else:
    print(f"❌ SSH service status: {status}")
    all_good = False

# ─── Check 4: Port 22 is listening ───────────────────────────────
print("\n[4] Checking if port 22 is listening...")
result = subprocess.run(
    ["powershell", "-Command",
     "netstat -an | Select-String ':22'"],
    capture_output=True, text=True
)
if ":22" in result.stdout:
    print("✅ Port 22 is open and listening")
else:
    print("❌ Port 22 is NOT listening")
    all_good = False

# ─── Check 5: Service set to auto-start ──────────────────────────
print("\n[5] Checking SSH service startup type...")
result = subprocess.run(
    ["powershell", "-Command", "(Get-Service sshd).StartType"],
    capture_output=True, text=True
)
startup = result.stdout.strip()
if startup == "Automatic":
    print("✅ SSH service is set to Automatic startup")
else:
    print(f"⚠️ SSH service startup type: {startup}")

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — Terrapin vulnerability mitigated!")
    print("   Re-run Nessus scan to confirm Plugin 187315 is resolved.")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 187315_WIN_FIX.py")
print("=" * 60)