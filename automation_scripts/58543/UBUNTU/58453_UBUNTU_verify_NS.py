import subprocess
import os

print("="*55)
print("  NLA Verification Script — Ubuntu")
print("="*55)

xrdp_conf = "/etc/xrdp/xrdp.ini"
all_good = True

# ─── Check 1: xrdp is installed ──────────────────────────────────
print("\n[1] Checking xrdp installation...")
result = subprocess.run(["which", "xrdp"], capture_output=True, text=True)
if result.stdout.strip():
    print("✅ xrdp is installed")
else:
    print("❌ xrdp is NOT installed")
    all_good = False

# ─── Check 2: xrdp service is running ────────────────────────────
print("\n[2] Checking xrdp service status...")
result = subprocess.run(
    ["systemctl", "is-active", "xrdp"],
    capture_output=True, text=True
)
if result.stdout.strip() == "active":
    print("✅ xrdp service is running")
else:
    print(f"❌ xrdp service is NOT running — Status: {result.stdout.strip()}")
    all_good = False

# ─── Check 3: NLA config in xrdp.ini ─────────────────────────────
print("\n[3] Checking xrdp.ini for NLA settings...")
if os.path.exists(xrdp_conf):
    with open(xrdp_conf, "r") as f:
        content = f.read()

    # Check security layer
    if "security_layer=tls" in content:
        print("✅ security_layer is set to TLS")
    else:
        print("❌ security_layer is NOT set to TLS")
        all_good = False

    # Check NLA enabled
    if "enable_nla=true" in content:
        print("✅ NLA is enabled in config")
    else:
        print("❌ NLA is NOT enabled in config")
        all_good = False
else:
    print(f"❌ xrdp.ini not found at {xrdp_conf}")
    all_good = False

# ─── Check 4: Port 3389 is listening ─────────────────────────────
print("\n[4] Checking if port 3389 is listening...")
result = subprocess.run(
    ["ss", "-tlnp"],
    capture_output=True, text=True
)
if "3389" in result.stdout:
    print("✅ Port 3389 is open and listening")
else:
    print("❌ Port 3389 is NOT listening — xrdp may not be running correctly")
    all_good = False

# ─── Check 5: xrdp enabled on boot ───────────────────────────────
print("\n[5] Checking if xrdp is enabled on boot...")
result = subprocess.run(
    ["systemctl", "is-enabled", "xrdp"],
    capture_output=True, text=True
)
if result.stdout.strip() == "enabled":
    print("✅ xrdp is enabled on boot")
else:
    print(f"⚠️ xrdp is NOT enabled on boot — Status: {result.stdout.strip()}")

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "="*55)
if all_good:
    print("✅ ALL CHECKS PASSED — NLA is correctly configured!")
else:
    print("❌ SOME CHECKS FAILED — Review above and re-run fix script.")
print("="*55)