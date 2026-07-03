import subprocess
import os
import shutil
from datetime import datetime

print("Starting TLS 1.1 fix for Ubuntu...")

# ─── Backup OpenSSL config ───────────────────────────────────────
openssl_conf = "/etc/ssl/openssl.cnf"
backup_path = f"{openssl_conf}.bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

if os.path.exists(openssl_conf):
    shutil.copy2(openssl_conf, backup_path)
    print(f"✅ Backup saved: {backup_path}")
else:
    print("⚠️ openssl.cnf not found at expected path — check your system.")

# ─── Method 1: update-crypto-policies (Ubuntu 20.04+) ────────────
print("\nAttempting crypto-policies method...")
try:
    subprocess.run(
        ["update-crypto-policies", "--set", "DEFAULT:NO-TLSv1:NO-TLSv1.1"],
        check=True
    )
    print("✅ Crypto policy updated: TLS 1.0 and TLS 1.1 disabled system-wide")

# ─── Method 2: Manual OpenSSL config patch (fallback) ────────────
except FileNotFoundError:
    print("⚠️ update-crypto-policies not found — applying manual OpenSSL patch...")

    try:
        with open(openssl_conf, "r") as f:
            content = f.read()

        # Avoid duplicate entries if script is run more than once
        if "MinProtocol = TLSv1.2" in content:
            print("⚠️ MinProtocol already set in openssl.cnf — skipping patch.")
        else:
            tls_block = """
[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=2
"""
            with open(openssl_conf, "a") as f:
                f.write(tls_block)
            print("✅ OpenSSL config patched: MinProtocol set to TLSv1.2")

    except Exception as e:
        print(f"❌ Failed to patch openssl.cnf: {e}")

except subprocess.CalledProcessError as e:
    print(f"❌ update-crypto-policies failed: {e}")

# ─── Restart TLS-dependent services ──────────────────────────────
print("\nChecking and restarting active TLS services...")
services = ["apache2", "nginx", "haproxy", "lighttpd"]

restarted = []
skipped = []

for svc in services:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", svc]
    )
    if result.returncode == 0:
        restart = subprocess.run(["systemctl", "restart", svc])
        if restart.returncode == 0:
            restarted.append(svc)
            print(f"✅ Restarted: {svc}")
        else:
            print(f"❌ Failed to restart: {svc}")
    else:
        skipped.append(svc)

print(f"\nRestarted services : {restarted if restarted else 'None'}")
print(f"Inactive (skipped) : {skipped if skipped else 'None'}")

print("\n✅ Fix applied successfully!")
print("➡️  Now run 157288_UBUNTU_verify_NS.py to confirm TLS 1.1 is disabled.")