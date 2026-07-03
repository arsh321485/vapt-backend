import subprocess
import os
import shutil
from datetime import datetime

print("Starting TLS 1.0 fix for Ubuntu...")

# ─── Backup OpenSSL config ───────────────────────────────────────
openssl_conf = "/etc/ssl/openssl.cnf"
backup_path = f"{openssl_conf}.bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

if os.path.exists(openssl_conf):
    shutil.copy2(openssl_conf, backup_path)
    print(f"Backup saved: {backup_path}")

# ─── Apply system-wide TLS policy ────────────────────────────────
try:
    subprocess.run(["update-crypto-policies", "--set", "DEFAULT:NO-TLSv1:NO-TLSv1.1"],
                   check=True)
    print("Crypto policy updated: TLS 1.0 and 1.1 disabled system-wide")
except FileNotFoundError:
    print("update-crypto-policies not found, applying manual OpenSSL config...")

    tls_block = """
[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=2
"""
    with open(openssl_conf, "a") as f:
        f.write(tls_block)
    print("OpenSSL config patched manually.")

# ─── Restart common services that use TLS ────────────────────────
services = ["apache2", "nginx", "haproxy"]

for svc in services:
    result = subprocess.run(["systemctl", "is-active", "--quiet", svc])
    if result.returncode == 0:
        subprocess.run(["systemctl", "restart", svc])
        print(f"Restarted: {svc}")

print("\n✅ Fix applied! Now run 104743_UBUNTU_verify_NS.py to confirm.")