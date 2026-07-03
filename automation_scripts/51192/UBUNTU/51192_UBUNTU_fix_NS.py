import subprocess
import os
import shutil
from datetime import datetime

print("=" * 60)
print("SSL Certificate Cannot Be Trusted Fix — Ubuntu")
print("Plugin 51192")
print("=" * 60)

# ─── Configuration ────────────────────────────────────────────────
CERT_DIR = "/etc/ssl/certs/custom"
KEY_DIR = "/etc/ssl/private/custom"
CERT_FILE = f"{CERT_DIR}/server.crt"
KEY_FILE = f"{KEY_DIR}/server.key"
CSR_FILE = f"{CERT_DIR}/server.csr"
CONFIG_FILE = f"{CERT_DIR}/openssl_san.cnf"
DAYS_VALID = 825  # Max browser-accepted validity

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

# ─── Step 1: Create directories ───────────────────────────────────
print("\n[1] Creating certificate directories...")
os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)
os.chmod(KEY_DIR, 0o700)
print(f"✅ Directories ready: {CERT_DIR}, {KEY_DIR}")

# ─── Step 2: Backup existing cert if present ─────────────────────
print("\n[2] Backing up existing certificate...")
if os.path.exists(CERT_FILE):
    shutil.copy2(CERT_FILE, f"{CERT_FILE}.bak_{timestamp}")
    print(f"✅ Certificate backed up")
if os.path.exists(KEY_FILE):
    shutil.copy2(KEY_FILE, f"{KEY_FILE}.bak_{timestamp}")
    print(f"✅ Key backed up")

# ─── Step 3: Create OpenSSL config with SAN ──────────────────────
print("\n[3] Creating OpenSSL config with Subject Alternative Names...")

# ← Update these values for your environment
COMMON_NAME = "your-server.example.com"
ORG = "Your Organization"
COUNTRY = "US"
STATE = "California"
CITY = "San Jose"
EMAIL = "admin@example.com"
SAN_DNS = "your-server.example.com"
SAN_IP = "192.168.1.1"  # ← change to your server IP

openssl_config = f"""
[req]
default_bits       = 4096
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext
x509_extensions    = v3_ca

[dn]
C  = {COUNTRY}
ST = {STATE}
L  = {CITY}
O  = {ORG}
CN = {COMMON_NAME}
emailAddress = {EMAIL}

[req_ext]
subjectAltName = @alt_names

[v3_ca]
subjectAltName = @alt_names
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = {SAN_DNS}
IP.1  = {SAN_IP}
"""

with open(CONFIG_FILE, "w") as f:
    f.write(openssl_config)
print(f"✅ OpenSSL config created: {CONFIG_FILE}")

# ─── Step 4: Generate private key ────────────────────────────────
print("\n[4] Generating 4096-bit RSA private key...")
try:
    subprocess.run([
        "openssl", "genrsa",
        "-out", KEY_FILE, "4096"
    ], check=True, capture_output=True)
    os.chmod(KEY_FILE, 0o600)
    print(f"✅ Private key generated: {KEY_FILE}")
except subprocess.CalledProcessError as e:
    print(f"❌ Failed to generate key: {e}")
    exit(1)

# ─── Step 5: Generate CSR ─────────────────────────────────────────
print("\n[5] Generating Certificate Signing Request (CSR)...")
try:
    subprocess.run([
        "openssl", "req",
        "-new",
        "-key", KEY_FILE,
        "-out", CSR_FILE,
        "-config", CONFIG_FILE
    ], check=True, capture_output=True)
    print(f"✅ CSR generated: {CSR_FILE}")
    print(f"   → Submit this CSR to your CA for a trusted certificate")
except subprocess.CalledProcessError as e:
    print(f"❌ Failed to generate CSR: {e}")

# ─── Step 6: Generate self-signed cert (temporary) ───────────────
print("\n[6] Generating temporary self-signed certificate...")
print("   ⚠️  Replace with CA-signed cert before production use!")
try:
    subprocess.run([
        "openssl", "x509",
        "-req",
        "-days", str(DAYS_VALID),
        "-in", CSR_FILE,
        "-signkey", KEY_FILE,
        "-out", CERT_FILE,
        "-extensions", "v3_ca",
        "-extfile", CONFIG_FILE
    ], check=True, capture_output=True)
    print(f"✅ Certificate generated: {CERT_FILE}")
except subprocess.CalledProcessError as e:
    print(f"❌ Failed to generate certificate: {e}")
    exit(1)

# ─── Step 7: Install certificate to system trust store ───────────
print("\n[7] Installing certificate to system trust store...")
try:
    trusted_cert = f"/usr/local/share/ca-certificates/server_{timestamp}.crt"
    shutil.copy2(CERT_FILE, trusted_cert)
    subprocess.run(["update-ca-certificates"], check=True, capture_output=True)
    print("✅ Certificate installed to system trust store")
except Exception as e:
    print(f"⚠️ Could not install to trust store: {e}")

# ─── Step 8: Restart web services ────────────────────────────────
print("\n[8] Restarting active web services...")
services = ["nginx", "apache2", "haproxy"]
for svc in services:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", svc]
    )
    if result.returncode == 0:
        subprocess.run(["systemctl", "restart", svc], check=True)
        print(f"✅ Restarted: {svc}")

print("\n" + "=" * 60)
print("✅ Fix applied!")
print(f"   CSR location : {CSR_FILE}")
print(f"   Cert location: {CERT_FILE}")
print(f"   Key location : {KEY_FILE}")
print("   → Submit CSR to trusted CA to get production certificate")
print("   → Run 51192_UBUNTU_VERIFY.py to confirm")
print("=" * 60)