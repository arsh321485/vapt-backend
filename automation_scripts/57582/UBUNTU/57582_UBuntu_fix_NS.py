import subprocess
import os
import shutil
from datetime import datetime

print("=" * 60)
print("SSL Self-Signed Certificate Fix — Ubuntu")
print("Plugin 57582")
print("=" * 60)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

# ─── Configuration ────────────────────────────────────────────────
CERT_DIR   = "/etc/ssl/certs/custom"
KEY_DIR    = "/etc/ssl/private/custom"
CERT_FILE  = f"{CERT_DIR}/server.crt"
KEY_FILE   = f"{KEY_DIR}/server.key"
CSR_FILE   = f"{CERT_DIR}/server.csr"
CONFIG_FILE= f"{CERT_DIR}/openssl_san.cnf"

# ← Update these for your environment
COMMON_NAME = "your-server.example.com"
ORG         = "Your Organization"
COUNTRY     = "US"
STATE       = "California"
CITY        = "San Jose"
EMAIL       = "admin@example.com"
SAN_DNS     = "your-server.example.com"
SAN_IP      = "192.168.1.1"   # ← change to your server IP

# ─── Step 1: Create directories ───────────────────────────────────
print("\n[1] Creating certificate directories...")
os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)
os.chmod(KEY_DIR, 0o700)
print(f"✅ Directories ready")

# ─── Step 2: Backup existing cert ────────────────────────────────
print("\n[2] Backing up existing certificate...")
for f in [CERT_FILE, KEY_FILE]:
    if os.path.exists(f):
        shutil.copy2(f, f"{f}.bak_{timestamp}")
        print(f"✅ Backed up: {f}")

# ─── Step 3: Check if Let's Encrypt is possible ──────────────────
print("\n[3] Checking if Certbot (Let's Encrypt) is available...")
result = subprocess.run(["which", "certbot"], capture_output=True, text=True)
if result.stdout.strip():
    print("✅ Certbot found — attempting Let's Encrypt certificate...")
    print("   ⚠️  Only works if server is publicly accessible on port 443")
    try:
        subprocess.run([
            "certbot", "certonly",
            "--standalone",
            "--non-interactive",
            "--agree-tos",
            "--email", EMAIL,
            "-d", SAN_DNS
        ], check=True)
        print("✅ Let's Encrypt certificate obtained!")
        print("   → Certificate is trusted by all major browsers/clients")
        print("   → No need for CSR submission to CA")
        letsencrypt = True
    except subprocess.CalledProcessError:
        print("⚠️ Let's Encrypt failed — falling back to CSR generation")
        letsencrypt = False
else:
    print("⚠️ Certbot not installed — proceeding with CSR generation")
    print("   Install certbot: sudo apt-get install certbot -y")
    letsencrypt = False

if not letsencrypt:
    # ─── Step 4: Create OpenSSL config ───────────────────────────
    print("\n[4] Creating OpenSSL config with SAN...")
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

    # ─── Step 5: Generate private key ────────────────────────────
    print("\n[5] Generating 4096-bit RSA private key...")
    subprocess.run([
        "openssl", "genrsa", "-out", KEY_FILE, "4096"
    ], check=True, capture_output=True)
    os.chmod(KEY_FILE, 0o600)
    print(f"✅ Private key generated: {KEY_FILE}")

    # ─── Step 6: Generate CSR ─────────────────────────────────────
    print("\n[6] Generating CSR...")
    subprocess.run([
        "openssl", "req", "-new",
        "-key", KEY_FILE,
        "-out", CSR_FILE,
        "-config", CONFIG_FILE
    ], check=True, capture_output=True)
    print(f"✅ CSR generated: {CSR_FILE}")
    print(f"   → Submit to trusted CA for a properly signed certificate")

    # ─── Step 7: Temp self-signed cert ───────────────────────────
    print("\n[7] Generating temporary self-signed certificate...")
    print("   ⚠️  Replace with CA-signed cert before production use!")
    subprocess.run([
        "openssl", "x509", "-req",
        "-days", "825",
        "-in", CSR_FILE,
        "-signkey", KEY_FILE,
        "-out", CERT_FILE,
        "-extensions", "v3_ca",
        "-extfile", CONFIG_FILE
    ], check=True, capture_output=True)
    print(f"✅ Temporary certificate generated: {CERT_FILE}")

    # ─── Step 8: Install to trust store ──────────────────────────
    print("\n[8] Installing to system trust store...")
    trusted = f"/usr/local/share/ca-certificates/server_{timestamp}.crt"
    shutil.copy2(CERT_FILE, trusted)
    subprocess.run(["update-ca-certificates"], check=True, capture_output=True)
    print("✅ Certificate installed to trust store")

# ─── Step 9: Restart web services ────────────────────────────────
print("\n[9] Restarting active web services...")
for svc in ["nginx", "apache2", "haproxy"]:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", svc]
    )
    if result.returncode == 0:
        subprocess.run(["systemctl", "restart", svc])
        print(f"✅ Restarted: {svc}")

print("\n" + "=" * 60)
print("✅ Fix applied!")
print(f"   CSR  : {CSR_FILE}")
print(f"   Cert : {CERT_FILE}")
print("   → Submit CSR to trusted CA for production certificate")
print("   → Run 57582_UBUNTU_VERIFY.py to confirm")
print("=" * 60)