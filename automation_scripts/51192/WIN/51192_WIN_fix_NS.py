import subprocess
import os
import shutil
from datetime import datetime

print("=" * 60)
print("SSL Certificate Cannot Be Trusted Fix — Windows")
print("Plugin 51192")
print("=" * 60)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

# ─── Configuration ────────────────────────────────────────────────
CERT_DIR = r"C:\SSL\Certs"
KEY_DIR = r"C:\SSL\Private"
CERT_FILE = os.path.join(CERT_DIR, "server.crt")
KEY_FILE = os.path.join(KEY_DIR, "server.key")
CSR_FILE = os.path.join(CERT_DIR, "server.csr")
CONFIG_FILE = os.path.join(CERT_DIR, "openssl_san.cnf")
PFX_FILE = os.path.join(CERT_DIR, "server.pfx")

# ← Update these for your environment
COMMON_NAME = "your-server.example.com"
ORG = "Your Organization"
COUNTRY = "US"
STATE = "California"
CITY = "San Jose"
SAN_DNS = "your-server.example.com"
SAN_IP = "192.168.1.1"   # ← change to your server IP
PFX_PASSWORD = "YourSecurePassword123!"  # ← change this

# ─── Step 1: Create directories ───────────────────────────────────
print("\n[1] Creating certificate directories...")
os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)
print(f"✅ Directories ready: {CERT_DIR}")

# ─── Step 2: Backup existing certs ───────────────────────────────
print("\n[2] Backing up existing certificates...")
if os.path.exists(CERT_FILE):
    shutil.copy2(CERT_FILE, f"{CERT_FILE}.bak_{timestamp}")
    print("✅ Certificate backed up")

# ─── Step 3: Create OpenSSL config ───────────────────────────────
print("\n[3] Creating OpenSSL config with SAN...")
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

# ─── Step 4: Check OpenSSL is available ──────────────────────────
print("\n[4] Checking OpenSSL availability...")
result = subprocess.run(["where", "openssl"], capture_output=True, text=True)
if result.returncode != 0:
    print("⚠️ OpenSSL not found in PATH")
    print("   Installing via winget...")
    try:
        subprocess.run([
            "winget", "install", "--id", "ShiningLight.OpenSSL.Light",
            "--silent", "--accept-package-agreements"
        ], check=True)
        print("✅ OpenSSL installed!")
    except Exception as e:
        print(f"❌ Could not install OpenSSL: {e}")
        print("   Download from: https://slproweb.com/products/Win32OpenSSL.html")
        exit(1)
else:
    print(f"✅ OpenSSL found: {result.stdout.strip()}")

# ─── Step 5: Generate private key ────────────────────────────────
print("\n[5] Generating 4096-bit RSA private key...")
try:
    subprocess.run([
        "openssl", "genrsa",
        "-out", KEY_FILE, "4096"
    ], check=True, capture_output=True)
    print(f"✅ Private key generated: {KEY_FILE}")
except subprocess.CalledProcessError as e:
    print(f"❌ Failed to generate key: {e}")
    exit(1)

# ─── Step 6: Generate CSR ─────────────────────────────────────────
print("\n[6] Generating Certificate Signing Request (CSR)...")
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

# ─── Step 7: Generate self-signed cert (temporary) ───────────────
print("\n[7] Generating temporary self-signed certificate...")
print("   ⚠️  Replace with CA-signed cert before production use!")
try:
    subprocess.run([
        "openssl", "x509",
        "-req",
        "-days", "825",
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

# ─── Step 8: Export as PFX for Windows IIS/RDP ───────────────────
print("\n[8] Exporting certificate as PFX for Windows services...")
try:
    subprocess.run([
        "openssl", "pkcs12",
        "-export",
        "-out", PFX_FILE,
        "-inkey", KEY_FILE,
        "-in", CERT_FILE,
        "-passout", f"pass:{PFX_PASSWORD}"
    ], check=True, capture_output=True)
    print(f"✅ PFX file generated: {PFX_FILE}")
except Exception as e:
    print(f"⚠️ Could not generate PFX: {e}")

# ─── Step 9: Import PFX into Windows Certificate Store ───────────
print("\n[9] Importing certificate into Windows Certificate Store...")
try:
    subprocess.run([
        "powershell", "-Command",
        f"Import-PfxCertificate -FilePath '{PFX_FILE}' "
        f"-CertStoreLocation Cert:\\LocalMachine\\My "
        f"-Password (ConvertTo-SecureString -String '{PFX_PASSWORD}' "
        f"-AsPlainText -Force)"
    ], check=True, capture_output=True)
    print("✅ Certificate imported to Windows Certificate Store")
except Exception as e:
    print(f"⚠️ Could not import to certificate store: {e}")

print("\n" + "=" * 60)
print("✅ Fix applied!")
print(f"   CSR location : {CSR_FILE}")
print(f"   Cert location: {CERT_FILE}")
print(f"   PFX location : {PFX_FILE}")
print("   → Submit CSR to trusted CA to get production certificate")
print("   → Run 51192_WIN_VERIFY.py to confirm")
print("=" * 60)