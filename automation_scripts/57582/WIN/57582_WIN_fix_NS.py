import subprocess
import os
import shutil
from datetime import datetime

print("=" * 60)
print("SSL Self-Signed Certificate Fix — Windows")
print("Plugin 57582")
print("=" * 60)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

# ─── Configuration ────────────────────────────────────────────────
CERT_DIR    = r"C:\SSL\Certs"
KEY_DIR     = r"C:\SSL\Private"
CERT_FILE   = os.path.join(CERT_DIR, "server.crt")
KEY_FILE    = os.path.join(KEY_DIR, "server.key")
CSR_FILE    = os.path.join(CERT_DIR, "server.csr")
CONFIG_FILE = os.path.join(CERT_DIR, "openssl_san.cnf")
PFX_FILE    = os.path.join(CERT_DIR, "server.pfx")

# ← Update these for your environment
COMMON_NAME  = "your-server.example.com"
ORG          = "Your Organization"
COUNTRY      = "US"
STATE        = "California"
CITY         = "San Jose"
SAN_DNS      = "your-server.example.com"
SAN_IP       = "192.168.1.1"   # ← change to your server IP
PFX_PASSWORD = "YourSecurePassword123!"  # ← change this

# ─── Step 1: Create directories ───────────────────────────────────
print("\n[1] Creating certificate directories...")
os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)
print(f"✅ Directories ready: {CERT_DIR}")

# ─── Step 2: Backup existing certs ───────────────────────────────
print("\n[2] Backing up existing certificate...")
if os.path.exists(CERT_FILE):
    shutil.copy2(CERT_FILE, f"{CERT_FILE}.bak_{timestamp}")
    print("✅ Certificate backed up")

# ─── Step 3: Check OpenSSL ────────────────────────────────────────
print("\n[3] Checking OpenSSL availability...")
result = subprocess.run(["where", "openssl"], capture_output=True, text=True)
if result.returncode != 0:
    print("⚠️ OpenSSL not found — installing via winget...")
    try:
        subprocess.run([
            "winget", "install", "--id",
            "ShiningLight.OpenSSL.Light",
            "--silent", "--accept-package-agreements"
        ], check=True)
        print("✅ OpenSSL installed!")
    except Exception as e:
        print(f"❌ Could not install OpenSSL: {e}")
        print("   Download from: https://slproweb.com/products/Win32OpenSSL.html")
        exit(1)
else:
    print(f"✅ OpenSSL found")

# ─── Step 4: Create OpenSSL config ───────────────────────────────
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
print(f"✅ OpenSSL config created")

# ─── Step 5: Generate private key ────────────────────────────────
print("\n[5] Generating 4096-bit RSA private key...")
subprocess.run([
    "openssl", "genrsa", "-out", KEY_FILE, "4096"
], check=True, capture_output=True)
print(f"✅ Private key generated: {KEY_FILE}")

# ─── Step 6: Generate CSR ─────────────────────────────────────────
print("\n[6] Generating CSR...")
subprocess.run([
    "openssl", "req", "-new",
    "-key", KEY_FILE,
    "-out", CSR_FILE,
    "-config", CONFIG_FILE
], check=True, capture_output=True)
print(f"✅ CSR generated: {CSR_FILE}")
print(f"   → Submit to trusted CA for a properly signed certificate")

# ─── Step 7: Temp self-signed cert ───────────────────────────────
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

# ─── Step 8: Export as PFX ───────────────────────────────────────
print("\n[8] Exporting as PFX for Windows services...")
try:
    subprocess.run([
        "openssl", "pkcs12", "-export",
        "-out", PFX_FILE,
        "-inkey", KEY_FILE,
        "-in", CERT_FILE,
        "-passout", f"pass:{PFX_PASSWORD}"
    ], check=True, capture_output=True)
    print(f"✅ PFX generated: {PFX_FILE}")
except Exception as e:
    print(f"⚠️ PFX generation failed: {e}")

# ─── Step 9: Import to Windows Certificate Store ─────────────────
print("\n[9] Importing to Windows Certificate Store...")
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

# ─── Step 10: Restart IIS if running ─────────────────────────────
print("\n[10] Checking and restarting IIS...")
result = subprocess.run([
    "powershell", "-Command",
    "(Get-Service W3SVC -ErrorAction SilentlyContinue).Status"
], capture_output=True, text=True)
if "Running" in result.stdout:
    subprocess.run(["iisreset", "/restart"], capture_output=True)
    print("✅ IIS restarted")
else:
    print("⚠️ IIS not running — skipping")

print("\n" + "=" * 60)
print("✅ Fix applied!")
print(f"   CSR  : {CSR_FILE}")
print(f"   Cert : {CERT_FILE}")
print(f"   PFX  : {PFX_FILE}")
print("   → Submit CSR to trusted CA for production certificate")
print("   → Run 57582_WIN_VERIFY.py to confirm")
print("=" * 60)