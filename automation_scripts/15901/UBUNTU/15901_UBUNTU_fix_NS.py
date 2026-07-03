import subprocess
import os
import shutil
import logging
import sys
import datetime

print("=" * 60)
print("SSL Certificate Expiry Fix — Plugin 15901")
print("Service: SSL on tcp/1433 — Ubuntu")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"15901_ubuntu_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("ssl_expiry_fix")

# ─── Configuration ────────────────────────────────────────────────
CERT_CN    = "hq-hrms.dom.com"   # ← change to your FQDN
ORG        = "Ibdar"
COUNTRY    = "BH"
CITY       = "Manama"
EMAIL      = "admin@dom.com"     # ← change this
SAN_DNS    = "hq-hrms.dom.com"   # ← change this
SAN_IP     = "YOUR_VM_IP"        # ← change this

CERT_DIR   = "/etc/ssl/certs/custom"
KEY_DIR    = "/etc/ssl/private/custom"
CERT_FILE  = f"{CERT_DIR}/server.crt"
KEY_FILE   = f"{KEY_DIR}/server.key"
CSR_FILE   = f"{CERT_DIR}/server.csr"
CONFIG_FILE= f"{CERT_DIR}/openssl_san.cnf"
DAYS_VALID = 825

# ─── Step 1: Create directories ───────────────────────────────────
log.info("\n[1] Creating certificate directories...")
os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)
os.chmod(KEY_DIR, 0o700)
log.info("✅ Directories ready")

# ─── Step 2: Backup expired cert ─────────────────────────────────
log.info("\n[2] Backing up expired certificate...")
for f in [CERT_FILE, KEY_FILE]:
    if os.path.exists(f):
        shutil.copy2(f, f"{f}.expired_{timestamp}")
        log.info("✅ Backed up expired cert: %s", f)

# ─── Step 3: Try Let's Encrypt first ─────────────────────────────
log.info("\n[3] Checking Certbot availability...")
result = subprocess.run(["which", "certbot"], capture_output=True, text=True)
letsencrypt = False

if result.stdout.strip():
    log.info("✅ Certbot found — attempting Let's Encrypt renewal...")
    try:
        subprocess.run([
            "certbot", "certonly",
            "--standalone",
            "--non-interactive",
            "--agree-tos",
            "--email", EMAIL,
            "-d", SAN_DNS,
            "--force-renewal"
        ], check=True)
        log.info("✅ Let's Encrypt certificate renewed!")
        letsencrypt = True
    except subprocess.CalledProcessError:
        log.warning("⚠️ Let's Encrypt failed — generating new cert via OpenSSL")
else:
    log.warning("⚠️ Certbot not found — install: sudo apt-get install certbot -y")

if not letsencrypt:
    # ─── Step 4: Create OpenSSL config ───────────────────────────
    log.info("\n[4] Creating OpenSSL config...")
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
L  = {CITY}
O  = {ORG}
CN = {CERT_CN}
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
    log.info("✅ OpenSSL config created")

    # ─── Step 5: Generate new private key ────────────────────────
    log.info("\n[5] Generating new 4096-bit RSA private key...")
    subprocess.run([
        "openssl", "genrsa", "-out", KEY_FILE, "4096"
    ], check=True, capture_output=True)
    os.chmod(KEY_FILE, 0o600)
    log.info("✅ Private key generated: %s", KEY_FILE)

    # ─── Step 6: Generate CSR ─────────────────────────────────────
    log.info("\n[6] Generating CSR...")
    subprocess.run([
        "openssl", "req", "-new",
        "-key", KEY_FILE,
        "-out", CSR_FILE,
        "-config", CONFIG_FILE
    ], check=True, capture_output=True)
    log.info("✅ CSR generated: %s", CSR_FILE)
    log.info("   → Submit to CA for a properly signed certificate")

    # ─── Step 7: Generate new self-signed cert ───────────────────
    log.info("\n[7] Generating new self-signed certificate...")
    log.warning("   ⚠️  Replace with CA-signed cert before production!")
    subprocess.run([
        "openssl", "x509", "-req",
        "-days", str(DAYS_VALID),
        "-in", CSR_FILE,
        "-signkey", KEY_FILE,
        "-out", CERT_FILE,
        "-extensions", "v3_ca",
        "-extfile", CONFIG_FILE
    ], check=True, capture_output=True)
    log.info("✅ New certificate generated: %s", CERT_FILE)

    # ─── Step 8: Install to trust store ──────────────────────────
    log.info("\n[8] Installing to system trust store...")
    trusted = f"/usr/local/share/ca-certificates/server_{timestamp}.crt"
    shutil.copy2(CERT_FILE, trusted)
    subprocess.run(["update-ca-certificates"], check=True, capture_output=True)
    log.info("✅ Certificate installed to trust store")

# ─── Step 9: Restart services ─────────────────────────────────────
log.info("\n[9] Restarting active SSL services...")
services = ["nginx", "apache2", "haproxy"]
for svc in services:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", svc]
    )
    if result.returncode == 0:
        subprocess.run(["systemctl", "restart", svc])
        log.info("✅ Restarted: %s", svc)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Cert : %s", CERT_FILE)
log.info("   CSR  : %s", CSR_FILE)
log.info("   Log  : %s", log_file)
log.info("   → Run 15901_UBUNTU_VERIFY.py to confirm")
log.info("=" * 60)