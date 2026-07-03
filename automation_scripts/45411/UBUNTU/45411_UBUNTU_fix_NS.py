import subprocess
import os
import shutil
import logging
import sys
import datetime

print("=" * 60)
print("SSL Certificate Wrong Hostname Fix — Plugin 45411")
print("Service: tcp/21112 — Ubuntu")
print("Current CN : ofcsslagent")
print("Expected   : hq-hr-srv.dom.com / hq-hrms.dom.com")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"45411_ubuntu_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("wrong_hostname_fix")

# ─── Configuration ────────────────────────────────────────────────
CERT_CN     = "hq-hr-srv.dom.com"
ORG         = "Ibdar"
COUNTRY     = "BH"
CITY        = "Manama"
EMAIL       = "admin@dom.com"      # ← change this
SAN_DNS1    = "hq-hr-srv.dom.com"
SAN_DNS2    = "hq-hr-srv"
SAN_DNS3    = "hq-hrms.dom.com"
SAN_IP      = "192.168.0.20"
DAYS_VALID  = 825

CERT_DIR    = "/etc/ssl/certs/custom"
KEY_DIR     = "/etc/ssl/private/custom"
CERT_FILE   = f"{CERT_DIR}/server.crt"
KEY_FILE    = f"{KEY_DIR}/server.key"
CSR_FILE    = f"{CERT_DIR}/server.csr"
CONFIG_FILE = f"{CERT_DIR}/openssl_san.cnf"

# ─── Step 1: Create directories ───────────────────────────────────
log.info("\n[1] Creating certificate directories...")
os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)
os.chmod(KEY_DIR, 0o700)
log.info("✅ Directories ready")

# ─── Step 2: Backup existing wrong cert ──────────────────────────
log.info("\n[2] Backing up existing wrong certificate...")
for f in [CERT_FILE, KEY_FILE]:
    if os.path.exists(f):
        shutil.copy2(f, f"{f}.wrong_hostname_{timestamp}")
        log.info("✅ Backed up: %s", f)

# ─── Step 3: Create OpenSSL config with all SANs ─────────────────
log.info("\n[3] Creating OpenSSL config with correct hostnames...")
log.info("   CN  : %s", CERT_CN)
log.info("   SAN : %s, %s, %s, %s",
         SAN_DNS1, SAN_DNS2, SAN_DNS3, SAN_IP)

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
DNS.1 = {SAN_DNS1}
DNS.2 = {SAN_DNS2}
DNS.3 = {SAN_DNS3}
IP.1  = {SAN_IP}
"""
with open(CONFIG_FILE, "w") as f:
    f.write(openssl_config)
log.info("✅ OpenSSL config created: %s", CONFIG_FILE)

# ─── Step 4: Generate new private key ────────────────────────────
log.info("\n[4] Generating new 4096-bit RSA private key...")
subprocess.run([
    "openssl", "genrsa", "-out", KEY_FILE, "4096"
], check=True, capture_output=True)
os.chmod(KEY_FILE, 0o600)
log.info("✅ Private key generated: %s", KEY_FILE)

# ─── Step 5: Generate CSR ─────────────────────────────────────────
log.info("\n[5] Generating CSR with correct hostname...")
subprocess.run([
    "openssl", "req", "-new",
    "-key", KEY_FILE,
    "-out", CSR_FILE,
    "-config", CONFIG_FILE
], check=True, capture_output=True)
log.info("✅ CSR generated: %s", CSR_FILE)
log.info("   → Submit to internal CA for a properly signed cert")

# ─── Step 6: Generate self-signed cert ───────────────────────────
log.info("\n[6] Generating self-signed certificate with correct CN...")
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
log.info("✅ Certificate generated with correct CN: %s", CERT_FILE)

# ─── Step 7: Verify CN is correct before installing ──────────────
log.info("\n[7] Verifying new certificate CN...")
result = subprocess.run([
    "openssl", "x509", "-in", CERT_FILE,
    "-noout", "-subject"
], capture_output=True, text=True)
log.info("   Subject: %s", result.stdout.strip())

if "ofcsslagent" in result.stdout.lower():
    log.error("❌ CN still shows 'ofcsslagent' — regenerate!")
    sys.exit(1)
else:
    log.info("✅ CN correctly set — 'ofcsslagent' is gone!")

# ─── Step 8: Install to trust store ──────────────────────────────
log.info("\n[8] Installing to system trust store...")
trusted = f"/usr/local/share/ca-certificates/server_{timestamp}.crt"
shutil.copy2(CERT_FILE, trusted)
subprocess.run(["update-ca-certificates"],
               check=True, capture_output=True)
log.info("✅ Certificate installed to trust store")

# ─── Step 9: Restart web services ────────────────────────────────
log.info("\n[9] Restarting active web services...")
for svc in ["nginx", "apache2", "haproxy"]:
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
log.info("   → Bind cert to port 21112 in your service config")
log.info("   → Run 45411_UBUNTU_VERIFY.py to confirm")
log.info("=" * 60)