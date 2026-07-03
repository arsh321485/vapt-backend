import subprocess
import os
import shutil
import logging
import sys
import datetime

print("=" * 60)
print("SSL Certificate Wrong Hostname Fix — Plugin 45411")
print("Service: tcp/21112 — Windows")
print("Current CN : ofcsslagent")
print("Expected   : hq-hr-srv.dom.com / hq-hrms.dom.com")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"45411_win_fix_{timestamp}.log"

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
# ← Update these for your environment
CERT_CN      = "hq-hr-srv.dom.com"       # Primary CN
ORG          = "Ibdar"
COUNTRY      = "BH"
CITY         = "Manama"
CA_NAME      = "dom-DC12SRV-CA"          # ← your internal CA
CERT_DIR     = r"C:\SSL\HostnameCerts"
CERT_FILE    = os.path.join(CERT_DIR, "server.crt")
KEY_FILE     = os.path.join(CERT_DIR, "server.key")
CSR_FILE     = os.path.join(CERT_DIR, "server.csr")
PFX_FILE     = os.path.join(CERT_DIR, "server.pfx")
CONFIG_FILE  = os.path.join(CERT_DIR, "openssl_san.cnf")
PFX_PASSWORD = "YourSecurePassword123!"  # ← change this
DAYS_VALID   = 825

# All known identities of this host — add to SAN
SAN_DNS1 = "hq-hr-srv.dom.com"
SAN_DNS2 = "hq-hr-srv"
SAN_DNS3 = "hq-hrms.dom.com"
SAN_IP   = "192.168.0.20"

# ─── Step 1: Create directories ───────────────────────────────────
log.info("\n[1] Creating certificate directories...")
os.makedirs(CERT_DIR, exist_ok=True)
log.info("✅ Directory ready: %s", CERT_DIR)

# ─── Step 2: Backup existing wrong cert ──────────────────────────
log.info("\n[2] Backing up existing wrong certificate...")
for f in [CERT_FILE, KEY_FILE, PFX_FILE]:
    if os.path.exists(f):
        shutil.copy2(f, f"{f}.wrong_hostname_{timestamp}")
        log.info("✅ Backed up: %s", f)

# ─── Step 3: Check OpenSSL ────────────────────────────────────────
log.info("\n[3] Checking OpenSSL availability...")
result = subprocess.run(["where", "openssl"],
                        capture_output=True, text=True)
if result.returncode != 0:
    log.warning("⚠️ OpenSSL not found — installing via winget...")
    subprocess.run([
        "winget", "install", "--id",
        "ShiningLight.OpenSSL.Light",
        "--silent", "--accept-package-agreements"
    ], check=True)
    log.info("✅ OpenSSL installed!")
else:
    log.info("✅ OpenSSL found")

# ─── Step 4: Create OpenSSL config with correct SAN ──────────────
log.info("\n[4] Creating OpenSSL config with correct hostnames...")
log.info("   Adding all known identities to SAN:")
log.info("   DNS: %s, %s, %s", SAN_DNS1, SAN_DNS2, SAN_DNS3)
log.info("   IP : %s", SAN_IP)

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

# ─── Step 5: Generate new private key ────────────────────────────
log.info("\n[5] Generating new 4096-bit RSA private key...")
try:
    subprocess.run([
        "openssl", "genrsa", "-out", KEY_FILE, "4096"
    ], check=True, capture_output=True)
    log.info("✅ Private key generated: %s", KEY_FILE)
except Exception as e:
    log.error("❌ Failed to generate key: %s", e)
    sys.exit(1)

# ─── Step 6: Generate CSR ─────────────────────────────────────────
log.info("\n[6] Generating CSR with correct hostname...")
try:
    subprocess.run([
        "openssl", "req", "-new",
        "-key", KEY_FILE,
        "-out", CSR_FILE,
        "-config", CONFIG_FILE
    ], check=True, capture_output=True)
    log.info("✅ CSR generated: %s", CSR_FILE)
    log.info("   → Submit to CA: %s", CA_NAME)
except Exception as e:
    log.error("❌ Failed to generate CSR: %s", e)

# ─── Step 7: Try auto-enrollment via internal CA ─────────────────
log.info("\n[7] Attempting auto-enrollment via internal CA...")
ca_enrolled = False
try:
    inf_file = os.path.join(CERT_DIR, "server.inf")
    inf_content = f"""[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN={CERT_CN}, O={ORG}, L={CITY}, C={COUNTRY}"
KeySpec = 1
KeyLength = 4096
Exportable = TRUE
MachineKeySet = TRUE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
ValidityPeriod = Years
ValidityPeriodUnits = 2

[Extensions]
2.5.29.17 = "{{text}}"
_continue_ = "dns={SAN_DNS1}&"
_continue_ = "dns={SAN_DNS2}&"
_continue_ = "dns={SAN_DNS3}&"
_continue_ = "ipaddress={SAN_IP}&"

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1
"""
    with open(inf_file, "w") as f:
        f.write(inf_content)

    req_file = os.path.join(CERT_DIR, "server.req")
    subprocess.run([
        "certreq", "-new", inf_file, req_file
    ], check=True, capture_output=True)

    cer_file = os.path.join(CERT_DIR, "server.cer")
    subprocess.run([
        "certreq", "-submit",
        "-config", f"-\\{CA_NAME}",
        req_file, cer_file
    ], check=True, capture_output=True)

    subprocess.run([
        "certreq", "-accept", cer_file
    ], check=True, capture_output=True)
    log.info("✅ Certificate enrolled from internal CA!")
    ca_enrolled = True

except Exception as e:
    log.warning("⚠️ CA enrollment failed: %s — using self-signed", e)

# ─── Step 8: Generate self-signed if CA failed ───────────────────
if not ca_enrolled:
    log.info("\n[8] Generating temporary self-signed certificate...")
    log.warning("   ⚠️  CN set correctly — replace with CA cert soon!")
    try:
        subprocess.run([
            "openssl", "x509", "-req",
            "-days", str(DAYS_VALID),
            "-in", CSR_FILE,
            "-signkey", KEY_FILE,
            "-out", CERT_FILE,
            "-extensions", "v3_ca",
            "-extfile", CONFIG_FILE
        ], check=True, capture_output=True)
        log.info("✅ Certificate generated: %s", CERT_FILE)
    except Exception as e:
        log.error("❌ Failed to generate certificate: %s", e)
        sys.exit(1)

    # Export PFX
    log.info("\n[9] Exporting as PFX...")
    try:
        subprocess.run([
            "openssl", "pkcs12", "-export",
            "-out", PFX_FILE,
            "-inkey", KEY_FILE,
            "-in", CERT_FILE,
            "-passout", f"pass:{PFX_PASSWORD}"
        ], check=True, capture_output=True)
        log.info("✅ PFX exported: %s", PFX_FILE)
    except Exception as e:
        log.warning("⚠️ PFX export failed: %s", e)

# ─── Step 9: Import to Windows Certificate Store ─────────────────
log.info("\n[10] Importing to Windows Certificate Store...")
try:
    subprocess.run([
        "powershell", "-Command",
        f"Import-PfxCertificate -FilePath '{PFX_FILE}' "
        f"-CertStoreLocation Cert:\\LocalMachine\\My "
        f"-Password (ConvertTo-SecureString -String '{PFX_PASSWORD}' "
        f"-AsPlainText -Force)"
    ], check=True, capture_output=True)
    log.info("✅ Certificate imported to Windows Store")
except Exception as e:
    log.warning("⚠️ Could not import to certificate store: %s", e)

# ─── Step 10: Show thumbprint for service binding ────────────────
log.info("\n[11] Retrieving certificate thumbprint...")
try:
    result = subprocess.run([
        "powershell", "-Command",
        f"Get-ChildItem Cert:\\LocalMachine\\My | "
        f"Where-Object {{$_.Subject -like '*{CERT_CN}*'}} | "
        f"Select-Object Thumbprint, Subject, NotAfter | Format-List"
    ], capture_output=True, text=True)
    log.info("   Certificate details:\n%s", result.stdout.strip())
    log.warning(
        "   ⚠️  Bind this certificate to port 21112 in your "
        "web service configuration"
    )
except Exception as e:
    log.warning("⚠️ Could not retrieve thumbprint: %s", e)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   CSR  : %s", CSR_FILE)
log.info("   Cert : %s", CERT_FILE)
log.info("   PFX  : %s", PFX_FILE)
log.info("   Log  : %s", log_file)
log.info("   → Bind new cert to tcp/21112 in service config")
log.info("   → Run 45411_WIN_VERIFY.py to confirm")
log.info("=" * 60)