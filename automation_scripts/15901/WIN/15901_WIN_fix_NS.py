import subprocess
import os
import shutil
import logging
import sys
import datetime

print("=" * 60)
print("SSL Certificate Expiry Fix — Plugin 15901")
print("Service: SQL Server (tcp/1433)")
print("Expired: Aug 10 10:45:02 2024 GMT")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"15901_win_fix_{timestamp}.log"

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
# ← Update these for your environment
CERT_CN        = "hq-hrms.dom.com"         # ← change to your FQDN
ORG            = "Ibdar"
COUNTRY        = "BH"
CITY           = "Manama"
CA_NAME        = "dom-DC12SRV-CA"          # ← your internal CA name
CERT_DIR       = r"C:\SSL\SQLCerts"
CERT_FILE      = os.path.join(CERT_DIR, "sqlserver.crt")
KEY_FILE       = os.path.join(CERT_DIR, "sqlserver.key")
CSR_FILE       = os.path.join(CERT_DIR, "sqlserver.csr")
PFX_FILE       = os.path.join(CERT_DIR, "sqlserver.pfx")
CONFIG_FILE    = os.path.join(CERT_DIR, "openssl_sql.cnf")
PFX_PASSWORD   = "YourSecurePassword123!"  # ← change this
DAYS_VALID     = 825

# ─── Step 1: Create directories ───────────────────────────────────
log.info("\n[1] Creating certificate directories...")
os.makedirs(CERT_DIR, exist_ok=True)
log.info("✅ Directory ready: %s", CERT_DIR)

# ─── Step 2: Backup existing cert ────────────────────────────────
log.info("\n[2] Backing up existing certificate...")
for f in [CERT_FILE, KEY_FILE, PFX_FILE]:
    if os.path.exists(f):
        shutil.copy2(f, f"{f}.bak_{timestamp}")
        log.info("✅ Backed up: %s", f)

# ─── Step 3: Check OpenSSL ────────────────────────────────────────
log.info("\n[3] Checking OpenSSL availability...")
result = subprocess.run(["where", "openssl"], capture_output=True, text=True)
if result.returncode != 0:
    log.warning("⚠️ OpenSSL not found — installing via winget...")
    try:
        subprocess.run([
            "winget", "install", "--id",
            "ShiningLight.OpenSSL.Light",
            "--silent", "--accept-package-agreements"
        ], check=True)
        log.info("✅ OpenSSL installed!")
    except Exception as e:
        log.error("❌ Could not install OpenSSL: %s", e)
        sys.exit(1)
else:
    log.info("✅ OpenSSL found")

# ─── Step 4: Create OpenSSL config ───────────────────────────────
log.info("\n[4] Creating OpenSSL config with SAN...")
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
DNS.1 = {CERT_CN}
"""
with open(CONFIG_FILE, "w") as f:
    f.write(openssl_config)
log.info("✅ OpenSSL config created: %s", CONFIG_FILE)

# ─── Step 5: Generate new private key ────────────────────────────
log.info("\n[5] Generating new 4096-bit RSA private key...")
try:
    subprocess.run([
        "openssl", "genrsa",
        "-out", KEY_FILE, "4096"
    ], check=True, capture_output=True)
    log.info("✅ Private key generated: %s", KEY_FILE)
except subprocess.CalledProcessError as e:
    log.error("❌ Failed to generate key: %s", e)
    sys.exit(1)

# ─── Step 6: Generate CSR ─────────────────────────────────────────
log.info("\n[6] Generating Certificate Signing Request (CSR)...")
try:
    subprocess.run([
        "openssl", "req", "-new",
        "-key", KEY_FILE,
        "-out", CSR_FILE,
        "-config", CONFIG_FILE
    ], check=True, capture_output=True)
    log.info("✅ CSR generated: %s", CSR_FILE)
    log.info("   → Submit to CA: %s", CA_NAME)
except subprocess.CalledProcessError as e:
    log.error("❌ Failed to generate CSR: %s", e)

# ─── Step 7: Try to auto-enroll via internal CA ──────────────────
log.info("\n[7] Attempting auto-enrollment via internal Windows CA...")
try:
    # Try certreq for internal CA submission
    inf_file = os.path.join(CERT_DIR, "sqlserver.inf")
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

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1 ; Server Authentication
"""
    with open(inf_file, "w") as f:
        f.write(inf_content)

    req_file = os.path.join(CERT_DIR, "sqlserver.req")
    subprocess.run([
        "certreq", "-new", inf_file, req_file
    ], check=True, capture_output=True)
    log.info("✅ certreq INF processed: %s", req_file)

    # Submit to internal CA
    cer_file = os.path.join(CERT_DIR, "sqlserver.cer")
    subprocess.run([
        "certreq", "-submit",
        "-config", f"-\\{CA_NAME}",
        req_file, cer_file
    ], check=True, capture_output=True)
    log.info("✅ Certificate submitted to CA: %s", CA_NAME)

    # Accept and install
    subprocess.run([
        "certreq", "-accept", cer_file
    ], check=True, capture_output=True)
    log.info("✅ Certificate accepted and installed!")
    ca_enrolled = True

except Exception as e:
    log.warning("⚠️ Auto-enrollment failed: %s", e)
    log.warning("   → Falling back to self-signed (temporary)")
    ca_enrolled = False

# ─── Step 8: Generate temp self-signed if CA failed ──────────────
if not ca_enrolled:
    log.info("\n[8] Generating temporary self-signed certificate...")
    log.warning("   ⚠️  Replace with CA-signed cert before production!")
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
        log.info("✅ Temporary certificate generated: %s", CERT_FILE)
    except Exception as e:
        log.error("❌ Failed to generate certificate: %s", e)
        sys.exit(1)

    # Export as PFX
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

# ─── Step 9: Import PFX to Windows Certificate Store ─────────────
log.info("\n[10] Importing certificate to Windows Store...")
try:
    subprocess.run([
        "powershell", "-Command",
        f"Import-PfxCertificate -FilePath '{PFX_FILE}' "
        f"-CertStoreLocation Cert:\\LocalMachine\\My "
        f"-Password (ConvertTo-SecureString -String '{PFX_PASSWORD}' "
        f"-AsPlainText -Force)"
    ], check=True, capture_output=True)
    log.info("✅ Certificate imported to LocalMachine\\My store")
except Exception as e:
    log.warning("⚠️ Could not import to certificate store: %s", e)

# ─── Step 10: Configure SQL Server to use new cert ────────────────
log.info("\n[11] Configuring SQL Server to use new certificate...")
log.warning("   ⚠️  SQL Server certificate must be configured via:")
log.warning("   SQL Server Configuration Manager →")
log.warning("   SQL Server Network Configuration →")
log.warning("   Protocols for MSSQLSERVER → Properties → Certificate tab")
log.warning("   OR via registry key below:")

sql_cert_thumbprint_cmd = (
    f"Get-ChildItem Cert:\\LocalMachine\\My | "
    f"Where-Object {{$_.Subject -like '*{CERT_CN}*'}} | "
    f"Select-Object Thumbprint, Subject, NotAfter"
)

result = subprocess.run([
    "powershell", "-Command", sql_cert_thumbprint_cmd
], capture_output=True, text=True)
log.info("   Available certificates:\n%s", result.stdout)

# ─── Step 11: Restart SQL Server ─────────────────────────────────
log.info("\n[12] Restarting SQL Server service...")
try:
    subprocess.run([
        "powershell", "-Command",
        "Restart-Service -Name MSSQLSERVER -Force"
    ], check=True, capture_output=True)
    log.info("✅ SQL Server restarted successfully!")
except Exception as e:
    log.warning("⚠️ Could not restart SQL Server: %s", e)
    log.warning("   → Restart manually via Services or SQL Config Manager")

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   CSR  : %s", CSR_FILE)
log.info("   Cert : %s", CERT_FILE)
log.info("   PFX  : %s", PFX_FILE)
log.info("   Log  : %s", log_file)
log.info("   ⚠️  Manually assign cert in SQL Server Config Manager")
log.info("   → Run 15901_WIN_VERIFY.py to confirm")
log.info("=" * 60)