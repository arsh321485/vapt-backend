import subprocess
import ssl
import socket
import os
import datetime
import logging
import sys

print("=" * 60)
print("SSL Certificate Expiry Verify — Plugin 15901")
print("Service: SQL Server (tcp/1433)")
print("=" * 60)

HOST      = "YOUR_VM_IP"     # ← change this
PORT      = 1433
CERT_FILE = r"C:\SSL\SQLCerts\sqlserver.crt"
CERT_CN   = "hq-hrms.dom.com"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("ssl_expiry_verify")
all_good = True

# ─── Check 1: Certificate file exists ────────────────────────────
log.info("\n[1] Checking certificate file...")
if os.path.exists(CERT_FILE):
    log.info("✅ Certificate found: %s", CERT_FILE)
else:
    log.error("❌ Certificate NOT found: %s", CERT_FILE)
    all_good = False

# ─── Check 2: Certificate validity dates ─────────────────────────
log.info("\n[2] Checking certificate validity dates...")
try:
    result = subprocess.run([
        "openssl", "x509", "-in", CERT_FILE,
        "-noout", "-dates"
    ], capture_output=True, text=True, check=True)
    log.info("   %s", result.stdout.strip())

    result2 = subprocess.run([
        "openssl", "x509", "-in", CERT_FILE,
        "-noout", "-checkend", "0"
    ], capture_output=True, text=True)
    if result2.returncode == 0:
        log.info("✅ Certificate is currently VALID (not expired)")
    else:
        log.error("❌ Certificate has EXPIRED!")
        all_good = False

    # Check valid for at least 30 days
    result3 = subprocess.run([
        "openssl", "x509", "-in", CERT_FILE,
        "-noout", "-checkend", "2592000"  # 30 days
    ], capture_output=True, text=True)
    if result3.returncode == 0:
        log.info("✅ Certificate valid for at least 30 more days")
    else:
        log.warning("⚠️ Certificate expires within 30 days — renew soon!")

except Exception as e:
    log.error("❌ Could not check validity: %s", e)
    all_good = False

# ─── Check 3: Subject and issuer ─────────────────────────────────
log.info("\n[3] Checking certificate subject and issuer...")
try:
    result = subprocess.run([
        "openssl", "x509", "-in", CERT_FILE,
        "-noout", "-subject", "-issuer"
    ], capture_output=True, text=True, check=True)
    log.info("   %s", result.stdout.strip())

    lines   = result.stdout.lower().splitlines()
    subject = next((l for l in lines if "subject" in l), "")
    issuer  = next((l for l in lines if "issuer" in l), "")

    if subject == issuer:
        log.warning("⚠️ Certificate is self-signed — replace with CA cert!")
    else:
        log.info("✅ Certificate is CA-signed")
except Exception as e:
    log.error("❌ Could not check subject/issuer: %s", e)

# ─── Check 4: Windows Certificate Store ──────────────────────────
log.info("\n[4] Checking Windows Certificate Store for SQL cert...")
try:
    result = subprocess.run([
        "powershell", "-Command",
        f"Get-ChildItem Cert:\\LocalMachine\\My | "
        f"Where-Object {{$_.Subject -like '*{CERT_CN}*'}} | "
        f"Select-Object Subject, NotAfter, Thumbprint | Format-List"
    ], capture_output=True, text=True)
    if result.stdout.strip():
        log.info("✅ SQL Server cert found in Windows Store:\n%s",
                 result.stdout.strip())
    else:
        log.warning("⚠️ No cert found for %s in LocalMachine\\My", CERT_CN)
except Exception as e:
    log.error("❌ Could not check certificate store: %s", e)

# ─── Check 5: SQL Server service running ─────────────────────────
log.info("\n[5] Checking SQL Server service status...")
try:
    result = subprocess.run([
        "powershell", "-Command",
        "(Get-Service MSSQLSERVER).Status"
    ], capture_output=True, text=True)
    status = result.stdout.strip()
    if status == "Running":
        log.info("✅ SQL Server is Running")
    else:
        log.error("❌ SQL Server status: %s", status)
        all_good = False
except Exception as e:
    log.warning("⚠️ Could not check SQL Server service: %s", e)

# ─── Check 6: Port 1433 is listening ─────────────────────────────
log.info("\n[6] Checking if port 1433 is listening...")
result = subprocess.run([
    "powershell", "-Command",
    "netstat -an | Select-String ':1433'"
], capture_output=True, text=True)
if "1433" in result.stdout:
    log.info("✅ Port 1433 is open and listening")
else:
    log.warning("⚠️ Port 1433 not detected — check SQL Server config")

# ─── Check 7: Live SSL connection ─────────────────────────────────
log.info("\n[7] Checking live SSL on %s:%d...", HOST, PORT)
try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        with ctx.wrap_socket(sock) as ssock:
            cert   = ssock.getpeercert()
            cipher = ssock.cipher()
            log.info("✅ SSL connection established")
            log.info("   Cipher: %s / %s / %s-bit",
                     cipher[0], cipher[1], cipher[2])
            if cert:
                not_after = cert.get("notAfter", "Unknown")
                log.info("   Valid until: %s", not_after)
except Exception as e:
    log.warning("⚠️ Could not connect to %s:%d: %s", HOST, PORT, e)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — SSL certificate is valid and not expired!")
    print("   Re-run Nessus scan to confirm Plugin 15901 resolved.")
else:
    print("❌ VERDICT: FAIL — Certificate is expired or missing.")
    print("   Review above and re-run 15901_WIN_FIX.py")
print("=" * 60)