import subprocess
import ssl
import socket
import os
import logging
import sys

print("=" * 60)
print("SSL Certificate Expiry Verify — Plugin 15901 — Ubuntu")
print("=" * 60)

HOST      = "YOUR_VM_IP"   # ← change this
PORT      = 1433           # ← change if different
CERT_FILE = "/etc/ssl/certs/custom/server.crt"

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

# ─── Check 2: Certificate not expired ────────────────────────────
log.info("\n[2] Checking certificate validity...")
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
        log.info("✅ Certificate is currently VALID")
    else:
        log.error("❌ Certificate has EXPIRED!")
        all_good = False

    # Check 30 days
    result3 = subprocess.run([
        "openssl", "x509", "-in", CERT_FILE,
        "-noout", "-checkend", "2592000"
    ], capture_output=True, text=True)
    if result3.returncode == 0:
        log.info("✅ Certificate valid for at least 30 more days")
    else:
        log.warning("⚠️ Certificate expires within 30 days!")

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

# ─── Check 4: Let's Encrypt cert check ───────────────────────────
log.info("\n[4] Checking for Let's Encrypt certificates...")
le_path = "/etc/letsencrypt/live"
if os.path.exists(le_path) and os.listdir(le_path):
    log.info("✅ Let's Encrypt certificates found in %s", le_path)
    # Check LE cert expiry
    for domain in os.listdir(le_path):
        le_cert = f"{le_path}/{domain}/cert.pem"
        if os.path.exists(le_cert):
            result = subprocess.run([
                "openssl", "x509", "-in", le_cert,
                "-noout", "-checkend", "0"
            ], capture_output=True, text=True)
            if result.returncode == 0:
                log.info("✅ LE cert for %s is valid", domain)
            else:
                log.error("❌ LE cert for %s has EXPIRED!", domain)
                all_good = False
else:
    log.info("   No Let's Encrypt certificates found")

# ─── Check 5: Live SSL connection ─────────────────────────────────
log.info("\n[5] Checking live SSL on %s:%d...", HOST, PORT)
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
    print("❌ VERDICT: FAIL — Certificate is still expired or invalid.")
    print("   Review above and re-run 15901_UBUNTU_FIX.py")
print("=" * 60)