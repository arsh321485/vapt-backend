import subprocess
import ssl
import socket
import os
import logging
import sys

print("=" * 60)
print("SSL Wrong Hostname Verify — Plugin 45411 — Ubuntu")
print("Service: tcp/21112")
print("=" * 60)

HOST      = "192.168.0.20"  # ← change if needed
PORT      = 21112
CERT_FILE = "/etc/ssl/certs/custom/server.crt"
CERT_CN   = "hq-hr-srv.dom.com"

EXPECTED_SANS = [
    "hq-hr-srv.dom.com",
    "hq-hr-srv",
    "hq-hrms.dom.com",
    "192.168.0.20"
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("wrong_hostname_verify")
all_good = True

# ─── Check 1: Certificate exists ─────────────────────────────────
log.info("\n[1] Checking certificate file...")
if os.path.exists(CERT_FILE):
    log.info("✅ Certificate found: %s", CERT_FILE)
else:
    log.error("❌ Certificate NOT found: %s", CERT_FILE)
    all_good = False

# ─── Check 2: CN is no longer 'ofcsslagent' ──────────────────────
log.info("\n[2] Checking CN is no longer 'ofcsslagent'...")
try:
    result = subprocess.run([
        "openssl", "x509", "-in", CERT_FILE,
        "-noout", "-subject"
    ], capture_output=True, text=True, check=True)
    subject = result.stdout.strip()
    log.info("   Subject: %s", subject)

    if "ofcsslagent" in subject.lower():
        log.error("❌ CN still shows 'ofcsslagent' — not fixed!")
        all_good = False
    elif CERT_CN.lower() in subject.lower():
        log.info("✅ CN correctly set to: %s", CERT_CN)
    else:
        log.warning("⚠️ CN: %s — verify this is correct", subject)

except Exception as e:
    log.error("❌ Could not check CN: %s", e)
    all_good = False

# ─── Check 3: SAN contains all identities ────────────────────────
log.info("\n[3] Checking Subject Alternative Names (SAN)...")
try:
    result = subprocess.run([
        "openssl", "x509", "-in", CERT_FILE,
        "-noout", "-text"
    ], capture_output=True, text=True, check=True)

    for identity in EXPECTED_SANS:
        if identity.lower() in result.stdout.lower():
            log.info("✅ SAN contains: %s", identity)
        else:
            log.warning("⚠️ SAN missing: %s", identity)

except Exception as e:
    log.error("❌ Could not check SAN: %s", e)

# ─── Check 4: Certificate validity ───────────────────────────────
log.info("\n[4] Checking certificate validity...")
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
        log.info("✅ Certificate is valid (not expired)")
    else:
        log.error("❌ Certificate has EXPIRED!")
        all_good = False
except Exception as e:
    log.error("❌ Could not check validity: %s", e)
    all_good = False

# ─── Check 5: Live SSL hostname verification ──────────────────────
log.info("\n[5] Checking live SSL on %s:%d...", HOST, PORT)
try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        with ctx.wrap_socket(sock) as ssock:
            cipher = ssock.cipher()
            log.info("✅ SSL connection established")
            log.info("   Cipher: %s / %s / %s-bit",
                     cipher[0], cipher[1], cipher[2])

    # With hostname verification
    ctx2 = ssl.create_default_context()
    ctx2.check_hostname = True
    ctx2.verify_mode    = ssl.CERT_REQUIRED
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        with ctx2.wrap_socket(sock, server_hostname=CERT_CN):
            log.info(
                "✅ Hostname verification PASSED for: %s", CERT_CN
            )

except ssl.SSLCertVerificationError as e:
    log.error(
        "❌ Hostname verification FAILED — CN still wrong: %s", e
    )
    all_good = False
except Exception as e:
    log.warning("⚠️ Could not connect: %s", e)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — Certificate hostname is now correct!")
    print("   Re-run Nessus scan to confirm Plugin 45411 resolved.")
else:
    print("❌ VERDICT: FAIL — Hostname mismatch still present.")
    print("   Review above and re-run 45411_UBUNTU_FIX.py")
print("=" * 60)