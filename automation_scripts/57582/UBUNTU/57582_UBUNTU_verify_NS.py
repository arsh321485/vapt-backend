import subprocess
import ssl
import socket
import os

print("=" * 60)
print("SSL Self-Signed Certificate Verify — Ubuntu")
print("Plugin 57582")
print("=" * 60)

HOST      = "YOUR_VM_IP"   # ← change this
PORT      = 443            # ← change if different
CERT_FILE = "/etc/ssl/certs/custom/server.crt"
all_good  = True

# ─── Check 1: Certificate file exists ────────────────────────────
print("\n[1] Checking certificate file...")
if os.path.exists(CERT_FILE):
    print(f"✅ Certificate found: {CERT_FILE}")
else:
    print(f"❌ Certificate NOT found: {CERT_FILE}")
    all_good = False

# ─── Check 2: Certificate is NOT self-signed ─────────────────────
print("\n[2] Checking if certificate is self-signed...")
try:
    result = subprocess.run([
        "openssl", "x509",
        "-in", CERT_FILE,
        "-noout", "-subject", "-issuer"
    ], capture_output=True, text=True, check=True)
    output = result.stdout.strip()
    print(f"   {output}")

    lines  = output.lower().splitlines()
    subject = next((l for l in lines if "subject" in l), "")
    issuer  = next((l for l in lines if "issuer" in l), "")

    if subject == issuer:
        print("❌ Certificate is SELF-SIGNED — not trusted by browsers!")
        print("   → Submit CSR to trusted CA to resolve this")
        all_good = False
    else:
        print("✅ Certificate is signed by a CA — not self-signed")
except Exception as e:
    print(f"❌ Could not check subject/issuer: {e}")
    all_good = False

# ─── Check 3: Certificate validity ───────────────────────────────
print("\n[3] Checking certificate validity dates...")
try:
    result = subprocess.run([
        "openssl", "x509", "-in", CERT_FILE,
        "-noout", "-dates"
    ], capture_output=True, text=True, check=True)
    print(f"   {result.stdout.strip()}")

    result2 = subprocess.run([
        "openssl", "x509", "-in", CERT_FILE,
        "-noout", "-checkend", "0"
    ], capture_output=True, text=True)
    if result2.returncode == 0:
        print("✅ Certificate is currently valid")
    else:
        print("❌ Certificate has EXPIRED!")
        all_good = False
except Exception as e:
    print(f"❌ Could not check validity: {e}")
    all_good = False

# ─── Check 4: Let's Encrypt cert check ───────────────────────────
print("\n[4] Checking for Let's Encrypt certificate...")
le_cert = "/etc/letsencrypt/live"
if os.path.exists(le_cert) and os.listdir(le_cert):
    print(f"✅ Let's Encrypt certificates found in {le_cert}")
else:
    print("⚠️ No Let's Encrypt certificates found")
    print("   → Consider using certbot for trusted certificate")

# ─── Check 5: Live SSL connection ────────────────────────────────
print(f"\n[5] Checking live SSL on {HOST}:{PORT}...")
try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        with ctx.wrap_socket(sock) as ssock:
            cipher = ssock.cipher()
            print(f"✅ SSL connection established")
            print(f"   Cipher: {cipher[0]} / {cipher[1]} / {cipher[2]}-bit")

            # Try with cert verification
    ctx2 = ssl.create_default_context()
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        with ctx2.wrap_socket(sock, server_hostname=HOST):
            print("✅ Certificate is trusted by system CA store!")
except ssl.SSLCertVerificationError:
    print("❌ Certificate is NOT trusted by system CA store")
    print("   → Replace self-signed cert with CA-signed certificate")
    all_good = False
except Exception as e:
    print(f"⚠️ Could not connect: {e}")

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — Certificate is trusted and valid!")
    print("   Re-run Nessus scan to confirm Plugin 57582 resolved.")
else:
    print("❌ VERDICT: FAIL — Certificate is still self-signed or invalid.")
    print("   Submit CSR to trusted CA and replace certificate.")
print("=" * 60)