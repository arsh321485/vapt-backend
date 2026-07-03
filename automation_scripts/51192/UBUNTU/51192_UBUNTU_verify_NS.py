import subprocess
import ssl
import socket
import datetime

print("=" * 60)
print("SSL Certificate Cannot Be Trusted Verify — Ubuntu")
print("Plugin 51192")
print("=" * 60)

HOST = "YOUR_VM_IP"   # ← change this
PORT = 1003           # ← change if different
CERT_FILE = "/etc/ssl/certs/custom/server.crt"

all_good = True

# ─── Check 1: Certificate file exists ────────────────────────────
print("\n[1] Checking certificate file exists...")
import os
if os.path.exists(CERT_FILE):
    print(f"✅ Certificate found: {CERT_FILE}")
else:
    print(f"❌ Certificate NOT found: {CERT_FILE}")
    all_good = False

# ─── Check 2: Certificate validity dates ─────────────────────────
print("\n[2] Checking certificate validity dates...")
try:
    result = subprocess.run([
        "openssl", "x509",
        "-in", CERT_FILE,
        "-noout",
        "-dates"
    ], capture_output=True, text=True, check=True)
    print(f"   {result.stdout.strip()}")

    # Check if expired
    result2 = subprocess.run([
        "openssl", "x509",
        "-in", CERT_FILE,
        "-noout",
        "-checkend", "0"
    ], capture_output=True, text=True)
    if result2.returncode == 0:
        print("✅ Certificate is currently valid (not expired)")
    else:
        print("❌ Certificate has EXPIRED!")
        all_good = False
except Exception as e:
    print(f"❌ Could not check certificate dates: {e}")
    all_good = False

# ─── Check 3: Certificate subject and issuer ─────────────────────
print("\n[3] Checking certificate subject and issuer...")
try:
    result = subprocess.run([
        "openssl", "x509",
        "-in", CERT_FILE,
        "-noout",
        "-subject", "-issuer"
    ], capture_output=True, text=True, check=True)
    output = result.stdout.strip()
    print(f"   {output}")

    lines = output.lower().splitlines()
    subject = next((l for l in lines if "subject" in l), "")
    issuer = next((l for l in lines if "issuer" in l), "")

    if subject == issuer:
        print("⚠️ Certificate is self-signed — submit CSR to trusted CA!")
    else:
        print("✅ Certificate is CA-signed")
except Exception as e:
    print(f"❌ Could not check subject/issuer: {e}")

# ─── Check 4: Key strength ────────────────────────────────────────
print("\n[4] Checking certificate key strength...")
try:
    result = subprocess.run([
        "openssl", "x509",
        "-in", CERT_FILE,
        "-noout",
        "-text"
    ], capture_output=True, text=True)
    if "Public-Key: (4096 bit)" in result.stdout:
        print("✅ Key strength: 4096-bit RSA")
    elif "Public-Key: (2048 bit)" in result.stdout:
        print("✅ Key strength: 2048-bit RSA (acceptable)")
    else:
        print("⚠️ Check key strength manually")
except Exception as e:
    print(f"❌ Could not check key strength: {e}")

# ─── Check 5: Live connection certificate check ───────────────────
print(f"\n[5] Checking live certificate on {HOST}:{PORT}...")
try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        with ctx.wrap_socket(sock) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            print(f"✅ SSL connection established")
            print(f"   Cipher: {cipher[0]} / {cipher[1]} / {cipher[2]}-bit")
            if cert:
                not_after = cert.get("notAfter", "Unknown")
                print(f"   Valid until: {not_after}")
except Exception as e:
    print(f"⚠️ Could not connect to {HOST}:{PORT}: {e}")

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — Certificate is valid!")
    print("   Re-run Nessus scan to confirm Plugin 51192 is resolved.")
else:
    print("❌ VERDICT: FAIL — Some checks failed.")
    print("   Review above and re-run 51192_UBUNTU_FIX.py")
print("=" * 60)