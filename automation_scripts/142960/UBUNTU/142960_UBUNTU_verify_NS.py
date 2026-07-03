import urllib.request
import urllib.error
import ssl
import subprocess
import logging
import sys

print("=" * 60)
print("HSTS Missing Verify — Plugin 142960 — Ubuntu")
print("Service: tcp/5580/www (TwistedWeb)")
print("=" * 60)

TARGET_HOST = "YOUR_VM_IP"   # ← change this
TARGET_PORT = 5580

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("hsts_verify")
all_good = True

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

# ─── Check 1: HSTS on HTTPS response ─────────────────────────────
log.info("\n[1] Checking HSTS header on port %d...", TARGET_PORT)
https_url = f"https://{TARGET_HOST}:{TARGET_PORT}/"

try:
    req      = urllib.request.Request(https_url)
    req.add_header("User-Agent", "NessusVerifyScript/1.0")
    response = urllib.request.urlopen(req, timeout=5, context=ctx)
    headers  = dict(response.headers)

    hsts = headers.get("Strict-Transport-Security", "")
    if hsts:
        log.info("✅ HSTS header: %s", hsts)
        if "max-age" in hsts:
            log.info("✅ max-age directive present")
        if "includeSubDomains" in hsts:
            log.info("✅ includeSubDomains present")
    else:
        log.error("❌ Strict-Transport-Security header MISSING!")
        all_good = False

    log.info("   All response headers:")
    for k, v in headers.items():
        log.info("   %s: %s", k, v)

except urllib.error.HTTPError as e:
    hsts = e.headers.get("Strict-Transport-Security", "")
    if hsts:
        log.info("✅ HSTS on HTTP %d: %s", e.code, hsts)
    else:
        log.error(
            "❌ HSTS missing on HTTP %d response — server: %s",
            e.code,
            e.headers.get("Server", "unknown")
        )
        all_good = False
except Exception as e:
    log.warning("⚠️ Could not connect to %s: %s", https_url, e)

# ─── Check 2: Port 5580 listening ────────────────────────────────
log.info("\n[2] Checking port %d is listening...", TARGET_PORT)
result = subprocess.run(
    ["ss", "-tlnp"], capture_output=True, text=True
)
if f":{TARGET_PORT}" in result.stdout:
    log.info("✅ Port %d is listening", TARGET_PORT)
else:
    log.warning("⚠️ Port %d not detected", TARGET_PORT)

# ─── Check 3: TwistedWeb process running ─────────────────────────
log.info("\n[3] Checking TwistedWeb process...")
result = subprocess.run(
    ["ps", "aux"], capture_output=True, text=True
)
twisted_procs = [
    l for l in result.stdout.splitlines()
    if "twisted" in l.lower() or
    ("python" in l.lower() and str(TARGET_PORT) in l)
]
if twisted_procs:
    log.info("✅ TwistedWeb/Python process found:")
    for p in twisted_procs[:3]:
        log.info("   %s", p[:120])
else:
    log.warning("⚠️ No TwistedWeb process detected")

# ─── Check 4: curl verification ──────────────────────────────────
log.info("\n[4] Verifying via curl (if available)...")
try:
    result = subprocess.run([
        "curl", "-sk", "-I",
        f"https://{TARGET_HOST}:{TARGET_PORT}/"
    ], capture_output=True, text=True, timeout=10)

    if "strict-transport-security" in result.stdout.lower():
        hsts_line = next(
            l for l in result.stdout.splitlines()
            if "strict-transport-security" in l.lower()
        )
        log.info("✅ curl confirms HSTS: %s", hsts_line.strip())
    else:
        log.error("❌ curl: HSTS header not found!")
        log.info("   curl headers:\n%s", result.stdout[:500])
        all_good = False

except FileNotFoundError:
    log.info("   curl not available — skipping")
except Exception as e:
    log.warning("⚠️ curl check failed: %s", e)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — HSTS header is present!")
    print("   Re-run Nessus scan to confirm Plugin 142960 resolved.")
else:
    print("❌ VERDICT: FAIL — HSTS header still missing.")
    print("   Add HSTSResource wrapper to TwistedWeb .tac file")
    print("   and restart the service.")
print("=" * 60)