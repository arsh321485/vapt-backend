import urllib.request
import urllib.error
import ssl
import logging
import sys
import subprocess

print("=" * 60)
print("HSTS Missing Verify — Plugin 142960 — Windows")
print("Service: tcp/5580/www")
print("=" * 60)

TARGET_HOST = "YOUR_VM_IP"   # ← change this
TARGET_PORT = 5580

URLS_TO_CHECK = [
    f"https://{TARGET_HOST}:{TARGET_PORT}/",
    f"http://{TARGET_HOST}:{TARGET_PORT}/",
]

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

# ─── Check 1: HSTS header on HTTPS ───────────────────────────────
log.info("\n[1] Checking HSTS header on HTTPS responses...")
https_url = f"https://{TARGET_HOST}:{TARGET_PORT}/"
try:
    req      = urllib.request.Request(https_url)
    req.add_header("User-Agent", "NessusVerifyScript/1.0")
    response = urllib.request.urlopen(req, timeout=5, context=ctx)
    headers  = dict(response.headers)

    hsts = headers.get("Strict-Transport-Security", "")
    if hsts:
        log.info("✅ HSTS header present: %s", hsts)
        if "max-age" in hsts:
            log.info("✅ max-age directive found")
        if "includeSubDomains" in hsts:
            log.info("✅ includeSubDomains present")
    else:
        log.error("❌ Strict-Transport-Security header MISSING!")
        all_good = False

    log.info("   All headers:")
    for k, v in headers.items():
        log.info("   %s: %s", k, v)

except urllib.error.HTTPError as e:
    hsts = e.headers.get("Strict-Transport-Security", "")
    if hsts:
        log.info("✅ HSTS on HTTP %d response: %s", e.code, hsts)
    else:
        log.error("❌ HSTS missing on HTTP %d response!", e.code)
        all_good = False
except Exception as e:
    log.warning("⚠️ Could not connect to %s: %s", https_url, e)

# ─── Check 2: Port 5580 is listening ─────────────────────────────
log.info("\n[2] Checking port 5580 is listening...")
result = subprocess.run([
    "powershell", "-Command",
    "netstat -an | Select-String ':5580'"
], capture_output=True, text=True)
if "5580" in result.stdout:
    log.info("✅ Port 5580 is listening")
else:
    log.warning("⚠️ Port 5580 not detected")

# ─── Check 3: TwistedWeb service running ─────────────────────────
log.info("\n[3] Checking TwistedWeb service...")
result = subprocess.run([
    "powershell", "-Command",
    "Get-Process | Where-Object {$_.Name -like '*python*' -or "
    "$_.Name -like '*twisted*'} | "
    "Select-Object Name, Id | Format-Table"
], capture_output=True, text=True)
if result.stdout.strip():
    log.info("✅ Python/Twisted process running:\n%s",
             result.stdout.strip())
else:
    log.warning("⚠️ No Python/Twisted process found")

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — HSTS header is present!")
    print("   Re-run Nessus scan to confirm Plugin 142960 resolved.")
else:
    print("❌ VERDICT: FAIL — HSTS header still missing.")
    print("   Review and re-run 142960_WIN_FIX.py")
print("=" * 60)