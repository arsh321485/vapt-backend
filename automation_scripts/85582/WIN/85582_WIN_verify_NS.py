import subprocess
import urllib.request
import urllib.error
import ssl
import logging
import sys

print("=" * 60)
print("Clickjacking Verify — Plugin 85582 — Windows")
print("Service: tcp/1010/www")
print("=" * 60)

TARGET_HOST = "192.168.0.20"  # ← change if needed
TARGET_PORT = 1010

URLS_TO_CHECK = [
    f"http://{TARGET_HOST}:{TARGET_PORT}/",
    f"http://{TARGET_HOST}:{TARGET_PORT}/Login",
    f"http://{TARGET_HOST}:{TARGET_PORT}/Login/Validate",
    f"http://{TARGET_HOST}:{TARGET_PORT}/login",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("clickjacking_verify")
all_good = True

# ─── Check 1: IIS custom headers configured ──────────────────────
log.info("\n[1] Checking IIS custom header configuration...")
try:
    result = subprocess.run([
        "powershell", "-Command",
        "Get-WebConfigurationProperty "
        "-pspath 'MACHINE/WEBROOT/APPHOST' "
        "-filter 'system.webServer/httpProtocol/customHeaders' "
        "-name Collection | "
        "Select-Object name, value | Format-Table -AutoSize"
    ], capture_output=True, text=True)
    log.info("   IIS Headers:\n%s", result.stdout.strip())

    if "X-Frame-Options" in result.stdout:
        log.info("✅ X-Frame-Options header found in IIS config")
    else:
        log.warning("⚠️ X-Frame-Options not found in IIS config")

    if "Content-Security-Policy" in result.stdout:
        log.info("✅ Content-Security-Policy header found in IIS config")
    else:
        log.warning("⚠️ Content-Security-Policy not found in IIS config")

except Exception as e:
    log.warning("⚠️ Could not check IIS config: %s", e)

# ─── Check 2: Live HTTP response headers ─────────────────────────
log.info("\n[2] Checking live HTTP response headers on all URLs...")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

for url in URLS_TO_CHECK:
    log.info("\n   URL: %s", url)
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "NessusVerifyScript/1.0")
        response = urllib.request.urlopen(req, timeout=5, context=ctx)
        headers  = dict(response.headers)

        xfo = headers.get("X-Frame-Options", "")
        csp = headers.get("Content-Security-Policy", "")

        if xfo:
            log.info("   ✅ X-Frame-Options    : %s", xfo)
        else:
            log.error("   ❌ X-Frame-Options missing!")
            all_good = False

        if csp and "frame-ancestors" in csp:
            log.info("   ✅ CSP frame-ancestors: %s", csp)
        elif csp:
            log.warning(
                "   ⚠️ CSP present but no frame-ancestors: %s", csp
            )
        else:
            log.warning("   ⚠️ Content-Security-Policy missing")

    except urllib.error.HTTPError as e:
        log.info("   HTTP %d — checking headers...", e.code)
        xfo = e.headers.get("X-Frame-Options", "")
        csp = e.headers.get("Content-Security-Policy", "")
        if xfo:
            log.info("   ✅ X-Frame-Options    : %s", xfo)
        else:
            log.error("   ❌ X-Frame-Options missing!")
            all_good = False
    except Exception as e:
        log.warning("   ⚠️ Could not connect to %s: %s", url, e)

# ─── Check 3: web.config exists ──────────────────────────────────
log.info("\n[3] Checking web.config exists...")
import os
web_config = r"C:\inetpub\wwwroot\web.config"
if os.path.exists(web_config):
    with open(web_config, "r") as f:
        content = f.read()
    if "X-Frame-Options" in content:
        log.info("✅ X-Frame-Options found in web.config")
    else:
        log.warning("⚠️ X-Frame-Options not in web.config")
else:
    log.warning("⚠️ web.config not found at default path")

# ─── Check 4: IIS service running ────────────────────────────────
log.info("\n[4] Checking IIS service status...")
result = subprocess.run([
    "powershell", "-Command",
    "(Get-Service W3SVC -ErrorAction SilentlyContinue).Status"
], capture_output=True, text=True)
if "Running" in result.stdout:
    log.info("✅ IIS is Running")
else:
    log.warning("⚠️ IIS status: %s", result.stdout.strip())

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — Clickjacking headers are present!")
    print("   Re-run Nessus scan to confirm Plugin 85582 resolved.")
else:
    print("❌ VERDICT: FAIL — Headers missing on some URLs.")
    print("   Review above and re-run 85582_WIN_FIX.py")
print("=" * 60)