import subprocess
import urllib.request
import urllib.error
import ssl
import logging
import sys
import os

print("=" * 60)
print("Clickjacking Verify — Plugin 85582 — Ubuntu")
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

# ─── Check 1: Config files have headers ──────────────────────────
log.info("\n[1] Checking config files for header directives...")

nginx_conf  = "/etc/nginx/conf.d/security_headers.conf"
apache_conf = "/etc/apache2/conf-available/security_headers.conf"

for conf in [nginx_conf, apache_conf]:
    if os.path.exists(conf):
        with open(conf, "r") as f:
            content = f.read()
        if "X-Frame-Options" in content:
            log.info("✅ X-Frame-Options in: %s", conf)
        else:
            log.warning("⚠️ X-Frame-Options missing in: %s", conf)
        if "frame-ancestors" in content:
            log.info("✅ CSP frame-ancestors in: %s", conf)
        else:
            log.warning("⚠️ CSP frame-ancestors missing in: %s", conf)

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
        response = urllib.request.urlopen(req, timeout=5)
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

# ─── Check 3: Web server services active ─────────────────────────
log.info("\n[3] Checking web server service status...")
for svc in ["nginx", "apache2"]:
    result = subprocess.run(
        ["systemctl", "is-active", svc],
        capture_output=True, text=True
    )
    status = result.stdout.strip()
    if status == "active":
        log.info("✅ %s is active", svc)
    else:
        log.info("   %s: %s", svc, status)

# ─── Check 4: Port 1010 is listening ─────────────────────────────
log.info("\n[4] Checking port %d is listening...", TARGET_PORT)
result = subprocess.run(
    ["ss", "-tlnp"], capture_output=True, text=True
)
if str(TARGET_PORT) in result.stdout:
    log.info("✅ Port %d is listening", TARGET_PORT)
else:
    log.warning("⚠️ Port %d not found in listening ports", TARGET_PORT)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — Clickjacking headers present on all URLs!")
    print("   Re-run Nessus scan to confirm Plugin 85582 resolved.")
else:
    print("❌ VERDICT: FAIL — Headers missing on some URLs.")
    print("   Review above and re-run 85582_UBUNTU_FIX.py")
print("=" * 60)