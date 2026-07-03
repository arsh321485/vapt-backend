import urllib.request
import urllib.error
import ssl
import logging
import sys
import re
import subprocess

print("=" * 60)
print("Cleartext Credentials Verify — Plugin 26194 — Ubuntu")
print("Service: tcp/1010/www")
print("=" * 60)

TARGET_HOST = "192.168.0.20"
HTTP_PORT   = 1010
HTTPS_PORT  = 443

URLS_TO_CHECK = [
    f"http://{TARGET_HOST}:{HTTP_PORT}/",
    f"http://{TARGET_HOST}:{HTTP_PORT}/login",
    f"http://{TARGET_HOST}:{HTTP_PORT}/Login",
    f"http://{TARGET_HOST}:{HTTP_PORT}/Login/Validate",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("cleartext_verify")
all_good = True

# ─── Check 1: HTTP redirects to HTTPS ────────────────────────────
log.info("\n[1] Checking HTTP → HTTPS redirects...")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

for url in URLS_TO_CHECK:
    log.info("\n   Testing: %s", url)
    try:
        opener = urllib.request.build_opener(NoRedirect)
        try:
            opener.open(url, timeout=5)
            log.error("   ❌ No redirect — HTTP not enforcing HTTPS!")
            all_good = False
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 307, 308):
                location = e.headers.get("Location", "")
                if location.startswith("https://"):
                    log.info(
                        "   ✅ HTTP %d → HTTPS redirect: %s",
                        e.code, location
                    )
                else:
                    log.error(
                        "   ❌ Redirect NOT to HTTPS: %s", location
                    )
                    all_good = False
            else:
                log.warning("   ⚠️ HTTP %d — no redirect", e.code)

    except Exception as e:
        log.warning("   ⚠️ Could not connect: %s", e)

# ─── Check 2: HTTPS form actions ─────────────────────────────────
log.info("\n[2] Checking form actions over HTTPS...")
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

for url in URLS_TO_CHECK:
    https_url = url.replace(
        f"http://{TARGET_HOST}:{HTTP_PORT}",
        f"https://{TARGET_HOST}:{HTTPS_PORT}"
    )
    try:
        req      = urllib.request.Request(https_url)
        response = urllib.request.urlopen(req, timeout=5,
                                          context=ctx)
        html     = response.read().decode("utf-8", errors="ignore")

        actions = re.findall(
            r'<form[^>]*action=["\']([^"\']*)["\']',
            html, re.IGNORECASE
        )
        for action in actions:
            if action.startswith("http://"):
                log.error(
                    "   ❌ Form submits over HTTP: %s", action
                )
                all_good = False
            else:
                log.info("   ✅ Form action secure: %s", action)

    except Exception as e:
        log.warning("   ⚠️ Could not check %s: %s", https_url, e)

# ─── Check 3: HSTS header ─────────────────────────────────────────
log.info("\n[3] Checking HSTS header...")
try:
    https_url = f"https://{TARGET_HOST}:{HTTPS_PORT}/"
    req       = urllib.request.Request(https_url)
    response  = urllib.request.urlopen(req, timeout=5, context=ctx)
    hsts      = response.headers.get(
        "Strict-Transport-Security", ""
    )
    if hsts:
        log.info("✅ HSTS header: %s", hsts)
    else:
        log.warning("⚠️ HSTS header not found")
except Exception as e:
    log.warning("⚠️ Could not check HSTS: %s", e)

# ─── Check 4: HTTPS port listening ───────────────────────────────
log.info("\n[4] Checking HTTPS port %d is listening...", HTTPS_PORT)
result = subprocess.run(
    ["ss", "-tlnp"], capture_output=True, text=True
)
if f":{HTTPS_PORT}" in result.stdout:
    log.info("✅ Port %d is listening", HTTPS_PORT)
else:
    log.warning("⚠️ Port %d not detected", HTTPS_PORT)

# ─── Check 5: Nginx redirect config ──────────────────────────────
log.info("\n[5] Checking nginx/apache redirect config...")
import os
nginx_conf  = "/etc/nginx/conf.d/https_redirect.conf"
apache_conf = (
    "/etc/apache2/sites-enabled/https_redirect.conf"
)
for conf in [nginx_conf, apache_conf]:
    if os.path.exists(conf):
        with open(conf, "r") as f:
            content = f.read()
        if "301" in content or "return 301" in content or \
           "RewriteRule" in content:
            log.info("✅ HTTPS redirect config found: %s", conf)
        else:
            log.warning("⚠️ No redirect rule in: %s", conf)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — Credentials transmitted over HTTPS!")
    print("   Re-run Nessus scan to confirm Plugin 26194 resolved.")
else:
    print("❌ VERDICT: FAIL — Some forms still transmit over HTTP.")
    print("   Review above and re-run 26194_UBUNTU_FIX.py")
print("=" * 60)