import urllib.request
import urllib.error
import ssl
import subprocess
import os
import logging
import sys

print("=" * 60)
print("Backup Files Verify — Plugin 11411 — Ubuntu")
print("Service: tcp/443/www")
print("=" * 60)

TARGET_HOST = "192.168.0.254"

BACKUP_URLS = [
    f"https://{TARGET_HOST}/logout~",
    f"https://{TARGET_HOST}/logout.bak",
    f"https://{TARGET_HOST}/logout.old",
    f"https://{TARGET_HOST}/index.bak",
    f"https://{TARGET_HOST}/.htaccess",
]

WEB_ROOTS = [
    "/var/www/html",
    "/var/www",
    "/opt/app",
]

BACKUP_EXTENSIONS = [
    "~", ".bak", ".old", ".orig",
    ".backup", ".tmp", ".swp",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("backup_verify")
all_good = True

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

# ─── Check 1: Backup URLs return 403/404 ─────────────────────────
log.info("\n[1] Checking backup file URLs are blocked...")
for url in BACKUP_URLS:
    log.info("\n   Testing: %s", url)
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "NessusVerifyScript/1.0")
        response = urllib.request.urlopen(
            req, timeout=5, context=ctx
        )
        log.error(
            "   ❌ HTTP %d — Backup file ACCESSIBLE!",
            response.status
        )
        all_good = False
    except urllib.error.HTTPError as e:
        if e.code in (403, 404):
            log.info("   ✅ HTTP %d — blocked/not found", e.code)
        else:
            log.warning("   ⚠️ HTTP %d — verify manually", e.code)
    except Exception as e:
        log.info("   ✅ Not accessible: %s", type(e).__name__)

# ─── Check 2: Nginx block config exists ──────────────────────────
log.info("\n[2] Checking nginx backup block config...")
nginx_conf = "/etc/nginx/conf.d/block_backups.conf"
apache_conf = "/etc/apache2/conf-enabled/block_backups.conf"

for conf in [nginx_conf, apache_conf]:
    if os.path.exists(conf):
        with open(conf, "r") as f:
            content = f.read()
        if "bak" in content or "~" in content:
            log.info("✅ Backup block config: %s", conf)
        else:
            log.warning("⚠️ Block config incomplete: %s", conf)

# ─── Check 3: No backup files in web roots ───────────────────────
log.info("\n[3] Scanning web roots for remaining backup files...")
found_backups = []
for web_root in WEB_ROOTS:
    if not os.path.exists(web_root):
        continue
    for dirpath, _, files in os.walk(web_root):
        for f in files:
            if any(f.endswith(ext) for ext in BACKUP_EXTENSIONS):
                found_backups.append(os.path.join(dirpath, f))

if found_backups:
    log.error("❌ Backup files still present:")
    for bf in found_backups:
        log.error("   %s", bf)
    all_good = False
else:
    log.info("✅ No backup files in web roots")

# ─── Check 4: curl verification ──────────────────────────────────
log.info("\n[4] Verifying /logout~ via curl...")
try:
    result = subprocess.run([
        "curl", "-sk", "-o", "/dev/null",
        "-w", "%{http_code}",
        f"https://{TARGET_HOST}/logout~"
    ], capture_output=True, text=True, timeout=10)

    code = result.stdout.strip()
    if code in ("403", "404"):
        log.info("✅ curl: /logout~ returns HTTP %s", code)
    else:
        log.error("❌ curl: /logout~ returns HTTP %s — still accessible!",
                  code)
        all_good = False
except FileNotFoundError:
    log.info("   curl not available — skipping")
except Exception as e:
    log.warning("⚠️ curl failed: %s", e)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — Backup files blocked/removed!")
    print("   Re-run Nessus scan to confirm Plugin 11411 resolved.")
else:
    print("❌ VERDICT: FAIL — Backup files still accessible.")
    print("   Review and re-run 11411_UBUNTU_FIX.py")
print("=" * 60)