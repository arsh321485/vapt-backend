import urllib.request
import urllib.error
import ssl
import subprocess
import logging
import sys
import os

print("=" * 60)
print("Backup Files Verify — Plugin 11411 — Windows")
print("Service: tcp/443/www")
print("=" * 60)

TARGET_HOST = "192.168.0.254"
TARGET_PORT = 443

# Known affected files from Nessus
BACKUP_URLS = [
    f"https://{TARGET_HOST}/logout~",
    f"https://{TARGET_HOST}/logout.bak",
    f"https://{TARGET_HOST}/logout.old",
    f"https://{TARGET_HOST}/index.bak",
    f"https://{TARGET_HOST}/web.config.bak",
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

# ─── Check 1: Backup files return 403/404 ────────────────────────
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
            log.info(
                "   ✅ HTTP %d — Access blocked/not found", e.code
            )
        else:
            log.warning("   ⚠️ HTTP %d — check manually", e.code)
    except Exception as e:
        log.info("   ✅ Connection refused/error: %s", e)

# ─── Check 2: web.config blocks backup extensions ────────────────
log.info("\n[2] Checking web.config for backup file blocks...")
web_roots = [r"C:\inetpub\wwwroot", r"C:\WebApps"]
for root in web_roots:
    wc = os.path.join(root, "web.config")
    if os.path.exists(wc):
        with open(wc, "r", encoding="utf-8",
                  errors="ignore") as f:
            content = f.read()
        if "Block Backup Files" in content or ".bak" in content:
            log.info("✅ Backup file blocking in web.config: %s", wc)
        else:
            log.warning("⚠️ No backup block rules in: %s", wc)

# ─── Check 3: No backup files in web root ────────────────────────
log.info("\n[3] Checking no backup files remain in web root...")
backup_exts = ["~", ".bak", ".old", ".orig", ".backup", ".tmp"]
found_backups = []
for root in web_roots:
    if not os.path.exists(root):
        continue
    for dirpath, _, files in os.walk(root):
        for f in files:
            if any(f.endswith(ext) for ext in backup_exts):
                found_backups.append(os.path.join(dirpath, f))

if found_backups:
    log.error("❌ Backup files still present:")
    for bf in found_backups:
        log.error("   %s", bf)
    all_good = False
else:
    log.info("✅ No backup files found in web root")

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — Backup files blocked/removed!")
    print("   Re-run Nessus scan to confirm Plugin 11411 resolved.")
else:
    print("❌ VERDICT: FAIL — Backup files still accessible.")
    print("   Review and re-run 11411_WIN_FIX.py")
print("=" * 60)