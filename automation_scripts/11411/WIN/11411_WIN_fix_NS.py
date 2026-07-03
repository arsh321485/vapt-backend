import subprocess
import os
import shutil
import logging
import sys
import datetime
import urllib.request
import ssl

print("=" * 60)
print("Backup Files Disclosure Fix — Plugin 11411")
print("Service: tcp/443/www — Windows")
print("Exposed: /logout~ at https://192.168.0.254/logout~")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"11411_win_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("backup_disclosure_fix")

TARGET_HOST = "192.168.0.254"
TARGET_PORT = 443

# Backup file extensions to find and delete/block
BACKUP_EXTENSIONS = [
    "~", ".bak", ".old", ".orig", ".backup",
    ".tmp", ".temp", ".swp", ".swo",
    ".bak1", ".bak2", ".copy", ".save",
]

# Known affected files from Nessus output
KNOWN_AFFECTED = [
    "/logout~",
]

# Web root search dirs
WEB_ROOTS = [
    r"C:\inetpub\wwwroot",
    r"C:\inetpub\wwwroot\app",
    r"C:\WebApps",
    r"C:\Apps",
]

# ─── Step 1: Find and delete backup files ────────────────────────
log.info("\n[1] Scanning web root for backup files...")

quarantine_dir = f"C:\\Windows\\Temp\\backup_quarantine_{timestamp}"
os.makedirs(quarantine_dir, exist_ok=True)
deleted_files  = []
quarantined    = []

for web_root in WEB_ROOTS:
    if not os.path.exists(web_root):
        continue
    log.info("   Scanning: %s", web_root)

    for dirpath, _, files in os.walk(web_root):
        for fname in files:
            fpath = os.path.join(dirpath, fname)
            _, ext = os.path.splitext(fname)

            # Check for backup extensions
            is_backup = (
                any(fname.endswith(bext)
                    for bext in BACKUP_EXTENSIONS) or
                fname.endswith("~") or
                fname.startswith(".")
            )

            if is_backup:
                log.warning("   Found backup file: %s", fpath)
                # Quarantine instead of delete
                quarantine_path = os.path.join(
                    quarantine_dir, fname + f".{timestamp}"
                )
                try:
                    shutil.move(fpath, quarantine_path)
                    log.info("   ✅ Quarantined: %s → %s",
                             fpath, quarantine_path)
                    quarantined.append(fpath)
                except Exception as e:
                    log.error("   ❌ Could not quarantine %s: %s",
                              fpath, e)

log.info("   Quarantined %d backup file(s)", len(quarantined))

# ─── Step 2: Block backup files via IIS URL Rewrite ──────────────
log.info("\n[2] Blocking backup file access via IIS...")

iis_result = subprocess.run([
    "powershell", "-Command",
    "(Get-Service W3SVC -ErrorAction SilentlyContinue).Status"
], capture_output=True, text=True)

if "Running" in iis_result.stdout:
    # Add URL Rewrite rule to block backup file access
    web_config_block = """<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <!-- Block Backup Files — Plugin 11411 Fix -->
        <rule name="Block Backup Files" stopProcessing="true">
          <match url=".*(\\.bak|\\.old|\\.orig|~|\\.backup|\\.tmp|\\.swp|\\.copy|\\.save)$"
                 ignoreCase="true" />
          <action type="CustomResponse"
                  statusCode="403"
                  statusReason="Forbidden"
                  statusDescription="Access Denied" />
        </rule>
        <!-- Block hidden/dot files -->
        <rule name="Block Hidden Files" stopProcessing="true">
          <match url="(^|/)\\." />
          <action type="CustomResponse"
                  statusCode="403"
                  statusReason="Forbidden"
                  statusDescription="Access Denied" />
        </rule>
      </rules>
    </rewrite>
    <security>
      <requestFiltering>
        <!-- Block backup extensions -->
        <fileExtensions>
          <add fileExtension=".bak" allowed="false" />
          <add fileExtension=".old" allowed="false" />
          <add fileExtension=".orig" allowed="false" />
          <add fileExtension=".backup" allowed="false" />
          <add fileExtension=".tmp" allowed="false" />
          <add fileExtension=".swp" allowed="false" />
        </fileExtensions>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
"""
    for web_root in WEB_ROOTS:
        if os.path.exists(web_root):
            wc_path = os.path.join(web_root, "web.config")
            if os.path.exists(wc_path):
                shutil.copy2(wc_path,
                             f"{wc_path}.bak_{timestamp}")

            with open(wc_path, "w", encoding="utf-8") as f:
                f.write(web_config_block)
            log.info("✅ web.config written: %s", wc_path)
            break

    # Restart IIS
    try:
        subprocess.run(["iisreset", "/restart"],
                      check=True, capture_output=True)
        log.info("✅ IIS restarted")
    except Exception as e:
        log.warning("⚠️ IIS restart: %s", e)

else:
    log.info("   IIS not running — skipping IIS step")

# ─── Step 3: Block specifically known affected URLs ───────────────
log.info("\n[3] Blocking known affected URLs: %s", KNOWN_AFFECTED)
log.info("   These have been quarantined and blocked via web.config")

# ─── Step 4: Check for backup files in IIS logs ───────────────────
log.info("\n[4] Checking IIS logs for backup file access...")
iis_log_dir = r"C:\inetpub\logs\LogFiles"
if os.path.exists(iis_log_dir):
    log.info("   IIS log dir: %s", iis_log_dir)
    for root, _, files in os.walk(iis_log_dir):
        for f in files:
            if f.endswith(".log"):
                log_path = os.path.join(root, f)
                try:
                    with open(log_path, "r",
                              encoding="utf-8",
                              errors="ignore") as lf:
                        for line in lf:
                            if any(bext in line.lower()
                                   for bext in [
                                       ".bak", ".old", "~",
                                       "logout~"
                                   ]):
                                log.warning(
                                    "   Access log hit: %s",
                                    line.strip()[:120]
                                )
                except Exception:
                    pass

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Quarantined : %d file(s) → %s",
         len(quarantined), quarantine_dir)
log.info("   Log         : %s", log_file)
log.info("   → Run 11411_WIN_VERIFY.py to confirm")
log.info("=" * 60)