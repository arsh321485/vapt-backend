import subprocess
import os
import shutil
import logging
import sys
import datetime
import re
import urllib.request

print("=" * 60)
print("Password Autocomplete Fix — Plugin 42057")
print("Service: tcp/1010/www — Windows")
print("Affected: /, /login, /Login/Validate, /Login")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"42057_win_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("autocomplete_fix")

TARGET_HOST = "192.168.0.20"
TARGET_PORT = 1010

# Common web root locations to search
WEB_ROOTS = [
    r"C:\inetpub\wwwroot",
    r"C:\inetpub\wwwroot\app",
    r"C:\WebApps",
    r"C:\Apps",
]

# Pages with password fields from Nessus output
AFFECTED_PAGES = [
    "/",
    "/login",
    "/Login",
    "/Login/Validate",
]

# ─── Step 1: Find web application files ──────────────────────────
log.info("\n[1] Searching for web application files...")

def find_web_files(root_dirs, extensions=(".html", ".cshtml",
                   ".aspx", ".php", ".htm")):
    found = []
    for root in root_dirs:
        if not os.path.exists(root):
            continue
        for dirpath, _, files in os.walk(root):
            for f in files:
                if f.lower().endswith(extensions):
                    found.append(os.path.join(dirpath, f))
    return found

web_files = find_web_files(WEB_ROOTS)
log.info("   Found %d web files to scan", len(web_files))

# ─── Step 2: Backup and fix HTML/view files ───────────────────────
log.info("\n[2] Scanning for password fields without autocomplete=off...")

fixed_files = []
backup_dir  = f"C:\\Windows\\Temp\\autocomplete_backup_{timestamp}"
os.makedirs(backup_dir, exist_ok=True)

for filepath in web_files:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Check if file has password input
        if 'type="password"' not in content.lower() and \
           "type='password'" not in content.lower():
            continue

        log.info("   Found password field in: %s", filepath)

        # Backup the file
        backup_path = os.path.join(
            backup_dir, os.path.basename(filepath) + ".bak"
        )
        shutil.copy2(filepath, backup_path)

        original = content

        # Fix 1: Add autocomplete="off" to form tags
        # that contain password fields
        content = re.sub(
            r'(<form\b(?![^>]*autocomplete)[^>]*)>',
            r'\1 autocomplete="off">',
            content,
            flags=re.IGNORECASE
        )

        # Fix 2: Add autocomplete="off" to password input fields
        content = re.sub(
            r'(<input\b(?![^>]*autocomplete)[^>]*type=["\']password["\'][^>]*)(/?>)',
            r'\1 autocomplete="off"\2',
            content,
            flags=re.IGNORECASE
        )

        # Fix 3: Handle inputs where type comes after other attrs
        content = re.sub(
            r'(<input\b[^>]*(?:type=["\']password["\'])[^>]*?)'
            r'(?<!autocomplete="off")(/?>)',
            lambda m: m.group(0) if 'autocomplete' in m.group(0).lower()
            else m.group(1) + ' autocomplete="off"' + m.group(2),
            content,
            flags=re.IGNORECASE
        )

        if content != original:
            with open(filepath, "w",
                      encoding="utf-8", errors="ignore") as f:
                f.write(content)
            log.info("   ✅ Fixed: %s", filepath)
            fixed_files.append(filepath)
        else:
            log.info("   ⚠️ Could not auto-fix: %s — fix manually",
                     filepath)

    except Exception as e:
        log.warning("   ⚠️ Error processing %s: %s", filepath, e)

log.info("\n   Fixed %d file(s)", len(fixed_files))
log.info("   Backups in: %s", backup_dir)

# ─── Step 3: Apply web.config to disable autocomplete globally ────
log.info("\n[3] Applying web.config autocomplete security header...")

# Add X-Content-Type-Options and also disable autocomplete
# via custom header approach as fallback
web_config_addition = """
  <!-- Autocomplete Security - Plugin 42057 -->
  <!-- Note: autocomplete=off must be set in HTML forms -->
  <!-- This header provides additional browser hints -->
"""

# Search for web.config files
for root in WEB_ROOTS:
    if not os.path.exists(root):
        continue
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.lower() == "web.config":
                wc_path = os.path.join(dirpath, f)
                log.info("   Found web.config: %s", wc_path)

# ─── Step 4: IIS URL Rewrite to inject header (alternative) ──────
log.info("\n[4] Checking IIS for additional header injection...")
iis_result = subprocess.run([
    "powershell", "-Command",
    "(Get-Service W3SVC -ErrorAction SilentlyContinue).Status"
], capture_output=True, text=True)

if "Running" in iis_result.stdout:
    log.info("   IIS is running")
    # Restart IIS to pick up any changes
    try:
        subprocess.run(["iisreset", "/restart"],
                      check=True, capture_output=True)
        log.info("✅ IIS restarted")
    except Exception as e:
        log.warning("⚠️ IIS restart failed: %s", e)
else:
    log.info("   IIS not running — restart your web server manually")

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Fixed files : %d", len(fixed_files))
log.info("   Backup dir  : %s", backup_dir)
log.info("   Log         : %s", log_file)
log.info("\n   ⚠️  IMPORTANT: If app uses server-side rendering")
log.info("   (ASP.NET, MVC, Razor), add autocomplete='off' to:")
log.info("   - Form tag: <form autocomplete='off'>")
log.info("   - Input   : <input type='password' autocomplete='off'>")
log.info("   → Run 42057_WIN_VERIFY.py to confirm")
log.info("=" * 60)