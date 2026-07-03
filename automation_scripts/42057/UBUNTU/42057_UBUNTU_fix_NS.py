import subprocess
import os
import shutil
import logging
import sys
import datetime
import re

print("=" * 60)
print("Password Autocomplete Fix — Plugin 42057")
print("Service: tcp/1010/www — Ubuntu")
print("Affected: /, /login, /Login/Validate, /Login")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"42057_ubuntu_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("autocomplete_fix")

TARGET_PORT = 1010

# Common web root locations on Ubuntu
WEB_ROOTS = [
    "/var/www/html",
    "/var/www",
    "/opt/app",
    "/opt/webapp",
    "/usr/share/nginx/html",
    "/srv/www",
]

# ─── Step 1: Find web root for port 1010 ─────────────────────────
log.info("\n[1] Finding web root for port %d...", TARGET_PORT)

# Check nginx config for port 1010
nginx_root = None
try:
    result = subprocess.run([
        "grep", "-r", str(TARGET_PORT),
        "/etc/nginx/"
    ], capture_output=True, text=True)
    if result.stdout:
        log.info("   Nginx config for port %d:\n%s",
                 TARGET_PORT, result.stdout[:300])

    # Try to find root directive
    root_result = subprocess.run([
        "grep", "-r", "root",
        "/etc/nginx/sites-enabled/"
    ], capture_output=True, text=True)
    for line in root_result.stdout.splitlines():
        if "root" in line and "/var" in line or "/opt" in line:
            parts = line.strip().split()
            if len(parts) >= 2:
                potential_root = parts[-1].rstrip(";")
                if os.path.exists(potential_root):
                    nginx_root = potential_root
                    log.info("   Found nginx root: %s", nginx_root)
                    break
except Exception as e:
    log.warning("   ⚠️ Could not parse nginx config: %s", e)

# Add found root to search list
if nginx_root and nginx_root not in WEB_ROOTS:
    WEB_ROOTS.insert(0, nginx_root)

# ─── Step 2: Find and fix HTML/template files ─────────────────────
log.info("\n[2] Scanning for password fields without autocomplete=off...")

def find_web_files(root_dirs, extensions=(
    ".html", ".htm", ".php", ".j2",
    ".jinja", ".jinja2", ".tpl", ".erb"
)):
    found = []
    for root in root_dirs:
        if not os.path.exists(root):
            continue
        for dirpath, _, files in os.walk(root):
            for f in files:
                if f.lower().endswith(extensions):
                    found.append(os.path.join(dirpath, f))
    return found

web_files   = find_web_files(WEB_ROOTS)
fixed_files = []
backup_dir  = f"/tmp/autocomplete_backup_{timestamp}"
os.makedirs(backup_dir, exist_ok=True)

log.info("   Found %d web files to scan", len(web_files))

for filepath in web_files:
    try:
        with open(filepath, "r",
                  encoding="utf-8", errors="ignore") as f:
            content = f.read()

        if 'type="password"' not in content.lower() and \
           "type='password'" not in content.lower():
            continue

        log.info("   Found password field in: %s", filepath)

        # Backup
        backup_path = os.path.join(
            backup_dir, os.path.basename(filepath) + ".bak"
        )
        shutil.copy2(filepath, backup_path)
        original = content

        # Fix form tags
        content = re.sub(
            r'(<form\b(?![^>]*autocomplete)[^>]*)>',
            r'\1 autocomplete="off">',
            content,
            flags=re.IGNORECASE
        )

        # Fix password input fields
        content = re.sub(
            r'(<input\b(?![^>]*autocomplete)[^>]*'
            r'type=["\']password["\'][^>]*)(/?>)',
            r'\1 autocomplete="off"\2',
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
            log.warning(
                "   ⚠️ Could not auto-fix: %s — fix manually",
                filepath
            )

    except Exception as e:
        log.warning("   ⚠️ Error processing %s: %s", filepath, e)

log.info("\n   Fixed %d file(s)", len(fixed_files))
log.info("   Backups in: %s", backup_dir)

# ─── Step 3: Restart web server ───────────────────────────────────
log.info("\n[3] Restarting active web server...")
for svc in ["nginx", "apache2"]:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", svc]
    )
    if result.returncode == 0:
        # Validate config first
        if svc == "nginx":
            val = subprocess.run(
                ["nginx", "-t"], capture_output=True, text=True
            )
            if val.returncode == 0:
                subprocess.run(["systemctl", "reload", svc])
                log.info("✅ %s reloaded", svc)
            else:
                log.error("❌ nginx config error: %s", val.stderr)
        else:
            subprocess.run(["systemctl", "reload", svc])
            log.info("✅ %s reloaded", svc)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Fixed files : %d", len(fixed_files))
log.info("   Backup dir  : %s", backup_dir)
log.info("   Log         : %s", log_file)
log.info("\n   ⚠️  If app uses server-side templates (Python/Java):")
log.info("   Add to form tag  : autocomplete='off'")
log.info("   Add to pwd input : autocomplete='off' or 'new-password'")
log.info("   → Run 42057_UBUNTU_VERIFY.py to confirm")
log.info("=" * 60)