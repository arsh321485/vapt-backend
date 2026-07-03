import subprocess
import os
import shutil
import logging
import sys
import datetime

print("=" * 60)
print("Backup Files Disclosure Fix — Plugin 11411")
print("Service: tcp/443/www — Ubuntu")
print("Exposed: /logout~ at https://192.168.0.254/logout~")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"11411_ubuntu_fix_{timestamp}.log"

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

BACKUP_EXTENSIONS = [
    "~", ".bak", ".old", ".orig", ".backup",
    ".tmp", ".temp", ".swp", ".swo",
    ".bak1", ".bak2", ".copy", ".save",
]

WEB_ROOTS = [
    "/var/www/html",
    "/var/www",
    "/opt/app",
    "/opt/webapp",
    "/usr/share/nginx/html",
    "/srv/www",
]

# ─── Step 1: Find nginx/apache web root ──────────────────────────
log.info("\n[1] Detecting web server and root...")
nginx_active  = subprocess.run(
    ["systemctl", "is-active", "--quiet", "nginx"]
).returncode == 0
apache_active = subprocess.run(
    ["systemctl", "is-active", "--quiet", "apache2"]
).returncode == 0

log.info("   nginx   : %s", nginx_active)
log.info("   apache2 : %s", apache_active)

# Try to find nginx document root
if nginx_active:
    result = subprocess.run([
        "grep", "-r", "root", "/etc/nginx/sites-enabled/"
    ], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "root" in line and "/" in line:
            parts = line.strip().split()
            if len(parts) >= 2:
                potential = parts[-1].rstrip(";")
                if os.path.exists(potential) and \
                   potential not in WEB_ROOTS:
                    WEB_ROOTS.insert(0, potential)
                    log.info("   Added nginx root: %s", potential)

# ─── Step 2: Find and quarantine backup files ─────────────────────
log.info("\n[2] Scanning for backup files in web roots...")

quarantine_dir = f"/tmp/backup_quarantine_{timestamp}"
os.makedirs(quarantine_dir, exist_ok=True)
quarantined = []

for web_root in WEB_ROOTS:
    if not os.path.exists(web_root):
        continue
    log.info("   Scanning: %s", web_root)

    for dirpath, _, files in os.walk(web_root):
        for fname in files:
            fpath = os.path.join(dirpath, fname)
            is_backup = (
                any(fname.endswith(bext)
                    for bext in BACKUP_EXTENSIONS) or
                fname.endswith("~")
            )
            if is_backup:
                log.warning("   Found: %s", fpath)
                qpath = os.path.join(
                    quarantine_dir,
                    fname + f".quarantine_{timestamp}"
                )
                try:
                    shutil.move(fpath, qpath)
                    log.info("   ✅ Quarantined: %s", fpath)
                    quarantined.append(fpath)
                except Exception as e:
                    log.error("   ❌ Could not quarantine: %s", e)

log.info("   Quarantined %d file(s)", len(quarantined))

# ─── Step 3: Block backup files via NGINX ────────────────────────
if nginx_active:
    log.info("\n[3a] Blocking backup files via NGINX...")
    backup_block_conf = "/etc/nginx/conf.d/block_backups.conf"

    if os.path.exists(backup_block_conf):
        shutil.copy2(backup_block_conf,
                     f"{backup_block_conf}.bak_{timestamp}")

    nginx_block = f"""# Block Backup File Access — Plugin 11411
# Generated: {timestamp}

# Block backup file extensions
location ~* \\.(?:bak|old|orig|backup|tmp|temp|swp|swo|copy|save)$ {{
    deny all;
    return 403;
    access_log off;
    log_not_found off;
}}

# Block tilde backup files (e.g., /logout~)
location ~* ~$ {{
    deny all;
    return 403;
    access_log off;
    log_not_found off;
}}

# Block hidden/dot files
location ~ /\\. {{
    deny all;
    return 403;
    access_log off;
    log_not_found off;
}}
"""
    with open(backup_block_conf, "w") as f:
        f.write(nginx_block)
    log.info("✅ nginx backup block config: %s", backup_block_conf)

    # Validate and reload
    result = subprocess.run(
        ["nginx", "-t"], capture_output=True, text=True
    )
    if result.returncode == 0:
        subprocess.run(["systemctl", "reload", "nginx"])
        log.info("✅ nginx reloaded")
    else:
        log.error("❌ nginx config error: %s", result.stderr)
        shutil.copy2(f"{backup_block_conf}.bak_{timestamp}",
                     backup_block_conf)

# ─── Step 4: Block via Apache2 ────────────────────────────────────
if apache_active:
    log.info("\n[3b] Blocking backup files via Apache2...")
    apache_conf = (
        "/etc/apache2/conf-available/block_backups.conf"
    )

    apache_block = f"""# Block Backup File Access — Plugin 11411
# Generated: {timestamp}

# Block backup extensions
<FilesMatch "\\.(bak|old|orig|backup|tmp|temp|swp|swo|copy|save)$">
    Require all denied
</FilesMatch>

# Block tilde backup files
<FilesMatch "~$">
    Require all denied
</FilesMatch>

# Block hidden files
<FilesMatch "^\\.">
    Require all denied
</FilesMatch>
"""
    with open(apache_conf, "w") as f:
        f.write(apache_block)

    subprocess.run([
        "a2enconf", "block_backups"
    ], capture_output=True)

    result = subprocess.run(
        ["apache2ctl", "configtest"],
        capture_output=True, text=True
    )
    if "Syntax OK" in result.stderr or "Syntax OK" in result.stdout:
        subprocess.run(["systemctl", "reload", "apache2"])
        log.info("✅ Apache2 reloaded with backup block rules")
    else:
        log.error("❌ Apache config error: %s", result.stderr)

# ─── Step 5: Set strict file permissions ──────────────────────────
log.info("\n[4] Setting restrictive permissions on web roots...")
for web_root in WEB_ROOTS:
    if os.path.exists(web_root):
        try:
            subprocess.run([
                "find", web_root,
                "-name", "*~",
                "-o", "-name", "*.bak",
                "-o", "-name", "*.old",
                "-o", "-name", "*.orig",
                "-exec", "chmod", "000", "{}", ";"
            ], capture_output=True)
            log.info(
                "✅ Restrictive permissions set on backups in: %s",
                web_root
            )
        except Exception as e:
            log.warning("⚠️ chmod failed: %s", e)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Quarantined : %d file(s) → %s",
         len(quarantined), quarantine_dir)
log.info("   Log         : %s", log_file)
log.info("   → Run 11411_UBUNTU_VERIFY.py to confirm")
log.info("=" * 60)