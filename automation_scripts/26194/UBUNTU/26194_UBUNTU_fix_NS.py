import subprocess
import os
import shutil
import logging
import sys
import datetime
import re

print("=" * 60)
print("Cleartext Credentials Fix — Plugin 26194")
print("Service: tcp/1010/www — Ubuntu")
print("Affected: /, /login, /Login/Validate, /Login")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"26194_ubuntu_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("cleartext_fix")

TARGET_HOST = "192.168.0.20"
HTTP_PORT   = 1010
HTTPS_PORT  = 443

WEB_ROOTS   = [
    "/var/www/html",
    "/var/www",
    "/opt/app",
    "/opt/webapp",
    "/usr/share/nginx/html",
]

# ─── Step 1: Detect active web server ────────────────────────────
log.info("\n[1] Detecting active web server...")
nginx_active  = subprocess.run(
    ["systemctl", "is-active", "--quiet", "nginx"]
).returncode == 0
apache_active = subprocess.run(
    ["systemctl", "is-active", "--quiet", "apache2"]
).returncode == 0
log.info("   nginx   : %s", nginx_active)
log.info("   apache2 : %s", apache_active)

# ─── Step 2: Fix form actions in HTML files ───────────────────────
log.info("\n[2] Fixing HTTP form actions to HTTPS...")

def find_web_files(roots):
    found = []
    for root in roots:
        if not os.path.exists(root):
            continue
        for dp, _, files in os.walk(root):
            for f in files:
                if f.lower().endswith((
                    ".html", ".htm", ".php", ".j2", ".jinja2"
                )):
                    found.append(os.path.join(dp, f))
    return found

web_files   = find_web_files(WEB_ROOTS)
fixed_files = []
backup_dir  = f"/tmp/cleartext_backup_{timestamp}"
os.makedirs(backup_dir, exist_ok=True)

for filepath in web_files:
    try:
        with open(filepath, "r",
                  encoding="utf-8", errors="ignore") as f:
            content = f.read()

        if 'type="password"' not in content.lower() and \
           "type='password'" not in content.lower():
            continue

        log.info("   Found password field: %s", filepath)
        shutil.copy2(
            filepath,
            os.path.join(backup_dir,
                         os.path.basename(filepath) + ".bak")
        )
        original = content

        # Replace http:// form actions with https://
        content = re.sub(
            r'(action=["\'])http://',
            r'\1https://',
            content,
            flags=re.IGNORECASE
        )

        # Add method=post if missing
        content = re.sub(
            r'(<form\b(?![^>]*method=["\']post["\'])'
            r'(?![^>]*method=["\']POST["\'])[^>]*)>',
            r'\1 method="post">',
            content,
            flags=re.IGNORECASE
        )

        if content != original:
            with open(filepath, "w",
                      encoding="utf-8", errors="ignore") as f:
                f.write(content)
            log.info("   ✅ Fixed: %s", filepath)
            fixed_files.append(filepath)

    except Exception as e:
        log.warning("   ⚠️ Error: %s — %s", filepath, e)

log.info("   Fixed %d file(s)", len(fixed_files))

# ─── Step 3: Apply HTTPS redirect in NGINX ───────────────────────
if nginx_active:
    log.info("\n[3a] Applying HTTPS redirect in NGINX...")
    redirect_conf = "/etc/nginx/conf.d/https_redirect.conf"

    if os.path.exists(redirect_conf):
        shutil.copy2(redirect_conf,
                     f"{redirect_conf}.bak_{timestamp}")

    nginx_redirect = f"""# Force HTTPS — Plugin 26194 Fix
# Generated: {timestamp}

server {{
    listen {HTTP_PORT};
    server_name {TARGET_HOST} _;

    # Redirect all HTTP to HTTPS
    return 301 https://$host$request_uri;
}}

server {{
    listen {HTTPS_PORT} ssl;
    server_name {TARGET_HOST} _;

    # SSL certificate — update these paths
    ssl_certificate     /etc/ssl/certs/custom/server.crt;
    ssl_certificate_key /etc/ssl/private/custom/server.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # HSTS
    add_header Strict-Transport-Security
               "max-age=31536000; includeSubDomains" always;

    location / {{
        # Proxy to your application backend
        # proxy_pass http://localhost:8080;
        root /var/www/html;
        index index.html;
    }}
}}
"""
    with open(redirect_conf, "w") as f:
        f.write(nginx_redirect)
    log.info("✅ NGINX HTTPS redirect config written: %s",
             redirect_conf)

    # Validate and reload
    result = subprocess.run(
        ["nginx", "-t"], capture_output=True, text=True
    )
    if result.returncode == 0:
        subprocess.run(["systemctl", "reload", "nginx"])
        log.info("✅ NGINX reloaded")
    else:
        log.error("❌ NGINX config error: %s", result.stderr)
        shutil.copy2(f"{redirect_conf}.bak_{timestamp}",
                     redirect_conf)

# ─── Step 4: Apply HTTPS redirect in Apache2 ─────────────────────
if apache_active:
    log.info("\n[3b] Applying HTTPS redirect in Apache2...")

    # Enable required modules
    for mod in ["ssl", "rewrite", "headers"]:
        subprocess.run([f"a2enmod", mod], capture_output=True)
        log.info("   ✅ Module enabled: %s", mod)

    apache_redirect = f"""# Force HTTPS — Plugin 26194 Fix
# Generated: {timestamp}

<VirtualHost *:{HTTP_PORT}>
    ServerName {TARGET_HOST}

    # Redirect all HTTP to HTTPS
    RewriteEngine On
    RewriteCond %{{HTTPS}} off
    RewriteRule ^(.*)$ https://%{{HTTP_HOST}}%{{REQUEST_URI}} [R=301,L]
</VirtualHost>

<VirtualHost *:{HTTPS_PORT}>
    ServerName {TARGET_HOST}

    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/custom/server.crt
    SSLCertificateKeyFile /etc/ssl/private/custom/server.key

    SSLProtocol TLSv1.2 TLSv1.3
    SSLCipherSuite HIGH:!aNULL:!MD5

    # HSTS
    Header always set Strict-Transport-Security \
        "max-age=31536000; includeSubDomains"

    DocumentRoot /var/www/html
</VirtualHost>
"""
    apache_conf = (
        "/etc/apache2/sites-available/https_redirect.conf"
    )
    with open(apache_conf, "w") as f:
        f.write(apache_redirect)

    subprocess.run(["a2ensite", "https_redirect"],
                   capture_output=True)

    result = subprocess.run(
        ["apache2ctl", "configtest"],
        capture_output=True, text=True
    )
    if "Syntax OK" in result.stderr or "Syntax OK" in result.stdout:
        subprocess.run(["systemctl", "reload", "apache2"])
        log.info("✅ Apache2 HTTPS redirect enabled and reloaded")
    else:
        log.error("❌ Apache config error: %s", result.stderr)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Fixed HTML files : %d", len(fixed_files))
log.info("   Backup dir       : %s", backup_dir)
log.info("   Log              : %s", log_file)
log.info("\n   ⚠️  Manual steps required:")
log.info("   1. Ensure valid SSL cert at /etc/ssl/certs/custom/")
log.info("   2. Update ssl_certificate paths in nginx/apache config")
log.info("   3. Verify app redirects HTTP → HTTPS on port %d",
         HTTP_PORT)
log.info("   → Run 26194_UBUNTU_VERIFY.py to confirm")
log.info("=" * 60)