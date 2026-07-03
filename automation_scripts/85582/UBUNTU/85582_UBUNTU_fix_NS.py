import subprocess
import os
import shutil
import logging
import sys
import datetime

print("=" * 60)
print("Clickjacking Fix — Plugin 85582")
print("Service: tcp/1010/www — Ubuntu")
print("Affected: /, /Login, /Login/Validate, /login")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"85582_ubuntu_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("clickjacking_fix")

TARGET_PORT = 1010

# ─── Step 1: Detect active web server ────────────────────────────
log.info("\n[1] Detecting active web server...")

nginx_active  = subprocess.run(
    ["systemctl", "is-active", "--quiet", "nginx"]
).returncode == 0

apache_active = subprocess.run(
    ["systemctl", "is-active", "--quiet", "apache2"]
).returncode == 0

haproxy_active = subprocess.run(
    ["systemctl", "is-active", "--quiet", "haproxy"]
).returncode == 0

log.info("   nginx   active: %s", nginx_active)
log.info("   apache2 active: %s", apache_active)
log.info("   haproxy active: %s", haproxy_active)

# ─── Step 2: Apply fix for NGINX ─────────────────────────────────
if nginx_active:
    log.info("\n[2a] Applying fix for NGINX...")
    nginx_conf_dir = "/etc/nginx/conf.d"
    security_conf  = f"{nginx_conf_dir}/security_headers.conf"

    # Backup existing
    if os.path.exists(security_conf):
        shutil.copy2(security_conf,
                     f"{security_conf}.bak_{timestamp}")
        log.info("✅ Backed up: %s", security_conf)

    nginx_headers = f"""# Clickjacking Protection — Plugin 85582
# Generated: {timestamp}

add_header X-Frame-Options "SAMEORIGIN" always;
add_header Content-Security-Policy "frame-ancestors 'self'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
"""
    with open(security_conf, "w") as f:
        f.write(nginx_headers)
    log.info("✅ NGINX security headers written: %s", security_conf)

    # Also check if port 1010 is specifically configured
    nginx_sites = "/etc/nginx/sites-enabled"
    if os.path.exists(nginx_sites):
        for site in os.listdir(nginx_sites):
            site_path = os.path.join(nginx_sites, site)
            with open(site_path, "r") as f:
                content = f.read()
            if str(TARGET_PORT) in content:
                log.info(
                    "✅ Port %d found in site: %s",
                    TARGET_PORT, site
                )

    # Validate nginx config
    result = subprocess.run(
        ["nginx", "-t"], capture_output=True, text=True
    )
    if result.returncode == 0:
        log.info("✅ NGINX config valid")
        subprocess.run(["systemctl", "reload", "nginx"])
        log.info("✅ NGINX reloaded")
    else:
        log.error("❌ NGINX config invalid: %s", result.stderr)
        # Restore backup
        if os.path.exists(f"{security_conf}.bak_{timestamp}"):
            shutil.copy2(
                f"{security_conf}.bak_{timestamp}", security_conf
            )

# ─── Step 3: Apply fix for Apache2 ───────────────────────────────
if apache_active:
    log.info("\n[2b] Applying fix for Apache2...")

    # Enable headers module
    subprocess.run(["a2enmod", "headers"], capture_output=True)
    log.info("✅ Apache headers module enabled")

    apache_conf = (
        "/etc/apache2/conf-available/security_headers.conf"
    )

    # Backup
    if os.path.exists(apache_conf):
        shutil.copy2(apache_conf,
                     f"{apache_conf}.bak_{timestamp}")

    apache_headers = f"""# Clickjacking Protection — Plugin 85582
# Generated: {timestamp}

Header always set X-Frame-Options "SAMEORIGIN"
Header always set Content-Security-Policy "frame-ancestors 'self'"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
"""
    with open(apache_conf, "w") as f:
        f.write(apache_headers)
    log.info("✅ Apache security headers written: %s", apache_conf)

    # Enable the config
    subprocess.run([
        "a2enconf", "security_headers"
    ], capture_output=True)
    log.info("✅ Apache security headers config enabled")

    # Validate and reload
    result = subprocess.run(
        ["apache2ctl", "configtest"],
        capture_output=True, text=True
    )
    if "Syntax OK" in result.stderr or "Syntax OK" in result.stdout:
        log.info("✅ Apache config valid")
        subprocess.run(["systemctl", "reload", "apache2"])
        log.info("✅ Apache2 reloaded")
    else:
        log.error("❌ Apache config error: %s", result.stderr)

# ─── Step 4: If neither nginx nor apache, try generic approach ────
if not nginx_active and not apache_active:
    log.warning(
        "\n[2c] Neither nginx nor apache2 active — "
        "checking for other server on port %d...", TARGET_PORT
    )
    result = subprocess.run(
        ["ss", "-tlnp"],
        capture_output=True, text=True
    )
    port_lines = [
        l for l in result.stdout.splitlines()
        if str(TARGET_PORT) in l
    ]
    if port_lines:
        log.info("   Service on port %d:\n%s",
                 TARGET_PORT, "\n".join(port_lines))
        log.warning(
            "   ⚠️  Manually add headers to the web server "
            "config listening on port %d", TARGET_PORT
        )
    else:
        log.warning(
            "   ⚠️  No service found on port %d", TARGET_PORT
        )

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Log: %s", log_file)
log.info("   → Run 85582_UBUNTU_VERIFY.py to confirm")
log.info("=" * 60)