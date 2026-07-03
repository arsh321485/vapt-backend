import subprocess
import os
import shutil
import logging
import sys
import datetime
import re

print("=" * 60)
print("Clickjacking Fix — Plugin 85582")
print("Service: tcp/1010/www — Windows")
print("Affected URLs: /, /Login, /Login/Validate, /login")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"85582_win_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("clickjacking_fix")

# ─── Configuration ────────────────────────────────────────────────
TARGET_PORT = 1010
TARGET_IP   = "192.168.0.20"

# IIS config paths
IIS_CONFIG  = r"C:\Windows\System32\inetsrv\config\applicationHost.config"
WEB_CONFIG  = r"C:\inetpub\wwwroot\web.config"   # ← change if different

# ─── Step 1: Detect web server type ──────────────────────────────
log.info("\n[1] Detecting web server...")

# Check IIS
iis_result = subprocess.run([
    "powershell", "-Command",
    "(Get-Service W3SVC -ErrorAction SilentlyContinue).Status"
], capture_output=True, text=True)

# Check other common servers
tomcat_result = subprocess.run([
    "powershell", "-Command",
    "Get-Service -Name *tomcat* -ErrorAction SilentlyContinue | "
    "Select-Object Name, Status"
], capture_output=True, text=True)

iis_running     = "Running" in iis_result.stdout
tomcat_running  = bool(tomcat_result.stdout.strip())

log.info("   IIS running    : %s", iis_running)
log.info("   Tomcat running : %s", tomcat_running)

# ─── Step 2: Backup configs ───────────────────────────────────────
log.info("\n[2] Backing up existing configurations...")
for config in [IIS_CONFIG, WEB_CONFIG]:
    if os.path.exists(config):
        shutil.copy2(config, f"{config}.bak_{timestamp}")
        log.info("✅ Backed up: %s", config)

# ─── Step 3: Apply fix via IIS (web.config) ───────────────────────
log.info("\n[3] Applying X-Frame-Options and CSP headers...")

# Method A: web.config (works for IIS and ASP.NET)
web_config_content = """<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <!-- Clickjacking Protection - Plugin 85582 -->
        <add name="X-Frame-Options" value="SAMEORIGIN" />
        <add name="Content-Security-Policy"
             value="frame-ancestors 'self'" />
        <add name="X-Content-Type-Options" value="nosniff" />
        <add name="X-XSS-Protection" value="1; mode=block" />
        <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
      </customHeaders>
    </httpProtocol>
    <security>
      <requestFiltering>
        <verbs>
          <add verb="TRACE" allowed="false" />
          <add verb="OPTIONS" allowed="false" />
        </verbs>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
"""

# Find the right web.config location
web_config_locations = [
    WEB_CONFIG,
    r"C:\inetpub\wwwroot\web.config",
    r"C:\inetpub\wwwroot\app\web.config",
]

config_written = False
for wc_path in web_config_locations:
    wc_dir = os.path.dirname(wc_path)
    if os.path.exists(wc_dir):
        # If web.config exists, merge headers
        if os.path.exists(wc_path):
            with open(wc_path, "r") as f:
                existing = f.read()

            if "X-Frame-Options" in existing:
                log.warning(
                    "⚠️ X-Frame-Options already in %s — "
                    "updating value...", wc_path
                )
                # Replace existing value
                existing = re.sub(
                    r'name="X-Frame-Options"[^/]*/\s*>',
                    'name="X-Frame-Options" value="SAMEORIGIN" />',
                    existing
                )
                with open(wc_path, "w") as f:
                    f.write(existing)
                log.info("✅ X-Frame-Options updated in: %s", wc_path)
            else:
                # Find customHeaders section and add
                if "<customHeaders>" in existing:
                    insert = (
                        "<customHeaders>\n"
                        '        <add name="X-Frame-Options" '
                        'value="SAMEORIGIN" />\n'
                        '        <add name="Content-Security-Policy" '
                        'value="frame-ancestors \'self\'" />\n'
                    )
                    existing = existing.replace(
                        "<customHeaders>", insert
                    )
                    with open(wc_path, "w") as f:
                        f.write(existing)
                    log.info("✅ Headers added to: %s", wc_path)
                else:
                    log.warning(
                        "⚠️ No customHeaders section found in: %s",
                        wc_path
                    )
        else:
            # Create new web.config
            with open(wc_path, "w") as f:
                f.write(web_config_content)
            log.info("✅ New web.config created: %s", wc_path)

        config_written = True
        break

if not config_written:
    log.warning("⚠️ Could not find web root — writing to current dir")
    with open("web.config", "w") as f:
        f.write(web_config_content)

# ─── Step 4: Apply via IIS PowerShell cmdlets ─────────────────────
log.info("\n[4] Applying headers via IIS PowerShell cmdlets...")
if iis_running:
    headers = [
        ("X-Frame-Options", "SAMEORIGIN"),
        ("Content-Security-Policy", "frame-ancestors 'self'"),
        ("X-Content-Type-Options", "nosniff"),
    ]
    for name, value in headers:
        try:
            # Remove existing header first
            subprocess.run([
                "powershell", "-Command",
                f"Remove-WebConfigurationProperty "
                f"-pspath 'MACHINE/WEBROOT/APPHOST' "
                f"-filter 'system.webServer/httpProtocol/customHeaders' "
                f"-name '.' "
                f"-AtElement @{{name='{name}'}} "
                f"-ErrorAction SilentlyContinue"
            ], capture_output=True)

            # Add new header
            subprocess.run([
                "powershell", "-Command",
                f"Add-WebConfigurationProperty "
                f"-pspath 'MACHINE/WEBROOT/APPHOST' "
                f"-filter 'system.webServer/httpProtocol/customHeaders' "
                f"-name '.' "
                f"-value @{{name='{name}';value='{value}'}}"
            ], check=True, capture_output=True)
            log.info("✅ IIS header added: %s: %s", name, value)
        except Exception as e:
            log.warning("⚠️ Could not add via IIS cmdlet: %s — %s",
                        name, e)

# ─── Step 5: Restart IIS ─────────────────────────────────────────
log.info("\n[5] Restarting IIS...")
if iis_running:
    try:
        subprocess.run(["iisreset", "/restart"], check=True,
                       capture_output=True)
        log.info("✅ IIS restarted successfully!")
    except Exception as e:
        log.warning("⚠️ IIS restart failed: %s", e)
else:
    log.info("   IIS not running — skipping restart")
    log.warning(
        "   ⚠️  If using another server (Tomcat, Node.js, etc.), "
        "add headers in that server's config manually"
    )

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Log: %s", log_file)
log.info("   → Run 85582_WIN_VERIFY.py to confirm")
log.info("=" * 60)