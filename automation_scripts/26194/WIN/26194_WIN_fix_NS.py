import subprocess
import os
import shutil
import logging
import sys
import datetime
import re

print("=" * 60)
print("Cleartext Credentials Fix — Plugin 26194")
print("Service: tcp/1010/www — Windows")
print("Affected: /, /login, /Login/Validate, /Login")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"26194_win_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("cleartext_fix")

TARGET_HOST  = "192.168.0.20"
TARGET_PORT  = 1010
HTTPS_PORT   = 443   # ← change if HTTPS is on different port

WEB_ROOTS = [
    r"C:\inetpub\wwwroot",
    r"C:\inetpub\wwwroot\app",
    r"C:\WebApps",
]

AFFECTED_PAGES = [
    "/",
    "/login",
    "/Login",
    "/Login/Validate",
]

# ─── Step 1: Backup configs ───────────────────────────────────────
log.info("\n[1] Backing up existing configurations...")
backup_dir = f"C:\\Windows\\Temp\\cleartext_backup_{timestamp}"
os.makedirs(backup_dir, exist_ok=True)
log.info("✅ Backup directory: %s", backup_dir)

# ─── Step 2: Fix form action URLs to use HTTPS ────────────────────
log.info("\n[2] Scanning for forms submitting over HTTP...")

def find_web_files(root_dirs):
    found = []
    for root in root_dirs:
        if not os.path.exists(root):
            continue
        for dirpath, _, files in os.walk(root):
            for f in files:
                if f.lower().endswith((
                    ".html", ".htm", ".aspx",
                    ".cshtml", ".php"
                )):
                    found.append(os.path.join(dirpath, f))
    return found

web_files   = find_web_files(WEB_ROOTS)
fixed_files = []
log.info("   Found %d web files to scan", len(web_files))

for filepath in web_files:
    try:
        with open(filepath, "r",
                  encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Only process files with password fields
        if 'type="password"' not in content.lower() and \
           "type='password'" not in content.lower():
            continue

        log.info("   Found password field in: %s", filepath)
        backup_path = os.path.join(
            backup_dir, os.path.basename(filepath) + ".bak"
        )
        shutil.copy2(filepath, backup_path)
        original = content

        # Fix 1: Replace http:// form actions with https://
        content = re.sub(
            r'(action=["\'])http://' + TARGET_HOST,
            r'\1https://' + TARGET_HOST,
            content,
            flags=re.IGNORECASE
        )

        # Fix 2: Replace http:// in action attributes generally
        content = re.sub(
            r'(<form[^>]*action=["\'])http://',
            r'\1https://',
            content,
            flags=re.IGNORECASE
        )

        # Fix 3: Add method="post" if not present on forms
        # with password fields (GET sends creds in URL)
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
            log.info("   ✅ Fixed form actions: %s", filepath)
            fixed_files.append(filepath)

    except Exception as e:
        log.warning("   ⚠️ Error: %s — %s", filepath, e)

# ─── Step 3: IIS HTTPS redirect via web.config ───────────────────
log.info("\n[3] Applying HTTPS redirect via web.config...")

https_redirect_config = f"""<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <!-- Force HTTPS — Plugin 26194 Fix -->
        <rule name="Force HTTPS" stopProcessing="true">
          <match url="(.*)" />
          <conditions>
            <add input="{{HTTPS}}" pattern="^OFF$" />
          </conditions>
          <action type="Redirect"
                  url="https://{{HTTP_HOST}}/{{R:1}}"
                  redirectType="Permanent" />
        </rule>
      </rules>
    </rewrite>
    <httpProtocol>
      <customHeaders>
        <!-- HSTS — force browser to use HTTPS -->
        <add name="Strict-Transport-Security"
             value="max-age=31536000; includeSubDomains" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
"""

# Find and update web.config
for root in WEB_ROOTS:
    if not os.path.exists(root):
        continue
    wc_path = os.path.join(root, "web.config")
    if os.path.exists(wc_path):
        shutil.copy2(wc_path,
                     f"{wc_path}.bak_{timestamp}")

        with open(wc_path, "r",
                  encoding="utf-8", errors="ignore") as f:
            existing = f.read()

        if "Force HTTPS" not in existing:
            # Merge rewrite rules
            if "<rewrite>" not in existing:
                # Add before </system.webServer>
                existing = existing.replace(
                    "</system.webServer>",
                    """  <rewrite>
      <rules>
        <rule name="Force HTTPS" stopProcessing="true">
          <match url="(.*)" />
          <conditions>
            <add input="{HTTPS}" pattern="^OFF$" />
          </conditions>
          <action type="Redirect"
                  url="https://{HTTP_HOST}/{R:1}"
                  redirectType="Permanent" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>"""
                )
                with open(wc_path, "w",
                          encoding="utf-8") as f:
                    f.write(existing)
                log.info("✅ HTTPS redirect added to: %s", wc_path)
            else:
                log.info("   Rewrite rules already exist in: %s",
                         wc_path)
        else:
            log.info("   Force HTTPS already in: %s", wc_path)
        break
else:
    # No web.config found — create one
    for root in WEB_ROOTS:
        if os.path.exists(root):
            wc_path = os.path.join(root, "web.config")
            with open(wc_path, "w", encoding="utf-8") as f:
                f.write(https_redirect_config)
            log.info("✅ New web.config created: %s", wc_path)
            break

# ─── Step 4: Enable SSL binding in IIS on port 443 ───────────────
log.info("\n[4] Checking IIS SSL binding for HTTPS...")
try:
    result = subprocess.run([
        "powershell", "-Command",
        "Get-WebBinding | "
        "Where-Object {$_.protocol -eq 'https'} | "
        "Select-Object bindingInformation | Format-List"
    ], capture_output=True, text=True)
    if result.stdout.strip():
        log.info("✅ HTTPS bindings found:\n%s", result.stdout.strip())
    else:
        log.warning("⚠️ No HTTPS bindings found!")
        log.warning("   → Add HTTPS binding in IIS Manager:")
        log.warning("     Site → Bindings → Add → https → port 443")
        log.warning("     Assign SSL certificate to the binding")
except Exception as e:
    log.warning("⚠️ Could not check IIS bindings: %s", e)

# ─── Step 5: Add HSTS header via IIS ─────────────────────────────
log.info("\n[5] Adding HSTS header via IIS...")
try:
    subprocess.run([
        "powershell", "-Command",
        "Remove-WebConfigurationProperty "
        "-pspath 'MACHINE/WEBROOT/APPHOST' "
        "-filter 'system.webServer/httpProtocol/customHeaders' "
        "-name '.' "
        "-AtElement @{name='Strict-Transport-Security'} "
        "-ErrorAction SilentlyContinue"
    ], capture_output=True)

    subprocess.run([
        "powershell", "-Command",
        "Add-WebConfigurationProperty "
        "-pspath 'MACHINE/WEBROOT/APPHOST' "
        "-filter 'system.webServer/httpProtocol/customHeaders' "
        "-name '.' "
        "-value @{name='Strict-Transport-Security';"
        "value='max-age=31536000; includeSubDomains'}"
    ], check=True, capture_output=True)
    log.info("✅ HSTS header added via IIS")
except Exception as e:
    log.warning("⚠️ Could not add HSTS via IIS: %s", e)

# ─── Step 6: Restart IIS ─────────────────────────────────────────
log.info("\n[6] Restarting IIS...")
try:
    iis_check = subprocess.run([
        "powershell", "-Command",
        "(Get-Service W3SVC -ErrorAction SilentlyContinue).Status"
    ], capture_output=True, text=True)
    if "Running" in iis_check.stdout:
        subprocess.run(["iisreset", "/restart"],
                      check=True, capture_output=True)
        log.info("✅ IIS restarted")
    else:
        log.warning("⚠️ IIS not running — start manually")
except Exception as e:
    log.warning("⚠️ IIS restart failed: %s", e)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Fixed files : %d", len(fixed_files))
log.info("   Backup dir  : %s", backup_dir)
log.info("   Log         : %s", log_file)
log.info("\n   ⚠️  Manual steps required:")
log.info("   1. Add HTTPS binding in IIS Manager (port 443)")
log.info("   2. Assign valid SSL certificate to HTTPS binding")
log.info("   3. Verify app redirects HTTP → HTTPS correctly")
log.info("   → Run 26194_WIN_VERIFY.py to confirm")
log.info("=" * 60)