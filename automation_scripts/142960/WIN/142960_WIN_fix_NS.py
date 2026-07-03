import subprocess
import os
import shutil
import logging
import sys
import datetime
import re

print("=" * 60)
print("HSTS Missing Fix — Plugin 142960")
print("Service: tcp/5580/www — Windows")
print("Server : TwistedWeb/22.10.0")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"142960_win_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("hsts_fix")

TARGET_HOST  = "YOUR_VM_IP"   # ← change this
TARGET_PORT  = 5580

# HSTS header value — 1 year
HSTS_VALUE = "max-age=31536000; includeSubDomains"

# Common locations for TwistedWeb/Python app configs
TWISTED_SEARCH_DIRS = [
    r"C:\TwistedWeb",
    r"C:\Python",
    r"C:\Apps",
    r"C:\inetpub\wwwroot",
    r"C:\Services",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]

# ─── Step 1: Find TwistedWeb app files ───────────────────────────
log.info("\n[1] Searching for TwistedWeb configuration files...")

def find_twisted_files(search_dirs):
    found = []
    for root in search_dirs:
        if not os.path.exists(root):
            continue
        for dirpath, _, files in os.walk(root):
            for f in files:
                if f.lower().endswith((
                    ".py", ".cfg", ".ini", ".conf", ".yaml", ".yml"
                )):
                    fpath = os.path.join(dirpath, f)
                    try:
                        with open(fpath, "r",
                                  encoding="utf-8",
                                  errors="ignore") as fp:
                            content = fp.read().lower()
                        if any(kw in content for kw in [
                            "twisted", "resource", "request",
                            "tac", "server.py", "site"
                        ]):
                            found.append(fpath)
                    except Exception:
                        pass
    return found

twisted_files = find_twisted_files(TWISTED_SEARCH_DIRS)
log.info("   Found %d potential Twisted files", len(twisted_files))
for f in twisted_files[:5]:
    log.info("   → %s", f)

# ─── Step 2: Backup and patch Python/Twisted files ────────────────
log.info("\n[2] Patching TwistedWeb files to add HSTS header...")
backup_dir  = f"C:\\Windows\\Temp\\hsts_backup_{timestamp}"
os.makedirs(backup_dir, exist_ok=True)
fixed_files = []

# HSTS injection code for Twisted
HSTS_TWISTED_PATCH = f'''
# HSTS Header — Plugin 142960 Fix
# Added: {timestamp}
HSTS_HEADER = b"max-age=31536000; includeSubDomains"
'''

HSTS_RENDER_PATCH = '''
        # Add HSTS header
        request.setHeader(
            b"Strict-Transport-Security",
            b"max-age=31536000; includeSubDomains"
        )
'''

for filepath in twisted_files:
    try:
        with open(filepath, "r",
                  encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Check if file has render or request handling
        if not any(kw in content for kw in [
            "def render", "request.setHeader",
            "Resource", "twisted.web"
        ]):
            continue

        # Skip if HSTS already present
        if "Strict-Transport-Security" in content or \
           "strict-transport-security" in content.lower():
            log.info("   ✅ HSTS already present: %s", filepath)
            continue

        log.info("   Found Twisted resource: %s", filepath)
        backup_path = os.path.join(
            backup_dir, os.path.basename(filepath) + ".bak"
        )
        shutil.copy2(filepath, backup_path)

        # Method 1: Add HSTS to render_GET methods
        patched = re.sub(
            r'(def render(?:_GET|_POST|_HEAD)?\s*\(self,\s*request\)[^:]*:)',
            r'\1\n        request.setHeader('
            r'b"Strict-Transport-Security", '
            r'b"max-age=31536000; includeSubDomains")',
            content,
            flags=re.MULTILINE
        )

        if patched != content:
            with open(filepath, "w",
                      encoding="utf-8", errors="ignore") as f:
                f.write(patched)
            log.info("   ✅ HSTS injected into: %s", filepath)
            fixed_files.append(filepath)

    except Exception as e:
        log.warning("   ⚠️ Error: %s — %s", filepath, e)

# ─── Step 3: IIS reverse proxy HSTS (if IIS fronts port 5580) ────
log.info("\n[3] Checking if IIS proxies port 5580...")
iis_result = subprocess.run([
    "powershell", "-Command",
    "(Get-Service W3SVC -ErrorAction SilentlyContinue).Status"
], capture_output=True, text=True)

if "Running" in iis_result.stdout:
    log.info("   IIS is running — adding HSTS header via IIS...")
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
            f"value='{HSTS_VALUE}'}}"
        ], check=True, capture_output=True)
        log.info("✅ HSTS added via IIS")
        subprocess.run(["iisreset", "/restart"],
                      capture_output=True)
        log.info("✅ IIS restarted")
    except Exception as e:
        log.warning("⚠️ IIS HSTS failed: %s", e)
else:
    log.info("   IIS not running")

# ─── Step 4: Create HSTS middleware wrapper ───────────────────────
log.info("\n[4] Creating HSTS middleware wrapper for Twisted...")
hsts_middleware = f'''#!/usr/bin/env python3
"""
HSTS Middleware for TwistedWeb — Plugin 142960 Fix
Generated: {timestamp}
Apply this by wrapping your root Resource with HSTSResource
"""
from twisted.web import resource


class HSTSResource(resource.Resource):
    """
    Wrapper that adds Strict-Transport-Security header
    to all responses from the wrapped resource.
    """
    isLeaf = False

    def __init__(self, wrapped):
        resource.Resource.__init__(self)
        self._wrapped = wrapped

    def getChildWithDefault(self, path, request):
        child = self._wrapped.getChildWithDefault(path, request)
        return HSTSResource(child) if child else child

    def render(self, request):
        request.setHeader(
            b"Strict-Transport-Security",
            b"max-age=31536000; includeSubDomains"
        )
        return self._wrapped.render(request)

    def getChild(self, path, request):
        child = self._wrapped.getChild(path, request)
        return child


# Usage in your .tac or server.py:
# from hsts_middleware import HSTSResource
# root = HSTSResource(your_existing_root_resource)
# site = server.Site(root)
'''

middleware_path = r"C:\TwistedWeb\hsts_middleware.py"
try:
    os.makedirs(os.path.dirname(middleware_path), exist_ok=True)
    with open(middleware_path, "w") as f:
        f.write(hsts_middleware)
    log.info("✅ HSTS middleware created: %s", middleware_path)
except Exception as e:
    # Save to temp if dir doesn't exist
    middleware_path = (
        f"C:\\Windows\\Temp\\hsts_middleware_{timestamp}.py"
    )
    with open(middleware_path, "w") as f:
        f.write(hsts_middleware)
    log.info("✅ HSTS middleware saved: %s", middleware_path)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Fixed files   : %d", len(fixed_files))
log.info("   Backup dir    : %s", backup_dir)
log.info("   HSTS Middleware: %s", middleware_path)
log.info("   Log           : %s", log_file)
log.info("\n   ⚠️  Manual step — wrap root resource:")
log.info("   from hsts_middleware import HSTSResource")
log.info("   root = HSTSResource(your_existing_root)")
log.info("   Restart TwistedWeb service after applying")
log.info("   → Run 142960_WIN_VERIFY.py to confirm")
log.info("=" * 60)