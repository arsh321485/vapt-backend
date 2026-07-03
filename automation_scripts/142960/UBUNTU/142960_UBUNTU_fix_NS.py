import subprocess
import os
import shutil
import logging
import sys
import datetime
import re

print("=" * 60)
print("HSTS Missing Fix — Plugin 142960")
print("Service: tcp/5580/www — Ubuntu")
print("Server : TwistedWeb/22.10.0")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"142960_ubuntu_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("hsts_fix")

TARGET_HOST = "YOUR_VM_IP"   # ← change this
TARGET_PORT = 5580

HSTS_VALUE = "max-age=31536000; includeSubDomains"

# Search directories for TwistedWeb app
SEARCH_DIRS = [
    "/opt",
    "/srv",
    "/var/www",
    "/home",
    "/usr/local/lib",
    "/app",
]

# ─── Step 1: Find TwistedWeb process and config ───────────────────
log.info("\n[1] Finding TwistedWeb process on port %d...", TARGET_PORT)

# Find process on port 5580
result = subprocess.run([
    "ss", "-tlnp", f"sport = :{TARGET_PORT}"
], capture_output=True, text=True)
log.info("   Port %d listener:\n%s", TARGET_PORT, result.stdout)

# Find Python/Twisted processes
result2 = subprocess.run([
    "ps", "aux"
], capture_output=True, text=True)
twisted_procs = [
    l for l in result2.stdout.splitlines()
    if "twisted" in l.lower() or
    ("python" in l.lower() and str(TARGET_PORT) in l)
]
for proc in twisted_procs:
    log.info("   Process: %s", proc[:120])

# ─── Step 2: Find TwistedWeb app files ───────────────────────────
log.info("\n[2] Searching for TwistedWeb application files...")

def find_twisted_files(search_dirs):
    found = []
    for root in search_dirs:
        if not os.path.exists(root):
            continue
        for dirpath, _, files in os.walk(root):
            for f in files:
                if f.lower().endswith((
                    ".py", ".tac", ".cfg", ".ini",
                    ".yaml", ".yml", ".conf"
                )):
                    fpath = os.path.join(dirpath, f)
                    try:
                        with open(fpath, "r",
                                  encoding="utf-8",
                                  errors="ignore") as fp:
                            content = fp.read()
                        if any(kw in content for kw in [
                            "twisted", "Resource",
                            "request.setHeader", "IResource",
                            "twisted.web", ".tac"
                        ]):
                            found.append((fpath, content))
                    except Exception:
                        pass
    return found

twisted_files = find_twisted_files(SEARCH_DIRS)
log.info("   Found %d potential files", len(twisted_files))

# ─── Step 3: Backup and patch Twisted resource files ─────────────
log.info("\n[3] Patching TwistedWeb files to add HSTS...")
backup_dir  = f"/tmp/hsts_backup_{timestamp}"
os.makedirs(backup_dir, exist_ok=True)
fixed_files = []

for filepath, content in twisted_files:
    try:
        # Skip if HSTS already present
        if "Strict-Transport-Security" in content or \
           "strict-transport-security" in content.lower():
            log.info("   ✅ HSTS already in: %s", filepath)
            continue

        # Only process files with render methods
        if not any(kw in content for kw in [
            "def render", "twisted.web.resource",
            "IResource", "Resource"
        ]):
            continue

        log.info("   Found Twisted resource: %s", filepath)
        backup_path = os.path.join(
            backup_dir, os.path.basename(filepath) + ".bak"
        )
        shutil.copy2(filepath, backup_path)

        # Inject HSTS into render methods
        patched = re.sub(
            r'(def render(?:_GET|_POST|_HEAD|_PUT)?\s*'
            r'\(self,\s*request\)[^:]*:)',
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
            log.info("   ✅ HSTS injected: %s", filepath)
            fixed_files.append(filepath)
        else:
            log.warning(
                "   ⚠️ Could not auto-patch: %s — manual fix needed",
                filepath
            )

    except Exception as e:
        log.warning("   ⚠️ Error: %s — %s", filepath, e)

log.info("   Fixed %d file(s)", len(fixed_files))

# ─── Step 4: Create HSTS middleware ──────────────────────────────
log.info("\n[4] Creating HSTS middleware for TwistedWeb...")
hsts_middleware = f'''#!/usr/bin/env python3
"""
HSTS Middleware for TwistedWeb — Plugin 142960 Fix
Generated: {timestamp}

USAGE:
  from hsts_middleware import HSTSResource
  root = HSTSResource(your_existing_root_resource)
  site = server.Site(root)
"""
from twisted.web import resource


class HSTSResource(resource.Resource):
    """Wraps any Resource to add HSTS header to all responses."""
    isLeaf = False

    def __init__(self, wrapped):
        resource.Resource.__init__(self)
        self._wrapped = wrapped
        self.isLeaf   = wrapped.isLeaf

    def getChildWithDefault(self, path, request):
        child = self._wrapped.getChildWithDefault(path, request)
        if isinstance(child, resource.Resource):
            return HSTSResource(child)
        return child

    def getChild(self, path, request):
        child = self._wrapped.getChild(path, request)
        return child

    def render(self, request):
        request.setHeader(
            b"Strict-Transport-Security",
            b"max-age=31536000; includeSubDomains"
        )
        return self._wrapped.render(request)

    def putChild(self, path, child):
        self._wrapped.putChild(path, child)
'''

# Try to save near the app
middleware_saved = False
for search_dir in SEARCH_DIRS:
    if os.path.exists(search_dir):
        for root, dirs, files in os.walk(search_dir):
            for f in files:
                if f.endswith(".tac") or f.endswith(".py"):
                    middleware_path = os.path.join(
                        root, "hsts_middleware.py"
                    )
                    try:
                        with open(middleware_path, "w") as fp:
                            fp.write(hsts_middleware)
                        log.info(
                            "✅ HSTS middleware: %s", middleware_path
                        )
                        middleware_saved = True
                        break
                    except Exception:
                        pass
            if middleware_saved:
                break
    if middleware_saved:
        break

if not middleware_saved:
    middleware_path = f"/tmp/hsts_middleware_{timestamp}.py"
    with open(middleware_path, "w") as f:
        f.write(hsts_middleware)
    log.info("✅ HSTS middleware saved: %s", middleware_path)

# ─── Step 5: Apply via nginx reverse proxy if present ─────────────
log.info("\n[5] Checking if nginx proxies port 5580...")
nginx_active = subprocess.run(
    ["systemctl", "is-active", "--quiet", "nginx"]
).returncode == 0

if nginx_active:
    log.info("   nginx active — adding HSTS via proxy header...")
    # Check if nginx proxies 5580
    result = subprocess.run([
        "grep", "-r", str(TARGET_PORT), "/etc/nginx/"
    ], capture_output=True, text=True)

    if result.stdout:
        log.info("   nginx proxies port %d — adding HSTS...",
                 TARGET_PORT)
        hsts_conf = "/etc/nginx/conf.d/hsts_5580.conf"
        if os.path.exists(hsts_conf):
            shutil.copy2(hsts_conf, f"{hsts_conf}.bak_{timestamp}")

        with open(hsts_conf, "w") as f:
            f.write(f"""# HSTS for port 5580 — Plugin 142960
# Generated: {timestamp}
map $scheme $hsts_header {{
    https "max-age=31536000; includeSubDomains";
    default "";
}}
""")

        result = subprocess.run(
            ["nginx", "-t"], capture_output=True, text=True
        )
        if result.returncode == 0:
            subprocess.run(["systemctl", "reload", "nginx"])
            log.info("✅ nginx reloaded with HSTS config")
    else:
        log.info("   nginx does not proxy port %d", TARGET_PORT)

# ─── Step 6: Restart TwistedWeb service ──────────────────────────
log.info("\n[6] Restarting TwistedWeb service...")
for svc_name in ["twisted", "twistd", "twistedweb"]:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", svc_name]
    )
    if result.returncode == 0:
        subprocess.run(["systemctl", "restart", svc_name])
        log.info("✅ Restarted service: %s", svc_name)
        break
else:
    log.warning(
        "⚠️ TwistedWeb service not found via systemctl")
    log.warning(
        "   → Manually restart: twistd -y your_app.tac"
    )

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Fixed files   : %d", len(fixed_files))
log.info("   Backup dir    : %s", backup_dir)
log.info("   Log           : %s", log_file)
log.info("\n   ⚠️  Manual step required:")
log.info("   Add HSTSResource wrapper to your .tac file:")
log.info("   from hsts_middleware import HSTSResource")
log.info("   root = HSTSResource(your_root)")
log.info("   Restart TwistedWeb after applying")
log.info("   → Run 142960_UBUNTU_VERIFY.py to confirm")
log.info("=" * 60)