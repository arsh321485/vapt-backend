import subprocess
import os
import shutil
import logging
import sys
import datetime

print("=" * 60)
print("SMB Signing Not Required Fix — Plugin 57608")
print("Service: tcp/445/cifs — Ubuntu (Samba)")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"57608_ubuntu_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("smb_signing_fix")

SMB_CONF_PATHS = [
    "/etc/samba/smb.conf",
    "/usr/local/samba/lib/smb.conf",
]

# ─── Step 1: Check if Samba is installed ─────────────────────────
log.info("\n[1] Checking Samba installation...")
result = subprocess.run(
    ["which", "samba"], capture_output=True, text=True
)
if not result.stdout.strip():
    log.warning("⚠️ Samba not found — installing...")
    try:
        subprocess.run([
            "apt-get", "install", "-y", "samba"
        ], check=True, capture_output=True)
        log.info("✅ Samba installed")
    except Exception as e:
        log.error("❌ Could not install Samba: %s", e)
        sys.exit(1)
else:
    log.info("✅ Samba is installed")

# ─── Step 2: Find smb.conf ────────────────────────────────────────
log.info("\n[2] Locating smb.conf...")
smb_conf = None
for path in SMB_CONF_PATHS:
    if os.path.exists(path):
        smb_conf = path
        log.info("✅ Found smb.conf: %s", smb_conf)
        break

if not smb_conf:
    smb_conf = "/etc/samba/smb.conf"
    log.warning("⚠️ smb.conf not found — will create at: %s",
                smb_conf)

# ─── Step 3: Backup smb.conf ──────────────────────────────────────
log.info("\n[3] Backing up smb.conf...")
backup_path = f"{smb_conf}.bak_{timestamp}"
if os.path.exists(smb_conf):
    shutil.copy2(smb_conf, backup_path)
    log.info("✅ Backup saved: %s", backup_path)

# ─── Step 4: Read and update smb.conf ────────────────────────────
log.info("\n[4] Applying SMB signing settings to smb.conf...")

if os.path.exists(smb_conf):
    with open(smb_conf, "r") as f:
        content = f.read()
else:
    content = "[global]\n"

lines      = content.splitlines(keepends=True)
new_lines  = []
in_global  = False
global_done = False

# Settings to add/update
REQUIRED_SETTINGS = {
    "server signing":    "mandatory",
    "client signing":    "mandatory",
    "smb signing":       "mandatory",
}

settings_added = {k: False for k in REQUIRED_SETTINGS}

for line in lines:
    stripped = line.strip().lower()

    # Detect [global] section
    if stripped == "[global]":
        in_global = True
        new_lines.append(line)
        continue

    # Detect end of [global] section
    if stripped.startswith("[") and stripped != "[global]":
        if in_global and not global_done:
            # Add missing settings before next section
            for setting, value in REQUIRED_SETTINGS.items():
                if not settings_added[setting]:
                    new_lines.append(
                        f"   {setting} = {value}\n"
                    )
                    log.info("   ✅ Added: %s = %s",
                             setting, value)
            global_done = True
            in_global   = False
        new_lines.append(line)
        continue

    # Replace existing signing settings
    if in_global:
        replaced = False
        for setting, value in REQUIRED_SETTINGS.items():
            if stripped.startswith(
                setting.replace(" ", "\\s*")
            ) or (
                "signing" in stripped and
                setting.split()[0] in stripped
            ):
                new_lines.append(f"   {setting} = {value}\n")
                settings_added[setting] = True
                log.info("   ✅ Updated: %s = %s", setting, value)
                replaced = True
                break
        if not replaced:
            new_lines.append(line)
    else:
        new_lines.append(line)

# If [global] section has no end (EOF)
if in_global and not global_done:
    for setting, value in REQUIRED_SETTINGS.items():
        if not settings_added[setting]:
            new_lines.append(f"   {setting} = {value}\n")
            log.info("   ✅ Added: %s = %s", setting, value)

# If no [global] section at all
if not any("[global]" in l.lower() for l in new_lines):
    signing_block = (
        "[global]\n"
        "   server signing = mandatory\n"
        "   client signing = mandatory\n"
        "\n"
    )
    new_lines.insert(0, signing_block)
    log.info("✅ Added new [global] section with signing settings")

with open(smb_conf, "w") as f:
    f.writelines(new_lines)

log.info("✅ smb.conf updated: %s", smb_conf)

# ─── Step 5: Test smb.conf syntax ────────────────────────────────
log.info("\n[5] Testing smb.conf syntax...")
try:
    result = subprocess.run(
        ["testparm", "-s", smb_conf],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        log.info("✅ smb.conf syntax is valid")
    else:
        log.error("❌ smb.conf syntax error: %s", result.stderr)
        log.warning("   Restoring backup...")
        shutil.copy2(backup_path, smb_conf)
        log.info("   Backup restored")
        sys.exit(1)
except Exception as e:
    log.warning("⚠️ testparm not available: %s", e)

# ─── Step 6: Restart Samba services ──────────────────────────────
log.info("\n[6] Restarting Samba services...")
for svc in ["smbd", "nmbd", "winbind"]:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", svc]
    )
    if result.returncode == 0:
        subprocess.run(["systemctl", "restart", svc])
        log.info("✅ Restarted: %s", svc)
    else:
        log.info("   %s not active — skipping", svc)

# ─── Step 7: Verify signing via testparm ─────────────────────────
log.info("\n[7] Verifying signing settings via testparm...")
try:
    result = subprocess.run(
        ["testparm", "-s", "--parameter-name=server signing"],
        capture_output=True, text=True
    )
    log.info("   server signing: %s",
             result.stdout.strip() or result.stderr.strip())
except Exception as e:
    log.warning("⚠️ testparm check: %s", e)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Backup : %s", backup_path)
log.info("   Log    : %s", log_file)
log.info("   → Run 57608_UBUNTU_VERIFY.py to confirm")
log.info("=" * 60)