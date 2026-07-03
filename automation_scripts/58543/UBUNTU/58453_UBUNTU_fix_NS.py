import subprocess
import os
import shutil
from datetime import datetime

print("Enabling Network Level Authentication (NLA) on Ubuntu...\n")

xrdp_conf = "/etc/xrdp/xrdp.ini"
backup_path = f"{xrdp_conf}.bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# ─── Check if xrdp is installed ──────────────────────────────────
result = subprocess.run(["which", "xrdp"], capture_output=True, text=True)
if not result.stdout.strip():
    print("❌ xrdp is not installed. Installing now...")
    try:
        subprocess.run(["apt-get", "install", "-y", "xrdp"], check=True)
        print("✅ xrdp installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install xrdp: {e}")
        exit(1)
else:
    print("✅ xrdp is already installed.")

# ─── Backup xrdp config ───────────────────────────────────────────
if os.path.exists(xrdp_conf):
    shutil.copy2(xrdp_conf, backup_path)
    print(f"✅ Backup saved: {backup_path}")
else:
    print("⚠️ xrdp.ini not found — check your xrdp installation.")
    exit(1)

# ─── Apply NLA settings in xrdp.ini ──────────────────────────────
try:
    with open(xrdp_conf, "r") as f:
        content = f.read()

    # Set security layer to NLA
    if "security_layer=negotiate" in content or "security_layer=rdp" in content:
        content = content.replace("security_layer=negotiate", "security_layer=tls")
        content = content.replace("security_layer=rdp", "security_layer=tls")
        print("✅ Security layer updated to TLS/NLA")
    elif "security_layer=tls" in content:
        print("⚠️ Security layer already set to TLS — skipping.")
    else:
        # Add it under [Globals] section
        content = content.replace("[Globals]", "[Globals]\nsecurity_layer=tls")
        print("✅ Security layer added to [Globals] section")

    # Enable NLA
    if "enable_nla=false" in content:
        content = content.replace("enable_nla=false", "enable_nla=true")
        print("✅ NLA enabled in config")
    elif "enable_nla=true" in content:
        print("⚠️ NLA already enabled — skipping.")
    else:
        content = content.replace("[Globals]", "[Globals]\nenable_nla=true")
        print("✅ NLA entry added to [Globals] section")

    with open(xrdp_conf, "w") as f:
        f.write(content)

except Exception as e:
    print(f"❌ Failed to update xrdp.ini: {e}")
    exit(1)

# ─── Install required NLA packages ───────────────────────────────
print("\nInstalling NLA dependencies...")
packages = ["xrdp", "xorgxrdp", "libpam-runtime"]

for pkg in packages:
    try:
        subprocess.run(["apt-get", "install", "-y", pkg], check=True,
                      capture_output=True)
        print(f"✅ {pkg} ready")
    except subprocess.CalledProcessError:
        print(f"⚠️ Could not install {pkg} — may already be installed or unavailable")

# ─── Configure PAM for NLA ────────────────────────────────────────
print("\nConfiguring PAM for NLA...")
try:
    subprocess.run(["pam-auth-update", "--enable", "mkhomedir"],
                   check=True, capture_output=True)
    print("✅ PAM configured successfully")
except Exception as e:
    print(f"⚠️ PAM configuration skipped: {e}")

# ─── Restart xrdp service ─────────────────────────────────────────
print("\nRestarting xrdp service...")
try:
    subprocess.run(["systemctl", "restart", "xrdp"], check=True)
    print("✅ xrdp restarted successfully!")
except subprocess.CalledProcessError as e:
    print(f"❌ Failed to restart xrdp: {e}")

# ─── Enable xrdp on boot ─────────────────────────────────────────
try:
    subprocess.run(["systemctl", "enable", "xrdp"], check=True)
    print("✅ xrdp enabled on system boot")
except subprocess.CalledProcessError as e:
    print(f"⚠️ Could not enable xrdp on boot: {e}")

print("\n✅ NLA Fix applied successfully!")
print("➡️  Now run verification script to confirm NLA is enabled.")