import subprocess
import os
import logging
import sys

print("=" * 60)
print("SMB Signing Verify — Plugin 57608 — Ubuntu (Samba)")
print("Service: tcp/445/cifs")
print("=" * 60)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("smb_signing_verify")
all_good = True

SMB_CONF = "/etc/samba/smb.conf"

# ─── Check 1: smb.conf has signing settings ───────────────────────
log.info("\n[1] Checking smb.conf for signing settings...")
if os.path.exists(SMB_CONF):
    with open(SMB_CONF, "r") as f:
        content = f.read().lower()

    signing_settings = [
        "server signing",
        "client signing",
    ]
    for setting in signing_settings:
        if setting in content:
            # Find the value
            for line in content.splitlines():
                if setting in line and "=" in line:
                    value = line.split("=")[-1].strip()
                    if value in ("mandatory", "required", "true"):
                        log.info(
                            "✅ %s = %s", setting, value
                        )
                    else:
                        log.error(
                            "❌ %s = %s (should be mandatory!)",
                            setting, value
                        )
                        all_good = False
        else:
            log.error("❌ %s not found in smb.conf!", setting)
            all_good = False
else:
    log.error("❌ smb.conf not found: %s", SMB_CONF)
    all_good = False

# ─── Check 2: testparm verification ──────────────────────────────
log.info("\n[2] Verifying via testparm...")
try:
    result = subprocess.run(
        ["testparm", "-s", SMB_CONF],
        capture_output=True, text=True
    )
    output = (result.stdout + result.stderr).lower()

    if "server signing = mandatory" in output or \
       "server signing = required" in output:
        log.info("✅ testparm confirms: server signing = mandatory")
    else:
        log.error("❌ testparm: server signing not mandatory!")
        all_good = False

    if "client signing = mandatory" in output or \
       "client signing = required" in output:
        log.info("✅ testparm confirms: client signing = mandatory")
    else:
        log.warning("⚠️ testparm: client signing not mandatory")

    log.info("   testparm output (snippet):\n%s",
             output[:500])
except Exception as e:
    log.warning("⚠️ testparm not available: %s", e)

# ─── Check 3: Samba services running ─────────────────────────────
log.info("\n[3] Checking Samba service status...")
for svc in ["smbd", "nmbd"]:
    result = subprocess.run(
        ["systemctl", "is-active", svc],
        capture_output=True, text=True
    )
    status = result.stdout.strip()
    if status == "active":
        log.info("✅ %s is active", svc)
    else:
        log.warning("⚠️ %s: %s", svc, status)

# ─── Check 4: Port 445 is listening ──────────────────────────────
log.info("\n[4] Checking port 445 is listening...")
result = subprocess.run(
    ["ss", "-tlnp"], capture_output=True, text=True
)
if ":445" in result.stdout:
    log.info("✅ Port 445 is listening")
else:
    log.warning("⚠️ Port 445 not detected")

# ─── Check 5: SMB signing via smbstatus ──────────────────────────
log.info("\n[5] Checking active SMB sessions signing...")
try:
    result = subprocess.run(
        ["smbstatus", "--signing"],
        capture_output=True, text=True
    )
    if result.stdout.strip():
        log.info("   SMB Status:\n%s", result.stdout.strip()[:300])
    else:
        log.info("   No active SMB sessions or smbstatus unavailable")
except Exception as e:
    log.info("   smbstatus not available: %s", e)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — SMB Signing is required!")
    print("   Re-run Nessus scan to confirm Plugin 57608 resolved.")
else:
    print("❌ VERDICT: FAIL — SMB signing not properly configured.")
    print("   Review above and re-run 57608_UBUNTU_FIX.py")
print("=" * 60)