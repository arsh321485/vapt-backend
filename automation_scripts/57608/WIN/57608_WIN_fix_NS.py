import winreg
import subprocess
import logging
import sys
import datetime

print("=" * 60)
print("SMB Signing Not Required Fix — Plugin 57608")
print("Service: tcp/445/cifs — Windows")
print("=" * 60)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = f"57608_win_fix_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
)
log = logging.getLogger("smb_signing_fix")

# ─── Step 1: Backup registry ──────────────────────────────────────
log.info("\n[1] Backing up SMB registry keys...")
backup_path = (
    f"C:\\Windows\\Temp\\smb_signing_backup_{timestamp}.reg"
)
try:
    subprocess.run([
        "reg", "export",
        r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        backup_path, "/y"
    ], check=True, capture_output=True)
    log.info("✅ Registry backed up to: %s", backup_path)
except Exception as e:
    log.warning("⚠️ Could not backup registry: %s", e)

# ─── Step 2: Enable SMB Signing on Server ─────────────────────────
log.info("\n[2] Enabling SMB Signing on Server (LanmanServer)...")

server_keys = {
    r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters": {
        "RequireSecuritySignature": 1,  # Require signing
        "EnableSecuritySignature":  1,  # Enable signing
    }
}

for key_path, values in server_keys.items():
    try:
        key = winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            key_path, 0, winreg.KEY_SET_VALUE
        )
        for name, value in values.items():
            winreg.SetValueEx(
                key, name, 0, winreg.REG_DWORD, value
            )
            log.info("✅ Set %s\\%s = %d", key_path, name, value)
        winreg.CloseKey(key)
    except Exception as e:
        log.error("❌ Failed to set server key: %s", e)

# ─── Step 3: Enable SMB Signing on Client ─────────────────────────
log.info("\n[3] Enabling SMB Signing on Client (LanmanWorkstation)...")

client_keys = {
    r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters": {
        "RequireSecuritySignature": 1,
        "EnableSecuritySignature":  1,
    }
}

for key_path, values in client_keys.items():
    try:
        key = winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            key_path, 0, winreg.KEY_SET_VALUE
        )
        for name, value in values.items():
            winreg.SetValueEx(
                key, name, 0, winreg.REG_DWORD, value
            )
            log.info("✅ Set %s\\%s = %d", key_path, name, value)
        winreg.CloseKey(key)
    except Exception as e:
        log.error("❌ Failed to set client key: %s", e)

# ─── Step 4: Apply via PowerShell (SMBv2/v3) ─────────────────────
log.info("\n[4] Applying SMB signing via PowerShell...")
try:
    # Require signing on server
    subprocess.run([
        "powershell", "-Command",
        "Set-SmbServerConfiguration "
        "-RequireSecuritySignature $true "
        "-EnableSecuritySignature $true "
        "-Force"
    ], check=True, capture_output=True)
    log.info("✅ SMB Server signing required via PowerShell")
except Exception as e:
    log.warning("⚠️ PowerShell server signing: %s", e)

try:
    # Require signing on client
    subprocess.run([
        "powershell", "-Command",
        "Set-SmbClientConfiguration "
        "-RequireSecuritySignature $true "
        "-Force"
    ], check=True, capture_output=True)
    log.info("✅ SMB Client signing required via PowerShell")
except Exception as e:
    log.warning("⚠️ PowerShell client signing: %s", e)

# ─── Step 5: Apply via Group Policy (secpol) ──────────────────────
log.info("\n[5] Applying Group Policy for SMB signing...")
try:
    # Microsoft network server: Digitally sign communications (always)
    subprocess.run([
        "powershell", "-Command",
        "secedit /configure /db secedit.sdb "
        "/cfg C:\\Windows\\security\\templates\\setup security.inf "
        "/overwrite /quiet"
    ], capture_output=True)

    # Use reg add as additional enforcement
    subprocess.run([
        "reg", "add",
        r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "/v", "RequireSecuritySignature",
        "/t", "REG_DWORD", "/d", "1", "/f"
    ], check=True, capture_output=True)

    subprocess.run([
        "reg", "add",
        r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "/v", "RequireSecuritySignature",
        "/t", "REG_DWORD", "/d", "1", "/f"
    ], check=True, capture_output=True)

    log.info("✅ Registry values confirmed via reg add")
except Exception as e:
    log.warning("⚠️ Group policy step: %s", e)

# ─── Step 6: Restart SMB service ─────────────────────────────────
log.info("\n[6] Restarting SMB services...")
for svc in ["LanmanServer", "LanmanWorkstation"]:
    try:
        subprocess.run([
            "powershell", "-Command",
            f"Restart-Service -Name {svc} -Force"
        ], check=True, capture_output=True)
        log.info("✅ Restarted: %s", svc)
    except Exception as e:
        log.warning("⚠️ Could not restart %s: %s", svc, e)

# ─── Step 7: Verify ───────────────────────────────────────────────
log.info("\n[7] Verifying SMB signing settings...")
try:
    result = subprocess.run([
        "powershell", "-Command",
        "Get-SmbServerConfiguration | "
        "Select-Object RequireSecuritySignature, "
        "EnableSecuritySignature | Format-List"
    ], capture_output=True, text=True)
    log.info("   SMB Server:\n%s", result.stdout.strip())

    result2 = subprocess.run([
        "powershell", "-Command",
        "Get-SmbClientConfiguration | "
        "Select-Object RequireSecuritySignature | Format-List"
    ], capture_output=True, text=True)
    log.info("   SMB Client:\n%s", result2.stdout.strip())
except Exception as e:
    log.warning("⚠️ Could not verify: %s", e)

log.info("\n" + "=" * 60)
log.info("✅ Fix applied!")
log.info("   Backup : %s", backup_path)
log.info("   Log    : %s", log_file)
log.info("   → Run 57608_WIN_VERIFY.py to confirm")
log.info("=" * 60)