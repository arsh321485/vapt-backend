import winreg
import subprocess
import logging
import sys

print("=" * 60)
print("SMB Signing Verify — Plugin 57608 — Windows")
print("Service: tcp/445/cifs")
print("=" * 60)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("smb_signing_verify")
all_good = True

# ─── Check 1: Server registry keys ───────────────────────────────
log.info("\n[1] Checking LanmanServer registry keys...")
server_path = (
    r"SYSTEM\CurrentControlSet\Services"
    r"\LanmanServer\Parameters"
)
try:
    key = winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, server_path
    )
    for name in ["RequireSecuritySignature",
                 "EnableSecuritySignature"]:
        try:
            value, _ = winreg.QueryValueEx(key, name)
            if value == 1:
                log.info("✅ Server %s = %d", name, value)
            else:
                log.error("❌ Server %s = %d (should be 1!)",
                          name, value)
                all_good = False
        except FileNotFoundError:
            log.error("❌ Server %s not found!", name)
            all_good = False
    winreg.CloseKey(key)
except Exception as e:
    log.error("❌ Could not check server registry: %s", e)
    all_good = False

# ─── Check 2: Client registry keys ───────────────────────────────
log.info("\n[2] Checking LanmanWorkstation registry keys...")
client_path = (
    r"SYSTEM\CurrentControlSet\Services"
    r"\LanmanWorkstation\Parameters"
)
try:
    key = winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, client_path
    )
    for name in ["RequireSecuritySignature",
                 "EnableSecuritySignature"]:
        try:
            value, _ = winreg.QueryValueEx(key, name)
            if value == 1:
                log.info("✅ Client %s = %d", name, value)
            else:
                log.error("❌ Client %s = %d (should be 1!)",
                          name, value)
                all_good = False
        except FileNotFoundError:
            log.warning("⚠️ Client %s not found", name)
    winreg.CloseKey(key)
except Exception as e:
    log.error("❌ Could not check client registry: %s", e)

# ─── Check 3: PowerShell SMB server config ────────────────────────
log.info("\n[3] Checking SMB Server configuration via PowerShell...")
try:
    result = subprocess.run([
        "powershell", "-Command",
        "Get-SmbServerConfiguration | "
        "Select-Object RequireSecuritySignature, "
        "EnableSecuritySignature | Format-List"
    ], capture_output=True, text=True)
    log.info("   SMB Server Config:\n%s", result.stdout.strip())

    if "RequireSecuritySignature : True" in result.stdout:
        log.info("✅ SMB Server RequireSecuritySignature = True")
    else:
        log.error("❌ SMB Server signing NOT required!")
        all_good = False
except Exception as e:
    log.warning("⚠️ Could not check via PowerShell: %s", e)

# ─── Check 4: PowerShell SMB client config ───────────────────────
log.info("\n[4] Checking SMB Client configuration via PowerShell...")
try:
    result = subprocess.run([
        "powershell", "-Command",
        "Get-SmbClientConfiguration | "
        "Select-Object RequireSecuritySignature | Format-List"
    ], capture_output=True, text=True)
    log.info("   SMB Client Config:\n%s", result.stdout.strip())

    if "RequireSecuritySignature : True" in result.stdout:
        log.info("✅ SMB Client RequireSecuritySignature = True")
    else:
        log.warning("⚠️ SMB Client signing not required")
except Exception as e:
    log.warning("⚠️ Could not check client: %s", e)

# ─── Check 5: SMB sessions signing status ────────────────────────
log.info("\n[5] Checking active SMB sessions signing status...")
try:
    result = subprocess.run([
        "powershell", "-Command",
        "Get-SmbSession | "
        "Select-Object ClientComputerName, Signed | Format-Table"
    ], capture_output=True, text=True)
    if result.stdout.strip():
        log.info("   Active SMB Sessions:\n%s", result.stdout.strip())
    else:
        log.info("   No active SMB sessions found")
except Exception as e:
    log.warning("⚠️ Could not check sessions: %s", e)

# ─── Check 6: Port 445 is listening ──────────────────────────────
log.info("\n[6] Checking port 445 is listening...")
result = subprocess.run([
    "powershell", "-Command",
    "netstat -an | Select-String ':445'"
], capture_output=True, text=True)
if "445" in result.stdout:
    log.info("✅ Port 445 is listening")
else:
    log.warning("⚠️ Port 445 not detected")

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — SMB Signing is required!")
    print("   Re-run Nessus scan to confirm Plugin 57608 resolved.")
else:
    print("❌ VERDICT: FAIL — SMB signing not properly configured.")
    print("   Review above and re-run 57608_WIN_FIX.py")
print("=" * 60)