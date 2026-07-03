import winreg
import subprocess
import logging
import sys
import datetime

# ─────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("C:\\Windows\\Temp\\sweet32_mitigation.log"),
    ],
)
log = logging.getLogger("sweet32_fix")

# ─────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────

SCHANNEL_BASE = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# Ciphers to DISABLE (3DES and weak ciphers)
CIPHERS_TO_DISABLE = [
    "Triple DES 168",        # 3DES — SWEET32 core
    "DES 56/56",             # Single DES — weak
    "RC4 40/128",            # RC4 — weak
    "RC4 56/128",            # RC4 — weak
    "RC4 64/128",            # RC4 — weak
    "RC4 128/128",           # RC4 — weak
    "NULL",                  # No encryption
]

# Ciphers to ENABLE (strong ciphers)
CIPHERS_TO_ENABLE = [
    "AES 128/128",
    "AES 256/256",
]

# ─────────────────────────────────────────────────────────────────
# BACKUP REGISTRY
# ─────────────────────────────────────────────────────────────────

def backup_registry():
    """Export SCHANNEL registry key as backup before making changes."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"C:\\Windows\\Temp\\schannel_backup_{timestamp}.reg"
    try:
        subprocess.run([
            "reg", "export",
            f"HKLM\\{SCHANNEL_BASE}",
            backup_path,
            "/y"
        ], check=True, capture_output=True)
        log.info("✅ Registry backup saved: %s", backup_path)
    except Exception as e:
        log.warning("⚠️ Could not create registry backup: %s", e)

# ─────────────────────────────────────────────────────────────────
# DISABLE WEAK CIPHERS
# ─────────────────────────────────────────────────────────────────

def disable_cipher(cipher_name: str):
    """Set Enabled = 0 for a cipher under SCHANNEL\\Ciphers."""
    key_path = f"{SCHANNEL_BASE}\\Ciphers\\{cipher_name}"
    try:
        key = winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            key_path,
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "Enabled", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        log.info("✅ Disabled cipher: %s", cipher_name)
    except Exception as e:
        log.error("❌ Failed to disable cipher %s: %s", cipher_name, e)

# ─────────────────────────────────────────────────────────────────
# ENABLE STRONG CIPHERS
# ─────────────────────────────────────────────────────────────────

def enable_cipher(cipher_name: str):
    """Set Enabled = 0xFFFFFFFF for a cipher under SCHANNEL\\Ciphers."""
    key_path = f"{SCHANNEL_BASE}\\Ciphers\\{cipher_name}"
    try:
        key = winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            key_path,
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "Enabled", 0, winreg.REG_DWORD, 0xFFFFFFFF)
        winreg.CloseKey(key)
        log.info("✅ Enabled cipher: %s", cipher_name)
    except Exception as e:
        log.error("❌ Failed to enable cipher %s: %s", cipher_name, e)

# ─────────────────────────────────────────────────────────────────
# DISABLE WEAK CIPHER ORDER (TLS cipher suite order)
# ─────────────────────────────────────────────────────────────────

def enforce_cipher_suite_order():
    """
    Set a strong cipher suite order under SSL Configuration.
    Removes 3DES from the negotiation order entirely.
    """
    key_path = r"SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    
    # Strong cipher suite order — 3DES excluded
    strong_suites = ",".join([
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_RSA_WITH_AES_128_CBC_SHA256",
    ])

    try:
        key = winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            key_path,
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "Functions", 0, winreg.REG_SZ, strong_suites)
        winreg.CloseKey(key)
        log.info("✅ Cipher suite order enforced (3DES excluded)")
    except Exception as e:
        log.error("❌ Failed to set cipher suite order: %s", e)

# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────

def main():
    log.info("=" * 60)
    log.info("SWEET32 Mitigation Script — CVE-2016-2183 / Plugin 42873")
    log.info("Target: Windows SCHANNEL Cipher Configuration")
    log.info("=" * 60)

    # Step 1: Backup
    backup_registry()

    # Step 2: Disable weak/3DES ciphers
    log.info("\nDisabling weak and 3DES cipher suites...")
    for cipher in CIPHERS_TO_DISABLE:
        disable_cipher(cipher)

    # Step 3: Enable strong ciphers
    log.info("\nEnabling strong cipher suites...")
    for cipher in CIPHERS_TO_ENABLE:
        enable_cipher(cipher)

    # Step 4: Enforce cipher suite order
    log.info("\nEnforcing strong cipher suite order...")
    enforce_cipher_suite_order()

    # Step 5: Reboot
    log.info("\n" + "=" * 60)
    log.info("✅ All changes applied successfully!")
    log.info("➡️  System will restart in 10 seconds...")
    log.info("➡️  After reboot run: sweet32_WIN_VERIFY.py")
    log.info("=" * 60)

    subprocess.run(["shutdown", "/r", "/t", "10"])


if __name__ == "__main__":
    main()