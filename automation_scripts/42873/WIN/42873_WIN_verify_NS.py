import winreg
import ssl
import socket
import logging
import sys

# ─────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sweet32_verify")

# ─────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────

SCHANNEL_BASE = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

CIPHERS_TO_CHECK_DISABLED = [
    "Triple DES 168",
    "DES 56/56",
    "RC4 40/128",
    "RC4 56/128",
    "RC4 64/128",
    "RC4 128/128",
    "NULL",
]

CIPHERS_TO_CHECK_ENABLED = [
    "AES 128/128",
    "AES 256/256",
]

TARGET_HOST = "YOUR_VM_IP"   # ← change this
TARGET_PORT = 21             # ← change if different (990 for implicit FTPS)

# ─────────────────────────────────────────────────────────────────
# CHECK 1: Registry Verification
# ─────────────────────────────────────────────────────────────────

def check_registry() -> bool:
    log.info("\n[1] Checking registry cipher settings...")
    all_good = True

    # Check disabled ciphers
    for cipher in CIPHERS_TO_CHECK_DISABLED:
        key_path = f"{SCHANNEL_BASE}\\Ciphers\\{cipher}"
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            value, _ = winreg.QueryValueEx(key, "Enabled")
            winreg.CloseKey(key)
            if value == 0:
                log.info("✅ Correctly disabled: %s", cipher)
            else:
                log.error("❌ Still ENABLED: %s (value=%s)", cipher, value)
                all_good = False
        except FileNotFoundError:
            log.warning("⚠️ Registry key not found for: %s (may be disabled by default)", cipher)
        except Exception as e:
            log.error("❌ Error checking %s: %s", cipher, e)
            all_good = False

    # Check enabled ciphers
    for cipher in CIPHERS_TO_CHECK_ENABLED:
        key_path = f"{SCHANNEL_BASE}\\Ciphers\\{cipher}"
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            value, _ = winreg.QueryValueEx(key, "Enabled")
            winreg.CloseKey(key)
            if value == 0xFFFFFFFF:
                log.info("✅ Correctly enabled: %s", cipher)
            else:
                log.warning("⚠️ Not explicitly enabled: %s (value=%s)", cipher, value)
        except FileNotFoundError:
            log.warning("⚠️ Registry key not found for: %s", cipher)
        except Exception as e:
            log.error("❌ Error checking %s: %s", cipher, e)

    return all_good

# ─────────────────────────────────────────────────────────────────
# CHECK 2: Live TLS Handshake (3DES probe)
# ─────────────────────────────────────────────────────────────────

def check_live_connection() -> bool:
    log.info("\n[2] Probing live TLS connection for 3DES ciphers...")
    log.info("    Target: %s:%d", TARGET_HOST, TARGET_PORT)

    sweet32_ciphers = [
        "DES-CBC3-SHA",
        "ECDHE-RSA-DES-CBC3-SHA",
        "EDH-RSA-DES-CBC3-SHA",
    ]

    found_vulnerable = False

    for cipher in sweet32_ciphers:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers(cipher)

            with socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=TARGET_HOST):
                    log.error("❌ VULNERABLE — Server accepted 3DES cipher: %s", cipher)
                    found_vulnerable = True

        except ssl.SSLError:
            log.info("✅ Cipher rejected by server: %s", cipher)
        except Exception as e:
            log.info("✅ Cipher not accepted: %s (%s)", cipher, type(e).__name__)

    return not found_vulnerable

# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────

def main():
    log.info("=" * 60)
    log.info("SWEET32 Verification Script — CVE-2016-2183 / Plugin 42873")
    log.info("Target: Windows SCHANNEL Cipher Configuration")
    log.info("=" * 60)

    registry_ok = check_registry()
    live_ok     = check_live_connection()

    log.info("\n" + "=" * 60)
    if registry_ok and live_ok:
        log.info("✅ VERDICT: PASS — SWEET32 ciphers are disabled!")
        log.info("   Re-run Nessus scan to confirm Plugin 42873 is resolved.")
    else:
        log.error("❌ VERDICT: FAIL — Some checks did not pass.")
        log.error("   Review above and re-run sweet32_WIN_FIX.py")
    log.info("=" * 60)


if __name__ == "__main__":
    main()