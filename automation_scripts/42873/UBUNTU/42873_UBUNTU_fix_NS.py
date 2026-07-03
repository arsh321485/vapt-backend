#!/usr/bin/env python3
"""
=============================================================================
SWEET32 (CVE-2016-2183) - SSL Medium Strength Cipher Suite Mitigation Script
Nessus Plugin ID: 42873
Target Service : FTP (tcp/21) over TLS (FTPS)
=============================================================================

WHAT THIS SCRIPT DOES:
  1. Auto-detects the installed FTPS server (vsftpd, ProFTPD, Pure-FTPd)
  2. Backs up the existing configuration
  3. Disables 3DES / medium-strength cipher suites
  4. Restarts the service to apply changes

AFFECTED CIPHERS (removed):
  - EDH-RSA-DES-CBC3-SHA
  - ECDHE-RSA-DES-CBC3-SHA
  - DES-CBC3-SHA
  (any cipher using 3DES-CBC or key lengths >=64-bit and <112-bit)

SUPPORTED SERVERS:
  - vsftpd  (/etc/vsftpd.conf)
  - ProFTPD (/etc/proftpd/proftpd.conf or /etc/proftpd.conf)
  - Pure-FTPd (/etc/pure-ftpd/conf/TLSCipherSuite)

REQUIREMENTS:
  - Python 3.6+
  - Must be run as root (sudo python3 sweet32_mitigation.py)
  - 'systemctl' or 'service' available for service management
"""

import os
import sys
import shutil
import subprocess
import logging
import argparse
import datetime
from pathlib import Path
from enum import Enum

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Strong cipher string — excludes 3DES, RC4, NULL, EXPORT, aNULL, eNULL
STRONG_CIPHER_STRING = (
    "HIGH:!3DES:!aNULL:!eNULL:!NULL:!RC4:!EXPORT:!LOW:!MD5:@STRENGTH"
)

# Per-server safe cipher override (OpenSSL format)
SERVER_CIPHER_STRINGS = {
    "vsftpd":   "HIGH:!3DES:!aNULL:!eNULL:!RC4:!EXPORT:!LOW:@STRENGTH",
    "proftpd":  "HIGH:!3DES:!aNULL:!eNULL:!RC4:!EXPORT:!LOW:@STRENGTH",
    "pure-ftpd": "HIGH:!3DES:!aNULL:!eNULL:!RC4:!EXPORT:!LOW:@STRENGTH",
}

# Backup directory
BACKUP_DIR = Path("/etc/sweet32_backups")

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/sweet32_mitigation.log"),
    ],
)
log = logging.getLogger("sweet32_mitigation")

# ─────────────────────────────────────────────────────────────────────────────
# SERVER DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

class ServerType(Enum):
    VSFTPD   = "vsftpd"
    PROFTPD  = "proftpd"
    PUREFTPD = "pure-ftpd"
    UNKNOWN  = "unknown"


SERVER_CONFIGS = {
    ServerType.VSFTPD: {
        "config_paths": ["/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf"],
        "service_name": "vsftpd",
        # Key that controls cipher suite in vsftpd
        "cipher_key":  "ssl_ciphers",
        "tls_enable_key": "ssl_enable",
    },
    ServerType.PROFTPD: {
        "config_paths": [
            "/etc/proftpd/proftpd.conf",
            "/etc/proftpd.conf",
            "/usr/local/etc/proftpd.conf",
        ],
        "service_name": "proftpd",
        "cipher_key":  "TLSCipherSuite",
        "tls_enable_key": "TLSEngine",
    },
    ServerType.PUREFTPD: {
        # Pure-FTPd uses a per-directive file model
        "config_paths": [
            "/etc/pure-ftpd/conf/TLSCipherSuite",
            "/etc/pure-ftpd/pure-ftpd.conf",
        ],
        "service_name": "pure-ftpd",
        "cipher_key":  "TLSCipherSuite",  # standalone file content
        "tls_enable_key": "TLS",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def require_root() -> None:
    """Abort if not running as root."""
    if os.geteuid() != 0:
        log.error("This script must be run as root. Use: sudo python3 %s", __file__)
        sys.exit(1)


def run_command(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    log.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        log.error("Command failed: %s\nSTDERR: %s", " ".join(cmd), result.stderr)
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")
    return result


def detect_server() -> tuple[ServerType, Path]:
    """
    Detect which FTPS server is installed by checking binary presence
    and config file existence. Returns (ServerType, config_path).
    """
    detection_map = {
        ServerType.VSFTPD:   ["vsftpd"],
        ServerType.PROFTPD:  ["proftpd", "in.proftpd"],
        ServerType.PUREFTPD: ["pure-ftpd"],
    }

    for server_type, binaries in detection_map.items():
        for binary in binaries:
            if shutil.which(binary):
                # Binary found — find its config file
                cfg = SERVER_CONFIGS[server_type]
                for path_str in cfg["config_paths"]:
                    p = Path(path_str)
                    if p.exists():
                        log.info("Detected server: %s  |  Config: %s", server_type.value, p)
                        return server_type, p
                # Binary exists but primary config not found — return first path as target
                log.warning(
                    "Binary '%s' found but no config file detected. "
                    "Will attempt to write to %s",
                    binary,
                    cfg["config_paths"][0],
                )
                return server_type, Path(cfg["config_paths"][0])

    log.error(
        "No supported FTP server detected (vsftpd / proftpd / pure-ftpd). "
        "Please apply cipher changes manually."
    )
    return ServerType.UNKNOWN, Path()


def backup_config(config_path: Path) -> Path:
    """Create a timestamped backup of the config file."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"{config_path.name}.{timestamp}.bak"
    shutil.copy2(config_path, backup_path)
    log.info("Backup created: %s", backup_path)
    return backup_path


def restart_service(service_name: str, dry_run: bool = False) -> bool:
    """Restart the FTP service via systemctl or service."""
    if dry_run:
        log.info("[DRY-RUN] Would restart service: %s", service_name)
        return True

    for manager in (["systemctl", "restart"], ["service", service_name, "restart"]):
        cmd = manager if "service" in manager[0] else manager + [service_name]
        try:
            run_command(cmd)
            log.info("Service '%s' restarted successfully.", service_name)
            return True
        except (RuntimeError, FileNotFoundError):
            continue

    log.error("Failed to restart service '%s'. Please restart it manually.", service_name)
    return False


# ─────────────────────────────────────────────────────────────────────────────
# PER-SERVER MITIGATION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def _set_or_replace_line(lines: list[str], key: str, value: str) -> list[str]:
    """
    Find a line matching '^key' (case-insensitive) in a config file's lines.
    Replace or append the key=value directive.
    """
    new_line = f"{key}={value}\n"
    replaced = False
    result = []
    for line in lines:
        stripped = line.strip()
        # Match both 'key=...' and 'key ...' patterns (vsftpd uses =, proftpd uses space)
        if stripped.lower().startswith(key.lower()) and not stripped.startswith("#"):
            result.append(new_line)
            replaced = True
            log.debug("Replaced line: '%s'  →  '%s'", stripped, new_line.strip())
        else:
            result.append(line)
    if not replaced:
        result.append(f"\n# Added by sweet32_mitigation.py\n{new_line}")
        log.debug("Appended new directive: %s", new_line.strip())
    return result


def mitigate_vsftpd(config_path: Path, dry_run: bool) -> bool:
    """Disable 3DES ciphers in vsftpd.conf."""
    log.info("Applying vsftpd mitigation on %s", config_path)
    lines = config_path.read_text().splitlines(keepends=True)

    # Ensure SSL is enabled (only reconfigure cipher, don't enable TLS if off)
    ssl_enabled = any(
        l.strip().lower().startswith("ssl_enable=yes") for l in lines
    )
    if not ssl_enabled:
        log.warning(
            "ssl_enable=YES not found in %s. "
            "3DES cipher removal only matters if TLS/SSL is active.",
            config_path,
        )

    # Remove/replace ssl_ciphers directive
    lines = _set_or_replace_line(lines, "ssl_ciphers", SERVER_CIPHER_STRINGS["vsftpd"])

    if not dry_run:
        config_path.write_text("".join(lines))
        log.info("vsftpd config updated.")
    else:
        log.info("[DRY-RUN] Would write updated vsftpd config:\n%s", "".join(lines[-8:]))
    return True


def mitigate_proftpd(config_path: Path, dry_run: bool) -> bool:
    """Disable 3DES ciphers in proftpd.conf."""
    log.info("Applying ProFTPD mitigation on %s", config_path)
    content = config_path.read_text()
    lines   = content.splitlines(keepends=True)

    cipher_key = "TLSCipherSuite"
    new_directive = f"TLSCipherSuite {SERVER_CIPHER_STRINGS['proftpd']}\n"
    replaced = False
    result   = []

    for line in lines:
        stripped = line.strip()
        if stripped.lower().startswith(cipher_key.lower()) and not stripped.startswith("#"):
            result.append(new_directive)
            replaced = True
            log.debug("Replaced: '%s'  →  '%s'", stripped, new_directive.strip())
        else:
            result.append(line)

    if not replaced:
        # Insert before closing </IfModule> or at end of <IfModule mod_tls.c> block
        result.append(f"\n# Added by sweet32_mitigation.py\n{new_directive}")

    if not dry_run:
        config_path.write_text("".join(result))
        log.info("ProFTPD config updated.")
    else:
        log.info("[DRY-RUN] Would write updated ProFTPD config.")
    return True


def mitigate_pureftpd(config_path: Path, dry_run: bool) -> bool:
    """Disable 3DES ciphers for Pure-FTPd."""
    log.info("Applying Pure-FTPd mitigation on %s", config_path)

    # Pure-FTPd can use a standalone cipher file
    standalone_cipher_file = Path("/etc/pure-ftpd/conf/TLSCipherSuite")

    if standalone_cipher_file.parent.exists():
        # Modern Debian/Ubuntu Pure-FTPd layout
        target = standalone_cipher_file
        if target.exists():
            backup_config(target)
        if not dry_run:
            target.write_text(SERVER_CIPHER_STRINGS["pure-ftpd"] + "\n")
            log.info("Pure-FTPd cipher file written: %s", target)
        else:
            log.info("[DRY-RUN] Would write cipher string to %s", target)
    else:
        # Fallback: single conf file — find or add TLSCipherSuite
        lines = config_path.read_text().splitlines(keepends=True)
        cipher_key = "TLSCipherSuite"
        new_line   = f"TLSCipherSuite {SERVER_CIPHER_STRINGS['pure-ftpd']}\n"
        replaced   = False
        result     = []
        for line in lines:
            if line.strip().lower().startswith(cipher_key.lower()):
                result.append(new_line)
                replaced = True
            else:
                result.append(line)
        if not replaced:
            result.append(f"\n# Added by sweet32_mitigation.py\n{new_line}")
        if not dry_run:
            config_path.write_text("".join(result))
    return True


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATION
# ─────────────────────────────────────────────────────────────────────────────

MITIGATORS = {
    ServerType.VSFTPD:   mitigate_vsftpd,
    ServerType.PROFTPD:  mitigate_proftpd,
    ServerType.PUREFTPD: mitigate_pureftpd,
}


def run_mitigation(dry_run: bool = False) -> None:
    """Main entry point for the mitigation workflow."""
    log.info("=" * 60)
    log.info("SWEET32 Mitigation Script — CVE-2016-2183 / Plugin 42873")
    log.info("=" * 60)

    require_root()

    # ── Step 1: Detect server ──────────────────────────────────────────────
    server_type, config_path = detect_server()
    if server_type == ServerType.UNKNOWN:
        sys.exit(2)

    cfg = SERVER_CONFIGS[server_type]

    # ── Step 2: Backup ────────────────────────────────────────────────────
    if config_path.exists() and not dry_run:
        backup_config(config_path)
    elif not config_path.exists():
        log.warning("Config file %s does not exist yet — will create.", config_path)

    # ── Step 3: Apply cipher changes ──────────────────────────────────────
    mitigator = MITIGATORS[server_type]
    success   = mitigator(config_path, dry_run)

    if not success:
        log.error("Mitigation failed. Aborting.")
        sys.exit(3)

    # ── Step 4: Restart service ───────────────────────────────────────────
    restarted = restart_service(cfg["service_name"], dry_run)

    # ── Summary ───────────────────────────────────────────────────────────
    log.info("-" * 60)
    if dry_run:
        log.info("DRY-RUN complete. No changes were written.")
    elif restarted:
        log.info(
            "✔  Mitigation complete.\n"
            "   Server  : %s\n"
            "   Config  : %s\n"
            "   Ciphers : %s\n"
            "   Next    : Run sweet32_verification.py to confirm fix.",
            server_type.value,
            config_path,
            SERVER_CIPHER_STRINGS[server_type.value],
        )
    else:
        log.warning(
            "Config updated but service restart failed. "
            "Please restart %s manually.",
            cfg["service_name"],
        )
    log.info("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SWEET32 (CVE-2016-2183) automated mitigation for FTP servers."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without modifying any files or restarting services.",
    )
    parser.add_argument(
        "--server",
        choices=["vsftpd", "proftpd", "pure-ftpd"],
        help="Force a specific server type instead of auto-detecting.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Override the config file path.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    # Manual overrides
    if args.server:
        _type_map = {
            "vsftpd":   ServerType.VSFTPD,
            "proftpd":  ServerType.PROFTPD,
            "pure-ftpd": ServerType.PUREFTPD,
        }
        _server_type = _type_map[args.server]
        _cfg_path    = args.config or Path(SERVER_CONFIGS[_server_type]["config_paths"][0])
        require_root()
        if _cfg_path.exists() and not args.dry_run:
            backup_config(_cfg_path)
        MITIGATORS[_server_type](_cfg_path, args.dry_run)
        restart_service(SERVER_CONFIGS[_server_type]["service_name"], args.dry_run)
    else:
        run_mitigation(dry_run=args.dry_run)