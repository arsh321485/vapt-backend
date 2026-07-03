#!/usr/bin/env python3
"""
=============================================================================
SWEET32 (CVE-2016-2183) - SSL Medium Strength Cipher Suite Verification Script
Nessus Plugin ID: 42873
Target Service : FTP (tcp/21) over TLS (FTPS — both Explicit & Implicit)
=============================================================================

WHAT THIS SCRIPT DOES:
  1. Connects to an FTPS server (port 21 explicit TLS, or port 990 implicit TLS)
  2. Enumerates all TLS cipher suites offered by the server
  3. Flags any cipher that:
       - Uses 3DES (SWEET32 exploit vector)
       - Has a key length < 112 bits
       - Is RC4, NULL, EXPORT, or anonymous (aNULL/eNULL)
  4. Produces a PASS / FAIL verdict with a detailed report

USAGE:
  python3 sweet32_verification.py <host> [options]

  Examples:
    python3 sweet32_verification.py 192.168.1.10
    python3 sweet32_verification.py ftp.example.com --port 21 --json
    python3 sweet32_verification.py 10.0.0.5 --port 990 --output report.json
    python3 sweet32_verification.py 10.0.0.5 --all-ciphers

REQUIREMENTS:
  Python 3.6+   (no extra pip packages required — uses stdlib ssl, ftplib, socket)
"""

import ssl
import socket
import ftplib
import argparse
import json
import sys
import logging
import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# WEAK / MEDIUM STRENGTH CIPHER PATTERNS  (Nessus Plugin 42873 logic)
# ─────────────────────────────────────────────────────────────────────────────

# These cipher suite name fragments are considered vulnerable
SWEET32_PATTERNS = [
    "3DES",         # All 3DES ciphers (SWEET32 core)
    "DES-CBC3",     # Alternative notation
    "DES-EDE",      # Another 3DES notation
]

# Additional medium/weak cipher patterns (Nessus plugin 42873 scope)
WEAK_PATTERNS = [
    "RC4",          # POODLE/Bar Mitzvah
    "NULL",         # No encryption
    "EXPORT",       # Export-grade (40/56-bit)
    "anon",         # Anonymous key exchange
    "aNULL",        # Anonymous auth
    "eNULL",        # No encryption
    "DES-CBC-",     # Single DES (56-bit)
    "RC2",          # RC2 (40/128-bit)
    "IDEA",         # IDEA (64-bit block — SWEET32 affected)
    "SEED",         # SEED (outdated)
]

# Ciphers considered STRONG (must use these)
STRONG_INDICATORS = ["AES", "CHACHA20", "AESGCM", "AES128", "AES256"]

# ─────────────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CipherResult:
    name:          str
    protocol:      str
    bits:          int
    is_sweet32:    bool = False
    is_weak:       bool = False
    weakness_reason: str = ""

    @property
    def is_vulnerable(self) -> bool:
        return self.is_sweet32 or self.is_weak

    @property
    def status(self) -> str:
        if self.is_sweet32:
            return "VULNERABLE (SWEET32/3DES)"
        if self.is_weak:
            return f"WEAK ({self.weakness_reason})"
        return "OK"


@dataclass
class ScanReport:
    host:               str
    port:               int
    scan_time:          str
    tls_mode:           str          # "explicit" | "implicit"
    server_certificate: dict
    all_ciphers:        list[CipherResult] = field(default_factory=list)
    vulnerable_ciphers: list[CipherResult] = field(default_factory=list)
    verdict:            str  = "UNKNOWN"
    error:              Optional[str] = None

    @property
    def passed(self) -> bool:
        return self.verdict == "PASS"


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

log = logging.getLogger("sweet32_verify")


# ─────────────────────────────────────────────────────────────────────────────
# CIPHER CLASSIFICATION
# ─────────────────────────────────────────────────────────────────────────────

def classify_cipher(name: str, bits: int) -> tuple[bool, bool, str]:
    """
    Returns (is_sweet32, is_weak, reason).
    """
    upper = name.upper()

    # SWEET32 check — 3DES
    for pat in SWEET32_PATTERNS:
        if pat.upper() in upper:
            return True, False, "3DES cipher (SWEET32/CVE-2016-2183)"

    # Nessus medium-strength definition: >=64-bit and <112-bit key length
    if 64 <= bits < 112:
        return False, True, f"Medium strength key ({bits}-bit, <112-bit threshold)"

    # Additional weak patterns
    for pat in WEAK_PATTERNS:
        if pat.upper() in upper:
            return False, True, f"Weak cipher pattern: {pat}"

    # Bit-length checks
    if bits < 64:
        return False, True, f"Low strength key ({bits}-bit)"

    return False, False, ""


def get_all_ssl_ciphers(context: ssl.SSLContext) -> list[tuple]:
    """Return all ciphers available in the given SSL context."""
    return context.get_ciphers()


# ─────────────────────────────────────────────────────────────────────────────
# CONNECTION HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def build_ssl_context(check_hostname: bool = False) -> ssl.SSLContext:
    """
    Build a permissive SSL context that will negotiate ANY cipher
    (so we can enumerate what the server supports, not just what we prefer).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname  = check_hostname
    ctx.verify_mode     = ssl.CERT_NONE   # Don't verify cert — enumeration only

    # Allow older protocols so we can detect legacy cipher offers
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except AttributeError:
        pass  # Python < 3.7 — ignore

    # Set a permissive cipher string to allow negotiation of weak ciphers
    try:
        ctx.set_ciphers("ALL:!aNULL:!eNULL")
    except ssl.SSLError:
        ctx.set_ciphers("ALL")

    return ctx


def get_cert_info(peer_cert: dict) -> dict:
    """Extract readable certificate metadata."""
    if not peer_cert:
        return {"error": "No certificate presented"}
    info = {}
    for field_name in ("subject", "issuer", "version", "serialNumber",
                        "notBefore", "notAfter"):
        if field_name in peer_cert:
            info[field_name] = str(peer_cert[field_name])
    return info


def connect_explicit_ftps(host: str, port: int, timeout: int) -> tuple[ssl.SSLSocket, dict]:
    """
    Connect via FTPS Explicit (STARTTLS on port 21).
    Returns (ssl_socket, cert_dict).
    """
    ctx = build_ssl_context()
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=timeout)
    ftp.sendcmd("AUTH TLS")
    ssl_sock = ctx.wrap_socket(ftp.sock, server_hostname=host)
    cert     = ssl_sock.getpeercert()
    return ssl_sock, cert


def connect_implicit_ftps(host: str, port: int, timeout: int) -> tuple[ssl.SSLSocket, dict]:
    """
    Connect via FTPS Implicit (TLS from first byte, port 990).
    Returns (ssl_socket, cert_dict).
    """
    ctx      = build_ssl_context()
    raw_sock = socket.create_connection((host, port), timeout=timeout)
    ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
    cert     = ssl_sock.getpeercert()
    return ssl_sock, cert


# ─────────────────────────────────────────────────────────────────────────────
# CIPHER ENUMERATION
# ─────────────────────────────────────────────────────────────────────────────

def probe_cipher(host: str, port: int, cipher_name: str,
                 tls_mode: str, timeout: int) -> Optional[CipherResult]:
    """
    Attempt a TLS handshake forcing a specific cipher.
    Returns a CipherResult if the server accepted it, None otherwise.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        ctx.set_ciphers(cipher_name)
    except ssl.SSLError:
        return None  # Cipher not supported by local OpenSSL build

    try:
        if tls_mode == "explicit":
            # STARTTLS handshake
            raw = socket.create_connection((host, port), timeout=timeout)
            # Read FTP banner
            raw.recv(1024)
            # Send AUTH TLS
            raw.sendall(b"AUTH TLS\r\n")
            resp = raw.recv(1024)
            if not resp.startswith(b"234"):
                raw.close()
                return None
            ssl_sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            # Implicit TLS
            raw      = socket.create_connection((host, port), timeout=timeout)
            ssl_sock = ctx.wrap_socket(raw, server_hostname=host)

        negotiated = ssl_sock.cipher()  # (name, protocol, bits)
        ssl_sock.close()

        if negotiated and negotiated[0].upper() == cipher_name.upper():
            proto = negotiated[1] or "TLS"
            bits  = negotiated[2] or 0
            is_s32, is_weak, reason = classify_cipher(cipher_name, bits)
            return CipherResult(
                name=cipher_name,
                protocol=proto,
                bits=bits,
                is_sweet32=is_s32,
                is_weak=is_weak,
                weakness_reason=reason,
            )
    except (ssl.SSLError, ConnectionRefusedError, OSError, TimeoutError):
        pass
    return None


def enumerate_ciphers_via_context(host: str, port: int,
                                   tls_mode: str, timeout: int) -> list[CipherResult]:
    """
    Enumerate ciphers by connecting once and inspecting what was negotiated,
    then iterating over the local OpenSSL cipher list.
    This is a best-effort approach without external tools like sslscan.
    """
    results        = []
    ctx            = build_ssl_context()
    all_local      = [c["name"] for c in ctx.get_ciphers()]

    log.info("Probing %d cipher suites against %s:%d (%s TLS)…",
             len(all_local), host, port, tls_mode)

    for cipher_name in all_local:
        result = probe_cipher(host, port, cipher_name, tls_mode, timeout)
        if result:
            results.append(result)
            icon = "✗" if result.is_vulnerable else "✓"
            log.debug("  %s  %-45s  %s-bit  %s",
                      icon, cipher_name, result.bits, result.status)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# PRIMARY SCAN FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def scan_host(host: str, port: int, timeout: int = 10,
              show_all: bool = False) -> ScanReport:
    """
    Full SWEET32 scan for the given host:port.
    Returns a ScanReport with verdict and cipher details.
    """
    report = ScanReport(
        host=host,
        port=port,
        scan_time=datetime.datetime.utcnow().isoformat() + "Z",
        tls_mode="explicit" if port != 990 else "implicit",
        server_certificate={},
    )

    # ── Step 1: Initial connection to grab cert ────────────────────────────
    log.info("Connecting to %s:%d (%s TLS)…", host, port, report.tls_mode)
    try:
        if report.tls_mode == "explicit":
            ssl_sock, cert = connect_explicit_ftps(host, port, timeout)
        else:
            ssl_sock, cert = connect_implicit_ftps(host, port, timeout)

        report.server_certificate = get_cert_info(cert)
        negotiated_cipher = ssl_sock.cipher()
        log.info("Initial negotiated cipher: %s", negotiated_cipher)
        ssl_sock.close()

    except ftplib.error_perm as e:
        report.error   = f"FTP permission error (server may not support TLS): {e}"
        report.verdict = "ERROR"
        log.error(report.error)
        return report
    except ConnectionRefusedError:
        report.error   = f"Connection refused to {host}:{port}"
        report.verdict = "ERROR"
        log.error(report.error)
        return report
    except Exception as e:
        report.error   = f"Connection failed: {type(e).__name__}: {e}"
        report.verdict = "ERROR"
        log.error(report.error)
        return report

    # ── Step 2: Enumerate all accepted ciphers ─────────────────────────────
    all_ciphers = enumerate_ciphers_via_context(
        host, port, report.tls_mode, timeout
    )

    report.all_ciphers        = all_ciphers
    report.vulnerable_ciphers = [c for c in all_ciphers if c.is_vulnerable]

    # ── Step 3: Verdict ───────────────────────────────────────────────────
    sweet32_ciphers = [c for c in all_ciphers if c.is_sweet32]
    if sweet32_ciphers:
        report.verdict = "FAIL"
    elif report.vulnerable_ciphers:
        report.verdict = "FAIL"  # Other weak ciphers also fail
    elif not all_ciphers:
        report.verdict = "UNKNOWN"  # Could not enumerate
        report.error   = "No ciphers were successfully probed."
    else:
        report.verdict = "PASS"

    return report


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT / REPORTING
# ─────────────────────────────────────────────────────────────────────────────

def print_human_report(report: ScanReport, show_all: bool = False) -> None:
    """Pretty-print the scan result to stdout."""
    RESET  = "\033[0m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BOLD   = "\033[1m"
    CYAN   = "\033[96m"

    width = 68
    print("\n" + "=" * width)
    print(f"{BOLD}  SWEET32 Verification Report — CVE-2016-2183 / Plugin 42873{RESET}")
    print("=" * width)
    print(f"  Host      : {report.host}")
    print(f"  Port      : {report.port}  ({report.tls_mode} TLS)")
    print(f"  Scanned   : {report.scan_time}")

    # Certificate
    cert = report.server_certificate
    if cert and "error" not in cert:
        print(f"\n{BOLD}  Certificate:{RESET}")
        for k, v in cert.items():
            print(f"    {k:15s}: {v}")

    print()

    # Vulnerable ciphers
    if report.vulnerable_ciphers:
        print(f"{BOLD}{RED}  ✗ VULNERABLE CIPHERS DETECTED ({len(report.vulnerable_ciphers)}):{RESET}")
        print(f"  {'Cipher Suite':<45} {'Bits':>6}  Status")
        print("  " + "-" * 62)
        for c in report.vulnerable_ciphers:
            marker = "🔴" if c.is_sweet32 else "🟡"
            print(f"  {marker} {c.name:<43} {c.bits:>6}  {RED}{c.status}{RESET}")
    else:
        print(f"{GREEN}  ✓ No vulnerable ciphers detected.{RESET}")

    # All ciphers (if requested)
    if show_all and report.all_ciphers:
        print(f"\n{BOLD}{CYAN}  All Accepted Ciphers ({len(report.all_ciphers)}):{RESET}")
        print(f"  {'Cipher Suite':<45} {'Bits':>6}  {'Protocol':<10}  Status")
        print("  " + "-" * 76)
        for c in sorted(report.all_ciphers, key=lambda x: x.bits, reverse=True):
            color = RED if c.is_vulnerable else GREEN
            icon  = "✗" if c.is_vulnerable else "✓"
            print(f"  {icon} {c.name:<43} {c.bits:>6}  {c.protocol:<10}  "
                  f"{color}{c.status}{RESET}")

    # Summary
    print()
    print("=" * width)
    if report.verdict == "PASS":
        print(f"  {BOLD}{GREEN}  VERDICT: PASS ✔  — No SWEET32/medium-strength ciphers found.{RESET}")
    elif report.verdict == "FAIL":
        sweet32_count = sum(1 for c in report.vulnerable_ciphers if c.is_sweet32)
        print(f"  {BOLD}{RED}  VERDICT: FAIL ✗  — {sweet32_count} SWEET32 cipher(s) still active.{RESET}")
        print(f"\n  {YELLOW}  Recommendation:{RESET}")
        print(f"    Run sweet32_mitigation.py --host {report.host} then re-scan.")
    elif report.error:
        print(f"  {BOLD}{YELLOW}  VERDICT: ERROR — {report.error}{RESET}")
    else:
        print(f"  {BOLD}{YELLOW}  VERDICT: UNKNOWN — Could not enumerate ciphers.{RESET}")
    print("=" * width + "\n")


def save_json_report(report: ScanReport, path: str) -> None:
    """Serialise the report to JSON."""
    def _serialise(obj):
        if isinstance(obj, CipherResult):
            d = asdict(obj)
            d["status"] = obj.status
            d["is_vulnerable"] = obj.is_vulnerable
            return d
        raise TypeError(f"Unserializable: {type(obj)}")

    payload = {
        "vulnerability": {
            "nessus_plugin_id": 42873,
            "cve":              "CVE-2016-2183",
            "name":             "SSL Medium Strength Cipher Suites Supported (SWEET32)",
            "cvss_v3":          7.5,
        },
        "scan": {
            "host":               report.host,
            "port":               report.port,
            "tls_mode":           report.tls_mode,
            "scan_time":          report.scan_time,
            "verdict":            report.verdict,
            "error":              report.error,
            "certificate":        report.server_certificate,
            "vulnerable_ciphers": [_serialise(c) for c in report.vulnerable_ciphers],
            "all_ciphers":        [_serialise(c) for c in report.all_ciphers],
        },
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    log.info("JSON report saved to: %s", path)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Verify SWEET32 (CVE-2016-2183) remediation on an FTPS server.\n"
            "Connects to the target, enumerates cipher suites, and "
            "reports whether 3DES/medium-strength ciphers are still accepted."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 sweet32_verification.py 192.168.1.10\n"
            "  python3 sweet32_verification.py ftp.example.com --port 990\n"
            "  python3 sweet32_verification.py 10.0.0.5 --all-ciphers --output report.json\n"
        ),
    )
    p.add_argument("host", help="Target hostname or IP address")
    p.add_argument("--port",        type=int, default=21,
                   help="FTP/FTPS port (default: 21 for explicit TLS; use 990 for implicit)")
    p.add_argument("--timeout",     type=int, default=10,
                   help="Connection timeout in seconds (default: 10)")
    p.add_argument("--all-ciphers", action="store_true",
                   help="Print all accepted ciphers, not just vulnerable ones")
    p.add_argument("--json",        action="store_true",
                   help="Output results as JSON to stdout")
    p.add_argument("--output",      metavar="FILE",
                   help="Save JSON report to a file")
    p.add_argument("--verbose",     action="store_true",
                   help="Enable debug logging")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stdout,
    )

    report = scan_host(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        show_all=args.all_ciphers,
    )

    if args.json:
        # JSON to stdout
        print(json.dumps(asdict(report), indent=2, default=str))
    else:
        print_human_report(report, show_all=args.all_ciphers)

    if args.output:
        save_json_report(report, args.output)

    # Exit code: 0 = PASS, 1 = FAIL/UNKNOWN, 2 = ERROR
    if report.verdict == "PASS":
        return 0
    if report.verdict == "ERROR":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())