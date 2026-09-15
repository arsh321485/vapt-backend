"""
Unique-IP counting for uploaded reports — frontend developer bug report:
the "This report has X IPs" plan-recommendation overlay was using
host_count (raw Nessus ReportHost rows, which can include duplicate
IP+hostname pairs and non-IP labels) instead of unique_ip_count (distinct
IPv4/IPv6 addresses of the actual scanned targets), causing the overlay's
count to disagree with the Assets page's real unique-host count for the
same file.

A Nessus <ReportHost name="..."> can be an IP OR a resolved hostname/FQDN
depending on scan settings; the separate <HostProperties> block usually
carries the real IP under a "host-ip" tag even when name is a hostname
(see host_information fallback chain already used in admindashboard/
userdashboard views). This module extracts one canonical IP per host
(preferring host_name if it's IP-shaped, falling back to host_information)
and counts the DISTINCT addresses across a report — same IP appearing
under two ReportHost entries (once by IP, once by its hostname) counts
once, and a host with no extractable IP at all (a bare OS/product label,
a name DNS couldn't resolve) contributes nothing rather than a guess.
"""
import re
import ipaddress
from typing import Optional, Iterable, Dict, Any, List

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_BRACKETED_IPV6_RE = re.compile(r"^\[([0-9a-fA-F:]+)\](?::\d+)?$")


def normalize_ip_candidate(raw: Optional[str]) -> Optional[str]:
    """
    Best-effort extraction of a single valid IPv4/IPv6 address out of a
    Nessus host_name-shaped string. Strips a URL scheme, path/query,
    a trailing :port, brackets and a :port around an IPv6 literal, and an
    IPv6 zone id (%eth0). Returns the canonical str(ipaddress...) form so
    textually-different-but-equal representations of the same address
    (e.g. leading zeros) still dedupe into one entry in a set, or None if
    the value plainly isn't an IP at all (a hostname, an OS/product label,
    etc.) — never raises.
    """
    if not raw:
        return None
    value = raw.strip()
    if not value:
        return None

    value = _SCHEME_RE.sub("", value)
    value = re.split(r"[/?#]", value, 1)[0].strip()
    if not value:
        return None

    bracket_match = _BRACKETED_IPV6_RE.match(value)
    if bracket_match:
        candidate = bracket_match.group(1)
    else:
        # Only strip a trailing :port for a host:port-shaped value (exactly
        # one colon) — an unbracketed IPv6 address has many colons, and
        # blindly stripping after the last one would corrupt it.
        if value.count(":") == 1 and not value.startswith(":"):
            host_part, _, maybe_port = value.rpartition(":")
            if maybe_port.isdigit():
                value = host_part
        candidate = value

    candidate = candidate.split("%", 1)[0]  # strip IPv6 zone id
    if not candidate:
        return None

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def extract_ip_from_host(host: Dict[str, Any]) -> Optional[str]:
    """Pull one IP out of a vulnerabilities_by_host-shaped host dict,
    trying host_name first, then the host_information fallback chain
    already established elsewhere in the codebase (admindashboard/
    userdashboard views) for when host_name is a hostname/FQDN, not an IP."""
    host_information = host.get("host_information") or {}
    candidates = [
        host.get("host_name"),
        host.get("host"),
        host_information.get("host-ip"),
        host_information.get("IP"),
        host_information.get("ip"),
    ]
    for raw in candidates:
        ip = normalize_ip_candidate(raw)
        if ip:
            return ip
    return None


def unique_ip_set(vulnerabilities_by_host: Optional[Iterable[Dict[str, Any]]]) -> set:
    """The distinct IPv4/IPv6 addresses across a vulnerabilities_by_host
    list. Pass active_hosts + locked_hosts combined to count the full,
    untrimmed report — see upload_report/views.py's UploadReportView for
    why unique_ip_count must reflect the whole file, not just what a
    Freemium trim currently leaves visible."""
    ips = set()
    for host in (vulnerabilities_by_host or []):
        ip = extract_ip_from_host(host)
        if ip:
            ips.add(ip)
    return ips


def compute_unique_ip_count(vulnerabilities_by_host: Optional[Iterable[Dict[str, Any]]]) -> int:
    return len(unique_ip_set(vulnerabilities_by_host))


def counts_from_report_doc(doc: Dict[str, Any]) -> Dict[str, int]:
    """The frontend's 4-field contract (host_count/unique_ip_count/
    visible_asset_count/locked_asset_count), computed from an already-
    loaded nessus_reports doc. Combines the currently-visible
    vulnerabilities_by_host with any Freemium-trimmed locked_hosts
    (billing.enforcement.select_freemium_active_hosts stores these back
    onto the same doc at upload time — see upload_report/views.py's
    _store_in_mongodb) so host_count/unique_ip_count reflect the WHOLE
    file, not just what a Freemium trim currently leaves visible."""
    visible_hosts = doc.get("vulnerabilities_by_host") or []
    locked_hosts = doc.get("locked_hosts") or []
    all_hosts = list(visible_hosts) + list(locked_hosts)
    return {
        "host_count": len(all_hosts),
        "unique_ip_count": compute_unique_ip_count(all_hosts),
        "visible_asset_count": len(visible_hosts),
        "locked_asset_count": len(locked_hosts),
    }
