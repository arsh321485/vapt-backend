"""
Best-effort classification of an uploaded-report host into one of the "All
Assets" page's tabs: "web_app" | "firewall" | "server" | "other" (the
generic "Assets" tab — bare IPs and anything else we can't confidently place
land here). Keyword/pattern based, no extra LLM call — good enough to route
the common, recognizable cases (vendor firewall names, URL-shaped web
targets, OS-bearing hosts); anything ambiguous safely falls back to "other"
rather than guessing wrong.

Order matters: firewall is checked first since a firewall's own findings
often mention generic web/crypto terms too (e.g. "TLS 1.0 Enabled on VPN
Portal") that would otherwise misroute it into "web_app".
"""
import re

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

_FIREWALL_KEYWORDS = [
    "firewall", "fw-", "fw_", "palo alto", "palo-alto", "paloalto", "pan-os", "panos",
    "fortigate", "fortinet", "fortios", "cisco asa", "checkpoint", "check point",
    "sonicwall", "juniper srx", "pfsense", "edge-gw", "edgegw", "gateway",
    "vpn concentrator", "ngfw",
]

_WEB_APP_VULN_KEYWORDS = [
    # Deliberately specific, not bare "ssl"/"tls"/"http" — those show up on
    # plenty of non-web services (mail, RDP, DB-over-TLS) too and caused
    # false positives (e.g. "SSL Version 2/3 Protocol Detection" on a plain
    # Windows server) when this list was broader. "web server" was also
    # removed from here (real bug, confirmed via a live report) — a finding
    # saying "the target web server is running IIS 8.0" describes SERVER
    # SOFTWARE running on the host, not an application-layer trait of the
    # host itself; it was misclassifying bare-IP hosts with no OS info as
    # "web_app" purely because IIS/Apache findings mention "web server" in
    # their own boilerplate description text. See _SERVER_SOFTWARE_KEYWORDS.
    "xss", "cross-site scripting", "sql injection", "csrf", "cross-site request forgery",
    "cookie", "web application", "content-security-policy", "clickjacking",
    "cors", "hsts", "strict transport security", "directory listing", "cgi",
    "http response splitting", "http header",
]

_SERVER_OS_KEYWORDS = [
    "windows", "linux", "unix", "macos", "mac os", "ubuntu", "centos", "debian",
    "red hat", "rhel", "solaris", "freebsd", "esxi", "vmware",
]

# Known web-server SOFTWARE — a finding mentioning these describes what's
# running on the machine (infrastructure), not that the host is itself a
# distinct "web application" — e.g. "Outdated Microsoft IIS 8.0" on a bare
# IP with no host_information.operating-system should land on "Server",
# not "Web App". Checked only when no app-layer signal (XSS/SQLi/CSRF/etc.,
# still in _WEB_APP_VULN_KEYWORDS above) already matched.
_SERVER_SOFTWARE_KEYWORDS = [
    "iis", "internet information services", "apache", "nginx", "tomcat",
    "web server", "lighttpd", "jboss", "weblogic", "websphere",
]


def classify_asset_type(host_name: str, host_information: dict = None, vulnerabilities: list = None) -> str:
    host_information = host_information or {}
    vulnerabilities = vulnerabilities or []
    name_lower = (host_name or "").strip().lower()

    combined_text = name_lower + " " + " ".join(
        f"{v.get('plugin_name', '')} {v.get('description', '')}".lower()
        for v in vulnerabilities
    )

    # Firewall — vendor names / device-role keywords, checked first (see
    # module docstring for why priority matters here).
    if any(k in combined_text for k in _FIREWALL_KEYWORDS):
        return "firewall"

    # Web app — URL-shaped host, or vulnerability content is dominated by
    # web-layer findings (HTTP/HTTPS, XSS, SQLi, cookies, CSRF, etc.)
    if name_lower.startswith("http://") or name_lower.startswith("https://"):
        return "web_app"
    if any(k in combined_text for k in _WEB_APP_VULN_KEYWORDS):
        return "web_app"

    # Server — real OS info present (Nessus host_information, or the
    # asset.operating_system column custom_report_ai.py now captures), OR a
    # known web-server software mention with no accompanying app-layer
    # signal above (see _SERVER_SOFTWARE_KEYWORDS docstring).
    os_str = (
        host_information.get("operating-system")
        or host_information.get("os")
        or host_information.get("OS")
        or host_information.get("operating_system")
        or host_information.get("system-type")
        or ""
    ).strip().lower()
    if os_str or any(k in combined_text for k in _SERVER_SOFTWARE_KEYWORDS):
        return "server"

    # Bare IP or anything else with no stronger signal -> generic "Assets" tab
    return "other"
