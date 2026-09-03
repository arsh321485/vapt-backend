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

_FIREWALL_KEYWORDS = [
    "firewall", "fw-", "fw_", "palo alto", "palo-alto", "paloalto", "pan-os", "panos",
    "fortigate", "fortinet", "fortios", "cisco asa", "cisco firepower", "cisco ftd",
    "cisco meraki mx", "checkpoint", "check point", "sonicwall", "juniper srx",
    "pfsense", "opnsense", "watchguard", "barracuda networks", "cyberoam",
    "sophos xg", "sophos utm", "zyxel usg", "web application firewall",
    "utm appliance", "edge-gw", "edgegw", "gateway", "vpn concentrator", "ngfw",
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
    "ssrf", "server-side request forgery", "xxe", "xml external entity",
    "path traversal", "directory traversal", "open redirect",
    "insecure deserialization", "template injection", "html injection",
    "session fixation", "wordpress", "drupal", "joomla", "graphql",
    "swagger ui", "rest api",
    # Real bug report: the extremely common Nessus/web-scanner finding
    # "Missing HTTP Security Headers" (and its many variants — "X-Frame-
    # Options Header Not Set", "X-Content-Type-Options Header Missing",
    # etc.) never matched anything above — "http header" only matches
    # when those two words sit right next to each other, which they don't
    # in "HTTP Security Headers". Confirmed on a real report: 11 of 13
    # web-facing subdomains (portal.sedco.com, taxapp.sedco.com, ...) fell
    # through to the generic "Assets" tab instead of "Web App" solely
    # because of this gap — every one of them had nothing but this one
    # finding. "security header"/"security headers" catches the phrase
    # regardless of vendor wording, without the false-positive risk of a
    # bare "header" keyword.
    "security header", "security headers", "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy",
]

# Real bug fix: this list existed but was never actually referenced inside
# classify_asset_type() below (dead code) — a host with no structured
# host_information OS field, but whose vulnerability text plainly mentions
# an OS (e.g. "Microsoft Windows Unsupported Version Detection"), fell all
# the way through to the generic "Assets" tab instead of "Server". Checked
# only as a fallback, after Firewall and Web App have already both failed
# to match, same discipline as the rest of this function — so a stray
# "Windows"/"Linux" word appearing in an already-classified web-app finding
# never gets a chance to override that.
_SERVER_OS_KEYWORDS = [
    "windows", "windows server", "linux", "unix", "macos", "mac os", "ubuntu",
    "centos", "debian", "red hat", "rhel", "solaris", "freebsd", "openbsd",
    "netbsd", "aix", "hp-ux", "amazon linux", "oracle linux", "suse", "opensuse",
    "alpine linux", "esxi", "vmware",
]

# Known web-server SOFTWARE — a finding mentioning these describes what's
# running on the machine (infrastructure), not that the host is itself a
# distinct "web application" — e.g. "Outdated Microsoft IIS 8.0" on a bare
# IP with no host_information.operating-system should land on "Server",
# not "Web App". Checked only when no app-layer signal (XSS/SQLi/CSRF/etc.,
# still in _WEB_APP_VULN_KEYWORDS above) already matched.
_SERVER_SOFTWARE_KEYWORDS = [
    "iis", "internet information services", "apache", "nginx", "tomcat",
    "web server", "lighttpd", "jboss", "weblogic", "websphere", "caddy",
    "haproxy", "varnish", "postfix", "sendmail", "exim", "mysql", "postgresql",
    "microsoft sql server", "mssql", "oracle database", "mongodb server",
    "redis server", "docker", "kubernetes", "hyper-v", "kvm", "proxmox",
]


def classify_asset_type(host_name: str, host_information: dict = None, vulnerabilities: list = None) -> str:
    host_information = host_information or {}
    vulnerabilities = vulnerabilities or []
    name_lower = (host_name or "").strip().lower()

    # Real bug report: a device whose OS/metadata field literally says
    # "Cisco ASA 5500" (a firewall) was landing on "Server" instead of
    # "Firewall" — confirmed on a real report. combined_text previously
    # only drew from host_name + each vulnerability's plugin_name/
    # description, never from host_information's own values (DNS Name, OS,
    # etc.), so the firewall-keyword check below had no way to see
    # "cisco asa" sitting in the OS field — it only found the OS string
    # later, in the Server check, by which point Firewall had already been
    # ruled out. Folding host_information's values in here means the same
    # firewall/web-app keyword checks also catch a vendor name that only
    # shows up in metadata, not in the hostname or a finding's own text.
    host_info_text = " ".join(str(v) for v in host_information.values() if v)
    combined_text = (
        name_lower + " " + host_info_text.lower() + " " + " ".join(
            f"{v.get('plugin_name', '')} {v.get('description', '')}".lower()
            for v in vulnerabilities
        )
    )

    # Firewall — vendor names / device-role keywords, checked first (see
    # module docstring for why priority matters here). combined_text is
    # already fully lowercased above, but a keyword is compared as-is — if
    # a future edit adds a keyword with any uppercase in it (e.g. "Cisco
    # ASA" instead of "cisco asa"), `k in combined_text` would silently
    # never match. Lowercase every keyword right here too so matching
    # stays correct regardless of how the list is written later, not just
    # because every entry happens to be lowercase today.
    if any(k.lower() in combined_text for k in _FIREWALL_KEYWORDS):
        return "firewall"

    # Web app — URL-shaped host, or vulnerability content is dominated by
    # web-layer findings (HTTP/HTTPS, XSS, SQLi, cookies, CSRF, etc.)
    if name_lower.startswith("http://") or name_lower.startswith("https://"):
        return "web_app"
    if any(k.lower() in combined_text for k in _WEB_APP_VULN_KEYWORDS):
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
    if (
        os_str
        or any(k.lower() in combined_text for k in _SERVER_SOFTWARE_KEYWORDS)
        or any(k.lower() in combined_text for k in _SERVER_OS_KEYWORDS)
    ):
        return "server"

    # Bare IP or anything else with no stronger signal -> generic "Assets" tab
    return "other"
