"""
Classification of an uploaded-report host into one of the "All Assets" page's
tabs: "web_app" | "firewall" | "server" | "other" (the generic "Assets" tab —
bare IPs and anything else we can't confidently place land here).

Two layers:
  1. classify_asset_type() below — the original keyword/pattern-based
     classifier. Still used as a fast, no-API-call SAFETY FALLBACK (see
     get_asset_type_map_for_report) for whenever the GPT layer can't be
     reached, and for the "web_app" case, which is decided locally (a
     URL-shaped host name) rather than sent to the model at all.
  2. classify_hosts_via_gpt() / get_asset_type_map_for_report() (bottom of
     this file) — real request: classification should be GPT-driven and
     based on the host's OS/platform, not on matching keywords against
     vulnerability names. One batched GPT call per report (never per host —
     a 50+ host report would otherwise mean 50+ API calls on every
     classification), result persisted onto the report doc so it only ever
     runs ONCE per report, not on every Assets-page load. Applies uniformly
     to every report type (Nessus, Nessus HTML, AWS, custom) since all of
     them normalize into the same vulnerabilities_by_host shape this
     operates on.
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
    # Real bug report: a genuine "Web Application Testing" report's own
    # findings — "Sensitive Information Accessible Through Browser Cache
    # After Logout", "TLS Security Controls Not Properly Enforced"
    # (missing Secure-cookie-attribute/HSTS, both browser/session-layer
    # concerns) — matched nothing above, so those hosts fell through to
    # GPT, which can only answer "server"/"other" (never "web_app"),
    # misclassifying application endpoints as generic assets.
    "browser cache", "session cookie", "secure attribute", "tls security control",
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

# Infrastructure/service-protocol findings, checked against a single
# FINDING's own title only (see classify_finding_type) — deliberately
# separate from _SERVER_SOFTWARE_KEYWORDS/_SERVER_OS_KEYWORDS above
# (those exist for HOST-level classify_asset_type/_keyword_server, where
# a bare "ssh"/"tls"/"cipher" match against combined free-text description
# would be too false-positive-prone). A finding's own TITLE saying "SSH"/
# "TLS 1.0"/"Terrapin"/etc. is unambiguous — these are the underlying
# transport/service-layer findings ("Outdated OpenSSH Version Disclosed",
# "SSH Terrapin Prefix Truncation Weakness", "Deprecated TLS 1.0/1.1 and
# Associated Weak Cipher Suites", "Weak SSH Configuration (Weak MAC
# Algorithms Enabled)") that real classification feedback said must count
# as "server", not inherit whatever the host's overall type is.
_SERVER_FINDING_KEYWORDS = [
    "ssh", "openssh", "terrapin", "zookeeper", "kafka", "ftp", "telnet",
    "rdp", "remote desktop", "smb", "samba", "snmp", "cipher suite",
    "weak cipher", "tls 1.0", "tls 1.1", "sslv2", "sslv3", "ssl 2.0", "ssl 3.0",
    "weak mac algorithm",
]


def _title_signal_text(host_name: str, host_information: dict, vulnerabilities: list) -> str:
    """Host name + host_information values + each finding's own TITLE only
    (never free-text description) — see classify_asset_type's own docstring
    for why titles-only avoids false positives from prose mentioning a
    keyword in passing. Shared so the Firewall/Web App keyword checks stay
    identical whether run inside classify_asset_type or as a pre-GPT check
    in get_asset_type_map_for_report."""
    name_lower = (host_name or "").strip().lower()
    host_info_text = " ".join(str(v) for v in (host_information or {}).values() if v)
    plugin_names_text = " ".join((v.get("plugin_name") or "") for v in (vulnerabilities or [])).lower()
    return name_lower + " " + host_info_text.lower() + " " + plugin_names_text


def _keyword_web_app_or_firewall(host_name: str, host_information: dict, vulnerabilities: list) -> str:
    """
    Firewall/Web-App keyword pre-check, usable ahead of the GPT classifier —
    real bug report: _CLASSIFY_PROMPT (below) only ever asks GPT to pick
    "firewall" | "server" | "other", never "web_app" — that category is
    otherwise ONLY ever assigned via the URL-prefix shortcut in
    get_asset_type_map_for_report. A host whose EXTRACTED name happens to
    come back as a bare domain (e.g. "travel-test.fgeninsurance.com" instead
    of "https://travel-test.fgeninsurance.com" — real, confirmed: the exact
    same source PDF produced both forms for the same asset across two
    separate extraction runs) could never be classified "web_app" even
    though its findings (cookies, HSTS, XSS, ...) plainly describe a web
    application — GPT structurally cannot return that answer for it, so it
    always landed on "server" or "other" instead, purely because of which
    written form the extraction happened to settle on for that run. Returns
    "firewall" or "web_app" when a confident keyword match exists (same
    priority order and keyword lists as classify_asset_type), else "" —
    callers should fall through to GPT/further classification in that case.
    """
    title_text = _title_signal_text(host_name, host_information, vulnerabilities)
    if any(k.lower() in title_text for k in _FIREWALL_KEYWORDS):
        return "firewall"
    if any(k.lower() in title_text for k in _WEB_APP_VULN_KEYWORDS):
        return "web_app"
    return ""


def classify_asset_type(host_name: str, host_information: dict = None, vulnerabilities: list = None) -> str:
    host_information = host_information or {}
    vulnerabilities = vulnerabilities or []
    name_lower = (host_name or "").strip().lower()

    # Two text blobs, deliberately different scope:
    #
    # combined_text — EVERYTHING, including each finding's free-text
    # description. Used only for the Server check below (OS/software
    # mentions in description prose are a genuine, desired signal there —
    # e.g. "the target web server is running IIS 8.0" correctly implying
    # Server infrastructure, see _SERVER_SOFTWARE_KEYWORDS).
    #
    # title_text — host name + host_information's own values (DNS Name,
    # OS, etc. — real bug report: a device whose OS/metadata field
    # literally said "Cisco ASA 5500" was landing on "Server" instead of
    # "Firewall" until this was folded in) + each finding's own TITLE
    # (plugin_name) ONLY, never its free-text description. Used for
    # Firewall and Web App — two real bugs, same root cause, both fixed
    # this way: a description explaining RC4's impact "...if plaintext is
    # repeatedly encrypted (e.g., HTTP cookies)..." false-positived "cookie"
    # into Web App, and a description mentioning a host's "default
    # gateway" while explaining an unrelated network issue could just as
    # easily false-positive "gateway" into Firewall — free prose can
    # mention almost anything in passing, unlike a finding's own name. The
    # real vendor/app-layer detection plugins these two lists exist to
    # catch say so directly in their own title ("Fortinet FortiOS
    # Detected", "Web Application Potentially Vulnerable to Clickjacking"),
    # so restricting to titles loses no real signal.
    host_info_text = " ".join(str(v) for v in host_information.values() if v)
    combined_text = (
        name_lower + " " + host_info_text.lower() + " " + " ".join(
            f"{v.get('plugin_name', '')} {v.get('description', '')}".lower()
            for v in vulnerabilities
        )
    )
    plugin_names_text = " ".join((v.get("plugin_name") or "") for v in vulnerabilities).lower()
    title_text = name_lower + " " + host_info_text.lower() + " " + plugin_names_text

    # Firewall — vendor names / device-role keywords, checked first (see
    # module docstring for why priority matters here). Same discipline as
    # Web App below: title_text (host name/metadata + each finding's own
    # TITLE), never free-text descriptions. A word like "gateway" is
    # common enough in generic boilerplate prose (e.g. a finding
    # explaining a host's "default gateway" while describing an unrelated
    # network issue) to false-positive the same way "cookie" did for Web
    # App — the real vendor-detection plugins that this list exists to
    # catch ("Fortinet FortiOS Detected", "Cisco ASA Software Detection",
    # etc.) say so directly in their own title, and a vendor name sitting
    # only in host_information (e.g. OS="Cisco ASA 5500") is still caught
    # here since host_info_text is folded into title_text too. A keyword
    # is compared as-is — if a future edit adds one with any uppercase in
    # it (e.g. "Cisco ASA" instead of "cisco asa"), `k in title_text`
    # would silently never match. Lowercase every keyword right here too
    # so matching stays correct regardless of how the list is written
    # later, not just because every entry happens to be lowercase today.
    if any(k.lower() in title_text for k in _FIREWALL_KEYWORDS):
        return "firewall"

    # Web app — URL-shaped host, or vulnerability content is dominated by
    # web-layer findings (HTTP/HTTPS, XSS, SQLi, cookies, CSRF, etc.)
    if name_lower.startswith("http://") or name_lower.startswith("https://"):
        return "web_app"
    if any(k.lower() in title_text for k in _WEB_APP_VULN_KEYWORDS):
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


# ── GPT-driven classification (OS/platform based, not vuln-name based) ─────

import json
import logging

logger = logging.getLogger(__name__)

_OS_FIELD_KEYS = ("operating-system", "os", "OS", "operating_system", "system-type")

_CLASSIFY_PROMPT = """You are classifying network scan hosts into device categories based on their OS/platform.

For each host below, pick exactly ONE category:
- "firewall" — the OS/platform indicates a firewall, VPN gateway, or network security appliance (examples: FortiOS, PAN-OS, Cisco ASA, SonicOS, pfSense, Check Point GAiA, Cisco Meraki MX)
- "server" — the OS/platform indicates a general-purpose server/workstation OS (examples: Windows Server, Windows 10/11, Ubuntu, Red Hat/RHEL, CentOS, Debian, macOS, ESXi, Solaris)
- "other" — genuinely nothing usable to go on (e.g. a bare IP with no OS field and no informative findings) — never guess

Each host's "signal" is either a structured OS string, or (when no OS field was detected) a list of that host's vulnerability finding TITLES. When working from titles, you do NOT need to pin down the exact OS — you only need to decide whether this is a general-purpose server running some service, as opposed to a firewall appliance or something with no signal at all. A title naming ANY server-side software or network service — a web server (nginx, Apache, IIS, Tomcat), a database (MySQL, PostgreSQL, MongoDB), SSH/OpenSSH, FTP, SMB, a message broker or coordination service (ZooKeeper, Kafka, RabbitMQ, Redis), or any other backend daemon — is enough on its own to classify "server", even if it doesn't tell you Windows vs Linux specifically (e.g. "Unauthenticated Apache ZooKeeper Instance Exposed" -> server; "Outdated nginx Version Disclosed" -> server; "Outdated OpenSSH Version Disclosed" -> server). Only fall back to "other" when the titles genuinely give you nothing — no OS hint AND no named server software/service at all.

Hosts:
{hosts_json}

Respond with ONLY this exact JSON shape, nothing else, no markdown fences:
{{"classifications": [{{"host_name": "...", "asset_type": "server"}}, ...]}}
"""


def _get_classification_llm():
    """Same construction pattern as custom_report_ai._get_validation_llm —
    reuses the same OPENAI_API_KEY/OPENAI_MODEL settings already configured
    for this project."""
    from langchain_openai import ChatOpenAI
    from django.conf import settings

    api_key = getattr(settings, "OPENAI_API_KEY", None)
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not configured in Django settings.")
    model = getattr(settings, "OPENAI_MODEL", "gpt-4o-mini")
    # Same "no timeout -> can hang forever" gap found and fixed in
    # mitigation_tool._get_crewai_llm / custom_report_ai._get_validation_llm.
    return ChatOpenAI(model=model, temperature=0, api_key=api_key, max_tokens=4096, timeout=60, max_retries=1)


def _strip_json_fences(raw: str) -> str:
    raw = (raw or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    return raw.strip()


def _os_signal_for_host(host_information: dict, vulnerabilities: list) -> str:
    """Structured OS field if present; otherwise up to 15 vulnerability
    finding TITLES (never full descriptions — same discipline as
    classify_asset_type's title_text, to avoid free-text false positives)
    as an inference signal for the model."""
    host_information = host_information or {}
    for key in _OS_FIELD_KEYS:
        val = (host_information.get(key) or "").strip()
        if val:
            return val

    titles = []
    for v in (vulnerabilities or [])[:15]:
        name = (v.get("plugin_name") or v.get("pluginname") or v.get("name") or "").strip()
        if name:
            titles.append(name)
    return "; ".join(titles)



# Real question raised after adding a timeout to this LLM call ("badi file
# aayi to problem to nahi hoga?"): classify_hosts_via_gpt used to send
# EVERY host in the report in one single call — fine for the ~200-host
# file this was built against, but a report with many more hosts would
# make that one prompt grow without bound, and a 60s timeout is NOT
# guaranteed to be enough for an arbitrarily large single call. Same fix
# as custom_report_ai.py's row-chunking: cap how many hosts go into any
# one call, so a bigger report just means more (still-bounded, still-fast)
# sequential calls instead of one unbounded one.
CLASSIFY_BATCH_SIZE = 100


def classify_hosts_via_gpt(hosts: list) -> dict:
    """
    hosts: list of {"host_name", "host_information", "vulnerabilities"}
    dicts — already filtered to exclude URL-shaped (web_app) hosts by the
    caller, since that case is decided locally, never sent to the model.

    Splits into batches of CLASSIFY_BATCH_SIZE hosts so a large report
    (many hosts) can never make a single call's prompt grow unbounded —
    however many hosts there are, each individual call stays the same
    safe size; a bigger report just means more sequential calls.

    Returns {host_name: "server"|"firewall"|"other"} for whichever hosts
    the model actually returned a valid classification for — a host
    missing from the result (model error, malformed response, or it just
    didn't answer for that one) is the caller's responsibility to fall
    back on (see get_asset_type_map_for_report). Never raises — any
    failure talking to the model or parsing its response for a given
    batch just leaves that batch's hosts out of the result.
    """
    entries = []
    for h in hosts:
        name = (h.get("host_name") or "").strip()
        if not name:
            continue
        entries.append({
            "host_name": name,
            "signal": _os_signal_for_host(h.get("host_information"), h.get("vulnerabilities")),
        })
    if not entries:
        return {}

    result = {}
    for start in range(0, len(entries), CLASSIFY_BATCH_SIZE):
        batch = entries[start:start + CLASSIFY_BATCH_SIZE]
        try:
            llm = _get_classification_llm()
            prompt = _CLASSIFY_PROMPT.format(hosts_json=json.dumps(batch))
            response = llm.invoke(prompt)
            raw_content = getattr(response, "content", "") or ""
            parsed = json.loads(_strip_json_fences(raw_content))
        except Exception:
            logger.exception(
                f"[AssetClassification] GPT batch classification failed for hosts "
                f"{start + 1}-{start + len(batch)} of {len(entries)}"
            )
            continue

        for row in (parsed.get("classifications") or []):
            if not isinstance(row, dict):
                continue
            name = (row.get("host_name") or "").strip()
            atype = (row.get("asset_type") or "").strip().lower()
            if name and atype in ("server", "firewall", "other"):
                result[name] = atype

    return result


def get_asset_type_map_for_report(db, report_id: str, hosts: list) -> dict:
    """
    The main entry point every read call site should use instead of calling
    classify_asset_type() per host in a loop.

    hosts: list of {"host_name", "host_information", "vulnerabilities"}
    dicts for every host currently shown for this report (already deduped
    by host_name by the caller).

    Returns {host_name: asset_type} covering every host passed in.
    Persists newly-computed classifications back onto the nessus_reports
    doc (field "asset_type_map", stored as a [{"host_name","asset_type"}]
    list — NOT a dict keyed by host_name, since host names are IPs/FQDNs
    containing dots, and Mongo update-operator paths treat "." as a nested-
    field separator; a list sidesteps that entirely) so the GPT call only
    ever runs once per report — every subsequent read for the same report,
    from any of the several call sites across admin/user asset views, is a
    plain Mongo lookup, no API call.
    """
    report_id = str(report_id)
    doc = db["nessus_reports"].find_one({"report_id": report_id}, {"asset_type_map": 1})
    stored = {
        row.get("host_name"): row.get("asset_type")
        for row in ((doc or {}).get("asset_type_map") or [])
        if row.get("host_name")
    }

    result = {}
    to_classify = []
    newly_stored = {}
    for h in hosts:
        name = (h.get("host_name") or "").strip()
        if not name:
            continue
        if name.lower().startswith(("http://", "https://")):
            # Decided locally, never sent to the model — a web app doesn't
            # have a meaningful "OS" the way this classifier reasons about.
            result[name] = "web_app"
            continue
        if name in stored:
            result[name] = stored[name]
            continue
        # Real bug report: GPT (classify_hosts_via_gpt below) can only ever
        # return "firewall"/"server"/"other" — never "web_app" — so a host
        # whose extracted name is a bare domain (not URL-prefixed) could
        # never land on Web App no matter how clearly its findings describe
        # one (cookies, HSTS, XSS, ...). See _keyword_web_app_or_firewall's
        # own docstring for the real report where the exact same asset got
        # "web_app" via the URL-prefix shortcut in one extraction run and
        # "server"/"other" in another, purely because of which written form
        # the extraction settled on. Decide Firewall/Web App from the
        # findings themselves first — same keyword lists/priority
        # classify_asset_type already uses — before ever reaching GPT, so
        # classification is consistent regardless of which form a host's
        # name happens to be stored in.
        keyword_type = _keyword_web_app_or_firewall(name, h.get("host_information"), h.get("vulnerabilities"))
        if keyword_type:
            result[name] = keyword_type
            newly_stored[name] = keyword_type
            continue
        # Real requirement: when a host has no explicit OS field, GPT is
        # still the one that should classify it — from the host's own
        # finding titles as its signal (see _os_signal_for_host and
        # _CLASSIFY_PROMPT, which now explicitly teaches it that a title
        # naming server-side software/services like nginx/OpenSSH/
        # ZooKeeper implies "server" even with no OS name attached) —
        # not a local keyword shortcut that skips the model entirely.
        to_classify.append(h)

    if to_classify:
        gpt_result = classify_hosts_via_gpt(to_classify)
        for h in to_classify:
            name = (h.get("host_name") or "").strip()
            atype = gpt_result.get(name)
            if not atype:
                # GPT unreachable, malformed response, or this specific host
                # missing from it — fall back to the fast, no-API-call
                # keyword classifier rather than leaving the page without an
                # answer. NOT persisted as a final answer (see below) so a
                # later successful GPT run can still improve it.
                atype = classify_asset_type(name, h.get("host_information"), h.get("vulnerabilities"))
                result[name] = atype
                continue
            result[name] = atype
            newly_stored[name] = atype

    if newly_stored:
        try:
            merged = dict(stored)
            merged.update(newly_stored)
            db["nessus_reports"].update_one(
                {"report_id": report_id},
                {"$set": {"asset_type_map": [
                    {"host_name": k, "asset_type": v} for k, v in merged.items()
                ]}},
            )
        except Exception:
            logger.exception(f"[AssetClassification] failed to persist asset_type_map for report_id={report_id}")

    return result


def classify_finding_type(plugin_name: str, host_asset_type: str) -> str:
    """
    Classifies a single VULNERABILITY FINDING (not the host it's on) into
    the same "web_app"/"firewall"/"server"/"other" taxonomy the Assets tab
    uses — for the All Vulnerabilities tab's per-vulnerability asset_type_
    counts breakdown (adminasset/userasset views.py).

    Real bug report: that breakdown used to just inherit the HOST's own
    overall classification for every one of its findings — wrong the
    moment one host has a mix of both natures, which is common (e.g. a
    web-app host's scan also turns up its underlying OpenSSH/nginx/TLS-
    config issues). Confirmed on a real report: producers-demo.fgeninsurance.com
    (correctly host-classified "web_app" — it IS a web application) has 8
    findings; only 2 (IDOR, TLS Security Controls) are genuinely web-app-
    nature, the other 6 (OpenSSH, SSH Terrapin, Apache HTTP Server,
    deprecated TLS/cipher suites, nginx, weak SSH MAC algorithms) are
    infrastructure/service findings that should count as "server" — under
    the old host-inherited logic, all 8 counted as "web_app".

    Same priority order as classify_asset_type (firewall, then web_app,
    then server), checked against the finding's own TITLE only (never
    free-text description — same false-positive discipline as everywhere
    else in this module). A finding with no confident signal of its own
    (e.g. a generic "SSL Certificate Expired") falls back to the host's
    overall type — still a reasonable default for a genuinely ambiguous
    finding.
    """
    title = (plugin_name or "").strip().lower()
    if any(k.lower() in title for k in _FIREWALL_KEYWORDS):
        return "firewall"
    if any(k.lower() in title for k in _WEB_APP_VULN_KEYWORDS):
        return "web_app"
    if (
        any(k.lower() in title for k in _SERVER_SOFTWARE_KEYWORDS)
        or any(k.lower() in title for k in _SERVER_OS_KEYWORDS)
        or any(k.lower() in title for k in _SERVER_FINDING_KEYWORDS)
    ):
        return "server"
    return host_asset_type or "other"


def classify_report_assets_background(report_id: str):
    """
    Real request: run classification proactively right after upload,
    instead of only lazily the first time someone opens the Assets page
    (which made THAT first page-load carry the GPT latency). Meant to be
    started as a daemon thread from the upload flow — see
    upload_report/views.py's _auto_generate_cards_bg call site, same
    pattern. By the time anyone actually opens the Assets page, this has
    very likely already finished, so it just reads the persisted result —
    the lazy path in get_asset_type_map_for_report is still there as a
    fallback/self-heal for reports uploaded before this existed, or if
    this background run hasn't finished (or failed) yet.

    Classifies BOTH currently-visible hosts and any Freemium-trimmed
    locked_hosts — so a later upgrade-unlock (upload_report/views.py's
    unlock_freemium_hosts_for_admin) doesn't need to trigger its own GPT
    run; the classification is already sitting there waiting for it.
    """
    from vaptfix.mongo_client import MongoContext

    report_id = str(report_id)
    try:
        with MongoContext() as db:
            doc = db["nessus_reports"].find_one(
                {"report_id": report_id},
                {"vulnerabilities_by_host": 1, "locked_hosts": 1},
            )
            if not doc:
                return
            all_hosts = list(doc.get("vulnerabilities_by_host") or []) + list(doc.get("locked_hosts") or [])
            if not all_hosts:
                return
            get_asset_type_map_for_report(db, report_id, all_hosts)
            logger.info(f"[AssetClassification] background classification finished for report_id={report_id} ({len(all_hosts)} host(s))")
    except Exception:
        logger.exception(f"[AssetClassification] background classification failed for report_id={report_id}")
