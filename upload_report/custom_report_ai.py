"""
Custom File Validation + Extraction
------------------------------------
Any uploaded file that is neither a recognized Nessus export nor an AWS
Inspector CSV falls through to here. A single GPT-4o-mini call does two
things at once:

  1. VALIDATE — is this actually vulnerability/security-assessment data?
     A file only counts if it has, for at least one finding: an asset/host
     identifier, a vulnerability name/description, and a severity indicator.
  2. EXTRACT — if valid, pull the findings into the same
     vulnerabilities_by_host shape the Nessus/AWS parsers produce, so the
     rest of the pipeline (storage, preview, mitigation-card generation)
     can be reused unchanged.

Fails CLOSED: any error talking to the model, or a response that doesn't
parse as the expected JSON, is treated as invalid. We never guess and never
fabricate a finding that isn't clearly present in the document.
"""

import json
import logging
import re
from typing import Any, Dict, Optional

from django.conf import settings

logger = logging.getLogger(__name__)

# Hard cap on how much raw text goes to the model — bounds token cost/latency
# while still covering realistic pentest reports. Confirmed real bug at the
# old 20000: a 27-page/13-host custom PDF report got truncated well before
# most of its per-host detail sections, so gpt-4o-mini only ever saw (and
# only ever extracted) the first 2 of 13 hosts — silently, no error, just a
# report that looked "successfully" processed with most of its data
# missing. gpt-4o-mini's context window is 128K tokens (~4 chars/token for
# English text), so 100000 chars (~25K tokens) still leaves comfortable
# room for the prompt wrapper and the JSON response, while covering
# reports several times larger than the one that triggered this.
MAX_INPUT_CHARS = 100000

VALIDATION_PROMPT = """You are a strict gatekeeper for a vulnerability-management platform (VAPTFIX). \
An admin has uploaded a file that isn't a recognized Nessus or AWS Inspector export. Your job is to \
decide whether it actually contains vulnerability / security-assessment findings, and if so extract them.

A file is VALID only if it contains, for at least one finding:
  1. An asset/host identifier that is SPECIFIC to that finding (IP, hostname, URL, ARN, server/
     application name, or a named agent/device from the document's own asset list — anything that
     identifies WHICH machine or target that particular finding is about)
  2. A vulnerability/finding name or description (WHAT is wrong)
  3. A severity or risk indicator (Critical/High/Medium/Low/Info, a CVSS score, or equivalent)

CRITICAL — do not confuse a platform/vendor/product/OS name inside a finding's own title or rule
category with an actual asset identifier. Names like "Cisco IOS", "Windows", "ASA", "Linux",
"Apache" appearing in a finding's name (e.g. "Cisco IOS warning message", "CIS Microsoft Windows 11
Benchmark: ...") describe WHAT KIND of system the underlying alerting rule is about, not WHICH
specific host it fired on — never invent a host_name like "Cisco IOS" or "Windows" out of these
words. Some documents (e.g. SIEM/log-monitoring alert summaries) list findings/alert types in one
aggregate table for the whole environment, with the actual monitored hosts/agents named only
separately (e.g. a "Top agents" list or chart) and never explicitly linked to any specific row in
that table. If you cannot tell, for a given finding, which SPECIFIC named host it applies to, do
NOT guess or attach it to any host anyway (not even one from an "agents" list elsewhere in the
document) — leave that finding out entirely rather than fabricate or guess the association. A
report that turns out to have NO finding with a genuine, specific host attribution should be marked
invalid with a reason explaining this (e.g. "This report lists alert types in aggregate but does not
state which specific host/agent each one applies to").

Never invent findings that are not clearly present in the text, and never output the same finding
twice for the same host unless the document itself repeats it with genuinely different specifics
(e.g. a different port). If a field is not stated, leave it "".

IMPORTANT — one finding can affect many hosts. Pentest reports are often organized by FINDING
(one write-up per vulnerability), not by host, and that write-up may list several affected
assets together — e.g. under a heading like "Affected Host(s)", "Affected IP(s)", "Affected
URL(s)", "Affected Asset(s)", or as a bullet/comma list in the finding's own text. When a single
finding lists multiple affected hosts, you MUST create a separate entry for that same
vulnerability (same plugin_name/description/risk_factor/solution) under EACH one of those hosts
in the "hosts" array — do not collapse them into just one representative host and do not drop
any of the listed hosts. A report with 3 distinct findings where one of them lists 12 affected
hosts should produce far more than 3 total host/vulnerability entries.

CRITICAL — one physical asset is very often WRITTEN multiple different ways across the same
document; do not let that turn one asset into several. The same target may appear as a bare IP
("119.92.208.117"), as a hostname/URL ("sas.dos1.ph", "https://sas.dos1.ph/N/"), or as a combined
"IP / hostname" pair on one line — sometimes even a different combination per finding. These are
NOT different assets, they are the same asset written differently. Resolve this BEFORE extracting:
  - Look for the document's own per-asset summary table (e.g. "Security Issues per Host/IP(s)",
    "Security Issues per URL(s)", "Vulnerabilities Per Host", or similar) — whatever identifier
    THAT table uses for a given asset is the canonical host_name for it.
  - Use that SAME canonical host_name for every finding affecting that asset, even when a
    particular finding's own "Host/IP(s) Affected" line only gives the IP, only the hostname/URL,
    or a differently-formatted variant of the same target.
  - If there is no such summary table to anchor on, pick whichever single written form is used
    most often for that target across the findings, and use it consistently everywhere.
  - Never create a second, near-duplicate host entry just because one finding happened to use a
    different written form of a target you've already used elsewhere in this same extraction.
  - Safety net — a long document makes it easy to slip and use a different written form of the
    same asset somewhere later in this same response without realizing it. Because of that, ALSO
    list every asset that has more than one written form ANYWHERE in the document under
    "host_aliases" below (canonical form + every alternate IP/hostname/URL form seen for it) — this
    lets those get merged back together even if "hosts" itself isn't perfectly consistent.

ALSO — separately from the per-finding "hosts" above — look for a scope/target/inventory
list: a section like "Scope of Assessment", "Target(s)", "Assets Tested", "In-Scope Systems",
or any table/list that enumerates every asset that was part of this assessment (commonly near
the start of the document, often with a Description/IP or similar column). List EVERY DISTINCT
ASSET from that list under "all_assets" below, using for each one the SAME canonical host_name
you resolved above — including ones that never show up in any specific finding's "Host(s)
Affected" (a host can be tested and found clean, with zero findings, and still belongs here). If
one row of that list gives BOTH a hostname/item name AND an IP for what is clearly the same single
entry (e.g. an "ITEM" column and an "IP" column side by side for one S.No.), that is still exactly
ONE asset — add only ONE identifier for that row, never both as if they were separate assets. If
the document has no such scope/target list, leave "all_assets" as an empty list — do not invent
one from the hosts mentioned in findings.

CAUTION — do not confuse a genuine scope/target list with an unrelated reference table that just
happens to list URLs, e.g. a "Test Environment vs Production" mapping, a login-page/endpoint
reference appendix, or a table of specific page URLs (anything ending in a path like "/login",
"/sign_in", "/#/login", a specific form or endpoint) used elsewhere in the document for context.
Only the document's own actual assessment-scope table counts. When a genuine scope entry and a
finding's own host both point at the same domain (one as a bare domain, the other as a full page
URL with a path), that is the SAME asset — use the bare domain form and do not add the page-URL
form as if it were a second, separate entry.

Return ONLY a single JSON object, no markdown fences, no commentary, matching exactly this schema:

{{
  "valid": true or false,
  "reason": "<one sentence: why valid, or why rejected>",
  "hosts": [
    {{
      "host_name": "<asset/host identifier>",
      "operating_system": "<OS/platform string if stated for this asset (e.g. 'Microsoft Windows Server 2016'), else \\"\\">",
      "vulnerabilities": [
        {{
          "plugin_name": "<vulnerability/finding name>",
          "description": "<what the finding says>",
          "risk_factor": "<Critical|High|Medium|Low|Info>",
          "solution": "<suggested fix/mitigation text if present in the document, else \\"\\">",
          "cvss_v3_base_score": "<score if present, else \\"\\">"
        }}
      ]
    }}
  ],
  "all_assets": ["<every asset/host identifier from the document's own scope/target/inventory list, else empty list>"],
  "host_aliases": [
    {{
      "canonical": "<the exact host_name string you used for this asset in 'hosts'/'all_assets' above>",
      "also_known_as": ["<every OTHER IP/hostname/URL form of this SAME asset seen anywhere in the document, even ones you did not use as a host_name>"]
    }}
  ]
}}

If invalid, "hosts", "all_assets", and "host_aliases" must all be empty lists. If no asset in this
document has more than one written form, "host_aliases" is an empty list too — most reports need
one.

DOCUMENT TEXT:
---
{document_text}
---
"""


RECALL_CHECK_PROMPT = """You previously extracted vulnerability findings from the document below. \
Below is the list of vulnerability/finding names (plugin_name) already extracted, one per \
host/finding pair:

{already_extracted}

A single extraction pass over a long document can sometimes miss a genuine finding entirely, with \
no error or warning. Re-read the FULL document text below carefully and look specifically for any \
vulnerability/security finding whose NAME is not already covered by the list above for at least \
one of its affected hosts (a finding already listed for every host it affects should NOT be \
repeated; if that SAME finding name also affects an additional host not already paired with it \
above, that host/finding pair IS missing and must be included). Pay particular attention to \
whether the document itself states a total finding count or a per-severity breakdown (e.g. "Total \
Number of Distinct Vulnerabilities Discovered", a Critical/High/Medium/Low count, or a per-asset \
summary table) — if the count implied by the list above doesn't match what the document claims, \
look again for the gap, most often a whole finding subsection that got skipped.

Use the exact same host_name convention already used above — if a finding you find here affects a \
host already named in that list, reuse that exact same host_name string; never introduce a \
different written form (IP vs hostname vs URL) of an asset already covered above.

Return ONLY a JSON object with any MISSED host/finding pairs, in this exact schema — nothing else, \
no markdown fences, no commentary:

{{
  "hosts": [
    {{
      "host_name": "<asset/host identifier>",
      "operating_system": "<OS/platform string if stated, else \\"\\">",
      "vulnerabilities": [
        {{
          "plugin_name": "<vulnerability/finding name>",
          "description": "<what the finding says>",
          "risk_factor": "<Critical|High|Medium|Low|Info>",
          "solution": "<suggested fix/mitigation text if present, else \\"\\">",
          "cvss_v3_base_score": "<score if present, else \\"\\">"
        }}
      ]
    }}
  ]
}}

If nothing was missed, return exactly {{"hosts": []}}.

DOCUMENT TEXT:
---
{document_text}
---
"""


_STATED_TOTAL_PATTERNS = [
    # "Vulnerability occurrences/findings: 22", "Total Findings: 22",
    # "Total Vulnerabilities: 22" — real finding-INSTANCE count (one per
    # host a finding affects), which is what total_vulnerabilities actually
    # needs to reach. Deliberately does NOT match "distinct" here — see the
    # dedicated distinct-count pattern at the bottom of this list for why.
    re.compile(
        r"(?:Total\s+(?:Number\s+of\s+)?(?:Vulnerabilit(?:y|ies)(?:\s*/\s*\w+)?|Findings)|"
        r"Vulnerability\s+Occurrences\s*/\s*Findings)\s*[:\-]?\s*(\d+)",
        re.IGNORECASE,
    ),
    # Natural-language executive-summary phrasing, e.g. "a total of 22
    # vulnerabilities were identified/discovered/found", "we identified 22
    # vulnerabilities" — no fixed "Total:" label at all, just prose. Also
    # excludes "distinct" for the same reason as the pattern above.
    re.compile(
        r"(?:a\s+total\s+of\s+|identified\s+|discovered\s+|found\s+)(\d+)\s+"
        r"total\s+vulnerabilit(?:y|ies)",
        re.IGNORECASE,
    ),
    # LAST resort — real bug report: "Total Number of Distinct
    # Vulnerabilities Discovered: N" states a count of DISTINCT
    # vulnerability TYPES, not finding instances. A finding that affects
    # several hosts is one "distinct vulnerability" but multiple instances
    # (e.g. confirmed real: one report's own table showed 10 distinct
    # types but 22 actual instances across hosts, since some findings hit
    # many hosts each). Trusting this as the retry-loop's target made the
    # loop stop as soon as instances reached the (too-low) distinct count
    # — often on the very first pass, since instances >= distinct types
    # whenever ANY finding spans more than one host — silently never
    # retrying to reach the real, higher instance total. Only used if
    # nothing else below (the table's own instance-level "Total" row, tried
    # FIRST in _extract_stated_total, or the phrasings above) is present.
    re.compile(r"Total\s+Number\s+of\s+Distinct\s+Vulnerabilities\s+Discovered\s*[:\-]?\s*(\d+)", re.IGNORECASE),
]

# A per-host severity-breakdown table's own "Total" row, e.g.
# "Total   0   2   5   15   22" (Critical/High/Medium/Low/Total columns) —
# this is the single most reliable source of the TRUE instance-level grand
# total when the document has one, since it's the literal sum of every
# host's own row — tried FIRST, ahead of every phrase-based pattern (see
# _STATED_TOTAL_PATTERNS' own docstring on the "distinct" vs "instance"
# distinction this exists to get right). Matched separately from
# _STATED_TOTAL_PATTERNS (regex backtracking makes "capture the LAST
# number on the line" unreliable as a single pattern); instead find
# "Total" and grab a short window of text after it, then pull out every
# number in plain code and take the last one. Deliberately tolerant of the
# numbers landing on separate lines (not just separated by spaces on one
# line) — confirmed real: PyPDF2's text extraction for a table can break
# each cell onto its own line rather than keeping a row on one line, so a
# strict single-line pattern silently never matched a real table that was
# plainly there in the source PDF. Requires 3+ numbers in the window (a
# real severity-breakdown row, not just "Total: 5").
_STATED_TOTAL_ROW_RE = re.compile(r"\bTotal\b\s*((?:[^A-Za-z]*?\d+){3,}[^A-Za-z]{0,20})", re.IGNORECASE)


def _extract_stated_total(document_text: str) -> Optional[int]:
    """
    Best-effort extraction of the document's OWN claimed total finding-
    INSTANCE count (not distinct vulnerability types — see
    _STATED_TOTAL_PATTERNS' own docstring). Tries the table's own "Total"
    row first (the most reliable instance-level source when present), then
    several common report-template phrasings in order (most reliable
    first), since different pentest report templates word this
    differently. Returns None if the document doesn't state one anywhere
    recognizable — extraction still proceeds normally, just without this
    extra guardrail.
    """
    row_match = _STATED_TOTAL_ROW_RE.search(document_text)
    if row_match:
        numbers = re.findall(r"\d+", row_match.group(1))
        if numbers:
            try:
                return int(numbers[-1])
            except ValueError:
                pass

    for pattern in _STATED_TOTAL_PATTERNS:
        m = pattern.search(document_text)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                continue
    return None


def _find_missed_findings(document_text: str, filename: str, vulnerabilities_by_host: list) -> list:
    """
    Second, self-check GPT pass over a prose (pdf/docx/doc/html) document —
    real bug report: a single extraction call over a long report can skip a
    genuine finding entirely with no error or signal (confirmed on a real
    PDF: the model returned 6 of the document's own 7 findings — one
    "Missing Security Headers" Low finding just never appeared, silently,
    even though its text was present and well within MAX_INPUT_CHARS).

    Re-reads the SAME document text, given what the first pass already
    found, and asks only for whatever's missing. Best-effort and additive
    only: any failure here (LLM error, unparseable response, empty result)
    just means nothing gets added — it never removes or changes what the
    first pass already found.
    """
    if not document_text:
        return []
    already_lines = []
    for h in vulnerabilities_by_host:
        host_name = h.get("host_name") or ""
        for v in h.get("vulnerabilities") or []:
            already_lines.append(f"- {host_name}: {v.get('plugin_name')}")
    already_extracted = "\n".join(already_lines) or "(none)"

    try:
        llm = _get_validation_llm()
        prompt = RECALL_CHECK_PROMPT.format(already_extracted=already_extracted, document_text=document_text)
        response = llm.invoke(prompt)
        raw_content = getattr(response, "content", "") or ""
    except Exception as exc:
        logger.warning(f"[CustomFileValidation] '{filename}' recall-check LLM call failed (non-fatal): {exc}")
        return []

    try:
        cleaned = _strip_json_fences(raw_content)
        result = json.loads(cleaned)
    except Exception as exc:
        logger.warning(
            f"[CustomFileValidation] '{filename}' recall-check response unparseable (non-fatal): {exc}"
        )
        return []

    missed_hosts = (result or {}).get("hosts") if isinstance(result, dict) else None
    return missed_hosts if isinstance(missed_hosts, list) else []


def _merge_missed_findings(vulnerabilities_by_host: list, missed_hosts: list, filename: str) -> None:
    """Mutates vulnerabilities_by_host in place, adding any genuinely-new host/finding pairs
    _find_missed_findings turned up. Never touches or duplicates anything already present."""
    if not missed_hosts:
        return
    host_index = {h["host_name"]: h for h in vulnerabilities_by_host}
    existing_pairs = {
        ((h.get("host_name") or "").strip().lower(), (v.get("plugin_name") or "").strip().lower())
        for h in vulnerabilities_by_host for v in h.get("vulnerabilities") or []
    }
    added = 0
    for h in missed_hosts:
        if not isinstance(h, dict):
            continue
        host_name = (h.get("host_name") or "").strip()
        if not host_name:
            continue
        for v in h.get("vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            plugin_name = (v.get("plugin_name") or "").strip()
            if not plugin_name:
                continue
            key = (host_name.lower(), plugin_name.lower())
            if key in existing_pairs:
                continue
            existing_pairs.add(key)
            description = (v.get("description") or "").strip()
            new_vuln = {
                "plugin_id": None,
                "plugin_name": plugin_name,
                "synopsis": "",
                "description": description,
                "description_points": [description],
                "solution": (v.get("solution") or "").strip(),
                "see_also": [],
                "risk_factor": (v.get("risk_factor") or "").strip().title(),
                "cvss_v3_base_score": str(v.get("cvss_v3_base_score") or ""),
                "plugin_information": "",
                "plugin_output": "",
                "plugin_output_url": None,
            }
            if host_name in host_index:
                host_index[host_name]["vulnerabilities"].append(new_vuln)
            else:
                os_str = (h.get("operating_system") or "").strip()
                new_host = {
                    "host_name": host_name,
                    "host_information": {"operating-system": os_str} if os_str else {},
                    "vulnerabilities": [new_vuln],
                }
                vulnerabilities_by_host.append(new_host)
                host_index[host_name] = new_host
            added += 1
    if added:
        logger.info(f"[CustomFileValidation] '{filename}' recall-check pass added {added} missed finding(s)")


def _get_validation_llm():
    """
    LangChain ChatOpenAI LLM — same construction pattern as
    mitigation_tool._get_crewai_llm(), but used as a plain single-shot call
    (no crew orchestration needed for a classify+extract task).
    """
    from langchain_openai import ChatOpenAI

    api_key = getattr(settings, "OPENAI_API_KEY", None)
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not configured in Django settings.")

    model = getattr(settings, "OPENAI_MODEL", "gpt-4o-mini")
    # max_tokens was previously unset, which leaves the response capped at
    # whatever OpenAI's default completion length is (well under what a
    # 13-host, multi-finding-per-host JSON extraction needs) — a report
    # that legitimately has many hosts could have its JSON response cut off
    # mid-generation, which then fails json.loads() and silently drops
    # everything the model hadn't finished writing yet. gpt-4o-mini
    # supports up to 16384 output tokens; give it the full budget.
    # Real bug report (same gap found in mitigation_tool._get_crewai_llm):
    # no timeout meant a hung call here could block forever — and unlike
    # the background card-generation path, THIS one runs synchronously
    # inside the upload HTTP request itself, so a hang ties up a gunicorn
    # worker indefinitely instead of just delaying a background thread.
    return ChatOpenAI(model=model, temperature=0, api_key=api_key, max_tokens=16384, timeout=90, max_retries=1)


_BROKEN_HYPHEN_RE = re.compile(r"(\w) -(\w)")


def _fix_broken_hyphens(text: str) -> str:
    """
    PyPDF2 (and some DOCX renders) routinely insert a stray space right
    before a hyphen inside a compound word at certain kerning/rendering
    boundaries — e.g. a Scope table's "maynilad-csat.dos1.ph" comes out as
    "maynilad -csat.dos1.ph". Confirmed real: that single stray space split
    one hostname into what looked like two different tokens downstream,
    contributing to the same asset getting extracted as two separate hosts.
    Only collapses "<word char> -<word char>" (hyphen immediately followed
    by another word char, no space after it) — a real em/en-dash range like
    "2020 - 2021" always has a space AFTER the hyphen too and is untouched.
    """
    return _BROKEN_HYPHEN_RE.sub(r"\1-\2", text)


def _extract_document_text(parsed_data: Dict[str, Any]) -> str:
    """Pull the best available raw text out of whatever the generic parsers produced."""
    report_type = parsed_data.get("type")

    if report_type in ("pdf", "docx", "doc"):
        text = parsed_data.get("text_full") or parsed_data.get("text_preview") or ""
        return _fix_broken_hyphens(text)

    if report_type == "html":
        return parsed_data.get("text_preview") or ""

    if report_type in ("csv", "excel"):
        columns = parsed_data.get("columns") or []
        rows = parsed_data.get("preview") or []
        lines = [", ".join(str(c) for c in columns)]
        for row in rows:
            if isinstance(row, dict):
                lines.append(", ".join(str(row.get(c, "")) for c in columns))
        return "\n".join(lines)

    return ""


def _strip_json_fences(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    return raw.strip()


def _iter_row_chunks(columns, rows, max_chars: int = MAX_INPUT_CHARS):
    """
    Splits a large CSV/Excel row set into several self-contained text
    chunks, each under max_chars and each carrying its own copy of the
    column header line, so every chunk can be validated/extracted by the
    model independently (each row is a standalone record — unlike prose,
    there's no cross-row context a chunk boundary could break).

    Real bug report: rows used to be capped to the first 50
    (_shape_dataframe_payload) and then truncated again at MAX_INPUT_CHARS
    in a single call — between the two, a 1853-row file only ever had
    ~50 rows (9 hosts) actually reach the model. Chunking instead of
    capping means every row gets processed, however large the file is —
    just as more (sequential) model calls rather than one.
    """
    header = ", ".join(str(c) for c in columns)
    budget = max(max_chars - len(header) - 1, 1000)  # leave room for the header line itself

    chunk_lines = []
    chunk_len = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        line = ", ".join(str(row.get(c, "")) for c in columns)
        # +1 for the newline that will join this line into the chunk
        if chunk_lines and chunk_len + len(line) + 1 > budget:
            yield header + "\n" + "\n".join(chunk_lines)
            chunk_lines = []
            chunk_len = 0
        chunk_lines.append(line)
        chunk_len += len(line) + 1

    if chunk_lines:
        yield header + "\n" + "\n".join(chunk_lines)


_IP_TOKEN_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_HOSTNAME_TOKEN_RE = re.compile(
    r'\bhttps?://[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]|\b[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9-]*)+\b'
)


def _normalize_host_token(token: str) -> str:
    """Strip a URL down to its bare domain (scheme + path removed) for alias matching."""
    t = re.sub(r'^https?://', '', token.strip(), flags=re.IGNORECASE)
    return t.split('/')[0].rstrip('.')


def _looks_like_real_ip(candidate: str) -> bool:
    """
    Real bug report: the bare _IP_TOKEN_RE pattern also matches numbered
    section headings like "2.6.2.5" (right before a finding's title, e.g.
    "2.6.2.5 ASP.NET Verbose Error Messages Disclosure") — dot-separated
    digit groups are structurally identical to an IPv4 address. A genuine
    target IP in these reports (119.92.208.117, 139.135.69.221, ...) almost
    always has at least two octets in double digits or more; a section
    number's octets are consistently tiny (single digits). Cheap enough
    to reduce false-positive "aliases" without needing real IP knowledge.
    """
    octets = candidate.split(".")
    if len(octets) != 4:
        return False
    return sum(1 for o in octets if int(o) >= 10) >= 2


def _extract_ip_hostname_aliases(document_text: str) -> Dict[str, str]:
    """
    Deterministic, regex-based pre-scan of the raw document text for lines
    that pair a bare IP with a hostname/URL for the SAME target — e.g.
    "119.92.208.117 / sas.dos1.ph", "sas.dos1.ph  119.92.208.117" (a Scope
    table row), "119.92.208.117 / https://sas.dos1.ph".

    Real bug report: asking the model to self-report every alias it used
    (VALIDATION_PROMPT's "host_aliases" field) isn't reliable on its own —
    confirmed on a real PDF where the model still used 3+ different written
    forms of the SAME asset across one response despite that instruction, a
    long document makes perfect self-consistency within one generation
    unreliable. A line that plainly contains exactly one IP and exactly one
    hostname/URL token next to each other is almost never a coincidence —
    this is a much stronger, ground-truth signal straight from the source
    text, so it's applied on top of (and overrides on conflict) whatever
    the model itself reported.

    Only fires when a line has EXACTLY one IP and EXACTLY one hostname-like
    token — a line with more than one of either is ambiguous and skipped
    rather than guessed at. Hostname is preferred as the canonical display
    form (matches how these reports' own per-asset summary tables usually
    label an asset), with the IP folded into it as an alias.
    """
    alias_map: Dict[str, str] = {}
    canonical_by_ip: Dict[str, str] = {}
    for line in document_text.splitlines():
        ips = [ip for ip in _IP_TOKEN_RE.findall(line) if _looks_like_real_ip(ip)]
        hosts = [h for h in _HOSTNAME_TOKEN_RE.findall(line) if not _IP_TOKEN_RE.fullmatch(h)]
        if len(ips) != 1 or len(hosts) != 1:
            continue
        ip = ips[0]
        host = _normalize_host_token(hosts[0])
        if not host or host == ip:
            continue
        canonical = canonical_by_ip.setdefault(ip, host)
        alias_map[ip.lower()] = canonical
        alias_map[host.lower()] = canonical
    return alias_map


def _build_alias_map(host_aliases_raw) -> Dict[str, str]:
    """
    Turns the model's "host_aliases" list into {alias_lower: canonical}
    (canonical maps to itself too), for deterministic code-level merging —
    see _apply_host_aliases. Never trust the model to have been perfectly
    self-consistent across "hosts" on its own; this is the safety net.
    """
    alias_map: Dict[str, str] = {}
    if not isinstance(host_aliases_raw, list):
        return alias_map
    for entry in host_aliases_raw:
        if not isinstance(entry, dict):
            continue
        canonical = (entry.get("canonical") or "").strip()
        if not canonical:
            continue
        alias_map[canonical.lower()] = canonical
        also_known_as = entry.get("also_known_as") or []
        if not isinstance(also_known_as, list):
            continue
        for alias in also_known_as:
            if not isinstance(alias, str):
                continue
            alias = alias.strip()
            if alias:
                alias_map[alias.lower()] = canonical
    return alias_map


def _resolve_alias_groups(*alias_maps: Dict[str, str]) -> Dict[str, str]:
    """
    Combines any number of alias maps (alias_lower -> canonical, e.g. the
    model's own self-reported "host_aliases" and the regex pre-scan) into
    ONE consistent grouping via union-find.

    Real bug report: naively merging two partial alias maps by just
    overwriting/preferring one source breaks as soon as the two sources
    describe the SAME asset from different, non-overlapping angles — e.g.
    the model links "sas.dos1.ph" <-> "https://sas.dos1.ph" while the regex
    scan separately links "119.92.208.117" <-> "sas.dos1.ph"; neither map
    alone connects the IP to the https:// form, but the two together
    should, and a first "prefer whichever source's canonical string is
    longer" attempt at this picked winners per-key independently, which
    silently discarded the one link that actually mattered. Union-find
    treats every (alias, canonical) pair from every source as "these are
    the same asset," regardless of which direction any one source
    expressed it — so any chain of overlapping pairs across sources
    collapses into a single group.

    Picks, for each resulting group, the longest non-IP member as the
    display canonical (falls back to the longest member if the whole group
    is bare IPs) — a hostname/URL is more identifying/readable than a bare
    IP, and the longest form is least likely to be a truncated extraction
    artifact (e.g. a stray space before a hyphen turning "maynilad-csat.
    dos1.ph" into just "csat.dos1.ph" for one source but not the other).
    """
    parent: Dict[str, str] = {}
    display: Dict[str, str] = {}

    def _register(token: str) -> str:
        key = token.lower()
        parent.setdefault(key, key)
        if key not in display or len(token) > len(display[key]):
            display[key] = token
        return key

    def _find(key: str) -> str:
        parent.setdefault(key, key)
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def _union(a: str, b: str) -> None:
        ka, kb = _register(a), _register(b)
        ra, rb = _find(ka), _find(kb)
        if ra != rb:
            parent[ra] = rb

    for amap in alias_maps:
        for alias, canonical in amap.items():
            _union(alias, canonical)

    groups: Dict[str, set] = {}
    for amap in alias_maps:
        for token in list(amap.keys()) + list(amap.values()):
            key = _register(token)
            groups.setdefault(_find(key), set()).add(key)

    resolved: Dict[str, str] = {}
    for members in groups.values():
        non_ip = [m for m in members if not _IP_TOKEN_RE.fullmatch(m)]
        pool = non_ip or list(members)
        canonical_key = max(pool, key=lambda k: len(display.get(k, k)))
        canonical = display.get(canonical_key, canonical_key)
        for m in members:
            resolved[m] = canonical
    return resolved


def _apply_host_aliases(vulnerabilities_by_host: list, alias_map: Dict[str, str]) -> list:
    """
    Deterministically merges any host bucket whose host_name is a known
    alias of another into that other (canonical) bucket — real bug report:
    the model's own "hosts" array wasn't reliably self-consistent across a
    long response (e.g. used "sas.dos1.ph" for one finding and
    "119.92.208.117" — the SAME physical asset per the document's own
    tables — for another), so prompt instructions alone weren't enough to
    stop the same asset splitting into 2+ entries. Dedupes by
    (host, plugin_name) while merging so nothing doubles up.
    """
    if not alias_map:
        return vulnerabilities_by_host
    merged: Dict[str, Dict[str, Any]] = {}
    order: list = []
    seen_pairs = set()
    for h in vulnerabilities_by_host:
        host_name = (h.get("host_name") or "").strip()
        canonical = alias_map.get(host_name.lower(), host_name)
        bucket = merged.get(canonical)
        if not bucket:
            bucket = {"host_name": canonical, "host_information": h.get("host_information") or {}, "vulnerabilities": []}
            merged[canonical] = bucket
            order.append(canonical)
        elif not bucket.get("host_information") and h.get("host_information"):
            bucket["host_information"] = h["host_information"]
        for v in h.get("vulnerabilities") or []:
            key = (canonical.lower(), (v.get("plugin_name") or "").strip().lower())
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            bucket["vulnerabilities"].append(v)
    return [merged[c] for c in order]


def _merge_by_normalized_domain(vulnerabilities_by_host: list) -> list:
    """
    Final safety-net merge pass — groups host entries purely by their
    normalized bare-domain form (strip scheme + path), independent of
    whatever alias_map an earlier step built. Real bug report: a LATER
    recall-pass iteration can introduce a host_name variant (e.g.
    "https://producers-demo.fgeninsurance.com", when the first pass had
    already settled on the bare "producers-demo.fgeninsurance.com") that
    the alias_map built from the FIRST pass's own text scan never saw —
    _apply_host_aliases only ever does an exact-key lookup against that
    fixed, one-time map, so a brand new variant slips straight past it.
    This instead re-derives the grouping fresh from whatever host_name
    strings are actually present right now, every time it's called — no
    dependency on when or how each variant was introduced.

    Canonical picked per group: prefer a member with NO scheme prefix
    (bare domain — matches how these reports' own summary tables usually
    label an asset), longest among those; falls back to the longest
    member overall if every member in the group has a scheme prefix.
    Dedupes vulnerabilities by plugin_name while merging (same finding
    reported under two written forms of the same host is one finding, not
    two).
    """
    groups: Dict[str, list] = {}
    order: list = []
    for h in vulnerabilities_by_host:
        key = _normalize_host_token(h.get("host_name") or "").lower()
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(h)

    merged: list = []
    for key in order:
        members = groups[key]
        if len(members) == 1:
            merged.append(members[0])
            continue
        bare = [m for m in members if not re.match(r"^https?://", m.get("host_name") or "", re.IGNORECASE)]
        pool = bare or members
        canonical_host = max(pool, key=lambda m: len(m.get("host_name") or ""))["host_name"]
        host_information: Dict[str, Any] = {}
        vulns: list = []
        seen_pairs = set()
        for m in members:
            if not host_information and m.get("host_information"):
                host_information = m["host_information"]
            for v in m.get("vulnerabilities") or []:
                pkey = (v.get("plugin_name") or "").strip().lower()
                if pkey in seen_pairs:
                    continue
                seen_pairs.add(pkey)
                vulns.append(v)
        merged.append({"host_name": canonical_host, "host_information": host_information, "vulnerabilities": vulns})
    return merged


def _validate_and_extract_chunk(document_text: str, filename: str, chunk_label: str = "") -> Dict[str, Any]:
    """
    One single GPT call: validate + extract a single already-sized-to-fit
    block of document text. Returns
        {"valid": False, "reason": "..."}
    or
        {"valid": True, "reason": "...", "vulnerabilities_by_host": [...], "total_vulnerabilities": N}
    Never raises — every failure mode (model error, unparseable response,
    empty/invalid result) is caught and returned as {"valid": False, ...}.
    """
    label = f"'{filename}'{chunk_label}"
    try:
        llm = _get_validation_llm()
        prompt = VALIDATION_PROMPT.format(document_text=document_text)
        response = llm.invoke(prompt)
        raw_content = getattr(response, "content", "") or ""
        finish_reason = (
            (response.response_metadata or {}).get("finish_reason")
            if hasattr(response, "response_metadata") else None
        )
        if finish_reason and finish_reason != "stop":
            # "length" here means the model's own JSON response got cut off
            # mid-generation (ran out of output tokens) — the parse below
            # will very likely fail or silently yield a partial host list.
            logger.warning(
                f"[CustomFileValidation] {label} LLM response finish_reason="
                f"'{finish_reason}' (not 'stop') — output may be truncated, "
                f"raw response length={len(raw_content)} chars"
            )
    except Exception as exc:
        # Real bug report: this always said "please try again" — misleading
        # for an OpenAI billing/quota outage specifically ("insufficient_
        # quota"/"credit_balance_exhausted" in the error), since retrying
        # can NEVER succeed until someone adds credits — an admin who kept
        # retrying (reasonably, given the wording) would just see the same
        # failure forever and have no way to know their file was fine and
        # the problem was on our end. Detect that one case and say so
        # plainly instead — still without naming OpenAI/"credits" to the
        # customer, since that's our own vendor's internal detail, not
        # theirs to troubleshoot. Logged with a distinct, greppable tag so
        # this is easy to tell apart from a genuinely transient failure in
        # monitoring/alerts — this one needs a human to go add credits,
        # not a retry.
        exc_text = str(exc)
        if "insufficient_quota" in exc_text or "credit_balance_exhausted" in exc_text:
            logger.critical(f"[CustomFileValidation][QUOTA_EXHAUSTED] AI validation is down for {label}: {exc_text}")
            return {
                "valid": False,
                "reason": "This file needs additional processing that's temporarily unavailable. "
                          "Retrying won't help right now — please contact VaptFix support so we can "
                          "process it once service is restored.",
            }
        logger.error(f"[CustomFileValidation] LLM call failed for {label}: {exc}")
        return {"valid": False, "reason": "Could not validate this file right now — please try again."}

    try:
        cleaned = _strip_json_fences(raw_content)
        result = json.loads(cleaned)
    except Exception as exc:
        logger.error(
            f"[CustomFileValidation] Could not parse LLM response for {label}: {exc} "
            f"— raw response length={len(raw_content)} chars, tail={raw_content[-200:]!r}"
        )
        return {"valid": False, "reason": "Could not validate this file's contents — please try again."}

    logger.info(
        f"[CustomFileValidation] {label} model returned {len(result.get('hosts') or [])} host(s)"
        if isinstance(result, dict) else
        f"[CustomFileValidation] {label} model returned a non-dict result"
    )

    if not isinstance(result, dict) or not result.get("valid"):
        reason = (
            (result or {}).get("reason")
            or "This file does not appear to contain vulnerability scan data."
        )
        return {"valid": False, "reason": reason}

    hosts_raw = result.get("hosts") or []
    if not isinstance(hosts_raw, list) or not hosts_raw:
        return {
            "valid": False,
            "reason": "No vulnerability findings with asset, severity, and description could be identified in this file.",
        }

    vulnerabilities_by_host = []
    total_vulnerabilities = 0

    for h in hosts_raw:
        if not isinstance(h, dict):
            continue
        host_name = (h.get("host_name") or "").strip()
        vulns_raw = h.get("vulnerabilities") or []
        if not host_name or not isinstance(vulns_raw, list) or not vulns_raw:
            continue

        vulns = []
        for v in vulns_raw:
            if not isinstance(v, dict):
                continue
            plugin_name = (v.get("plugin_name") or "").strip()
            description = (v.get("description") or "").strip()
            # Real bug report: VaptFix's OWN downloadable report (and any
            # other condensed, table-only summary — name/asset/team/
            # severity/date/status columns, no free-text description per
            # row) never survived this — VALIDATION_PROMPT's own stated
            # bar for a valid finding is "a name OR description" (see its
            # point 2), but this required BOTH, so every finding in a
            # description-less table got silently dropped here, emptying
            # vulnerabilities_by_host and rejecting the whole file as "not
            # vulnerability scan data" even though it clearly was. Only
            # plugin_name is genuinely required — description empty is a
            # legitimate, if minimal, real finding.
            if not plugin_name:
                continue  # doesn't meet the minimum bar — drop this one finding, not the whole file
            risk_factor = (v.get("risk_factor") or "").strip().title()
            vulns.append({
                "plugin_id": None,
                "plugin_name": plugin_name,
                "synopsis": "",
                "description": description,
                "description_points": [description],
                "solution": (v.get("solution") or "").strip(),
                "see_also": [],
                "risk_factor": risk_factor,
                "cvss_v3_base_score": str(v.get("cvss_v3_base_score") or ""),
                "plugin_information": "",
                "plugin_output": "",
                "plugin_output_url": None,
            })

        if vulns:
            os_str = (h.get("operating_system") or "").strip()
            vulnerabilities_by_host.append({
                "host_name": host_name,
                "host_information": {"operating-system": os_str} if os_str else {},
                "vulnerabilities": vulns,
            })
            total_vulnerabilities += len(vulns)

    if not vulnerabilities_by_host:
        return {
            "valid": False,
            "reason": "No vulnerability findings with asset, severity, and description could be identified in this file.",
        }

    alias_map = _build_alias_map(result.get("host_aliases"))
    vulnerabilities_by_host = _apply_host_aliases(vulnerabilities_by_host, alias_map)
    total_vulnerabilities = sum(len(h["vulnerabilities"]) for h in vulnerabilities_by_host)

    # Real bug report: a host mentioned only in the document's own scope/
    # target list (e.g. "Scope of Assessment") but with zero findings
    # against it never appeared anywhere in "hosts" above (that array is
    # built purely from per-finding write-ups), so it was silently dropped
    # from vulnerabilities_by_host entirely — undercounting "Total Assets"
    # against the file's own stated scope (e.g. 24 scoped IPs, only 7 of
    # them counted, because only 7 had any finding). Nessus's own parser
    # already includes a scanned-but-clean host (see
    # parse_nessus_xml_streaming's ReportHost handling) — match that same
    # behavior here using the model's separate "all_assets" list, adding
    # any name not already covered by a finding as a clean (zero-
    # vulnerability) asset instead of leaving it out.
    covered_host_names = {h["host_name"].lower() for h in vulnerabilities_by_host}
    covered_host_normalized = {_normalize_host_token(h["host_name"]).lower() for h in vulnerabilities_by_host}
    all_assets_raw = result.get("all_assets") or []
    if isinstance(all_assets_raw, list):
        for asset_name in all_assets_raw:
            if not isinstance(asset_name, str):
                continue
            asset_name = asset_name.strip()
            if not asset_name:
                continue
            # Canonicalize through the same alias map — a scope-list entry
            # for an asset already covered by a real finding (just written
            # differently, e.g. the "ITEM" form when findings used the IP)
            # must not create a second, empty duplicate of it.
            asset_name = alias_map.get(asset_name.lower(), asset_name)
            if asset_name.lower() in covered_host_names:
                continue
            # Real bug report: a scope-list entry that's really just a
            # specific PAGE on an already-covered host (e.g. "https://
            # producers-demo.fgeninsurance.com/producers/sign_in" when
            # "producers-demo.fgeninsurance.com" already has real findings)
            # still got added as a second, empty "asset" — exact-string
            # dedup above only ever caught it when the two strings matched
            # exactly. Normalize to bare domain (strip scheme + path)
            # before the real dedup check.
            normalized = _normalize_host_token(asset_name).lower()
            if normalized in covered_host_normalized:
                continue
            covered_host_names.add(asset_name.lower())
            covered_host_normalized.add(normalized)
            vulnerabilities_by_host.append({
                "host_name": asset_name,
                "host_information": {},
                "vulnerabilities": [],
            })

    return {
        "valid": True,
        "reason": (result or {}).get("reason") or "",
        "vulnerabilities_by_host": vulnerabilities_by_host,
        "total_vulnerabilities": total_vulnerabilities,
        "alias_map": alias_map,
    }


def validate_and_extract_custom_report(parsed_data: Dict[str, Any], filename: str = "") -> Dict[str, Any]:
    """
    Validate an unrecognized ("custom") uploaded file and, if it genuinely
    contains vulnerability-scan data, extract it into the same
    vulnerabilities_by_host shape the Nessus/AWS parsers produce.

    Returns either:
        {"valid": False, "reason": "..."}
    or:
        {
            "valid": True,
            "type": "custom",
            "scan_info": {...},
            "total_hosts": N,
            "total_vulnerabilities": M,
            "vulnerabilities_by_host": [...]
        }

    CSV/Excel goes through _iter_row_chunks — one _validate_and_extract_chunk
    call per chunk, however many chunks a large file needs, then merged —
    so a file's row count no longer caps how much of it actually gets
    processed (see _iter_row_chunks' own docstring for the bug this fixes).
    PDF/DOCX/DOC/HTML stay single-shot (unchanged): those are prose, where
    a finding's own text can span far more context than one row, so
    splitting them the same mechanical way risks cutting a finding's
    write-up in half — MAX_INPUT_CHARS truncation (with the existing
    logged warning) is the safer tradeoff there.
    """
    report_type = parsed_data.get("type")

    if report_type in ("csv", "excel"):
        columns = parsed_data.get("columns") or []
        rows = parsed_data.get("preview") or []
        if not columns or not rows:
            return {"valid": False, "reason": "Could not extract any readable rows from this file."}

        chunks = list(_iter_row_chunks(columns, rows))
        logger.info(
            f"[CustomFileValidation] '{filename}' {len(rows)} row(s) split into "
            f"{len(chunks)} chunk(s) for extraction"
        )

        merged_hosts: Dict[str, Dict[str, Any]] = {}
        any_valid = False
        first_invalid_reason = None
        for idx, chunk_text in enumerate(chunks):
            chunk_result = _validate_and_extract_chunk(
                chunk_text, filename, chunk_label=f" (chunk {idx + 1}/{len(chunks)})"
            )
            if not chunk_result.get("valid"):
                if first_invalid_reason is None:
                    first_invalid_reason = chunk_result.get("reason")
                continue
            any_valid = True
            for h in chunk_result.get("vulnerabilities_by_host") or []:
                host_name = h.get("host_name")
                if not host_name:
                    continue
                existing = merged_hosts.get(host_name)
                if existing:
                    existing["vulnerabilities"].extend(h.get("vulnerabilities") or [])
                    if not existing.get("host_information") and h.get("host_information"):
                        existing["host_information"] = h["host_information"]
                else:
                    merged_hosts[host_name] = {
                        "host_name": host_name,
                        "host_information": h.get("host_information") or {},
                        "vulnerabilities": list(h.get("vulnerabilities") or []),
                    }

        if not any_valid or not merged_hosts:
            return {
                "valid": False,
                "reason": first_invalid_reason
                or "No vulnerability findings with asset, severity, and description could be identified in this file.",
            }

        vulnerabilities_by_host = list(merged_hosts.values())
        total_vulnerabilities = sum(len(h["vulnerabilities"]) for h in vulnerabilities_by_host)
        return {
            "valid": True,
            "type": "custom",
            "scan_info": {"source": "Custom file", "validated_by": "gpt-4o-mini"},
            "total_hosts": len(vulnerabilities_by_host),
            "total_vulnerabilities": total_vulnerabilities,
            "vulnerabilities_by_host": vulnerabilities_by_host,
        }

    # Prose documents (pdf/docx/doc/html) — unchanged single-shot path.
    document_text = (_extract_document_text(parsed_data) or "").strip()

    if not document_text:
        return {"valid": False, "reason": "Could not extract any readable text from this file."}

    truncated = document_text[:MAX_INPUT_CHARS]
    # Always visible — not just on truncation — so a run that comes back
    # with fewer hosts than expected can be diagnosed from the logs alone:
    # was the input text short to begin with (an extraction-quality problem
    # in parsers.py, e.g. PyPDF2 missing text on some pages) or did it get
    # cut off here.
    logger.info(
        f"[CustomFileValidation] '{filename}' extracted text length={len(document_text)} chars "
        f"(sending {len(truncated)} chars to the model)"
    )
    if len(document_text) > MAX_INPUT_CHARS:
        # Confirmed real: this silently dropping data (some hosts/findings
        # past the cutoff never reaching the model at all) is exactly what
        # made a 13-host report save with only 2 — now at least visible in
        # the logs instead of looking like a clean, complete extraction.
        logger.warning(
            f"[CustomFileValidation] '{filename}' text is {len(document_text)} chars, "
            f"truncated to {MAX_INPUT_CHARS} before sending to the model — some "
            f"findings past this point may not be extracted."
        )

    chunk_result = _validate_and_extract_chunk(truncated, filename)
    if not chunk_result.get("valid"):
        return chunk_result

    vulnerabilities_by_host = chunk_result.get("vulnerabilities_by_host") or []
    # Combine the model's own self-reported aliases with the deterministic
    # regex pre-scan into one consistent grouping (see
    # _resolve_alias_groups's own docstring for why a naive merge isn't
    # enough here).
    alias_map = _resolve_alias_groups(chunk_result.get("alias_map") or {}, _extract_ip_hostname_aliases(truncated))
    vulnerabilities_by_host = _apply_host_aliases(vulnerabilities_by_host, alias_map)
    vulnerabilities_by_host = _merge_by_normalized_domain(vulnerabilities_by_host)

    # Real bug report: a single extraction pass over a long prose document
    # can silently skip a genuine finding — confirmed on a real PDF (7
    # findings per the document's own stated total, only 6 extracted). A
    # single follow-up pass helps but isn't reliable enough on its own —
    # confirmed on a real report where a SECOND independent extraction
    # attempt (re-running this whole function from scratch) came back with
    # LESS coverage than the first, not more (6 hosts' worth of findings
    # that the first run found cleanly went missing the second time). LLM
    # recall genuinely varies run to run; one retry is not a fix.
    #
    # Guardrail: when the document states its own total finding count (see
    # _extract_stated_total), keep running the same "what's missing" recall
    # pass — each one only asking about whatever's STILL not covered —
    # until the extracted total reaches that stated number or a retry cap
    # is hit. Every retry is strictly additive (see _merge_missed_findings),
    # so this can only recover findings, never lose ones already found.
    stated_total = _extract_stated_total(truncated)
    max_recall_attempts = 3
    for attempt in range(1, max_recall_attempts + 1):
        missed_hosts = _find_missed_findings(truncated, filename, vulnerabilities_by_host)
        # Canonicalize the recall pass's own host names through the SAME
        # alias map before merging — it's a fresh, independent LLM call, so
        # nothing stops it from writing an asset in yet another form (e.g.
        # the IP where an earlier pass settled on the hostname).
        for h in missed_hosts or []:
            if isinstance(h, dict) and h.get("host_name"):
                h["host_name"] = alias_map.get(h["host_name"].strip().lower(), h["host_name"])
        added_before = sum(len(h.get("vulnerabilities") or []) for h in vulnerabilities_by_host)
        _merge_missed_findings(vulnerabilities_by_host, missed_hosts, filename)
        vulnerabilities_by_host = _apply_host_aliases(vulnerabilities_by_host, alias_map)
        # Safety net beyond the fixed alias_map — see its own docstring.
        vulnerabilities_by_host = _merge_by_normalized_domain(vulnerabilities_by_host)
        added_after = sum(len(h.get("vulnerabilities") or []) for h in vulnerabilities_by_host)

        if stated_total is None:
            break  # no ground truth to check against — one pass is all we do
        if added_after >= stated_total:
            break
        if added_after == added_before:
            # This pass found nothing new — another identical retry is
            # unlikely to either; stop rather than spend more calls for
            # nothing.
            logger.warning(
                f"[CustomFileValidation] '{filename}' still short of the document's "
                f"stated total ({added_after}/{stated_total}) after attempt {attempt}, "
                f"but this pass found nothing new — stopping retries."
            )
            break
        if attempt == max_recall_attempts:
            logger.warning(
                f"[CustomFileValidation] '{filename}' still short of the document's "
                f"stated total ({added_after}/{stated_total}) after {max_recall_attempts} "
                f"recall attempts — giving up, storing what was found."
            )

    return {
        "valid": True,
        "type": "custom",
        "scan_info": {"source": "Custom file", "validated_by": "gpt-4o-mini"},
        "total_hosts": len(vulnerabilities_by_host),
        "total_vulnerabilities": sum(len(h.get("vulnerabilities") or []) for h in vulnerabilities_by_host),
        "vulnerabilities_by_host": vulnerabilities_by_host,
    }
