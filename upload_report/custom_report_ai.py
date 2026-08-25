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
from typing import Any, Dict

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
  1. An asset/host identifier (IP, hostname, URL, ARN, server/application name — anything that
     identifies WHAT was tested)
  2. A vulnerability/finding name or description (WHAT is wrong)
  3. A severity or risk indicator (Critical/High/Medium/Low/Info, a CVSS score, or equivalent)

If the file is NOT a vulnerability/security report (e.g. an invoice, resume, contract, empty or
unrelated document, or a document with no actual findings), mark it invalid and explain why in one
sentence.

Never invent findings that are not clearly present in the text. If a field is not stated, leave it "".

IMPORTANT — one finding can affect many hosts. Pentest reports are often organized by FINDING
(one write-up per vulnerability), not by host, and that write-up may list several affected
assets together — e.g. under a heading like "Affected Host(s)", "Affected IP(s)", "Affected
URL(s)", "Affected Asset(s)", or as a bullet/comma list in the finding's own text. When a single
finding lists multiple affected hosts, you MUST create a separate entry for that same
vulnerability (same plugin_name/description/risk_factor/solution) under EACH one of those hosts
in the "hosts" array — do not collapse them into just one representative host and do not drop
any of the listed hosts. A report with 3 distinct findings where one of them lists 12 affected
hosts should produce far more than 3 total host/vulnerability entries.

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
  ]
}}

If invalid, "hosts" must be an empty list.

DOCUMENT TEXT:
---
{document_text}
---
"""


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
    return ChatOpenAI(model=model, temperature=0, api_key=api_key, max_tokens=16384)


def _extract_document_text(parsed_data: Dict[str, Any]) -> str:
    """Pull the best available raw text out of whatever the generic parsers produced."""
    report_type = parsed_data.get("type")

    if report_type in ("pdf", "docx", "doc"):
        return parsed_data.get("text_full") or parsed_data.get("text_preview") or ""

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
    """
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

    try:
        llm = _get_validation_llm()
        prompt = VALIDATION_PROMPT.format(document_text=truncated)
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
                f"[CustomFileValidation] '{filename}' LLM response finish_reason="
                f"'{finish_reason}' (not 'stop') — output may be truncated, "
                f"raw response length={len(raw_content)} chars"
            )
    except Exception as exc:
        logger.error(f"[CustomFileValidation] LLM call failed for '{filename}': {exc}")
        return {"valid": False, "reason": "Could not validate this file right now — please try again."}

    try:
        cleaned = _strip_json_fences(raw_content)
        result = json.loads(cleaned)
    except Exception as exc:
        logger.error(
            f"[CustomFileValidation] Could not parse LLM response for '{filename}': {exc} "
            f"— raw response length={len(raw_content)} chars, tail={raw_content[-200:]!r}"
        )
        return {"valid": False, "reason": "Could not validate this file's contents — please try again."}

    logger.info(
        f"[CustomFileValidation] '{filename}' model returned {len(result.get('hosts') or [])} host(s)"
        if isinstance(result, dict) else
        f"[CustomFileValidation] '{filename}' model returned a non-dict result"
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
            if not plugin_name or not description:
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

    return {
        "valid": True,
        "type": "custom",
        "scan_info": {"source": "Custom file", "validated_by": "gpt-4o-mini"},
        "total_hosts": len(vulnerabilities_by_host),
        "total_vulnerabilities": total_vulnerabilities,
        "vulnerabilities_by_host": vulnerabilities_by_host,
    }
