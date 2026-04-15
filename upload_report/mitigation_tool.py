import re
import json
import logging
import datetime

from django.conf import settings

logger = logging.getLogger(__name__)

MODEL_NAME = "gpt-4o"


def _get_openai_client():
    """Lazily instantiate the OpenAI client using the key from settings."""
    try:
        import openai
    except ImportError:
        raise ImportError(
            "openai package is not installed. Run: pip install openai>=1.0.0"
        )

    api_key = getattr(settings, "OPENAI_API_KEY", None)
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not configured in Django settings.")

    return openai.OpenAI(api_key=api_key)


def _detect_os(operating_system: str) -> str:
    """Return 'linux' if OS string indicates Linux, else 'windows'."""
    if operating_system and "linux" in operating_system.lower():
        return "linux"
    return "windows"


def _build_prompt(
    plugin_name: str,
    description: str,
    plugin_output: str = "",
    host_name: str = "",
    operating_system: str = "",
) -> str:
    """Build the full 3-task prompt sent to OpenAI."""

    host_line = f"\n- **Affected Host (use as resource_id):** {host_name.strip()}" if host_name and host_name.strip() else ""
    os_label = _detect_os(operating_system)
    os_display = "Linux" if os_label == "linux" else "Windows"
    os_line = f"\n- **Operating System:** {operating_system.strip()}" if operating_system and operating_system.strip() else f"\n- **Operating System:** Windows (default)"

    plugin_output_section = ""
    if plugin_output and plugin_output.strip():
        plugin_output_section = f"\n- **Plugin Output (scan result):**\n{plugin_output.strip()}\n"

    intro = f"""You are a cybersecurity remediation expert with deep technical knowledge.

## Vulnerability Information
- **Vulnerability Name:** {plugin_name}{host_line}{os_line}
- **Description:**
{description}{plugin_output_section}

CRITICAL GUIDELINES:
- Do NOT follow a generic or template-based plan.
- Carefully analyze the **root cause** of this vulnerability and build a **vulnerability-specific** set of mitigation steps and actions.
- Include ONLY relevant, actionable steps tailored to this vulnerability.
- Use the Plugin Output above (if provided) to make commands and steps more specific to the actual scan findings.
- For the JSON card: set resource_id = the Affected Host value above (e.g. IP address or hostname). For region, derive it from the host IP subnet or network zone if identifiable; otherwise null.
- For assigned_team: choose EXACTLY ONE of these four options based on the vulnerability category:
  * "Patch Management" — for missing patches, outdated software versions, CVEs with vendor fixes
  * "Configuration Management" — for misconfigured services, weak settings, insecure defaults
  * "Network Security" — for SSL/TLS issues, open ports, firewall rules, network protocols
  * "Architectural Flaws" — for design-level weaknesses, structural issues, authentication/authorization flaws
"""

    os_table_instruction = (
        f"- Each step must target **{os_display}** systems ONLY. Do NOT include steps for the other OS.\n"
        f"- The 'Operating System' column in every row must be set to **{os_display}**."
    )

    tasks = f"""
---

## TASK 1 — MITIGATION TABLE

Provide a highly detailed, step-by-step mitigation table with the following rules:
{os_table_instruction}
- Include ALL steps required to fully remediate this specific vulnerability. Do not pad with unnecessary steps.
- Each "Commands for Action" cell must contain copy-paste-ready, production-quality commands with full paths and parameters.
- For code vulnerabilities: provide exact code snippets, before/after examples, regex patterns.
- For config vulnerabilities: provide complete config file content, backup/rollback commands.
- For network/SSL: provide exact cipher suite configs, certificate generation commands.

| Step No | Step Name | Action | Operating System | System File/Path | Responsible Party | Artifacts/Tools Used | Commands for Action | Criticality | Precautions | Verification Steps | Effort Estimate | Patch Available | Fallback Remediation | Reference Links | Applicable Platforms | Remediation Timeline |
|---------|-----------|--------|-----------------|------------------|-------------------|----------------------|---------------------|-------------|-------------|-------------------|-----------------|-----------------|-----------------------|----------------|---------------------|---------------------|

---

## TASK 2 — VULNERABILITY CARD (JSON)

After the table, output a JSON block with the following structure inside a ```json code fence.
Use ONLY what can be determined from the vulnerability information above.
For fields that cannot be determined, use null.

```json
{{
  "resource_id": "<use the Affected Host IP/hostname from above — do NOT leave null if host is provided>",
  "region": "<network subnet or zone derived from host IP, e.g. '192.168.1.x subnet' or null if not determinable>",
  "affected_packages": "<comma-separated list of affected software/packages>",
  "vendor_advisory": "<official vendor advisory URL or null>",
  "reference_url": "<primary reference URL — CVE, NVD, or vendor>",
  "vulnerability_type": "<e.g. Remote Code Execution, Information Disclosure, DoS>",
  "affected_port_ranges": "<e.g. 443, 80, 0-1024, or null if not applicable>",
  "assigned_team": "<must be exactly one of: Patch Management | Configuration Management | Network Security | Architectural Flaws>",
  "vendor_fix_available": "Yes or No",
  "steps_to_fix_count": <integer — total number of logical steps in your table above>,
  "steps_to_fix_description": "<1-2 sentence summary of the overall remediation approach>",
  "deadline": "<recommended deadline — e.g. 24 hours for Critical, 7 days for High, 30 days for Medium, 90 days for Low>",
  "artifacts_tools": "<comma-separated list of tools required>",
  "post_mitigation_troubleshooting_guide": "<3-5 numbered steps to verify the fix and handle common post-fix issues>"
}}
```

---

## TASK 3 — CONTEXTUAL ANALYSIS

Below the JSON block, provide:
1. Brief technical description of the vulnerability's root cause
2. Affected systems, versions, and components
3. Potential impact and attack scenarios
4. How the mitigation steps address the root cause
5. Common implementation pitfalls to avoid
6. Testing procedures to verify the fix is effective
"""

    return intro + tasks


def _extract_json_fallback(json_str: str) -> dict:
    """
    Last-resort field extraction when json.loads fails.
    Extracts known field values using per-field regex.
    """
    fields = [
        "resource_id", "region", "affected_packages", "vendor_advisory",
        "reference_url", "vulnerability_type", "affected_port_ranges",
        "assigned_team", "vendor_fix_available",
        "steps_to_fix_description", "deadline",
        "artifacts_tools", "post_mitigation_troubleshooting_guide",
    ]
    extracted = {}
    for field in fields:
        m = re.search(rf'"{field}"\s*:\s*"([^"]*)"', json_str)
        if m:
            extracted[field] = m.group(1)
        else:
            m_null = re.search(rf'"{field}"\s*:\s*(null)', json_str)
            if m_null:
                extracted[field] = None

    # steps_to_fix_count is an integer
    m_count = re.search(r'"steps_to_fix_count"\s*:\s*(\d+)', json_str)
    if m_count:
        extracted["steps_to_fix_count"] = int(m_count.group(1))

    return extracted


def _parse_markdown_table(table_str: str) -> list:
    """
    Parse a markdown table string into a list of dicts.
    Each data row becomes one dict with column names as keys.

    Column names are normalised to snake_case (lowercase, spaces → underscores).

    Returns an empty list if the table cannot be parsed.
    """
    if not table_str:
        return []

    lines = [ln for ln in table_str.splitlines() if ln.strip()]

    # Find header row — first line that starts with '|'
    header_line = None
    header_idx = 0
    for i, ln in enumerate(lines):
        if ln.strip().startswith("|"):
            header_line = ln
            header_idx = i
            break

    if not header_line:
        return []

    # Parse column names from header
    raw_headers = [h.strip() for h in header_line.split("|") if h.strip()]
    # Normalise to snake_case keys
    columns = [
        re.sub(r"\s+", "_", h.strip().lower())
          .replace("/", "_")
          .replace("-", "_")
          .replace("(", "")
          .replace(")", "")
        for h in raw_headers
    ]

    rows = []
    for ln in lines[header_idx + 1:]:
        stripped = ln.strip()
        if not stripped.startswith("|"):
            continue
        # Skip separator rows like |---|---|
        if re.match(r"^\|[-| :]+\|$", stripped):
            continue

        cells = [c.strip() for c in stripped.split("|")]
        # Remove empty strings from leading/trailing '|'
        cells = [c for c in cells if c != ""] if cells[0] == "" else cells
        # Ensure cell count matches columns
        if len(cells) < len(columns):
            cells += [""] * (len(columns) - len(cells))

        row = {columns[i]: cells[i] for i in range(len(columns))}
        row["sub_tasks"] = _parse_action_sub_tasks(row.get("action", ""))
        rows.append(row)

    return rows


def _parse_contextual_analysis(text: str) -> list:
    """
    Parse the contextual analysis freetext into a list of section objects.

    Each numbered section becomes:
    {
        "section_number": "1",
        "heading": "Brief technical description ...",
        "content": "The vulnerability arises from ..."
    }

    Lines that don't belong to a numbered section are grouped under
    section_number "0" with heading "General".
    """
    if not text:
        return []

    sections = []
    current = None

    # Match lines like "1.", "1. **Heading**", "1. Heading"
    section_start = re.compile(r"^\s*(\d+)\.\s*\*{0,2}(.+?)\*{0,2}\s*:?\s*$")

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        m = section_start.match(stripped)
        if m:
            if current:
                sections.append(current)
            current = {
                "section_number": m.group(1),
                "heading": m.group(2).strip().strip("*").strip(),
                "content": "",
            }
        else:
            if current is None:
                # Header lines before first numbered section
                current = {"section_number": "0", "heading": "General", "content": ""}
            content_line = stripped.lstrip("-").strip()
            if content_line:
                current["content"] = (
                    (current["content"] + " " + content_line).strip()
                )

    if current:
        sections.append(current)

    return sections


def _parse_troubleshooting_guide(text: str) -> list:
    """
    Parse the post_mitigation_troubleshooting_guide string into step objects.

    Input: "1. Run openssl s_client ... 2. Check browser padlock ... 3. Verify TLS ..."

    Output:
      [
        {"step_number": "1", "action": "Run openssl s_client ..."},
        {"step_number": "2", "action": "Check browser padlock ..."},
      ]
    """
    if not text:
        return []

    steps = []
    parts = re.split(r"(?<!\d)(\d+)\.\s+", text.strip())
    # parts alternates: [pre_text, num, content, num, content, ...]
    i = 1
    while i < len(parts) - 1:
        step_num = parts[i].strip()
        action = parts[i + 1].strip()
        if action:
            steps.append({"step_number": step_num, "action": action})
        i += 2

    if not steps and text.strip():
        steps.append({"step_number": "1", "action": text.strip()})

    return steps


def _parse_action_sub_tasks(action_text: str) -> list:
    """
    Parse numbered items in an action field into sub_tasks.

    Input:
        "1. Open the vulnerable file...\n2. Search for functions:\n- PHP: exec()\n- Python: os.system()\n3. Identify..."

    Output:
        [
            {"number": "1", "description": "Open the vulnerable file...", "items": []},
            {"number": "2", "description": "Search for functions:", "items": ["PHP: exec()", "Python: os.system()"]},
            {"number": "3", "description": "Identify...", "items": []}
        ]
    """
    if not action_text:
        return []

    sub_tasks = []
    current = None

    for line in action_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        m = re.match(r'^(\d+)\.\s+(.+)', stripped)
        if m:
            if current:
                sub_tasks.append(current)
            current = {
                "number": m.group(1),
                "description": m.group(2).strip(),
                "items": [],
            }
        elif stripped.startswith('-') and current is not None:
            item_text = stripped.lstrip('-').strip()
            if item_text:
                current["items"].append(item_text)
        elif current is not None:
            # continuation line of current description
            current["description"] += " " + stripped

    if current:
        sub_tasks.append(current)

    # If no numbered items found but text exists, treat whole text as single sub_task
    if not sub_tasks and action_text.strip():
        sub_tasks.append({
            "number": "1",
            "description": action_text.strip(),
            "items": [],
        })

    return sub_tasks


def _parse_raw_response_sections(raw_text: str) -> list:
    """
    Parse the full raw AI response into a list of section objects.

    Each ## TASK section becomes:
    {
        "section_number": "1",
        "section_title": "MITIGATION TABLE",
        "content": ["line1", "line2", ...]
    }
    Lines before the first section are grouped under section_number "0".
    """
    if not raw_text:
        return []

    task_pattern = re.compile(
        r"##\s*TASK\s*(\d+)\s*[—\-–]?\s*(.*)", re.IGNORECASE
    )

    sections = []
    current = {"section_number": "0", "section_title": "Header", "content": []}

    for line in raw_text.splitlines():
        m = task_pattern.match(line.strip())
        if m:
            if current["content"] or current["section_number"] != "0":
                sections.append(current)
            current = {
                "section_number": m.group(1).strip(),
                "section_title": m.group(2).strip().strip("—-–").strip(),
                "content": [],
            }
        else:
            if line.strip():
                current["content"].append(line.rstrip())

    if current["content"]:
        sections.append(current)

    return sections


def _parse_response(raw_text: str) -> dict:
    """
    Parse the raw OpenAI response into three components:
      - mitigation_table: list of dicts (one per table row, keys = column names)
      - vulnerability_card: the parsed JSON dict
      - contextual_analysis: the freeform text section after the JSON block
    """
    result = {
        "mitigation_table": [],
        "vulnerability_card": {},
        "contextual_analysis": [],
        "raw_response_sections": [],
    }

    # --- Extract JSON block (```json ... ```) ---
    json_match = re.search(
        r"```json\s*(\{.*?\})\s*```",
        raw_text,
        re.DOTALL | re.IGNORECASE,
    )
    json_end_pos = 0
    if json_match:
        json_str = json_match.group(1).strip()
        json_end_pos = json_match.end()
        try:
            result["vulnerability_card"] = json.loads(json_str)
        except json.JSONDecodeError as exc:
            logger.warning(f"JSON parse failed ({exc}). Attempting fallback extraction.")
            result["vulnerability_card"] = _extract_json_fallback(json_str)
    else:
        # Try bare JSON object containing a known field
        bare = re.search(
            r'\{[^{}]*"vendor_fix_available"[^{}]*\}', raw_text, re.DOTALL
        )
        if bare:
            json_end_pos = bare.end()
            try:
                result["vulnerability_card"] = json.loads(bare.group(0))
            except json.JSONDecodeError:
                result["vulnerability_card"] = _extract_json_fallback(bare.group(0))

    # --- Extract and parse Mitigation Table ---
    table_match = re.search(
        r"(\|[ \t]*Step No.*?)(?=```json|\Z)",
        raw_text,
        re.DOTALL | re.IGNORECASE,
    )
    if table_match:
        result["mitigation_table"] = _parse_markdown_table(table_match.group(1).strip())

    # --- Extract and parse Contextual Analysis ---
    raw_contextual = ""
    if json_end_pos:
        raw_contextual = raw_text[json_end_pos:].strip()
    else:
        ctx_match = re.search(
            r"(##\s*TASK\s*3|##\s*Contextual|\*\*Contextual)",
            raw_text,
            re.IGNORECASE,
        )
        if ctx_match:
            raw_contextual = raw_text[ctx_match.start():].strip()

    result["contextual_analysis"] = _parse_contextual_analysis(raw_contextual)
    result["raw_response_sections"] = _parse_raw_response_sections(raw_text)

    return result


class MitigationGenerationTool:
    """
    Generates detailed vulnerability mitigation plans and structured
    Vulnerability Card data using the OpenAI chat completions API.
    """

    def _run(
        self,
        plugin_name: str,
        description: str,
        plugin_output: str = "",
        report_id: str = "",
        host_name: str = "",
        operating_system: str = "",
    ) -> dict:
        """
        Execute the mitigation generation.

        Returns a dict with keys:
            success, vulnerability_name, description, plugin_output, report_id,
            mitigation_table, vulnerability_card, contextual_analysis,
            raw_response, generated_at, error
        """
        base = {
            "vulnerability_name": plugin_name,
            "description": description,
            "plugin_output": plugin_output or None,
            "report_id": report_id or None,
            "generated_at": datetime.datetime.utcnow().isoformat(),
        }

        try:
            client = _get_openai_client()
            prompt = _build_prompt(plugin_name, description, plugin_output, host_name, operating_system)

            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity remediation assistant helping IT teams fix vulnerabilities in their systems. "
                            "Always follow the exact output format requested, "
                            "including the markdown table and the JSON block."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=4000,
            )

            raw_text = response.choices[0].message.content.strip()
            parsed = _parse_response(raw_text)

            return {
                **base,
                "success": True,
                "mitigation_table": parsed["mitigation_table"],
                "vulnerability_card": parsed["vulnerability_card"],
                "contextual_analysis": parsed["contextual_analysis"],
                "raw_response_sections": parsed["raw_response_sections"],
                "error": None,
            }

        except Exception as exc:
            logger.error(f"MitigationGenerationTool error: {exc}", exc_info=True)
            return {
                **base,
                "success": False,
                "mitigation_table": [],
                "vulnerability_card": {},
                "contextual_analysis": [],
                "raw_response_sections": [],
                "error": str(exc),
            }
