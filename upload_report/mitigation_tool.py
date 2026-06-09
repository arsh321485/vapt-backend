import os
import re
import json
import logging
import datetime

# Suppress CrewAI's interactive "Would you like to view your execution traces?" prompt
# CREWAI_TESTING=true makes _is_test_environment() return True, which bypasses the 20s blocking prompt
os.environ.setdefault("CREWAI_TESTING", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")

from django.conf import settings

logger = logging.getLogger(__name__)


def _get_crewai_llm():
    """Return a LangChain ChatOpenAI LLM using the project's OPENAI_API_KEY."""
    try:
        from langchain_openai import ChatOpenAI
    except ImportError:
        raise ImportError(
            "langchain-openai is not installed. Run: pip install langchain-openai>=0.2.0"
        )

    api_key = getattr(settings, "OPENAI_API_KEY", None)
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not configured in Django settings.")

    model = getattr(settings, "OPENAI_MODEL", "gpt-4o-mini")
    return ChatOpenAI(model=model, temperature=0.3, api_key=api_key)


def _detect_os(operating_system: str) -> str:
    """Return OS category: linux, windows, macos, android, ios."""
    os_lower = (operating_system or "").lower()
    if any(k in os_lower for k in ("linux", "ubuntu", "debian", "centos", "rhel", "fedora", "kali", "red hat")):
        return "linux"
    if any(k in os_lower for k in ("mac", "macos", "osx", "darwin")):
        return "macos"
    if "android" in os_lower:
        return "android"
    if any(k in os_lower for k in ("ios", "iphone", "ipad", "ipados")):
        return "ios"
    return "windows"


_VALID_TEAMS = {
    "network-security",
    "patch-management",
    "architectural-flaws",
    "configuration-management",
}

_TEAM_KEYWORDS = {
    # Check patch-management FIRST — unpatched/CVE takes priority over technology keywords
    "patch-management": [
        "missing patch", "missing patches", "unpatched", "outdated",
        "end of life", "eol", "kernel", "cve-", "upgrade", "obsolete",
        "out of date", "security update", "hotfix", "service pack",
        "out-of-date", "needs update", "vulnerable version", "patches",
    ],
    "architectural-flaws": [
        "default credential", "default credentials", "credential",
        "default password", "weak password", "weak credential",
        "authentication bypass", "privilege escalation", "broken auth",
        "insecure design", "access control", "authorization", "default login",
        "hardcoded", "no authentication", "improper authentication",
    ],
    "network-security": [
        "ssl/tls", "weak cipher", "rc4", "3des", "tls 1.0", "tls 1.1",
        "open port", "telnet", "ftp ", "snmp", "firewall", "port scan",
        "smb", "rdp", "exposed service", "unnecessary service",
        "cipher suite", "ssl cipher", "tls cipher",
    ],
    "configuration-management": [
        "misconfigur", "missing header", "security header",
        "hsts", "csp", "x-frame", "cors", "default setting",
        "permission", "directory listing", "information disclosure",
        "banner", "version disclosure", "debug mode",
    ],
}


def _resolve_assigned_team(vuln_name: str, vuln_card: dict) -> str:
    """
    Ensure assigned_team is one of the 4 valid slugs.
    If LLM returned an invalid value, infer from vulnerability name.
    """
    raw = (vuln_card.get("assigned_team") or "").strip().lower().replace(" ", "-")
    if raw in _VALID_TEAMS:
        return raw

    combined = (vuln_name + " " + (vuln_card.get("vulnerability_type") or "")).lower()
    for team, keywords in _TEAM_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            return team

    return "configuration-management"  # safe default


_TEAM_DISPLAY_NAMES = {
    "network-security":         "Network Security",
    "patch-management":         "Patch Management",
    "architectural-flaws":      "Architectural Flaws",
    "configuration-management": "Configuration Management",
}


def _team_display_name(slug: str) -> str:
    """Convert team slug to Title Case display name."""
    return _TEAM_DISPLAY_NAMES.get(slug, slug.replace("-", " ").title())


def _extract_json_fallback(json_str: str) -> dict:
    """Last-resort field extraction when json.loads fails."""
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

    m_count = re.search(r'"steps_to_fix_count"\s*:\s*(\d+)', json_str)
    if m_count:
        extracted["steps_to_fix_count"] = int(m_count.group(1))

    return extracted


def _parse_markdown_table(table_str: str) -> list:
    """
    Parse a markdown table string into a list of dicts.
    Column names are normalised to snake_case.
    """
    if not table_str:
        return []

    lines = [ln for ln in table_str.splitlines() if ln.strip()]

    header_line = None
    header_idx = 0
    for i, ln in enumerate(lines):
        if ln.strip().startswith("|"):
            header_line = ln
            header_idx = i
            break

    if not header_line:
        return []

    raw_headers = [h.strip() for h in header_line.split("|") if h.strip()]
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
        if re.match(r"^\|[-| :]+\|$", stripped):
            continue

        cells = [c.strip() for c in stripped.split("|")]
        cells = [c for c in cells if c != ""] if cells[0] == "" else cells
        if len(cells) < len(columns):
            cells += [""] * (len(columns) - len(cells))

        row = {columns[i]: cells[i] for i in range(len(columns))}
        row["sub_tasks"] = _parse_action_sub_tasks(row.get("action", ""))
        where_to_run = _infer_where_to_run(
            row.get("commands_for_action", ""),
            row.get("system_file_path", ""),
            row.get("operating_system", ""),
        )
        row["where_to_run"] = where_to_run
        row["where_to_run_label"] = _where_to_run_label(where_to_run)
        row = _ensure_execution_guidance_fields(row)
        row["command_blocks"] = _parse_command_blocks(
            row.get("commands_for_action", ""),
            row.get("system_file_path", ""),
            row.get("step_no", ""),
            row.get("task_name", ""),
        )
        raw_tools = row.get("artifacts_tools_used", "")
        if isinstance(raw_tools, str):
            row["artifacts_tools_used"] = [t.strip() for t in raw_tools.split(",") if t.strip()]
        rows.append(row)

    return rows


def _parse_contextual_analysis(text: str) -> list:
    """Parse numbered contextual analysis sections into a list of section objects."""
    if not text:
        return []

    sections = []
    current = None

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
    """Parse post_mitigation_troubleshooting_guide string into step objects."""
    if not text:
        return []

    steps = []
    parts = re.split(r"(?<!\d)(\d+)\.\s+", text.strip())
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
    """Parse numbered items in an action field into sub_tasks."""
    if not action_text:
        return []

    action_text = re.sub(r'<br\s*/?>', '\n', action_text, flags=re.IGNORECASE)

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
            current["description"] += " " + stripped

    if current:
        sub_tasks.append(current)

    if not sub_tasks and action_text.strip():
        sub_tasks.append({
            "number": "1",
            "description": action_text.strip(),
            "items": [],
        })

    return sub_tasks


def _infer_where_to_run(commands_for_action: str, system_file_path: str = "", operating_system: str = "") -> str:
    """Infer execution context for frontend display."""
    cmd = (commands_for_action or "").strip().lower()
    path = (system_file_path or "").strip().lower()
    os_label = (operating_system or "").strip().lower()

    if not cmd:
        return "not_applicable"

    sql_keywords = ("select ", "update ", "insert ", "delete ", "create table", "alter table", "drop table")
    if any(k in cmd for k in sql_keywords):
        return "sql_console"

    browser_hints = ("http://", "https://", "open browser", "navigate to", "web console")
    if any(k in cmd for k in browser_hints):
        return "browser"

    ui_hints = ("click ", "go to settings", "open control panel", "open services.msc", "group policy")
    if any(k in cmd for k in ui_hints):
        return "application_ui"

    powershell_hints = ("get-", "set-", "new-", "remove-", "restart-service", "powershell", "ps1")
    if any(k in cmd for k in powershell_hints):
        return "powershell"

    cmd_hints = ("cmd.exe", "sc.exe", "net start", "net stop", "copy ", "xcopy ")
    if any(k in cmd for k in cmd_hints):
        return "cmd"

    bash_hints = ("apt ", "yum ", "dnf ", "systemctl ", "chmod ", "chown ", "grep ", "sed ", "awk ", "sudo ")
    if any(k in cmd for k in bash_hints):
        return "bash"

    if os_label == "windows" or "c:\\" in path:
        return "terminal"
    if os_label == "linux" or path.startswith("/"):
        return "terminal"

    return "terminal"


def _where_to_run_label(where_to_run: str) -> str:
    labels = {
        "powershell": "PowerShell (Windows — press Win+X, then click PowerShell)",
        "cmd": "Command Prompt (Windows — press Win+R, type cmd, press Enter)",
        "bash": "Terminal / Bash (Linux or Mac — open Terminal app)",
        "terminal": "Terminal / Command Prompt (open the terminal on your system)",
        "sql_console": "SQL Console (open your database client, e.g. MySQL Workbench or phpMyAdmin)",
        "browser": "Web Browser (open Chrome, Firefox, or Edge)",
        "application_ui": "Application Settings (open the application and go to Settings)",
        "not_applicable": "No command needed — follow the steps in the Action column",
    }
    return labels.get(where_to_run, "Terminal / Command Prompt (open the terminal on your system)")


def _detect_service_label(command_line: str) -> str:
    """
    Detect which service/file path a single command line targets.
    Returns a label string, or empty string if no match.
    """
    line = command_line  # keep original case for regex matching

    if re.search(r'(?i)apache24|apache2\.4|\\apache\\|\\apache24\\|\\Apache24\\|httpd-ssl|mod_ssl', line):
        return 'Apache'
    if re.search(r'(?i)/etc/apache2/|apache2\.conf|httpd\.conf|apachectl', line):
        return 'Apache'
    if re.search(r'(?i)\\nginx\\|/etc/nginx/|nginx\.conf', line):
        return 'Nginx'
    if re.search(r'(?i)\bnginx\b(?!\s+-t)', line):   # 'nginx' as a path/service, not 'nginx -t' (that's verify)
        return 'Nginx'
    if re.search(r'(?i)iisreset|W3SVC|Get-WebConfiguration|system\.webServer|inetpub|applicationHost', line):
        return 'IIS'
    if re.search(r'(?i)SCHANNEL|SecurityProviders.*SCHANNEL|TLS\s+1\.[012].*\\\\Server|HKLM.*Protocols', line):
        return 'Windows Registry (Schannel)'
    if re.search(r'(?i)HKLM[:\\/].*(?:TLS|SSL|Cipher|Schannel)', line):
        return 'Windows Registry (Schannel)'
    if re.search(r'(?i)/etc/ssh/|sshd_config', line):
        return 'SSH'
    if re.search(r'(?i)letsencrypt|certbot|/etc/ssl/certs', line):
        return 'SSL Certificate'
    if re.search(r'(?i)\bufw\b|firewall-cmd|New-NetFirewallRule', line):
        return 'Firewall'

    return ''


def _smart_split_commands(commands_str: str) -> list:
    """
    When no labeled # ── blocks exist, detect service/path labels per command
    line and group consecutive commands with the same label.
    Returns list of (label, commands_block) tuples, or [] if only one label found.
    """
    lines = commands_str.splitlines()

    # Label each line: (original_line, detected_label or None)
    line_labels = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('```'):
            line_labels.append((line, None))
            continue
        if stripped.startswith('#'):
            line_labels.append((line, None))  # comment — no label
            continue
        label = _detect_service_label(stripped)
        line_labels.append((line, label or None))

    # Check if multiple distinct labels are present
    detected = [lbl for _, lbl in line_labels if lbl]
    distinct = list(dict.fromkeys(detected))  # ordered, deduplicated
    if len(distinct) <= 1:
        return []  # nothing to split

    # Group consecutive lines with the same label;
    # unlabeled lines attach to the current group
    groups = []
    current_label = None
    current_lines = []

    for line, label in line_labels:
        if label and label != current_label:
            # New service label — save current group and start a new one
            if current_lines:
                groups.append((current_label or '', '\n'.join(current_lines)))
            current_label = label
            current_lines = [line]
        else:
            if line.strip():  # skip pure blank lines between groups
                current_lines.append(line)

    if current_lines:
        groups.append((current_label or '', '\n'.join(current_lines)))

    # Filter out empty groups
    return [(lbl, cmds) for lbl, cmds in groups if cmds.strip()]


def _extract_verification_command(commands: str) -> str:
    """Extract the most likely verification command from a command block."""
    verify_patterns = [
        r'systemctl\s+status\s+\S+',
        r'openssl\s+s_client\s+.+',
        r'curl\s+-[vsIk].+',
        r'Test-NetConnection\s+.+',
        r'Get-Service\s+.+',
        r'nmap\s+.+',
        r'netstat\s+.+',
        r'\bss\s+-\w+',
        r'apachectl\s+(?:configtest|-t)',
        r'nginx\s+-t',
        r'sslscan\s+.+',
        r'testssl\.sh\s+.+',
    ]
    for line in commands.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        for pattern in verify_patterns:
            if re.search(pattern, stripped, re.IGNORECASE):
                return stripped
    return ""


def _build_on_failure(label: str, where_to_run: str, file_path: str = "") -> str:
    """Generate on-failure guidance based on execution context."""
    if where_to_run == "bash":
        base = "Check logs: journalctl -xe  or  tail -50 /var/log/syslog"
    elif where_to_run == "powershell":
        base = ("Check Windows Event Viewer or run: "
                "Get-EventLog -LogName System -Newest 20 | Where-Object {$_.EntryType -eq 'Error'}")
    elif where_to_run == "cmd":
        base = "Open Event Viewer (eventvwr.msc) and check the System log for errors."
    else:
        base = "Check system logs for error details and verify you have sufficient permissions."

    if file_path:
        base += f"  Verify target file exists: {file_path}"

    prefix = f"[{label}] " if label else ""
    return f"{prefix}{base}  Correct any errors shown and retry."


def _build_command_block(
    label: str,
    commands: str,
    system_file_path: str = "",
    step_no: str = "",
    step_name: str = "",
) -> dict:
    """Build a single command block dict with all execution guidance fields."""
    where = _infer_where_to_run(commands, system_file_path)
    verification_check = _extract_verification_command(commands)

    if label:
        expected_output = f"All '{label}' commands complete without errors."
    else:
        expected_output = f"Command completes without errors for step {step_no or step_name or 'this step'}."

    if verification_check:
        expected_output += " Verification command confirms the change is applied."

    return {
        "label": label,
        "commands": commands,
        "where_to_run": where,
        "where_to_run_label": _where_to_run_label(where),
        "expected_output": expected_output,
        "verification_check": verification_check or "Confirm the change is in place and no error messages appear.",
        "on_failure_what_to_do": _build_on_failure(label, where, system_file_path),
    }


def _parse_command_blocks(
    commands_str: str,
    system_file_path: str = "",
    step_no: str = "",
    step_name: str = "",
) -> list:
    """
    Split commands_for_action into labeled blocks (# ── Label ──).
    Each block gets its own where_to_run, expected_output,
    verification_check, and on_failure_what_to_do.
    """
    if not commands_str:
        return []

    commands_str = re.sub(r'<br\s*/?>', '\n', commands_str, flags=re.IGNORECASE)

    # Match: # ── Label ─────────────────────────  (box-drawing or hyphens)
    header_re = re.compile(
        r'^#\s*[─━—\-]{2,}\s*(.+?)\s*[─━—\-]*\s*$',
        re.MULTILINE,
    )

    headers = list(header_re.finditer(commands_str))

    if headers:
        # Path 1: explicit # ── Label ── headers from LLM
        blocks = []
        for i, match in enumerate(headers):
            label = match.group(1).strip()
            start = match.end()
            end = headers[i + 1].start() if i + 1 < len(headers) else len(commands_str)
            block_commands = commands_str[start:end].strip()
            blocks.append(_build_command_block(label, block_commands, system_file_path, step_no, step_name))
        return blocks

    # Path 2: no headers — try smart service/path detection
    smart_groups = _smart_split_commands(commands_str)
    if smart_groups:
        return [
            _build_command_block(lbl, cmds, system_file_path, step_no, step_name)
            for lbl, cmds in smart_groups
        ]

    # Path 3: single unlabeled block
    return [_build_command_block("", commands_str.strip(), system_file_path, step_no, step_name)]


def _ensure_execution_guidance_fields(row: dict) -> dict:
    commands = (row.get("commands_for_action") or "").strip()
    verification_steps = (row.get("verification_steps") or "").strip()
    step_name = (row.get("step_name") or "").strip()
    step_no = (row.get("step_no") or "").strip()
    fallback_remediation = (row.get("fallback_remediation") or "").strip()

    if not row.get("expected_output"):
        if verification_steps and verification_steps.lower() not in ("n/a", "na", ""):
            row["expected_output"] = (
                f"After completing this step: {verification_steps}"
            )
        elif commands and commands.lower() not in ("n/a", "na", ""):
            row["expected_output"] = (
                "The command completes without error messages. "
                f"Confirm the change is applied as described in '{step_name or 'this step'}'."
            )
        else:
            row["expected_output"] = (
                f"The changes described in step {step_no or 'this'} are visible and in effect."
            )

    if not row.get("verification_check"):
        if verification_steps and verification_steps.lower() not in ("n/a", "na", ""):
            row["verification_check"] = verification_steps
        else:
            row["verification_check"] = (
                "Check that the change is in place and there are no error messages or warnings."
            )

    if not row.get("on_success_next_step"):
        next_step = int(step_no) + 1 if step_no and step_no.isdigit() else None
        if next_step:
            row["on_success_next_step"] = f"Step {step_no} complete. Proceed to Step {next_step}."
        else:
            row["on_success_next_step"] = f"'{step_name}' complete. Move on to the next step."

    if not row.get("on_failure_what_to_do"):
        if fallback_remediation and fallback_remediation.lower() not in ("n/a", "na", ""):
            row["on_failure_what_to_do"] = (
                f"Fallback: {fallback_remediation}. "
                "Also check file paths, permissions, and that required services are running."
            )
        elif commands and commands.lower() not in ("n/a", "na", ""):
            row["on_failure_what_to_do"] = (
                f"Verify the command syntax and that you have the required permissions to run it. "
                f"Check system logs for error details, then retry step {step_no or 'this step'}."
            )
        else:
            row["on_failure_what_to_do"] = (
                f"Review the action instructions for '{step_name or 'this step'}', "
                "check permissions, and consult system logs before retrying."
            )
    return row


def _parse_vaptcode_response(raw_text: str) -> dict:
    """
    Parse vaptcode_integrated 4-agent JSON output into mitigation_tool format.

    vaptcode Card Formatter outputs:
      { analysis{}, card{}, os_profile{}, steps[], summary{} }

    Returns the same shape as _parse_response() plus 3 extra keys:
      vaptcode_os_profile, vaptcode_analysis, vaptcode_summary
    """
    result = {
        "mitigation_table":      [],
        "vulnerability_card":    {},
        "contextual_analysis":   [],
        "raw_response_sections": [],
        "vaptcode_os_profile":   {},
        "vaptcode_analysis":     {},
        "vaptcode_summary":      {},
    }

    # ── Extract JSON from agent output ──────────────────────────────────
    card = None
    text = (raw_text or "").strip()

    # Try 1: pure JSON
    try:
        card = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass

    # Try 2: ```json ... ``` fences
    if not isinstance(card, dict):
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL | re.IGNORECASE)
        if m:
            try:
                card = json.loads(m.group(1))
            except (json.JSONDecodeError, ValueError):
                pass

    # Try 3: first { ... } block
    if not isinstance(card, dict):
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                card = json.loads(m.group(0))
            except (json.JSONDecodeError, ValueError):
                pass

    if not isinstance(card, dict):
        logger.warning("[MitigationCrew] Could not parse vaptcode JSON output")
        return result

    analysis   = card.get("analysis",  {}) or {}
    card_meta  = card.get("card",      {}) or {}
    os_profile = card.get("os_profile",{}) or {}
    steps      = card.get("steps",     []) or []
    summary    = card.get("summary",   {}) or {}

    result["vaptcode_os_profile"] = os_profile
    result["vaptcode_analysis"]   = analysis
    result["vaptcode_summary"]    = summary

    # ── Build vulnerability_card (existing schema) ───────────────────────
    cve_list = analysis.get("cve_ids", []) or []
    result["vulnerability_card"] = {
        "vulnerability_type":            analysis.get("category", ""),
        "vendor_advisory":               analysis.get("evidence", ""),
        "reference_url":                 "",
        "affected_packages":             ", ".join(cve_list) if isinstance(cve_list, list) else "",
        "assigned_team":                 card_meta.get("assigned_to", ""),
        "vendor_fix_available":          "Yes",
        "steps_to_fix_count":            summary.get("total_steps") or len(steps),
        "steps_to_fix_description":      summary.get("next_action", ""),
        "deadline":                      "",
        "artifacts_tools":               "",
        "post_mitigation_troubleshooting_guide": summary.get("rollback_plan", ""),
        "resource_id":                   card_meta.get("ip_address", ""),
        "region":                        "",
        "affected_port_ranges":          card_meta.get("port_service", ""),
        "file_path":                     "",
    }

    # ── Build mitigation_table from steps[] ──────────────────────────────
    mitigation_table = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        action_obj = step.get("action", {}) or {}

        # Build action text (LOCATE / REMOVE / REPLACE / WHERE)
        action_parts = []
        for key, label in [("locate", "LOCATE"), ("remove", "REMOVE"),
                           ("replace", "REPLACE"), ("where", "WHERE")]:
            val = (action_obj.get(key) or "").strip()
            if val:
                action_parts.append(f"{label}: {val}")
        action_text = "\n".join(action_parts)

        # Build commands_for_action as ARRAY directly from command_to_run[]
        commands_array = []
        commands_str_temp = ""  # temp string only for where_to_run inference
        for cmd_block in (step.get("command_to_run") or []):
            if isinstance(cmd_block, dict):
                lbl  = (cmd_block.get("label") or "").strip()
                cmds = cmd_block.get("commands", [])
                if isinstance(cmds, str):
                    cmds = [cmds] if cmds else []
                clean_cmds = [str(c) for c in cmds if c]
                commands_array.append({"label": lbl, "commands": clean_cmds})
                commands_str_temp += "\n".join(clean_cmds) + "\n"
            elif isinstance(cmd_block, str) and cmd_block:
                commands_array.append({"label": "", "commands": [cmd_block]})
                commands_str_temp += cmd_block + "\n"

        # Normalise artifacts_tools_used to list
        tools = step.get("artifacts_tools_used", [])
        if isinstance(tools, str):
            tools = [t.strip() for t in tools.split(",") if t.strip()]
        elif not isinstance(tools, list):
            tools = []

        # Pass temp string to enrichment helpers (they expect a string)
        row = {
            "step_no":                  str(step.get("step_number", "")),
            "task_name":                step.get("task_name", ""),
            "action":                   action_text,
            "commands_for_action":      commands_str_temp,
            "system_file_path":         (step.get("file_path") or "").strip(),
            "assigned_to":              step.get("assigned_to", ""),
            "artifacts_tools_used":     tools,
            "verification_steps":       (action_obj.get("verify") or "").strip(),
            "important_consideration":  (step.get("important_consideration") or "").strip(),
        }
        row = _ensure_execution_guidance_fields(row)
        where = _infer_where_to_run(commands_str_temp, row.get("system_file_path", ""))
        row["where_to_run"]       = where
        row["where_to_run_label"] = _where_to_run_label(where)

        # Overwrite commands_for_action with ARRAY; remove sub_tasks & command_blocks
        row["commands_for_action"] = commands_array
        row.pop("sub_tasks",      None)
        row.pop("command_blocks", None)

        mitigation_table.append(row)

    result["mitigation_table"] = mitigation_table

    # ── contextual_analysis (for VulnerabilityCardDetailView) ────────────
    result["contextual_analysis"] = [
        {
            "section_number": "1",
            "heading": "Vulnerability Analysis",
            "content": (
                f"Category: {analysis.get('category', '')}\n"
                f"CVEs: {', '.join(analysis.get('cve_ids', []) or [])}\n"
                f"Severity: {analysis.get('severity', '')} / "
                f"CVSS: {analysis.get('cvss_estimate', '')}\n"
                f"Attack Vector: {analysis.get('attack_vector', '')}\n"
                f"Impact: {analysis.get('attacker_impact', '')}\n"
                f"Evidence: {analysis.get('evidence', '')}"
            ),
        },
        {
            "section_number": "2",
            "heading": "OS Profile",
            "content": (
                f"Platform: {os_profile.get('display_name', '')}\n"
                f"Vendor: {os_profile.get('vendor', '')}\n"
                f"Paradigm: {os_profile.get('paradigm', '')}\n"
                f"Confidence: {os_profile.get('confidence', '')}"
            ),
        },
    ]

    return result


def _parse_raw_response_sections(raw_text: str) -> list:
    """Parse the full raw AI response into a list of section objects."""
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
    Parse the crew agent's raw output into three components:
      - mitigation_table: list of dicts (one per table row)
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
    Generates detailed vulnerability mitigation plans using a 5-agent CrewAI crew:
      Agent 1 — Vulnerability Analyst
      Agent 2 — OS & Service Profiler
      Agent 3 — Remediation Engineer
      Agent 4 — Mitigation Card Formatter & QA
      Agent 5 — Output Structuring Specialist
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
        Execute the 5-agent mitigation crew and return structured results.

        Returns a dict with keys:
            success, vulnerability_name, description, plugin_output, report_id,
            mitigation_table, vulnerability_card, contextual_analysis,
            raw_response_sections, generated_at, error
        """
        base = {
            "vulnerability_name": plugin_name,
            "description": description,
            "plugin_output": plugin_output or None,
            "report_id": report_id or None,
            "generated_at": datetime.datetime.utcnow().isoformat(),
        }

        try:
            from crewai import Crew, Process
            from .crew_agent.agents import build_agents
            from .crew_agent.tasks import build_tasks

            llm = _get_crewai_llm()

            os_str = operating_system.strip() if operating_system else "Windows"
            os_category = _detect_os(os_str)  # "windows" / "linux" / "macos" / "android" / "ios"

            finding = {
                "ip":          host_name.strip() if host_name else "unknown",
                "os":          os_str,
                "os_category": os_category,
                "port":        "unknown",
                "vuln_name":   plugin_name,
                "description": description,
                "plugin_output": plugin_output or "",
                # Agent will classify into one of the 4 valid teams
                "assigned_to": (
                    "Classify this vulnerability to EXACTLY ONE of: "
                    "Patch Management | Network Security | "
                    "Configuration Management | Architectural Flaws"
                ),
            }

            agents = build_agents(llm)
            tasks  = build_tasks(agents, finding)

            crew = Crew(
                agents=list(agents.values()),
                tasks=tasks,
                process=Process.sequential,
                verbose=False,
            )

            logger.info(f"[MitigationCrew] Starting 4-agent vaptcode crew for: {plugin_name}")
            crew_result = crew.kickoff()
            raw_text = str(crew_result)

            parsed = _parse_vaptcode_response(raw_text)

            # Agent-driven team classification using analysis.category
            vuln_card = parsed["vulnerability_card"]
            team_slug = _resolve_assigned_team(plugin_name, {
                "vulnerability_type": parsed.get("vaptcode_analysis", {}).get("category", ""),
                "assigned_team":      vuln_card.get("assigned_team", ""),
            })
            team_display = _team_display_name(team_slug)
            vuln_card["assigned_team"] = team_display

            # Sync assigned_to in every mitigation table row
            for row in parsed["mitigation_table"]:
                row["assigned_to"] = team_display

            logger.info(
                f"[MitigationCrew] Done — steps: {len(parsed['mitigation_table'])}, "
                f"assigned_team: {team_display}"
            )

            return {
                **base,
                "success":               True,
                "mitigation_table":      parsed["mitigation_table"],
                "vulnerability_card":    vuln_card,
                "contextual_analysis":   parsed["contextual_analysis"],
                "raw_response_sections": parsed["raw_response_sections"],
                "vaptcode_os_profile":   parsed.get("vaptcode_os_profile", {}),
                "vaptcode_analysis":     parsed.get("vaptcode_analysis", {}),
                "vaptcode_summary":      parsed.get("vaptcode_summary", {}),
                "error":                 None,
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
