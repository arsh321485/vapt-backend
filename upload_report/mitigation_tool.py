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
    Generates detailed vulnerability mitigation plans using a 4-agent CrewAI crew:
      Agent 1 — Vulnerability Analyst
      Agent 2 — OS & Service Profiler
      Agent 3 — Remediation Engineer
      Agent 4 — Mitigation Card Formatter
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
        Execute the 4-agent mitigation crew and return structured results.

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
                "ip": host_name.strip() if host_name else "unknown",
                "os": os_str,
                "os_category": os_category,
                "port": "unknown",
                "vuln_name": plugin_name,
                "description": description,
                "plugin_output": plugin_output or "",
                "assigned_to": "Security Engineer",
            }

            agents = build_agents(llm)
            tasks = build_tasks(agents, finding)

            crew = Crew(
                agents=list(agents.values()),
                tasks=tasks,
                process=Process.sequential,
                verbose=False,
            )

            logger.info(f"[MitigationCrew] Starting 4-agent crew for: {plugin_name}")
            crew_result = crew.kickoff()
            raw_text = str(crew_result)

            parsed = _parse_response(raw_text)

            logger.info(
                f"[MitigationCrew] Done — table rows: {len(parsed['mitigation_table'])}, "
                f"card fields: {len(parsed['vulnerability_card'])}"
            )

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
