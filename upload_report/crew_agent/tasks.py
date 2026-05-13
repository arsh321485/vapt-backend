"""
Nessus Crew Agent — Tasks v3 (Exact Terminology + Complete Command Coverage)
Each task prompt embeds the OS terminology table and the command-coverage requirement.
"""

from crewai import Task
from .os_classifier import get_profile, OSFamily


def _terminology_table(os_name: str) -> str:
    """Return a terminology enforcement table for the detected OS."""
    p = get_profile(os_name)
    is_win = p.family == OSFamily.WINDOWS

    if is_win:
        return (
            f"\n{'━'*62}\n"
            f"TARGET OS TERMINOLOGY TABLE — {p.display_name.upper()}\n"
            f"{'━'*62}\n"
            f"  How to open admin shell : {p.open_shell_admin}\n"
            f"  Shell label in text     : {p.shell_label}\n"
            f"  Text editor             : {p.editor_name}\n"
            f"  Open editor cmd         : {p.open_editor.format(file='<file>')}\n"
            f"  Service stop            : {p.svc_stop.format(svc='<svc>')}\n"
            f"  Service restart         : {p.svc_restart.format(svc='<svc>')}\n"
            f"  Service status          : {p.svc_status.format(svc='<svc>')}\n"
            f"  Apache restart          : {p.apache_restart_cmd}\n"
            f"  Nginx  restart          : {p.nginx_restart_cmd}\n"
            f"  Apache SSL config path  : {p.apache_ssl_conf}\n"
            f"  Nginx  SSL config path  : {p.nginx_ssl_conf}\n"
            f"  Firewall tool           : {p.firewall_tool}\n"
            f"  Block port              : {p.block_port_tcp.format(port='<port>')}\n"
            f"\n  ❌ FORBIDDEN TERMS (never appear in a Windows card):\n"
            f"     'terminal', 'Terminal', 'bash', 'systemctl', 'apt-get', 'yum',\n"
            f"     'ufw', 'firewall-cmd', '/etc/' paths, 'nano', 'vi'\n"
            f"{'━'*62}\n"
        )
    else:
        return (
            f"\n{'━'*62}\n"
            f"TARGET OS TERMINOLOGY TABLE — {p.display_name.upper()}\n"
            f"{'━'*62}\n"
            f"  How to open shell       : {p.open_shell_admin}\n"
            f"  Shell label in text     : {p.shell_label}\n"
            f"  Text editor             : {p.editor_name}\n"
            f"  Open editor cmd         : {p.open_editor.format(file='<file>')}\n"
            f"  Package manager         : {p.pkg_install.format(pkg='<pkg>')}\n"
            f"  Update index            : {p.pkg_update_index}\n"
            f"  Service restart         : {p.svc_restart.format(svc='<svc>')}\n"
            f"  Service status          : {p.svc_status.format(svc='<svc>')}\n"
            f"  Apache service name     : {p.apache_svc_name}\n"
            f"  Apache restart          : {p.apache_restart_cmd}\n"
            f"  Apache validate         : {p.apache_validate}\n"
            f"  Apache SSL config path  : {p.apache_ssl_conf}\n"
            f"  Nginx  service name     : {p.nginx_svc_name}\n"
            f"  Nginx  restart          : {p.nginx_restart_cmd}\n"
            f"  Nginx  validate         : {p.nginx_validate}\n"
            f"  Nginx  SSL config path  : {p.nginx_ssl_conf}\n"
            f"  Firewall tool           : {p.firewall_tool}\n"
            f"  Block port              : {p.block_port_tcp.format(port='<port>')}\n"
            f"  List ports              : {p.list_ports}\n"
            f"\n  ❌ FORBIDDEN TERMS (never appear in a Linux card):\n"
            f"     'Command Prompt', 'PowerShell', 'Notepad', 'iisreset',\n"
            f"     'Get-Service', 'Stop-Service', 'netsh', 'HKLM', backslash paths\n"
            f"{'━'*62}\n"
        )


def _command_coverage_rule() -> str:
    return (
        "\nCOMMAND BLOCK COVERAGE RULE:\n"
        "  Every command that targets a specific file path or service MUST be placed\n"
        "  inside its own labeled block using this exact format:\n\n"
        "    # ── <Service or File Label> ─────────────────────────────────────\n"
        "    <command 1>\n"
        "    <command 2>\n"
        "    <verification command>\n\n"
        "  LABELING RULES — derive the label from the service or path:\n"
        "    Command targets C:\\Apache24\\... or /etc/apache2/...  →  # ── Apache ──────────\n"
        "    Command targets C:\\nginx\\... or /etc/nginx/...       →  # ── Nginx ───────────\n"
        "    Command uses iisreset / W3SVC / Get-WebConfiguration  →  # ── IIS ─────────────\n"
        "    Command targets HKLM:\\...\\SCHANNEL\\...              →  # ── Windows Registry (Schannel) ──\n"
        "    Command targets /etc/ssh/ or sshd_config              →  # ── SSH ─────────────\n\n"
        "  ABSOLUTE REQUIREMENTS:\n"
        "  - If commands target multiple services/paths, EVERY command must be in\n"
        "    its own labeled block. NEVER mix Apache and Nginx in one block.\n"
        "  - NEVER write only one unlabeled block when multiple services are involved.\n"
        "  - Each block MUST end with a verification command.\n"
        "  - Apply this rule in BOTH the Action field and the Commands for Action field.\n"
    )


def build_tasks(agents: dict, finding: dict) -> list:

    ip          = finding.get("ip",           "unknown")
    os_name     = finding.get("os",           "unknown")
    port        = finding.get("port",         "unknown")
    vuln_name   = finding.get("vuln_name",    "unknown")
    description = finding.get("description",  "")
    plugin_out  = finding.get("plugin_output","")
    assigned_to = finding.get("assigned_to",  "Security Engineer")

    profile  = get_profile(os_name)
    term_tbl = _terminology_table(os_name)
    cmd_rule = _command_coverage_rule()

    # ── Task 1: Vulnerability Analysis ──────────────────────────────────────
    task_analyse = Task(
        description=f"""
Analyse the Nessus finding and produce a structured intelligence report.

FINDING:
  IP              : {ip}
  OS              : {os_name}
  Port            : {port}
  Vulnerability   : {vuln_name}
  Assigned To     : {assigned_to}
  Description     : {description or 'Not provided'}
  Plugin Output   : {plugin_out or 'Not provided'}

Use vulnerability_lookup and risk_rater tools.

OUTPUT MUST INCLUDE:
  1. Normalized vulnerability name
  2. CVE references (if detectable)
  3. Severity (Critical / High / Medium / Low)
  4. CVSS score estimate
  5. Vulnerability category
  6. Attack vector
  7. What an attacker can do
  8. Key evidence from plugin output
""",
        expected_output="Structured vulnerability intelligence: name, severity, CVSS, category, CVE, attack vector, attacker impact, plugin evidence.",
        agent=agents["vulnerability_analyst"],
    )

    # ── Task 2: OS Profiling ─────────────────────────────────────────────────
    task_profile = Task(
        description=f"""
Profile the target OS and return the authoritative terminology and environment profile.

TARGET:
  OS    : {os_name}
  Port  : {port}

Use os_profiler tool with os_name="{os_name}" and port="{port}".

This profile is the SINGLE SOURCE OF TRUTH.
Every term in the mitigation card — shell name, editor name, config paths,
service commands — must come from this profile.
{term_tbl}
""",
        expected_output=f"Complete OS profile for {profile.display_name}: exact terminology, all paths, all service commands.",
        agent=agents["os_profiler"],
        context=[task_analyse],
    )

    # ── Task 3: Remediation Plan ─────────────────────────────────────────────
    task_remediate = Task(
        description=f"""
Generate a complete, OS-specific remediation plan for the Nessus finding.

FINDING CONTEXT:
  IP            : {ip}
  OS            : {os_name}  →  {profile.display_name}
  Port          : {port}
  Vulnerability : {vuln_name}
  Assigned To   : {assigned_to}
  Description   : {description or 'Not provided'}
  Plugin Output : {plugin_out or 'Not provided'}

STEP 1 — Call mitigation_knowledge tool:
  vuln_name="{vuln_name}", os_name="{os_name}",
  ip="{ip}", port="{port}", assigned_to="{assigned_to}"

STEP 2 — Review the returned steps. Adapt or expand if needed.

MANDATORY STRUCTURE FOR EACH STEP:
  a) Step number (sequential)
  b) Assigned To: {assigned_to}
  c) Task Name: short, action-oriented
  d) Action — must include ALL of:
       LOCATE  : exact file/UI/registry path
       REMOVE  : exact line(s)/value(s) to delete  (❌ before-example)
       REPLACE : exact replacement                  (✅ after-example)
       WHERE   : location within the file or system
       VERIFY  : command that confirms change was applied
  e) File Path   : exact path for {profile.display_name}
  f) Command to Run : (see coverage rule below)
  g) Artifacts / Tools Used
  h) Important Consideration
{cmd_rule}
{term_tbl}
ALL commands must run on {profile.display_name}.
Shell to reference: {profile.shell_label}
Editor to reference: {profile.editor_name}
Open admin shell: {profile.open_shell_admin}
""",
        expected_output=(
            f"Complete OS-specific remediation plan for {profile.display_name}. "
            "Each step has LOCATE/REMOVE/REPLACE/WHERE/VERIFY. "
            "Command field has labeled blocks for every sub-path mentioned in Action. "
            f"All terminology matches {profile.display_name} profile."
        ),
        agent=agents["remediation_engineer"],
        context=[task_analyse, task_profile],
    )

    # ── Task 4: Card Formatting + QA ────────────────────────────────────────
    is_windows = profile.family == OSFamily.WINDOWS
    qa_checks = (
        "Windows checks: reject bash, /etc/ paths, systemctl, apt-get, ufw, nano, the word terminal"
        if is_windows else
        "Linux checks: reject PowerShell, HKLM paths, backslash paths, Get-Service, iisreset, Notepad, Command Prompt"
    )

    task_format = Task(
        description=f"""
QA-check the remediation plan, correct any cross-OS violations, then produce the output in THREE sections.

QA CHECK — run before formatting:
  Target OS: {profile.display_name}
  {qa_checks}
  Command coverage check: every action with multiple paths has a labeled block per path.
  Correct violations silently before outputting.

═══════════════════════════════════════════════════════════════
SECTION 1 — MARKDOWN TABLE
═══════════════════════════════════════════════════════════════
Output a markdown table with EXACTLY these column headers:

| Step No | Assigned To | Task Name | Action | System File Path | Commands for Action | Artifacts/Tools Used | Important Consideration | Verification Steps |
|---|---|---|---|---|---|---|---|---|

Rules for table cells:
  - Action      : full LOCATE / REMOVE ❌ / REPLACE ✅ / VERIFY text (use <br> for line breaks inside cell)
  - Commands    : all labeled command blocks for this step (use <br> for line breaks inside cell)
  - Verification: the command(s) that confirm the change was applied
  - Use the EXACT OS-specific paths and commands for {profile.display_name}
  - {profile.shell_label} terminology only — no cross-OS contamination

═══════════════════════════════════════════════════════════════
SECTION 2 — JSON VULNERABILITY CARD
═══════════════════════════════════════════════════════════════
Output a JSON block (```json ... ```) with these exact fields:

TEAM ASSIGNMENT RULES — assigned_team MUST be exactly one of these 4 values:
  "network-security"       → SSL/TLS issues, weak ciphers, open ports, Telnet/FTP exposure,
                             firewall gaps, SNMP, DNS, any network-layer vulnerability
  "patch-management"       → Missing OS/software patches, outdated packages, EOL software,
                             unpatched CVEs, kernel vulnerabilities, outdated libraries
  "architectural-flaws"    → Authentication bypass, default/weak credentials, privilege
                             escalation, insecure design, missing access controls, broken auth
  "configuration-management" → Misconfigured services, wrong permissions, insecure headers,
                             SSL config errors, default settings left enabled, config drift

```json
{{
  "resource_id": "{ip}",
  "region": "on-premises",
  "affected_packages": "<list affected software if known, else null>",
  "vendor_advisory": "<CVE advisory URL if available, else null>",
  "reference_url": "<reference URL if available, else null>",
  "vulnerability_type": "<category from vulnerability analysis>",
  "affected_port_ranges": "{port}",
  "assigned_team": "<MUST be one of: network-security | patch-management | architectural-flaws | configuration-management>",
  "vendor_fix_available": "<yes/no/unknown>",
  "steps_to_fix_description": "<one-sentence summary of the fix>",
  "deadline": "<recommended deadline based on severity>",
  "artifacts_tools": "<comma-separated list of all tools used>",
  "post_mitigation_troubleshooting_guide": "<numbered steps to verify fix, e.g.: 1. Re-run Nessus scan 2. Check service status>",
  "steps_to_fix_count": <total number of remediation steps as integer>
}}
```

═══════════════════════════════════════════════════════════════
SECTION 3 — CONTEXTUAL ANALYSIS
═══════════════════════════════════════════════════════════════
Output a numbered contextual analysis with these sections:

1. **Risk Assessment**: Explain the severity and business impact of this vulnerability.
2. **Technical Context**: Describe the root cause and technical details.
3. **Remediation Priority**: Recommend timeline and prioritization.
4. **Post-Fix Validation**: Describe how to confirm the fix was successful.
5. **QA Corrections Made**: List any cross-OS or terminology fixes applied during QA.
""",
        expected_output=(
            "Three sections: (1) markdown pipe table with step-by-step remediation, "
            "(2) JSON vulnerability card block, "
            "(3) numbered contextual analysis. "
            f"All terminology verified correct for {profile.display_name}. "
            "No cross-OS contamination."
        ),
        agent=agents["card_formatter"],
        context=[task_analyse, task_profile, task_remediate],
    )

    # ── Task 5: Output Structuring ──────────────────────────────────────────────
    task_structure = Task(
        description=f"""
Re-read the Card Formatter's output and produce a corrected version with every field
in the correct column.

TARGET OS: {profile.display_name}

YOUR ONLY JOB: Fix fields that are in the wrong table cell. The data content is correct
but content may have been placed in the wrong column. Relocate — never delete.

COLUMN RULES:

  Action
    ✅ LOCATE / REMOVE ❌ / REPLACE ✅ / WHERE / VERIFY prose
    ❌ NOT executable shell commands

  Commands for Action
    ✅ Executable commands only, in labeled blocks:
         # ── <Service> ─────────────────────────────
         <command>
    ❌ NOT prose text, NOT LOCATE descriptions, NOT bare tool names

  Artifacts/Tools Used
    ✅ Tool names only — comma-separated (e.g., Nmap, PowerShell, openssl, Notepad)
    ❌ NOT commands, NOT file paths

  Important Consideration
    ✅ Warnings, notes, precautions, backup reminders
    ❌ NOT commands, NOT action text

  Verification Steps
    ✅ The command or instruction to confirm the fix worked
    ❌ NOT action prose, NOT tool name lists

COMMON FIX EXAMPLES:
  Artifacts/Tools shows "Get-TlsCipherSuite | Select-Object Name"
    → That is a command. Move it to Commands for Action.
    → Artifacts/Tools should be: "PowerShell, Get-TlsCipherSuite cmdlet"

  Commands shows "PowerShell, Notepad"
    → Those are tool names. Move them to Artifacts/Tools.
    → Commands should contain the actual executable commands.

  Important Consideration shows "Get-Service W3SVC"
    → That is a command. Move it to Verification Steps.
    → Consideration should contain only the warning or note.

OUTPUT — reproduce all THREE sections with corrections applied:

═══════════════════════════════════════════════════════════════
SECTION 1 — MARKDOWN TABLE
═══════════════════════════════════════════════════════════════
| Step No | Assigned To | Task Name | Action | System File Path | Commands for Action | Artifacts/Tools Used | Important Consideration | Verification Steps |
|---|---|---|---|---|---|---|---|---|

═══════════════════════════════════════════════════════════════
SECTION 2 — JSON VULNERABILITY CARD
═══════════════════════════════════════════════════════════════
Keep ALL JSON fields exactly as received from the Card Formatter. Do not change any value.

═══════════════════════════════════════════════════════════════
SECTION 3 — CONTEXTUAL ANALYSIS
═══════════════════════════════════════════════════════════════
Keep the numbered contextual analysis exactly as received. Do not change any content.
""",
        expected_output=(
            "Three corrected sections: (1) markdown pipe table where each cell contains "
            "only the correct type of content for that column, "
            "(2) JSON vulnerability card block unchanged from Card Formatter output, "
            "(3) contextual analysis unchanged. "
            f"All terminology correct for {profile.display_name}."
        ),
        agent=agents["output_structurer"],
        context=[task_format],
    )

    return [task_analyse, task_profile, task_remediate, task_format, task_structure]
