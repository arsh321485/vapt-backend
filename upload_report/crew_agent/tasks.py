"""
Nessus Mitigation Crew — Task Definitions (vaptcode_integrated 4-agent system)

Each task is a focused prompt. The OS Profile schema (Task 2 output) is the
contract between the OS Profiler and the downstream Remediation Engineer
and QA Formatter, so it is defined once here and reused.
"""

from crewai import Task


# ─────────────────────────────────────────────────────────────────────────────
# OS Profile schema — Task 2 fills this; Tasks 3 and 4 consume it.
# Kept paradigm-agnostic so the same shape works for Windows, Linux, Cisco IOS,
# FortiOS, ESXi, BIG-IP, RouterOS, printers, BMCs — anything the LLM knows.
# ─────────────────────────────────────────────────────────────────────────────

OS_PROFILE_SCHEMA = """\
{
  "display_name":  "<full human-readable name including version, e.g. 'Cisco IOS 15.4(3)M5'>",
  "vendor":        "<vendor or upstream project, e.g. 'Cisco Systems'>",
  "device_class":  "<one of: server | network_device | security_appliance | load_balancer | hypervisor | storage | printer | iot_embedded | unknown>",
  "paradigm":      "<one of: file_edit_systemd | file_edit_sc | cli_config_mode | restricted_cli | gui_primary | unknown>",
  "confidence":    "<high | medium | low — your confidence in this profile's correctness>",

  "admin_access": {
    "how_to_open":           "<how a human reaches the privileged context>",
    "shell_label":           "<short name used in prose, e.g. 'PowerShell as Administrator'>",
    "sudo_or_elevation":     "<'' if already elevated, otherwise the prefix or step required>"
  },

  "config_editing": {
    "paradigm_description":  "<one sentence: file-based, CLI config mode, GUI, etc.>",
    "editor_or_method":      "<exact tool, e.g. 'nano' or 'configure terminal'>",
    "enter_config_mode":     "<command or step to enter editable state; 'N/A' if file-based>",
    "save_changes":          "<command to persist changes>",
    "validate_changes":      "<command to validate config syntax before applying, or 'N/A'>",
    "discard_changes":       "<how to roll back uncommitted edits, or 'N/A'>"
  },

  "key_commands": {
    "show_version":          "<exact command>",
    "show_running_config":   "<exact command>",
    "list_users":            "<exact command>",
    "view_logs":             "<exact command>",
    "list_listening_ports":  "<exact command>",
    "list_processes":        "<exact command>",
    "restart_full_system":   "<exact command>"
  },

  "software_management": {
    "paradigm":              "<e.g. 'apt package management', 'firmware image swap'>",
    "install_or_upgrade":    "<command template, use {pkg} placeholder>",
    "query_installed":       "<command template, use {pkg} placeholder>",
    "vendor_advisory_url":   "<canonical PSIRT or security-advisory page for this vendor>"
  },

  "service_or_feature_management": {
    "paradigm":              "<e.g. 'systemd units', 'Windows SCM', 'features in running-config'>",
    "start":                 "<template with {svc}>",
    "stop":                  "<template with {svc}>",
    "restart":               "<template with {svc}>",
    "enable_at_boot":        "<template with {svc}>",
    "disable_at_boot":       "<template with {svc}>",
    "status":                "<template with {svc}>"
  },

  "firewall_paradigm": {
    "tool":                  "<e.g. 'UFW', 'Windows Defender Firewall', 'Cisco IOS ACLs'>",
    "block_port_template":   "<template with {port}>",
    "list_rules":            "<command or step to list active rules>"
  },

  "user_management": {
    "change_password":       "<template with {user}>",
    "lock_or_disable":       "<template with {user}>",
    "remove_account":        "<template with {user}>"
  },

  "forbidden_terms": [
    "<term from OTHER OSes that would be wrong here, e.g. 'systemctl' on a Cisco router>",
    "<another forbidden term>",
    "<...>"
  ],

  "key_safety_notes": [
    "<critical safety constraint>",
    "<another>"
  ]
}"""


OUTPUT_CARD_SCHEMA = """\
{
  "analysis": {
    "vulnerability_name":  "<normalized name>",
    "cve_ids":             ["<CVE-YYYY-NNNNN>", "..."],
    "severity":            "<Critical | High | Medium | Low | Informational>",
    "cvss_estimate":       "<numeric range or single score>",
    "category":            "<specific category — e.g. 'Cryptographic Weakness — TLS cipher downgrade'>",
    "attack_vector":       "<one sentence>",
    "attacker_impact":     "<one sentence>",
    "evidence":            "<key facts from the plugin output, paraphrased>",
    "scan_caveats":        "<e.g. 'Nessus could not authenticate — finding is undetermined'; or ''>"
  },

  "card": {
    "vulnerability":  "<finding.vuln_name>",
    "ip_address":     "<finding.ip>",
    "os":             "<profile.display_name>",
    "port_service":   "<finding.port>",
    "assigned_to":    "<EXACTLY ONE of: Patch Management | Network Security | Configuration Management | Architectural Flaws — choose based on vulnerability category>"
  },

  "os_profile":
    <copy the COMPLETE OS profile JSON object produced by Task 2 verbatim
     here — every field, no changes>,

  "steps": [
    {
      "step_number":   1,
      "assigned_to":   "<EXACTLY ONE of: Patch Management | Network Security | Configuration Management | Architectural Flaws>",
      "task_name":     "<short task title>",
      "action": {
        "locate":  "<where to find the thing to change>",
        "remove":  "<exact bad value or 'N/A — additive change'>",
        "replace": "<exact good value>",
        "where":   "<location within file / config / system>",
        "verify":  "<command that confirms the change>"
      },
      "file_path":        "<exact path or 'N/A — <reason>'>",
      "command_to_run": [
        {
          "label":    "<sub-path label>",
          "commands": ["<command 1>", "<command 2>"]
        }
      ],
      "artifacts_tools_used":    ["<tool1>", "<tool2>"],
      "important_consideration": "<warning or dependency>"
    }
  ],

  "summary": {
    "total_steps":            "<integer>",
    "target_os":              "<profile.display_name>",
    "shell_used":             "<profile.admin_access.shell_label>",
    "config_files_modified":  ["<path or 'running-config'>"],
    "estimated_time":         "<e.g. '2-3 hours including maintenance window'>",
    "rollback_plan":          "<text>",
    "next_action":            "<text — must mention re-scanning in Nessus>",
    "qa_corrections_made":    ["<correction or leave empty>"]
  }
}"""


def build_tasks(agents: dict, finding: dict) -> list:

    ip          = finding.get("ip",           "unknown")
    os_name     = finding.get("os",           "unknown")
    port        = finding.get("port",         "unknown")
    vuln_name   = finding.get("vuln_name",    "unknown")
    description = finding.get("description",  "")
    plugin_out  = finding.get("plugin_output","")
    assigned_to = finding.get("assigned_to",  "Security Team")

    # ── Task 1: Vulnerability Analysis ──────────────────────────────────
    task_analyse = Task(
        description=f"""
Analyse the following Nessus finding and produce a structured intelligence record.

FINDING:
  IP             : {ip}
  OS (reported)  : {os_name}
  Port / Service : {port}
  Vulnerability  : {vuln_name}

DESCRIPTION (from Nessus):
{description or '(none provided)'}

PLUGIN OUTPUT (from Nessus):
{plugin_out or '(none provided)'}

YOUR OUTPUT must include:
  1. Normalized vulnerability name
  2. CVE references mentioned in the description / plugin output, plus any
     others you know are associated with this finding
  3. Severity and CVSS estimate based on the vulnerability class
  4. Category — be SPECIFIC (e.g. 'Cryptographic Weakness — TLS cipher downgrade',
     'Software Lifecycle — End of Life', 'Authentication Weakness — Default Credentials',
     'Misconfiguration — Missing security headers')
  5. Attack vector — what the attacker needs and where the attack originates
  6. Attacker impact — what they can achieve on success
  7. Key evidence — the concrete facts from the plugin output
  8. Scan caveats — if Nessus reports authentication failure or undetermined finding

APPLY QUALITY CRITERIA: C2 C5 C7 C9 A8 C6 C8 A2 I6
""",
        expected_output=(
            "Structured vulnerability intelligence covering all eight points: "
            "name, CVEs, severity, CVSS, category, attack vector, impact, "
            "evidence, and scan caveats."
        ),
        agent=agents["vulnerability_analyst"],
    )

    # ── Task 2: OS Profile Generation ───────────────────────────────────
    task_profile = Task(
        description=f"""
Produce a structured OS profile for the platform reported in the finding.

REPORTED OS STRING (verbatim from Nessus):
  "{os_name}"

This string may name any commercial or open-source OS or firmware — a Linux
distribution, Windows Server, macOS, BSD, Cisco IOS / IOS XE / NX-OS / ASA,
Juniper JunOS, Palo Alto PAN-OS, Fortinet FortiOS, VMware ESXi, NetApp ONTAP,
a printer firmware, or anything else.

Use your knowledge of that exact platform to fill in the schema below.
If you are uncertain, mark confidence=low and note the uncertainty.
Do NOT fabricate command syntax.

The `forbidden_terms` list is critical. Populate it with command names,
paths, and tool names that belong to OTHER operating systems:
  - For Cisco IOS, forbid: systemctl, apt-get, yum, PowerShell, /etc/, nano
  - For Windows,   forbid: systemctl, apt-get, /etc/, nano, configure terminal
  - For Linux,     forbid: PowerShell, Get-Service, Notepad, HKLM, configure terminal

REQUIRED OUTPUT — a single JSON object matching this schema exactly.
No prose outside the JSON, no markdown fences:

APPLY CRITERIA: B1 B2 B5 B10

{OS_PROFILE_SCHEMA}
""",
        expected_output=(
            "A single JSON object filling the OS profile schema for the "
            f'reported OS "{os_name}". All fields present. paradigm and '
            "device_class chosen from the allowed values. forbidden_terms "
            "populated with at least five terms that would be wrong for this OS."
        ),
        agent=agents["os_profiler"],
        context=[task_analyse],
    )

    # ── Task 3: Remediation Plan ─────────────────────────────────────────
    task_remediate = Task(
        description=f"""
Generate the complete step-by-step mitigation plan, using the OS profile
produced by the previous task as your single source of truth for vocabulary.

FINDING:
  IP             : {ip}
  OS (reported)  : {os_name}
  Port / Service : {port}
  Vulnerability  : {vuln_name}

DESCRIPTION  : {description or '(none provided)'}
PLUGIN OUTPUT: {plugin_out or '(none provided)'}

TEAM ASSIGNMENT: {assigned_to}
Each step's assigned_to must be EXACTLY ONE of:
  Patch Management | Network Security | Configuration Management | Architectural Flaws
Choose based on the vulnerability's nature (not the finding.assigned_to text).

RULES:
  1. Use the OS profile's paradigm exclusively.
  2. Each step must contain ALL of: LOCATE / REMOVE / REPLACE / WHERE / VERIFY
  3. Multiple sub-paths → one labelled command block per sub-path.
  4. Every command block ends with a verification command.
  5. Commands must be real and copy-pasteable.
  6. NONE of the OS profile's forbidden_terms appear in your output.
  7. Vendor-patch-only fixes still include: identification, backup, staging,
     change-window, rollback, and post-fix verification.

QUALITY PRINCIPLES: P1 P2 P3 P4 P5 P6 P7
L-TIER: D6 D8 D10 D12 D14 D15 E1 E2 E4 E5 E7 E12
SAFETY: F2 F3 F5 F6 F7 F8 F9 F10
AUDITABILITY: H4 H5
QUANTITIES: G10
ESCALATION: J2

Produce 5 to 12 steps depending on the complexity.
""",
        expected_output=(
            "A complete, OS-correct mitigation plan. Each step contains "
            "LOCATE / REMOVE / REPLACE / WHERE / VERIFY plus labelled "
            "command blocks for every sub-path. All terminology drawn from "
            "the OS profile produced in Task 2."
        ),
        agent=agents["remediation_engineer"],
        context=[task_analyse, task_profile],
    )

    # ── Task 4: Card Formatter + QA ──────────────────────────────────────
    task_format = Task(
        description=f"""
QA-check the remediation plan against the OS profile, fix any violations
silently, then emit the final mitigation card as JSON.

QA CHECKLIST:
  ☐ NONE of the OS profile's forbidden_terms appear in any field.
  ☐ Every Action with multiple sub-paths has a command_to_run per sub-path.
  ☐ Every command_to_run entry ends with a verification command.
  ☐ Each Action has all five sub-fields: locate, remove, replace, where, verify.
  ☐ step_number values are sequential integers starting at 1.
  ☐ summary.next_action mentions re-scanning {ip}:{port} in Nessus.
  ☐ summary.rollback_plan references a backup created in an earlier step.
  ☐ summary.shell_used quotes the OS profile's admin_access.shell_label verbatim.

TEAM ASSIGNMENT (CRITICAL):
  card.assigned_to and every step's assigned_to must be EXACTLY ONE of:
    Patch Management | Network Security | Configuration Management | Architectural Flaws

  Assignment rules:
    - Patch Management      → missing patches, EOL software, outdated versions, CVE upgrades
    - Network Security      → SSL/TLS weaknesses, weak ciphers, open ports, exposed services,
                              firewall issues, protocol vulnerabilities
    - Configuration Management → misconfiguration, missing security headers, default settings,
                                  information disclosure, directory listing, debug mode
    - Architectural Flaws   → default credentials, authentication bypass, privilege escalation,
                              broken auth, hardcoded passwords, access control issues

  Choose based on the vulnerability's category from Task 1 — not from the finding input text.

BUSINESS-REVIEW QA (P1-P7): specific version, vendor URL, multiple discovery paths,
dependent components, GUI tools, granular sub-steps, formal change management.

L-TIER QA: C2 C5 C6 C7 C8 C9 A2 A8 I6 B1 B2 B5 B10
           D6 D8 D10 D12 D14 D15 E1 E4 E5 E7 E12
           F2 F3 F5 F6 F7 F8 F9 F10 H3 H4 H5 G10 J2

Record each fix in summary.qa_corrections_made with the criterion ID.

CARD HEADER VALUES (use exactly):
  vulnerability : {vuln_name}
  ip_address    : {ip}
  os            : <profile.display_name from Task 2>
  port_service  : {port}
  assigned_to   : <EXACTLY ONE of the 4 valid teams based on vulnerability category>

EMBED THE OS PROFILE:
  Copy the COMPLETE OS profile JSON object from Task 2 into
  mitigation_card.os_profile verbatim — every field, no changes.

OUTPUT — return ONLY this JSON object, no markdown fences, no commentary:

{OUTPUT_CARD_SCHEMA}

Escape backslashes in path strings as \\\\ inside JSON.
""",
        expected_output=(
            "A single valid JSON object matching the OUTPUT_CARD_SCHEMA: "
            "analysis, card, os_profile, steps[], summary. "
            "card.assigned_to and every step.assigned_to is exactly one of the "
            "4 valid teams. No forbidden terms. No markdown fences. "
            "Parseable with json.loads()."
        ),
        agent=agents["card_formatter"],
        context=[task_analyse, task_profile, task_remediate],
    )

    return [task_analyse, task_profile, task_remediate, task_format]
