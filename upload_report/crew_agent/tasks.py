"""
Nessus Mitigation Crew — Task Definitions

Five tasks. The OS Profile schema (Task 2 output) is the contract between
the OS Profiler and the downstream Remediation Engineer and QA Formatter.
Task 3 (backup) runs async in parallel with Task 4 (remediation).
"""

from crewai import Task


OS_PROFILE_SCHEMA = """\
{
  "display_name":  "<full human-readable name including version, e.g. 'Cisco IOS 15.4(3)M5'>",
  "vendor":        "<vendor or upstream project, e.g. 'Cisco Systems'>",
  "device_class":  "<one of: server | network_device | security_appliance | load_balancer | hypervisor | storage | printer | iot_embedded | unknown>",
  "paradigm":      "<one of: file_edit_systemd | file_edit_sc | cli_config_mode | restricted_cli | gui_primary | unknown>",
  "confidence":    "<high | medium | low>",

  "admin_access": {
    "how_to_open":       "<how a human reaches the privileged context>",
    "shell_label":       "<short name, e.g. 'Cisco IOS CLI (Privileged EXEC mode)'>",
    "sudo_or_elevation": "<'' if already elevated, otherwise the prefix or step required>"
  },

  "config_editing": {
    "paradigm_description": "<one sentence: file-based, CLI config mode, GUI, etc.>",
    "editor_or_method":     "<exact tool, e.g. 'configure terminal'>",
    "enter_config_mode":    "<command or step; 'N/A' if file-based>",
    "save_changes":         "<command to persist, e.g. 'copy running-config startup-config'>",
    "validate_changes":     "<command to validate config syntax, or 'N/A'>",
    "discard_changes":      "<how to roll back uncommitted edits, or 'N/A'>"
  },

  "key_commands": {
    "show_version":         "<exact command>",
    "show_running_config":  "<exact command>",
    "list_users":           "<exact command>",
    "view_logs":            "<exact command>",
    "list_listening_ports": "<exact command>",
    "list_processes":       "<exact command>",
    "restart_full_system":  "<exact command>"
  },

  "software_management": {
    "paradigm":           "<e.g. 'apt package management', 'firmware image swap'>",
    "install_or_upgrade": "<command template, use {pkg} placeholder>",
    "query_installed":    "<command template, use {pkg} placeholder>",
    "vendor_advisory_url":"<canonical PSIRT or security-advisory page>"
  },

  "service_or_feature_management": {
    "paradigm":       "<e.g. 'systemd units', 'Windows SCM'>",
    "start":          "<template with {svc}>",
    "stop":           "<template with {svc}>",
    "restart":        "<template with {svc}>",
    "enable_at_boot": "<template with {svc}>",
    "disable_at_boot":"<template with {svc}>",
    "status":         "<template with {svc}>"
  },

  "firewall_paradigm": {
    "tool":                "<e.g. 'UFW', 'firewalld', 'Cisco IOS ACLs'>",
    "block_port_template": "<template with {port}>",
    "list_rules":          "<command or step to list active rules>"
  },

  "user_management": {
    "change_password": "<template with {user}>",
    "lock_or_disable": "<template with {user}>",
    "remove_account":  "<template with {user}>"
  },

  "forbidden_terms": [
    "<term from OTHER OSes that would be wrong here, e.g. 'systemctl' on a Cisco router>",
    "<another forbidden term>"
  ],

  "key_safety_notes": [
    "<critical safety constraint>",
    "<another>"
  ]
}"""


OUTPUT_CARD_SCHEMA = """\
{
  "analysis": {
    "vulnerability_name": "<normalized name>",
    "cve_ids":            ["<CVE-YYYY-NNNNN>", "..."],
    "severity":           "<Critical | High | Medium | Low | Informational>",
    "cvss_estimate":      "<numeric range or single score>",
    "category":           "<short category>",
    "attack_vector":      "<one sentence>",
    "attacker_impact":    "<one sentence>",
    "evidence":           "<key facts from plugin output>",
    "scan_caveats":       "<e.g. 'Nessus could not authenticate'; or ''>"
  },

  "card": {
    "vulnerability":           "<primary vuln name>",
    "vulnerabilities_covered": ["<plugin ID / vuln name>"],
    "affected_hosts":          ["<IP/host>"],
    "os":                      "<profile.display_name>",
    "port_service":            "<finding.port>",
    "assigned_to":             "<finding.assigned_to>"
  },

  "steps": [
    {
      "step_number":  1,
      "assigned_to":  "<name>",
      "task_name":    "<short task title>",
      "action": {
        "locate":  "<where to find the thing to change>",
        "remove":  "<exact bad value or '❌ none — additive change'>",
        "replace": "<exact good value>",
        "where":   "<location within file / config / system>",
        "verify":  "<command that confirms the change>"
      },
      "file_path": "<exact path or 'N/A — <reason>'>",
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
    "total_steps":           "<integer>",
    "target_os":             "<profile.display_name>",
    "shell_used":            "<profile.admin_access.shell_label>",
    "config_files_modified": ["<path or 'running-config'>"],
    "estimated_time":        "<e.g. '2–3 hours'>",
    "next_action":           "<must mention re-scanning ALL affected hosts in Nessus>",
    "qa_corrections_made":   ["<correction or leave empty>"]
  }
}"""


BACKUP_CARD_SCHEMA = """\
{
  "backup_card": {
    "vulnerability":  "<finding.vuln_name>",
    "affected_hosts": ["<IP/host>"],
    "os":             "<profile.display_name>",
    "port_service":   "<finding.port>",
    "assigned_to":    "<finding.assigned_to>",
    "purpose":        "<one sentence: what this backup protects>"
  },

  "steps": [
    {
      "step_number": 1,
      "phase":       "<pre-check | backup | verify-backup | restore-procedure>",
      "assigned_to": "<name>",
      "task_name":   "<short task title>",
      "action": {
        "what":        "<what is being captured or restored>",
        "where":       "<source on the asset>",
        "destination": "<OFF-asset destination: remote share / TFTP server / backup volume>",
        "verify":      "<command that proves the backup/restore is good>"
      },
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

  "restore_summary": {
    "trigger":                   "<when to restore>",
    "restore_order":             ["<step ref>"],
    "estimated_restore_time":    "<e.g. '15–30 minutes'>",
    "post_restore_verification": "<command(s) that confirm asset is back to pre-change state>"
  }
}"""


def build_tasks(agents: dict, finding: dict) -> list:

    ip          = finding.get("ip",           "unknown")
    hosts       = finding.get("affected_hosts") or [ip]
    hosts_label = ", ".join(hosts)
    vuln_names  = finding.get("vuln_names") or []
    vuln_block  = ("\n".join(f"  - {v}" for v in vuln_names)
                   if vuln_names else "  (single finding)")
    os_name     = finding.get("os",           "unknown")
    port        = finding.get("port",         "unknown")
    vuln_name   = finding.get("vuln_name",    "unknown")
    description = finding.get("description",  "")
    plugin_out  = finding.get("plugin_output","")
    assigned_to = finding.get("assigned_to",  "Security Engineer")

    # ── Task 1: Vulnerability Analysis ──────────────────────────────────
    task_analyse = Task(
        description=f"""
Analyse the following Nessus finding and produce a structured intelligence record.

FINDING:
  Affected hosts : {hosts_label}
  OS (reported)  : {os_name}
  Port / Service : {port}
  Vulnerability  : {vuln_name}
  All findings in this group:
{vuln_block}
  Assigned To    : {assigned_to}

DESCRIPTION (from Nessus):
{description or '(none provided)'}

PLUGIN OUTPUT (from Nessus):
{plugin_out or '(none provided)'}

YOUR OUTPUT must include:
  1. Normalized vulnerability name
  2. CVE references mentioned in the description / plugin output, plus any
     others you know are associated with this finding
  3. Severity and CVSS estimate based on the vulnerability class
  4. Category (e.g. cryptographic weakness, authentication, software flaw,
     misconfiguration, exposed service, vendor advisory, etc.)
  5. Attack vector — what the attacker needs and where the attack originates
  6. Attacker impact — what they can achieve on success
  7. Key evidence — the concrete facts from the plugin output that prove
     the device is (or may be) affected
  8. Scan caveats — if Nessus reports that it could not authenticate or
     that the finding is undetermined, state that explicitly

Do not invent CVEs or attribute fictional advisories. If you are unsure,
say so.
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

Use your knowledge of that exact platform to fill in the schema below.
If you are inferring from a related vendor product, lower the confidence
and note the uncertainty. Do NOT fabricate command syntax — if you do not
know a specific command, write "<unknown — consult vendor documentation>"
rather than guess.

The `forbidden_terms` list is critical. Populate it with command names,
paths, and tool names that belong to OTHER operating systems and would be
wrong if they appeared in a mitigation written for THIS one. For example:
  - For Cisco IOS, forbid: systemctl, apt-get, yum, PowerShell, /etc/, nano
  - For Windows,   forbid: systemctl, apt-get, /etc/, nano, configure terminal
  - For Linux,     forbid: PowerShell, Get-Service, Notepad, HKLM, configure terminal

REQUIRED OUTPUT — a single JSON object matching this schema exactly.
No prose outside the JSON, no markdown fences:

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

    # ── Task 3: Backup Card (ASYNC — parallel track) ─────────────────────
    task_backup = Task(
        description=f"""
Produce the standalone BACKUP CARD for this finding. Operators execute
this card BEFORE the mitigation card; if the mitigation must be rolled
back, the restore procedure on this card is what they follow.

FINDING CONTEXT:
  Affected hosts: {hosts_label}
  OS            : {os_name}
  Port          : {port}
  Vulnerability : {vuln_name}
  Assigned To   : {assigned_to}
  Description   : {description or 'Not provided'}
  Plugin Output : {plugin_out or 'Not provided'}

VULNERABILITY-AWARE SCOPE — back up exactly what the mitigation for THIS
vulnerability class will touch on THIS asset:
  • SSL/TLS fix on Linux        → web-server config files and the certs/keys
  • SSL/TLS fix on Windows      → reg export of Schannel keys + IIS config backup
  • Network-device firmware fix → running-config AND startup-config exported
    off-box, current image preserved, boot variables recorded
  • FortiGate                   → execute backup config to TFTP/USB +
    firmware version recorded
  • Database vulnerability      → full DB backup, size-verified
  • Package/library upgrade     → current version inventory captured

STRUCTURE — steps in four phases, in this order:
  1. pre-check          — space on the backup destination, reachability, privileges
  2. backup             — one step per artefact, exact commands, OFF-asset destination
  3. verify-backup      — file size / integrity / archive listing
  4. restore-procedure  — exact ordered commands to return asset to pre-mitigation state

STRICT GATES:
  • OS FIDELITY      — every command matches the target OS paradigm.
  • PRODUCT FIDELITY — vendor-exact syntax only.

RULES:
  • Every step ends with a verification command.
  • OPERATIONAL ONLY — no change requests, ticketing, approvals.
  • NO LITERAL IPs — use <target_ip> / <target_host> placeholders.
  • Backups must land OFF the asset being changed.

OUTPUT — return ONLY this JSON object, no markdown fences, no commentary:

{BACKUP_CARD_SCHEMA}

Escape backslashes in any path strings as \\\\ inside JSON.
""",
        expected_output=(
            "A single valid JSON object matching BACKUP_CARD_SCHEMA: "
            "backup_card, steps[] (phased pre-check → backup → verify-backup "
            "→ restore-procedure), restore_summary. Every command OS-correct "
            "and product-correct. Parseable with json.loads()."
        ),
        agent=agents["backup_engineer"],
        context=[task_analyse, task_profile],
        async_execution=True,
    )

    # ── Task 4: Remediation Plan ─────────────────────────────────────────
    task_remediate = Task(
        description=f"""
Generate the complete step-by-step mitigation plan, using the OS profile
produced by the previous task as your single source of truth for vocabulary.

FINDING:
  Affected hosts : {hosts_label}
  OS (reported)  : {os_name}
  Port / Service : {port}
  Vulnerability  : {vuln_name}
  All findings in this group:
{vuln_block}
  Assigned To    : {assigned_to}

DESCRIPTION  : {description or '(none provided)'}
PLUGIN OUTPUT: {plugin_out or '(none provided)'}

RULES:
  1. Use the OS profile's paradigm. Match the profile — do not mix paradigms.
  2. Each step must contain ALL of: LOCATE, REMOVE, REPLACE, WHERE, VERIFY.
  3. If the action touches multiple sub-paths, command_to_run contains one
     labelled entry per sub-path.
  4. Every command_to_run entry ends with a verification command.
  5. Commands must be real and copy-pasteable.
  5a. NO COMMENT-ONLY COMMAND BLOCKS.
  5b. PLACEHOLDERS COME WITH A WORKED EXAMPLE (# example: ...).
  6. NONE of the OS profile's forbidden_terms appear anywhere in your output.
  7. Where the only true fix is a vendor patch, the plan still includes
     identification, staging, apply step, post-fix verification.
  8. NO BACKUP CONTENT OF ANY KIND.
  9. CONSOLIDATED DISCOVERY — ONE STEP (MAX TWO). All read-only discovery
     belongs in a SINGLE opening step.
  10. NO LITERAL IPs OR HOSTNAMES IN STEPS. Use <target_ip>, <target_host>.

QUALITY PRINCIPLES:
  P1 — LATEST STABLE RELEASE. Target the LATEST stable/recommended release,
       not just the minimum fix. Name it specifically.
  P2 — VENDOR OFFICIAL URL in important_consideration or as # comment.
  P3 — MULTIPLE DISCOVERY PATHS (CLI + GUI where applicable).
  P4 — DEPENDENT COMPONENT ENUMERATION in inventory steps.
  P5 — GUI TOOLS in artifacts_tools_used alongside CLI tools.
  P6 — GRANULAR SUB-STEPS for procedural tasks (install, upgrade, migration).

Produce 4 to 10 steps. Each step targets {assigned_to}.
""",
        expected_output=(
            "A complete, OS-correct mitigation plan. Each step contains "
            "LOCATE / REMOVE / REPLACE / WHERE / VERIFY plus labelled "
            "command blocks for every sub-path."
        ),
        agent=agents["remediation_engineer"],
        context=[task_analyse, task_profile],
    )

    # ── Task 5: Card Formatter + QA ─────────────────────────────────────
    task_format = Task(
        description=f"""
QA-check the remediation plan against the OS profile, fix any violations
silently, then emit the final mitigation card as JSON.

GATE 1 — OS FIDELITY (strict):
  The target OS is: {os_name}
  ☐ NONE of the OS profile's forbidden_terms appear in any field.
  ☐ The fix mechanism matches the OS paradigm.

GATE 2 — PRODUCT FIDELITY (strict):
  ☐ Every command block uses ONLY this product's syntax.
  ☐ Commands are valid for the product VERSION in the finding.

STRUCTURE CHECKLIST:
  ☐ EXECUTABLE COMMANDS — every command block has at least one executable command.
  ☐ DISCOVERY CONSOLIDATION — at most 1–2 discovery steps.
  ☐ Every Action describing multiple sub-paths has command_to_run per sub-path.
  ☐ Every command_to_run entry ends with a verification command.
  ☐ step_number values are sequential integers starting at 1.
  ☐ summary.next_action mentions re-scanning ALL affected hosts on {port}.
  ☐ NO BACKUP CONTENT — neither steps nor mentions.
  ☐ NO LITERAL IPs inside steps or summary.

OPERATIONAL-CONTENT CHECKS:
  ☐ P1 — Upgrade steps target LATEST stable release, named specifically.
  ☐ P2 — Canonical vendor URL included.
  ☐ P3 — Multiple discovery paths (CLI + GUI where applicable).
  ☐ P4 — Dependent components enumerated.
  ☐ P5 — GUI tools in artifacts_tools_used.
  ☐ P6 — Granular sub-steps for procedural tasks.

MANAGEMENT-CONTENT STRIP:
  ☐ Delete any step about change requests, approvals, ticketing, maintenance windows.

CARD HEADER VALUES (use exactly):
  vulnerability           : {vuln_name}
  affected_hosts          : {ip}
  os                      : <profile.display_name from Task 2>
  port_service            : {port}
  assigned_to             : {assigned_to}

OUTPUT — return ONLY this JSON object, no markdown fences, no commentary:

{OUTPUT_CARD_SCHEMA}

Escape backslashes in any path strings as \\\\ inside JSON.
""",
        expected_output=(
            "A single valid JSON object matching the OUTPUT_CARD_SCHEMA: "
            "analysis, card, steps[], summary. Every command OS-correct and "
            "product-correct. No forbidden terms, no management/process content. "
            "No markdown fences. Parseable with json.loads()."
        ),
        agent=agents["card_formatter"],
        context=[task_analyse, task_profile, task_remediate],
    )

    # Order matters: task_backup is async — it kicks off before task_remediate
    # runs and executes in parallel. task_format (sync, last) waits for both tracks.
    return [task_analyse, task_profile, task_backup, task_remediate, task_format]
