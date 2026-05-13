"""
Nessus Crew Agent — Tools v3 (OS-Profile-Driven, Exact Terminology)
"""

from typing import Type
from pydantic import BaseModel, Field
from crewai.tools import BaseTool
from .os_classifier import get_profile, detect_os_family, OSFamily
from .knowledge_base import find_template, render_steps, TEMPLATE_REGISTRY


class VulnLookupIn(BaseModel):
    vuln_name:   str = Field(...)
    description: str = Field(default="")

class OSProfileIn(BaseModel):
    os_name: str = Field(...)
    port:    str = Field(default="")

class KnowledgeIn(BaseModel):
    vuln_name:   str = Field(...)
    os_name:     str = Field(...)
    ip:          str = Field(default="TARGET_IP")
    port:        str = Field(default="443/tcp")
    description: str = Field(default="")
    assigned_to: str = Field(default="Security Engineer")

class RiskIn(BaseModel):
    vuln_name:     str = Field(...)
    plugin_output: str = Field(default="")


# ── Tool 1: Vulnerability Lookup ─────────────────────────────────────────────

class VulnerabilityLookupTool(BaseTool):
    name: str = "vulnerability_lookup"
    description: str = "Look up vulnerability by name. Returns category, severity, CVSS range, template availability."
    args_schema: Type[BaseModel] = VulnLookupIn

    def _run(self, vuln_name: str, description: str = "") -> str:
        tmpl = find_template(vuln_name, description)
        if tmpl:
            return (
                f"TEMPLATE FOUND\n"
                f"Category   : {tmpl.category}\n"
                f"Severity   : {tmpl.severity}\n"
                f"CVSS Range : {tmpl.cvss_range}\n"
                f"Steps      : {len(tmpl.steps)} OS-specific steps available\n"
            )
        return (
            f"No exact template for '{vuln_name}'.\n"
            f"Available: {', '.join(t.category for t in TEMPLATE_REGISTRY)}\n"
            "Custom steps will be generated using OS-specific best practices."
        )


# ── Tool 2: OS Profiler ──────────────────────────────────────────────────────

class OSProfilerTool(BaseTool):
    name: str = "os_profiler"
    description: str = (
        "Detect OS family and return ALL terminology, paths, and commands for that OS. "
        "This is the SINGLE SOURCE OF TRUTH — every term in the mitigation card comes from here."
    )
    args_schema: Type[BaseModel] = OSProfileIn

    def _run(self, os_name: str, port: str = "") -> str:
        p = get_profile(os_name)
        f = detect_os_family(os_name)
        return "\n".join([
            f"DETECTED OS     : {p.display_name}",
            f"OS FAMILY       : {f.value}",
            "",
            "── EXACT TERMINOLOGY (use verbatim in the mitigation card) ──",
            f"Shell label     : {p.shell_label}",
            f"Open admin shell: {p.open_shell_admin}",
            f"Open user shell : {p.open_shell_user}",
            f"Text editor     : {p.editor_name}",
            f"Open editor     : {p.open_editor.format(file='<file>')}",
            f"Sudo prefix     : '{p.sudo_prefix}' (empty = already elevated)",
            "",
            "── PACKAGE MANAGEMENT ──",
            f"Install         : {p.pkg_install.format(pkg='<pkg>')}",
            f"Upgrade         : {p.pkg_upgrade.format(pkg='<pkg>')}",
            f"Update index    : {p.pkg_update_index}",
            f"Remove          : {p.pkg_remove.format(pkg='<pkg>')}",
            "",
            "── SERVICE MANAGEMENT ──",
            f"Start           : {p.svc_start.format(svc='<svc>')}",
            f"Stop            : {p.svc_stop.format(svc='<svc>')}",
            f"Restart         : {p.svc_restart.format(svc='<svc>')}",
            f"Enable          : {p.svc_enable.format(svc='<svc>')}",
            f"Disable         : {p.svc_disable.format(svc='<svc>')}",
            f"Status          : {p.svc_status.format(svc='<svc>')}",
            f"Apache svc name : {p.apache_svc_name}",
            f"Nginx  svc name : {p.nginx_svc_name}",
            "",
            "── CONFIG FILE PATHS ──",
            f"Apache SSL conf : {p.apache_ssl_conf}",
            f"Apache main conf: {p.apache_main_conf}",
            f"Apache validate : {p.apache_validate}",
            f"Apache restart  : {p.apache_restart_cmd}",
            f"Apache log error: {p.apache_log_error}",
            f"Nginx SSL conf  : {p.nginx_ssl_conf}",
            f"Nginx validate  : {p.nginx_validate}",
            f"Nginx restart   : {p.nginx_restart_cmd}",
            f"Nginx log error : {p.nginx_log_error}",
            f"SSL cert dir    : {p.ssl_cert_dir}",
            f"SSH config      : {p.ssh_config}",
            "",
            "── NETWORK / FIREWALL ──",
            f"List ports      : {p.list_ports}",
            f"Block port      : {p.block_port_tcp.format(port='<port>')}",
            f"Check port      : {p.check_port.format(ip='<ip>', port='<port>')}",
            f"Firewall tool   : {p.firewall_tool}",
            f"Firewall list   : {p.firewall_list}",
            "",
            "── USER MANAGEMENT ──",
            f"List users      : {p.list_users}",
            f"Change password : {p.change_password.format(user='<user>')}",
            f"Lock account    : {p.lock_account.format(user='<user>')}",
            f"Disable account : {p.disable_account.format(user='<user>')}",
            "",
            "── STRICT RULE ──",
            f"All commands in the mitigation card MUST use terminology above.",
            f"DO NOT use terms from any other OS. Never say 'terminal' for Windows.",
            f"Never say 'Command Prompt' or 'PowerShell' for Linux.",
        ])


# ── Tool 3: Mitigation Knowledge ────────────────────────────────────────────

class MitigationKnowledgeTool(BaseTool):
    name: str = "mitigation_knowledge"
    description: str = (
        "Retrieve fully OS-specific mitigation steps from the knowledge base. "
        "Every command, path, and tool in the output is correct for the target OS only."
    )
    args_schema: Type[BaseModel] = KnowledgeIn

    def _run(
        self,
        vuln_name:   str,
        os_name:     str,
        ip:          str = "TARGET_IP",
        port:        str = "443/tcp",
        description: str = "",
        assigned_to: str = "Security Engineer",
    ) -> str:
        if not os_name:
            return "ERROR: os_name is required."

        p    = get_profile(os_name)
        tmpl = find_template(vuln_name, description)
        if not tmpl:
            return (
                f"No template for '{vuln_name}'.\n"
                f"Target OS: {p.display_name} | Shell: {p.shell_label} | Editor: {p.editor_name}\n"
                f"Generate custom steps using ONLY: {p.shell_label}, {p.editor_name}, "
                f"{p.pkg_install.format(pkg='<pkg>')}, {p.svc_restart.format(svc='<svc>')}"
            )

        ctx   = {"ip": ip, "port": port, "os": os_name, "assigned_to": assigned_to}
        steps = render_steps(tmpl, os_name, ctx)

        lines = [
            f"MITIGATION PLAN: {vuln_name}",
            f"Target OS  : {p.display_name}",
            f"Shell      : {p.shell_label}",
            f"Editor     : {p.editor_name}",
            f"Category   : {tmpl.category}",
            f"Severity   : {tmpl.severity}",
            f"Steps      : {len(steps)}",
            "=" * 60,
        ]
        for s in steps:
            lines += [
                f"STEP {s['step_no']:02d} | {s['task_name']}",
                f"Assigned To  : {s['assigned_to']}",
                f"File Path    : {s['file_path']}",
                f"Tools Used   : {s['artifacts_tools_used']}",
                f"Consider     : {s['important_consideration']}",
                "",
                "ACTION:",
                s["action"],
                "",
                "COMMAND TO RUN:",
                s["command_to_run"],
                "=" * 60,
            ]
        return "\n".join(lines)


# ── Tool 4: Risk Rater ───────────────────────────────────────────────────────

_RISK = {
    "critical": (["rce", "remote code execution", "unauthenticated", "root access",
                  "privilege escalation", "default credential"], "9.0–10.0", "Immediate — within 24 hours."),
    "high":     (["sql injection", "command injection", "authentication bypass",
                  "stored xss", "deserialization", "eol", "end of life", "missing patch"], "7.0–8.9", "Within 7 days."),
    "medium":   (["ssl", "tls", "weak cipher", "missing header", "open port",
                  "information disclosure", "csrf", "session"], "4.0–6.9", "Within standard patch cycle."),
    "low":      (["banner grab", "version disclosure", "self-signed", "weak policy"], "0.1–3.9", "Next scheduled review."),
}

class RiskRaterTool(BaseTool):
    name: str = "risk_rater"
    description: str = "Estimate severity and CVSS score from vulnerability name and plugin output."
    args_schema: Type[BaseModel] = RiskIn

    def _run(self, vuln_name: str, plugin_output: str = "") -> str:
        combined = (vuln_name + " " + plugin_output).lower()
        for sev, (kws, cvss, action) in _RISK.items():
            for kw in kws:
                if kw in combined:
                    return f"Severity  : {sev.upper()}\nCVSS Range: {cvss}\nAction    : {action}\nKeyword   : '{kw}'"
        return "Severity: MEDIUM (default)\nCVSS Range: 4.0–6.9\nAction: Within standard patch cycle."
