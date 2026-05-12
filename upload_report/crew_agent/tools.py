"""
Nessus Crew Agent — Custom Tools
These tools give agents structured knowledge access without relying on internet searches.
"""

import re
from typing import Type, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool
from .knowledge_base import (
    find_template,
    render_steps,
    TEMPLATE_REGISTRY,
    MitigationTemplate,
)


# =========================================================================== #
# Input Schemas
# =========================================================================== #

class VulnLookupInput(BaseModel):
    vuln_name: str = Field(..., description="The full vulnerability name from Nessus")
    description: str = Field(default="", description="Vulnerability description for context")

class OSProfileInput(BaseModel):
    os_name: str = Field(..., description="Operating system name and version")
    port: str = Field(default="", description="Port number and protocol")

class CommandInput(BaseModel):
    action: str = Field(..., description="The action or task to build a command for")
    os_name: str = Field(..., description="Target operating system")
    service: str = Field(default="", description="Service name (e.g., apache2, nginx)")

class KnowledgeInput(BaseModel):
    vuln_name: str = Field(..., description="Vulnerability name to retrieve mitigation steps for")
    description: str = Field(default="", description="Vulnerability description")
    ip: str = Field(default="{ip}", description="Target IP address")
    port: str = Field(default="{port}", description="Target port")
    os_name: str = Field(default="{os}", description="Target OS")
    os_category: str = Field(default="linux", description="OS category: windows / linux / macos")
    assigned_to: str = Field(default="Security Engineer", description="Engineer assigned to this task")

class RiskInput(BaseModel):
    vuln_name: str = Field(..., description="Vulnerability name")
    plugin_output: str = Field(default="", description="Nessus plugin output")


# =========================================================================== #
# Tool 1 — Vulnerability Lookup
# =========================================================================== #

class VulnerabilityLookupTool(BaseTool):
    name: str = "vulnerability_lookup"
    description: str = (
        "Look up a vulnerability by name and return its category, typical severity, "
        "CVSS score range, and matched knowledge base template."
    )
    args_schema: Type[BaseModel] = VulnLookupInput

    def _run(self, vuln_name: str, description: str = "") -> str:
        template = find_template(vuln_name, description)
        if template:
            return (
                f"MATCH FOUND\n"
                f"Category   : {template.category}\n"
                f"Severity   : {template.severity}\n"
                f"CVSS Range : {template.cvss_range}\n"
                f"Steps      : {len(template.steps)} remediation steps available\n"
                f"Pattern    : {template.vuln_pattern}"
            )
        cats = [f"  - {t.category} ({t.severity})" for t in TEMPLATE_REGISTRY]
        return (
            f"No exact template match for '{vuln_name}'.\n"
            f"Available categories:\n" + "\n".join(cats) + "\n"
            f"The Remediation Engineer will generate custom steps based on best practices."
        )


# =========================================================================== #
# Tool 2 — OS Profiler
# =========================================================================== #

_OS_PROFILES = {
    "ubuntu": {
        "pkg_manager": "apt-get",
        "service_manager": "systemctl",
        "apache_config": "/etc/apache2/sites-enabled/default-ssl.conf",
        "nginx_config": "/etc/nginx/sites-enabled/default",
        "ssh_config": "/etc/ssh/sshd_config",
        "ssl_dir": "/etc/ssl/certs/",
        "log_dir": "/var/log/apache2/",
        "restart_apache": "sudo systemctl restart apache2",
        "restart_nginx": "sudo systemctl restart nginx",
        "verify_config_apache": "apachectl configtest",
        "verify_config_nginx": "nginx -t",
        "firewall": "ufw",
    },
    "debian": {
        "pkg_manager": "apt-get",
        "service_manager": "systemctl",
        "apache_config": "/etc/apache2/sites-enabled/default-ssl.conf",
        "nginx_config": "/etc/nginx/sites-enabled/default",
        "ssh_config": "/etc/ssh/sshd_config",
        "ssl_dir": "/etc/ssl/certs/",
        "log_dir": "/var/log/apache2/",
        "restart_apache": "sudo systemctl restart apache2",
        "restart_nginx": "sudo systemctl restart nginx",
        "verify_config_apache": "apachectl configtest",
        "verify_config_nginx": "nginx -t",
        "firewall": "ufw",
    },
    "rhel": {
        "pkg_manager": "yum",
        "service_manager": "systemctl",
        "apache_config": "/etc/httpd/conf.d/ssl.conf",
        "nginx_config": "/etc/nginx/nginx.conf",
        "ssh_config": "/etc/ssh/sshd_config",
        "ssl_dir": "/etc/pki/tls/certs/",
        "log_dir": "/var/log/httpd/",
        "restart_apache": "sudo systemctl restart httpd",
        "restart_nginx": "sudo systemctl restart nginx",
        "verify_config_apache": "apachectl configtest",
        "verify_config_nginx": "nginx -t",
        "firewall": "firewall-cmd",
    },
    "centos": {
        "pkg_manager": "yum",
        "service_manager": "systemctl",
        "apache_config": "/etc/httpd/conf.d/ssl.conf",
        "nginx_config": "/etc/nginx/nginx.conf",
        "ssh_config": "/etc/ssh/sshd_config",
        "ssl_dir": "/etc/pki/tls/certs/",
        "log_dir": "/var/log/httpd/",
        "restart_apache": "sudo systemctl restart httpd",
        "restart_nginx": "sudo systemctl restart nginx",
        "verify_config_apache": "apachectl configtest",
        "verify_config_nginx": "nginx -t",
        "firewall": "firewall-cmd",
    },
    "windows": {
        "pkg_manager": "Windows Update / Chocolatey",
        "service_manager": "sc / Get-Service",
        "apache_config": "C:\\Apache24\\conf\\extra\\httpd-ssl.conf",
        "nginx_config": "C:\\nginx\\conf\\nginx.conf",
        "ssh_config": "C:\\ProgramData\\ssh\\sshd_config",
        "ssl_dir": "C:\\ProgramData\\ssl\\",
        "log_dir": "C:\\Apache24\\logs\\",
        "restart_apache": "net stop Apache2.4 && net start Apache2.4",
        "restart_nginx": "nginx -s reload",
        "verify_config_apache": "httpd -t",
        "verify_config_nginx": "nginx -t",
        "firewall": "netsh advfirewall",
    },
}

_PORT_SERVICES = {
    "21": "FTP",
    "22": "SSH",
    "23": "Telnet",
    "25": "SMTP",
    "80": "HTTP",
    "110": "POP3",
    "143": "IMAP",
    "443": "HTTPS/SSL",
    "445": "SMB",
    "3306": "MySQL",
    "3389": "RDP",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "8080": "HTTP-alt",
    "8443": "HTTPS-alt",
    "27017": "MongoDB",
}


class OSProfilerTool(BaseTool):
    name: str = "os_profiler"
    description: str = (
        "Profile a target OS and return the exact config file paths, package manager, "
        "service manager, log directories, firewall tool, and service restart commands "
        "relevant for remediation."
    )
    args_schema: Type[BaseModel] = OSProfileInput

    def _run(self, os_name: str, port: str = "") -> str:
        os_lower = os_name.lower()
        os_key = None
        for key in _OS_PROFILES:
            if key in os_lower:
                os_key = key
                break
        if not os_key:
            os_key = "ubuntu"
        profile = _OS_PROFILES[os_key]

        port_clean = re.sub(r"[^0-9]", "", port.split("/")[0]) if port else ""
        service_hint = _PORT_SERVICES.get(port_clean, "Unknown service")

        lines = [f"OS Profile for: {os_name}  (detected: {os_key.upper()})"]
        lines.append(f"Port {port} → likely service: {service_hint}")
        lines.append("")
        for k, v in profile.items():
            lines.append(f"  {k:<30}: {v}")

        # Strict OS isolation — explicitly forbid wrong-OS commands
        lines.append("")
        if os_key == "windows":
            lines.append("═" * 60)
            lines.append("CRITICAL OS ISOLATION — TARGET IS WINDOWS")
            lines.append("Use ONLY the paths and commands listed above.")
            lines.append("FORBIDDEN (Linux/Mac — DO NOT USE THESE):")
            lines.append("  ✗ sudo, apt, yum, dnf, systemctl, service")
            lines.append("  ✗ nano, vim, vi  (use: notepad or notepad++)")
            lines.append("  ✗ /etc/, /var/, /tmp/, /usr/, /home/")
            lines.append("  ✗ cp, chmod, chown, grep, tail, cat")
            lines.append("  ✗ bash, sh, systemd, journalctl")
            lines.append("REQUIRED (Windows — ALWAYS use these):")
            lines.append("  ✓ notepad, copy, del, type, dir")
            lines.append("  ✓ net stop / net start / sc query")
            lines.append("  ✓ PowerShell: Get-Service, Set-Content, Get-Content")
            lines.append("  ✓ Paths starting with C:\\ (backslash, NOT forward slash)")
            lines.append("  ✓ %TEMP% instead of /tmp/")
            lines.append("  ✓ netsh advfirewall instead of ufw/iptables")
            lines.append("═" * 60)
        elif os_key in ("ubuntu", "debian", "rhel", "centos"):
            lines.append("═" * 60)
            lines.append("CRITICAL OS ISOLATION — TARGET IS LINUX")
            lines.append("Use ONLY the paths and commands listed above.")
            lines.append("FORBIDDEN (Windows — DO NOT USE THESE):")
            lines.append("  ✗ notepad, net stop, net start, sc query")
            lines.append("  ✗ C:\\ paths, %TEMP%, netsh, choco, winget")
            lines.append("  ✗ PowerShell Get- cmdlets")
            lines.append("REQUIRED (Linux — ALWAYS use these):")
            lines.append("  ✓ sudo nano / sudo vim")
            lines.append("  ✓ sudo systemctl restart/stop/start/status")
            lines.append("  ✓ sudo cp, sudo chmod, sudo chown")
            lines.append(f"  ✓ Paths from profile above (/etc/, /var/log/, /tmp/)")
            if os_key in ("ubuntu", "debian"):
                lines.append("  ✓ sudo apt-get for package management")
            else:
                lines.append("  ✓ sudo yum for package management")
            lines.append("═" * 60)

        return "\n".join(lines)


# =========================================================================== #
# Tool 3 — Command Builder
# =========================================================================== #

_COMMAND_PATTERNS = {
    "backup": {
        "ubuntu": "sudo cp {file} {file}.bak_$(date +%Y%m%d)",
        "rhel":   "sudo cp {file} {file}.bak_$(date +%Y%m%d)",
        "windows": r'copy "{file}" "{file}.bak_%date:~-4,4%%date:~-10,2%%date:~-7,2%"',
    },
    "open file": {
        "ubuntu": "sudo nano {file}",
        "rhel":   "sudo nano {file}",
        "windows": r'notepad "{file}"',
    },
    "edit config": {
        "ubuntu": "sudo nano {file}",
        "rhel":   "sudo nano {file}",
        "windows": r'notepad "C:\Apache24\conf\extra\httpd-ssl.conf"',
    },
    "restart apache": {
        "ubuntu": "sudo systemctl restart apache2",
        "rhel":   "sudo systemctl restart httpd",
        "windows": "net stop Apache2.4 && net start Apache2.4",
    },
    "restart nginx": {
        "ubuntu": "sudo systemctl restart nginx",
        "rhel":   "sudo systemctl restart nginx",
        "windows": "nginx -s reload",
    },
    "check service": {
        "ubuntu": "sudo systemctl status {service}",
        "rhel":   "sudo systemctl status {service}",
        "windows": "sc query {service}",
    },
    "disable service": {
        "ubuntu": "sudo systemctl stop {service} && sudo systemctl disable {service}",
        "rhel":   "sudo systemctl stop {service} && sudo systemctl disable {service}",
        "windows": "net stop {service} && sc config {service} start= disabled",
    },
    "block port": {
        "ubuntu": "sudo ufw deny in {port}/tcp && sudo ufw status",
        "rhel":   "sudo firewall-cmd --permanent --remove-port={port}/tcp && sudo firewall-cmd --reload",
        "windows": "netsh advfirewall firewall add rule name=\"Block_{port}\" dir=in action=block protocol=TCP localport={port}",
    },
    "validate config apache": {
        "ubuntu": "apachectl configtest",
        "rhel":   "apachectl configtest",
        "windows": "httpd -t",
    },
    "validate config nginx": {
        "ubuntu": "nginx -t",
        "rhel":   "nginx -t",
        "windows": "nginx -t",
    },
    "update package": {
        "ubuntu": "sudo apt-get update && sudo apt-get install --only-upgrade {pkg}",
        "rhel":   "sudo yum update {pkg}",
        "windows": "choco upgrade {pkg}",
    },
    "check logs": {
        "ubuntu": r"tail -f /var/log/apache2/error.log | grep -iE 'ssl|error'",
        "rhel":   r"tail -f /var/log/httpd/error_log | grep -iE 'ssl|error'",
        "windows": r'Get-Content C:\Apache24\logs\error.log -Wait | Select-String -Pattern "ssl|error"',
    },
    "verify ssl": {
        "ubuntu": "nmap --script ssl-enum-ciphers -p {port} {ip}",
        "rhel":   "nmap --script ssl-enum-ciphers -p {port} {ip}",
        "windows": "nmap --script ssl-enum-ciphers -p {port} {ip}",
    },
    "check open ports": {
        "ubuntu": "ss -tlnp | grep {port}",
        "rhel":   "ss -tlnp | grep {port}",
        "windows": "netstat -ano | findstr {port}",
    },
    "generate dhparam": {
        "ubuntu": "openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048",
        "rhel":   "openssl dhparam -out /etc/pki/tls/certs/dhparam.pem 2048",
        "windows": r'"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" dhparam -out C:\ProgramData\ssl\dhparam.pem 2048',
    },
    "change password": {
        "ubuntu": "sudo passwd {user}",
        "rhel":   "sudo passwd {user}",
        "windows": "net user {user} NewStr0ngP@ss!",
    },
    "disable user": {
        "ubuntu": "sudo usermod -L {user}",
        "rhel":   "sudo usermod -L {user}",
        "windows": "net user {user} /active:no",
    },
}


class CommandBuilderTool(BaseTool):
    name: str = "command_builder"
    description: str = (
        "Build the correct runnable command for a given action on a specific OS. "
        "Returns the exact command string with placeholders filled where possible."
    )
    args_schema: Type[BaseModel] = CommandInput

    def _run(self, action: str, os_name: str, service: str = "") -> str:
        os_key = "ubuntu"
        for key in ["windows", "ubuntu", "debian", "rhel", "centos"]:
            if key in os_name.lower():
                os_key = key
                break

        action_lower = action.lower()
        results = []
        for pattern, os_cmds in _COMMAND_PATTERNS.items():
            # Match if ALL words in the pattern key appear in the action
            pattern_words = pattern.split()
            if all(word in action_lower for word in pattern_words):
                cmd = os_cmds.get(os_key, os_cmds.get("ubuntu", "N/A"))
                results.append(f"Action '{pattern}' on {os_key.upper()}:\n  {cmd}")

        if results:
            return "\n".join(results)
        return (
            f"No specific template for '{action}' on {os_name}. "
            f"Generate a {'Windows CMD/PowerShell' if os_key == 'windows' else 'Linux bash'} "
            f"command appropriate for this action on {os_name}."
        )


# =========================================================================== #
# Tool 4 — Mitigation Knowledge Base
# =========================================================================== #

class MitigationKnowledgeTool(BaseTool):
    name: str = "mitigation_knowledge"
    description: str = (
        "Retrieve detailed, step-by-step mitigation steps from the knowledge base "
        "for a given vulnerability. Returns all steps with full action details, "
        "file paths, commands, tools, and considerations."
    )
    args_schema: Type[BaseModel] = KnowledgeInput

    def _run(
        self,
        vuln_name: str,
        description: str = "",
        ip: str = "{ip}",
        port: str = "{port}",
        os_name: str = "{os}",
        os_category: str = "linux",
        assigned_to: str = "Security Engineer",
    ) -> str:
        template = find_template(vuln_name, description)
        if not template:
            return (
                f"No template found for '{vuln_name}'. "
                f"Generate custom steps based on security best practices for {os_name} ({os_category}). "
                f"IMPORTANT: All commands and paths MUST be specific to {os_name}. "
                f"Ensure each step covers: LOCATE, REMOVE (❌ bad example), REPLACE WITH (✅ good example), "
                f"file path, runnable command, tools used, and important consideration."
            )

        context = {
            "ip": ip,
            "port": port.split("/")[0].strip(),
            "os": os_name,
            "os_category": os_category,
            "assigned_to": assigned_to,
        }
        steps = render_steps(template, context)

        lines = [
            f"MITIGATION PLAN: {vuln_name}",
            f"Category : {template.category}",
            f"Severity : {template.severity}",
            f"CVSS     : {template.cvss_range}",
            f"Steps    : {len(steps)}",
            "",
        ]
        for step in steps:
            lines += [
                f"{'=' * 60}",
                f"Step {step.step_no:02d} | {step.task_name}",
                f"Assigned To  : {step.assigned_to}",
                f"File Path    : {step.file_path}",
                f"Command      : {step.command_to_run}",
                f"Tools Used   : {step.artifacts_tools_used}",
                f"⚠ Consider  : {step.important_consideration}",
                f"",
                f"ACTION:",
                step.action,
                "",
            ]
        return "\n".join(lines)


# =========================================================================== #
# Tool 5 — Risk Rater
# =========================================================================== #

_RISK_KEYWORDS = {
    "critical": ["remote code execution", "rce", "unauthenticated", "root access",
                 "privilege escalation", "default credential", "zero day"],
    "high": ["sql injection", "command injection", "path traversal", "authentication bypass",
             "xss stored", "deserialization", "missing patch", "eol", "end of life"],
    "medium": ["ssl", "tls", "weak cipher", "missing header", "information disclosure",
               "open port", "session fixation", "csrf"],
    "low": ["banner grab", "version disclosure", "self-signed", "weak password policy"],
}


class RiskRaterTool(BaseTool):
    name: str = "risk_rater"
    description: str = (
        "Estimate the risk severity and CVSS score range for a vulnerability "
        "based on the vulnerability name and plugin output."
    )
    args_schema: Type[BaseModel] = RiskInput

    def _run(self, vuln_name: str, plugin_output: str = "") -> str:
        combined = (vuln_name + " " + plugin_output).lower()

        for severity in ["critical", "high", "medium", "low"]:
            for kw in _RISK_KEYWORDS[severity]:
                if kw in combined:
                    cvss_map = {
                        "critical": "9.0–10.0",
                        "high": "7.0–8.9",
                        "medium": "4.0–6.9",
                        "low": "0.1–3.9",
                    }
                    return (
                        f"Estimated Severity : {severity.upper()}\n"
                        f"CVSS Range        : {cvss_map[severity]}\n"
                        f"Matched keyword   : '{kw}'\n"
                        f"Recommendation    : {'Immediate remediation required.' if severity in ('critical','high') else 'Remediate within standard patch cycle.'}"
                    )

        return (
            "Severity: MEDIUM (default — no specific risk keyword matched)\n"
            "CVSS Range: 4.0–6.9\n"
            "Note: Manual review recommended to confirm severity."
        )
