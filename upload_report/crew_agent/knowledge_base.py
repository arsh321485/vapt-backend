"""
Mitigation Knowledge Base v3 — OS-Profile-Driven, Dynamic Commands

Rules:
  1. Every term (shell, editor, service manager) comes from OSProfile — never hardcoded.
  2. Every command_fn returns ALL sub-paths mentioned in the action.
  3. Commands use exact, copy-pasteable syntax.
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Callable
from .os_classifier import OSProfile, OSFamily, get_profile


# ── Helpers ─────────────────────────────────────────────────────────────────

def _is_win(p: OSProfile) -> bool:
    return p.family == OSFamily.WINDOWS

def _port_num(port_str: str) -> str:
    return port_str.split("/")[0].strip()

def _section(title: str, body: str) -> str:
    bar = "─" * (60 - len(title) - 4)
    return f"# ── {title} {bar}\n{body.rstrip()}"


# ── Step dataclass ──────────────────────────────────────────────────────────

@dataclass
class MitigationStep:
    step_no:          int
    task_name:        str
    action_fn:        Callable[[OSProfile, dict], str]
    file_path_fn:     Callable[[OSProfile, dict], str]
    command_fn:       Callable[[OSProfile, dict], str]
    tools_fn:         Callable[[OSProfile, dict], str]
    consideration_fn: Callable[[OSProfile, dict], str]

    def render(self, profile: OSProfile, ctx: dict) -> dict:
        return {
            "step_no":                 self.step_no,
            "assigned_to":             ctx.get("assigned_to", "Security Engineer"),
            "task_name":               self.task_name,
            "action":                  self.action_fn(profile, ctx),
            "file_path":               self.file_path_fn(profile, ctx),
            "command_to_run":          self.command_fn(profile, ctx),
            "artifacts_tools_used":    self.tools_fn(profile, ctx),
            "important_consideration": self.consideration_fn(profile, ctx),
        }


@dataclass
class MitigationTemplate:
    vuln_pattern: str
    category:     str
    severity:     str
    cvss_range:   str
    steps:        List[MitigationStep]


# ===========================================================================
# TEMPLATE 1 — SSL/TLS Weak Cipher Suites
# ===========================================================================

def _s1_action(p: OSProfile, ctx: dict) -> str:
    ip, port = ctx["ip"], _port_num(ctx["port"])
    scan = p.ssl_scan.format(ip=ip, port=port)
    save = f"{scan} | Out-File C:\\Temp\\cipher_before.txt" if _is_win(p) else f"{scan} > /tmp/cipher_before.txt"
    return (
        f"Run an SSL cipher enumeration scan to capture all cipher suites currently supported.\n\n"
        f"LOCATE: {p.open_shell_admin}.\n\n"
        f"WHAT TO RUN:\n  {scan}\n\n"
        f"LOOK FOR (❌ these must be removed):\n"
        f"  - RC4-SHA, RC4-MD5\n  - DES-CBC3-SHA (3DES)\n"
        f"  - TLSv1.0 or TLSv1.1 cipher suites\n  - NULL, EXPORT, or ANON ciphers\n\n"
        f"SAVE OUTPUT for before/after comparison:\n  {save}\n\n"
        f"EXAMPLE output showing a vulnerable server:\n"
        f"  TLSv1.0:\n    ciphers:\n"
        f"      RC4-SHA - rsa 2048 --- C    ← ❌ weak\n"
        f"      DES-CBC3-SHA - rsa 2048 --- C ← ❌ weak"
    )

def _s1_cmd(p: OSProfile, ctx: dict) -> str:
    ip, port = ctx["ip"], _port_num(ctx["port"])
    scan = p.ssl_scan.format(ip=ip, port=port)
    if _is_win(p):
        return (
            _section("Run cipher scan — PowerShell", scan) + "\n\n" +
            _section("Save output to file — PowerShell", f"{scan} | Out-File C:\\Temp\\cipher_before.txt") + "\n\n" +
            _section("Verify file was saved — PowerShell", "Test-Path C:\\Temp\\cipher_before.txt")
        )
    return (
        _section("Run cipher scan — Terminal", scan) + "\n\n" +
        _section("Save output to file — Terminal", f"{scan} > /tmp/cipher_before.txt") + "\n\n" +
        _section("Verify file was saved — Terminal", "ls -lh /tmp/cipher_before.txt")
    )


def _s2_action(p: OSProfile, ctx: dict) -> str:
    if _is_win(p):
        return (
            f"Back up all SSL/TLS configuration files before making changes.\n\n"
            f"LOCATE: {p.open_shell_admin}.\n\n"
            f"WHERE the config files are:\n"
            f"  IIS    : Managed via IIS Manager\n"
            f"  Apache : {p.apache_ssl_conf}\n"
            f"  Nginx  : {p.nginx_ssl_conf}\n\n"
            f"WHAT TO DO:\n\n"
            f"  ❌ Do NOT edit any file without backing it up first.\n\n"
            f"  ✅ Backup Apache SSL config:\n"
            f"    {p.copy_file.format(src=p.apache_ssl_conf, dst=p.apache_ssl_conf + '.bak')}\n\n"
            f"  ✅ Backup Nginx config:\n"
            f"    {p.copy_file.format(src=p.nginx_ssl_conf, dst=p.nginx_ssl_conf + '.bak')}\n\n"
            f"  ✅ Export IIS SSL bindings (PowerShell):\n"
            f"    Get-WebConfiguration 'system.webServer/security/access' | Export-Clixml 'C:\\Backup\\iis_ssl_backup.xml'\n\n"
            f"VERIFY backups exist:\n"
            f"  Test-Path '{p.apache_ssl_conf}.bak'\n"
            f"  Test-Path 'C:\\Backup\\iis_ssl_backup.xml'"
        )
    date_tag = "$(date +%Y%m%d_%H%M%S)"
    return (
        f"Back up all SSL/TLS configuration files before making changes.\n\n"
        f"LOCATE: {p.open_shell_admin}.\n\n"
        f"WHERE the config files are:\n"
        f"  Apache: {p.apache_ssl_conf}\n"
        f"  Nginx : {p.nginx_ssl_conf}\n\n"
        f"WHAT TO DO:\n\n"
        f"  ❌ Do NOT edit any file without backing it up first.\n\n"
        f"  ✅ Backup Apache SSL config:\n"
        f"    cp {p.apache_ssl_conf} {p.apache_ssl_conf}.bak_{date_tag}\n\n"
        f"  ✅ Backup Nginx SSL config:\n"
        f"    cp {p.nginx_ssl_conf} {p.nginx_ssl_conf}.bak_{date_tag}\n\n"
        f"VERIFY backups exist:\n"
        f"  ls -lh {p.apache_ssl_conf}.bak_*\n"
        f"  ls -lh {p.nginx_ssl_conf}.bak_*"
    )

def _s2_cmd(p: OSProfile, ctx: dict) -> str:
    if _is_win(p):
        a_bak = p.apache_ssl_conf + ".bak"
        n_bak = p.nginx_ssl_conf + ".bak"
        return (
            _section("Backup Apache SSL config — PowerShell", p.copy_file.format(src=p.apache_ssl_conf, dst=a_bak)) + "\n\n" +
            _section("Backup Nginx config — PowerShell", p.copy_file.format(src=p.nginx_ssl_conf, dst=n_bak)) + "\n\n" +
            _section("Export IIS SSL bindings — PowerShell",
                "Get-WebConfiguration 'system.webServer/security/access' |\n"
                "  Export-Clixml 'C:\\Backup\\iis_ssl_backup.xml'") + "\n\n" +
            _section("Verify all backups exist — PowerShell",
                f"Test-Path '{a_bak}'\nTest-Path '{n_bak}'\nTest-Path 'C:\\Backup\\iis_ssl_backup.xml'")
        )
    date_tag = "$(date +%Y%m%d_%H%M%S)"
    return (
        _section("Backup Apache SSL config — Terminal", f"cp {p.apache_ssl_conf} {p.apache_ssl_conf}.bak_{date_tag}") + "\n\n" +
        _section("Backup Nginx SSL config — Terminal", f"cp {p.nginx_ssl_conf} {p.nginx_ssl_conf}.bak_{date_tag}") + "\n\n" +
        _section("Verify backups exist — Terminal",
            f"ls -lh {p.apache_ssl_conf}.bak_*\nls -lh {p.nginx_ssl_conf}.bak_*")
    )


def _s3_action(p: OSProfile, ctx: dict) -> str:
    if _is_win(p):
        return (
            f"Disable TLS 1.0 and TLS 1.1 on Windows via the Registry (applies globally to IIS, RDP, Schannel).\n\n"
            f"LOCATE: {p.open_shell_admin}.\n\n"
            f"WHAT TO REMOVE (❌ current insecure registry state):\n"
            f"  Key: Protocols\\TLS 1.0\\Server → DWORD 'Enabled' = 1\n"
            f"  Key: Protocols\\TLS 1.1\\Server → DWORD 'Enabled' = 1\n\n"
            f"WHAT TO REPLACE WITH (✅ run in {p.shell_label} as Administrator):\n\n"
            f"  # Disable TLS 1.0\n"
            f"  $path10 = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server'\n"
            f"  New-Item -Path $path10 -Force | Out-Null\n"
            f"  Set-ItemProperty -Path $path10 -Name 'Enabled' -Value 0 -Type DWord\n"
            f"  Set-ItemProperty -Path $path10 -Name 'DisabledByDefault' -Value 1 -Type DWord\n\n"
            f"  # Disable TLS 1.1\n"
            f"  $path11 = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server'\n"
            f"  New-Item -Path $path11 -Force | Out-Null\n"
            f"  Set-ItemProperty -Path $path11 -Name 'Enabled' -Value 0 -Type DWord\n"
            f"  Set-ItemProperty -Path $path11 -Name 'DisabledByDefault' -Value 1 -Type DWord\n\n"
            f"  FOR Apache — also update {p.apache_ssl_conf}:\n"
            f"  ❌ Remove: SSLProtocol all\n"
            f"  ✅ Replace: SSLProtocol -all +TLSv1.2 +TLSv1.3\n\n"
            f"  FOR Nginx — also update {p.nginx_ssl_conf}:\n"
            f"  ❌ Remove: ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"
            f"  ✅ Replace: ssl_protocols TLSv1.2 TLSv1.3;\n\n"
            f"⚠ A full system REBOOT is required after registry changes."
        )
    return (
        f"Remove TLS 1.0 and TLS 1.1 from the web server SSL config.\n\n"
        f"LOCATE: {p.open_shell_admin}.\n\n"
        f"Open the SSL config file:\n"
        f"  Apache: {p.open_editor.format(file=p.apache_ssl_conf)}\n"
        f"  Nginx:  {p.open_editor.format(file=p.nginx_ssl_conf)}\n\n"
        f"WHAT TO REMOVE (❌):\n"
        f"  Apache: SSLProtocol all  OR  SSLProtocol TLSv1 TLSv1.1 TLSv1.2\n"
        f"  Nginx:  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n\n"
        f"WHAT TO REPLACE WITH (✅):\n"
        f"  Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
        f"  Nginx:  ssl_protocols TLSv1.2 TLSv1.3;\n\n"
        f"VERIFY config is valid:\n"
        f"  {p.apache_validate}   → must return: Syntax OK\n"
        f"  {p.nginx_validate}    → must return: syntax is ok"
    )

def _s3_cmd(p: OSProfile, ctx: dict) -> str:
    if _is_win(p):
        return (
            _section("Disable TLS 1.0 — PowerShell as Administrator",
                "$path10 = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server'\n"
                "New-Item -Path $path10 -Force | Out-Null\n"
                "Set-ItemProperty -Path $path10 -Name 'Enabled' -Value 0 -Type DWord\n"
                "Set-ItemProperty -Path $path10 -Name 'DisabledByDefault' -Value 1 -Type DWord") + "\n\n" +
            _section("Disable TLS 1.1 — PowerShell as Administrator",
                "$path11 = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server'\n"
                "New-Item -Path $path11 -Force | Out-Null\n"
                "Set-ItemProperty -Path $path11 -Name 'Enabled' -Value 0 -Type DWord\n"
                "Set-ItemProperty -Path $path11 -Name 'DisabledByDefault' -Value 1 -Type DWord") + "\n\n" +
            _section("Update Apache config — Notepad",
                f'notepad "{p.apache_ssl_conf}"\n'
                "# FIND:    SSLProtocol all\n# REPLACE: SSLProtocol -all +TLSv1.2 +TLSv1.3") + "\n\n" +
            _section("Update Nginx config — Notepad",
                f'notepad "{p.nginx_ssl_conf}"\n'
                "# FIND:    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n# REPLACE: ssl_protocols TLSv1.2 TLSv1.3;") + "\n\n" +
            _section("Verify registry change — PowerShell",
                "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server'\n"
                "# Expected → Enabled: 0")
        )
    return (
        _section("Find protocol line in Apache config — Terminal",
            f"{p.grep_file.format(pattern='SSLProtocol', file=p.apache_ssl_conf)}") + "\n\n" +
        _section("Edit Apache SSL config — Terminal",
            f"{p.open_editor.format(file=p.apache_ssl_conf)}\n"
            "  # FIND:    SSLProtocol all\n  # REPLACE: SSLProtocol -all +TLSv1.2 +TLSv1.3") + "\n\n" +
        _section("Find protocol line in Nginx config — Terminal",
            f"{p.grep_file.format(pattern='ssl_protocols', file=p.nginx_ssl_conf)}") + "\n\n" +
        _section("Edit Nginx SSL config — Terminal",
            f"{p.open_editor.format(file=p.nginx_ssl_conf)}\n"
            "  # FIND:    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n  # REPLACE: ssl_protocols TLSv1.2 TLSv1.3;") + "\n\n" +
        _section("Validate configs — Terminal",
            f"{p.apache_validate}    # must return: Syntax OK\n"
            f"{p.nginx_validate}     # must return: syntax is ok")
    )


def _s4_action(p: OSProfile, ctx: dict) -> str:
    if _is_win(p):
        return (
            f"Disable weak cipher suites at the Windows OS level.\n\n"
            f"LOCATE: {p.open_shell_admin}.\n\n"
            f"LIST current ciphers:\n"
            f"  Get-TlsCipherSuite | Select-Object Name | Sort-Object Name\n\n"
            f"WHAT TO REMOVE (❌ disable if present):\n"
            f"  TLS_RSA_WITH_RC4_128_SHA\n  TLS_RSA_WITH_RC4_128_MD5\n  TLS_RSA_WITH_3DES_EDE_CBC_SHA\n\n"
            f"WHAT TO REPLACE WITH (✅):\n"
            f"  Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_SHA'\n"
            f"  Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_MD5'\n"
            f"  Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'\n\n"
            f"WHERE Apache ({p.apache_ssl_conf}):\n"
            f"  ❌ Remove: SSLCipherSuite ALL:!EXP:!NULL\n"
            f"  ✅ Replace: SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\n"
            f"             SSLHonorCipherOrder on\n\n"
            f"WHERE Nginx ({p.nginx_ssl_conf}):\n"
            f"  ❌ Remove: ssl_ciphers HIGH:!aNULL:!MD5;\n"
            f"  ✅ Replace: ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\n"
            f"             ssl_prefer_server_ciphers on;"
        )
    return (
        f"Replace the insecure cipher suite list with a strong, modern configuration.\n\n"
        f"LOCATE: {p.open_shell_admin}.\n\n"
        f"Open the SSL config file:\n"
        f"  Apache: {p.open_editor.format(file=p.apache_ssl_conf)}\n"
        f"  Nginx:  {p.open_editor.format(file=p.nginx_ssl_conf)}\n\n"
        f"WHAT TO REMOVE (❌):\n"
        f"  Apache: SSLCipherSuite ALL:!EXP:!NULL\n"
        f"  Nginx:  ssl_ciphers HIGH:!aNULL:!MD5;\n\n"
        f"WHAT TO REPLACE WITH (✅):\n"
        f"  Apache: SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\n"
        f"          SSLHonorCipherOrder on\n"
        f"  Nginx:  ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\n"
        f"          ssl_prefer_server_ciphers on;\n\n"
        f"VERIFY no weak ciphers remain:\n"
        f"  grep -iE 'RC4|3DES|MD5|NULL|EXPORT' {p.apache_ssl_conf}\n"
        f"  → No output = no weak ciphers ✅"
    )

def _s4_cmd(p: OSProfile, ctx: dict) -> str:
    if _is_win(p):
        return (
            _section("List all current cipher suites — PowerShell",
                "Get-TlsCipherSuite | Select-Object Name | Sort-Object Name") + "\n\n" +
            _section("Disable RC4 ciphers — PowerShell as Administrator",
                "Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_SHA'\n"
                "Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_MD5'") + "\n\n" +
            _section("Disable 3DES cipher — PowerShell as Administrator",
                "Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'") + "\n\n" +
            _section("Update Apache cipher config — Notepad",
                f'notepad "{p.apache_ssl_conf}"\n'
                "  # FIND:    SSLCipherSuite ALL:!EXP:!NULL\n"
                "  # REPLACE: SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\n"
                "  #          SSLHonorCipherOrder on") + "\n\n" +
            _section("Update Nginx cipher config — Notepad",
                f'notepad "{p.nginx_ssl_conf}"\n'
                "  # FIND:    ssl_ciphers HIGH:!aNULL:!MD5;\n"
                "  # REPLACE: ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\n"
                "  #          ssl_prefer_server_ciphers on;") + "\n\n" +
            _section("Confirm weak ciphers removed — PowerShell",
                "Get-TlsCipherSuite | Where-Object {$_.Name -match 'RC4|3DES|NULL|EXPORT'}\n"
                "# Expected: no output")
        )
    return (
        _section("Find cipher line in Apache config — Terminal",
            f"{p.grep_file.format(pattern='SSLCipherSuite', file=p.apache_ssl_conf)}") + "\n\n" +
        _section("Edit Apache SSL config — Terminal",
            f"{p.open_editor.format(file=p.apache_ssl_conf)}\n"
            "  # FIND:    SSLCipherSuite ALL:!EXP:!NULL\n"
            "  # REPLACE: SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\n"
            "  #          SSLHonorCipherOrder on") + "\n\n" +
        _section("Edit Nginx SSL config — Terminal",
            f"{p.open_editor.format(file=p.nginx_ssl_conf)}\n"
            "  # FIND:    ssl_ciphers HIGH:!aNULL:!MD5;\n"
            "  # REPLACE: ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\n"
            "  #          ssl_prefer_server_ciphers on;") + "\n\n" +
        _section("Verify no weak ciphers remain — Terminal",
            f"grep -iE 'RC4|3DES|MD5|NULL|EXPORT' {p.apache_ssl_conf}\n"
            f"grep -iE 'RC4|3DES|MD5|NULL|EXPORT' {p.nginx_ssl_conf}\n"
            "# Expected: no output from either command")
    )


def _s5_action(p: OSProfile, ctx: dict) -> str:
    if _is_win(p):
        return (
            f"Validate the config and restart all affected services.\n\n"
            f"LOCATE: {p.open_shell_admin}.\n\n"
            f"VALIDATE before restarting:\n"
            f"  Apache: {p.apache_validate}  → Must return: httpd.exe: Syntax OK\n"
            f"  Nginx:  {p.nginx_validate}   → Must return: syntax is ok\n\n"
            f"RESTART each applicable service:\n"
            f"  ✅ IIS:    iisreset /restart\n"
            f"  ✅ Apache: {p.apache_restart_cmd}\n"
            f"  ✅ Nginx:  {p.nginx_restart_cmd}\n\n"
            f"VERIFY each service is running:\n"
            f"  {p.svc_status.format(svc='W3SVC')}         # IIS\n"
            f"  {p.svc_status.format(svc=p.apache_svc_name)}   # Apache\n\n"
            f"⚠ Registry TLS changes (Step 3) require a FULL REBOOT."
        )
    return (
        f"Validate configuration files and restart the web server.\n\n"
        f"LOCATE: {p.open_shell_admin}.\n\n"
        f"VALIDATE before restarting (REQUIRED):\n"
        f"  Apache: {p.apache_validate}  → Must return: Syntax OK\n"
        f"  Nginx:  {p.nginx_validate}   → Must return: syntax is ok\n\n"
        f"RESTART each applicable service:\n"
        f"  ✅ Apache ({p.apache_svc_name}): {p.apache_restart_cmd}\n"
        f"  ✅ Nginx  ({p.nginx_svc_name}):  {p.nginx_restart_cmd}\n\n"
        f"VERIFY the service is running:\n"
        f"  {p.svc_status.format(svc=p.apache_svc_name)}\n"
        f"  → Active: active (running) = success ✅"
    )

def _s5_cmd(p: OSProfile, ctx: dict) -> str:
    if _is_win(p):
        return (
            _section("Validate Apache config — PowerShell", p.apache_validate) + "\n\n" +
            _section("Validate Nginx config — PowerShell", p.nginx_validate) + "\n\n" +
            _section("Restart IIS — PowerShell as Administrator", "iisreset /restart") + "\n\n" +
            _section(f"Restart Apache ({p.apache_svc_name}) — PowerShell", p.apache_restart_cmd) + "\n\n" +
            _section("Verify services running — PowerShell",
                f"{p.svc_status.format(svc='W3SVC')}\n{p.svc_status.format(svc=p.apache_svc_name)}\n# Expected: Status = Running")
        )
    return (
        _section("Validate Apache config — Terminal", f"{p.apache_validate}\n# Must return: Syntax OK") + "\n\n" +
        _section("Validate Nginx config — Terminal", f"{p.nginx_validate}\n# Must return: syntax is ok") + "\n\n" +
        _section(f"Restart Apache ({p.apache_svc_name}) — Terminal", p.apache_restart_cmd) + "\n\n" +
        _section(f"Restart Nginx ({p.nginx_svc_name}) — Terminal", p.nginx_restart_cmd) + "\n\n" +
        _section("Verify services active — Terminal",
            f"{p.svc_status.format(svc=p.apache_svc_name)}\n{p.svc_status.format(svc=p.nginx_svc_name)}\n# Expected: Active: active (running)") + "\n\n" +
        _section("Check logs for errors — Terminal",
            f"{p.tail_log.format(file=p.apache_log_error)}\n{p.tail_log.format(file=p.nginx_log_error)}")
    )


def _s6_action(p: OSProfile, ctx: dict) -> str:
    ip, port = ctx["ip"], _port_num(ctx["port"])
    scan = p.ssl_scan.format(ip=ip, port=port)
    if _is_win(p):
        return (
            f"Re-run the cipher scan and confirm all weak ciphers are removed.\n\n"
            f"LOCATE: {p.open_shell_admin}.\n\n"
            f"WHAT TO RUN:\n  {scan} | Out-File C:\\Temp\\cipher_after.txt\n\n"
            f"WHAT YOU SHOULD NOT SEE (❌ FAIL):\n  - RC4, 3DES, MD5, NULL, EXPORT ciphers\n  - TLSv1.0 or TLSv1.1\n\n"
            f"WHAT YOU SHOULD SEE (✅ PASS):\n  - TLSv1.2 and/or TLSv1.3 only\n  - AES128-GCM or AES256-GCM ciphers\n\n"
            f"COMPARE before/after:\n  Compare-Object (Get-Content C:\\Temp\\cipher_before.txt) (Get-Content C:\\Temp\\cipher_after.txt)\n\n"
            f"EXTERNAL VALIDATION:\n  Visit https://www.ssllabs.com/ssltest/  →  target grade: A or A+"
        )
    return (
        f"Re-run the cipher scan and confirm all weak ciphers have been removed.\n\n"
        f"LOCATE: {p.open_shell_user}.\n\n"
        f"WHAT TO RUN:\n  {scan} > /tmp/cipher_after.txt\n\n"
        f"WHAT YOU SHOULD NOT SEE (❌ FAIL):\n  - RC4, 3DES, MD5, NULL, EXPORT ciphers\n  - TLSv1.0 or TLSv1.1\n\n"
        f"WHAT YOU SHOULD SEE (✅ PASS):\n  - TLSv1.2 and/or TLSv1.3 only\n  - AES128-GCM or AES256-GCM ciphers\n\n"
        f"COMPARE before/after:\n  diff /tmp/cipher_before.txt /tmp/cipher_after.txt\n\n"
        f"EXTERNAL VALIDATION:\n  Visit https://www.ssllabs.com/ssltest/  →  target grade: A or A+"
    )

def _s6_cmd(p: OSProfile, ctx: dict) -> str:
    ip, port = ctx["ip"], _port_num(ctx["port"])
    scan = p.ssl_scan.format(ip=ip, port=port)
    if _is_win(p):
        return (
            _section("Run post-fix cipher scan — PowerShell", f"{scan} | Out-File C:\\Temp\\cipher_after.txt") + "\n\n" +
            _section("Compare before vs after — PowerShell",
                "Compare-Object (Get-Content C:\\Temp\\cipher_before.txt) (Get-Content C:\\Temp\\cipher_after.txt)") + "\n\n" +
            _section("Check for weak ciphers still present — PowerShell",
                "Select-String -Path C:\\Temp\\cipher_after.txt -Pattern 'RC4|3DES|MD5|NULL|EXPORT'\n# Expected: no matches") + "\n\n" +
            _section("Monitor Apache error log — PowerShell", p.tail_log.format(file=p.apache_log_error))
        )
    return (
        _section("Run post-fix cipher scan — Terminal", f"{scan} > /tmp/cipher_after.txt") + "\n\n" +
        _section("Compare before vs after — Terminal", "diff /tmp/cipher_before.txt /tmp/cipher_after.txt") + "\n\n" +
        _section("Check for weak ciphers still present — Terminal",
            "grep -iE 'RC4|3DES|MD5|NULL|EXPORT' /tmp/cipher_after.txt\n# Expected: no output") + "\n\n" +
        _section("Monitor Apache error log — Terminal",
            f"{p.tail_log.format(file=p.apache_log_error)} | grep -iE 'ssl|handshake|no shared cipher'") + "\n\n" +
        _section("Monitor Nginx error log — Terminal",
            f"{p.tail_log.format(file=p.nginx_log_error)} | grep -iE 'ssl|handshake|no shared cipher'")
    )


SSL_WEAK_CIPHER = MitigationTemplate(
    vuln_pattern = r"ssl|tls|cipher|weak cipher|rc4|3des|des|md5|export cipher|null cipher",
    category     = "Cryptographic Weakness",
    severity     = "Medium",
    cvss_range   = "4.0–6.9",
    steps        = [
        MitigationStep(1, "Identify Supported Ciphers — Baseline Scan",
            _s1_action, lambda p, c: "N/A", _s1_cmd,
            lambda p, c: f"Nmap, {p.shell_label}",
            lambda p, c: "Save baseline output BEFORE the fix. Required for audit evidence."),
        MitigationStep(2, "Backup SSL Configuration Files",
            _s2_action,
            lambda p, c: (
                f"IIS: export via PowerShell | Apache: {p.apache_ssl_conf} | Nginx: {p.nginx_ssl_conf}"
                if _is_win(p) else f"Apache: {p.apache_ssl_conf} | Nginx: {p.nginx_ssl_conf}"
            ),
            _s2_cmd,
            lambda p, c: (f"{p.shell_label}, Export-Clixml, {p.editor_name}" if _is_win(p) else f"{p.shell_label}, cp, tar"),
            lambda p, c: "Never skip backup. It is the only way to safely rollback if something breaks."),
        MitigationStep(3, "Disable Weak TLS Protocols (TLS 1.0 and TLS 1.1)",
            _s3_action,
            lambda p, c: (
                f"IIS/Schannel: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols | Apache: {p.apache_ssl_conf} | Nginx: {p.nginx_ssl_conf}"
                if _is_win(p) else f"Apache: {p.apache_ssl_conf} | Nginx: {p.nginx_ssl_conf}"
            ),
            _s3_cmd,
            lambda p, c: (f"{p.shell_label}, regedit, {p.editor_name}" if _is_win(p) else f"{p.shell_label}, {p.editor_name}, {p.apache_validate}, {p.nginx_validate}"),
            lambda p, c: (
                "FULL SYSTEM REBOOT required after registry changes — iisreset alone does NOT apply Schannel changes."
                if _is_win(p) else "Old clients using TLS 1.0/1.1 will stop connecting. Confirm business impact before applying."
            )),
        MitigationStep(4, "Remove Weak Ciphers and Configure Strong Cipher Suites",
            _s4_action,
            lambda p, c: (
                f"Schannel Registry | Apache: {p.apache_ssl_conf} | Nginx: {p.nginx_ssl_conf}"
                if _is_win(p) else f"Apache: {p.apache_ssl_conf} | Nginx: {p.nginx_ssl_conf}"
            ),
            _s4_cmd,
            lambda p, c: (f"{p.shell_label}, Disable-TlsCipherSuite, {p.editor_name}" if _is_win(p) else f"{p.shell_label}, {p.editor_name}, grep"),
            lambda p, c: (
                "IIS Crypto by Nartac Software (free) is the safest option on Windows."
                if _is_win(p) else "Replace the ENTIRE SSLCipherSuite/ssl_ciphers line. Never mix strong and weak ciphers."
            )),
        MitigationStep(5, "Restart Services and Apply Changes",
            _s5_action, lambda p, c: "N/A", _s5_cmd,
            lambda p, c: (f"iisreset, {p.shell_label}, {p.apache_validate}, {p.nginx_validate}" if _is_win(p) else f"{p.shell_label}, systemctl, {p.apache_validate}, {p.nginx_validate}"),
            lambda p, c: (
                "Registry TLS changes (Step 3) require a FULL REBOOT. Config-only changes only need service restart."
                if _is_win(p) else "Always run configtest/nginx -t before restarting. A failed restart on production causes downtime."
            )),
        MitigationStep(6, "Verify Fix and Monitor",
            _s6_action, lambda p, c: "N/A", _s6_cmd,
            lambda p, c: f"Nmap, {p.shell_label}, SSL Labs (ssllabs.com)",
            lambda p, c: "Screenshot the clean scan output and attach to the Nessus ticket as proof."),
    ]
)


# ===========================================================================
# TEMPLATE 2 — Default / Weak Credentials
# ===========================================================================

def _c1_action(p, ctx):
    ip = ctx["ip"]
    if _is_win(p):
        return (
            f"Enumerate all local accounts and identify those with default, weak, or blank credentials.\n\n"
            f"LOCATE: {p.open_shell_admin}.\n\n"
            f"WHAT TO RUN:\n  {p.list_users}\n\n"
            f"IDENTIFY blank-password accounts:\n"
            f"  Get-LocalUser | Where-Object {{$_.PasswordRequired -eq $false}}\n"
            f"  → Any result = account with no password required = ❌ critical risk\n\n"
            f"LOOK FOR (❌ accounts to address):\n"
            f"  - Administrator: blank, admin, Password1, Welcome1\n"
            f"  - Guest: should be disabled\n  - DefaultAccount: should be disabled"
        )
    return (
        f"Enumerate all local accounts and identify those with default, weak, or blank credentials.\n\n"
        f"LOCATE: {p.open_shell_admin}.\n  SSH to target: ssh user@{ip}\n\n"
        f"WHAT TO RUN:\n  {p.list_users}\n\n"
        f"IDENTIFY blank-password accounts:\n"
        f"  sudo awk -F: '($2 == \"\" || $2 == \"!\") {{print \"BLANK/LOCKED:\", $1}}' /etc/shadow\n\n"
        f"LOOK FOR (❌ accounts to address):\n"
        f"  - root with password: root, toor, blank\n"
        f"  - admin, ubuntu, ec2-user with cloud default passwords\n"
        f"  - Service accounts (mysql, postgres, redis) with interactive shells"
    )

def _c1_cmd(p, ctx):
    if _is_win(p):
        return (
            _section("List all local users — PowerShell", p.list_users) + "\n\n" +
            _section("Find accounts without password required — PowerShell",
                "Get-LocalUser | Where-Object {$_.PasswordRequired -eq $false}")
        )
    return (
        _section("List all non-system users — Terminal", p.list_users) + "\n\n" +
        _section("Find accounts with blank passwords — Terminal",
            "sudo awk -F: '($2 == \"\" || $2 == \"!\") {print \"Issue:\", $1}' /etc/shadow") + "\n\n" +
        _section("List accounts with interactive shells — Terminal",
            "grep -vE '/nologin|/false|/sync' /etc/passwd | cut -d: -f1,7")
    )

def _c2_action(p, ctx):
    if _is_win(p):
        return (
            f"Change all default and weak passwords to strong, unique credentials.\n\n"
            f"LOCATE: {p.open_shell_admin} on {ctx['ip']}.\n\n"
            f"WHAT TO REMOVE (❌): Administrator: admin, Password1, Welcome1, [blank]\n\n"
            f"WHAT TO REPLACE WITH (✅): Minimum 14 characters, mixed case, numbers, symbols\n"
            f"  Example: Xk9#mRvL2@wZqT7!\n  Store immediately in your password vault.\n\n"
            f"COMMAND:\n  {p.change_password.format(user='Administrator')}\n\n"
            f"WHERE: Apply to every account identified in Step 1 on {ctx['ip']}."
        )
    return (
        f"Change all default and weak passwords to strong, unique credentials.\n\n"
        f"LOCATE: {p.open_shell_admin} on {ctx['ip']}.\n\n"
        f"WHAT TO REMOVE (❌): root:root, admin:admin, ubuntu:ubuntu, [blank]\n\n"
        f"WHAT TO REPLACE WITH (✅): Minimum 16 characters, mixed case, numbers, symbols\n"
        f"  Example: T7#mKx9!qRvL2@wZ\n  Store immediately in your password vault.\n\n"
        f"COMMAND:\n  {p.change_password.format(user='<username>')}\n"
        f"  → You will be prompted to enter and confirm the new password.\n\n"
        f"WHERE: Apply on {ctx['ip']} for each account from Step 1."
    )

def _c2_cmd(p, ctx):
    if _is_win(p):
        return (
            _section("Change local Administrator password — PowerShell", p.change_password.format(user="Administrator")) + "\n\n" +
            _section("Change local user password — PowerShell", p.change_password.format(user="<username>")) + "\n\n" +
            _section("Verify password is now required — PowerShell",
                "Get-LocalUser -Name '<username>' | Select-Object Name,PasswordRequired\n# Expected: PasswordRequired = True")
        )
    return (
        _section("Change password for a user — Terminal", p.change_password.format(user="<username>")) + "\n\n" +
        _section("Force password change on next login — Terminal", "sudo chage -d 0 <username>") + "\n\n" +
        _section("Verify the password was set — Terminal",
            "sudo grep '^<username>:' /etc/shadow | cut -d: -f2\n# Expected: a hashed string, NOT empty or '!'")
    )

def _c3_action(p, ctx):
    if _is_win(p):
        return (
            f"Disable all unnecessary default accounts.\n\n"
            f"LOCATE: {p.open_shell_admin}.\n\n"
            f"WHAT TO REMOVE (❌): Guest → always disable | DefaultAccount → always disable\n\n"
            f"WHAT TO DO (✅):\n"
            f"  {p.disable_account.format(user='Guest')}\n"
            f"  {p.disable_account.format(user='DefaultAccount')}\n\n"
            f"VERIFY:\n  Get-LocalUser | Select-Object Name, Enabled\n"
            f"  → Guest: Enabled = False ✅\n  → DefaultAccount: Enabled = False ✅"
        )
    return (
        f"Disable unnecessary default accounts that have interactive shell access.\n\n"
        f"LOCATE: {p.open_shell_admin}.\n\n"
        f"IDENTIFY unnecessary accounts:\n  grep -vE '/nologin|/false' /etc/passwd | cut -d: -f1,7\n\n"
        f"WHAT TO DO (✅ lock preferred — preserves file ownership):\n"
        f"  Lock: {p.lock_account.format(user='<username>')}\n"
        f"  Or disable shell: {p.disable_account.format(user='<username>')}\n\n"
        f"VERIFY:\n  sudo passwd -S <username>\n  → Should show: L (locked) ✅"
    )

def _c3_cmd(p, ctx):
    if _is_win(p):
        return (
            _section("Disable Guest account — PowerShell as Administrator", p.disable_account.format(user="Guest")) + "\n\n" +
            _section("Disable DefaultAccount — PowerShell as Administrator", p.disable_account.format(user="DefaultAccount")) + "\n\n" +
            _section("Verify both accounts are disabled — PowerShell",
                "Get-LocalUser | Select-Object Name, Enabled\n# Guest: Enabled = False\n# DefaultAccount: Enabled = False")
        )
    return (
        _section("Find accounts with interactive shells — Terminal",
            "grep -vE '/nologin|/false' /etc/passwd | cut -d: -f1,7") + "\n\n" +
        _section("Lock an account — Terminal", p.lock_account.format(user="<username>")) + "\n\n" +
        _section("Disable shell access — Terminal", p.disable_account.format(user="<username>")) + "\n\n" +
        _section("Verify account is locked — Terminal",
            "sudo passwd -S <username>\n# Expected: <username> L ... (L = locked)")
    )

DEFAULT_CREDENTIALS = MitigationTemplate(
    vuln_pattern = r"default credential|default password|weak password|default login|default account",
    category     = "Authentication Weakness",
    severity     = "Critical",
    cvss_range   = "9.0–10.0",
    steps        = [
        MitigationStep(1, "Enumerate and Identify Default or Weak Accounts",
            _c1_action,
            lambda p, c: ("SAM / Active Directory" if _is_win(p) else "/etc/passwd, /etc/shadow"),
            _c1_cmd,
            lambda p, c: (f"{p.shell_label}, Get-LocalUser" if _is_win(p) else f"{p.shell_label}, awk, /etc/shadow"),
            lambda p, c: "Document all accounts found before changes. Do not skip — service accounts may be dependencies."),
        MitigationStep(2, "Change All Default and Weak Passwords",
            _c2_action, lambda p, c: "N/A", _c2_cmd,
            lambda p, c: (f"{p.shell_label}, Set-ADAccountPassword, password vault" if _is_win(p) else f"{p.shell_label}, passwd, password vault"),
            lambda p, c: "Store new credentials in a vault immediately. NEVER record passwords in tickets or emails."),
        MitigationStep(3, "Disable Unnecessary Default Accounts",
            _c3_action,
            lambda p, c: ("SAM / Active Directory" if _is_win(p) else "/etc/passwd, /etc/shadow"),
            _c3_cmd,
            lambda p, c: (f"{p.shell_label}, Disable-LocalUser" if _is_win(p) else f"{p.shell_label}, usermod, passwd"),
            lambda p, c: "Confirm with the application team before disabling any service account."),
    ]
)


# ===========================================================================
# TEMPLATE 3 — Open Ports / Unnecessary Services
# ===========================================================================

def _p1_action(p, ctx):
    port = _port_num(ctx["port"])
    ip   = ctx["ip"]
    if _is_win(p):
        return (
            f"Confirm which service is bound to port {port} and whether it is required.\n\n"
            f"LOCATE: {p.open_shell_admin}.\n\n"
            f"WHAT TO RUN:\n"
            f"  netstat -ano | findstr :{port}\n"
            f"  → Note the PID in the rightmost column\n"
            f"  {p.find_process.format(proc='<PID>')}  → identifies the process name\n\n"
            f"DECIDE:\n"
            f"  - Not required → disable in Step 2\n"
            f"  - Required → restrict access via {p.firewall_tool} in Step 3"
        )
    return (
        f"Confirm which service is bound to port {port} and whether it is required.\n\n"
        f"LOCATE: {p.open_shell_admin}.\n\n"
        f"WHAT TO RUN:\n"
        f"  {p.list_ports} | grep :{port}\n"
        f"  nmap -sV -p {port} {ip}\n\n"
        f"DECIDE:\n"
        f"  - Not required → disable in Step 2\n"
        f"  - Required → restrict via {p.firewall_tool} in Step 3"
    )

def _p1_cmd(p, ctx):
    port = _port_num(ctx["port"])
    ip   = ctx["ip"]
    if _is_win(p):
        return (
            _section(f"Find what holds port {port} — PowerShell", f"netstat -ano | findstr :{port}") + "\n\n" +
            _section("Identify process by PID — PowerShell", "Get-Process -Id <PID_from_above>")
        )
    return (
        _section(f"Find what holds port {port} — Terminal", f"{p.list_ports} | grep :{port}") + "\n\n" +
        _section("Identify service with Nmap — Terminal", f"nmap -sV -p {port} {ip}")
    )

def _p2_action(p, ctx):
    port = _port_num(ctx["port"])
    if _is_win(p):
        return (
            f"Stop and disable the service running on port {port}.\n\n"
            f"LOCATE: {p.open_shell_admin}.\n\n"
            f"WHAT TO REMOVE (❌):\n"
            f"  {p.svc_stop.format(svc='<ServiceName>')}\n"
            f"  {p.svc_disable.format(svc='<ServiceName>')}\n\n"
            f"VERIFY port is closed:\n"
            f"  netstat -ano | findstr :{port}\n  → No output = port closed ✅"
        )
    return (
        f"Stop and disable the service running on port {port}.\n\n"
        f"LOCATE: {p.open_shell_admin}.\n\n"
        f"WHAT TO REMOVE (❌):\n"
        f"  {p.svc_stop.format(svc='<service_name>')}\n"
        f"  {p.svc_disable.format(svc='<service_name>')}\n\n"
        f"VERIFY port is closed:\n"
        f"  {p.list_ports} | grep :{port}\n  → No output = port closed ✅"
    )

def _p2_cmd(p, ctx):
    port = _port_num(ctx["port"])
    if _is_win(p):
        return (
            _section("Stop the service — PowerShell as Administrator", p.svc_stop.format(svc="<ServiceName>")) + "\n\n" +
            _section("Disable from auto-starting — PowerShell", p.svc_disable.format(svc="<ServiceName>")) + "\n\n" +
            _section(f"Verify port {port} is closed — PowerShell",
                f"netstat -ano | findstr :{port}\n# Expected: no output")
        )
    return (
        _section("Stop and disable the service — Terminal",
            f"{p.svc_stop.format(svc='<service_name>')}\n{p.svc_disable.format(svc='<service_name>')}") + "\n\n" +
        _section(f"Verify port {port} is closed — Terminal",
            f"{p.list_ports} | grep :{port}\n# Expected: no output")
    )

def _p3_action(p, ctx):
    port = _port_num(ctx["port"])
    ip   = ctx["ip"]
    return (
        f"Add a {p.firewall_tool} rule to block inbound access to port {port}.\n\n"
        f"LOCATE: {p.open_shell_admin}.\n\n"
        f"WHAT TO RUN (✅):\n  {p.block_port_tcp.format(port=port)}\n\n"
        f"VERIFY rule is active:\n  {p.firewall_list}\n\n"
        f"VERIFY port is blocked externally:\n  {p.check_port.format(ip=ip, port=port)}"
    )

def _p3_cmd(p, ctx):
    port = _port_num(ctx["port"])
    ip   = ctx["ip"]
    label = "PowerShell as Administrator" if _is_win(p) else "Terminal"
    return (
        _section(f"Block inbound TCP port {port} — {label}", p.block_port_tcp.format(port=port)) + "\n\n" +
        _section("List active firewall rules — " + label, p.firewall_list) + "\n\n" +
        _section("Verify port is blocked externally — " + label,
            f"{p.check_port.format(ip=ip, port=port)}\n"
            f"# Expected: {'TcpTestSucceeded: False' if _is_win(p) else str(port) + '/tcp filtered'}")
    )

OPEN_PORTS = MitigationTemplate(
    vuln_pattern = r"open port|unnecessary service|exposed service|unsecured port|telnet|ftp|rsh|rlogin|finger|chargen|echo",
    category     = "Attack Surface Reduction",
    severity     = "Medium",
    cvss_range   = "4.0–6.9",
    steps        = [
        MitigationStep(1, "Identify and Confirm Service on Port",
            _p1_action, lambda p, c: "N/A", _p1_cmd,
            lambda p, c: (f"{p.shell_label}, netstat, Get-Process" if _is_win(p) else f"{p.shell_label}, ss, Nmap"),
            lambda p, c: "Do NOT disable without confirming the service has no active business dependency."),
        MitigationStep(2, "Disable the Unnecessary or Insecure Service",
            _p2_action, lambda p, c: "N/A", _p2_cmd,
            lambda p, c: (f"{p.shell_label}, Stop-Service, Set-Service" if _is_win(p) else f"{p.shell_label}, systemctl"),
            lambda p, c: "Confirm all dependent applications are updated before disabling."),
        MitigationStep(3, "Block Port at Firewall Level",
            _p3_action, lambda p, c: "N/A", _p3_cmd,
            lambda p, c: f"{p.shell_label}, {p.firewall_tool}",
            lambda p, c: "Apply firewall block at BOTH host and network perimeter for defense-in-depth."),
    ]
)


# ===========================================================================
# Registry + lookup
# ===========================================================================

TEMPLATE_REGISTRY: List[MitigationTemplate] = [
    SSL_WEAK_CIPHER,
    DEFAULT_CREDENTIALS,
    OPEN_PORTS,
]


def find_template(vuln_name: str, description: str = "") -> Optional[MitigationTemplate]:
    combined = (vuln_name + " " + description).lower()
    for tmpl in TEMPLATE_REGISTRY:
        if re.search(tmpl.vuln_pattern, combined, re.IGNORECASE):
            return tmpl
    return None


def render_steps(template: MitigationTemplate, os_string: str, context: dict) -> List[dict]:
    """Render all steps using the OS profile derived from os_string."""
    profile = get_profile(os_string)
    return [step.render(profile, context) for step in template.steps]
