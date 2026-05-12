"""
Nessus Crew Agent — Task Definitions
Tasks wire together agent responsibilities and expected outputs.
"""

from crewai import Task


def build_tasks(agents: dict, finding: dict) -> list:
    """
    Create the four sequential tasks for the mitigation crew.
    finding dict keys: ip, os, port, vuln_name, description, plugin_output, assigned_to
    """

    ip          = finding.get("ip", "unknown")
    os_name     = finding.get("os", "unknown")
    os_category = finding.get("os_category", "windows")
    port        = finding.get("port", "unknown")
    vuln_name   = finding.get("vuln_name", "unknown")
    description = finding.get("description", "")
    plugin_out  = finding.get("plugin_output", "")
    assigned_to = finding.get("assigned_to", "Security Engineer")

    # Build OS-specific command reference block injected into remediation task
    if os_category == "windows":
        os_command_block = f"""
CRITICAL — TARGET OS IS WINDOWS: "{os_name}"
You MUST use ONLY Windows-compatible commands. Linux/Mac commands are FORBIDDEN.

WINDOWS COMMAND REFERENCE (use these exact patterns):
  Open file in editor   : notepad C:\\path\\to\\file.conf  OR  notepad++ C:\\path\\to\\file.conf
  Copy/backup file      : copy "C:\\path\\file.conf" "C:\\path\\file.conf.bak"
  Delete line in file   : Use notepad to manually edit, OR PowerShell: (Get-Content file) | Where-Object {{$_ -notmatch 'pattern'}} | Set-Content file
  Restart service       : net stop ServiceName && net start ServiceName  OR  Restart-Service -Name ServiceName
  Check service status  : sc query ServiceName  OR  Get-Service -Name ServiceName
  Install package       : choco install packagename  OR  winget install packagename
  Firewall rule         : netsh advfirewall firewall add rule name="Rule" dir=in action=block protocol=TCP localport={port}
  View logs             : Get-EventViewer  OR  type C:\\path\\to\\logfile.log
  Run as admin          : Run PowerShell or CMD as Administrator (right-click → Run as administrator)
  Registry edit         : reg add "HKLM\\..." /v ValueName /t REG_SZ /d "value" /f
  OpenSSL (if installed): "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe" command
  Nmap scan             : nmap --script ssl-enum-ciphers -p {port} {ip}

WINDOWS PATHS (NOT Linux paths):
  Web server config     : C:\\Apache24\\conf\\extra\\httpd-ssl.conf  OR  C:\\nginx\\conf\\nginx.conf
  SSH config            : C:\\ProgramData\\ssh\\sshd_config
  SSL certificates      : C:\\ProgramData\\ssl\\  OR  C:\\Apache24\\conf\\ssl\\
  Logs                  : C:\\Apache24\\logs\\  OR  C:\\nginx\\logs\\
  Temp files            : C:\\Windows\\Temp\\  OR  %TEMP%\\

DO NOT USE: sudo, apt, yum, systemctl, /etc/, /var/, /tmp/, nano, chmod, chown, bash, sh
"""
    elif os_category == "macos":
        os_command_block = f"""
CRITICAL — TARGET OS IS macOS: "{os_name}"
You MUST use ONLY macOS-compatible commands.

macOS COMMAND REFERENCE:
  Open file             : nano /path/to/file  OR  open -e /path/to/file
  Copy/backup file      : cp /path/file /path/file.bak
  Restart service       : sudo launchctl stop com.service.name && sudo launchctl start com.service.name
  Install package       : brew install packagename
  Firewall              : sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on
  Check service         : launchctl list | grep servicename
  SSL/TLS               : /usr/local/etc/openssl/openssl.cnf  OR  /etc/ssl/openssl.cnf
  Web server config     : /usr/local/etc/httpd/extra/httpd-ssl.conf  (Homebrew Apache)
  Nmap scan             : nmap --script ssl-enum-ciphers -p {port} {ip}
"""
    else:
        # linux (default)
        os_command_block = f"""
CRITICAL — TARGET OS IS LINUX: "{os_name}"
You MUST use ONLY Linux-compatible commands.

LINUX COMMAND REFERENCE:
  Open file             : sudo nano /etc/path/file.conf  OR  sudo vim /etc/path/file.conf
  Copy/backup file      : sudo cp /etc/file /etc/file.bak_$(date +%Y%m%d)
  Restart service       : sudo systemctl restart servicename
  Check service         : sudo systemctl status servicename
  Install package       : sudo apt-get install packagename  (Debian/Ubuntu)  OR  sudo yum install packagename  (RHEL/CentOS)
  Firewall              : sudo ufw deny {port}/tcp  (UFW)  OR  sudo firewall-cmd --permanent --remove-port={port}/tcp  (firewalld)
  Web server config     : /etc/apache2/sites-enabled/default-ssl.conf  (Apache/Ubuntu)  OR  /etc/nginx/sites-enabled/default  (Nginx)
  SSH config            : /etc/ssh/sshd_config
  SSL dir               : /etc/ssl/certs/
  Logs                  : /var/log/apache2/  OR  /var/log/nginx/
  Nmap scan             : nmap --script ssl-enum-ciphers -p {port} {ip}
"""

    # ------------------------------------------------------------------ #
    # Task 1 — Vulnerability Analysis                                     #
    # ------------------------------------------------------------------ #
    task_analyse = Task(
        description=f"""
Analyse the following Nessus vulnerability finding and produce a structured intelligence report.

NESSUS FINDING:
  IP Address      : {ip}
  Operating System: {os_name}
  Port / Service  : {port}
  Vulnerability   : {vuln_name}
  Assigned To     : {assigned_to}

  Description:
  {description or 'Not provided'}

  Plugin Output:
  {plugin_out or 'Not provided'}

Your output MUST include:
1. Vulnerability name (cleaned/normalized)
2. CVE references if detectable from name or plugin output
3. Estimated severity (Critical / High / Medium / Low)
4. Estimated CVSS score range
5. Vulnerability category (e.g., Cryptographic Weakness, Authentication Weakness)
6. Attack vector (Network / Adjacent / Local / Physical)
7. Summary of what the vulnerability enables an attacker to do
8. Key data points from the plugin output that confirm the vulnerability

Use the vulnerability_lookup and risk_rater tools to assist your analysis.
""",
        expected_output="""
A structured vulnerability intelligence report containing:
- Normalized vulnerability name
- Severity and CVSS range
- Vulnerability category
- CVE references (if any)
- Attack vector
- What an attacker can do with this vulnerability
- Key evidence from plugin output
- Any special considerations for remediation
""",
        agent=agents["vulnerability_analyst"],
    )

    # ------------------------------------------------------------------ #
    # Task 2 — OS and Service Profiling                                   #
    # ------------------------------------------------------------------ #
    task_profile = Task(
        description=f"""
Profile the target system to determine exact configuration file paths, commands,
and environment details needed for remediation.

TARGET SYSTEM:
  IP Address      : {ip}
  Operating System: {os_name}
  Port / Service  : {port}
  Vulnerability   : {vuln_name}

Use the os_profiler tool with os_name="{os_name}" and port="{port}".

Your output MUST include:
1. Package manager (apt / yum / Windows Update / etc.)
2. Service manager (systemctl / service / sc / etc.)
3. Exact config file path for the affected service
4. Log directory path
5. Service restart command
6. Configuration validation command
7. Firewall tool available on this OS
8. Any OS-specific caveats for the remediation

If the OS is unknown or unrecognized, default to Ubuntu/Debian paths and note the assumption.
""",
        expected_output="""
An OS and service profile containing:
- Package manager
- Service manager
- Exact config file paths specific to this OS and service
- Log directory
- Restart and validation commands
- Firewall tool
- Any OS-specific caveats
""",
        agent=agents["os_profiler"],
        context=[task_analyse],
    )

    # ------------------------------------------------------------------ #
    # Task 3 — Remediation Plan Generation                                #
    # ------------------------------------------------------------------ #
    task_remediate = Task(
        description=f"""
Using the vulnerability intelligence report and OS profile, generate a COMPLETE,
detailed step-by-step remediation plan for this Nessus finding.

CONTEXT:
  IP Address      : {ip}
  Operating System: {os_name}
  Port            : {port}
  Vulnerability   : {vuln_name}
  Assigned To     : {assigned_to}
  Description     : {description or 'Not provided'}
  Plugin Output   : {plugin_out or 'Not provided'}

{os_command_block}

MANDATORY — Use the mitigation_knowledge tool first with:
  vuln_name="{vuln_name}", description="{description}", ip="{ip}", port="{port}", os_name="{os_name}", os_category="{os_category}", assigned_to="{assigned_to}"

Then use command_builder to generate OS-specific commands for each step.

REQUIREMENTS FOR EACH STEP:
Each step MUST contain ALL of the following:
  a) Step number (sequential)
  b) Assigned To: {assigned_to}
  c) Task Name: short, action-oriented (e.g., "Disable Weak TLS Protocols")
  d) Action: DETAILED — must include:
       - LOCATE: Exact file/location to find the setting
       - REMOVE: Exact line(s)/value(s) to delete, with a ❌ before-example
       - REPLACE WITH: Exact replacement config, with a ✅ after-example
       - WHERE: Exact location within the file
       - Verification step: how to confirm the change was applied
  e) File Path: Exact path on the OS, or "N/A"
  f) Command to Run: Real, runnable command with actual syntax, or "N/A"
  g) Artifacts / Tools Used: comma-separated list
  h) Important Consideration: risk, dependency, or warning

MANDATORY STEPS TO COVER (minimum 8 steps):
  1. Pre-check / audit scan or baseline
  2. Backup configuration files
  3. Open configuration file
  4. Remove/disable the vulnerable component
  5. Configure secure replacement
  6. Additional hardening relevant to this vulnerability
  7. Restart/apply changes
  8. Verify fix (rescan, command verification)

Adapt commands to the exact OS identified ({os_name}).
""",
        expected_output="""
A complete, detailed remediation plan with 8+ steps.
Each step contains:
- Step number, Assigned To, Task Name
- Detailed Action with LOCATE, REMOVE ❌, REPLACE WITH ✅, WHERE, and verification
- Exact File Path, Runnable Command, Tools Used, Important Consideration
All steps are specific to the target OS and vulnerability.
""",
        agent=agents["remediation_engineer"],
        context=[task_analyse, task_profile],
    )

    # ------------------------------------------------------------------ #
    # Task 4 — Mitigation Card Formatter                                  #
    # Output format MUST match the structured parser expectations:        #
    #   Section 1: Markdown table (17 columns)                            #
    #   Section 2: JSON block in ```json fence                            #
    #   Section 3: Numbered contextual analysis                           #
    # ------------------------------------------------------------------ #
    task_format = Task(
        description=f"""
Format the complete remediation plan into EXACTLY THREE sections in this EXACT order.
Do NOT add any introductory text before the table. Start IMMEDIATELY with the table.

VULNERABILITY CONTEXT:
  IP / Host       : {ip}
  Operating System: {os_name}
  Port            : {port}
  Vulnerability   : {vuln_name}
  Assigned To     : {assigned_to}

⚠ OS ENFORCEMENT: Every command in the "Commands for Action" column MUST be valid for "{os_name}".
{"Windows commands only — NO sudo/systemctl/apt/nano//etc/ paths. Use PowerShell/CMD/net stop/notepad." if os_category == "windows" else "macOS commands only — use brew/launchctl/nano." if os_category == "macos" else "Linux commands only — use systemctl/apt/yum/sudo/nano."}
Copy ALL commands exactly from the Remediation Engineer's plan without converting them to a different OS.

═══════════════════════════════════════════════════════════════
SECTION 1 — MITIGATION TABLE (start here, no preamble)
═══════════════════════════════════════════════════════════════

Output a markdown table with EXACTLY these 20 column headers in this exact order:

| Step No | Step Name | Action | Operating System | System File/Path | Responsible Party | Artifacts/Tools Used | Commands for Action | Criticality | Precautions | Verification Steps | Effort Estimate | Patch Available | Fallback Remediation | Reference Links | Applicable Platforms | Remediation Timeline | Expected Output | On Success Next Step | On Failure What To Do |
|---------|-----------|--------|-----------------|------------------|-------------------|----------------------|---------------------|-------------|-------------|-------------------|-----------------|-----------------|-----------------------|----------------|---------------------|---------------------|-----------------|---------------------|----------------------|

COLUMN RULES (follow strictly):
- "Step No": sequential integer (1, 2, 3...)
- "Step Name": short action-oriented name (e.g. "Backup SSL Config")
- "Action": MANDATORY FORMAT — write as numbered sub-steps with <br> between every line.
  Minimum 3 numbered sub-steps per row. Example:
  1. Open terminal on the target server.<br>2. Run the baseline scan command shown in Commands column.<br>3. Save the output to /tmp/before_scan.txt for comparison after the fix.
- "Operating System": always write exactly "{os_name}"
- "System File/Path": exact file path or N/A
- "Responsible Party": always write exactly "{assigned_to}"
- "Artifacts/Tools Used": comma-separated tool names
- "Commands for Action": exact copy-paste-ready command(s) or N/A
- "Criticality": exactly one of: Critical / High / Medium / Low
- "Precautions": warnings before executing this step, or N/A
- "Verification Steps": plain English — what to check to confirm this step succeeded
- "Effort Estimate": e.g. "15 minutes", "1 hour", "30 minutes"
- "Patch Available": Yes / No / N/A
- "Fallback Remediation": what to do if this step fails or causes issues
- "Reference Links": CVE link, NVD link, or vendor doc URL — or N/A
- "Applicable Platforms": platforms this step applies to, e.g. "Linux", "Windows", "All"
- "Remediation Timeline": e.g. "Immediate", "Within 24 hours", "Within 7 days"
- "Expected Output": STEP-SPECIFIC — what the user should actually see on screen if THIS step worked correctly.
  Examples: "Command outputs 'TLSv1 disabled' with no errors", "Service shows 'active (running)' status",
  "File /etc/ssl/openssl.cnf now contains MinProtocol = TLSv1.2"
  Never write a generic response — always describe the exact observable result for this specific step.
- "On Success Next Step": brief instruction naming the NEXT step specifically.
  Example: "Proceed to Step 3 — Open the configuration file" or "All steps complete — run the final verification scan"
- "On Failure What To Do": STEP-SPECIFIC troubleshooting for THIS step only.
  Examples: "Check file permissions with 'ls -la /etc/ssl/' and verify you have sudo/root access",
  "Service may be locked — run 'systemctl status nginx' to see the error, then check /var/log/nginx/error.log",
  "Restore from backup at /backup/openssl.cnf.bak and retry with correct syntax"
  Never write a generic response — always describe what to check specifically for this step.

Include ALL steps from the remediation plan. No blank cells — use N/A if truly not applicable.

═══════════════════════════════════════════════════════════════
SECTION 2 — VULNERABILITY CARD (immediately after the table)
═══════════════════════════════════════════════════════════════

Immediately after the table rows, output this JSON block inside a ```json code fence:

```json
{{
  "resource_id": "{ip}",
  "region": "<network subnet or zone derived from IP, e.g. '192.168.1.x subnet', or null>",
  "affected_packages": "<comma-separated list of affected software/packages>",
  "vendor_advisory": "<official vendor advisory URL or null>",
  "reference_url": "<primary CVE or NVD reference URL>",
  "vulnerability_type": "<e.g. Cryptographic Weakness, Authentication Weakness, Remote Code Execution>",
  "affected_port_ranges": "{port}",
  "assigned_team": "<EXACTLY ONE of: Patch Management | Configuration Management | Network Security | Architectural Flaws>",
  "vendor_fix_available": "<Yes or No>",
  "steps_to_fix_count": <total number of rows in the table above as an integer>,
  "steps_to_fix_description": "<1-2 sentence summary of the overall remediation approach>",
  "deadline": "<24 hours for Critical, 7 days for High, 30 days for Medium, 90 days for Low>",
  "artifacts_tools": "<comma-separated list of all tools used across all steps>",
  "post_mitigation_troubleshooting_guide": "1. <first post-fix check> 2. <second check> 3. <third check> 4. <fourth check> 5. <fifth check>"
}}
```

═══════════════════════════════════════════════════════════════
SECTION 3 — CONTEXTUAL ANALYSIS (immediately after JSON block)
═══════════════════════════════════════════════════════════════

Immediately after the JSON block, write these 6 numbered sections (no extra heading):

1. Brief technical description of the vulnerability root cause
<content>

2. Affected systems, versions, and components
<content>

3. Potential impact and attack scenarios
<content>

4. How the mitigation steps address the root cause
<content>

5. Common implementation pitfalls to avoid
<content>

6. Testing procedures to verify the fix is effective
<content>
""",
        expected_output="""
Three sections in exact order:
1. Markdown table with 20 columns containing all remediation steps (no preamble)
2. JSON block in ```json fence with all vulnerability card fields
3. Six numbered contextual analysis sections
""",
        agent=agents["card_formatter"],
        context=[task_analyse, task_profile, task_remediate],
    )

    return [task_analyse, task_profile, task_remediate, task_format]
