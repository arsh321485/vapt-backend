"""
Mitigation Knowledge Base
Extracted and expanded from the Nessus Vulnerability Mitigation Sheet.
Each entry maps a vulnerability pattern to a full mitigation plan template.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import re

@dataclass
class MitigationStep:
    step_no: int
    assigned_to: str
    task_name: str
    action: str
    file_path: str
    command_to_run: str
    artifacts_tools_used: str
    important_consideration: str


@dataclass
class MitigationTemplate:
    vuln_pattern: str          # regex pattern to match vulnerability name
    category: str
    severity: str
    cvss_range: str
    steps: List[MitigationStep]


# ---------------------------------------------------------------------------
# TEMPLATE 1 — SSL/TLS Weak Cipher Suites (from uploaded sheet)
# ---------------------------------------------------------------------------
SSL_WEAK_CIPHER = MitigationTemplate(
    vuln_pattern=r"ssl|tls|cipher|weak cipher|rc4|3des|des|md5|export cipher|null cipher",
    category="Cryptographic Weakness",
    severity="Medium",
    cvss_range="4.0–6.9",
    steps=[
        MitigationStep(
            step_no=1,
            assigned_to="{assigned_to}",
            task_name="Identify Supported Ciphers",
            action=(
                "Run an Nmap SSL cipher scan against the target IP and port.\n"
                "LOCATE: Open a terminal on your assessment workstation.\n"
                "WHAT TO RUN: Execute the ssl-enum-ciphers Nmap script to enumerate all supported cipher suites.\n"
                "LOOK FOR (❌ WEAK — must be removed):\n"
                "  - RC4-SHA, RC4-MD5\n"
                "  - DES-CBC3-SHA (3DES)\n"
                "  - NULL-MD5, EXP-RC4-MD5\n"
                "  - Any TLSv1.0 or TLSv1.1 cipher\n"
                "EXAMPLE OUTPUT showing a vulnerable server:\n"
                "  TLSv1.0:\n"
                "    ciphers:\n"
                "      RC4-SHA    - rsa 2048 --- A\n"
                "      DES-CBC3-SHA - rsa 2048 --- C\n"
                "Save full output to a file: nmap ... > /tmp/cipher_scan_before.txt\n"
                "This baseline is required for comparison after the fix."
            ),
            file_path="N/A",
            command_to_run="nmap --script ssl-enum-ciphers -p {port} {ip} > /tmp/cipher_scan_before.txt",
            artifacts_tools_used="Nmap, terminal",
            important_consideration="Save output for comparison after the fix. Do NOT proceed without baseline."
        ),
        MitigationStep(
            step_no=2,
            assigned_to="{assigned_to}",
            task_name="Backup SSL Configuration",
            action=(
                "Back up the web server SSL configuration files BEFORE making any changes.\n"
                "LOCATE: Determine which web server is running:\n"
                "  Run: ps aux | grep -E 'apache|nginx|httpd'\n"
                "  Example output: 'apache2 -k start' → Apache is running.\n"
                "WHAT TO BACKUP (file paths per server):\n"
                "  Apache: /etc/apache2/sites-enabled/default-ssl.conf\n"
                "          /etc/apache2/mods-enabled/ssl.conf\n"
                "  Nginx:  /etc/nginx/sites-enabled/default\n"
                "          /etc/nginx/nginx.conf\n"
                "COMMAND EXAMPLE (Apache):\n"
                "  cp /etc/apache2/sites-enabled/default-ssl.conf \\\n"
                "     /etc/apache2/sites-enabled/default-ssl.conf.bak_$(date +%Y%m%d)\n"
                "COMMAND EXAMPLE (Nginx):\n"
                "  cp /etc/nginx/sites-enabled/default \\\n"
                "     /etc/nginx/sites-enabled/default.bak_$(date +%Y%m%d)\n"
                "WHERE TO STORE: Keep backup on same server AND copy to /tmp or a remote backup location."
            ),
            file_path="/etc/apache2/sites-enabled/, /etc/nginx/sites-enabled/",
            command_to_run=(
                "cp /etc/apache2/sites-enabled/default-ssl.conf "
                "/etc/apache2/sites-enabled/default-ssl.conf.bak_$(date +%Y%m%d)\n"
                "cp /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.bak_$(date +%Y%m%d)"
            ),
            artifacts_tools_used="cp, terminal",
            important_consideration="REQUIRED before making changes. Without a backup you cannot rollback safely."
        ),
        MitigationStep(
            step_no=3,
            assigned_to="{assigned_to}",
            task_name="Open SSL Configuration File",
            action=(
                "Open the correct SSL configuration file in a text editor.\n"
                "LOCATE the correct file:\n"
                "  Apache: /etc/apache2/sites-enabled/default-ssl.conf\n"
                "          also check: /etc/apache2/mods-enabled/ssl.conf\n"
                "  Nginx:  /etc/nginx/sites-enabled/default\n"
                "          or: /etc/nginx/conf.d/ssl.conf\n"
                "HOW TO IDENTIFY WHICH SERVER IS RUNNING:\n"
                "  Run: ps aux | grep -E 'apache|nginx'\n"
                "  Example → 'nginx: master process' means Nginx.\n"
                "WHAT TO OPEN:\n"
                "  For Apache: sudo nano /etc/apache2/sites-enabled/default-ssl.conf\n"
                "  For Nginx:  sudo nano /etc/nginx/sites-enabled/default\n"
                "SEARCH inside the file for 'SSLProtocol' (Apache) or 'ssl_protocols' (Nginx) to jump to the right section."
            ),
            file_path="/etc/apache2/sites-enabled/default-ssl.conf OR /etc/nginx/sites-enabled/default",
            command_to_run=(
                "# Identify server\n"
                "ps aux | grep -E 'apache|nginx'\n"
                "# Open config\n"
                "sudo nano /etc/apache2/sites-enabled/default-ssl.conf   # Apache\n"
                "sudo nano /etc/nginx/sites-enabled/default               # Nginx"
            ),
            artifacts_tools_used="nano, vim, terminal",
            important_consideration="Ensure the correct config file is edited — wrong file = no effect."
        ),
        MitigationStep(
            step_no=4,
            assigned_to="{assigned_to}",
            task_name="Disable Weak SSL/TLS Protocols",
            action=(
                "Remove TLS 1.0 and TLS 1.1 support from the server configuration.\n\n"
                "LOCATE: In the open config file, search for lines beginning with 'SSLProtocol' (Apache) or 'ssl_protocols' (Nginx).\n\n"
                "WHAT TO REMOVE (❌ INSECURE — delete or replace these exact lines):\n"
                "  Apache examples — any of these must be changed:\n"
                "    SSLProtocol all\n"
                "    SSLProtocol TLSv1 TLSv1.1 TLSv1.2\n"
                "    SSLProtocol -SSLv3\n"
                "  Nginx examples:\n"
                "    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"
                "    ssl_protocols SSLv3 TLSv1;\n\n"
                "WHAT TO REPLACE WITH (✅ SECURE — use exactly this):\n"
                "  Apache:\n"
                "    SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
                "  Nginx:\n"
                "    ssl_protocols TLSv1.2 TLSv1.3;\n\n"
                "WHERE: This line is typically found in the <VirtualHost *:443> block (Apache) or the server {} block (Nginx).\n\n"
                "VERIFY config is valid after saving:\n"
                "  Apache: apachectl configtest   → must return 'Syntax OK'\n"
                "  Nginx:  nginx -t               → must return 'syntax is ok'"
            ),
            file_path="/etc/apache2/sites-enabled/default-ssl.conf OR /etc/nginx/sites-enabled/default",
            command_to_run=(
                "# After editing, verify config:\n"
                "apachectl configtest           # Apache\n"
                "nginx -t                       # Nginx"
            ),
            artifacts_tools_used="nano, apachectl, nginx, terminal",
            important_consideration=(
                "TLS 1.0/1.1 clients (old Windows XP, IE 10, Android 4.x) will stop connecting. "
                "Confirm no legacy clients depend on these before disabling."
            )
        ),
        MitigationStep(
            step_no=5,
            assigned_to="{assigned_to}",
            task_name="Remove Weak Ciphers and Configure Strong Cipher Suites",
            action=(
                "Replace insecure cipher suite definitions with a strong, modern configuration.\n\n"
                "LOCATE: In the same SSL config file, find lines containing 'SSLCipherSuite' (Apache) or 'ssl_ciphers' (Nginx).\n\n"
                "WHAT TO REMOVE (❌ INSECURE — these allow broken ciphers):\n"
                "  Apache examples:\n"
                "    SSLCipherSuite ALL:!EXP:!NULL\n"
                "    SSLCipherSuite HIGH:MEDIUM:LOW\n"
                "    SSLCipherSuite ALL\n"
                "  Nginx examples:\n"
                "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
                "    ssl_ciphers ALL:!ADH:!EXPORT:RC4+RSA:+HIGH:+MEDIUM;\n\n"
                "SPECIFIC WEAK CIPHERS TO CONFIRM ABSENCE OF (❌ must NOT appear in nmap output):\n"
                "  RC4-SHA, RC4-MD5, DES-CBC3-SHA, NULL-MD5, EXP-RC4-MD5, EXPORT-*, IDEA-*\n\n"
                "WHAT TO REPLACE WITH (✅ SECURE — replace the entire SSLCipherSuite line):\n"
                "  Apache:\n"
                "    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\n"
                "    SSLHonorCipherOrder on\n"
                "  Nginx:\n"
                "    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\n"
                "    ssl_prefer_server_ciphers on;\n\n"
                "WHERE: Replace within the same SSL VirtualHost or server block where the old cipher line was.\n\n"
                "VERIFY: After restart, run nmap cipher scan again and confirm NO weak ciphers in output."
            ),
            file_path="/etc/apache2/sites-enabled/default-ssl.conf OR /etc/nginx/sites-enabled/default",
            command_to_run=(
                "# Verify weak ciphers removed after restart:\n"
                "nmap --script ssl-enum-ciphers -p {port} {ip} | grep -E 'RC4|3DES|MD5|NULL|EXPORT'"
            ),
            artifacts_tools_used="nano, Nmap, terminal",
            important_consideration=(
                "Do NOT mix strong + weak ciphers — replace the ENTIRE SSLCipherSuite line. "
                "Partial removal is insufficient as the server may still negotiate the weak option."
            )
        ),
        MitigationStep(
            step_no=6,
            assigned_to="{assigned_to}",
            task_name="Configure Strong Diffie-Hellman Parameters",
            action=(
                "Replace default or weak DH parameters with a 2048-bit minimum DH group.\n\n"
                "LOCATE: Check if a dhparam file already exists:\n"
                "  ls -la /etc/ssl/certs/dhparam.pem\n"
                "  If missing or size < 2048 bits → regenerate.\n\n"
                "WHAT TO REMOVE / REPLACE:\n"
                "  ❌ REMOVE any existing line referencing a DH file smaller than 2048 bits:\n"
                "    SSLOpenSSLConfCmd DHParameters \"/etc/ssl/certs/dhparam512.pem\"   # INSECURE\n"
                "  ❌ If no dhparam is configured, the server uses weak default DH — also insecure.\n\n"
                "WHAT TO DO:\n"
                "  1. Generate a new strong DH parameter file (2048 bits minimum):\n"
                "     openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048\n"
                "  2. Add/replace in Apache config:\n"
                "    ✅ SSLOpenSSLConfCmd DHParameters \"/etc/ssl/certs/dhparam.pem\"\n"
                "  3. For Nginx — Nginx automatically handles DH with modern ciphers.\n"
                "     Optionally add: ssl_dhparam /etc/ssl/certs/dhparam.pem;\n\n"
                "WHERE: Add the DHParameters line inside the <VirtualHost *:443> block (Apache).\n\n"
                "VERIFY: After restart, run Nmap and look for 'dh bits: 2048' in ssl-enum-ciphers output."
            ),
            file_path="/etc/ssl/certs/dhparam.pem",
            command_to_run="openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048",
            artifacts_tools_used="openssl, terminal",
            important_consideration=(
                "Generation may take 1–2 minutes on low-resource servers. "
                "Do not interrupt. On very slow VMs, use 'openssl dhparam ... 2048' not 4096 for speed."
            )
        ),
        MitigationStep(
            step_no=7,
            assigned_to="{assigned_to}",
            task_name="Disable SSL Compression and Session Ticket Weaknesses",
            action=(
                "Disable SSL compression (CRIME attack vector) and weak session tickets.\n\n"
                "LOCATE: Open SSL config file (same file as previous steps).\n"
                "  Search for: SSLCompression, SSLSessionTickets, ssl_session_tickets\n\n"
                "WHAT TO ADD / REPLACE:\n"
                "  ❌ If you see: SSLCompression on  → this is insecure\n"
                "  ✅ REPLACE WITH or ADD:\n"
                "     Apache:\n"
                "       SSLCompression off\n"
                "       SSLSessionTickets off\n"
                "     Nginx:\n"
                "       ssl_session_tickets off;\n\n"
                "WHERE: Add these directives inside the same <VirtualHost *:443> or http/server block.\n\n"
                "EXAMPLE — Apache config section after change:\n"
                "  SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
                "  SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:...\n"
                "  SSLCompression off        ← ADD THIS\n"
                "  SSLSessionTickets off     ← ADD THIS\n\n"
                "VERIFY: After restart, use SSL Labs (ssllabs.com/ssltest/) → Compression should show 'No'."
            ),
            file_path="/etc/apache2/sites-enabled/default-ssl.conf OR /etc/nginx/sites-enabled/default",
            command_to_run="sudo nano /etc/apache2/sites-enabled/default-ssl.conf   # then add the lines above",
            artifacts_tools_used="nano, SSL Labs, terminal",
            important_consideration=(
                "Prevents CRIME and BREACH attacks. SSLSessionTickets off requires all servers "
                "in a cluster to be updated simultaneously to avoid session issues."
            )
        ),
        MitigationStep(
            step_no=8,
            assigned_to="{assigned_to}",
            task_name="Restart Web Server and Apply Changes",
            action=(
                "Restart the web server to activate all configuration changes.\n\n"
                "BEFORE RESTARTING — validate the config first:\n"
                "  Apache: apachectl configtest    → MUST return 'Syntax OK'\n"
                "  Nginx:  nginx -t                → MUST return 'syntax is ok'\n\n"
                "WHAT TO RUN:\n"
                "  ✅ Apache restart:\n"
                "    sudo systemctl restart apache2\n"
                "  ✅ Nginx restart:\n"
                "    sudo systemctl restart nginx\n\n"
                "VERIFY the service came back up:\n"
                "  sudo systemctl status apache2   # should show 'active (running)'\n"
                "  sudo systemctl status nginx\n\n"
                "IF THE SERVICE FAILS TO START:\n"
                "  1. Check error log: tail -50 /var/log/apache2/error.log\n"
                "  2. Roll back to backup: cp /etc/apache2/sites-enabled/default-ssl.conf.bak /etc/apache2/sites-enabled/default-ssl.conf\n"
                "  3. Restart again with the rollback config."
            ),
            file_path="N/A",
            command_to_run=(
                "# Validate config first\n"
                "apachectl configtest && sudo systemctl restart apache2   # Apache\n"
                "nginx -t && sudo systemctl restart nginx                  # Nginx\n"
                "# Confirm running\n"
                "sudo systemctl status apache2"
            ),
            artifacts_tools_used="systemctl, apachectl, terminal",
            important_consideration=(
                "Always validate config BEFORE restarting. A failed restart on a production server "
                "causes downtime. If unsure, test in a staging environment first."
            )
        ),
        MitigationStep(
            step_no=9,
            assigned_to="{assigned_to}",
            task_name="Verify Removal of Weak Ciphers",
            action=(
                "Re-run the Nmap cipher scan and confirm all weak ciphers have been removed.\n\n"
                "WHAT TO RUN:\n"
                "  nmap --script ssl-enum-ciphers -p {port} {ip} > /tmp/cipher_scan_after.txt\n\n"
                "WHAT YOU SHOULD NOT SEE (❌ FAIL — if any of these appear, fix is incomplete):\n"
                "  - RC4, RC4-SHA, RC4-MD5\n"
                "  - 3DES, DES-CBC3-SHA\n"
                "  - MD5, NULL-MD5\n"
                "  - TLSv1.0, TLSv1.1\n"
                "  - EXPORT*, IDEA*\n\n"
                "WHAT YOU SHOULD SEE (✅ PASS):\n"
                "  - TLSv1.2 only ciphers: AES128-GCM-SHA256, AES256-GCM-SHA384\n"
                "  - TLSv1.3 ciphers: TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256\n"
                "  - 'least strength: A' in Nmap output\n\n"
                "COMPARE: diff /tmp/cipher_scan_before.txt /tmp/cipher_scan_after.txt\n"
                "This shows exactly what was removed vs what remains."
            ),
            file_path="N/A",
            command_to_run=(
                "nmap --script ssl-enum-ciphers -p {port} {ip} > /tmp/cipher_scan_after.txt\n"
                "diff /tmp/cipher_scan_before.txt /tmp/cipher_scan_after.txt"
            ),
            artifacts_tools_used="Nmap, terminal, diff",
            important_consideration=(
                "This is the FINAL validation step. Do not close the remediation ticket "
                "until the scan output is clean. Screenshot the output for the audit record."
            )
        ),
        MitigationStep(
            step_no=10,
            assigned_to="{assigned_to}",
            task_name="External Validation via SSL Labs",
            action=(
                "Use Qualys SSL Labs to validate the public-facing TLS configuration.\n\n"
                "LOCATE: Navigate to https://www.ssllabs.com/ssltest/ in a browser.\n\n"
                "WHAT TO DO:\n"
                "  1. Enter the hostname of {ip} (use FQDN if applicable, not raw IP).\n"
                "  2. Check 'Do not show the results on the boards' for privacy.\n"
                "  3. Click 'Submit'.\n"
                "  4. Wait for full analysis (~2–5 minutes).\n\n"
                "WHAT YOU SHOULD SEE (✅ PASS):\n"
                "  - Overall Grade: A or A+\n"
                "  - Protocol Support: TLS 1.2, TLS 1.3 only\n"
                "  - Key Exchange: Supported — ECDHE\n"
                "  - Cipher Strength: 256 bit\n"
                "  - Vulnerabilities: None\n\n"
                "WHAT YOU SHOULD NOT SEE (❌ FAIL):\n"
                "  - Grade B, C, or F\n"
                "  - BEAST, POODLE, CRIME, or DROWN listed as vulnerabilities\n"
                "  - RC4 or 3DES listed in cipher details\n\n"
                "WHERE: Screenshot the report summary page and attach to the remediation ticket."
            ),
            file_path="N/A",
            command_to_run="N/A — Browser-based at https://www.ssllabs.com/ssltest/",
            artifacts_tools_used="SSL Labs, web browser",
            important_consideration=(
                "Confirms real-world security from an external perspective. "
                "Only applicable for publicly-reachable hosts. For internal hosts use testssl.sh instead."
            )
        ),
        MitigationStep(
            step_no=11,
            assigned_to="{assigned_to}",
            task_name="Monitor Logs for Compatibility Issues",
            action=(
                "Monitor the web server error logs to detect any client compatibility issues after the cipher changes.\n\n"
                "LOCATE the error log:\n"
                "  Apache: /var/log/apache2/error.log\n"
                "  Nginx:  /var/log/nginx/error.log\n\n"
                "WHAT TO LOOK FOR (❌ PROBLEM indicators):\n"
                "  - 'SSL handshake failed'\n"
                "  - 'no shared cipher'\n"
                "  - 'SSL_ERROR_RX_RECORD_TOO_LONG'\n"
                "  - Sudden spike in 4xx or 5xx errors for HTTPS requests\n\n"
                "WHAT TO DO IF FOUND:\n"
                "  1. Identify the client (check User-Agent in access log).\n"
                "  2. Determine if client is a legacy system that must be supported.\n"
                "  3. If legacy client MUST connect — consult business owner for exception process.\n"
                "  4. Do NOT re-enable weak ciphers without a formal risk acceptance document.\n\n"
                "EXAMPLE monitoring command — live tail:\n"
                "  tail -f /var/log/apache2/error.log | grep -i 'ssl\\|handshake\\|cipher'"
            ),
            file_path="/var/log/apache2/error.log OR /var/log/nginx/error.log",
            command_to_run=(
                "tail -f /var/log/apache2/error.log | grep -iE 'ssl|handshake|cipher|no shared'\n"
                "tail -f /var/log/nginx/error.log   | grep -iE 'ssl|handshake|cipher|no shared'"
            ),
            artifacts_tools_used="tail, grep, terminal, logs",
            important_consideration=(
                "Monitor for at least 48 hours post-change. Helps detect compatibility issues "
                "with legacy clients before they escalate into support tickets."
            )
        ),
        MitigationStep(
            step_no=12,
            assigned_to="{assigned_to}",
            task_name="Document Changes and Close Remediation",
            action=(
                "Document all changes made, update the vulnerability tracker, and retain backup files.\n\n"
                "WHAT TO DOCUMENT:\n"
                "  1. Date and time of change.\n"
                "  2. Exact lines removed from config (copy from backup diff).\n"
                "  3. Exact lines added to config.\n"
                "  4. Nmap scan output before (cipher_scan_before.txt) and after (cipher_scan_after.txt).\n"
                "  5. SSL Labs grade screenshot.\n"
                "  6. Affected system: {ip}, OS: {os}, Port: {port}.\n\n"
                "WHERE TO FILE:\n"
                "  - Nessus / vulnerability management platform: update finding status to 'Remediated'.\n"
                "  - Change management system: link the change record.\n"
                "  - Internal wiki or runbook: add entry for this server's SSL config.\n\n"
                "BACKUP RETENTION:\n"
                "  Keep the .bak files for minimum 30 days:\n"
                "  ls /etc/apache2/sites-enabled/*.bak\n\n"
                "STAKEHOLDER COMMUNICATION:\n"
                "  Notify: App owners, IT ops, and security team that legacy TLS 1.0/1.1 is disabled.\n"
                "  Include: Date of change, impact (old clients may fail), rollback plan."
            ),
            file_path="N/A",
            command_to_run=(
                "# Archive before/after scan outputs\n"
                "cp /tmp/cipher_scan_before.txt /var/log/security/remediations/\n"
                "cp /tmp/cipher_scan_after.txt  /var/log/security/remediations/"
            ),
            artifacts_tools_used="documentation tools, Nessus, change management system",
            important_consideration=(
                "Required for audit and compliance. Without documentation, the remediation "
                "cannot be verified during a PCI-DSS, ISO 27001, or SOC 2 audit."
            )
        ),
    ]
)


# ---------------------------------------------------------------------------
# TEMPLATE 2 — Default/Weak Credentials
# ---------------------------------------------------------------------------
DEFAULT_CREDENTIALS = MitigationTemplate(
    vuln_pattern=r"default credential|default password|weak password|default login|default account",
    category="Authentication Weakness",
    severity="Critical",
    cvss_range="9.0–10.0",
    steps=[
        MitigationStep(
            step_no=1,
            assigned_to="{assigned_to}",
            task_name="Identify All Default Accounts",
            action=(
                "Enumerate all accounts on the target system and identify those using default credentials.\n\n"
                "LOCATE: Log into the target system at {ip} on port {port}.\n"
                "  For Linux: cat /etc/passwd | grep -v nologin\n"
                "  For Windows: net user\n"
                "  For network device: show running-config | include username\n\n"
                "WHAT TO LOOK FOR (❌ PROBLEMATIC accounts):\n"
                "  - Username 'admin' with password 'admin'\n"
                "  - Username 'root' with password 'root' or 'toor'\n"
                "  - Username 'cisco' with password 'cisco'\n"
                "  - Any account with blank password\n"
                "  - Service accounts with vendor default passwords (e.g., 'sa'/'sa' for SQL Server)\n\n"
                "VERIFY which accounts are default by checking vendor documentation for the service on port {port}."
            ),
            file_path="/etc/passwd (Linux), SAM (Windows)",
            command_to_run="cat /etc/shadow | awk -F: '($2==\"\" || $2==\"!!\"){print $1}'  # blank/locked accounts",
            artifacts_tools_used="terminal, net user, /etc/passwd",
            important_consideration="Document all accounts found before making changes."
        ),
        MitigationStep(
            step_no=2,
            assigned_to="{assigned_to}",
            task_name="Change All Default Credentials Immediately",
            action=(
                "Change every default password to a strong, unique password.\n\n"
                "LOCATE: Each account identified in Step 1.\n\n"
                "WHAT TO REMOVE (❌ default passwords like these MUST be replaced):\n"
                "  admin:admin, root:root, cisco:cisco, admin:password, sa:(blank)\n\n"
                "WHAT TO REPLACE WITH (✅ strong password requirements):\n"
                "  - Minimum 16 characters\n"
                "  - Mix of uppercase, lowercase, numbers, symbols\n"
                "  - Example strong password: T7#mKx9!qRvL2@wZ\n"
                "  - Store in a corporate password vault (e.g., CyberArk, HashiCorp Vault)\n\n"
                "COMMANDS:\n"
                "  Linux — change password:    sudo passwd <username>\n"
                "  Windows — change password:  net user <username> NewStr0ngP@ss!\n"
                "  MySQL:  ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewStr0ngP@ss!';\n"
                "  Cisco:  username admin secret 9 <hash_of_strong_password>"
            ),
            file_path="N/A",
            command_to_run="sudo passwd admin   # Linux\nnet user administrator NewStr0ngP@ss! /domain   # Windows",
            artifacts_tools_used="terminal, password manager, Active Directory",
            important_consideration=(
                "Store new credentials in a corporate vault immediately. "
                "Do NOT write passwords in tickets, emails, or documentation in cleartext."
            )
        ),
        MitigationStep(
            step_no=3,
            assigned_to="{assigned_to}",
            task_name="Disable or Remove Unnecessary Default Accounts",
            action=(
                "Disable or delete vendor default accounts that are not operationally required.\n\n"
                "LOCATE accounts to disable:\n"
                "  Linux: cat /etc/passwd | grep -vE 'nologin|false'\n"
                "  Check for: guest, nobody, ftp, lp, games — these are typically unnecessary.\n\n"
                "WHAT TO REMOVE (❌ disable accounts not needed for operations):\n"
                "  - 'guest' account on Linux/Windows\n"
                "  - Default vendor accounts (e.g., 'oracle', 'postgres' with default passwords)\n\n"
                "WHAT TO DO:\n"
                "  ✅ Disable (preferred, preserves file ownership):\n"
                "    sudo usermod -L <username>          # Lock account (Linux)\n"
                "    net user <username> /active:no      # Disable (Windows)\n"
                "  ✅ Delete if truly unnecessary:\n"
                "    sudo userdel -r <username>          # Linux\n"
                "    net user <username> /delete         # Windows\n\n"
                "WHERE: Apply on the target host {ip}."
            ),
            file_path="/etc/passwd, /etc/shadow",
            command_to_run=(
                "sudo usermod -L guest         # Lock account Linux\n"
                "sudo userdel -r guestuser     # Delete account Linux\n"
                "net user guest /active:no     # Disable Windows"
            ),
            artifacts_tools_used="usermod, userdel, net user, terminal",
            important_consideration="Confirm with application team before deleting service accounts — some apps require them."
        ),
        MitigationStep(
            step_no=4,
            assigned_to="{assigned_to}",
            task_name="Enforce Strong Password Policy",
            action=(
                "Configure the system to enforce a strong password policy to prevent weak passwords in future.\n\n"
                "LOCATE: Password policy configuration file.\n"
                "  Linux (PAM): /etc/pam.d/common-password or /etc/security/pwquality.conf\n"
                "  Windows: Group Policy — Computer Configuration > Windows Settings > Security Settings > Account Policies\n\n"
                "WHAT TO REMOVE (❌ weak/default policy settings):\n"
                "  /etc/pam.d/common-password line (insecure, no requirements):\n"
                "    password requisite pam_pwquality.so retry=3\n\n"
                "WHAT TO REPLACE WITH (✅ strong policy):\n"
                "  /etc/pam.d/common-password:\n"
                "    password requisite pam_pwquality.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 reject_username\n\n"
                "  /etc/security/pwquality.conf:\n"
                "    minlen = 14\n"
                "    dcredit = -1\n"
                "    ucredit = -1\n"
                "    ocredit = -1\n"
                "    lcredit = -1\n"
                "    reject_username = 1\n\n"
                "WHERE: Edit on target host {ip}. Apply via Group Policy for Windows domain."
            ),
            file_path="/etc/pam.d/common-password, /etc/security/pwquality.conf",
            command_to_run="sudo nano /etc/security/pwquality.conf",
            artifacts_tools_used="PAM, Group Policy, nano",
            important_consideration="Test PAM changes with a non-root account first to avoid lockout."
        ),
        MitigationStep(
            step_no=5,
            assigned_to="{assigned_to}",
            task_name="Verify and Document Remediation",
            action=(
                "Re-run the Nessus scan on {ip}:{port} to confirm the default credential finding is resolved.\n\n"
                "WHAT TO RUN:\n"
                "  1. Re-scan with Nessus using the same plugin that detected the vulnerability.\n"
                "  2. Attempt login with the old default credentials — they must fail.\n\n"
                "EXPECTED RESULT (✅ PASS):\n"
                "  - Nessus plugin no longer triggers.\n"
                "  - Login with old credentials returns 'Authentication Failed'.\n\n"
                "WHAT TO DOCUMENT:\n"
                "  - New credential location (vault reference, NOT the password itself).\n"
                "  - Accounts changed, disabled, or deleted.\n"
                "  - Screenshot of Nessus rescan showing finding as resolved."
            ),
            file_path="N/A",
            command_to_run="# Re-scan in Nessus console — run same policy against {ip}",
            artifacts_tools_used="Nessus, password vault, documentation tools",
            important_consideration="Remediation is not complete until the Nessus rescan confirms the finding is gone."
        ),
    ]
)


# ---------------------------------------------------------------------------
# TEMPLATE 3 — Unpatched Software / Missing Security Updates
# ---------------------------------------------------------------------------
MISSING_PATCHES = MitigationTemplate(
    vuln_pattern=r"patch|update|outdated|unsupported|end.of.life|eol|obsolete|missing update|security update|version",
    category="Software Lifecycle",
    severity="High",
    cvss_range="7.0–9.9",
    steps=[
        MitigationStep(
            step_no=1,
            assigned_to="{assigned_to}",
            task_name="Identify Installed Software Version",
            action=(
                "Confirm the exact version of the vulnerable software on {ip}.\n\n"
                "LOCATE: Connect to target {ip} via SSH (Linux) or RDP (Windows).\n\n"
                "WHAT TO RUN:\n"
                "  Linux — for a specific package:\n"
                "    dpkg -l <package_name>           # Debian/Ubuntu\n"
                "    rpm -q <package_name>            # RHEL/CentOS\n"
                "  Windows — check installed version:\n"
                "    Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like '*software_name*'}\n\n"
                "EXAMPLE — checking OpenSSL version:\n"
                "  openssl version -a\n"
                "  → OpenSSL 1.0.2k  26 Jan 2017   (❌ EOL — must update)\n\n"
                "LOOK UP: Check vendor security advisory for CVE associated with this finding to confirm affected range."
            ),
            file_path="N/A",
            command_to_run=(
                "# Linux\n"
                "dpkg -l | grep <package>\n"
                "# Windows\n"
                "Get-WmiObject -Class Win32_Product | Select Name,Version | Where-Object {$_.Name -like '*<package>*'}"
            ),
            artifacts_tools_used="dpkg, rpm, PowerShell, terminal",
            important_consideration="Record exact version — needed for change management record."
        ),
        MitigationStep(
            step_no=2,
            assigned_to="{assigned_to}",
            task_name="Backup Configuration Before Update",
            action=(
                "Back up all configuration files for the vulnerable service before patching.\n\n"
                "LOCATE: Find all configuration files for the service running on port {port}.\n"
                "  Common config locations:\n"
                "    Apache: /etc/apache2/\n"
                "    OpenSSH: /etc/ssh/sshd_config\n"
                "    OpenSSL: /etc/ssl/, /etc/pki/\n"
                "    Nginx: /etc/nginx/\n\n"
                "WHAT TO BACKUP:\n"
                "  tar -czf /tmp/service_config_backup_$(date +%Y%m%d).tar.gz /etc/<service>/\n\n"
                "EXAMPLE — backup SSH config:\n"
                "  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak_$(date +%Y%m%d)\n\n"
                "WHERE TO STORE: Copy backup to a remote host or backup system — not just /tmp."
            ),
            file_path="/etc/<service>/ (varies by service)",
            command_to_run="tar -czf /tmp/svc_config_$(date +%Y%m%d).tar.gz /etc/<service>/",
            artifacts_tools_used="tar, cp, terminal",
            important_consideration="Config files may differ between versions — backup before update in case of rollback."
        ),
        MitigationStep(
            step_no=3,
            assigned_to="{assigned_to}",
            task_name="Apply Security Update / Patch",
            action=(
                "Update the vulnerable software to the latest stable, patched version.\n\n"
                "LOCATE the correct package to update:\n"
                "  Run: apt list --upgradable 2>/dev/null | grep <package>   # Debian/Ubuntu\n"
                "  Run: yum check-update <package>                            # RHEL/CentOS\n\n"
                "WHAT TO REMOVE (❌ old, vulnerable version — will be replaced by update):\n"
                "  Example: openssl 1.0.2k (vulnerable to CVE-2022-0778)\n\n"
                "WHAT TO REPLACE WITH (✅ latest patched version):\n"
                "  Ubuntu/Debian:\n"
                "    sudo apt-get update && sudo apt-get install --only-upgrade <package>\n"
                "  RHEL/CentOS:\n"
                "    sudo yum update <package>\n"
                "  Windows:\n"
                "    Install-Module -Name PSWindowsUpdate\n"
                "    Get-WindowsUpdate -Install -AcceptAll\n\n"
                "WHERE: Apply directly on {ip}. If clustered, patch one node at a time.\n\n"
                "VERIFY new version installed:\n"
                "  dpkg -l | grep <package>   → should show the patched version number."
            ),
            file_path="N/A",
            command_to_run=(
                "# Ubuntu/Debian\n"
                "sudo apt-get update && sudo apt-get install --only-upgrade <package>\n"
                "# RHEL/CentOS\n"
                "sudo yum update <package>\n"
                "# Verify\n"
                "dpkg -l | grep <package>"
            ),
            artifacts_tools_used="apt, yum, Windows Update, terminal",
            important_consideration=(
                "Test patches in a staging environment before production. "
                "Schedule a maintenance window for services requiring restart."
            )
        ),
        MitigationStep(
            step_no=4,
            assigned_to="{assigned_to}",
            task_name="Restart Affected Service",
            action=(
                "Restart the patched service to load the updated binaries.\n\n"
                "LOCATE the service name:\n"
                "  systemctl list-units --type=service | grep <service>\n\n"
                "WHAT TO RUN:\n"
                "  sudo systemctl restart <service_name>\n\n"
                "EXAMPLE — restarting Apache after OpenSSL update:\n"
                "  sudo systemctl restart apache2\n"
                "  sudo systemctl status apache2   → 'active (running)' = success\n\n"
                "IF SERVICE FAILS TO START:\n"
                "  1. journalctl -xe | tail -50          # View startup errors\n"
                "  2. Restore backup config if config-related\n"
                "  3. Roll back package: apt-get install <package>=<old_version>"
            ),
            file_path="N/A",
            command_to_run=(
                "sudo systemctl restart <service>\n"
                "sudo systemctl status <service>"
            ),
            artifacts_tools_used="systemctl, journalctl, terminal",
            important_consideration="Coordinate restart with application team to minimise user impact."
        ),
        MitigationStep(
            step_no=5,
            assigned_to="{assigned_to}",
            task_name="Verify and Rescan",
            action=(
                "Run a targeted Nessus rescan against {ip}:{port} to confirm the vulnerability is resolved.\n\n"
                "WHAT TO DO:\n"
                "  1. In Nessus, create a targeted scan for {ip} using the same scan policy.\n"
                "  2. Run the scan and look for the specific plugin that triggered this finding.\n\n"
                "EXPECTED RESULT (✅ PASS):\n"
                "  - The specific CVE plugin no longer reports on {ip}.\n"
                "  - Version detected by Nessus matches the patched version.\n\n"
                "ALSO VERIFY:\n"
                "  dpkg -l <package>  → shows patched version\n"
                "  Or run: <service> --version  → shows new version number\n\n"
                "Document the rescan report as proof of remediation."
            ),
            file_path="N/A",
            command_to_run="# Run targeted Nessus scan via Nessus UI against {ip}",
            artifacts_tools_used="Nessus, terminal",
            important_consideration="Rescan must be done by the security team to be valid for audit purposes."
        ),
    ]
)


# ---------------------------------------------------------------------------
# TEMPLATE 4 — Open Ports / Unnecessary Services
# ---------------------------------------------------------------------------
OPEN_PORTS = MitigationTemplate(
    vuln_pattern=r"open port|unnecessary service|exposed service|unsecured port|telnet|ftp|rsh|rlogin|finger|chargen|echo",
    category="Attack Surface Reduction",
    severity="Medium",
    cvss_range="4.0–6.9",
    steps=[
        MitigationStep(
            step_no=1,
            assigned_to="{assigned_to}",
            task_name="Identify and Confirm Service on Port",
            action=(
                "Confirm what service is running on the exposed port and whether it is required.\n\n"
                "LOCATE: Run a service banner grab on the target.\n\n"
                "WHAT TO RUN:\n"
                "  nmap -sV -p {port} {ip}\n"
                "  nc -v {ip} {port}   # Banner grab\n\n"
                "EXAMPLE — confirming Telnet on port 23:\n"
                "  nmap -sV -p 23 {ip}\n"
                "  → 23/tcp open  telnet  Linux telnetd\n\n"
                "QUESTION TO ANSWER: Is this service operationally required?\n"
                "  - Check with application and infrastructure teams.\n"
                "  - If not required → disable it (Step 2).\n"
                "  - If required → restrict access (Step 3).\n"
                "  - Legacy insecure protocols (Telnet, FTP, RSH) → REPLACE with secure alternative (SSH/SFTP)."
            ),
            file_path="N/A",
            command_to_run="nmap -sV -p {port} {ip}",
            artifacts_tools_used="Nmap, netcat, terminal",
            important_consideration="Do NOT disable a service without confirming it is not required by an application."
        ),
        MitigationStep(
            step_no=2,
            assigned_to="{assigned_to}",
            task_name="Disable the Unnecessary or Insecure Service",
            action=(
                "Stop and disable the identified unnecessary or insecure service on {ip}.\n\n"
                "LOCATE the service:\n"
                "  systemctl list-units --type=service | grep telnet\n"
                "  systemctl list-units --type=service | grep ftp\n\n"
                "WHAT TO REMOVE (❌ stop and disable these insecure services):\n"
                "  Example — Telnet:\n"
                "    sudo systemctl stop telnet.socket\n"
                "    sudo systemctl disable telnet.socket\n"
                "  Example — FTP (vsftpd):\n"
                "    sudo systemctl stop vsftpd\n"
                "    sudo systemctl disable vsftpd\n\n"
                "WHAT TO REPLACE WITH (✅ secure alternative):\n"
                "  Telnet → SSH: sudo apt-get install openssh-server && systemctl enable ssh\n"
                "  FTP   → SFTP (included with OpenSSH): configure /etc/ssh/sshd_config with Subsystem sftp\n\n"
                "WHERE: Apply on {ip}. After disabling, verify port {port} is no longer listening:\n"
                "  ss -tlnp | grep {port}   → should return nothing."
            ),
            file_path="N/A",
            command_to_run=(
                "sudo systemctl stop <service> && sudo systemctl disable <service>\n"
                "ss -tlnp | grep {port}   # Confirm port is closed"
            ),
            artifacts_tools_used="systemctl, ss, terminal",
            important_consideration=(
                "Disabling a service immediately closes the port. "
                "Ensure no other application depends on this service before disabling."
            )
        ),
        MitigationStep(
            step_no=3,
            assigned_to="{assigned_to}",
            task_name="Block Port at Firewall Level",
            action=(
                "Add a firewall rule to block access to port {port} from untrusted networks.\n\n"
                "LOCATE the firewall management tool on {ip}:\n"
                "  Linux: ufw status OR iptables -L\n"
                "  Windows: netsh advfirewall show allprofiles\n\n"
                "WHAT TO ADD (✅ block inbound access to port {port}):\n"
                "  UFW (Ubuntu):\n"
                "    sudo ufw deny in {port}\n"
                "  iptables:\n"
                "    sudo iptables -A INPUT -p tcp --dport {port} -j DROP\n"
                "    sudo iptables-save > /etc/iptables/rules.v4\n"
                "  Windows Firewall:\n"
                "    netsh advfirewall firewall add rule name='Block Port {port}' dir=in action=block protocol=TCP localport={port}\n\n"
                "VERIFY:\n"
                "  nmap -p {port} {ip}   → port should show as 'filtered' or 'closed'."
            ),
            file_path="N/A",
            command_to_run=(
                "# UFW\n"
                "sudo ufw deny in {port}\n"
                "sudo ufw status\n"
                "# Verify\n"
                "nmap -p {port} {ip}"
            ),
            artifacts_tools_used="ufw, iptables, netsh, Nmap",
            important_consideration=(
                "Firewall rules provide defense-in-depth even if the service is disabled. "
                "Apply at both host and network firewall level."
            )
        ),
        MitigationStep(
            step_no=4,
            assigned_to="{assigned_to}",
            task_name="Verify Port Closure and Rescan",
            action=(
                "Confirm that port {port} on {ip} is no longer accessible.\n\n"
                "WHAT TO RUN:\n"
                "  nmap -sV -p {port} {ip}\n\n"
                "EXPECTED RESULT (✅ PASS):\n"
                "  {port}/tcp closed\n"
                "  OR\n"
                "  {port}/tcp filtered\n\n"
                "ALSO VERIFY internally:\n"
                "  ss -tlnp | grep {port}   → should return no output (service not listening)\n\n"
                "WHAT MEANS FAILURE (❌):\n"
                "  {port}/tcp open  <service>   → service still running, check steps 2 and 3."
            ),
            file_path="N/A",
            command_to_run=(
                "nmap -sV -p {port} {ip}\n"
                "ss -tlnp | grep {port}"
            ),
            artifacts_tools_used="Nmap, ss, terminal",
            important_consideration="Run scan from both internal and external perspective to confirm closure at all layers."
        ),
    ]
)


# ---------------------------------------------------------------------------
# TEMPLATE 5 — Missing Security Headers / HTTP Issues
# ---------------------------------------------------------------------------
MISSING_HEADERS = MitigationTemplate(
    vuln_pattern=r"security header|http header|clickjack|x-frame|content-security|hsts|x-xss|x-content-type|cors|cookie|same.site",
    category="Web Application Security",
    severity="Medium",
    cvss_range="4.0–6.9",
    steps=[
        MitigationStep(
            step_no=1,
            assigned_to="{assigned_to}",
            task_name="Audit Current HTTP Security Headers",
            action=(
                "Enumerate all HTTP response headers currently returned by the server on {ip}:{port}.\n\n"
                "LOCATE: Open a terminal and run a curl header check.\n\n"
                "WHAT TO RUN:\n"
                "  curl -I -k https://{ip}:{port}/\n"
                "  OR use securityheaders.com for a visual audit.\n\n"
                "LOOK FOR (❌ MISSING — these headers should be present but are absent):\n"
                "  - Strict-Transport-Security\n"
                "  - Content-Security-Policy\n"
                "  - X-Content-Type-Options\n"
                "  - X-Frame-Options\n"
                "  - Referrer-Policy\n"
                "  - Permissions-Policy\n\n"
                "EXAMPLE output showing missing headers:\n"
                "  HTTP/1.1 200 OK\n"
                "  Server: Apache/2.4.29\n"
                "  Content-Type: text/html\n"
                "  ← No security headers listed above = VULNERABLE"
            ),
            file_path="N/A",
            command_to_run="curl -I -k https://{ip}:{port}/",
            artifacts_tools_used="curl, securityheaders.com, browser DevTools",
            important_consideration="Note ALL missing headers — fix all in one change rather than multiple change records."
        ),
        MitigationStep(
            step_no=2,
            assigned_to="{assigned_to}",
            task_name="Add Security Headers to Web Server Configuration",
            action=(
                "Add all required HTTP security headers to the web server configuration.\n\n"
                "LOCATE the web server config:\n"
                "  Apache: /etc/apache2/sites-enabled/default-ssl.conf or /etc/apache2/conf-enabled/security.conf\n"
                "  Nginx: /etc/nginx/sites-enabled/default\n\n"
                "WHAT TO REMOVE (❌ if found — overly permissive header values):\n"
                "  X-Frame-Options ALLOWALL\n"
                "  Access-Control-Allow-Origin: *\n\n"
                "WHAT TO ADD (✅ insert these inside the VirtualHost or server block):\n"
                "  Apache:\n"
                "    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
                "    Header always set X-Content-Type-Options \"nosniff\"\n"
                "    Header always set X-Frame-Options \"DENY\"\n"
                "    Header always set Content-Security-Policy \"default-src 'self'\"\n"
                "    Header always set Referrer-Policy \"no-referrer-when-downgrade\"\n"
                "  Nginx:\n"
                "    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
                "    add_header X-Content-Type-Options \"nosniff\" always;\n"
                "    add_header X-Frame-Options \"DENY\" always;\n"
                "    add_header Content-Security-Policy \"default-src 'self'\" always;\n\n"
                "WHERE: Place inside the <VirtualHost *:443> block or equivalent HTTPS server block.\n\n"
                "ENABLE Apache headers module first (if not already):\n"
                "  sudo a2enmod headers && sudo systemctl restart apache2"
            ),
            file_path="/etc/apache2/sites-enabled/default-ssl.conf OR /etc/nginx/sites-enabled/default",
            command_to_run=(
                "# Enable Apache headers module\n"
                "sudo a2enmod headers\n"
                "# Edit config\n"
                "sudo nano /etc/apache2/sites-enabled/default-ssl.conf\n"
                "# Restart\n"
                "sudo systemctl restart apache2"
            ),
            artifacts_tools_used="nano, Apache mod_headers, Nginx, terminal",
            important_consideration=(
                "Content-Security-Policy must be tested carefully — overly strict CSP can break the application. "
                "Start with report-only mode: Content-Security-Policy-Report-Only."
            )
        ),
        MitigationStep(
            step_no=3,
            assigned_to="{assigned_to}",
            task_name="Verify Headers are Present",
            action=(
                "Confirm all security headers are now returned in server responses.\n\n"
                "WHAT TO RUN:\n"
                "  curl -I -k https://{ip}:{port}/\n\n"
                "EXPECTED OUTPUT (✅ all these must be present):\n"
                "  Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                "  X-Content-Type-Options: nosniff\n"
                "  X-Frame-Options: DENY\n"
                "  Content-Security-Policy: default-src 'self'\n"
                "  Referrer-Policy: no-referrer-when-downgrade\n\n"
                "ALSO TEST via securityheaders.com — should grade A or A+.\n\n"
                "COMPARE with Step 1 baseline to confirm all missing headers are now present."
            ),
            file_path="N/A",
            command_to_run=(
                "curl -I -k https://{ip}:{port}/ | grep -E 'Strict|X-Content|X-Frame|CSP|Referrer'"
            ),
            artifacts_tools_used="curl, securityheaders.com",
            important_consideration="Test from outside the server (different machine) to avoid localhost bypass."
        ),
    ]
)


# ---------------------------------------------------------------------------
# Registry — all templates in lookup order
# ---------------------------------------------------------------------------
TEMPLATE_REGISTRY: List[MitigationTemplate] = [
    SSL_WEAK_CIPHER,
    DEFAULT_CREDENTIALS,
    MISSING_PATCHES,
    OPEN_PORTS,
    MISSING_HEADERS,
]


def find_template(vuln_name: str, description: str = "") -> Optional[MitigationTemplate]:
    """Return the best-matching template for a given vulnerability."""
    combined = (vuln_name + " " + description).lower()
    for template in TEMPLATE_REGISTRY:
        if re.search(template.vuln_pattern, combined, re.IGNORECASE):
            return template
    return None


# Ordered substitution list — Linux path/command → Windows equivalent.
# Order matters: more specific patterns must come before shorter overlapping ones.
_LINUX_TO_WINDOWS = [
    # --- Paths ---
    ("/etc/apache2/sites-enabled/default-ssl.conf", r"C:\Apache24\conf\extra\httpd-ssl.conf"),
    ("/etc/apache2/mods-enabled/ssl.conf",          r"C:\Apache24\conf\extra\httpd-ssl.conf"),
    ("/etc/apache2/sites-enabled/",                 r"C:\Apache24\conf\extra\ "),
    ("/etc/apache2/conf-enabled/security.conf",     r"C:\Apache24\conf\extra\httpd-ssl.conf"),
    ("/etc/apache2/",                               r"C:\Apache24\conf\ "),
    ("/etc/nginx/sites-enabled/default",            r"C:\nginx\conf\nginx.conf"),
    ("/etc/nginx/conf.d/ssl.conf",                  r"C:\nginx\conf\nginx.conf"),
    ("/etc/nginx/sites-enabled/",                   r"C:\nginx\conf\ "),
    ("/etc/nginx/nginx.conf",                       r"C:\nginx\conf\nginx.conf"),
    ("/etc/nginx/",                                 r"C:\nginx\conf\ "),
    ("/etc/ssh/sshd_config",                        r"C:\ProgramData\ssh\sshd_config"),
    ("/etc/ssl/certs/dhparam.pem",                  r"C:\ProgramData\ssl\dhparam.pem"),
    ("/etc/ssl/certs/",                             r"C:\ProgramData\ssl\ "),
    ("/etc/ssl/",                                   r"C:\ProgramData\ssl\ "),
    ("/etc/pki/tls/certs/",                         r"C:\ProgramData\ssl\ "),
    ("/etc/pam.d/common-password",                  "Group Policy > Account Policies > Password Policy"),
    ("/etc/security/pwquality.conf",                "Group Policy > Password Policy settings"),
    ("/etc/passwd",                                 r"C:\Windows\System32\config\SAM  (use: net user)"),
    ("/etc/shadow",                                 r"C:\Windows\System32\config\SAM  (use: net user)"),
    ("/etc/",                                       r"C:\Windows\System32\ "),
    ("/var/log/apache2/error.log",                  r"C:\Apache24\logs\error.log"),
    ("/var/log/apache2/",                           r"C:\Apache24\logs\ "),
    ("/var/log/nginx/error.log",                    r"C:\nginx\logs\error.log"),
    ("/var/log/nginx/",                             r"C:\nginx\logs\ "),
    ("/var/log/security/remediations/",             r"C:\Security\Remediations\ "),
    ("/var/log/",                                   r"C:\Windows\Logs\ "),
    ("/tmp/cipher_scan_before.txt",                 r"%TEMP%\cipher_scan_before.txt"),
    ("/tmp/cipher_scan_after.txt",                  r"%TEMP%\cipher_scan_after.txt"),
    ("/tmp/svc_config_",                            r"%TEMP%\svc_config_"),
    ("/tmp/",                                       r"%TEMP%\ "),
    # --- Service management ---
    ("sudo systemctl restart apache2",              "net stop Apache2.4 && net start Apache2.4"),
    ("sudo systemctl restart httpd",                "net stop Apache2.4 && net start Apache2.4"),
    ("sudo systemctl restart nginx",                "nginx -s reload"),
    ("sudo systemctl stop vsftpd",                  "net stop ftpsvc"),
    ("sudo systemctl disable vsftpd",               "sc config ftpsvc start= disabled"),
    ("sudo systemctl stop telnet.socket",           "net stop TlntSvr"),
    ("sudo systemctl disable telnet.socket",        "sc config TlntSvr start= disabled"),
    ("sudo systemctl stop ",                        "net stop "),
    ("sudo systemctl start ",                       "net start "),
    ("sudo systemctl status apache2",               "sc query Apache2.4"),
    ("sudo systemctl status nginx",                 "sc query nginx"),
    ("sudo systemctl status ",                      "sc query "),
    ("sudo systemctl enable ssh",                   "sc config sshd start= auto && net start sshd"),
    ("sudo systemctl",                              "sc"),
    ("systemctl list-units --type=service",         'Get-Service | Where-Object {$_.Status -eq "Running"}'),
    # --- File editing ---
    ("sudo nano /etc/apache2/",                     r"notepad C:\Apache24\conf\ "),
    ("sudo nano /etc/nginx/",                       r"notepad C:\nginx\conf\ "),
    ("sudo nano /etc/ssh/sshd_config",              r"notepad C:\ProgramData\ssh\sshd_config"),
    ("sudo nano ",                                  "notepad "),
    ("sudo vim ",                                   "notepad "),
    ("sudo vi ",                                    "notepad "),
    # --- File operations ---
    ("cp /etc/apache2/sites-enabled/default-ssl.conf ",
     r'copy "C:\Apache24\conf\extra\httpd-ssl.conf" '),
    (".bak_$(date +%Y%m%d)",                        ".bak_%date:~-4,4%%date:~-10,2%%date:~-7,2%"),
    ("$(date +%Y%m%d)",                             "%date:~-4,4%%date:~-10,2%%date:~-7,2%"),
    ("tar -czf ",                                   "Compress-Archive -Path "),
    ("sudo cp ",                                    "copy "),
    ("cp ",                                         "copy "),
    # --- Process / service listing ---
    ("ps aux | grep -E 'apache|nginx|httpd'",       'sc query Apache2.4 | findstr "STATE" && sc query nginx | findstr "STATE"'),
    ("ps aux | grep",                               "Get-Process |"),
    ("ss -tlnp | grep",                             "netstat -ano | findstr"),
    ("ss -tlnp",                                    "netstat -ano"),
    # --- Log tailing ---
    ("tail -f /var/log/apache2/error.log | grep -iE",
     r'Get-Content C:\Apache24\logs\error.log -Wait | Select-String -Pattern'),
    ("tail -f /var/log/nginx/error.log | grep -iE",
     r'Get-Content C:\nginx\logs\error.log -Wait | Select-String -Pattern'),
    ("tail -f ",                                    "Get-Content -Wait "),
    ("tail -50 ",                                   "Get-Content -Tail 50 "),
    ("tail -",                                      "Get-Content -Tail "),
    # --- Grep / text search ---
    ("grep -iE",                                    "Select-String -Pattern"),
    ("grep -E",                                     "Select-String -Pattern"),
    ("grep -v nologin",                             'Where-Object {$_.Enabled -eq $true}'),
    ("grep -v",                                     "Where-Object"),
    ("grep",                                        "Select-String"),
    # --- Package management ---
    ("sudo apt-get update && sudo apt-get install --only-upgrade ",
     "choco upgrade "),
    ("sudo apt-get install --only-upgrade ",        "choco upgrade "),
    ("sudo apt-get install openssh-server",
     "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"),
    ("sudo apt-get install ",                       "choco install "),
    ("sudo apt-get update",                         "choco upgrade all"),
    ("sudo yum update ",                            "choco upgrade "),
    ("sudo yum install ",                           "choco install "),
    ("apt list --upgradable",                       "choco outdated"),
    ("yum check-update",                            "choco outdated"),
    ("dpkg -l | grep",                              "Get-Package | Where-Object {$_.Name -like"),
    ("dpkg -l",                                     "Get-Package"),
    ("rpm -q ",                                     "Get-Package -Name "),
    # --- Firewall ---
    ("sudo ufw deny in ",                           "netsh advfirewall firewall add rule name='Block Port' dir=in action=block protocol=TCP localport="),
    ("sudo ufw deny ",                              "netsh advfirewall firewall add rule name='Block' dir=in action=block protocol=TCP localport="),
    ("sudo ufw status",                             "netsh advfirewall show allprofiles"),
    ("sudo ufw",                                    "netsh advfirewall"),
    ("sudo iptables -A INPUT",                      "netsh advfirewall firewall add rule name='Block' dir=in action=block protocol=TCP"),
    ("sudo iptables",                               "netsh advfirewall firewall"),
    ("sudo firewall-cmd",                           "netsh advfirewall firewall"),
    # --- Apache modules ---
    ("sudo a2enmod headers",
     r"# Enable headers: edit C:\Apache24\conf\httpd.conf — uncomment: LoadModule headers_module modules/mod_headers.so"),
    ("sudo a2enmod ",
     r"# Enable Apache module: edit C:\Apache24\conf\httpd.conf — uncomment the LoadModule line"),
    # --- User management ---
    ("sudo usermod -L ",                            "net user /active:no "),
    ("sudo userdel -r ",                            "net user /delete "),
    ("sudo passwd ",                                "net user <username> <newpassword>  # Windows: "),
    ("cat /etc/passwd | grep",                      "net user"),
    ("cat /etc/shadow | awk",                       "net user"),
    ("cat /etc/passwd",                             "net user"),
    # --- OpenSSL ---
    ("openssl dhparam -out /etc/ssl/certs/dhparam.pem",
     r'"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" dhparam -out C:\ProgramData\ssl\dhparam.pem'),
    ("openssl dhparam",
     r'"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" dhparam'),
    ("openssl ",
     r'"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" '),
    # --- Journald ---
    ("journalctl -xe | tail -50",                   "Get-EventLog -LogName Application -Newest 50"),
    ("journalctl -xe",                              "Get-EventLog -LogName Application -Newest 50"),
    # --- sudo catch-all (last) ---
    ("sudo ",                                       ""),  # strip remaining sudo
]


def _apply_windows_substitution(text: str) -> str:
    """Replace Linux-specific paths and commands with Windows equivalents."""
    for linux_pattern, windows_replacement in _LINUX_TO_WINDOWS:
        text = text.replace(linux_pattern, windows_replacement)
    return text


def render_steps(template: MitigationTemplate, context: dict) -> List[MitigationStep]:
    """Return a copy of the template steps with context variables filled in.
    When os_category in context is 'windows', Linux commands/paths are replaced
    with Windows equivalents before returning.
    """
    os_category = context.get("os_category", "linux")

    filled = []
    for s in template.steps:
        def fill(text: str) -> str:
            for k, v in context.items():
                text = text.replace("{" + k + "}", str(v))
            if os_category == "windows":
                text = _apply_windows_substitution(text)
            return text

        filled.append(MitigationStep(
            step_no=s.step_no,
            assigned_to=fill(s.assigned_to),
            task_name=fill(s.task_name),
            action=fill(s.action),
            file_path=fill(s.file_path),
            command_to_run=fill(s.command_to_run),
            artifacts_tools_used=fill(s.artifacts_tools_used),
            important_consideration=fill(s.important_consideration),
        ))
    return filled
