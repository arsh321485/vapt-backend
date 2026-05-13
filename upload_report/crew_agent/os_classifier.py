"""
OS Classifier — Precise Terminology & Profile Definitions (v3)

Every term used in the mitigation card is defined here.
No generic fallbacks — each OS has exact language for shell, editor, paths, commands.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict


class OSFamily(str, Enum):
    WINDOWS       = "windows"
    LINUX_DEBIAN  = "linux_debian"   # Ubuntu, Debian, Kali, Mint, Pop!_OS
    LINUX_RHEL    = "linux_rhel"     # RHEL, CentOS, Rocky, AlmaLinux, Fedora
    LINUX_SUSE    = "linux_suse"     # SUSE, openSUSE
    LINUX_GENERIC = "linux_generic"
    MACOS         = "macos"


@dataclass(frozen=True)
class OSProfile:
    family:        OSFamily
    display_name:  str

    # ── Exact UI / shell terminology ─────────────────────────────────────
    open_shell_admin: str       # "Open PowerShell as Administrator"
    open_shell_user:  str       # "Open a Terminal"
    shell_label:      str       # "PowerShell", "Terminal"
    editor_name:      str       # "Notepad", "nano"
    open_editor:      str       # "notepad {file}", "sudo nano {file}"
    sudo_prefix:      str       # "" (PowerShell already elevated), "sudo "

    # ── Package management ──────────────────────────────────────────────
    pkg_install:        str
    pkg_upgrade:        str
    pkg_update_index:   str
    pkg_remove:         str
    pkg_query:          str

    # ── Service management ──────────────────────────────────────────────
    svc_start:    str
    svc_stop:     str
    svc_restart:  str
    svc_enable:   str
    svc_disable:  str
    svc_status:   str

    apache_svc_name: str
    nginx_svc_name:  str

    # ── Process inspection ──────────────────────────────────────────────
    list_processes: str
    find_process:   str

    # ── File operations ─────────────────────────────────────────────────
    copy_file:  str
    list_dir:   str
    read_file:  str
    tail_log:   str
    grep_file:  str

    # ── Network / ports ─────────────────────────────────────────────────
    list_ports:      str
    block_port_tcp:  str
    check_port:      str
    firewall_tool:   str
    firewall_list:   str

    # ── SSL / Crypto ─────────────────────────────────────────────────────
    ssl_scan:    str
    ssl_verify:  str
    gen_dhparam: str

    # ── Apache config paths ──────────────────────────────────────────────
    apache_ssl_conf:    str
    apache_main_conf:   str
    apache_validate:    str
    apache_restart_cmd: str
    apache_log_error:   str
    apache_log_access:  str

    # ── Nginx config paths ───────────────────────────────────────────────
    nginx_ssl_conf:    str
    nginx_main_conf:   str
    nginx_validate:    str
    nginx_restart_cmd: str
    nginx_log_error:   str
    nginx_log_access:  str

    # ── SSL certificate directories ──────────────────────────────────────
    ssl_cert_dir:  str
    dhparam_path:  str

    # ── SSH ──────────────────────────────────────────────────────────────
    ssh_config: str

    # ── User management ─────────────────────────────────────────────────
    list_users:       str
    change_password:  str
    lock_account:     str
    disable_account:  str

    # ── System info ──────────────────────────────────────────────────────
    os_version_cmd: str


# =========================================================================== #
# Profile: Windows (Server / Desktop)
# =========================================================================== #

_WIN = OSProfile(
    family       = OSFamily.WINDOWS,
    display_name = "Windows",

    open_shell_admin = "Open PowerShell as Administrator (right-click Start → Windows PowerShell (Admin))",
    open_shell_user  = "Open PowerShell or Command Prompt",
    shell_label      = "PowerShell",
    editor_name      = "Notepad",
    open_editor      = 'notepad "{file}"',
    sudo_prefix      = "",

    pkg_install      = "choco install -y {pkg}",
    pkg_upgrade      = "choco upgrade -y {pkg}",
    pkg_update_index = "choco upgrade -y chocolatey",
    pkg_remove       = "choco uninstall -y {pkg}",
    pkg_query        = 'Get-WmiObject -Class Win32_Product | Where-Object {{$_.Name -like "*{pkg}*"}} | Select-Object Name,Version',

    svc_start   = 'Start-Service -Name "{svc}"',
    svc_stop    = 'Stop-Service  -Name "{svc}" -Force',
    svc_restart = 'Restart-Service -Name "{svc}" -Force',
    svc_enable  = 'Set-Service -Name "{svc}" -StartupType Automatic',
    svc_disable = 'Set-Service -Name "{svc}" -StartupType Disabled',
    svc_status  = 'Get-Service -Name "{svc}" | Select-Object Name,Status,StartType',

    apache_svc_name = "Apache2.4",
    nginx_svc_name  = "nginx",

    list_processes = "Get-Process | Select-Object Name,Id,CPU | Sort-Object CPU -Descending",
    find_process   = 'Get-Process | Where-Object {{$_.Name -like "*{proc}*"}}',

    copy_file  = 'Copy-Item -Path "{src}" -Destination "{dst}" -Force',
    list_dir   = "Get-ChildItem",
    read_file  = 'Get-Content "{file}"',
    tail_log   = 'Get-Content "{file}" -Wait -Tail 50',
    grep_file  = 'Select-String -Path "{file}" -Pattern "{pattern}"',

    list_ports      = "netstat -ano",
    block_port_tcp  = 'netsh advfirewall firewall add rule name="Block TCP {port}" dir=in action=block protocol=TCP localport={port}',
    check_port      = "Test-NetConnection -ComputerName {ip} -Port {port}",
    firewall_tool   = "Windows Defender Firewall (netsh advfirewall)",
    firewall_list   = "netsh advfirewall firewall show rule name=all dir=in",

    ssl_scan    = "nmap --script ssl-enum-ciphers -p {port} {ip}",
    ssl_verify  = 'openssl s_client -connect {ip}:{port}',
    gen_dhparam = 'openssl dhparam -out "{out}" 2048',

    apache_ssl_conf    = "C:\\Apache24\\conf\\extra\\httpd-ssl.conf",
    apache_main_conf   = "C:\\Apache24\\conf\\httpd.conf",
    apache_validate    = "C:\\Apache24\\bin\\httpd.exe -t",
    apache_restart_cmd = 'Restart-Service -Name "Apache2.4" -Force',
    apache_log_error   = "C:\\Apache24\\logs\\error.log",
    apache_log_access  = "C:\\Apache24\\logs\\access.log",

    nginx_ssl_conf    = "C:\\nginx\\conf\\nginx.conf",
    nginx_main_conf   = "C:\\nginx\\conf\\nginx.conf",
    nginx_validate    = "C:\\nginx\\nginx.exe -t",
    nginx_restart_cmd = "C:\\nginx\\nginx.exe -s reload",
    nginx_log_error   = "C:\\nginx\\logs\\error.log",
    nginx_log_access  = "C:\\nginx\\logs\\access.log",

    ssl_cert_dir = "C:\\ProgramData\\ssl\\certs\\",
    dhparam_path = "C:\\ProgramData\\ssl\\certs\\dhparam.pem",

    ssh_config = "C:\\ProgramData\\ssh\\sshd_config",

    list_users      = "Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,LastLogon",
    change_password = 'net user {user} "NewStr0ngP@ss#2024!"',
    lock_account    = 'Disable-LocalUser -Name "{user}"',
    disable_account = 'Disable-LocalUser -Name "{user}"',

    os_version_cmd = "Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsHardwareAbstractionLayer",
)


# =========================================================================== #
# Profile: Ubuntu / Debian
# =========================================================================== #

_UBUNTU = OSProfile(
    family       = OSFamily.LINUX_DEBIAN,
    display_name = "Ubuntu / Debian",

    open_shell_admin = "Open a Terminal (Ctrl+Alt+T) — commands below require sudo",
    open_shell_user  = "Open a Terminal (Ctrl+Alt+T)",
    shell_label      = "Terminal",
    editor_name      = "nano",
    open_editor      = "sudo nano {file}",
    sudo_prefix      = "sudo ",

    pkg_install      = "sudo apt-get install -y {pkg}",
    pkg_upgrade      = "sudo apt-get install --only-upgrade {pkg}",
    pkg_update_index = "sudo apt-get update",
    pkg_remove       = "sudo apt-get remove --purge {pkg}",
    pkg_query        = "dpkg -l | grep {pkg}",

    svc_start   = "sudo systemctl start {svc}",
    svc_stop    = "sudo systemctl stop {svc}",
    svc_restart = "sudo systemctl restart {svc}",
    svc_enable  = "sudo systemctl enable {svc}",
    svc_disable = "sudo systemctl disable {svc}",
    svc_status  = "sudo systemctl status {svc}",

    apache_svc_name = "apache2",
    nginx_svc_name  = "nginx",

    list_processes = "ps aux --sort=-%cpu | head -20",
    find_process   = "ps aux | grep {proc}",

    copy_file  = 'cp "{src}" "{dst}"',
    list_dir   = "ls -la",
    read_file  = "cat {file}",
    tail_log   = "sudo tail -f {file}",
    grep_file  = "grep -n '{pattern}' {file}",

    list_ports      = "ss -tlnp",
    block_port_tcp  = "sudo ufw deny in {port}/tcp",
    check_port      = "nmap -p {port} {ip}",
    firewall_tool   = "UFW (Uncomplicated Firewall)",
    firewall_list   = "sudo ufw status verbose",

    ssl_scan    = "nmap --script ssl-enum-ciphers -p {port} {ip}",
    ssl_verify  = "openssl s_client -connect {ip}:{port}",
    gen_dhparam = "openssl dhparam -out {out} 2048",

    apache_ssl_conf    = "/etc/apache2/sites-enabled/default-ssl.conf",
    apache_main_conf   = "/etc/apache2/apache2.conf",
    apache_validate    = "sudo apachectl configtest",
    apache_restart_cmd = "sudo systemctl restart apache2",
    apache_log_error   = "/var/log/apache2/error.log",
    apache_log_access  = "/var/log/apache2/access.log",

    nginx_ssl_conf    = "/etc/nginx/sites-enabled/default",
    nginx_main_conf   = "/etc/nginx/nginx.conf",
    nginx_validate    = "sudo nginx -t",
    nginx_restart_cmd = "sudo systemctl restart nginx",
    nginx_log_error   = "/var/log/nginx/error.log",
    nginx_log_access  = "/var/log/nginx/access.log",

    ssl_cert_dir = "/etc/ssl/certs/",
    dhparam_path = "/etc/ssl/certs/dhparam.pem",

    ssh_config = "/etc/ssh/sshd_config",

    list_users      = "cut -d: -f1,3,7 /etc/passwd | awk -F: '$2>=1000 && $3 !~/nologin|false/{print $1, $3}'",
    change_password = "sudo passwd {user}",
    lock_account    = "sudo usermod -L {user}",
    disable_account = "sudo usermod --shell /usr/sbin/nologin --expiredate 1 {user}",

    os_version_cmd = "lsb_release -a && uname -r",
)


# =========================================================================== #
# Profile: RHEL / CentOS / Rocky / AlmaLinux
# =========================================================================== #

_RHEL = OSProfile(
    family       = OSFamily.LINUX_RHEL,
    display_name = "RHEL / CentOS / Rocky / AlmaLinux",

    open_shell_admin = "Open a Terminal — commands below require sudo or root",
    open_shell_user  = "Open a Terminal",
    shell_label      = "Terminal",
    editor_name      = "nano",
    open_editor      = "sudo nano {file}",
    sudo_prefix      = "sudo ",

    pkg_install      = "sudo yum install -y {pkg}",
    pkg_upgrade      = "sudo yum update -y {pkg}",
    pkg_update_index = "sudo yum check-update",
    pkg_remove       = "sudo yum remove -y {pkg}",
    pkg_query        = "rpm -qa | grep {pkg}",

    svc_start   = "sudo systemctl start {svc}",
    svc_stop    = "sudo systemctl stop {svc}",
    svc_restart = "sudo systemctl restart {svc}",
    svc_enable  = "sudo systemctl enable {svc}",
    svc_disable = "sudo systemctl disable {svc}",
    svc_status  = "sudo systemctl status {svc}",

    apache_svc_name = "httpd",
    nginx_svc_name  = "nginx",

    list_processes = "ps aux --sort=-%cpu | head -20",
    find_process   = "ps aux | grep {proc}",

    copy_file  = 'cp "{src}" "{dst}"',
    list_dir   = "ls -la",
    read_file  = "cat {file}",
    tail_log   = "sudo tail -f {file}",
    grep_file  = "grep -n '{pattern}' {file}",

    list_ports      = "ss -tlnp",
    block_port_tcp  = "sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 port port={port} protocol=tcp reject' && sudo firewall-cmd --reload",
    check_port      = "nmap -p {port} {ip}",
    firewall_tool   = "firewalld (firewall-cmd)",
    firewall_list   = "sudo firewall-cmd --list-all",

    ssl_scan    = "nmap --script ssl-enum-ciphers -p {port} {ip}",
    ssl_verify  = "openssl s_client -connect {ip}:{port}",
    gen_dhparam = "openssl dhparam -out {out} 2048",

    apache_ssl_conf    = "/etc/httpd/conf.d/ssl.conf",
    apache_main_conf   = "/etc/httpd/conf/httpd.conf",
    apache_validate    = "sudo apachectl configtest",
    apache_restart_cmd = "sudo systemctl restart httpd",
    apache_log_error   = "/var/log/httpd/error_log",
    apache_log_access  = "/var/log/httpd/access_log",

    nginx_ssl_conf    = "/etc/nginx/conf.d/default.conf",
    nginx_main_conf   = "/etc/nginx/nginx.conf",
    nginx_validate    = "sudo nginx -t",
    nginx_restart_cmd = "sudo systemctl restart nginx",
    nginx_log_error   = "/var/log/nginx/error.log",
    nginx_log_access  = "/var/log/nginx/access.log",

    ssl_cert_dir = "/etc/pki/tls/certs/",
    dhparam_path = "/etc/pki/tls/certs/dhparam.pem",

    ssh_config = "/etc/ssh/sshd_config",

    list_users      = "cut -d: -f1,3,7 /etc/passwd | awk -F: '$2>=1000 && $3 !~/nologin|false/{print $1, $3}'",
    change_password = "sudo passwd {user}",
    lock_account    = "sudo usermod -L {user}",
    disable_account = "sudo usermod --shell /sbin/nologin --expiredate 1 {user}",

    os_version_cmd = "cat /etc/redhat-release && uname -r",
)


# =========================================================================== #
# Profile: SUSE / openSUSE
# =========================================================================== #

_SUSE = OSProfile(
    family       = OSFamily.LINUX_SUSE,
    display_name = "SUSE / openSUSE",

    open_shell_admin = "Open a Terminal — commands below require sudo or root",
    open_shell_user  = "Open a Terminal",
    shell_label      = "Terminal",
    editor_name      = "nano",
    open_editor      = "sudo nano {file}",
    sudo_prefix      = "sudo ",

    pkg_install      = "sudo zypper install -y {pkg}",
    pkg_upgrade      = "sudo zypper update -y {pkg}",
    pkg_update_index = "sudo zypper refresh",
    pkg_remove       = "sudo zypper remove -y {pkg}",
    pkg_query        = "rpm -qa | grep {pkg}",

    svc_start   = "sudo systemctl start {svc}",
    svc_stop    = "sudo systemctl stop {svc}",
    svc_restart = "sudo systemctl restart {svc}",
    svc_enable  = "sudo systemctl enable {svc}",
    svc_disable = "sudo systemctl disable {svc}",
    svc_status  = "sudo systemctl status {svc}",

    apache_svc_name = "apache2",
    nginx_svc_name  = "nginx",

    list_processes = "ps aux --sort=-%cpu | head -20",
    find_process   = "ps aux | grep {proc}",

    copy_file  = 'cp "{src}" "{dst}"',
    list_dir   = "ls -la",
    read_file  = "cat {file}",
    tail_log   = "sudo tail -f {file}",
    grep_file  = "grep -n '{pattern}' {file}",

    list_ports      = "ss -tlnp",
    block_port_tcp  = "sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 port port={port} protocol=tcp reject' && sudo firewall-cmd --reload",
    check_port      = "nmap -p {port} {ip}",
    firewall_tool   = "firewalld (firewall-cmd)",
    firewall_list   = "sudo firewall-cmd --list-all",

    ssl_scan    = "nmap --script ssl-enum-ciphers -p {port} {ip}",
    ssl_verify  = "openssl s_client -connect {ip}:{port}",
    gen_dhparam = "openssl dhparam -out {out} 2048",

    apache_ssl_conf    = "/etc/apache2/vhosts.d/vhost-ssl.conf",
    apache_main_conf   = "/etc/apache2/httpd.conf",
    apache_validate    = "sudo apachectl configtest",
    apache_restart_cmd = "sudo systemctl restart apache2",
    apache_log_error   = "/var/log/apache2/error.log",
    apache_log_access  = "/var/log/apache2/access.log",

    nginx_ssl_conf    = "/etc/nginx/vhosts.d/default-ssl.conf",
    nginx_main_conf   = "/etc/nginx/nginx.conf",
    nginx_validate    = "sudo nginx -t",
    nginx_restart_cmd = "sudo systemctl restart nginx",
    nginx_log_error   = "/var/log/nginx/error.log",
    nginx_log_access  = "/var/log/nginx/access.log",

    ssl_cert_dir = "/etc/ssl/certs/",
    dhparam_path = "/etc/ssl/certs/dhparam.pem",

    ssh_config = "/etc/ssh/sshd_config",

    list_users      = "cut -d: -f1,3,7 /etc/passwd | awk -F: '$2>=1000 && $3 !~/nologin|false/{print $1, $3}'",
    change_password = "sudo passwd {user}",
    lock_account    = "sudo usermod -L {user}",
    disable_account = "sudo usermod --shell /sbin/nologin --expiredate 1 {user}",

    os_version_cmd = "cat /etc/os-release && uname -r",
)


# =========================================================================== #
# Profile: macOS
# =========================================================================== #

_MACOS = OSProfile(
    family       = OSFamily.MACOS,
    display_name = "macOS",

    open_shell_admin = "Open Terminal (Applications → Utilities → Terminal) — commands below use sudo",
    open_shell_user  = "Open Terminal (Applications → Utilities → Terminal)",
    shell_label      = "Terminal",
    editor_name      = "nano",
    open_editor      = "sudo nano {file}",
    sudo_prefix      = "sudo ",

    pkg_install      = "brew install {pkg}",
    pkg_upgrade      = "brew upgrade {pkg}",
    pkg_update_index = "brew update",
    pkg_remove       = "brew uninstall {pkg}",
    pkg_query        = "brew info {pkg}",

    svc_start   = "sudo brew services start {svc}",
    svc_stop    = "sudo brew services stop {svc}",
    svc_restart = "sudo brew services restart {svc}",
    svc_enable  = "sudo brew services start {svc}",
    svc_disable = "sudo brew services stop {svc}",
    svc_status  = "sudo brew services list | grep {svc}",

    apache_svc_name = "httpd",
    nginx_svc_name  = "nginx",

    list_processes = "ps aux | sort -rk 3 | head -20",
    find_process   = "ps aux | grep {proc}",

    copy_file  = 'cp "{src}" "{dst}"',
    list_dir   = "ls -la",
    read_file  = "cat {file}",
    tail_log   = "sudo tail -f {file}",
    grep_file  = "grep -n '{pattern}' {file}",

    list_ports      = "lsof -i -n -P | grep LISTEN",
    block_port_tcp  = "# Add to /etc/pf.conf: block in proto tcp from any to any port {port}  →  then: sudo pfctl -f /etc/pf.conf",
    check_port      = "nmap -p {port} {ip}",
    firewall_tool   = "pf (Packet Filter) via /etc/pf.conf",
    firewall_list   = "sudo pfctl -sr",

    ssl_scan    = "nmap --script ssl-enum-ciphers -p {port} {ip}",
    ssl_verify  = "openssl s_client -connect {ip}:{port}",
    gen_dhparam = "openssl dhparam -out {out} 2048",

    apache_ssl_conf    = "/usr/local/etc/httpd/extra/httpd-ssl.conf",
    apache_main_conf   = "/usr/local/etc/httpd/httpd.conf",
    apache_validate    = "sudo apachectl configtest",
    apache_restart_cmd = "sudo brew services restart httpd",
    apache_log_error   = "/usr/local/var/log/httpd/error_log",
    apache_log_access  = "/usr/local/var/log/httpd/access_log",

    nginx_ssl_conf    = "/usr/local/etc/nginx/servers/default-ssl.conf",
    nginx_main_conf   = "/usr/local/etc/nginx/nginx.conf",
    nginx_validate    = "sudo nginx -t",
    nginx_restart_cmd = "sudo brew services restart nginx",
    nginx_log_error   = "/usr/local/var/log/nginx/error.log",
    nginx_log_access  = "/usr/local/var/log/nginx/access.log",

    ssl_cert_dir = "/usr/local/etc/ssl/",
    dhparam_path = "/usr/local/etc/ssl/dhparam.pem",

    ssh_config = "/etc/ssh/sshd_config",

    list_users      = "dscl . list /Users | grep -v '^_'",
    change_password = "sudo dscl . -passwd /Users/{user}",
    lock_account    = "sudo dscl . -create /Users/{user} AuthenticationAuthority ';DisabledUser;'",
    disable_account = "sudo dscl . -create /Users/{user} UserShell /usr/bin/false",

    os_version_cmd = "sw_vers",
)


# =========================================================================== #
# Detection + Registry
# =========================================================================== #

_DETECTION_RULES: list = [
    (["windows server", "windows 10", "windows 11", "windows 2022", "windows 2019",
      "windows 2016", "windows 2012", "win server", "winnt", "microsoft windows",
      "iis", "server 2019", "server 2022", "server 2016"], OSFamily.WINDOWS),
    (["rhel", "red hat", "centos", "rocky", "almalinux", "fedora", "oracle linux"], OSFamily.LINUX_RHEL),
    (["suse", "opensuse", "sles"], OSFamily.LINUX_SUSE),
    (["ubuntu", "debian", "kali", "mint", "pop!_os", "elementary", "raspbian"], OSFamily.LINUX_DEBIAN),
    (["macos", "mac os x", "darwin", "osx"], OSFamily.MACOS),
    (["linux", "unix"], OSFamily.LINUX_GENERIC),
]

_PROFILES: Dict[OSFamily, OSProfile] = {
    OSFamily.WINDOWS:       _WIN,
    OSFamily.LINUX_DEBIAN:  _UBUNTU,
    OSFamily.LINUX_RHEL:    _RHEL,
    OSFamily.LINUX_SUSE:    _SUSE,
    OSFamily.LINUX_GENERIC: _UBUNTU,   # safe fallback
    OSFamily.MACOS:         _MACOS,
}


def detect_os_family(os_string: str) -> OSFamily:
    s = os_string.lower().strip()
    for keywords, family in _DETECTION_RULES:
        if any(k in s for k in keywords):
            return family
    return OSFamily.LINUX_GENERIC


def get_profile(os_string: str) -> OSProfile:
    return _PROFILES[detect_os_family(os_string)]


def is_windows(os_string: str) -> bool:
    return detect_os_family(os_string) == OSFamily.WINDOWS


def is_linux(os_string: str) -> bool:
    return detect_os_family(os_string) in (
        OSFamily.LINUX_DEBIAN, OSFamily.LINUX_RHEL, OSFamily.LINUX_SUSE, OSFamily.LINUX_GENERIC
    )
