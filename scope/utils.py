import ipaddress
import re
import logging
from io import BytesIO
from typing import Tuple, List, Dict, Optional

import sendgrid
from sendgrid.helpers.mail import Mail
from django.conf import settings

logger = logging.getLogger(__name__)

# Internal IP ranges (RFC 1918 + loopback)
INTERNAL_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Mobile URL patterns
MOBILE_URL_PATTERNS = [
    r"^(https?://)?(m\.|mobile\.)",
    r"\.(apk|ipa)$",
    r"(android|ios|mobile|app)\.",
    r"://api\.",
    r"(play\.google\.com|apps\.apple\.com)",
]

# Maximum subnet size to expand (prevent database overload)
MAX_SUBNET_EXPANSION = 24  # /24 = 256 IPs


def is_internal_ip(ip_str: str) -> bool:
    """Check if an IP address is in internal/private ranges."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        for net in INTERNAL_RANGES:
            if ip in net:
                return True
        return False
    except ValueError:
        return False


def is_internal_subnet(subnet_str: str) -> bool:
    """Check if a subnet's network address is in internal ranges."""
    try:
        network = ipaddress.ip_network(subnet_str.strip(), strict=False)
        network_address = network.network_address
        for net in INTERNAL_RANGES:
            if network_address in net:
                return True
        return False
    except ValueError:
        return False


def is_valid_ip(value: str) -> bool:
    """Validate if a string is a valid IP address."""
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_subnet(value: str) -> bool:
    """Validate if a string is a valid subnet (CIDR notation)."""
    try:
        if "/" not in value:
            return False
        ipaddress.ip_network(value.strip(), strict=False)
        return True
    except ValueError:
        return False


# Bare filenames (no http(s):// scheme) whose extension looks exactly like
# a 2+ letter TLD — e.g. "test.apk", "report.pdf", "photo.png" — used to
# pass is_valid_url's regex, which only checks the shape "word.word", not
# whether that "word" is a plausible TLD. Confirmed via real testing:
# pasting "test.apk" as a scope target got silently accepted (misdetected
# as a mobile app URL, since ".apk" also matches MOBILE_URL_PATTERNS).
_NON_URL_FILE_EXTENSIONS = {
    "apk", "ipa", "exe", "msi", "dmg", "deb", "rpm", "iso",
    "zip", "rar", "7z", "tar", "gz",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt",
    "png", "jpg", "jpeg", "gif", "bmp", "svg", "webp",
    "mp3", "mp4", "avi", "mov", "wav",
    "json", "xml", "log", "bak", "tmp",
}


def is_valid_url(value: str) -> bool:
    """Validate if a string is a valid URL."""
    value = value.strip()
    url_pattern = re.compile(
        r"^(https?://)?"
        r"([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
        r"(:\d+)?"
        r"(/.*)?$",
        re.IGNORECASE
    )
    if not url_pattern.match(value):
        return False

    # Reject bare filenames with no scheme whose "TLD" is really just a
    # file extension — a legitimate mobile-app-download URL still passes
    # since it either has http(s):// or a real path (contains "/").
    has_scheme = value.lower().startswith(("http://", "https://"))
    if not has_scheme and "/" not in value:
        last_label = value.rsplit(".", 1)[-1].split(":")[0].lower()
        if last_label in _NON_URL_FILE_EXTENSIONS:
            return False

    return True


def is_mobile_url(value: str) -> bool:
    """Detect if a URL is likely a mobile URL based on patterns."""
    value_lower = value.lower().strip()
    for pattern in MOBILE_URL_PATTERNS:
        if re.search(pattern, value_lower):
            return True
    return False


def expand_subnet(subnet_str: str) -> List[str]:
    """
    Expand a subnet into individual IP addresses.
    Only expands subnets up to /24 (256 IPs) to prevent database overload.

    Returns:
        List of individual IP addresses as strings
    """
    try:
        network = ipaddress.ip_network(subnet_str.strip(), strict=False)
        prefix_len = network.prefixlen

        # Check if subnet is too large to expand
        if prefix_len < MAX_SUBNET_EXPANSION:
            logger.warning(
                f"Subnet {subnet_str} is too large to expand (/{prefix_len}). "
                f"Maximum is /{MAX_SUBNET_EXPANSION}"
            )
            return []

        # Expand to individual IPs
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def detect_entry_type(value: str) -> Tuple[str, bool, Optional[str]]:
    """
    Auto-detect the entry type based on the value.

    Returns:
        Tuple of (entry_type, is_internal, subnet_mask)
    """
    value = value.strip()

    # Check for subnet (CIDR notation)
    if is_valid_subnet(value):
        is_internal = is_internal_subnet(value)
        try:
            network = ipaddress.ip_network(value, strict=False)
            subnet_mask = str(network.netmask)
        except ValueError:
            subnet_mask = None
        return ("subnet", is_internal, subnet_mask)

    # Check for IP address
    if is_valid_ip(value):
        is_internal = is_internal_ip(value)
        entry_type = "internal_ip" if is_internal else "external_ip"
        return (entry_type, is_internal, None)

    # Check for URL
    if is_valid_url(value):
        is_mobile = is_mobile_url(value)
        entry_type = "mobile_url" if is_mobile else "web_url"
        return (entry_type, False, None)

    # Default to external IP if nothing matches (will be validated later)
    return ("external_ip", False, None)


def validate_entry(value: str, entry_type: str) -> Tuple[bool, str]:
    """
    Validate an entry value against its type.

    Returns:
        Tuple of (is_valid, error_message)
    """
    value = value.strip()

    if not value:
        return (False, "Value cannot be empty")

    if entry_type in ("internal_ip", "external_ip"):
        if not is_valid_ip(value):
            return (False, f"Invalid IP address: {value}")
        return (True, "")

    if entry_type == "subnet":
        if not is_valid_subnet(value):
            return (False, f"Invalid subnet format: {value}")
        return (True, "")

    if entry_type in ("web_url", "mobile_url"):
        if not is_valid_url(value):
            return (False, f"Invalid URL format: {value}")
        return (True, "")

    return (False, f"Unknown entry type: {entry_type}")


def parse_file_content(file_obj, filename: str) -> List[str]:
    """
    Parse file content to extract values.
    Supports CSV, Excel (.xlsx, .xls), and Text (.txt) files.

    Returns:
        List of extracted values (stripped, non-empty)
    """
    values = []
    filename_lower = filename.lower()

    try:
        if filename_lower.endswith((".xlsx", ".xls")):
            # Excel file
            import pandas as pd
            df = pd.read_excel(BytesIO(file_obj.read()), header=None)
            for col in df.columns:
                for val in df[col].dropna():
                    str_val = str(val).strip()
                    if str_val:
                        values.append(str_val)

        elif filename_lower.endswith(".csv"):
            # CSV file
            import pandas as pd
            file_obj.seek(0)
            df = pd.read_csv(BytesIO(file_obj.read()), header=None)
            for col in df.columns:
                for val in df[col].dropna():
                    str_val = str(val).strip()
                    if str_val:
                        values.append(str_val)

        elif filename_lower.endswith(".txt"):
            # Text file - one value per line
            file_obj.seek(0)
            content = file_obj.read()
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="ignore")
            for line in content.splitlines():
                str_val = line.strip()
                if str_val:
                    values.append(str_val)

        else:
            # Try to read as text
            file_obj.seek(0)
            content = file_obj.read()
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="ignore")
            for line in content.splitlines():
                str_val = line.strip()
                if str_val:
                    values.append(str_val)

    except Exception as e:
        logger.error(f"Error parsing file {filename}: {str(e)}")
        raise ValueError(f"Failed to parse file: {str(e)}")

    return values


def parse_targets_string(targets_str: str) -> List[str]:
    """
    Parse a multiline string of targets into a list.

    Returns:
        List of targets (stripped, non-empty, unique)
    """
    values = []
    for line in targets_str.strip().splitlines():
        val = line.strip()
        if val and val not in values:
            values.append(val)
    return values


def process_entries(values: List[str], expand_subnets: bool = True) -> List[Dict]:
    """
    Process a list of values and return entry data with auto-detected types.

    Args:
        values: List of target values
        expand_subnets: If True, expand subnets to individual IPs

    Returns:
        List of dicts with keys: value, entry_type, is_internal, subnet_mask, is_valid, error
    """
    results = []
    seen_values = set()

    for value in values:
        value = value.strip()
        if not value or value in seen_values:
            continue

        seen_values.add(value)
        entry_type, is_internal, subnet_mask = detect_entry_type(value)
        is_valid, error = validate_entry(value, entry_type)

        # Handle subnet expansion
        if is_valid and entry_type == "subnet" and expand_subnets:
            expanded_ips = expand_subnet(value)

            if expanded_ips:
                # Add individual IPs instead of subnet
                for ip in expanded_ips:
                    if ip not in seen_values:
                        seen_values.add(ip)
                        ip_is_internal = is_internal_ip(ip)
                        ip_entry_type = "internal_ip" if ip_is_internal else "external_ip"
                        results.append({
                            "value": ip,
                            "entry_type": ip_entry_type,
                            "is_internal": ip_is_internal,
                            "subnet_mask": None,
                            "is_valid": True,
                            "error": None
                        })
            else:
                # Subnet too large or invalid - keep as subnet entry
                results.append({
                    "value": value,
                    "entry_type": entry_type,
                    "is_internal": is_internal,
                    "subnet_mask": subnet_mask,
                    "is_valid": True,
                    "error": None,
                    "warning": f"Subnet too large to expand (max /{MAX_SUBNET_EXPANSION})"
                })
        else:
            results.append({
                "value": value,
                "entry_type": entry_type,
                "is_internal": is_internal,
                "subnet_mask": subnet_mask,
                "is_valid": is_valid,
                "error": error if not is_valid else None
            })

    return results


def send_scope_lock_notification(scope_owner_email: str, scope_name: str, locked_by_email: str) -> bool:
    """Send email notification when a scope is locked."""
    try:
        sg = sendgrid.SendGridAPIClient(api_key=settings.SENDGRID_API_KEY)

        body = f"""
Dear Administrator,

Your scope "{scope_name}" has been locked.

Locked by: {locked_by_email}

If you believe this was done in error or need assistance, please contact your super administrator.

Thank you,
VAPTFIX Team
"""

        mail = Mail(
            from_email=settings.DEFAULT_FROM_EMAIL,
            to_emails=scope_owner_email,
            subject=f"Scope Locked: {scope_name}",
            plain_text_content=body,
        )

        response = sg.send(mail)
        logger.info(f"Scope lock notification sent to {scope_owner_email}: {response.status_code}")
        return response.status_code in [200, 201, 202]

    except Exception as e:
        logger.error(f"Failed to send scope lock notification: {str(e)}")
        return False


def send_new_scope_submission_email(superadmin_emails: List[str], admin_email: str, scope) -> bool:
    """
    Sent to every Super Admin the moment an admin submits a scope via
    "Enter Your Scope" (file upload or manual entry) — scope/views.py's
    ScopeCreateAPIView calls this right after the Scope/ScopeEntry rows are
    created. There's no scanning engine (see SCOPE_AUTO_SCAN_PROPOSAL.md),
    so a human has to notice and act on this — download the scope, test it
    externally, then upload the real result via Django Admin's "Add Upload
    Report" form (its "Fulfills Scope" dropdown, see upload_report/admin.py).

    Uses the same branded HTML template as billing's account-lifecycle
    emails (billing/account_lifecycle.py's _branded_email_html) instead of
    a raw plain-text SendGrid message — previously this rendered as an
    unstyled wall of text with no visual hierarchy or link to act on.
    """
    from users.utils import Util
    from billing.account_lifecycle import _branded_email_html

    try:
        target_count = scope.entries.count()
    except Exception:
        target_count = 0

    backend_url = getattr(settings, "VAPTFIX_BACKEND_URL", "").rstrip("/")
    admin_link = f"{backend_url}/admin/scope/scope/{scope.id}/change/" if backend_url else None

    def _row(label, value):
        return f"""
        <tr>
          <td style="padding:6px 0; color:#6b7280; font-size:14px; width:140px; vertical-align:top;">{label}</td>
          <td style="padding:6px 0; color:#1f2040; font-size:14px; font-weight:600;">{value}</td>
        </tr>
        """

    button_html = ""
    if admin_link:
        button_html = f"""
        <table cellpadding="0" cellspacing="0" style="margin:0 auto;">
          <tr><td style="background:#23124d; border-radius:8px;">
            <a href="{admin_link}"
               style="display:inline-block; padding:12px 26px; color:#ffffff; font-size:15px;
                      font-weight:600; text-decoration:none;">Review in Django Admin</a>
          </td></tr>
        </table>
        """

    body_html = f"""
        <p style="color:#3a3f4b; font-size:15px; line-height:1.6; margin:0 0 20px 0;">
            A new scope has been submitted and needs testing.
        </p>
        <table cellpadding="0" cellspacing="0" style="width:100%; margin:0 0 24px 0; border-collapse:collapse;">
          {_row("Submitted by", admin_email)}
          {_row("Scope name", scope.name)}
          {_row("Targets", target_count)}
        </table>
        <p style="color:#3a3f4b; font-size:15px; line-height:1.6; margin:0 0 24px 0;">
            Download this scope, test it externally, then upload the real result through
            <strong>&quot;Add Upload Report&quot;</strong> (using its
            <strong>&quot;Fulfills Scope&quot;</strong> dropdown) once testing is complete —
            the submitting admin will be emailed automatically once it's ready.
        </p>
        {button_html}
    """

    html, logo_b64 = _branded_email_html("📋 New scope submitted", body_html)
    ok, err = Util.send_mail({
        "to_email": superadmin_emails,
        "subject": f"New scope submitted: {scope.name} ({admin_email})",
        "html_content": html,
        "inline_logo_b64": logo_b64,
    })
    if not ok:
        logger.error(f"Failed to send new-scope-submission notification to {superadmin_emails}: {err}")
    return ok


def send_scope_report_ready_email(admin_email: str, scope_name: str) -> bool:
    """
    Sent once a Super Admin's test result "for" a submitted scope has
    finished automation-script (agent) generation — see
    upload_report/views.py's _auto_generate_cards_bg, which checks
    nessus_reports.scope_id (set from UploadReportAdminForm's
    "Fulfills Scope" dropdown) and calls this right after
    cards_generation_complete flips True. The admin submitted the scope
    and then had nothing to watch (a Super Admin tests it externally,
    possibly days later) — this email is what tells them to come back.
    """
    try:
        sg = sendgrid.SendGridAPIClient(api_key=settings.SENDGRID_API_KEY)

        body = f"""
Dear Administrator,

Good news — your submitted scope "{scope_name}" has been tested, and the
report is ready with full automation/remediation scripts generated for
every finding.

Log in to VAPTFIX to review the results and continue.

Thank you,
VAPTFIX Team
"""

        mail = Mail(
            from_email=settings.DEFAULT_FROM_EMAIL,
            to_emails=admin_email,
            subject=f"Your scope \"{scope_name}\" is ready — automation scripts generated",
            plain_text_content=body,
        )

        response = sg.send(mail)
        logger.info(f"Scope-ready notification sent to {admin_email}: {response.status_code}")
        return response.status_code in [200, 201, 202]

    except Exception as e:
        logger.error(f"Failed to send scope-ready notification: {str(e)}")
        return False


def send_contact_superadmin_email(
    admin_email: str,
    admin_name: str,
    scope_name: str,
    scope_id: str,
    subject: str,
    message: str,
    superadmin_email: str
) -> bool:
    """
    Send email to super admin when an admin needs assistance with a scope.
    """
    try:
        sg = sendgrid.SendGridAPIClient(api_key=settings.SENDGRID_API_KEY)

        body = f"""
Support Request from Admin

From: {admin_name} ({admin_email})
Scope: {scope_name}
Scope ID: {scope_id}

Subject: {subject}

Message:
{message}

---
This is an automated message from VAPTFIX.
Please respond directly to the admin at: {admin_email}
"""

        mail = Mail(
            from_email=settings.DEFAULT_FROM_EMAIL,
            to_emails=superadmin_email,
            subject=f"[VAPTFIX Support] {subject}",
            plain_text_content=body,
        )

        # Add reply-to header so super admin can reply directly to admin
        mail.reply_to = admin_email

        response = sg.send(mail)
        logger.info(f"Contact super admin email sent from {admin_email}: {response.status_code}")
        return response.status_code in [200, 201, 202]

    except Exception as e:
        logger.error(f"Failed to send contact super admin email: {str(e)}")
        return False


def get_superadmin_emails() -> List[str]:
    """
    Get list of super admin email addresses.

    Real bug found via testing send_new_scope_submission_email: djongo
    mistranslates a bare boolean filter (User.objects.filter(is_superuser=True))
    into invalid SQL and raises, which this function's except-block was
    silently swallowing — every call to this had been returning [] the
    whole time, so no scope/support/contact-superadmin notification email
    that depends on it was ever actually reaching anyone. Same djongo
    boolean-filter issue documented elsewhere in this codebase (e.g.
    upload_report/admin.py's admin dropdown) — fixed the same way, with a
    raw pymongo query instead of the ORM filter.
    """
    try:
        from vaptfix.mongo_client import get_shared_db
        db = get_shared_db()
        docs = db["users_user"].find({"is_superuser": True}, {"email": 1})
        return [d["email"] for d in docs if d.get("email")]
    except Exception as e:
        logger.error(f"Failed to get super admin emails: {str(e)}")
        return []
