from rest_framework import generics, permissions, status,filters
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from bson import ObjectId
from django.shortcuts import get_object_or_404
from .models import UserDetail
from .serializers import UserDetailSerializer, UserDetailCreateSerializer,UserDetailUpdateSerializer,UserDetailRoleUpdateSerializer
from django.utils import timezone
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import (
    Mail, Attachment, FileContent, FileName, FileType, Disposition, ContentId
)
from django.conf import settings
import logging
import base64
import os
import threading
import requests

REQUEST_TIMEOUT_SECONDS = 15

def _http_get(url, **kwargs):
    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT_SECONDS)
    return requests.get(url, timeout=timeout, **kwargs)

def _http_post(url, **kwargs):
    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT_SECONDS)
    return requests.post(url, timeout=timeout, **kwargs)

def _http_put(url, **kwargs):
    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT_SECONDS)
    return requests.put(url, timeout=timeout, **kwargs)

def _http_delete(url, **kwargs):
    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT_SECONDS)
    return requests.delete(url, timeout=timeout, **kwargs)

def _http_patch(url, **kwargs):
    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT_SECONDS)
    return requests.patch(url, timeout=timeout, **kwargs)

logger = logging.getLogger('users_details')


ROLE_TO_SLACK_CHANNEL = {
    "Patch Management": "patch-management",
    "Configuration Management": "configuration-management",
    "Network Security": "network-security",
    "Architectural Flaws": "architectural-flaws",
}

TEAM_EMAIL_CONTENT = {
    "Configuration Management": {
        "subject": "Welcome to the Configuration Management Team",
        "heading": "Welcome to the Configuration Management Team",
        "body": (
            "<p>Welcome to the Configuration Management team under the Vulnerability Management Program. "
            "Your expertise will be key in maintaining secure system baselines and ensuring compliance "
            "with our configuration standards across all environments.</p>"
            "<p>In this team, you'll review configuration-related vulnerabilities, track deviations from "
            "security baselines, and coordinate remediation with system owners. You'll work closely with "
            "patching and network teams to reduce exposure through hardened configurations and best practices.</p>"
            "<p>Access to configuration baselines, compliance reports, and monitoring tools will be provided "
            "this week. Take a moment to explore the documentation and connect with your team lead for guidance "
            "on current priorities.</p>"
            "<p>Thank you for joining us in driving proactive configuration security and stability.</p>"
        ),
    },
    "Architectural Flaws": {
        "subject": "Welcome to the Architectural Flaws Team",
        "heading": "Welcome to the Architectural Flaws Team",
        "body": (
            "<p>We're pleased to welcome you to the Architectural Flaws team — a vital part of our "
            "Vulnerability Management Program focused on addressing systemic design issues and long-term risk reduction.</p>"
            "<p>Your work will involve analyzing application, system, and network architectures to identify "
            "weaknesses that cannot be mitigated by simple patches or configuration changes. You'll collaborate "
            "with development, infrastructure, and risk teams to propose design improvements, compensating "
            "controls, and roadmap updates.</p>"
            "<p>In the next few days, you'll receive access to architectural diagrams, threat models, and "
            "the vulnerability backlog for your review. Don't hesitate to engage with your peers as we "
            "tackle foundational security enhancements together.</p>"
            "<p>Welcome aboard — your insight will help shape a more resilient architecture for the entire organization.</p>"
        ),
    },
    "Network Security": {
        "subject": "Welcome to the Network Security Team",
        "heading": "Welcome to the Network Security Team",
        "body": (
            "<p>Welcome to the Network Security team of our Vulnerability Management Program! Your contribution "
            "will be central to identifying, prioritizing, and resolving vulnerabilities within our network "
            "infrastructure and perimeter defenses.</p>"
            "<p>You'll focus on reviewing scan results, verifying exposure points, and coordinating remediation "
            "efforts to harden our firewalls, routers, and network-access systems. Continuous coordination with "
            "the patch and configuration teams ensures that vulnerabilities are addressed holistically.</p>"
            "<p>You'll soon receive access to our network vulnerability dashboards, asset inventory, and ticket "
            "tracking platform. Please familiarize yourself with the network remediation process and escalation contacts.</p>"
            "<p>We're thrilled to have your skills onboard in securing our organization's connectivity and defense layers.</p>"
        ),
    },
    "Patch Management": {
        "subject": "Welcome to the Patch Management Team",
        "heading": "Welcome to the Patch Management Team",
        "body": (
            "<p>Welcome to the Patch Management team under the Vulnerability Management Program. Your role will "
            "be critical in ensuring timely remediation of vulnerabilities through effective patching and software "
            "updates across all systems.</p>"
            "<p>In this team, you will focus on identifying missing patches, managing outdated software versions, "
            "and addressing vulnerabilities associated with known CVEs that have vendor-provided fixes. You will "
            "work closely with configuration and network teams to ensure systems are consistently updated and "
            "protected against known threats.</p>"
            "<p>Thank you for contributing to strengthening our security posture through proactive patch management.</p>"
        ),
    },
}


def sync_member_to_slack_channels(bot_token, slack_user_id, member_roles):
    """
    Invite a Slack user to the channels matching their Member_roles.
    Returns (results list, added_channel_ids list).
    """
    if not bot_token or not slack_user_id:
        return [], []

    headers = {"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"}
    results = []
    added_channel_ids = []

    # Debug: trace Slack IDs and roles used for invites
    logger.info(
        f"[SlackSync] Start: slack_user_id={slack_user_id} roles={member_roles} bot_token_set={bool(bot_token)}"
    )

    # Fetch existing channel list — Slack stores names as lowercase
    resp = _http_get(
        "https://slack.com/api/conversations.list",
        headers=headers,
        # Slack channels can be private; include both types so role->channel mapping works.
        params={"types": "public_channel,private_channel", "limit": 1000}, timeout=15
    )
    payload = resp.json() if resp is not None else {}
    channel_map = {ch["name"].lower(): ch["id"] for ch in payload.get("channels", [])}
    logger.info(f"[SlackSync] conversations.list status={resp.status_code} channels_found={len(channel_map)}")

    for role in member_roles:
        slack_name = ROLE_TO_SLACK_CHANNEL.get(role)
        if not slack_name:
            continue
        channel_id = channel_map.get(slack_name)
        if not channel_id:
            # Channel does not exist — auto-create it as a public channel
            logger.info(f"[SlackSync] Channel '{slack_name}' not found, auto-creating...")
            create_resp = _http_post(
                "https://slack.com/api/conversations.create",
                headers=headers,
                json={"name": slack_name, "is_private": False}, timeout=15
            )
            create_data = create_resp.json()
            if create_data.get("ok"):
                channel_id = create_data["channel"]["id"]
                channel_map[slack_name] = channel_id
                logger.info(f"[SlackSync] Created channel '{slack_name}' id={channel_id}")
            else:
                err = create_data.get("error")
                logger.warning(f"[SlackSync] Could not create channel '{slack_name}': {err}")
                if err == "name_taken":
                    # Channel exists but bot is not in it (so conversations.list didn't return it).
                    # Retry with exclude_archived=false to find the existing channel ID.
                    retry_resp = _http_get(
                        "https://slack.com/api/conversations.list",
                        headers=headers,
                        params={"types": "public_channel,private_channel", "limit": 1000, "exclude_archived": False}, timeout=15
                    )
                    retry_map = {ch["name"].lower(): ch["id"] for ch in retry_resp.json().get("channels", [])}
                    channel_id = retry_map.get(slack_name)
                    if channel_id:
                        channel_map[slack_name] = channel_id
                        logger.info(f"[SlackSync] Resolved existing channel '{slack_name}' id={channel_id} after name_taken retry")
                    else:
                        results.append({"role": role, "status": "channel_not_found", "error": err})
                        continue
                else:
                    results.append({"role": role, "status": "channel_not_found", "error": err})
                    continue
        # Bot must be in the channel before it can invite others
        _http_post(
            "https://slack.com/api/conversations.join",
            headers=headers,
            json={"channel": channel_id}, timeout=15
        )
        logger.info(f"[SlackSync] Inviting slack_user_id={slack_user_id} to channel_id={channel_id} role={role}")
        invite_resp = _http_post(
            "https://slack.com/api/conversations.invite",
            headers=headers,
            json={"channel": channel_id, "users": slack_user_id}, timeout=15
        )
        invite_data = invite_resp.json()
        if invite_data.get("ok") or invite_data.get("error") == "already_in_channel":
            results.append({"role": role, "status": "invited", "channel_id": channel_id})
            added_channel_ids.append(channel_id)
        else:
            logger.warning(
                f"[SlackSync] Invite failed role={role} channel_id={channel_id} error={invite_data.get('error')} "
                f"full={invite_data}"
            )
            results.append({"role": role, "status": "failed", "error": invite_data.get("error")})

    logger.info(f"[SlackSync] Done: added_channel_ids={added_channel_ids} results={results}")
    return results, added_channel_ids


def lookup_slack_user_by_email(bot_token, email):
    """
    Look up a Slack user's ID by their email address.
    Returns slack_user_id string or None if not found.
    """
    if not bot_token or not email:
        return None
    headers = {"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"}
    logger.info(f"[SlackLookup] lookupByEmail email={email} bot_token_set={bool(bot_token)}")
    resp = _http_get(
        "https://slack.com/api/users.lookupByEmail",
        headers=headers,
        params={"email": email}, timeout=15
    )
    data = resp.json()
    if data.get("ok"):
        slack_user_id = data.get("user", {}).get("id")
        logger.info(f"[SlackLookup] Found slack_user_id={slack_user_id} for email={email}")
        return slack_user_id
    logger.warning(f"[SlackLookup] Not found email={email} slack_error={data.get('error')} full={data}")
    return None


def invite_user_to_slack_workspace(bot_token, email):
    """
    Invite user to Slack workspace by email.
    Returns a normalized result dict.
    """
    if not bot_token or not email:
        return {"status": "failed", "error": "missing_token_or_email", "invited": False}

    headers = {"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"}
    try:
        resp = _http_post(
            "https://slack.com/api/users.admin.invite",
            headers=headers,
            json={"email": email},
            timeout=10,
        )
        data = resp.json() if resp is not None else {}
        if data.get("ok"):
            return {"status": "invited", "error": None, "invited": True}
        err = data.get("error")
        if err in {"already_invited", "already_in_team"}:
            return {"status": "already_member", "error": err, "invited": False}
        return {"status": "failed", "error": err or "unknown_error", "invited": False}
    except Exception as exc:
        return {"status": "failed", "error": str(exc), "invited": False}


def sync_member_to_teams_channels(access_token, team_id, user_email, member_roles):
    """
    Add a user to the VAPTFIX team. Once added to the team, the user automatically
    gets access to all standard channels (Patch Management, Configuration Management,
    Network Security, Architectural Flaws).

    For private/shared channels, members are added individually.
    """
    if not access_token or not team_id:
        return []

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    results = []

    try:
        logger.info(
            f"[TeamsSync] Start: team_id={team_id} user_email={user_email} roles={member_roles} access_token_set={bool(access_token)}"
        )
        # Get user's Azure AD ID by email
        user_resp = _http_get(
            f"https://graph.microsoft.com/v1.0/users/{user_email}",
            headers=headers, timeout=10
        )
        if user_resp.status_code != 200:
            logger.warning(
                f"[TeamsSync] Graph users lookup failed status={user_resp.status_code} user_email={user_email} body={user_resp.text}"
            )
            return [{"error": f"Could not find user {user_email} in Azure AD", "detail": user_resp.text}]

        user_id = user_resp.json().get('id')
        logger.info(f"[TeamsSync] Found Azure user_id={user_id} for email={user_email}")

        # Add user as team member — this gives access to ALL standard channels automatically
        team_member_payload = {
            "@odata.type": "#microsoft.graph.aadUserConversationMember",
            "roles": [],
            "user@odata.bind": f"https://graph.microsoft.com/v1.0/users('{user_id}')"
        }
        team_member_resp = _http_post(
            f"https://graph.microsoft.com/v1.0/teams/{team_id}/members",
            headers=headers, json=team_member_payload, timeout=10
        )
        if team_member_resp.status_code in (200, 201):
            results.append({"action": "added_to_team", "status": "success"})
        elif team_member_resp.status_code == 409:
            results.append({"action": "added_to_team", "status": "already_member"})
        else:
            logger.warning(
                f"[TeamsSync] Add to team failed status={team_member_resp.status_code} body={team_member_resp.text}"
            )
            results.append({"action": "added_to_team", "status": "failed", "error": team_member_resp.text})

        # For standard channels, team membership = channel access (no individual add needed)
        # Only add to private/shared channels individually
        channels_resp = _http_get(
            f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels",
            headers=headers, timeout=10
        )
        if channels_resp.status_code == 200:
            channels = channels_resp.json().get('value', [])
            logger.info(f"[TeamsSync] channels fetched count={len(channels)}")
            # Build O(1) lookup map instead of linear search per role
            channel_map_display = {ch['displayName']: ch for ch in channels}
            for role in member_roles:
                matching_channel = channel_map_display.get(role)
                if not matching_channel:
                    results.append({"channel": role, "status": "channel_not_found"})
                    continue

                membership_type = matching_channel.get('membershipType', 'standard')
                logger.info(
                    f"[TeamsSync] role={role} channel_id={matching_channel.get('id')} membershipType={membership_type}"
                )
                if membership_type == 'standard':
                    # Standard channels: user gets access via team membership
                    results.append({"channel": role, "status": "auto_access_via_team_membership"})
                else:
                    # Private/shared channels: add member individually
                    add_payload = {
                        "@odata.type": "#microsoft.graph.aadUserConversationMember",
                        "roles": [],
                        "user@odata.bind": f"https://graph.microsoft.com/v1.0/users('{user_id}')"
                    }
                    add_resp = _http_post(
                        f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{matching_channel['id']}/members",
                        headers=headers, json=add_payload, timeout=10
                    )
                    if add_resp.status_code in (200, 201):
                        results.append({"channel": role, "status": "added"})
                    elif add_resp.status_code == 409:
                        results.append({"channel": role, "status": "already_member"})
                    else:
                        logger.warning(
                            f"[TeamsSync] Add to channel failed role={role} status={add_resp.status_code} body={add_resp.text}"
                        )
                        results.append({"channel": role, "status": "failed", "error": add_resp.text})

    except Exception as e:
        logger.exception(f"[TeamsSync] Exception during sync: {str(e)}")
        results.append({"error": str(e)})

    return results
User = get_user_model()
class UserDetailCreateView(generics.CreateAPIView):
    serializer_class = UserDetailCreateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def _load_logo_b64(self):
        """Load logo.png as base64 string for inline email attachment."""
        logo_path = os.path.join(str(settings.BASE_DIR), "users", "static", "users", "logo.png")
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as f:
                return base64.b64encode(f.read()).decode("utf-8")
        return None

    def _logo_html(self, logo_b64):
        if logo_b64:
            return '<img src="cid:vaptfix_logo" alt="VaptFix Pro" style="height:48px;" />'
        return '<span style="color:#ffffff; font-size:20px; font-weight:bold; letter-spacing:1px;">VaptFix Pro</span>'

    def _attach_logo(self, message, logo_b64):
        if logo_b64:
            message.add_attachment(Attachment(
                FileContent(logo_b64),
                FileName("logo.png"),
                FileType("image/png"),
                Disposition("inline"),
                ContentId("vaptfix_logo"),
            ))

    def send_welcome_email(self, email, first_name, last_name, roles, set_password_url=None):
        """Send styled 'Set Your Password' email to newly added team member (screen.png style)."""

        if not email or not isinstance(email, str):
            return False, "Invalid email address"

        if not settings.SENDGRID_API_KEY:
            logger.error("SENDGRID_API_KEY is not configured")
            return False, "SendGrid API key not configured"

        full_name = f"{first_name} {last_name}".strip() or "User"
        roles_list = roles if isinstance(roles, list) else [str(roles)]

        roles_badges_html = "".join(
            f'<span style="display:inline-block; background-color:#e0f7fa; color:#006064;'
            f'border:1px solid #b2ebf2; border-radius:20px; padding:6px 16px;'
            f'font-size:13px; margin:4px 6px 4px 0; font-weight:500;">{r}</span>'
            for r in roles_list
        )

        logo_b64 = self._load_logo_b64()
        logo_html = self._logo_html(logo_b64)
        set_password_link = set_password_url or getattr(settings, "VAPTFIX_LOGIN_URL", "#")

        html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background-color:#f0f2f5;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0f2f5;padding:40px 0;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0"
             style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,0.12);">
        <!-- Dark Header -->
        <tr>
          <td style="background-color:#1e1b4b;padding:32px 40px;text-align:center;">
            {logo_html}
          </td>
        </tr>
        <!-- Body -->
        <tr>
          <td style="padding:36px 40px 28px 40px;">
            <p style="color:#999;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin:0 0 4px 0;">SUBJECT</p>
            <h2 style="color:#1a1a2e;margin:0 0 14px 0;font-size:22px;">Welcome to VAPTFIX</h2>
            <hr style="border:none;border-top:1px solid #e8eaed;margin:0 0 22px 0;" />
            <p style="color:#333;font-size:15px;line-height:1.6;margin:0 0 14px 0;">
              Dear {full_name.upper()},
            </p>
            <p style="color:#555;font-size:14px;line-height:1.7;margin:0 0 18px 0;">
              We are pleased to inform you that your account has been successfully created in
              <strong>VAPTFIX</strong>. You have been granted access to the Intelligence portal
              as part of the Rational Curator framework.
            </p>
            <!-- Assigned Roles -->
            <div style="background:#f8fafc;border:1px solid #e8eaed;border-radius:8px;padding:18px 20px;margin:0 0 20px 0;">
              <p style="color:#999;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin:0 0 10px 0;">ASSIGNED ROLES</p>
              <div>{roles_badges_html}</div>
            </div>
            <p style="color:#555;font-size:14px;line-height:1.7;margin:0 0 22px 0;">
              Please set your password using the link below to activate your account and start securing your assets.
            </p>
            <!-- Set Password Button -->
            <div style="text-align:center;margin:0 0 22px 0;">
              <a href="{set_password_link}"
                 style="background-color:#1e1b4b;color:#ffffff;padding:14px 36px;
                        text-decoration:none;border-radius:30px;font-size:15px;
                        font-weight:bold;display:inline-block;letter-spacing:0.3px;">
                Set Your Password &rarr;
              </a>
            </div>
            <!-- Expiry Notice -->
            <div style="background:#eff6ff;border-left:4px solid #3b82f6;border-radius:6px;padding:12px 16px;margin:0 0 8px 0;">
              <p style="color:#1e40af;font-size:13px;margin:0;line-height:1.6;">
                &#8505;&nbsp; This link will expire in 24 hours.
                If you did not request this account, please contact our support team immediately.
              </p>
            </div>
          </td>
        </tr>
        <!-- Footer -->
        <tr>
          <td style="padding:18px 40px;text-align:center;border-top:1px solid #e8eaed;">
            <p style="color:#999;font-size:12px;margin:0 0 6px 0;">
              <a href="#" style="color:#666;text-decoration:none;margin:0 8px;">PRIVACY POLICY</a> |
              <a href="#" style="color:#666;text-decoration:none;margin:0 8px;">TERMS OF SERVICE</a> |
              <a href="#" style="color:#666;text-decoration:none;margin:0 8px;">HELP CENTER</a>
            </p>
            <p style="color:#bbb;font-size:11px;margin:0;">&copy; 2026 VAPTFIX. ALL RIGHTS RESERVED.</p>
            <p style="color:#ddd;font-size:18px;margin:6px 0 0 0;">&#x2022; &nbsp; &#x2022; &nbsp; &#x2022;</p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

        try:
            message = Mail(
                from_email=settings.DEFAULT_FROM_EMAIL,
                to_emails=email,
                subject="Welcome to VAPTFIX – Set Your Password",
                html_content=html_content,
            )
            self._attach_logo(message, logo_b64)

            sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
            response = sg.send(message)
            logger.info(f"Set-password email sent to {email}. Status: {response.status_code}")

            if response.status_code in [200, 201, 202]:
                return True, None
            return False, f"SendGrid status: {response.status_code}"

        except Exception as e:
            logger.error(f"Failed to send set-password email to {email}: {str(e)}", exc_info=True)
            return False, str(e)

    def send_team_welcome_emails(self, email, first_name, last_name, roles, admin_email=""):
        """Send team-specific welcome emails — one per assigned team role (mail.png style)."""
        import datetime

        if not email or not settings.SENDGRID_API_KEY:
            return

        # Always look up the actual user's name from DB to ensure correct name is used
        try:
            detail = UserDetail.objects.only('first_name', 'last_name').filter(email=email).first()
            if detail:
                first_name = detail.first_name or first_name
                last_name = detail.last_name or last_name
        except Exception as e:
            logger.warning("Could not load latest name from UserDetail for %s: %s", email, e)

        roles_list = roles if isinstance(roles, list) else [str(roles)]
        full_name = f"{first_name} {last_name}".strip() or "Team Member"
        admin_display = admin_email or "your administrator"
        today_str = datetime.date.today().strftime("%B %d, %Y")
        frontend_url = getattr(settings, 'FRONTEND_URL', 'https://vaptfix.ai')

        logo_b64 = self._load_logo_b64()
        logo_html = self._logo_html(logo_b64)

        for role in roles_list:
            team_info = TEAM_EMAIL_CONTENT.get(role)
            if not team_info:
                continue

            html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background-color:#f0f2f5;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0f2f5;padding:40px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0"
             style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,0.12);">
        <!-- Header -->
        <tr>
          <td style="background-color:#1e1b4b;padding:28px 40px;text-align:center;">
            {logo_html}
          </td>
        </tr>
        <!-- Body -->
        <tr>
          <td style="padding:36px 40px 20px 40px;">
            <h2 style="color:#1a1a2e;margin:0 0 4px 0;font-size:21px;">{team_info["heading"]}</h2>
            <p style="color:#888;font-size:13px;margin:0 0 22px 0;">Vulnerability Management Program</p>
            <p style="color:#333;font-size:15px;margin:0 0 16px 0;">Hi {first_name.upper()},</p>
            <div style="color:#555;font-size:14px;line-height:1.8;margin:0 0 24px 0;">
              {team_info["body"]}
            </div>
            <!-- Added By -->
            <div style="background:#f8fafc;border:1px solid #e8eaed;border-radius:8px;padding:14px 18px;margin:0 0 24px 0;">
              <p style="color:#999;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin:0 0 4px 0;">ADDED BY</p>
              <p style="color:#333;font-size:14px;margin:0;font-weight:500;">{admin_display}</p>
            </div>
            <!-- Signature -->
            <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 20px 0;">
              <tr>
                <td style="vertical-align:middle;">
                  <div style="display:inline-block;width:44px;height:44px;border-radius:50%;
                              background-color:#312e81;text-align:center;line-height:44px;
                              color:#fff;font-size:15px;font-weight:bold;margin-right:12px;vertical-align:middle;">
                    VN
                  </div>
                  <div style="display:inline-block;vertical-align:middle;">
                    <p style="margin:0;font-size:14px;font-weight:bold;color:#1a1a2e;">Vulnerability Management Program Lead</p>
                    <p style="margin:0;font-size:12px;color:#888;">Vulnerability Management Program Lead</p>
                  </div>
                </td>
                <td style="text-align:right;vertical-align:middle;">
                  <p style="margin:0;font-size:12px;color:#999;">&#128197; Today, {today_str}</p>
                </td>
              </tr>
            </table>
            <!-- Buttons -->
            <div style="margin:0 0 28px 0;">
              <a href="https://vaptfix.ai/auth?mode=signin"
                 style="background-color:#1e1b4b;color:#ffffff;padding:12px 24px;
                        text-decoration:none;border-radius:30px;font-size:14px;
                        font-weight:bold;display:inline-block;">
                Go to Dashboard &rarr;
              </a>
            </div>
          </td>
        </tr>
        <!-- Footer -->
        <tr>
          <td style="background:#f4f4f8;padding:16px 40px;text-align:center;border-top:1px solid #e8eaed;">
            <p style="color:#bbb;font-size:11px;margin:0;">&copy; 2026 VAPTFIX. ALL RIGHTS RESERVED.</p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

            try:
                message = Mail(
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to_emails=email,
                    subject=team_info["subject"],
                    html_content=html_content,
                )
                self._attach_logo(message, logo_b64)

                sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
                response = sg.send(message)
                logger.info(f"Team welcome email [{role}] sent to {email}. Status: {response.status_code}")
            except Exception as e:
                logger.error(f"Failed to send team email [{role}] to {email}: {str(e)}", exc_info=True)

    def send_post_password_welcome_email(self, email, first_name, last_name, roles):
        """Send general welcome email after user successfully sets their password."""

        if not email or not settings.SENDGRID_API_KEY:
            return False, "Missing email or SendGrid key"

        full_name = f"{first_name} {last_name}".strip() or "Team Member"
        roles_list = roles if isinstance(roles, list) else [str(roles)]

        if len(roles_list) == 1:
            team_label = roles_list[0]
        elif len(roles_list) == 2:
            team_label = " & ".join(roles_list)
        else:
            team_label = ", ".join(roles_list[:-1]) + ", & " + roles_list[-1]

        roles_badges_html = "".join(
            f'<span style="display:inline-block;background-color:#e0f7fa;color:#006064;'
            f'border:1px solid #b2ebf2;border-radius:20px;padding:5px 14px;'
            f'font-size:13px;margin:4px 6px 4px 0;font-weight:500;">{r}</span>'
            for r in roles_list
        )

        logo_b64 = self._load_logo_b64()
        logo_html = self._logo_html(logo_b64)
        frontend_url = getattr(settings, 'FRONTEND_URL', 'https://vaptfix.ai')

        html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background-color:#f0f2f5;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0f2f5;padding:40px 0;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0"
             style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,0.12);">
        <!-- Dark Header -->
        <tr>
          <td style="background-color:#1e1b4b;padding:32px 40px;text-align:center;">
            {logo_html}
          </td>
        </tr>
        <!-- Body -->
        <tr>
          <td style="padding:36px 40px 28px 40px;">
            <h2 style="color:#1a1a2e;margin:0 0 14px 0;font-size:22px;">Welcome to the {team_label} Team</h2>
            <hr style="border:none;border-top:1px solid #e8eaed;margin:0 0 22px 0;" />
            <p style="color:#333;font-size:15px;line-height:1.6;margin:0 0 14px 0;">
              Hi {first_name.upper()},
            </p>
            <p style="color:#555;font-size:14px;line-height:1.7;margin:0 0 14px 0;">
              Welcome to the <strong>{team_label}</strong> team as part of our Vulnerability Management Program!
              We're glad to have you on board. Your role will be key in strengthening our organization's security
              posture by helping identify, assess, and remediate vulnerabilities within your area of focus.
            </p>
            <p style="color:#555;font-size:14px;line-height:1.7;margin:0 0 14px 0;">
              As part of this team, you'll collaborate closely with other domain groups — including Patch Management,
              Configuration Management, Architectural Flaws, and Network Security — to ensure a streamlined and
              coordinated approach to risk reduction.
            </p>
            <p style="color:#555;font-size:14px;line-height:1.7;margin:0 0 20px 0;">
              Over the next few days, you'll receive access to our tools, dashboards, and reporting channels.
              Please take a moment to review our internal procedures and reach out to your team lead if you have any questions.
            </p>
            <!-- Teams -->
            <div style="background:#f8fafc;border:1px solid #e8eaed;border-radius:8px;padding:16px 20px;margin:0 0 24px 0;">
              <p style="color:#999;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin:0 0 10px 0;">YOUR TEAMS</p>
              <div>{roles_badges_html}</div>
            </div>
            <!-- Go to Dashboard -->
            <div style="text-align:center;margin:0 0 8px 0;">
              <a href="https://vaptfix.ai/auth?mode=signin"
                 style="background-color:#1e1b4b;color:#ffffff;padding:13px 34px;
                        text-decoration:none;border-radius:30px;font-size:15px;
                        font-weight:bold;display:inline-block;">
                Go to Dashboard &rarr;
              </a>
            </div>
          </td>
        </tr>
        <!-- Footer -->
        <tr>
          <td style="padding:18px 40px;text-align:center;border-top:1px solid #e8eaed;">
            <p style="color:#999;font-size:12px;margin:0 0 6px 0;">
              <a href="#" style="color:#666;text-decoration:none;margin:0 8px;">PRIVACY POLICY</a> |
              <a href="#" style="color:#666;text-decoration:none;margin:0 8px;">TERMS OF SERVICE</a> |
              <a href="#" style="color:#666;text-decoration:none;margin:0 8px;">HELP CENTER</a>
            </p>
            <p style="color:#bbb;font-size:11px;margin:0;">&copy; 2026 VAPTFIX. ALL RIGHTS RESERVED.</p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

        try:
            message = Mail(
                from_email=settings.DEFAULT_FROM_EMAIL,
                to_emails=email,
                subject=f"Welcome to the {team_label} Team – VAPTFIX",
                html_content=html_content,
            )
            self._attach_logo(message, logo_b64)

            sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
            response = sg.send(message)
            logger.info(f"Post-password welcome email sent to {email}. Status: {response.status_code}")

            if response.status_code in [200, 201, 202]:
                return True, None
            return False, f"SendGrid status: {response.status_code}"

        except Exception as e:
            logger.error(f"Failed to send post-password welcome email to {email}: {str(e)}", exc_info=True)
            return False, str(e)

    def send_platform_access_email(self, email, first_name, last_name, platform_name="VAPTFIX Platform", channel_names=None):
        """Send platform access email for users added from UserDetails/Slack/Teams flows."""
        if not email or not settings.SENDGRID_API_KEY:
            return False, "Missing email or SendGrid key"

        try:
            detail = UserDetail.objects.only('first_name', 'last_name').filter(email=email).first()
            if detail:
                first_name = detail.first_name or first_name
                last_name = detail.last_name or last_name
        except Exception as e:
            logger.warning("Suppressed error: %s", e)

        channels_list = channel_names if isinstance(channel_names, list) else ([channel_names] if channel_names else [])
        channels_html = ""
        if channels_list:
            channels_html = "".join(
                f'<li style="padding:6px 0;color:#333;font-size:14px;">{ch}</li>'
                for ch in channels_list
            )

        logo_b64 = self._load_logo_b64()
        logo_html = self._logo_html(logo_b64)

        html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background-color:#f0f2f5;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0f2f5;padding:40px 0;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0"
             style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,0.12);">
        <tr>
          <td style="background-color:#1e1b4b;padding:32px 40px;text-align:center;">
            {logo_html}
          </td>
        </tr>
        <tr>
          <td style="padding:36px 40px 28px 40px;">
            <p style="color:#333;font-size:15px;line-height:1.6;margin:0 0 14px 0;">
              Hi {(first_name or "User").upper()},
            </p>
            <p style="color:#555;font-size:14px;line-height:1.7;margin:0 0 18px 0;">
              You have been granted access to <strong>{platform_name}</strong> in VAPTFIX.
            </p>
            {f'<div style="background:#f8fafc;border:1px solid #e8eaed;border-radius:8px;padding:16px 20px;margin:0 0 24px 0;"><p style="color:#999;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin:0 0 10px 0;">ASSIGNED CHANNELS / AREAS</p><ul style="margin:0;padding:0 0 0 16px;">{channels_html}</ul></div>' if channels_html else ''}
            <p style="color:#555;font-size:14px;line-height:1.7;margin:0;">
              You can now continue your onboarding in the VAPTFIX portal.
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:18px 40px;text-align:center;border-top:1px solid #e8eaed;">
            <p style="color:#bbb;font-size:11px;margin:0;">&copy; 2026 VAPTFIX. ALL RIGHTS RESERVED.</p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

        try:
            message = Mail(
                from_email=settings.DEFAULT_FROM_EMAIL,
                to_emails=email,
                subject=f"Access Granted: {platform_name} – VAPTFIX",
                html_content=html_content,
            )
            self._attach_logo(message, logo_b64)
            sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
            response = sg.send(message)
            logger.info(f"Platform access email sent to {email} for {platform_name}. Status: {response.status_code}")
            if response.status_code in [200, 201, 202]:
                return True, None
            return False, f"SendGrid status: {response.status_code}"
        except Exception as e:
            logger.error(f"Failed to send platform access email to {email}: {str(e)}", exc_info=True)
            return False, str(e)

    def send_slack_platform_email(self, email, first_name, last_name, channel_names):
        """Send email notifying user they've been added to Slack channels."""
        if not channel_names:
            return False, "No channel names provided"
        return self.send_platform_access_email(
            email=email,
            first_name=first_name,
            last_name=last_name,
            platform_name="Slack Workspace",
            channel_names=channel_names,
        )

    def create(self, request, *args, **kwargs):
        try:
            # Check for duplicate: same admin + same email
            admin_id = request.data.get("admin_id")
            email = request.data.get("email")
            if admin_id and email:
                if UserDetail.objects.filter(admin__id=admin_id, email=email).exists():
                    return Response(
                        {"error": f"User with email '{email}' already exists for this admin."},
                        status=status.HTTP_409_CONFLICT
                    )

            # Validate and create user detail
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user_detail = serializer.save()

            # IMPORTANT: The UserDetail is created for the admin_id coming from request body.
            # Platform sync tokens must be read from that same admin (user_detail.admin),
            # not from request.user (the authenticated user).
            admin_user = user_detail.admin

            # Extract data to send email
            email = user_detail.email
            first_name = user_detail.first_name or ""
            last_name = user_detail.last_name or ""
            roles = user_detail.Member_role or []

            logger.info(f"Creating user detail for {email} with roles: {roles}")

            # Create Django User for this member and generate set-password link
            from django.utils.http import urlsafe_base64_encode
            from django.utils.encoding import force_bytes
            from django.contrib.auth.tokens import PasswordResetTokenGenerator

            User = get_user_model()
            user, created = User.objects.get_or_create(
                email=email,
                defaults={"is_active": True}
            )
            if created:
                user.set_unusable_password()
                user.save()

            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)
            set_password_url = f"https://vaptfix.ai/auth?mode=set-password&uid={uid}&token={token}"

            # Send emails in background so the API response is not blocked
            admin_email = getattr(admin_user, "email", "")
            _view = self

            def _send_emails():
                _view.send_platform_access_email(
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    platform_name="VAPTFIX Platform",
                    channel_names=roles,
                )
                _view.send_welcome_email(
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    roles=roles,
                    set_password_url=set_password_url,
                )
                _view.send_team_welcome_emails(
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    roles=roles,
                    admin_email=admin_email,
                )

            threading.Thread(target=_send_emails, daemon=True).start()
            email_sent, error = True, None  # optimistic — logged inside send methods

            # Sync to MS Teams — use token from request body first, else fall back to admin's stored token
            teams_sync_result = []
            ms_access_token = request.data.get("access_token") or getattr(admin_user, "ms_access_token", None)
            team_id = request.data.get("team_id") or getattr(admin_user, "ms_team_id", None)
            logger.info(
                f"[UserDetailCreate] Teams sync check: admin_id={getattr(admin_user, 'id', None)} "
                f"ms_access_token_set={bool(ms_access_token)} ms_team_id={getattr(admin_user, 'ms_team_id', None)} "
                f"team_id_used={team_id} roles={roles}"
            )
            if ms_access_token and team_id and roles:
                teams_sync_result = sync_member_to_teams_channels(
                    access_token=ms_access_token,
                    team_id=team_id,
                    user_email=email,
                    member_roles=roles,
                )
                user_detail.team_id = team_id
                user_detail.save(update_fields=["team_id"])
                logger.info(f"[UserDetailCreate] MS Teams sync done for {email}: {teams_sync_result}")
            else:
                if not ms_access_token:
                    logger.warning(f"[UserDetailCreate] Teams sync skipped: missing ms_access_token for admin_id={admin_user.id}")
                elif not team_id:
                    logger.warning(f"[UserDetailCreate] Teams sync skipped: missing team_id/ms_team_id for admin_id={admin_user.id}")
                elif not roles:
                    logger.warning(f"[UserDetailCreate] Teams sync skipped: missing roles for {email}")

            # Sync to Slack — use token from request body first, else fall back to admin's stored token
            slack_sync_result = {}
            slack_bot_token = request.data.get("slack_bot_token") or getattr(admin_user, "slack_bot_token", None)
            logger.info(
                f"[UserDetailCreate] Slack sync check: admin_id={getattr(admin_user, 'id', None)} "
                f"slack_bot_token_set={bool(slack_bot_token)} roles={roles} target_email={email}"
            )
            if slack_bot_token and roles:
                # Try to get slack_user_id from the member's own User record first (already stored at OAuth time)
                member_user = User.objects.filter(email=email).first()
                slack_user_id = getattr(member_user, "slack_user_id", None) or lookup_slack_user_by_email(slack_bot_token, email)
                if slack_user_id:
                    slack_results, channel_ids = sync_member_to_slack_channels(
                        bot_token=slack_bot_token,
                        slack_user_id=slack_user_id,
                        member_roles=roles,
                    )
                    slack_sync_result = {
                        "status": "success",
                        "workspace": {"invited": False, "already_member": True},
                        "user_lookup": {"email": email, "slack_user_id": slack_user_id},
                        "channels": slack_results,
                    }
                    if channel_ids:
                        user_detail.slack_channel_ids = list(set(channel_ids))
                        user_detail.save(update_fields=["slack_channel_ids"])
                    logger.info(f"[UserDetailCreate] Slack sync done for {email}: {slack_sync_result}")

                    # Send Slack platform email — channels where user was successfully added
                    synced_channels = [
                        ROLE_TO_SLACK_CHANNEL.get(r["role"], r["role"])
                        for r in slack_results
                        if r.get("status") == "invited"
                    ]
                    if synced_channels:
                        _slack_email = email
                        _slack_first = first_name
                        _slack_last = last_name
                        _slack_channels = synced_channels
                        _view_ref = self

                        def _send_slack_platform_email():
                            try:
                                _view_ref.send_slack_platform_email(
                                    email=_slack_email,
                                    first_name=_slack_first,
                                    last_name=_slack_last,
                                    channel_names=_slack_channels,
                                )
                            except Exception:
                                logger.exception(f"[UserDetailCreate] Slack platform email failed for {_slack_email}")

                        threading.Thread(target=_send_slack_platform_email, daemon=True).start()
                else:
                    invite_result = invite_user_to_slack_workspace(slack_bot_token, email)
                    if invite_result.get("status") in {"invited", "already_member"}:
                        slack_sync_result = {
                            "status": "pending_workspace_join" if invite_result.get("status") == "invited" else "already_member_no_lookup",
                            "workspace": {
                                "invited": invite_result.get("status") == "invited",
                                "already_member": invite_result.get("status") == "already_member",
                                "invite_email": email,
                            },
                            "channels": [],
                            "note": "User invited to Slack workspace. Channel mapping will apply after Slack account becomes discoverable.",
                        }
                    else:
                        slack_sync_result = {
                            "status": "failed",
                            "workspace": {"invited": False, "already_member": False},
                            "channels": [],
                            "error": invite_result.get("error") or "User not found in Slack workspace for this email",
                        }
                    logger.warning(
                        f"[UserDetailCreate] Slack sync failed: lookupByEmail returned None for target_email={email} "
                        f"admin_id={admin_user.id}"
                    )
            else:
                if not slack_bot_token:
                    logger.warning(f"[UserDetailCreate] Slack sync skipped: missing slack_bot_token for admin_id={admin_user.id}")
                    slack_sync_result = {"status": "skipped", "error": "missing_slack_bot_token"}
                elif not roles:
                    logger.warning(f"[UserDetailCreate] Slack sync skipped: missing roles for {email}")
                    slack_sync_result = {"status": "skipped", "error": "missing_roles"}

            response_data = {
                "message": "User detail created successfully",
                "email_sent": email_sent,
                "data": UserDetailSerializer(user_detail).data
            }

            if not email_sent:
                response_data["email_error"] = error
                logger.warning(f"User created but email failed for {email}: {error}")
            else:
                logger.info(f"User created and email sent successfully for {email}")

            if teams_sync_result:
                response_data["teams_sync"] = teams_sync_result
            if slack_sync_result:
                response_data["slack_sync"] = slack_sync_result

            return Response(response_data, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Error creating user detail: {str(e)}", exc_info=True)
            return Response(
                {"error": "Failed to create user detail", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
            


class UserDetailListView(generics.ListAPIView):
    serializer_class = UserDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Restrict to only the logged-in admin's own team members
        return UserDetail.objects.filter(admin=self.request.user).select_related("admin").order_by("-created_at")


class UserDetailView(generics.RetrieveAPIView):
    serializer_class = UserDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        detail_id = self.kwargs.get("detail_id")
        obj_id = ObjectId(detail_id)
        return get_object_or_404(UserDetail, _id=obj_id)

class UserDetailUpdateView(generics.UpdateAPIView):
    """
    Update a UserDetail. Uses UserDetailUpdateSerializer for input/validation
    and returns the full serialized UserDetail (UserDetailSerializer) on success.
    Supports PUT (full update) and PATCH (partial update).
    """
    serializer_class = UserDetailUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        detail_id = self.kwargs.get("detail_id")
        obj_id = ObjectId(detail_id)
        return get_object_or_404(UserDetail, _id=obj_id)

    # override update to return consistent response format
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)  # supports partial updates
        instance = self.get_object()

        # permission: only owner admin or staff can update (adjust if needed)
        if not (request.user == instance.admin or request.user.is_staff):
            return Response(
                {"detail": "You do not have permission to update this member."},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)  # calls serializer.update

        # Refresh instance from DB to get latest values
        instance.refresh_from_db()

        return Response({
            "message": "User detail updated successfully",
            "data": UserDetailSerializer(instance).data
        }, status=status.HTTP_200_OK)

    # allow PATCH requests too
    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)





class UserDetailRoleDeleteView(generics.DestroyAPIView):
    """
    Delete a specific role from UserDetail.Member_role list.
    If Member_role becomes empty after deletion, delete the entire UserDetail record.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        detail_id = self.kwargs.get("detail_id")
        try:
            obj_id = ObjectId(detail_id)
        except Exception:
            return None
        return get_object_or_404(UserDetail, _id=obj_id)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if not instance:
            return Response({"detail": "Invalid detail_id"}, status=status.HTTP_400_BAD_REQUEST)

        # Permission check: Only the admin who owns this record or staff can delete
        try:
            is_owner = (request.user.id == instance.admin.id)
        except Exception:
            is_owner = False

        if not (is_owner or request.user.is_staff):
            return Response(
                {"detail": "You do not have permission to delete this member's role."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Read confirmation and role from request body
        confirm = request.data.get("confirm", False)
        provided_role = request.data.get("member_role")

        # Handle both boolean and string "true"/"false"
        if isinstance(confirm, str):
            confirm = confirm.lower() == "true"

        if not confirm:
            return Response(
                {"detail": "Deletion not confirmed. Please set confirm to true."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not provided_role:
            return Response(
                {"detail": "member_role is required in request body."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Allowed roles
        allowed_roles = {
            "Patch Management",
            "Configuration Management",
            "Network Security",
            "Architectural Flaws",
        }
        if provided_role not in allowed_roles:
            return Response(
                {"detail": f"Invalid member_role. Must be one of: {', '.join(allowed_roles)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get current Member_role (ensure list)
        member_roles = instance.Member_role or []
        if not isinstance(member_roles, list):
            member_roles = [member_roles] if member_roles else []

        # Check if role exists
        if provided_role not in member_roles:
            return Response(
                {"detail": f"Role '{provided_role}' not found in member's roles. Current roles: {member_roles}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Remove role
        member_roles.remove(provided_role)

        # Build member full name
        member_name = f"{instance.first_name} {instance.last_name}"

        # If no roles left, delete the user detail record
        if len(member_roles) == 0:
            instance.delete()
            return Response(
                {
                    "message": f"Role '{provided_role}' removed successfully from {member_name}. No roles remaining; the member record was deleted.",
                    "action": "record_deleted",
                    "deleted_role": provided_role
                },
                status=status.HTTP_200_OK
            )

        # Otherwise update and return remaining roles
        instance.Member_role = member_roles
        instance.save()
        return Response(
            {
                "message": f"Role '{provided_role}' removed successfully from {member_name}.",
                "action": "role_removed",
                "deleted_role": provided_role,
                "remaining_roles": member_roles
            },
            status=status.HTTP_200_OK
        )
      
class UserDetailCompleteDeleteView(generics.DestroyAPIView):
    """
    Delete the entire UserDetail record (not just a single role).
    
    Requirements:
      - request.user is the admin for that UserDetail (or is_staff)
      - frontend sends {"confirm": true} in the request body
    """
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        detail_id = self.kwargs.get("detail_id")
        try:
            obj_id = ObjectId(detail_id)
        except Exception:
            return None
        return get_object_or_404(UserDetail, _id=obj_id)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        # Permission check
        if not (request.user.id == instance.admin.id or request.user.is_staff):
            return Response(
                {"detail": "You do not have permission to delete this member."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Read confirmation from request body
        confirm = request.data.get("confirm", False)

        # Handle both boolean and string "true"/"false"
        if isinstance(confirm, str):
            confirm = confirm.lower() == "true"

        if not confirm:
            return Response(
                {"detail": "Deletion not confirmed. Please set confirm to true."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Delete the entire record
        member_name = f"{instance.first_name} {instance.last_name}"
        member_roles = instance.Member_role
        instance.delete()
        
        return Response(
            {
                "message": f"Member {member_name} deleted successfully.",
                "action": "Record Deleted",
                "deleted_roles": member_roles
            },
            status=status.HTTP_200_OK
        )
       
class UserDetailSearchView(generics.ListAPIView):
    serializer_class = UserDetailSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = UserDetail.objects.all().order_by("-created_at")
    filter_backends = [filters.SearchFilter]
    search_fields = ["first_name", "last_name", "email", "Member_role", "user_type"]

    def get_queryset(self):
        # Restrict to only the logged-in admin's own team members
        return UserDetail.objects.filter(admin=self.request.user).select_related("admin").order_by("-created_at")


class UserDetailRoleUpdateView(generics.GenericAPIView):
    """
    PATCH endpoint to add or replace roles.

    - Add (default): {"new_roles": ["Configuration Management", "Patch Management"] }
    - Replace first occurrence: {"operation":"replace","old_role":"Network Security","new_roles":["Patch Management"]}

    If "confirm" explicitly provided and False -> rejected. If omitted or True -> proceeds.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserDetailRoleUpdateSerializer

    # canonical allowed roles (Title Case stored)
    allowed_roles = [
        "Patch Management",
        "Configuration Management",
        "Network Security",
        "Architectural Flaws",
    ]
    _allowed_map = {r.lower(): r for r in allowed_roles}

    def get_object(self):
        detail_id = self.kwargs.get("detail_id")
        try:
            obj_id = ObjectId(detail_id)
        except Exception:
            return None
        return get_object_or_404(UserDetail, _id=obj_id)

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()
        if not instance:
            return Response({"detail": "Invalid detail_id"}, status=status.HTTP_400_BAD_REQUEST)

        # Permission check: Only owner admin or staff
        try:
            is_owner = (request.user.id == instance.admin.id)
        except Exception:
            is_owner = False

        if not (is_owner or request.user.is_staff):
            return Response(
                {"detail": "You do not have permission to update this member's role."},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        old_role_raw = serializer.validated_data.get("old_role", None)
        new_roles_raw = serializer.validated_data["new_roles"]
        operation = serializer.validated_data.get("operation", "add")
        confirm = serializer.validated_data.get("confirm", None)

        # handle confirm: if explicitly False -> reject
        if confirm is False:
            return Response(
                {"detail": "Update not confirmed. Please set confirm=true or omit confirm."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Normalize new_roles: map case-insensitively to canonical values
        normalized_new = []
        invalid_new = []
        for r in new_roles_raw:
            key = (r or "").strip().lower()
            canonical = self._allowed_map.get(key)
            if not canonical:
                invalid_new.append(r)
            else:
                normalized_new.append(canonical)

        if invalid_new:
            return Response(
                {"detail": f"Invalid new_roles: {invalid_new}. Allowed: {', '.join(self.allowed_roles)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Normalize old_role if provided
        old_role = None
        if old_role_raw:
            key = old_role_raw.strip().lower()
            old_role = self._allowed_map.get(key)
            if not old_role:
                return Response(
                    {"detail": f"Invalid old_role '{old_role_raw}'. Allowed: {', '.join(self.allowed_roles)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # If operation == "replace" require old_role
        if operation == "replace" and not old_role:
            return Response(
                {"detail": "old_role is required when operation is 'replace'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Ensure Member_role is a list
        roles = instance.Member_role or []
        if not isinstance(roles, list):
            roles = [roles] if roles else []

        roles_lower = [r.lower() for r in roles]

        if operation == "replace":
            # Replace first occurrence of old_role (case-insensitive)
            if old_role.lower() not in roles_lower:
                return Response(
                    {"detail": f"Old role '{old_role}' not found. Current roles: {roles}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            updated_roles = []
            replaced = False
            seen_lower = set()

            for r in roles:
                if (not replaced) and (r.lower() == old_role.lower()):
                    # insert all normalized_new (avoid duplicates)
                    for nr in normalized_new:
                        if nr.lower() not in seen_lower:
                            updated_roles.append(nr)
                            seen_lower.add(nr.lower())
                    replaced = True
                else:
                    if r.lower() not in seen_lower:
                        updated_roles.append(r)
                        seen_lower.add(r.lower())

            action = "roles_replaced"
            message = f"Role '{old_role}' replaced with {normalized_new}."
        else:
            # operation == "add" (default) — append normalized_new, avoid duplicates
            updated_roles = []
            seen_lower = set()
            for r in roles:
                if r.lower() not in seen_lower:
                    updated_roles.append(r)
                    seen_lower.add(r.lower())
            for nr in normalized_new:
                if nr.lower() not in seen_lower:
                    updated_roles.append(nr)
                    seen_lower.add(nr.lower())

            action = "roles_added"
            message = f"Added roles {normalized_new}."

        # Save and respond
        instance.Member_role = updated_roles
        instance.save()

        # Sync new roles with Teams channels if access_token and team_id provided
        teams_sync_result = []
        ms_access_token = request.data.get("access_token")
        team_id = instance.team_id or request.data.get("team_id")
        if ms_access_token and team_id and normalized_new:
            teams_sync_result = sync_member_to_teams_channels(
                access_token=ms_access_token,
                team_id=team_id,
                user_email=instance.email,
                member_roles=normalized_new
            )

        # Sync new roles with Slack channels if slack_bot_token and slack_user_id provided
        slack_sync_result = []
        slack_bot_token = request.data.get("slack_bot_token")
        slack_user_id = request.data.get("slack_user_id")
        if slack_bot_token and slack_user_id and normalized_new:
            slack_results, channel_ids = sync_member_to_slack_channels(
                bot_token=slack_bot_token,
                slack_user_id=slack_user_id,
                member_roles=normalized_new,
            )
            slack_sync_result = slack_results
            if channel_ids:
                existing_ids = instance.slack_channel_ids or []
                instance.slack_channel_ids = list(set(existing_ids + channel_ids))
                instance.save()

        member_name = f"{instance.first_name or ''} {instance.last_name or ''}".strip()
        response_data = {
            "message": f"Roles {normalized_new} added successfully to {member_name}.",
            "action": action,
            "updated_roles": updated_roles,
            "member_name": member_name,
        }
        if teams_sync_result:
            response_data["teams_sync"] = teams_sync_result

        if slack_sync_result:
            response_data["slack_sync"] = slack_sync_result

        return Response(response_data, status=status.HTTP_200_OK)
        
        
class MemberProfileView(generics.RetrieveAPIView):
    """
    GET /api/admin/users_details/member-profile/
    Returns the UserDetail profile of the currently logged-in member.
    """
    serializer_class = UserDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return UserDetail.objects.filter(email__iexact=self.request.user.email).first()

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        if not instance:
            return Response(
                {"error": "Member profile not found for this account."},
                status=status.HTTP_404_NOT_FOUND
            )
        serializer = self.get_serializer(instance)
        return Response({
            "message": "Profile retrieved successfully",
            "user": serializer.data
        }, status=status.HTTP_200_OK)


class UserDetailByAdminAPIView(generics.ListAPIView):
    """
    List all UserDetails created by a specific admin.
    Only the logged-in admin can view their own team members.
    """
    serializer_class = UserDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        admin_id = self.kwargs.get("admin_id")

        # Restrict: logged-in user can only view their own team members
        if str(self.request.user.id) != str(admin_id):
            return UserDetail.objects.none()

        return UserDetail.objects.filter(admin=self.request.user).select_related("admin").order_by("-created_at")

    def list(self, request, *args, **kwargs):
        admin_id = self.kwargs.get("admin_id")

        # Return 403 if trying to access another admin's data
        if str(request.user.id) != str(admin_id):
            return Response(
                {"detail": "You can only view your own team members."},
                status=status.HTTP_403_FORBIDDEN
            )

        queryset = list(self.get_queryset())

        if not queryset:
            return Response(
                {
                    "count": 0,
                    "results": [],
                    "message": "No users found for this admin"
                },
                status=status.HTTP_200_OK
            )

        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {
                "count": len(queryset),
                "admin_id": admin_id,
                "results": serializer.data
            },
            status=status.HTTP_200_OK
        )


class UserDetailSlackResyncView(generics.GenericAPIView):
    """
    Re-sync Slack channel membership for a team member.
    POST /api/admin/users-details/user-detail/<detail_id>/resync-slack/
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, detail_id):
        try:
            obj_id = ObjectId(detail_id)
        except Exception:
            return Response({"detail": "Invalid detail_id"}, status=status.HTTP_400_BAD_REQUEST)

        user_detail = get_object_or_404(UserDetail, _id=obj_id, admin=request.user)
        roles = user_detail.Member_role or []
        if not roles:
            return Response(
                {
                    "message": "Slack resync skipped",
                    "slack_sync": {"status": "skipped", "error": "missing_roles"},
                },
                status=status.HTTP_200_OK,
            )

        bot_token = request.data.get("slack_bot_token") or getattr(request.user, "slack_bot_token", None)
        if not bot_token:
            return Response(
                {
                    "message": "Slack resync skipped",
                    "slack_sync": {"status": "skipped", "error": "missing_slack_bot_token"},
                },
                status=status.HTTP_200_OK,
            )

        member_user = get_user_model().objects.filter(email=user_detail.email).first()
        slack_user_id = getattr(member_user, "slack_user_id", None) or lookup_slack_user_by_email(bot_token, user_detail.email)
        if not slack_user_id:
            invite_result = invite_user_to_slack_workspace(bot_token, user_detail.email)
            return Response(
                {
                    "message": "Slack resync pending",
                    "slack_sync": {
                        "status": "pending_workspace_join" if invite_result.get("status") == "invited" else "failed",
                        "workspace": {
                            "invited": invite_result.get("status") == "invited",
                            "already_member": invite_result.get("status") == "already_member",
                            "invite_email": user_detail.email,
                        },
                        "channels": [],
                        "error": invite_result.get("error"),
                    },
                },
                status=status.HTTP_200_OK,
            )

        slack_results, channel_ids = sync_member_to_slack_channels(
            bot_token=bot_token,
            slack_user_id=slack_user_id,
            member_roles=roles,
        )
        if channel_ids:
            user_detail.slack_channel_ids = list(set(channel_ids))
            user_detail.save(update_fields=["slack_channel_ids"])

        return Response(
            {
                "message": "Slack resync completed",
                "data": UserDetailSerializer(user_detail).data,
                "slack_sync": {
                    "status": "success",
                    "workspace": {"invited": False, "already_member": True},
                    "user_lookup": {"email": user_detail.email, "slack_user_id": slack_user_id},
                    "channels": slack_results,
                },
            },
            status=status.HTTP_200_OK,
        )