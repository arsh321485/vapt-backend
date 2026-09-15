"""
What happens to an admin's account and data when their Premium subscription
lapses — wired from billing/stripe_service.py's webhook handlers:

  invoice.payment_failed          -> send_payment_failed_warning_email()
  customer.subscription.deleted   -> purge_premium_admin_data() (+ the
                                      account-closed email, sent from inside it)

Only applies to Premium subscriptions — Freemium/Custom lapsing doesn't
trigger any of this. Deliberately destructive by explicit instruction: full,
permanent, irreversible deletion of the admin's operational data, and the
account itself locked out of login entirely (deactivated, no password reset/
set-password path works afterwards) — not a soft disconnect. Financial
records (billing.Subscription, billing.Invoice, billing.BillingCustomer,
billing.StripeWebhookEvent) are the one deliberate exception and are never
touched here — they're the accounting/audit trail and Stripe's own source of
truth for what was actually charged, kept regardless of what happens to the
account they're attached to.
"""
import logging
import os
import base64

import requests
from django.conf import settings

from users.models import User
from users.utils import Util

logger = logging.getLogger(__name__)


def _logo_b64():
    logo_path = os.path.join(str(settings.BASE_DIR), "users", "static", "users", "logo.png")
    if os.path.exists(logo_path):
        with open(logo_path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    return None


def _branded_email_html(title, body_html):
    logo_b64 = _logo_b64()
    logo_html = (
        '<img src="cid:vaptfix_logo" alt="VAPTFIX" style="height:42px; display:block; margin:0 auto;" />'
        if logo_b64 else
        '<div style="font-size:20px; color:#ffffff; font-weight:700; letter-spacing:0.5px;">VAPTFIX</div>'
    )
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="margin:0; padding:0; background-color:#eef0f6; font-family:Arial, sans-serif;">
      <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#eef0f6; padding:36px 0;">
        <tr>
          <td align="center">
            <table width="480" cellpadding="0" cellspacing="0"
                   style="background:#ffffff; border-radius:22px; overflow:hidden;
                          box-shadow:0 12px 30px rgba(18, 22, 33, 0.10);">
              <tr>
                <td style="background-color:#23124d; padding:20px 30px; text-align:center;">
                  {logo_html}
                </td>
              </tr>
              <tr>
                <td style="padding:34px 34px 30px 34px;">
                  <h1 style="color:#1f2040; margin:0 0 16px 0; font-size:26px; line-height:1.2;">{title}</h1>
                  {body_html}
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
    """
    return html, logo_b64


def _send(admin, subject, title, body_html):
    html, logo_b64 = _branded_email_html(title, body_html)
    ok, err = Util.send_mail({
        "to_email": admin.email,
        "subject": subject,
        "html_content": html,
        "inline_logo_b64": logo_b64,
    })
    if not ok:
        logger.error(f"[BillingLifecycle] Failed to send '{subject}' to {admin.email}: {err}")
    return ok


def send_payment_failed_warning_email(admin, subscription):
    """
    Fired on invoice.payment_failed for a Premium subscription — Stripe
    itself retries the charge for roughly 2-3 weeks before giving up and
    firing customer.subscription.deleted, so this lands well before the
    account is actually closed and gives a real chance to fix billing.
    """
    body_html = f"""
        <p style="color:#3a3f4b; font-size:15px; line-height:1.6; margin:0 0 16px 0;">
            Hi,
        </p>
        <p style="color:#3a3f4b; font-size:15px; line-height:1.6; margin:0 0 16px 0;">
            We couldn't process the latest payment for your VaptFix Premium subscription.
            We'll keep retrying automatically, but if the payment keeps failing, your
            subscription will be cancelled — and at that point <strong>all your VaptFix
            data (reports, vulnerabilities, scope, team members, everything) will be
            permanently deleted</strong>, and your account will be locked.
        </p>
        <p style="color:#3a3f4b; font-size:15px; line-height:1.6; margin:0 0 20px 0;">
            Please update your billing details as soon as possible to avoid this.
        </p>
        <table cellpadding="0" cellspacing="0" style="margin:0 auto;">
          <tr><td style="background:#23124d; border-radius:8px;">
            <a href="{getattr(settings, 'FRONTEND_URL', 'https://vaptfix.ai')}/billing"
               style="display:inline-block; padding:12px 26px; color:#ffffff; font-size:15px;
                      font-weight:600; text-decoration:none;">Update Billing Details</a>
          </td></tr>
        </table>
    """
    return _send(
        admin,
        subject="Action needed: your VaptFix payment failed",
        title="⚠️ Payment failed",
        body_html=body_html,
    )


def send_account_closed_email(admin):
    """Sent as part of purge_premium_admin_data() — informs the admin their
    account is closed and data has been permanently deleted."""
    body_html = f"""
        <p style="color:#3a3f4b; font-size:15px; line-height:1.6; margin:0 0 16px 0;">
            Hi,
        </p>
        <p style="color:#3a3f4b; font-size:15px; line-height:1.6; margin:0 0 16px 0;">
            Your VaptFix Premium subscription has ended. As a result, your account has
            been closed and <strong>all associated data has been permanently deleted</strong> —
            uploaded reports, vulnerabilities, scope, team members, and any connected
            Slack/Microsoft Teams workspace. This cannot be undone.
        </p>
        <p style="color:#3a3f4b; font-size:15px; line-height:1.6; margin:0 0 16px 0;">
            If you'd like to use VaptFix again, you're welcome to sign up as a new
            account at any time.
        </p>
    """
    return _send(
        admin,
        subject="Your VaptFix account has been closed",
        title="Account closed",
        body_html=body_html,
    )


def _revoke_slack(admin):
    bot_token = getattr(admin, "slack_bot_token", None)
    if not bot_token:
        return
    try:
        resp = requests.post(
            "https://slack.com/api/auth.revoke",
            headers={"Authorization": f"Bearer {bot_token}"},
            timeout=15,
        )
        logger.info(f"[BillingLifecycle] Slack auth.revoke for {admin.email}: {resp.status_code} {resp.text[:200]}")
    except Exception:
        logger.exception(f"[BillingLifecycle] Slack auth.revoke failed for {admin.email}")


def _remove_teams_bot_and_revoke(admin):
    team_id = getattr(admin, "ms_team_id", None)
    access_token = getattr(admin, "ms_access_token", None)
    if team_id and access_token:
        try:
            from teams_bot.conversation_store import get_team_channel_reference
            ref = get_team_channel_reference(team_id)
            if ref:
                # Best-effort: uninstall our Teams app from the team so it
                # stops posting/responding there. Needs the app's catalog
                # entry id, which (per earlier investigation) this app
                # doesn't have — Graph lookup will just come back empty and
                # this silently no-ops, which is fine; clearing the tokens
                # below is what actually revokes our access either way.
                headers = {"Authorization": f"Bearer {access_token}"}
                cat = requests.get(
                    f"https://graph.microsoft.com/v1.0/appCatalogs/teamsApps?$filter=externalId eq '{settings.MICROSOFT_CLIENT_ID}'",
                    headers=headers, timeout=15,
                )
                apps = (cat.json().get("value") or []) if cat.status_code == 200 else []
                if apps:
                    installed = requests.get(
                        f"https://graph.microsoft.com/v1.0/teams/{team_id}/installedApps?$filter=teamsApp/id eq '{apps[0]['id']}'",
                        headers=headers, timeout=15,
                    )
                    for inst in (installed.json().get("value") or []) if installed.status_code == 200 else []:
                        requests.delete(
                            f"https://graph.microsoft.com/v1.0/teams/{team_id}/installedApps/{inst['id']}",
                            headers=headers, timeout=15,
                        )
        except Exception:
            logger.exception(f"[BillingLifecycle] Teams app removal failed for {admin.email}")


def purge_admin_records(admin_id: str, admin_email: str, member_emails=None, aad_ids=None, team_id=None,
                         *, admin=None, dry_run: bool = False):
    """
    The actual cross-app/cross-collection cascade — factored out of
    purge_premium_admin_data() so it can also be driven purely by
    admin_id/admin_email (no live User row required). That split exists for
    a real gap: an admin manually deleted from the database (e.g. via the
    Django admin panel or a raw query) leaves every OTHER collection this
    app writes to untouched — Django's FK CASCADE only ever fires for
    models with a real ForeignKey to User, and this app's raw-pymongo
    collections (nessus_reports, vulnerability_cards, deleted/held asset
    history, tickets, ...) have no such relationship at all. Since almost
    every admin-scoped Mongo lookup in this app falls back to matching on
    admin_email when admin_id doesn't match (see e.g. billing/
    asset_service.py's get_admin_asset_count), a fresh signup with that
    SAME email — which gets a brand-new admin_id — still matches all this
    leftover data by email and resurfaces it under the "new" account. A
    truly clean re-signup requires purging every collection this function
    covers, not just the one report an admin happened to remember to delete.

    Pass a live `admin` User instance when one still exists so ORM deletes
    can use the FK relation directly (`admin=admin`) instead of the raw
    id column — behavior is identical either way, filtering on the same
    underlying column. `dry_run=True` counts what WOULD be deleted without
    deleting anything (via .count() instead of .delete(), and
    count_documents() instead of delete_many()).

    Returns {collection_or_model_name: count}.
    """
    member_emails = set(member_emails or [])
    member_emails.add(admin_email)
    aad_ids = set(aad_ids or [])

    from vaptfix.mongo_client import MongoContext

    with MongoContext() as db:
        report_ids = set()
        for doc in db["nessus_reports"].find(
            {"$or": [{"admin_id": admin_id}, {"admin_email": admin_email}]},
            {"report_id": 1},
        ):
            rid = doc.get("report_id") or str(doc.get("_id"))
            if rid:
                report_ids.add(str(rid))

        # fix_vulnerabilities(_closed) docs need to be resolved to their own
        # _id first — fix_step_feedback / fix_vulnerability_final_feedback
        # are keyed by fix_vulnerability_id only, no report_id/admin field
        # of their own (two-hop lookup).
        fix_vuln_ids = set()
        if report_ids:
            for coll in ("fix_vulnerabilities", "fix_vulnerabilities_closed"):
                for doc in db[coll].find({"report_id": {"$in": list(report_ids)}}, {"_id": 1}):
                    fix_vuln_ids.add(str(doc["_id"]))

    # -- Django ORM models -------------------------------------------------
    from upload_report.models import UploadReport
    from risk_criteria.models import RiskCriteria
    from users_details.models import UserDetail
    from scope.models import Scope
    from location.models import Location
    from scoping.models import ProjectDetail, TestingMethodology

    def _qs_result(qs):
        if dry_run:
            return qs.count()
        deleted, _ = qs.delete()
        return deleted

    deleted_counts = {}
    if admin is not None:
        upload_report_qs = UploadReport.objects.filter(admin=admin)
        risk_criteria_qs = RiskCriteria.objects.filter(admin=admin)
        user_detail_qs = UserDetail.objects.filter(admin=admin)
        scope_qs = Scope.objects.filter(admin=admin)
        location_qs = Location.objects.filter(admin=admin)
        project_detail_qs = ProjectDetail.objects.filter(admin=admin)
        testing_methodology_qs = TestingMethodology.objects.filter(admin=admin)
    else:
        upload_report_qs = UploadReport.objects.filter(admin_id=admin_id)
        risk_criteria_qs = RiskCriteria.objects.filter(admin_id=admin_id)
        user_detail_qs = UserDetail.objects.filter(admin_id=admin_id)
        scope_qs = Scope.objects.filter(admin_id=admin_id)
        location_qs = Location.objects.filter(admin_id=admin_id)
        project_detail_qs = ProjectDetail.objects.filter(admin_id=admin_id)
        testing_methodology_qs = TestingMethodology.objects.filter(admin_id=admin_id)

    deleted_counts["UploadReport"] = _qs_result(upload_report_qs)
    # UploadReport.admin_email is denormalized independently of the admin
    # FK (kept even after a SET_NULL) — a row created before the FK was
    # cleared, or one the admin_id filter above missed entirely because the
    # User row is already gone, still needs catching by email.
    deleted_counts["UploadReport (by admin_email)"] = _qs_result(
        UploadReport.objects.filter(admin_email__iexact=admin_email)
    )
    deleted_counts["RiskCriteria"] = _qs_result(risk_criteria_qs)
    deleted_counts["UserDetail"] = _qs_result(user_detail_qs)
    deleted_counts["Scope"] = _qs_result(scope_qs)
    deleted_counts["Location"] = _qs_result(location_qs)
    deleted_counts["ProjectDetail"] = _qs_result(project_detail_qs)
    deleted_counts["TestingMethodology"] = _qs_result(testing_methodology_qs)

    # -- Raw Mongo collections ----------------------------------------------
    with MongoContext() as db:
        def _mongo_result(coll_name, filt):
            if dry_run:
                return db[coll_name].count_documents(filt)
            return db[coll_name].delete_many(filt).deleted_count

        admin_id_or_email = {"$or": [{"admin_id": admin_id}, {"admin_email": admin_email}]}
        member_email_filter = {"user_email": {"$in": list(member_emails)}}

        # Collections keyed directly by admin_id/admin_email.
        for coll in (
            "nessus_reports", "support_requests", "timeline_extension_requests",
            "notifications_notification",
        ):
            try:
                count = _mongo_result(coll, admin_id_or_email)
                if count:
                    deleted_counts[coll] = count
            except Exception:
                logger.exception(f"[BillingLifecycle] delete failed for collection={coll}")

        # Keyed by user_email (admin's own + every team member's — these
        # collections record who downloaded/gave feedback on a script, not
        # who owns the account).
        for coll in ("script_user_downloads", "script_feedback"):
            try:
                count = _mongo_result(coll, member_email_filter)
                if count:
                    deleted_counts[coll] = count
            except Exception:
                logger.exception(f"[BillingLifecycle] delete failed for collection={coll}")

        # tickets: admin-created ones carry admin_id/admin_email; team-member
        # -submitted ones carry only report_id — need both filters, OR'd.
        try:
            ticket_filter = {"$or": [
                {"admin_id": admin_id}, {"admin_email": admin_email},
                {"report_id": {"$in": list(report_ids)}},
            ]} if report_ids else admin_id_or_email
            count = _mongo_result("tickets", ticket_filter)
            if count:
                deleted_counts["tickets"] = count
        except Exception:
            logger.exception("[BillingLifecycle] delete failed for collection=tickets")

        # ScopeEntry docs (scope_entries) have no admin field of their own —
        # cascade-deleted via the Scope ORM delete above already; nothing to
        # do here directly.

        if report_ids:
            rid_filter = {"report_id": {"$in": list(report_ids)}}
            for coll in (
                "vulnerability_cards", "parsed_reports",
                "fix_vulnerabilities", "fix_vulnerabilities_closed",
                "hold_assets", "deleted_assets",
                "hold_vulnerabilities", "deleted_vulnerabilities",
                "card_gen_locks",
            ):
                try:
                    count = _mongo_result(coll, rid_filter)
                    if count:
                        deleted_counts[coll] = count
                except Exception:
                    logger.exception(f"[BillingLifecycle] delete failed for collection={coll}")

            # fix_vulnerability_steps carries its own report_id field too —
            # direct filter, no need to go via fix_vuln_ids.
            try:
                count = _mongo_result("fix_vulnerability_steps", rid_filter)
                if count:
                    deleted_counts["fix_vulnerability_steps"] = count
            except Exception:
                logger.exception("[BillingLifecycle] delete failed for collection=fix_vulnerability_steps")

        if fix_vuln_ids:
            fv_filter = {"fix_vulnerability_id": {"$in": list(fix_vuln_ids)}}
            for coll in ("fix_step_feedback", "fix_vulnerability_final_feedback"):
                try:
                    count = _mongo_result(coll, fv_filter)
                    if count:
                        deleted_counts[coll] = count
                except Exception:
                    logger.exception(f"[BillingLifecycle] delete failed for collection={coll}")

        # Teams bot bookkeeping — no admin_id/admin_email field on
        # teams_bot_conversations, only user_aad_id + team_id.
        try:
            if team_id:
                count = _mongo_result("teams_bot_team_channels", {"team_id": team_id})
                if count:
                    deleted_counts["teams_bot_team_channels"] = count
            conv_filter_or = []
            if aad_ids:
                conv_filter_or.append({"user_aad_id": {"$in": list(aad_ids)}})
            if team_id:
                conv_filter_or.append({"team_id": team_id})
            if conv_filter_or:
                count = _mongo_result("teams_bot_conversations", {"$or": conv_filter_or})
                if count:
                    deleted_counts["teams_bot_conversations"] = count
        except Exception:
            logger.exception("[BillingLifecycle] delete failed for teams_bot collections")

    verb = "Dry-run purge" if dry_run else "Purge"
    logger.warning(f"[BillingLifecycle] {verb} complete for admin={admin_email}: {deleted_counts}")
    return deleted_counts


def purge_premium_admin_data(admin: User):
    """
    Full, permanent, irreversible deletion of a Premium admin's data after
    their subscription ends — deliberately aggressive per explicit
    instruction. Never touches billing.Subscription / billing.Invoice /
    billing.BillingCustomer / billing.StripeWebhookEvent (financial/audit
    records) or the User row itself (deactivated instead of deleted, so
    Invoice/Subscription FKs stay intact and the email/account identity
    can't be silently reused — see purge_admin_data management command /
    purge_admin_records() above for the variant that DOES delete the row,
    for when an admin is being removed on purpose rather than auto-purged
    after a lapsed subscription).
    """
    admin_id = str(admin.id)
    admin_email = admin.email
    logger.warning(f"[BillingLifecycle] Starting full data purge for admin={admin_email} id={admin_id}")

    _revoke_slack(admin)
    _remove_teams_bot_and_revoke(admin)

    # -- Gather everything needed to find related records BEFORE the ORM
    # deletes inside purge_admin_records() remove the rows these come from
    # (team member emails, Teams AAD ids) ---------------------------------
    from users_details.models import UserDetail

    member_details = list(UserDetail.objects.filter(admin=admin).values("email", "ms_teams_member_id"))
    member_emails = {admin_email} | {d["email"] for d in member_details if d.get("email")}
    aad_ids = {aid for aid in (
        [getattr(admin, "ms_teams_object_id", None)] + [d.get("ms_teams_member_id") for d in member_details]
    ) if aid}
    team_id = getattr(admin, "ms_team_id", None)

    deleted_counts = purge_admin_records(
        admin_id, admin_email, member_emails=member_emails, aad_ids=aad_ids, team_id=team_id, admin=admin,
    )

    # -- Send the closure notice BEFORE locking the account, then deactivate --
    try:
        send_account_closed_email(admin)
    except Exception:
        logger.exception(f"[BillingLifecycle] account-closed email failed for {admin_email}")

    User.objects.filter(pk=admin.pk).update(
        is_active=False,
        slack_bot_token=None, slack_team_id=None, slack_user_id=None,
        ms_access_token=None, ms_refresh_token=None, ms_team_id=None,
    )

    return deleted_counts
