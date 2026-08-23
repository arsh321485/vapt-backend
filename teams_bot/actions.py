"""
Routes Adaptive Card Action.Submit clicks (action_id in the activity's
`value`) to their handler, and does the actual work — scope/report
submission, risk-criteria save, nav-tab content. The Teams counterpart of
SlackInteractivityView._handle_action / _handle_view_submission.

teams_bot runs in the SAME Django process as the rest of the app (no
separate service), so instead of round-tripping through
VAPTFIX_BACKEND_URL like the Slack integration does, handlers here either
call the relevant DRF view in-process (force_authenticate as the resolved
admin) or use the ORM directly for anything simple enough not to need the
view's extra validation.
"""
import logging

from django.core.cache import cache
from rest_framework.test import APIRequestFactory, force_authenticate

from . import cards
from .onboarding import post_onboarding_step

logger = logging.getLogger(__name__)

_factory = APIRequestFactory()


def _call_view_in_process(view_cls, admin, data=None, files=None, method="post"):
    """Invokes a DRF APIView's endpoint in-process as `admin`, multipart so
    both plain fields and file uploads work through the same call."""
    payload = dict(data or {})
    if files:
        payload.update(files)
    factory_method = getattr(_factory, method)
    request = factory_method("/internal/", payload, format="multipart")
    force_authenticate(request, user=admin)
    response = view_cls.as_view()(request)
    if hasattr(response, "render"):
        response.render()
    return response.status_code, response.data


def _pending_upload_key(team_id):
    return f"teams_bot_pending_upload:{team_id}"


def set_pending_upload_intent(team_id, purpose):
    """purpose: "report" or "scope_csv" — read back by
    TeamsBotMessagesView._handle_message when the next attachment arrives.

    Keyed by team_id, NOT conversation_id — confirmed via real Teams data
    that a channel post and a reply inside its own thread get DIFFERENT
    conversation ids (the reply's has a ";messageid=..." suffix). The
    button click (a reply) and the file the admin attaches next (usually a
    fresh top-level post, not a reply in that same thread) landed in two
    different conversations, so a conversation_id-keyed flag was never
    found when the file arrived — team_id is the one thing guaranteed
    stable across both.
    """
    cache.set(_pending_upload_key(team_id), purpose, timeout=900)


def pop_pending_upload_intent(team_id):
    key = _pending_upload_key(team_id)
    purpose = cache.get(key)
    if purpose:
        cache.delete(key)
    return purpose


def submit_report_file(admin, file_name, file_bytes):
    from upload_report.views import UploadReportView
    from django.core.files.uploadedfile import SimpleUploadedFile

    upload = SimpleUploadedFile(file_name, file_bytes)
    status_code, data = _call_view_in_process(
        UploadReportView, admin, files={"file": upload},
    )
    return status_code, data


def submit_scope_csv(admin, file_name, file_bytes):
    from scope.views import ScopeCreateAPIView
    from django.core.files.uploadedfile import SimpleUploadedFile

    upload = SimpleUploadedFile(file_name, file_bytes)
    status_code, data = _call_view_in_process(
        ScopeCreateAPIView, admin, files={"file": upload},
    )
    return status_code, data


def submit_scope_manual(admin, targets_raw):
    from scope.views import ScopeCreateAPIView

    # parse_targets_string on the backend only splits on newlines — accept
    # comma-separated input too, same normalization the Slack integration
    # applies before this same endpoint.
    targets = (targets_raw or "").replace(",", "\n")
    status_code, data = _call_view_in_process(
        ScopeCreateAPIView, admin, data={"targets": targets},
    )
    return status_code, data


def get_existing_risk_criteria(admin):
    from risk_criteria.models import RiskCriteria
    rc = RiskCriteria.objects.filter(admin=admin).order_by("-created_at").first()
    if not rc:
        return None
    return {"critical": rc.critical, "high": rc.high, "medium": rc.medium, "low": rc.low}


def save_risk_criteria(admin, critical, high, medium, low):
    from risk_criteria.models import RiskCriteria
    rc = RiskCriteria.objects.filter(admin=admin).order_by("-created_at").first()
    if rc:
        rc.critical, rc.high, rc.medium, rc.low = critical, high, medium, low
        rc.save(update_fields=["critical", "high", "medium", "low", "updated_at"])
    else:
        RiskCriteria.objects.create(admin=admin, critical=critical, high=high, medium=medium, low=low)


def handle_card_action(admin, team_id, conversation_id, value: dict):
    """
    Returns an Adaptive Card (dict) to send back as the reply for a given
    action_id — the single dispatch point _handle_message hands
    Action.Submit clicks off to.
    """
    action_id = (value or {}).get("action_id")

    if action_id == "open_provide_scope":
        return cards.provide_scope_card()

    if action_id == "open_enter_scope_options":
        return cards.enter_scope_options_card()

    if action_id == "back_to_provide_scope":
        return cards.provide_scope_card()

    if action_id == "open_upload_report":
        return cards.open_website_upload_card("report")

    if action_id == "open_scope_csv":
        return cards.open_website_upload_card("scope")

    if action_id == "open_scope_manual":
        return cards.manual_scope_form_card()

    if action_id == "submit_manual_scope":
        targets = value.get("manual_scope_targets") or ""
        if not targets.strip():
            return cards.text_result_card("❌ Missing targets", "Please enter at least one target.")
        try:
            status_code, data = submit_scope_manual(admin, targets)
        except Exception:
            logger.exception("[TeamsBot] submit_scope_manual failed")
            return cards.text_result_card("❌ Something went wrong", "Could not submit scope — please try again.")
        if status_code >= 300:
            reason = (data or {}).get("message") or "Could not create scope."
            return cards.text_result_card("❌ Could not save scope", str(reason))
        return cards.text_result_card("✅ Scope saved", "Your scope has been submitted. We'll take it from here.")

    if action_id == "open_risk_criteria":
        existing = get_existing_risk_criteria(admin)
        return cards.risk_criteria_form_card(existing)

    if action_id == "submit_risk_criteria":
        critical = value.get("rc_critical") or cards.RISK_CRITERIA_DEFAULTS["critical"]
        high = value.get("rc_high") or cards.RISK_CRITERIA_DEFAULTS["high"]
        medium = value.get("rc_medium") or cards.RISK_CRITERIA_DEFAULTS["medium"]
        low = value.get("rc_low") or cards.RISK_CRITERIA_DEFAULTS["low"]
        try:
            save_risk_criteria(admin, critical, high, medium, low)
        except Exception:
            logger.exception("[TeamsBot] save_risk_criteria failed")
            return cards.text_result_card("❌ Something went wrong", "Could not save risk criteria — please try again.")
        # Transition complete — same follow-up Slack does: post the real
        # navbar right after, into the admin-dashboard channel.
        try:
            post_onboarding_step(admin, team_id=team_id, force_state="ready")
        except Exception:
            logger.exception("[TeamsBot] failed to post navbar after risk criteria save")
        return cards.text_result_card("✅ Risk criteria saved", "Loading your dashboard…")

    if action_id in ("fix_sub_assets", "fix_sub_vulns", "fix_sub_common"):
        try:
            body = cards.fix_tab_body(team_id, active_sub=action_id)
        except Exception:
            logger.exception(f"[TeamsBot] fix_tab_body failed for {action_id}")
            body = [cards._header("🔧 Fix"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "fix_common_team":
        team_key = value.get("team") or "config"
        try:
            body = cards.fix_tab_body(team_id, active_sub="fix_sub_common", common_team=team_key)
        except Exception:
            logger.exception("[TeamsBot] fix_tab_body (common vulns team switch) failed")
            body = [cards._header("🧩 Common Vulns"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id and action_id.startswith("nav_"):
        return _handle_nav(admin, team_id, action_id)

    return cards.text_result_card("🤔 Not sure what that was", "Please try that action again.")


def _handle_nav(admin, team_id, action_id):
    """
    nav_home and nav_team render the real bento-grid dashboard as a PNG
    image — the exact same rendering pipeline already built for Slack
    (see teams_bot.views.TeamsDashboardImageView), so these match the
    reference design pixel-for-pixel instead of a hand-built approximation.
    Other tabs (Fix/Register/Automations/Timeline Ext.) are acknowledged
    for now rather than left as dead clicks — full per-tab content is the
    next phase of this port.
    """
    if action_id == "nav_home":
        try:
            body = cards.dashboard_image_card_body(team_id, kind="dashboard", title="VaptFix Admin Dashboard")
        except Exception:
            logger.exception("[TeamsBot] dashboard image body failed, falling back to text summary")
            body = _home_summary_body(admin)
        return cards.nav_buttons_card(active_action_id="nav_home", extra_body=body)

    if action_id == "nav_team":
        try:
            body = cards.dashboard_image_card_body(team_id, kind="teamperf", title="Team Performance")
        except Exception:
            logger.exception("[TeamsBot] team performance image body failed")
            body = [cards._header("👥 Team"), cards._body_text("Could not load team performance right now.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "nav_fix":
        try:
            body = cards.fix_tab_body(team_id, active_sub="fix_sub_assets")
        except Exception:
            logger.exception("[TeamsBot] fix_tab_body (default) failed")
            body = [cards._header("🔧 Fix"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    label = dict(cards.NAV_ITEMS).get(action_id, action_id)
    return cards.nav_buttons_card(
        active_action_id=action_id,
        extra_body=[cards._header(label), cards._body_text(
            "Full content for this tab is coming in the next update — for now, use the website for this section."
        )],
    )


def _home_summary_body(admin):
    """
    Full Home-tab body — mirrors the layout of the reference design
    (Microsoft -Admin/home.html): header, 3 stat cards, severity breakdown,
    vulnerabilities fixed, mitigation timeline, support requests. See
    cards.home_dashboard_card_body for how each section is actually built.
    """
    try:
        from admindashboard.views import AdminDashboardSummaryAPIView
        status_code, data = _call_view_in_process(AdminDashboardSummaryAPIView, admin, method="get")
        if status_code >= 300 or not isinstance(data, dict):
            raise ValueError(f"summary call failed: {status_code}")
        return cards.home_dashboard_card_body(data)
    except Exception:
        logger.exception("[TeamsBot] home summary fetch failed")
        return [cards._header("🏠 Home"), cards._body_text("Could not load your dashboard summary right now.")]
