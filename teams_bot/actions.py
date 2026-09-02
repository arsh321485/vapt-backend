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
from . import fix_tab
from . import register_tab
from . import automations_tab
from . import team_tab
from . import timeline_tab
from . import reminder_tab
from . import download_tab
from .onboarding import post_onboarding_step

logger = logging.getLogger(__name__)

_factory = APIRequestFactory()


def _call_view_in_process(view_cls, admin, data=None, files=None, method="post", url_kwargs=None, request_format="multipart"):
    """Invokes a DRF endpoint in-process as `admin` — multipart by default so
    both plain fields and file uploads work through the same call.

    `url_kwargs`: for endpoints whose path carries arguments (report_id,
    fix_vuln_id, plugin_id, ...) — DRF hands these to the view as normal
    view kwargs, same as the URLconf would, so pass them here instead of
    trying to bake them into the (never-actually-routed) "/internal/" path.
    `view_cls` also accepts a plain @api_view-decorated function (has no
    .as_view()) — those are called directly, same call shape either way.
    `request_format`: "json" for bodies with nested lists/dicts (multipart
    can't encode those) — e.g. {"vulnerability_names": [...]}.
    """
    payload = dict(data or {})
    if files:
        payload.update(files)
    factory_method = getattr(_factory, method)
    request = factory_method("/internal/", payload, format=request_format)
    force_authenticate(request, user=admin)
    view = view_cls.as_view() if hasattr(view_cls, "as_view") else view_cls
    response = view(request, **(url_kwargs or {}))
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


def format_scope_result_message(data):
    """
    Builds a plain-text summary from ScopeCreateAPIView's response —
    created/error counts, up to 3 per-line errors, and the Freemium/
    Premium plan_recommendation message — used by both the manual-entry
    and file-upload scope submission paths. Confirmed via real feedback
    that Teams (and Slack) were showing a bare "Scope saved" success
    message that silently dropped rejected entries and the plan
    recommendation the website surfaces, even though the same
    ScopeCreateAPIView response already carries all of it.
    """
    processing = (data or {}).get("processing") or {}
    created_count = processing.get("created_count", 0)
    error_count = processing.get("error_count", 0)
    errors = processing.get("errors") or []

    lines = [f"{created_count} target(s) saved."]
    if error_count:
        lines.append(f"{error_count} entr{'y' if error_count == 1 else 'ies'} were rejected:")
        for e in errors[:3]:
            lines.append(f"  • {e.get('value')}: {e.get('error')}")
        if len(errors) > 3:
            lines.append(f"  …and {len(errors) - 3} more.")

    rec = (data or {}).get("plan_recommendation") or {}
    if rec.get("message"):
        lines.append("")
        lines.append(rec["message"])

    return "\n".join(lines)


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


def handle_card_action(admin, team_id, channel_id, value: dict):
    """
    Returns an Adaptive Card (dict) to send back as the reply for a given
    action_id — the single dispatch point _handle_message hands
    Action.Submit clicks off to.
    """
    action_id = (value or {}).get("action_id")

    # Real bug report: the admin themself clicking/messaging inside one of
    # their OWN 4 team-role channels (e.g. "vaptfix Configuration
    # Management team") fell all the way through every action_id check
    # below with no match (those cards' action_ids belong to the member-
    # side vocabulary, not this admin one) and landed on the generic "Not
    # sure what that was" fallback — confusing, and no indication of WHY.
    # get_team_name_for_channel only returns non-None for those 4 specific
    # channels (never for the admin-dashboard channel or General), so this
    # is a precise "you're the admin, but this is a member-only channel"
    # signal, not just "channel_id looked unfamiliar".
    if channel_id and team_id:
        from . import conversation_store
        member_team_name = conversation_store.get_team_name_for_channel(team_id, channel_id)
        if member_team_name:
            return cards.text_result_card(
                "🔒 Not available",
                f"Only {member_team_name} team members can access this channel. Please use the vaptfix admin dashboard channel instead.",
            )

    if action_id == "open_provide_scope":
        return cards.provide_scope_card()

    if action_id == "open_enter_scope_options":
        return cards.enter_scope_options_card()

    if action_id == "back_to_provide_scope":
        return cards.provide_scope_card()

    if action_id == "open_upload_report":
        return cards.open_website_upload_card("report", admin=admin)

    if action_id == "open_scope_csv":
        return cards.open_website_upload_card("scope", admin=admin)

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
        return cards.text_result_card("✅ Scope saved", format_scope_result_message(data))

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
        # Return the real navbar/dashboard directly as THIS action's own
        # response — NOT a separate proactive post (post_onboarding_step)
        # plus a generic "Loading…" placeholder returned alongside it.
        # Confirmed real bug: those two raced to own the same "active
        # card" slot; the placeholder always won and then nothing ever
        # replaced it, so the risk-criteria-saved click looked
        # permanently stuck on "Loading your dashboard…".
        try:
            from . import onboarding as _onboarding
            return _onboarding.build_state_card(admin, team_id, "ready")
        except Exception:
            logger.exception("[TeamsBot] failed to build dashboard card after risk criteria save")
            return cards.text_result_card("✅ Risk criteria saved", "Mention me (@VaptFix) to open your dashboard.")

    if action_id in ("fix_sub_assets", "fix_sub_vulns", "fix_sub_common"):
        try:
            body = fix_tab.fix_tab_body(admin, active_sub=action_id)
        except Exception:
            logger.exception(f"[TeamsBot] fix_tab_body failed for {action_id}")
            body = [cards._header("🔧 Fix"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "fix_common_team":
        team_key = value.get("team") or "config"
        try:
            body = fix_tab.fix_tab_body(admin, active_sub="fix_sub_common", common_team=team_key)
        except Exception:
            logger.exception("[TeamsBot] fix_tab_body (common vulns team switch) failed")
            body = [cards._header("🧩 Common Vulns"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    # Fix tab drill-down: asset/vuln "View" + pagination + Back — all real
    # Action.Submit clicks now (see teams_bot.fix_tab), matching Slack's
    # actual clickable list+detail behaviour instead of a flat picture.
    if action_id == "fix_asset_pg":
        offset = int(value.get("offset") or 0)
        try:
            body = fix_tab.fix_tab_body(admin, active_sub="fix_sub_assets", offset=offset)
        except Exception:
            logger.exception("[TeamsBot] fix_asset_pg failed")
            body = [cards._header("💻 All Assets"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "fix_asset_view":
        host = value.get("host") or ""
        back_offset = int(value.get("offset") or 0)
        try:
            body = [cards._fix_subnav_columnset("fix_sub_assets")] + fix_tab.asset_detail_body(admin, host, back_offset=back_offset)
        except Exception:
            logger.exception("[TeamsBot] fix_asset_view failed")
            body = [cards._header("🖥 Asset"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "fix_asset_vuln_view":
        host = value.get("host") or ""
        idx = value.get("idx")
        idx = int(idx) if idx is not None else None
        list_offset = int(value.get("offset") or 0)
        try:
            body = [cards._fix_subnav_columnset("fix_sub_assets")] + fix_tab.asset_vuln_detail_body(admin, idx, host, back_offset=list_offset)
        except Exception:
            logger.exception("[TeamsBot] fix_asset_vuln_view failed")
            body = [cards._header("📋 Vulnerability"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "fix_asset_vuln_back":
        host = value.get("host") or ""
        offset = int(value.get("offset") or 0)
        try:
            body = [cards._fix_subnav_columnset("fix_sub_assets")] + fix_tab.asset_detail_body(admin, host, back_offset=offset)
        except Exception:
            logger.exception("[TeamsBot] fix_asset_vuln_back failed")
            body = [cards._header("🖥 Asset"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "fix_asset_back":
        offset = int(value.get("offset") or 0)
        try:
            body = fix_tab.fix_tab_body(admin, active_sub="fix_sub_assets", offset=offset)
        except Exception:
            logger.exception("[TeamsBot] fix_asset_back failed")
            body = [cards._header("💻 All Assets"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "fix_vuln_pg":
        offset = int(value.get("offset") or 0)
        try:
            body = fix_tab.fix_tab_body(admin, active_sub="fix_sub_vulns", offset=offset)
        except Exception:
            logger.exception("[TeamsBot] fix_vuln_pg failed")
            body = [cards._header("📋 All Vulns"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "fix_vuln_view":
        idx = value.get("idx")
        idx = int(idx) if idx is not None else None
        back_offset = int(value.get("offset") or 0)
        try:
            body = [cards._fix_subnav_columnset("fix_sub_vulns")] + fix_tab.vuln_detail_body(admin, idx, back_offset=back_offset)
        except Exception:
            logger.exception("[TeamsBot] fix_vuln_view failed")
            body = [cards._header("📋 Vulnerability"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "fix_vuln_toggle":
        # Manual/Automation Fix toggle inside a vuln's own detail page —
        # works from any entry point (flat All Vulns list, an asset's own
        # vuln list, or Register's filtered list — ctx says which), see
        # fix_tab._vuln_detail_full_body's ctx/back_action_id/extra_value
        # handling.
        sub = value.get("sub") or "manual"
        ctx = value.get("ctx") or "vulns"
        idx = value.get("idx")
        idx = int(idx) if idx is not None else None
        offset = int(value.get("offset") or 0)
        host = value.get("host") or ""

        if ctx == "register":
            sev = value.get("sev") or "all"
            st = value.get("st") or "all"
            try:
                content = register_tab.register_vuln_detail_body(admin, idx, sub=sub, sev=sev, st=st, offset=offset)
                body = [register_tab.register_subnav_columnset("reg_sub_register")] + content
            except Exception:
                logger.exception("[TeamsBot] fix_vuln_toggle (register) failed")
                body = [cards._header("📋 Vulnerability"), cards._body_text("Could not load this right now.")]
            return cards.nav_buttons_card(active_action_id="nav_register", extra_body=body)

        active_sub = "fix_sub_assets" if ctx == "asset" else "fix_sub_vulns"
        try:
            if ctx == "asset":
                content = fix_tab.asset_vuln_detail_body(admin, idx, host, back_offset=offset, sub=sub)
            else:
                content = fix_tab.vuln_detail_body(admin, idx, back_offset=offset, sub=sub)
            body = [cards._fix_subnav_columnset(active_sub)] + content
        except Exception:
            logger.exception("[TeamsBot] fix_vuln_toggle failed")
            body = [cards._header("📋 Vulnerability"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "fix_step_nav":
        # Previous/Next Step inside Manual Fix's one-at-a-time view — same
        # ctx-based routing as fix_vuln_toggle above, just re-rendering
        # with a specific step_number instead of toggling sub.
        ctx = value.get("ctx") or "vulns"
        idx = value.get("idx")
        idx = int(idx) if idx is not None else None
        offset = int(value.get("offset") or 0)
        host = value.get("host") or ""
        step = value.get("step")
        step = int(step) if step is not None else None

        if ctx == "register":
            sev = value.get("sev") or "all"
            st = value.get("st") or "all"
            try:
                content = register_tab.register_vuln_detail_body(admin, idx, sub="manual", sev=sev, st=st, offset=offset, step_number=step)
                body = [register_tab.register_subnav_columnset("reg_sub_register")] + content
            except Exception:
                logger.exception("[TeamsBot] fix_step_nav (register) failed")
                body = [cards._header("📋 Vulnerability"), cards._body_text("Could not load this right now.")]
            return cards.nav_buttons_card(active_action_id="nav_register", extra_body=body)

        active_sub = "fix_sub_assets" if ctx == "asset" else "fix_sub_vulns"
        try:
            if ctx == "asset":
                content = fix_tab.asset_vuln_detail_body(admin, idx, host, back_offset=offset, sub="manual", step_number=step)
            else:
                content = fix_tab.vuln_detail_body(admin, idx, back_offset=offset, sub="manual", step_number=step)
            body = [cards._fix_subnav_columnset(active_sub)] + content
        except Exception:
            logger.exception("[TeamsBot] fix_step_nav failed")
            body = [cards._header("📋 Vulnerability"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    # ── Register tab ──────────────────────────────────────────────────
    if action_id in ("reg_sub_register", "reg_sub_script"):
        try:
            body = register_tab.register_tab_body(admin, active_sub=action_id)
        except Exception:
            logger.exception(f"[TeamsBot] register_tab_body failed for {action_id}")
            body = [cards._header("📋 Register"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_register", extra_body=body)

    if action_id in ("reg_sev", "reg_st"):
        sev = value.get("sev") or "all"
        st = value.get("st") or "all"
        try:
            body = register_tab.register_tab_body(admin, active_sub="reg_sub_register", sev=sev, st=st, offset=0)
        except Exception:
            logger.exception(f"[TeamsBot] {action_id} failed")
            body = [cards._header("📋 Register"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_register", extra_body=body)

    if action_id == "reg_view_pg":
        sev = value.get("sev") or "all"
        st = value.get("st") or "all"
        offset = int(value.get("offset") or 0)
        try:
            body = register_tab.register_tab_body(admin, active_sub="reg_sub_register", sev=sev, st=st, offset=offset)
        except Exception:
            logger.exception("[TeamsBot] reg_view_pg failed")
            body = [cards._header("📋 Register"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_register", extra_body=body)

    if action_id == "script_pg":
        offset = int(value.get("offset") or 0)
        try:
            body = register_tab.register_tab_body(admin, active_sub="reg_sub_script", offset=offset)
        except Exception:
            logger.exception("[TeamsBot] script_pg failed")
            body = [cards._header("📜 Script"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_register", extra_body=body)

    if action_id == "reg_view":
        idx = value.get("idx")
        idx = int(idx) if idx is not None else None
        sev = value.get("sev") or "all"
        st = value.get("st") or "all"
        offset = int(value.get("offset") or 0)
        try:
            content = register_tab.register_vuln_detail_body(admin, idx, sub="manual", sev=sev, st=st, offset=offset)
            body = [register_tab.register_subnav_columnset("reg_sub_register")] + content
        except Exception:
            logger.exception("[TeamsBot] reg_view failed")
            body = [cards._header("📋 Vulnerability"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_register", extra_body=body)

    if action_id == "reg_view_back":
        sev = value.get("sev") or "all"
        st = value.get("st") or "all"
        offset = int(value.get("offset") or 0)
        try:
            body = register_tab.register_tab_body(admin, active_sub="reg_sub_register", sev=sev, st=st, offset=offset)
        except Exception:
            logger.exception("[TeamsBot] reg_view_back failed")
            body = [cards._header("📋 Register"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_register", extra_body=body)

    # ── Automations tab ───────────────────────────────────────────────
    if action_id in ("auto_sub_full", "auto_sub_partial"):
        try:
            body = automations_tab.automations_tab_body(admin, active_sub=action_id)
        except Exception:
            logger.exception(f"[TeamsBot] automations_tab_body failed for {action_id}")
            body = [cards._header("🤖 Automations"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_automation", extra_body=body)

    if action_id == "auto_sev":
        category = value.get("category") or "full"
        sev = value.get("sev") or "all"
        active_sub = "auto_sub_partial" if category == "partial" else "auto_sub_full"
        try:
            body = automations_tab.automations_tab_body(admin, active_sub=active_sub, sev=sev, offset=0)
        except Exception:
            logger.exception("[TeamsBot] auto_sev failed")
            body = [cards._header("🤖 Automations"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_automation", extra_body=body)

    if action_id == "auto_list_pg":
        category = value.get("category") or "full"
        sev = value.get("sev") or "all"
        offset = int(value.get("offset") or 0)
        active_sub = "auto_sub_partial" if category == "partial" else "auto_sub_full"
        try:
            body = automations_tab.automations_tab_body(admin, active_sub=active_sub, sev=sev, offset=offset)
        except Exception:
            logger.exception("[TeamsBot] auto_list_pg failed")
            body = [cards._header("🤖 Automations"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_automation", extra_body=body)

    if action_id == "fix_vuln_back":
        offset = int(value.get("offset") or 0)
        try:
            body = fix_tab.fix_tab_body(admin, active_sub="fix_sub_vulns", offset=offset)
        except Exception:
            logger.exception("[TeamsBot] fix_vuln_back failed")
            body = [cards._header("📋 All Vulns"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "fix_common_vuln_pg":
        team_key = value.get("team") or "config"
        offset = int(value.get("offset") or 0)
        try:
            body = fix_tab.fix_tab_body(admin, active_sub="fix_sub_common", offset=offset, common_team=team_key)
        except Exception:
            logger.exception("[TeamsBot] fix_common_vuln_pg failed")
            body = [cards._header("🧩 Common Vulns"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "fix_common_vuln_view":
        team_key = value.get("team") or "config"
        idx = value.get("idx")
        idx = int(idx) if idx is not None else None
        back_offset = int(value.get("offset") or 0)
        try:
            body = [cards._fix_subnav_columnset("fix_sub_common")] + fix_tab.common_vuln_detail_body(admin, team_key, idx, back_offset=back_offset)
        except Exception:
            logger.exception("[TeamsBot] fix_common_vuln_view failed")
            body = [cards._header("🧩 Vulnerability"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "fix_common_vuln_back":
        team_key = value.get("team") or "config"
        offset = int(value.get("offset") or 0)
        try:
            body = fix_tab.fix_tab_body(admin, active_sub="fix_sub_common", offset=offset, common_team=team_key)
        except Exception:
            logger.exception("[TeamsBot] fix_common_vuln_back failed")
            body = [cards._header("🧩 Common Vulns"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    # ── Team tab ───────────────────────────────────────────────────────
    if action_id in dict(team_tab.TEAM_SUBTABS):
        try:
            body = team_tab.team_tab_body(admin, team_id, active_sub=action_id)
        except Exception:
            logger.exception(f"[TeamsBot] team_tab_body failed for {action_id}")
            body = [cards._header("👥 Team"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "team_adduser_show_picked":
        picked_email = (value.get("au_pick_member") or "").strip()
        try:
            if picked_email:
                body = [team_tab.team_subnav_columnset("team_sub_adduser")] + team_tab.picked_member_preview_body(admin, picked_email)
            else:
                body = [team_tab.team_subnav_columnset("team_sub_adduser"), cards._header("Pick someone first"), cards._body_text("Select a Teams member from the dropdown, then tap Fetch Details.")]
                body.extend(team_tab.add_user_form_body(admin))
        except Exception:
            logger.exception("[TeamsBot] team_adduser_show_picked failed")
            body = [team_tab.team_subnav_columnset("team_sub_adduser"), cards._header("❌ Something went wrong"), cards._body_text("Please try again.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "team_adduser_pick_assets":
        try:
            body = [team_tab.team_subnav_columnset("team_sub_adduser")] + team_tab.assets_vulns_picker_body(admin, value)
        except Exception:
            logger.exception("[TeamsBot] team_adduser_pick_assets failed")
            body = [team_tab.team_subnav_columnset("team_sub_adduser"), cards._header("❌ Something went wrong"), cards._body_text("Please try again.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "team_adduser_submit":
        try:
            ok, message = team_tab.submit_add_user(admin, value)
            body = [team_tab.team_subnav_columnset("team_sub_adduser")]
            body.append(cards._header("✅ User Added" if ok else "❌ Could not add user"))
            body.append(cards._body_text(message))
            if not ok:
                body.extend(team_tab.add_user_form_body(admin))
        except Exception:
            logger.exception("[TeamsBot] team_adduser_submit failed")
            body = [team_tab.team_subnav_columnset("team_sub_adduser"), cards._header("❌ Something went wrong"), cards._body_text("Please try again.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "team_deleteuser_pg":
        offset = int(value.get("offset") or 0)
        try:
            body = team_tab.team_tab_body(admin, team_id, active_sub="team_sub_deleteuser", offset=offset)
        except Exception:
            logger.exception("[TeamsBot] team_deleteuser_pg failed")
            body = [cards._header("🗑️ Delete User"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "team_deleteuser_view":
        detail_id = value.get("detail_id") or ""
        offset = int(value.get("offset") or 0)
        try:
            body = [team_tab.team_subnav_columnset("team_sub_deleteuser")] + team_tab.delete_user_confirm_body(admin, detail_id, offset=offset)
        except Exception:
            logger.exception("[TeamsBot] team_deleteuser_view failed")
            body = [cards._header("🗑️ Delete User"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "team_deleteuser_back":
        offset = int(value.get("offset") or 0)
        try:
            body = team_tab.team_tab_body(admin, team_id, active_sub="team_sub_deleteuser", offset=offset)
        except Exception:
            logger.exception("[TeamsBot] team_deleteuser_back failed")
            body = [cards._header("🗑️ Delete User"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id in ("team_deleteuser_deactivate_confirm", "team_deleteuser_delete_confirm"):
        detail_id = value.get("detail_id") or ""
        offset = int(value.get("offset") or 0)
        try:
            content = (
                team_tab.deactivate_confirm_body(detail_id, offset) if action_id == "team_deleteuser_deactivate_confirm"
                else team_tab.delete_confirm_body(detail_id, offset)
            )
            body = [team_tab.team_subnav_columnset("team_sub_deleteuser")] + content
        except Exception:
            logger.exception(f"[TeamsBot] {action_id} failed")
            body = [cards._header("🗑️ Delete User"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id in ("team_deleteuser_deactivate_do", "team_deleteuser_delete_do"):
        detail_id = value.get("detail_id") or ""
        offset = int(value.get("offset") or 0)
        try:
            ok, message = (
                team_tab.do_deactivate_user(admin, detail_id) if action_id == "team_deleteuser_deactivate_do"
                else team_tab.do_delete_user(admin, detail_id)
            )
            body = [team_tab.team_subnav_columnset("team_sub_deleteuser"), cards._header("✅ Done" if ok else "❌ Failed"), cards._body_text(message)]
        except Exception:
            logger.exception(f"[TeamsBot] {action_id} failed")
            body = [team_tab.team_subnav_columnset("team_sub_deleteuser"), cards._header("❌ Something went wrong"), cards._body_text("Please try again.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "team_role_pg":
        offset = int(value.get("offset") or 0)
        try:
            body = team_tab.team_tab_body(admin, team_id, active_sub="team_sub_deleteteamuser", offset=offset)
        except Exception:
            logger.exception("[TeamsBot] team_role_pg failed")
            body = [cards._header("🔄 Update User Role"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "team_role_view":
        detail_id = value.get("detail_id") or ""
        offset = int(value.get("offset") or 0)
        try:
            body = [team_tab.team_subnav_columnset("team_sub_deleteteamuser")] + team_tab.update_role_detail_body(admin, detail_id, offset=offset)
        except Exception:
            logger.exception("[TeamsBot] team_role_view failed")
            body = [cards._header("🔄 Update User Role"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "team_role_back":
        offset = int(value.get("offset") or 0)
        try:
            body = team_tab.team_tab_body(admin, team_id, active_sub="team_sub_deleteteamuser", offset=offset)
        except Exception:
            logger.exception("[TeamsBot] team_role_back failed")
            body = [cards._header("🔄 Update User Role"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "team_role_remove_confirm":
        detail_id = value.get("detail_id") or ""
        role = value.get("role") or ""
        offset = int(value.get("offset") or 0)
        try:
            body = [team_tab.team_subnav_columnset("team_sub_deleteteamuser")] + team_tab.role_remove_confirm_body(detail_id, role, offset)
        except Exception:
            logger.exception("[TeamsBot] team_role_remove_confirm failed")
            body = [cards._header("🔄 Update User Role"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "team_role_remove_do":
        detail_id = value.get("detail_id") or ""
        role = value.get("role") or ""
        offset = int(value.get("offset") or 0)
        try:
            ok, message = team_tab.do_remove_role(admin, detail_id, role)
            body = [team_tab.team_subnav_columnset("team_sub_deleteteamuser"), cards._header("✅ Done" if ok else "❌ Failed"), cards._body_text(message)]
        except Exception:
            logger.exception("[TeamsBot] team_role_remove_do failed")
            body = [team_tab.team_subnav_columnset("team_sub_deleteteamuser"), cards._header("❌ Something went wrong"), cards._body_text("Please try again.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "team_ext_pg":
        offset = int(value.get("offset") or 0)
        try:
            body = team_tab.team_tab_body(admin, team_id, active_sub="team_sub_externaluser", offset=offset)
        except Exception:
            logger.exception("[TeamsBot] team_ext_pg failed")
            body = [cards._header("🌐 External User"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    # ── Timeline Ext. tab ──────────────────────────────────────────────
    if action_id in dict(timeline_tab.REQUEST_SUBTABS):
        try:
            body = timeline_tab.timeline_tab_body(admin, active_sub=action_id)
        except Exception:
            logger.exception(f"[TeamsBot] timeline_tab_body failed for {action_id}")
            body = [cards._header("📨 Timeline Ext."), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_request", extra_body=body)

    if action_id == "ext_list_pg":
        offset = int(value.get("offset") or 0)
        try:
            body = timeline_tab.timeline_tab_body(admin, active_sub="req_sub_extensions", offset=offset)
        except Exception:
            logger.exception("[TeamsBot] ext_list_pg failed")
            body = [cards._header("📨 Timeline Ext."), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_request", extra_body=body)

    if action_id == "hist_toggle":
        view = value.get("view") or "approve"
        try:
            body = timeline_tab.timeline_tab_body(admin, active_sub="req_sub_history", view=view, offset=0)
        except Exception:
            logger.exception("[TeamsBot] hist_toggle failed")
            body = [cards._header("🕘 History"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_request", extra_body=body)

    if action_id == "hist_list_pg":
        view = value.get("view") or "approve"
        offset = int(value.get("offset") or 0)
        try:
            body = timeline_tab.timeline_tab_body(admin, active_sub="req_sub_history", view=view, offset=offset)
        except Exception:
            logger.exception("[TeamsBot] hist_list_pg failed")
            body = [cards._header("🕘 History"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_request", extra_body=body)

    if action_id == "hist_view":
        request_id = value.get("request_id") or ""
        view = value.get("view") or "approve"
        offset = int(value.get("offset") or 0)
        try:
            body = timeline_tab.history_detail_body(admin, request_id, view=view, back_offset=offset)
        except Exception:
            logger.exception("[TeamsBot] hist_view failed")
            body = [cards._header("🕘 Request"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_request", extra_body=body)

    if action_id == "hist_back":
        view = value.get("view") or "approve"
        offset = int(value.get("offset") or 0)
        try:
            body = timeline_tab.timeline_tab_body(admin, active_sub="req_sub_history", view=view, offset=offset)
        except Exception:
            logger.exception("[TeamsBot] hist_back failed")
            body = [cards._header("🕘 History"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_request", extra_body=body)

    if action_id in ("ext_approve_do", "ext_reject_start", "ext_reject_cancel", "ext_reject_do"):
        request_id = value.get("request_id") or ""
        offset = int(value.get("offset") or 0)
        src = value.get("src") or "ext"
        view = value.get("view") or "approve"
        active_sub = "req_sub_history" if src == "hist" else "req_sub_extensions"

        def _back_to_list():
            if src == "hist":
                return timeline_tab.timeline_tab_body(admin, active_sub="req_sub_history", view=view, offset=offset)
            return timeline_tab.timeline_tab_body(admin, active_sub="req_sub_extensions", offset=offset)

        try:
            # _back_to_list() (== timeline_tab_body) already starts its own
            # body with request_subnav_columnset — prepending it again here
            # on top of that produced the real bug reported: the pill row
            # rendered TWICE the instant Approve/Reject succeeded. Only the
            # branches that DON'T route through _back_to_list() (a failure
            # message, or reject_reason_body, neither of which include
            # their own subnav) still need the explicit prepend.
            if action_id == "ext_approve_do":
                ok, message = timeline_tab.do_approve(admin, request_id)
                if not ok:
                    body = [timeline_tab.request_subnav_columnset(active_sub), cards._header("❌ Failed"), cards._body_text(message)]
                else:
                    body = _back_to_list()
            elif action_id == "ext_reject_start":
                body = [timeline_tab.request_subnav_columnset(active_sub)] + timeline_tab.reject_reason_body(request_id, offset, src, view=view)
            elif action_id == "ext_reject_cancel":
                body = _back_to_list()
            else:  # ext_reject_do
                reason = (value.get("reject_reason") or "").strip()
                ok, message = timeline_tab.do_reject(admin, request_id, reason=reason)
                if not ok:
                    body = [timeline_tab.request_subnav_columnset(active_sub), cards._header("❌ Failed"), cards._body_text(message)]
                else:
                    body = _back_to_list()
        except Exception:
            logger.exception(f"[TeamsBot] {action_id} failed")
            body = [timeline_tab.request_subnav_columnset(active_sub), cards._header("❌ Something went wrong"), cards._body_text("Please try again.")]
        return cards.nav_buttons_card(active_action_id="nav_request", extra_body=body)

    # ── Reminder tab ───────────────────────────────────────────────────
    if action_id in dict(reminder_tab.REMINDER_SUBTABS):
        try:
            body = reminder_tab.reminder_tab_body(admin, active_sub=action_id)
        except Exception:
            logger.exception(f"[TeamsBot] reminder_tab_body failed for {action_id}")
            body = [cards._header("🔔 Reminder"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_notification", extra_body=body)

    if action_id == "remind_bucket_pg":
        bucket = value.get("bucket") or "overdue"
        active_sub = {v: k for k, v in reminder_tab._SUB_TO_BUCKET.items()}.get(bucket, "notif_sub_overdue")
        offset = int(value.get("offset") or 0)
        try:
            body = reminder_tab.reminder_tab_body(admin, active_sub=active_sub, offset=offset)
        except Exception:
            logger.exception("[TeamsBot] remind_bucket_pg failed")
            body = [cards._header("🔔 Reminder"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_notification", extra_body=body)

    if action_id == "remind_sup_filter":
        st = value.get("st") or "all"
        team = value.get("team") or "all"
        try:
            body = reminder_tab.reminder_tab_body(admin, active_sub="notif_sub_support", st=st, team=team, offset=0)
        except Exception:
            logger.exception("[TeamsBot] remind_sup_filter failed")
            body = [cards._header("🎫 Support"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_notification", extra_body=body)

    if action_id == "remind_sup_pg":
        st = value.get("st") or "all"
        team = value.get("team") or "all"
        offset = int(value.get("offset") or 0)
        try:
            body = reminder_tab.reminder_tab_body(admin, active_sub="notif_sub_support", st=st, team=team, offset=offset)
        except Exception:
            logger.exception("[TeamsBot] remind_sup_pg failed")
            body = [cards._header("🎫 Support"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_notification", extra_body=body)

    if action_id == "remind_sup_view":
        idx = value.get("idx")
        idx = int(idx) if idx is not None else None
        st = value.get("st") or "all"
        team = value.get("team") or "all"
        offset = int(value.get("offset") or 0)
        try:
            body = reminder_tab.support_detail_body(admin, idx, st=st, team=team, back_offset=offset)
        except Exception:
            logger.exception("[TeamsBot] remind_sup_view failed")
            body = [cards._header("🎫 Support Request"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_notification", extra_body=body)

    if action_id == "remind_sup_back":
        st = value.get("st") or "all"
        team = value.get("team") or "all"
        offset = int(value.get("offset") or 0)
        try:
            body = reminder_tab.reminder_tab_body(admin, active_sub="notif_sub_support", st=st, team=team, offset=offset)
        except Exception:
            logger.exception("[TeamsBot] remind_sup_back failed")
            body = [cards._header("🎫 Support"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_notification", extra_body=body)

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
        body = cards.freemium_upgrade_banner_items(admin, team_id) + body
        return cards.nav_buttons_card(active_action_id="nav_home", extra_body=body)

    if action_id == "nav_team":
        try:
            body = team_tab.team_tab_body(admin, team_id, active_sub="team_sub_team")
        except Exception:
            logger.exception("[TeamsBot] team_tab_body (default) failed")
            body = [cards._header("👥 Team"), cards._body_text("Could not load team performance right now.")]
        return cards.nav_buttons_card(active_action_id="nav_team", extra_body=body)

    if action_id == "nav_fix":
        try:
            body = fix_tab.fix_tab_body(admin, active_sub="fix_sub_assets")
        except Exception:
            logger.exception("[TeamsBot] fix_tab_body (default) failed")
            body = [cards._header("🔧 Fix"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_fix", extra_body=body)

    if action_id == "nav_register":
        try:
            body = register_tab.register_tab_body(admin, active_sub="reg_sub_register")
        except Exception:
            logger.exception("[TeamsBot] register_tab_body (default) failed")
            body = [cards._header("📋 Register"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_register", extra_body=body)

    if action_id == "nav_automation":
        try:
            body = automations_tab.automations_tab_body(admin, active_sub="auto_sub_full")
        except Exception:
            logger.exception("[TeamsBot] automations_tab_body (default) failed")
            body = [cards._header("🤖 Automations"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_automation", extra_body=body)

    if action_id == "nav_request":
        try:
            body = timeline_tab.timeline_tab_body(admin, active_sub="req_sub_extensions")
        except Exception:
            logger.exception("[TeamsBot] timeline_tab_body (default) failed")
            body = [cards._header("📨 Timeline Ext."), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_request", extra_body=body)

    if action_id == "nav_notification":
        try:
            body = reminder_tab.reminder_tab_body(admin, active_sub="notif_sub_overdue")
        except Exception:
            logger.exception("[TeamsBot] reminder_tab_body (default) failed")
            body = [cards._header("🔔 Reminder"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_notification", extra_body=body)

    if action_id == "nav_download":
        try:
            body = download_tab.download_report_body(admin, team_id)
        except Exception:
            logger.exception("[TeamsBot] download_report_body failed")
            body = [cards._header("📥 Download Report"), cards._body_text("Could not load this right now.")]
        return cards.nav_buttons_card(active_action_id="nav_download", extra_body=body)

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
