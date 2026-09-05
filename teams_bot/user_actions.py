"""
Dispatch entry point for regular-team-member ("user side") activities —
the member-context counterpart to actions.handle_card_action (admin side).
Kept as a fully separate module/function so admin dispatch is untouched;
teams_bot.views routes here only after member_resolve.is_member_sender
confirms the sender is a genuine team member, not the admin.
"""
import logging

from . import cards
from . import member_resolve
from . import user_home_tab as home
from . import user_fix_tab as fix
from . import user_register_tab as register
from . import user_support_tab as support
from . import user_fixed_tab as fixed
from . import user_reminder_tab as reminder
from . import user_extend_tab as extend

logger = logging.getLogger(__name__)

# action_id -> top nav tab it renders under (drives which nav pill is
# highlighted + which sub-nav row, if any, sits under it).
_FIX_ACTION_IDS = {
    "unav_fix", "ufix_sub_assets", "ufix_sub_vulns", "ufix_sub_common",
    "ufix_asset_pg", "ufix_vuln_pg", "ufix_common_vuln_pg",
    "ufix_asset_sev", "ufix_asset_st", "ufix_vuln_sev", "ufix_vuln_st",
    "ufix_common_vuln_sev", "ufix_common_vuln_st",
    "ufix_asset_view", "ufix_asset_back",
    "ufix_asset_vuln_view", "ufix_asset_vuln_back",
    "ufix_vuln_view", "ufix_vuln_back",
    "ufix_common_vuln_view", "ufix_common_vuln_back",
}
_REGISTER_ACTION_IDS = {
    "unav_register", "ureg_sub_register", "ureg_sub_scripts",
    "ureg_sev", "ureg_st", "ureg_view", "ureg_view_pg", "ureg_view_back", "ureg_script_pg",
}
_SUPPORT_ACTION_IDS = {"unav_support", "usup_pg", "usup_view", "usup_raise_form", "usup_submit", "usup_back"}
_FIXED_ACTION_IDS = {"unav_fixed", "ufixed_pg", "ufixed_view", "ufixed_step_nav", "ufixed_back"}
_REMINDER_ACTION_IDS = {"unav_reminder", "urem_sub_overdue", "urem_sub_today", "urem_sub_thisweek", "urem_sub_nextweek", "urem_pg"}
_EXTEND_ACTION_IDS = {
    "unav_extend", "uex_sub_list", "uex_sub_new", "uex_pg", "uex_new_submit", "uex_view", "uex_view_back",
    "uex_new_pick_asset", "uex_new_back_to_asset", "uex_new_pick_vuln",
}
# Reached from a vuln's own detail page regardless of whether it was
# opened via Fix or Register — ctx (embedded in the click's own value)
# says which, so the response re-highlights the right tab.
_VULN_DETAIL_ACTION_IDS = {
    "ufix_vuln_toggle", "ufix_mark_mitigated", "ufix_retest",
    "ufix_step_nav", "ufix_step_complete", "usup_step_form", "usup_step_submit",
}


def handle_user_activity(activity: dict, admin, team_id: str, value: dict):
    """
    `value`: the click payload (Action.Execute/Action.Submit `data`), or
    `{}` for a plain typed message / fresh @mention (-> defaults to Home,
    same convention as the admin side's post_onboarding_step-on-@mention).
    Returns a ready-to-post/update Adaptive Card dict.
    """
    ctx = member_resolve.resolve_member_context(activity, admin, team_id)
    if ctx["error"]:
        # Real bug report: this card (e.g. "Only the admin can access this
        # channel" when a member clicks inside the admin-dashboard channel,
        # or "You're not part of the X team" in someone else's team
        # channel) was returned as a normal response — which the caller
        # then used to EDIT the shared channel card in place, showing this
        # personal, per-clicker message to everyone in that channel,
        # including the admin. Every ctx["error"] case here is specific to
        # THIS clicker, never something the rest of the channel should see
        # — flag it the same way the admin-side mirror bug was fixed, so
        # views.py routes it to a private 1:1 reply instead and leaves the
        # shared card alone.
        card = cards.access_blocked_card(ctx["error"])
        card["_is_access_blocked"] = True
        return card

    team_name = ctx["team_name"]
    member_user = ctx["member_user"]
    member_detail = ctx["member_detail"]
    value = value or {}
    action_id = value.get("action_id") or "unav_home"

    try:
        if action_id in _FIX_ACTION_IDS:
            body = _render_fix(member_user, admin, team_id, team_name, action_id, value)
            return home.nav_buttons_card(team_name, active_action_id="unav_fix", extra_body=body)

        if action_id in _REGISTER_ACTION_IDS:
            body = _render_register(member_user, team_id, team_name, action_id, value)
            return home.nav_buttons_card(team_name, active_action_id="unav_register", extra_body=body)

        if action_id in _SUPPORT_ACTION_IDS:
            body = _render_support(admin, member_user, member_detail, team_name, action_id, value)
            return home.nav_buttons_card(team_name, active_action_id="unav_support", extra_body=body)

        if action_id in _FIXED_ACTION_IDS:
            body = _render_fixed(member_user, team_name, action_id, value)
            return home.nav_buttons_card(team_name, active_action_id="unav_fixed", extra_body=body)

        if action_id in _REMINDER_ACTION_IDS:
            sub = action_id if action_id.startswith("urem_sub_") else (value.get("sub") or "urem_sub_overdue")
            offset = _as_int(value.get("offset")) or 0
            body = reminder.reminder_list_body(member_user, team_name, sub_action_id=sub, offset=offset)
            return home.nav_buttons_card(team_name, active_action_id="unav_reminder", extra_body=body)

        if action_id in _EXTEND_ACTION_IDS:
            if action_id == "uex_new_submit":
                idx = _as_int(value.get("idx"))
                selected_asset = value.get("asset")
                deadline_choice = value.get("uex_new_deadline")
                ok, error = extend.submit_new_request(member_user, team_name, selected_asset, idx, deadline_choice, value.get("uex_new_reason"))
                banner = _result_banner(ok, "Your admin has been notified and can review it." if ok else (error or "Could not submit extension request."))
                body = [banner, extend.extend_subnav_columnset("uex_sub_list")] + extend.request_list_body(member_user, team_name)
                return home.nav_buttons_card(team_name, active_action_id="unav_extend", extra_body=body)
            if action_id == "uex_new_pick_asset":
                selected_asset = value.get("uex_new_asset")
                body = extend.extend_tab_body(member_user, team_name, active_sub="uex_sub_new", selected_asset=selected_asset)
                return home.nav_buttons_card(team_name, active_action_id="unav_extend", extra_body=body)
            if action_id == "uex_new_pick_vuln":
                selected_asset = value.get("asset")
                idx = _as_int(value.get("uex_new_idx"))
                body = extend.extend_tab_body(member_user, team_name, active_sub="uex_sub_new", selected_asset=selected_asset, selected_idx=idx)
                return home.nav_buttons_card(team_name, active_action_id="unav_extend", extra_body=body)
            if action_id == "uex_new_back_to_asset":
                body = extend.extend_tab_body(member_user, team_name, active_sub="uex_sub_new", selected_asset=None)
                return home.nav_buttons_card(team_name, active_action_id="unav_extend", extra_body=body)
            if action_id == "uex_view":
                offset = _as_int(value.get("offset")) or 0
                body = extend.request_detail_body(member_user, team_name, _as_int(value.get("idx")), back_offset=offset)
                return home.nav_buttons_card(team_name, active_action_id="unav_extend", extra_body=body)
            if action_id == "uex_view_back":
                offset = _as_int(value.get("offset")) or 0
                body = [extend.extend_subnav_columnset("uex_sub_list")] + extend.request_list_body(member_user, team_name, offset=offset)
                return home.nav_buttons_card(team_name, active_action_id="unav_extend", extra_body=body)
            active_sub = action_id if action_id in ("uex_sub_list", "uex_sub_new") else "uex_sub_list"
            offset = _as_int(value.get("offset")) or 0
            body = extend.extend_tab_body(member_user, team_name, active_sub=active_sub, offset=offset)
            return home.nav_buttons_card(team_name, active_action_id="unav_extend", extra_body=body)

        if action_id in _VULN_DETAIL_ACTION_IDS:
            active_tab = "unav_register" if (value.get("ctx") == "register") else "unav_fix"
            body = _render_vuln_detail_action(member_user, admin, team_id, team_name, action_id, value)
            return home.nav_buttons_card(team_name, active_action_id=active_tab, extra_body=body)
    except Exception:
        logger.exception("[TeamsBot] user_actions render failed for team=%s action_id=%s", team_name, action_id)
        return home.nav_buttons_card(team_name, active_action_id="unav_home", extra_body=[cards._body_text("❌ Something went wrong — please try again.")])

    # unav_home (default)
    try:
        home_body = home.home_tab_body(team_id, team_name)
    except Exception:
        logger.exception("[TeamsBot] home.home_tab_body failed for team=%s", team_name)
        home_body = [cards._body_text("❌ Couldn't load your dashboard right now — please try again.")]
    return home.nav_buttons_card(team_name, active_action_id="unav_home", extra_body=home_body)


# ── Fix ──────────────────────────────────────────────────────────────────

def _render_fix(member_user, admin, team_id, team_name, action_id, value):
    offset = _as_int(value.get("offset")) or 0
    sev = value.get("sev") or "all"
    st = value.get("st") or "all"

    if action_id == "ufix_sub_vulns":
        return fix.fix_tab_body(member_user, admin, team_name, sub_action_id="ufix_sub_vulns")
    if action_id == "ufix_sub_common":
        return fix.fix_tab_body(member_user, admin, team_name, sub_action_id="ufix_sub_common")
    if action_id in ("ufix_vuln_pg", "ufix_vuln_sev", "ufix_vuln_st"):
        return fix.fix_tab_body(member_user, admin, team_name, sub_action_id="ufix_sub_vulns", offset=offset, sev=sev, st=st)
    if action_id in ("ufix_asset_pg", "ufix_asset_sev", "ufix_asset_st"):
        return fix.fix_tab_body(member_user, admin, team_name, sub_action_id="ufix_sub_assets", offset=offset, sev=sev, st=st)
    if action_id in ("ufix_common_vuln_pg", "ufix_common_vuln_sev", "ufix_common_vuln_st"):
        return [fix._fix_subnav_columnset("ufix_sub_common")] + fix._common_vulns_for_team(admin, team_name, sev=sev, st=st, offset=offset)

    if action_id == "ufix_asset_view":
        return fix.asset_detail_body(member_user, team_name, value.get("host"), back_offset=offset)
    if action_id == "ufix_asset_back":
        return fix.fix_tab_body(member_user, admin, team_name, sub_action_id="ufix_sub_assets", offset=offset)
    if action_id == "ufix_asset_vuln_back":
        return fix.asset_detail_body(member_user, team_name, value.get("host"), back_offset=offset)
    if action_id == "ufix_vuln_back":
        return fix.fix_tab_body(member_user, admin, team_name, sub_action_id="ufix_sub_vulns", offset=offset)

    if action_id == "ufix_asset_vuln_view":
        return fix.vuln_detail_body(member_user, team_id, team_name, _as_int(value.get("idx")), ctx="asset", host=value.get("host"), offset=offset, admin=admin)
    if action_id == "ufix_vuln_view":
        return fix.vuln_detail_body(member_user, team_id, team_name, _as_int(value.get("idx")), ctx="vulns", offset=offset, admin=admin)

    if action_id == "ufix_common_vuln_view":
        return [fix._fix_subnav_columnset("ufix_sub_common")] + fix.common_vuln_detail_for_team(admin, team_name, _as_int(value.get("idx")), back_offset=offset)
    if action_id == "ufix_common_vuln_back":
        return fix.fix_tab_body(member_user, admin, team_name, sub_action_id="ufix_sub_common", offset=offset)

    # unav_fix (default) / ufix_sub_assets
    return fix.fix_tab_body(member_user, admin, team_name, sub_action_id="ufix_sub_assets")


# ── Register ─────────────────────────────────────────────────────────────

def _render_register(member_user, team_id, team_name, action_id, value):
    offset = _as_int(value.get("offset")) or 0
    sev = value.get("sev") or "all"
    st = value.get("st") or "all"

    if action_id == "ureg_sub_scripts":
        return register.register_tab_body(member_user, team_id, team_name, active_sub="ureg_sub_scripts")
    if action_id in ("ureg_sev", "ureg_st"):
        return register.register_tab_body(member_user, team_id, team_name, active_sub="ureg_sub_register", sev=sev, st=st, offset=0)
    if action_id == "ureg_view_pg":
        return register.register_tab_body(member_user, team_id, team_name, active_sub="ureg_sub_register", sev=sev, st=st, offset=offset)
    if action_id == "ureg_script_pg":
        return register.register_tab_body(member_user, team_id, team_name, active_sub="ureg_sub_scripts", offset=offset)
    if action_id == "ureg_view":
        return [register.register_subnav_columnset("ureg_sub_register")] + register.register_vuln_detail_body(
            member_user, team_id, team_name, _as_int(value.get("idx")), sev=sev, st=st, offset=offset,
        )
    if action_id == "ureg_view_back":
        return register.register_tab_body(member_user, team_id, team_name, active_sub="ureg_sub_register", sev=sev, st=st, offset=offset)

    # unav_register (default) / ureg_sub_register
    return register.register_tab_body(member_user, team_id, team_name, active_sub="ureg_sub_register")


# ── Support ──────────────────────────────────────────────────────────────

def _render_support(admin, member_user, member_detail, team_name, action_id, value):
    offset = _as_int(value.get("offset")) or 0

    if action_id == "usup_pg":
        return support.list_support_requests(admin, member_user, team_name, offset=offset)
    if action_id == "usup_view":
        return support.view_body(admin, member_user, team_name, _as_int(value.get("idx")), back_offset=offset)
    if action_id == "usup_raise_form":
        return support.raise_form_body()
    if action_id == "usup_submit":
        ok, error = support.raise_support_request(admin, member_user, member_detail, team_name, value.get("usup_message"))
        body = [cards._section_title("✅ Request Raised" if ok else "❌ Could not raise request")]
        body.append(cards._body_text("Your admin has been notified." if ok else (error or "Something went wrong.")))
        body.append({"type": "ActionSet", "spacing": "Medium", "actions": [cards._execute_action("← Back to Support Status", {"action_id": "usup_back"})]})
        return body
    if action_id == "usup_back":
        return support.list_support_requests(admin, member_user, team_name, offset=offset)

    # unav_support (default)
    return support.list_support_requests(admin, member_user, team_name)


# ── Fixed ────────────────────────────────────────────────────────────────

def _render_fixed(member_user, team_name, action_id, value):
    offset = _as_int(value.get("offset")) or 0

    if action_id == "ufixed_pg":
        return fixed.fixed_list_body(member_user, team_name, offset=offset)
    if action_id == "ufixed_view":
        return fixed.fixed_detail_body(member_user, team_name, _as_int(value.get("idx")), back_offset=offset)
    if action_id == "ufixed_step_nav":
        step = _as_int(value.get("step"))
        return fixed.fixed_detail_body(member_user, team_name, _as_int(value.get("idx")), back_offset=offset, step_number=step)
    if action_id == "ufixed_back":
        return fixed.fixed_list_body(member_user, team_name, offset=offset)

    # unav_fixed (default)
    return fixed.fixed_list_body(member_user, team_name)


# ── Shared vuln-detail actions (toggle / mark mitigated / extension) ─────

def _render_vuln_detail_action(member_user, admin, team_id, team_name, action_id, value):
    offset = _as_int(value.get("offset")) or 0
    vctx = value.get("ctx") or "vulns"
    host = value.get("host")
    idx = _as_int(value.get("idx"))

    if action_id == "ufix_vuln_toggle":
        if vctx == "register":
            return [register.register_subnav_columnset("ureg_sub_register")] + register.register_vuln_detail_body(
                member_user, team_id, team_name, idx, sub=value.get("sub") or "manual",
                sev=value.get("sev") or "all", st=value.get("st") or "all", offset=offset,
            )
        return fix.vuln_detail_body(member_user, team_id, team_name, idx, ctx=vctx, host=host, offset=offset, sub=value.get("sub") or "manual", admin=admin)

    data = fix._fetch_team_data(member_user, team_name)
    rows = data.get("rows") or []
    if idx is None or idx < 0 or idx >= len(rows):
        return [cards._body_text("This vulnerability could not be found — the report may have refreshed.")]
    r = rows[idx]

    value_base = {"idx": idx, "ctx": vctx, "offset": offset}
    if vctx == "asset":
        value_base["host"] = host
    if vctx == "register":
        value_base["sev"] = value.get("sev") or "all"
        value_base["st"] = value.get("st") or "all"

    if action_id == "ufix_mark_mitigated":
        ok, error = fix.mark_mitigated(member_user, r, data.get("report_id"))
        banner = _result_banner(ok, f"{r.get('vul_name') or 'This vulnerability'} on {r.get('asset') or '—'} marked mitigated — your admin can verify it in the dashboard." if ok else (error or "Could not update fix status."))
        return [banner] + _render_full_detail(member_user, team_id, team_name, vctx, idx, host, offset, value, sub="manual", admin=admin)

    if action_id in ("ufix_step_nav", "ufix_step_complete"):
        step = _as_int(value.get("step")) or 1
        if action_id == "ufix_step_complete":
            ok, error = fix.complete_step(member_user, r, data.get("report_id"), step)
            if not ok:
                banner = _result_banner(False, error or "Could not update this step.")
                return [banner] + _render_full_detail(member_user, team_id, team_name, vctx, idx, host, offset, value, sub="manual", step_number=step, admin=admin)
            step = step + 1  # auto-advance to the next step after completing this one
        return _render_full_detail(member_user, team_id, team_name, vctx, idx, host, offset, value, sub="manual", step_number=step, admin=admin)

    if action_id == "usup_step_form":
        step = _as_int(value.get("step")) or 1
        return fix.step_support_form_body(step, value_base)

    if action_id == "usup_step_submit":
        step = _as_int(value.get("step")) or 1
        ok, error = fix.submit_step_support_request(member_user, r, data.get("report_id"), step, value.get("usup_step_message"))
        banner = _result_banner(ok, "Your admin has been notified about this step." if ok else (error or "Could not raise support request."))
        return [banner] + _render_full_detail(member_user, team_id, team_name, vctx, idx, host, offset, value, sub="manual", step_number=step, admin=admin)

    if action_id == "ufix_retest":
        ok, error = fix.submit_retest(member_user, r, data.get("report_id"))
        banner = _result_banner(ok, f"{r.get('vul_name') or 'This vulnerability'} on {r.get('asset') or '—'} sent to your admin for verification." if ok else (error or "Could not submit for retest."))
        return [banner] + _render_full_detail(member_user, team_id, team_name, vctx, idx, host, offset, value, sub="manual", admin=admin)

    return [cards._body_text("Nothing to show.")]


def _result_banner(ok, text):
    return {
        "type": "TextBlock", "text": ("✅ " if ok else "❌ ") + text,
        "weight": "Bolder", "size": "Small", "color": "good" if ok else "attention", "wrap": True, "spacing": "Medium",
    }


def _render_full_detail(member_user, team_id, team_name, vctx, idx, host, offset, value, sub="manual", step_number=None, admin=None):
    """Re-renders the SAME vuln's full detail (facts + toggle + steps +
    action buttons) after an action — keeps the member's context on
    screen instead of collapsing it down to a bare result message, and
    naturally reflects any state change (e.g. Mark Mitigated closes the
    vuln, so this then shows the closed-state read-only steps view)."""
    if vctx == "register":
        return [register.register_subnav_columnset("ureg_sub_register")] + register.register_vuln_detail_body(
            member_user, team_id, team_name, idx, sub=sub,
            sev=value.get("sev") or "all", st=value.get("st") or "all", offset=offset, step_number=step_number,
        )
    return fix.vuln_detail_body(member_user, team_id, team_name, idx, ctx=vctx, host=host, offset=offset, sub=sub, step_number=step_number, admin=admin)


def _as_int(v):
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None
