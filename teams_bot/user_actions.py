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

logger = logging.getLogger(__name__)

# Tabs not yet built — shown as a real (not broken) card so the nav bar is
# fully clickable from day one, same incremental approach the admin-side
# build used (each tab wired up and verified one at a time).
_COMING_SOON = {
    "unav_register": "Register",
    "unav_extend":   "Timeline Extension",
    "unav_support":  "Support Status",
    "unav_fixed":    "Fixed",
    "unav_reminder": "Reminder",
}

# action_id -> which top nav tab it belongs under, so a Fix sub-tab/
# pagination/drill-down click still renders with "Fix" highlighted in the
# persistent nav bar, not silently falling back to Home.
_FIX_ACTION_IDS = {
    "unav_fix", "ufix_sub_assets", "ufix_sub_vulns",
    "ufix_asset_pg", "ufix_vuln_pg", "ufix_asset_view", "ufix_asset_back", "ufix_asset_vuln_view", "ufix_vuln_view",
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
        return cards.text_result_card("🔒 Not available", ctx["error"])

    team_name = ctx["team_name"]
    member_user = ctx["member_user"]
    action_id = (value or {}).get("action_id") or "unav_home"

    if action_id in _COMING_SOON:
        label = _COMING_SOON[action_id]
        extra_body = [
            cards._section_title(f"🚧 {label}"),
            cards._body_text(f"{label} is coming very soon here — for now it's available on Slack for your team."),
        ]
        return home.nav_buttons_card(team_name, active_action_id=action_id, extra_body=extra_body)

    if action_id in _FIX_ACTION_IDS:
        try:
            fix_body = _render_fix(member_user, team_name, action_id, value or {})
        except Exception:
            logger.exception("[TeamsBot] user_fix_tab render failed for team=%s action_id=%s", team_name, action_id)
            fix_body = [cards._body_text("❌ Couldn't load Fix right now — please try again.")]
        return home.nav_buttons_card(team_name, active_action_id="unav_fix", extra_body=fix_body)

    # unav_home (default)
    try:
        home_body = home.home_tab_body(team_id, team_name)
    except Exception:
        logger.exception("[TeamsBot] home.home_tab_body failed for team=%s", team_name)
        home_body = [cards._body_text("❌ Couldn't load your dashboard right now — please try again.")]
    return home.nav_buttons_card(team_name, active_action_id="unav_home", extra_body=home_body)


def _render_fix(member_user, team_name, action_id, value):
    """Routes every Fix-related action_id (top-level tab, sub-tab switch,
    pagination, asset drill-down, vuln detail, back) to the right
    user_fix_tab body — mirrors admin actions.py's own fix-tab dispatch
    shape, just against the team-scoped data source."""
    offset = int(value.get("offset") or 0)

    if action_id == "ufix_sub_vulns":
        return fix.fix_tab_body(member_user, team_name, sub_action_id="ufix_sub_vulns")
    if action_id == "ufix_vuln_pg":
        return fix.fix_tab_body(member_user, team_name, sub_action_id="ufix_sub_vulns", offset=offset)
    if action_id == "ufix_asset_pg":
        return fix.fix_tab_body(member_user, team_name, sub_action_id="ufix_sub_assets", offset=offset)
    if action_id == "ufix_asset_view":
        return fix.asset_detail_body(member_user, team_name, value.get("host"), back_offset=offset)
    if action_id == "ufix_asset_back":
        return fix.fix_tab_body(member_user, team_name, sub_action_id="ufix_sub_assets", offset=offset)
    if action_id == "ufix_asset_vuln_view":
        host = value.get("host")
        return fix.vuln_detail_body(
            member_user, team_name, value.get("idx"),
            "ufix_asset_view", {"host": host, "offset": offset},
        )
    if action_id == "ufix_vuln_view":
        return fix.vuln_detail_body(
            member_user, team_name, value.get("idx"),
            "ufix_vuln_pg", {"offset": offset},
        )
    # unav_fix (default) / ufix_sub_assets
    return fix.fix_tab_body(member_user, team_name, sub_action_id="ufix_sub_assets")
