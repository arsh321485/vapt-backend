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

logger = logging.getLogger(__name__)

# Tabs not yet built — shown as a real (not broken) card so the nav bar is
# fully clickable from day one, same incremental approach the admin-side
# build used (each tab wired up and verified one at a time).
_COMING_SOON = {
    "unav_fix":      "Fix",
    "unav_register": "Register",
    "unav_extend":   "Timeline Extension",
    "unav_support":  "Support Status",
    "unav_fixed":    "Fixed",
    "unav_reminder": "Reminder",
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
        body = [
            {"type": "TextBlock", "text": f"👥 {team_name}", "weight": "Bolder", "size": "Small", "isSubtle": True, "spacing": "None", "wrap": True},
            cards.two_row_pill_columnset(home.UNAV_ITEMS, action_id, lambda a: {"action_id": a}, split=4),
            cards._section_title(f"🚧 {label}"),
            cards._body_text(f"{label} is coming very soon here — for now it's available on Slack for your team."),
        ]
        return cards._card(body=body)

    # unav_home (default)
    try:
        home_body = home.home_tab_body(member_user, team_name)
    except Exception:
        logger.exception("[TeamsBot] home.home_tab_body failed for team=%s", team_name)
        home_body = [cards._body_text("❌ Couldn't load your dashboard right now — please try again.")]
    return home.nav_buttons_card(team_name, active_action_id="unav_home", extra_body=home_body)
