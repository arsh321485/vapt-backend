"""
User-side ("regular team member") persistent nav bar + Home tab.

Mirrors users.views.SlackSlashCommandView's team-channel side exactly —
same 7 tabs, same order, same sub-tab structure (see _TEAM_NAV_ITEMS /
_TEAM_FIX_SUBTABS / _TEAM_REG_SUBTABS / _TEAM_EXTEND_SUBTABS /
_TEAM_REMINDER_SUBTABS) — just rendered as native Adaptive Cards instead
of Slack Block Kit, and reusing the SAME /api/user/... backend endpoints
Slack's own team side already calls (_get_team_vulns's docstring: "via the
same member-facing API their own dashboard uses"). action_id spelling is
prefixed "u..." (unav_/ufix_sub_/ureg_sub_/uex_sub_/urem_sub_) so nothing
here can ever collide with the admin-side dispatch in actions.py.
"""
import logging

from . import cards

logger = logging.getLogger(__name__)

UNAV_ITEMS = [
    ("unav_home",     "🏠 Home"),
    ("unav_fix",      "🔧 Fix"),
    ("unav_register", "📋 Register"),
    ("unav_extend",   "📨 Timeline Ext."),
    ("unav_support",  "🎫 Support Status"),
    ("unav_fixed",    "✅ Fixed"),
    ("unav_reminder", "🔔 Reminder"),
]
UFIX_SUBTABS = [
    ("ufix_sub_assets", "🖥 All Assets"),
    ("ufix_sub_vulns",  "📋 All Vulns"),
    ("ufix_sub_common", "🧩 Common Vulns"),
]
UREG_SUBTABS = [
    ("ureg_sub_register", "📋 Register"),
    ("ureg_sub_scripts",  "📜 Scripts"),
]
UEXTEND_SUBTABS = [
    ("uex_sub_list", "📋 Extension Requests"),
    ("uex_sub_new",  "⏳ Request Extension"),
]
UREMINDER_SUBTABS = [
    ("urem_sub_overdue",  "🔴 Overdue"),
    ("urem_sub_today",    "🟠 Due Today"),
    ("urem_sub_thisweek", "🟡 This Week"),
    ("urem_sub_nextweek", "🟢 Next Week"),
]


def nav_buttons_card(team_name, active_action_id="unav_home", extra_body=None):
    """
    The persistent user-side nav bar, same construction as
    cards.nav_buttons_card (admin side) — a click always re-derives
    team_name from which channel the click happened in (see
    member_resolve.resolve_member_context), so button values only ever
    need to carry the action_id (+ any sub-tab filters/offset), never the
    team itself.
    """
    body = [
        {"type": "TextBlock", "text": f"👥 {team_name}", "weight": "Bolder", "size": "Small", "isSubtle": True, "spacing": "None", "wrap": True},
        # split=3 (not the even half) puts Support Status right after
        # Timeline Ext. in the SAME row — real feedback that the previous
        # split=4 wrapped Support Status to the start of row 2, reading as
        # unrelated to Timeline Ext. instead of "the next tab over."
        cards.two_row_pill_columnset(UNAV_ITEMS, active_action_id, lambda action_id: {"action_id": action_id}, split=3),
    ]
    body.extend(extra_body or [])
    return cards._card(body=body)


def home_tab_body(team_id, team_name):
    """
    Real Home content for `team_name` — a rendered PNG (same real
    bento-grid design as the reference userdashboard.html mockup, and the
    same one the admin's own Home tab already uses), not a native-card
    approximation. Reuses cards.dashboard_image_card_body with
    kind="userdash", the exact mechanism Slack's own team Home tab already
    uses (see users.views.SlackSlashCommandView's dashboard-image view,
    kind == "userdash" branch) — teams_bot.views.TeamsDashboardImageView's
    own "userdash" branch resolves a representative member of `team_name`
    server-side and calls the same /api/user/dashboard/summary/ endpoint
    the native-card version used, so the data is identical, only the
    rendering differs.
    """
    return cards.dashboard_image_card_body(
        team_id, kind="userdash", title=f"{team_name} Dashboard", extra_params={"team": team_name},
    )
