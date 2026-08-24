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
        cards.two_row_pill_columnset(UNAV_ITEMS, active_action_id, lambda action_id: {"action_id": action_id}, split=4),
    ]
    body.extend(extra_body or [])
    return cards._card(body=body)


def home_tab_body(member_user, team_name):
    """
    Real Home content for `team_name`, scoped to `member_user`'s own
    admin/report — calls the exact same summary endpoint the website's own
    user dashboard uses (userdashboard.UserDashboardSummaryAPIView),
    server-side-filtered to `team_name` (falls back to the member's full
    team list if `team_name` somehow isn't one of theirs — see that view's
    own `active_teams` guard — member_resolve already checked this too,
    ahead of ever calling in here, so that fallback shouldn't trigger in
    practice). Reuses cards.home_dashboard_card_body verbatim — it's
    already generic over "whatever this summary dict says", admin-scoped
    or team-scoped alike.
    """
    from userdashboard.views import UserDashboardSummaryAPIView
    from .actions import _call_view_in_process

    try:
        status_code, data = _call_view_in_process(
            UserDashboardSummaryAPIView, member_user, method="get", data={"team": team_name},
        )
    except Exception:
        logger.exception("[TeamsBot] UserDashboardSummaryAPIView call failed")
        return [{"type": "TextBlock", "text": "❌ Couldn't load your dashboard right now — please try again.", "wrap": True}]

    if status_code >= 400:
        return [{"type": "TextBlock", "text": "❌ Couldn't load your dashboard right now — please try again.", "wrap": True}]

    body = cards.home_dashboard_card_body(data or {})
    # Swap the generic admin-facing header/blurb for a team-scoped one —
    # home_dashboard_card_body's first two elements are always _header +
    # _body_text (see cards.py), safe to replace by position.
    body[0] = cards._header(f"🏠 {team_name} Dashboard")
    body[1] = cards._body_text(f"Your team's summary — assets, vulnerabilities, mitigation timeline and support tickets for {team_name}.")
    return body
