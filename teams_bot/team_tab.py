"""
Team tab — Team Performance (unchanged, real dashboard image), Add User,
Delete User, Update User Role (removes a member from one team — Slack's
own team_sub_deleteteamuser does exactly this despite the "Update Role"
label, see users.views.SlackSlashCommandView's handler for that action_id),
External User. Mirrors _TEAM_SUBTABS / _team_subtab_blocks / _cmd_adduser /
_cmd_deleteuser(_permanent) / _format_externalusers.

Add/Delete/Role-removal are real mutations (creates a real User + UserDetail
and sends real emails; deactivates or permanently deletes a User; removes a
role) — each destructive one goes through an explicit Confirm/Cancel step
first, same as everywhere else hard-to-reverse in this app.
"""
import logging

from . import cards
from . import fix_tab

logger = logging.getLogger(__name__)

PAGE_SIZE = 5

TEAM_SUBTABS = [
    ("team_sub_team", "📈 Team Performance"),
    ("team_sub_adduser", "➕ Add User"),
    ("team_sub_deleteuser", "🗑️ Delete User"),
    ("team_sub_deleteteamuser", "🔄 Update User Role"),
    ("team_sub_externaluser", "🌐 External User"),
]

# code -> full team name, matches SlackSlashCommandView._TEAM_MAP exactly.
TEAM_ROLE_OPTIONS = [
    ("pm", "Patch Management"),
    ("cm", "Configuration Management"),
    ("ns", "Network Security"),
    ("af", "Architectural Flaws"),
]
TEAM_CODE_TO_NAME = dict(TEAM_ROLE_OPTIONS)


def team_subnav_columnset(active_sub):
    return cards.pill_columnset(TEAM_SUBTABS, active_sub, lambda k: {"action_id": k})


# ── shared data fetch ─────────────────────────────────────────────────

def _fetch_members(admin, user_type=None):
    from users_details.views import UserDetailListView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        UserDetailListView, admin, method="get",
        data={"user_type": user_type} if user_type else None,
    )
    if status_code >= 300:
        raise ValueError(f"member list fetch failed: {status_code}")
    if isinstance(data, list):
        return data
    return data.get("results") or []


def _member_name(m):
    name = f"{(m.get('first_name') or '').strip()} {(m.get('last_name') or '').strip()}".strip()
    return name or m.get("email") or "Unknown"


def _member_detail_id(m):
    return str(m.get("_id") or m.get("id") or "")


# ── Add User ───────────────────────────────────────────────────────────

def add_user_form_body():
    # NOTE: deliberately NOT using isRequired/errorMessage on these inputs —
    # confirmed via real testing that Adaptive Cards validates every
    # isRequired input on the CARD as a whole before letting ANY
    # Action.Execute fire, including the top nav bar's own selectAction
    # clicks living in the same card body. With isRequired set here, an
    # admin who opened Add User couldn't click any other tab until they'd
    # filled this form in — required-field checking is done server-side
    # in submit_add_user() instead, which already returns a clear error
    # message without blocking navigation.
    return [
        {"type": "TextBlock", "text": "➕ Add User", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Add a new team member and grant them access to one team. A welcome email with login instructions is sent automatically.", "size": "Small", "isSubtle": True, "wrap": True},
        {"type": "Input.ChoiceSet", "id": "au_type", "label": "User Type", "style": "compact", "value": "external",
         "choices": [{"title": "External", "value": "external"}, {"title": "Internal", "value": "internal"}]},
        {"type": "Input.Text", "id": "au_first", "label": "First Name", "placeholder": "e.g. Ritu"},
        {"type": "Input.Text", "id": "au_last", "label": "Last Name", "placeholder": "optional"},
        {"type": "Input.Text", "id": "au_email", "label": "Email", "style": "Email", "placeholder": "name@example.com"},
        {"type": "Input.ChoiceSet", "id": "au_team", "label": "Team", "style": "compact",
         "placeholder": "Select a team",
         "choices": [{"title": name, "value": code} for code, name in TEAM_ROLE_OPTIONS]},
        {
            "type": "ActionSet", "spacing": "Medium",
            "actions": [cards._execute_action("✅ Add User", {"action_id": "team_adduser_submit"}, style="positive")],
        },
    ]


def submit_add_user(admin, form_data):
    """`form_data` is the Input.* values Teams echoes back alongside our own
    action_id — mirrors users.views.SlackSlashCommandView._cmd_adduser's
    real API call (POST /api/admin/users_details/add-user-detail/), minus
    Slack's own Slack-user-lookup step (this form collects email/name
    directly, the same fields the website's own Add User form takes)."""
    from users_details.views import UserDetailCreateView
    from .actions import _call_view_in_process

    email = (form_data.get("au_email") or "").strip()
    first = (form_data.get("au_first") or "").strip()
    last = (form_data.get("au_last") or "").strip() or first
    user_type = form_data.get("au_type") or "external"
    code = form_data.get("au_team") or ""
    team_name = TEAM_CODE_TO_NAME.get(code)

    if not email or not first or not team_name:
        return False, "Email, First Name and Team are all required."

    status_code, data = _call_view_in_process(
        UserDetailCreateView, admin, method="post", request_format="json",
        data={
            "admin_id": str(admin.id),
            "email": email,
            "first_name": first,
            "last_name": last,
            "user_type": user_type,
            "team_name": team_name,
            "Member_role": [team_name],
        },
    )
    if status_code >= 300:
        err = (data or {}).get("error") or (data or {}).get("detail") or (data or {}).get("email")
        return False, str(err) if err else f"Could not add user (status {status_code})."
    return True, f"{first} ({email}) added to {team_name}. A welcome email has been sent."


# ── Delete User (deactivate / permanently delete) ───────────────────────

def delete_user_list_body(admin, offset=0):
    members = _fetch_members(admin)
    total = len(members)
    page = members[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "🗑️ Delete User", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Deactivate (reversible) or permanently delete a team member.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No team members found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for m in page:
        detail_id = _member_detail_id(m)
        subtitle = f"{m.get('email') or '—'}   ·   {', '.join(m.get('Member_role') or []) or '—'}"
        body.append(fix_tab._row(
            _member_name(m), subtitle, "team_deleteuser_view",
            {"detail_id": detail_id, "offset": offset},
        ))
    body.extend(fix_tab._pagination_body(offset, total, "team_deleteuser_pg"))
    return body


def delete_user_confirm_body(admin, detail_id, offset=0):
    members = _fetch_members(admin)
    target = next((m for m in members if _member_detail_id(m) == detail_id), None)
    body = [fix_tab._back_action("← Back to Delete User", "team_deleteuser_back", {"offset": offset})]
    if not target:
        body.append({"type": "TextBlock", "text": "This user could not be found — the list may have changed.", "wrap": True, "spacing": "Medium"})
        return body
    body.append({"type": "TextBlock", "text": _member_name(target), "weight": "Bolder", "size": "Medium", "spacing": "Medium", "wrap": True})
    body.append({
        "type": "FactSet",
        "facts": [
            {"title": "Email", "value": target.get("email") or "—"},
            {"title": "Type", "value": target.get("user_type") or "—"},
            {"title": "Team(s)", "value": ", ".join(target.get("Member_role") or []) or "—"},
        ],
    })
    val = {"detail_id": detail_id, "offset": offset}
    body.append({
        "type": "ActionSet", "spacing": "Medium",
        "actions": [
            cards._execute_action("🚫 Deactivate", {"action_id": "team_deleteuser_deactivate_confirm", **val}),
            cards._execute_action("🗑 Delete Permanently", {"action_id": "team_deleteuser_delete_confirm", **val}, style="destructive"),
        ],
    })
    return body


def _confirm_body(title, warning, confirm_action_id, val):
    return [
        {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "spacing": "Medium", "color": "attention", "wrap": True},
        {"type": "TextBlock", "text": warning, "wrap": True, "size": "Small"},
        {
            "type": "ActionSet", "spacing": "Medium",
            "actions": [
                cards._execute_action("✅ Yes, confirm", {"action_id": confirm_action_id, **val}, style="destructive"),
                cards._execute_action("← Cancel", {"action_id": "team_deleteuser_view", **val}),
            ],
        },
    ]


def deactivate_confirm_body(detail_id, offset):
    return _confirm_body(
        "⚠️ Deactivate this user?",
        "They immediately lose access to VaptFix. This is reversible by an admin later, but not from here.",
        "team_deleteuser_deactivate_do", {"detail_id": detail_id, "offset": offset},
    )


def delete_confirm_body(detail_id, offset):
    return _confirm_body(
        "⚠️ Permanently delete this user?",
        "This removes their team-member record entirely and cannot be undone from here.",
        "team_deleteuser_delete_do", {"detail_id": detail_id, "offset": offset},
    )


def do_deactivate_user(admin, detail_id):
    members = _fetch_members(admin)
    target = next((m for m in members if _member_detail_id(m) == detail_id), None)
    if not target or not target.get("email"):
        return False, "This user could not be found."
    from django.contrib.auth import get_user_model
    User = get_user_model()
    try:
        u = User.objects.get(email=target["email"])
    except User.DoesNotExist:
        return False, f"No VaptFix login account found for {target['email']}."
    u.is_active = False
    u.save(update_fields=["is_active"])
    return True, f"{target['email']} has been deactivated."


def do_delete_user(admin, detail_id):
    from users_details.views import UserDetailCompleteDeleteView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        UserDetailCompleteDeleteView, admin, method="delete", request_format="json",
        data={"confirm": True}, url_kwargs={"detail_id": detail_id},
    )
    if status_code >= 300:
        err = (data or {}).get("detail") or f"status {status_code}"
        return False, f"Could not delete user — {err}."
    return True, "User permanently deleted."


# ── Update User Role (remove from one team) ─────────────────────────────

def update_role_list_body(admin, offset=0):
    members = _fetch_members(admin)
    total = len(members)
    page = members[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "🔄 Update User Role", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Remove a member's access to one of their assigned teams.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No team members found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for m in page:
        detail_id = _member_detail_id(m)
        roles = m.get("Member_role") or []
        subtitle = f"{m.get('email') or '—'}   ·   Teams: {', '.join(roles) or '—'}"
        body.append(fix_tab._row(
            _member_name(m), subtitle, "team_role_view",
            {"detail_id": detail_id, "offset": offset},
        ))
    body.extend(fix_tab._pagination_body(offset, total, "team_role_pg"))
    return body


def update_role_detail_body(admin, detail_id, offset=0):
    members = _fetch_members(admin)
    target = next((m for m in members if _member_detail_id(m) == detail_id), None)
    body = [fix_tab._back_action("← Back to Update User Role", "team_role_back", {"offset": offset})]
    if not target:
        body.append({"type": "TextBlock", "text": "This user could not be found — the list may have changed.", "wrap": True, "spacing": "Medium"})
        return body
    body.append({"type": "TextBlock", "text": _member_name(target), "weight": "Bolder", "size": "Medium", "spacing": "Medium", "wrap": True})
    roles = target.get("Member_role") or []
    body.append({"type": "TextBlock", "text": f"{target.get('email') or '—'}", "size": "Small", "isSubtle": True})
    if not roles:
        body.append({"type": "TextBlock", "text": "This user has no team roles left.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    body.append({"type": "TextBlock", "text": "Tap a team to remove this member from it:", "size": "Small", "weight": "Bolder", "spacing": "Medium"})
    actions_list = [
        cards._execute_action(f"✕ Remove from {role}", {"action_id": "team_role_remove_confirm", "detail_id": detail_id, "role": role, "offset": offset}, style="destructive")
        for role in roles
    ]
    body.append({"type": "ActionSet", "spacing": "Medium", "actions": actions_list})
    return body


def role_remove_confirm_body(detail_id, role, offset):
    return _confirm_body(
        f"⚠️ Remove from {role}?",
        "They immediately lose access to this team's assets and vulnerabilities. If this was their only team, their whole account is removed.",
        "team_role_remove_do", {"detail_id": detail_id, "role": role, "offset": offset},
    )


def do_remove_role(admin, detail_id, role):
    from users_details.views import UserDetailRoleDeleteView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        UserDetailRoleDeleteView, admin, method="delete", request_format="json",
        data={"confirm": True, "member_role": role}, url_kwargs={"detail_id": detail_id},
    )
    if status_code >= 300:
        err = (data or {}).get("detail") or f"status {status_code}"
        return False, f"Could not remove {role} — {err}."
    return True, f"Removed from {role}."


# ── External User ─────────────────────────────────────────────────────

def external_user_list_body(admin, offset=0):
    members = _fetch_members(admin, user_type="external")
    total = len(members)
    page = members[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "🌐 External Users", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": f"Total external users: {total}", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No external users found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for m in page:
        subtitle = f"{m.get('email') or '—'}   ·   {m.get('team_name') or ', '.join(m.get('Member_role') or []) or '—'}"
        body.append({
            "type": "Container", "spacing": "Medium", "separator": True,
            "items": [
                {"type": "TextBlock", "text": f"🟢 {_member_name(m)}", "weight": "Bolder", "size": "Small", "wrap": True},
                {"type": "TextBlock", "text": subtitle, "size": "Small", "isSubtle": True, "spacing": "None"},
            ],
        })
    body.extend(fix_tab._pagination_body(offset, total, "team_ext_pg"))
    return body


# ── Top-level entry point ────────────────────────────────────────────────

def team_tab_body(admin, team_id, active_sub="team_sub_team", offset=0):
    body = [team_subnav_columnset(active_sub)]
    try:
        if active_sub == "team_sub_adduser":
            body.extend(add_user_form_body())
        elif active_sub == "team_sub_deleteuser":
            body.extend(delete_user_list_body(admin, offset=offset))
        elif active_sub == "team_sub_deleteteamuser":
            body.extend(update_role_list_body(admin, offset=offset))
        elif active_sub == "team_sub_externaluser":
            body.extend(external_user_list_body(admin, offset=offset))
        else:
            body.extend(cards.dashboard_image_card_body(team_id, kind="teamperf", title="Team Performance"))
    except Exception:
        logger.exception(f"[TeamsBot] team_tab_body failed for {active_sub}")
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "spacing": "Medium"})
    return body
