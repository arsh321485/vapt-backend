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
    # 5 items, one of them ("Update User Role") long enough to truncate
    # in a single row — same two-row fix as the top nav bar and Reminder.
    return cards.two_row_pill_columnset(TEAM_SUBTABS, active_sub, lambda k: {"action_id": k})


# ── shared data fetch ─────────────────────────────────────────────────

def _live_sync_members_from_teams(admin):
    """
    Best-effort live pull of the Team's real Microsoft Teams membership
    into UserDetail. Replaces reliance on the Graph change-notification
    subscription set up once in CreateTeamsSubscriptionView — confirmed
    via a real Graph API check that subscription had silently expired
    (it caps at ~3 days and nothing renews it), so a member added
    directly in Teams (native "Add member") never showed up here until
    manually re-synced. This runs the same sync logic that view already
    has on every Team-tab open instead, no subscription needed at all.

    Throttled via cached_fetch (~45s) so switching between Delete User /
    Update User Role / External User in a row doesn't hit Graph on every
    single click. Never raises — a failed sync just means this click
    sees whatever was already in the DB, same as before this existed.
    """
    def _do_sync():
        team_id = getattr(admin, "ms_team_id", None)
        access_token = getattr(admin, "ms_access_token", None)
        if not team_id or not access_token:
            return False
        try:
            from users.views import CreateTeamsSubscriptionView
            view = CreateTeamsSubscriptionView()
            result = view._sync_existing_members(admin, team_id, access_token)
            if isinstance(result, dict) and result.get("error"):
                # Most likely an expired access token — refresh once and retry.
                new_token = _refresh_ms_access_token(admin)
                if new_token:
                    view._sync_existing_members(admin, team_id, new_token)
            return True
        except Exception:
            logger.exception("[TeamsBot] live Teams member sync failed")
            return False
    return fix_tab.cached_fetch(f"team_member_sync:{admin.id}", 45, _do_sync)


def _refresh_ms_access_token(admin):
    """Same refresh_token grant MicrosoftTeamsTokenRefreshView uses —
    returns the new access token (and persists it) or None on failure."""
    refresh_token = getattr(admin, "ms_refresh_token", None)
    if not refresh_token:
        return None
    try:
        from django.conf import settings
        from users.views import _http_post
        resp = _http_post(
            settings.MICROSOFT_TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "client_id": settings.MICROSOFT_CLIENT_ID,
                "client_secret": settings.MICROSOFT_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "scope": "https://graph.microsoft.com/.default offline_access",
            },
            timeout=15,
        )
        data = resp.json()
        new_token = data.get("access_token")
        if not new_token:
            return None
        from django.contrib.auth import get_user_model
        User = get_user_model()
        User.objects.filter(pk=admin.pk).update(
            ms_access_token=new_token,
            ms_refresh_token=data.get("refresh_token") or refresh_token,
        )
        admin.ms_access_token = new_token
        return new_token
    except Exception:
        logger.exception("[TeamsBot] MS Teams access token refresh failed")
        return None


def _fetch_teams_members_from_graph(admin):
    """
    Real Microsoft Teams roster for this admin's team (email + display
    name), straight from Graph — used to let Add User PICK someone who's
    already a Teams member instead of retyping their name/email by hand
    (Slack's own Add User modal does the same thing with a users_select
    picker). Cached ~45s (fix_tab.cached_fetch), same throttling reasoning
    as _live_sync_members_from_teams.
    """
    def _do_fetch():
        team_id = getattr(admin, "ms_team_id", None)
        access_token = getattr(admin, "ms_access_token", None)
        if not team_id or not access_token:
            return []
        try:
            import requests
            resp = requests.get(
                f"https://graph.microsoft.com/v1.0/teams/{team_id}/members",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=15,
            )
            if resp.status_code == 401:
                new_token = _refresh_ms_access_token(admin)
                if not new_token:
                    return []
                resp = requests.get(
                    f"https://graph.microsoft.com/v1.0/teams/{team_id}/members",
                    headers={"Authorization": f"Bearer {new_token}"},
                    timeout=15,
                )
            if resp.status_code != 200:
                return []
            out = []
            for m in resp.json().get("value") or []:
                email = (m.get("email") or "").strip()
                if not email or (email.lower() == (getattr(admin, "email", "") or "").strip().lower()):
                    continue  # skip the admin themselves
                out.append({"email": email, "displayName": m.get("displayName") or email})
            return out
        except Exception:
            logger.exception("[TeamsBot] fetch Teams members from Graph failed")
            return []
    return fix_tab.cached_fetch(f"teams_graph_members:{admin.id}", 45, _do_fetch)


def _fetch_members(admin, user_type=None):
    _live_sync_members_from_teams(admin)
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

def add_user_form_body(admin):
    # NOTE: deliberately NOT using isRequired/errorMessage on these inputs —
    # confirmed via real testing that Adaptive Cards validates every
    # isRequired input on the CARD as a whole before letting ANY
    # Action.Execute fire, including the top nav bar's own selectAction
    # clicks living in the same card body. With isRequired set here, an
    # admin who opened Add User couldn't click any other tab until they'd
    # filled this form in — required-field checking is done server-side
    # in submit_add_user() instead, which already returns a clear error
    # message without blocking navigation.
    body = [
        {"type": "TextBlock", "text": "➕ Add User", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Add a new team member and grant them access to one team. A welcome email with login instructions is sent automatically.", "size": "Small", "isSubtle": True, "wrap": True},
    ]

    # Real people already on this Teams team (confirmed via real testing
    # this was expected — Slack's own Add User picks from a workspace
    # member directory the same way, instead of retyping a name/email
    # that's already known). Adaptive Cards has no live onChange between
    # inputs — picking someone here can't auto-fill the Name/Email fields
    # below in the same render, so "Fetch Details" does one round-trip to
    # picked_member_preview_body(), which shows their REAL name/email
    # pulled from Teams before asking for a team and submitting.
    teams_members = _fetch_teams_members_from_graph(admin)
    if teams_members:
        body.append({"type": "TextBlock", "text": "Pick someone already in this Teams team:", "size": "Small", "weight": "Bolder", "spacing": "Medium"})
        body.append({
            "type": "Input.ChoiceSet", "id": "au_pick_member", "style": "compact",
            "placeholder": "Select a Teams member",
            "choices": [{"title": f"{m['displayName']} ({m['email']})", "value": m["email"]} for m in teams_members],
        })
        body.append({
            "type": "ActionSet", "spacing": "Small",
            "actions": [cards._execute_action("🔎 Fetch Details", {"action_id": "team_adduser_show_picked"}, style="positive")],
        })
        body.append({"type": "TextBlock", "text": "— or fill in manually for someone not yet in this Teams team —", "size": "Small", "isSubtle": True, "spacing": "Medium", "wrap": True})

    body.extend([
        {"type": "Input.ChoiceSet", "id": "au_type", "label": "User Type", "style": "compact", "value": "external",
         "choices": [{"title": "External", "value": "external"}, {"title": "Internal", "value": "internal"}]},
        {"type": "Input.Text", "id": "au_first", "label": "First Name", "placeholder": "e.g. Ritu"},
        {"type": "Input.Text", "id": "au_last", "label": "Last Name", "placeholder": "optional"},
        {"type": "Input.Text", "id": "au_email", "label": "Email", "style": "Email", "placeholder": "name@example.com"},
        {"type": "Input.ChoiceSet", "id": "au_team", "label": "Team(s)", "style": "expanded", "isMultiSelect": True,
         "choices": [{"title": name, "value": code} for code, name in TEAM_ROLE_OPTIONS]},
        {
            "type": "ActionSet", "spacing": "Medium",
            "actions": [cards._execute_action("✅ Add User", {"action_id": "team_adduser_submit"}, style="positive")],
        },
    ])
    return body


def picked_member_preview_body(admin, picked_email):
    """Round-trip target for the "🔎 Fetch Details" button — shows the REAL
    Name/Email pulled from the live Teams roster for whoever was picked in
    add_user_form_body's au_pick_member dropdown, since Adaptive Cards has
    no live onChange to auto-fill those fields in the same render. The
    Team choice + final submit both happen here; submitting bakes
    au_pick_member/au_type back into the Action.Execute data so
    submit_add_user() resolves the name/email from the Graph roster again
    (matching how the manual-entry path already works)."""
    picked = next((m for m in _fetch_teams_members_from_graph(admin) if m["email"] == picked_email), None)
    display_name = (picked or {}).get("displayName") or picked_email

    body = [
        {"type": "TextBlock", "text": "➕ Add User", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Fetched from this Teams team — confirm the team to grant access to:", "size": "Small", "isSubtle": True, "wrap": True},
        {
            "type": "FactSet",
            "facts": [
                {"title": "Name", "value": display_name},
                {"title": "Email", "value": picked_email},
            ],
        },
        {"type": "Input.ChoiceSet", "id": "au_team", "label": "Team(s)", "style": "expanded", "isMultiSelect": True,
         "choices": [{"title": name, "value": code} for code, name in TEAM_ROLE_OPTIONS]},
        {
            "type": "ActionSet", "spacing": "Medium",
            "actions": [
                cards._execute_action("✅ Add User", {
                    "action_id": "team_adduser_submit",
                    "au_pick_member": picked_email,
                    "au_type": "internal",
                }, style="positive"),
                cards._execute_action("← Choose someone else", {"action_id": "team_sub_adduser"}),
            ],
        },
    ]
    return body


def submit_add_user(admin, form_data):
    """`form_data` is the Input.* values Teams echoes back alongside our own
    action_id — mirrors users.views.SlackSlashCommandView._cmd_adduser's
    real API call (POST /api/admin/users_details/add-user-detail/). If a
    real Teams member was picked from au_pick_member, their name/email
    come from the live Graph roster (matching Slack's own users_select
    picker behavior); otherwise falls back to the manual fields, the same
    ones the website's own Add User form takes."""
    from users_details.views import UserDetailCreateView
    from .actions import _call_view_in_process

    picked_email = (form_data.get("au_pick_member") or "").strip()
    if picked_email:
        picked = next((m for m in _fetch_teams_members_from_graph(admin) if m["email"] == picked_email), None)
        email = picked_email
        display_name = (picked or {}).get("displayName") or ""
        name_parts = display_name.split()
        first = name_parts[0] if name_parts else email
        last = " ".join(name_parts[1:]) if len(name_parts) > 1 else first
    else:
        email = (form_data.get("au_email") or "").strip()
        first = (form_data.get("au_first") or "").strip()
        last = (form_data.get("au_last") or "").strip() or first

    user_type = form_data.get("au_type") or "external"
    # au_team is Input.ChoiceSet with isMultiSelect: true (checkboxes) now
    # — Adaptive Cards echoes multi-select values back as a single
    # comma-separated string, not a list, so split it here.
    codes = [c.strip() for c in (form_data.get("au_team") or "").split(",") if c.strip()]
    team_names = [TEAM_CODE_TO_NAME[c] for c in codes if c in TEAM_CODE_TO_NAME]

    if not email or not first or not team_names:
        return False, "Pick a Teams member (or fill in Email/First Name manually) and select at least one Team."

    teams_label = ", ".join(team_names)
    status_code, data = _call_view_in_process(
        UserDetailCreateView, admin, method="post", request_format="json",
        data={
            "admin_id": str(admin.id),
            "email": email,
            "first_name": first,
            "last_name": last,
            "user_type": user_type,
            "team_name": team_names[0],
            "Member_role": team_names,
        },
    )
    if status_code < 300:
        return True, f"{first} ({email}) added to {teams_label}. A welcome email has been sent."

    err = (data or {}).get("error") or (data or {}).get("detail") or (data or {}).get("email")
    already_exists = "already exists" in str(err or "")
    if not already_exists:
        return False, str(err) if err else f"Could not add user (status {status_code})."

    # A UserDetail already exists for this email — most commonly because
    # the live Teams-membership sync (see _live_sync_members_from_teams)
    # already created a Viewer-only stub for them just from being a Teams
    # team member, before anyone explicitly granted them a real role.
    # Mirrors users.views.SlackSlashCommandView._cmd_adduser's own
    # already-exists handling: merge the requested team(s) into their
    # existing Member_role instead of treating "already has a stub
    # record with no real access yet" as a hard failure.
    try:
        from users_details.models import UserDetail
        from users_details.views import _ud_set
        existing = UserDetail.objects.filter(admin=admin, email=email).first()
        if not existing:
            return False, str(err)
        current_roles = [r for r in (existing.Member_role or []) if r != "Viewer"]
        for team_name in team_names:
            if team_name not in current_roles:
                current_roles.append(team_name)
        upd = {"Member_role": current_roles, "user_type": user_type}
        if not existing.team_name:
            upd["team_name"] = team_names[0]
        _ud_set(existing, **upd)
        return True, f"{first} ({email})'s access now includes: {', '.join(current_roles)}."
    except Exception:
        logger.exception("[TeamsBot] failed to merge roles for existing user %s", email)
        return False, str(err)


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
            body.extend(add_user_form_body(admin))
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
