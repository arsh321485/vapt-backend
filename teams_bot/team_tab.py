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


# Real follow-up request: back to one row, full text still visible — see
# cards.NAV_ITEMS' own comment for the reasoning (emoji dropped, same
# unverified-in-real-Teams status; revert to
# cards.two_row_pill_columnset(TEAM_SUBTABS, ..., split=3) if this row
# renders broken/truncated in real Teams).
TEAM_SUBTABS = [
    ("team_sub_team", "Team Performance"),
    ("team_sub_adduser", "Add User"),
    ("team_sub_deleteuser", "Delete User"),
    ("team_sub_deleteteamuser", "Update User Role"),
    ("team_sub_externaluser", "External User"),
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

def normalize_adduser_form_data(value):
    """The raw click `value` Teams echoes back has au_team/au_assets/
    au_vulns/au_pick_member under REV-SUFFIXED ids (au_team_3, not
    au_team — see add_user_form_body's docstring on why those ids change
    every render). Every actions.py dispatch handler for this flow calls
    this first so add_user_form_body/_apply_select_all/submit_add_user
    only ever have to deal with the plain, unsuffixed keys — this is the
    one place that knows about the suffix scheme."""
    value = value or {}
    rev = value.get("_rev") or "0"
    normalized = dict(value)
    for field in ("au_team", "au_assets", "au_vulns", "au_pick_member"):
        suffixed = value.get(f"{field}_{rev}")
        if suffixed is not None:
            normalized[field] = suffixed
    return normalized


def add_user_form_body(admin, form_data=None):
    """
    One combined screen for the whole Add User flow — real request: picking
    a team used to jump to a SEPARATE "Next" screen for Assets/Vulnerabilities,
    which made it unclear whose assets/vulns were even being looked at.
    Matching Slack's own Add User modal (team checkboxes -> assets/vulns
    pickers appear right there, same screen), team selection now shows the
    Assets/Vulnerabilities lists directly below it, still on this one card.

    `form_data` is None for the very first render (nav tab click) and the
    previous click's own `value` dict on every re-render after that (team
    picked, "Fetch Details", Select All, etc.) — since every Input element
    below lives on this SAME card, Adaptive Cards auto-includes their
    current values on ANY button click, so re-rendering from `form_data`
    naturally preserves whatever was already typed/checked without this
    function needing to thread values through button `data` by hand (the
    "carried" pattern the old 3-screen version needed — no longer required
    now that it's one screen). actions.py normalizes the raw click `value`
    into this plain-keyed shape (au_team, au_assets, au_vulns — not their
    rev-suffixed on-card ids) before calling in — see _normalize_form_data.

    Real bug report: checking Team(s), then clicking "Show Assets &
    Vulnerabilities", visually UNCHECKED the team box again in the
    re-rendered card — even though the assets/vulns shown were correctly
    for that team (form_data really did carry it through correctly; only
    the checkbox's own displayed state was wrong). Two compounding causes,
    both fixed:
      1. The actual root cause: the team/assets/vulns ChoiceSet elements
         below were setting "initial_options" (a list of {title, value}
         dicts) to preselect values — that's Slack Block Kit's
         multi_static_select convention, not a real Adaptive Cards
         Input.ChoiceSet property, so Teams silently ignored it and the
         checkbox never showed as checked on ANY render, touched or not.
         Adaptive Cards' real property is "value": a plain string,
         comma-separated when isMultiSelect is true — see where each
         element sets it below.
      2. A real, separate Adaptive Cards quirk that's still worth guarding
         against even with (1) fixed: once a user HAS touched a
         checkbox-style input, some clients ignore a later render's
         preset "value" for that SAME element id and keep showing
         whatever the user last set (the "stuck checkbox" issue Slack's
         own Add User modal already had to work around — see
         users.views.SlackSlashCommandView._build_adduser_picker_blocks).
         Every dynamic ChoiceSet below (au_pick_member, au_team,
         au_assets, au_vulns) gets a fresh, rev-suffixed id every render
         (au_team_1, au_team_2, ...) so the client treats each render as
         a brand-new widget instead of an update to a "dirty" one — _rev
         (a hidden field) carries the current render's number forward so
         the next click's normalization knows which suffix to read the
         submitted value back from.
    """
    form_data = form_data or {}
    rev = int(form_data.get("_rev") or 0) + 1
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

    picked_email = (form_data.get("au_pick_member") or "").strip()
    picked_member = None
    if picked_email:
        picked_member = next((m for m in _fetch_teams_members_from_graph(admin) if m["email"] == picked_email), None)

    if picked_member:
        # Fetched from the live Teams roster — shown read-only, matching
        # the old picked_member_preview_body's FactSet. au_pick_member is
        # re-declared as a hidden-equivalent (Input.Text, not shown) purely
        # so its value keeps auto-carrying through every further click on
        # this card; there's no need to let them re-pick from here.
        body.append({
            "type": "FactSet",
            "facts": [
                {"title": "Name", "value": picked_member.get("displayName") or picked_email},
                {"title": "Email", "value": picked_email},
            ],
        })
        body.append({"type": "Input.Text", "id": "au_pick_member", "value": picked_email, "isVisible": False})
        body.append({"type": "Input.Text", "id": "au_type", "value": "internal", "isVisible": False})
    else:
        # Real people already on this Teams team (confirmed via real testing
        # this was expected — Slack's own Add User picks from a workspace
        # member directory the same way, instead of retyping a name/email
        # that's already known). Adaptive Cards has no live onChange between
        # inputs — picking someone here can't auto-fill the Name/Email
        # fields below in the same render, so "Fetch Details" does one
        # round-trip back to this same function with au_pick_member set,
        # which then renders the read-only branch above instead.
        teams_members = _fetch_teams_members_from_graph(admin)
        if teams_members:
            body.append({"type": "TextBlock", "text": "Pick someone already in this Teams team:", "size": "Small", "weight": "Bolder", "spacing": "Medium"})
            body.append({
                "type": "Input.ChoiceSet", "id": f"au_pick_member_{rev}", "style": "compact",
                "placeholder": "Select a Teams member",
                "choices": [{"title": f"{m['displayName']} ({m['email']})", "value": m["email"]} for m in teams_members],
            })
            body.append({
                "type": "ActionSet", "spacing": "Small",
                "actions": [cards._execute_action("🔎 Fetch Details", {"action_id": "team_adduser_refresh"}, style="positive")],
            })
            body.append({"type": "TextBlock", "text": "— or fill in manually for someone not yet in this Teams team —", "size": "Small", "isSubtle": True, "spacing": "Medium", "wrap": True})

        body.extend([
            {"type": "Input.ChoiceSet", "id": "au_type", "label": "User Type", "style": "compact",
             "value": form_data.get("au_type") or "external",
             "choices": [{"title": "External", "value": "external"}, {"title": "Internal", "value": "internal"}]},
            {"type": "Input.Text", "id": "au_first", "label": "First Name", "placeholder": "e.g. Ritu", "value": form_data.get("au_first") or ""},
            {"type": "Input.Text", "id": "au_last", "label": "Last Name", "placeholder": "optional", "value": form_data.get("au_last") or ""},
            {"type": "Input.Text", "id": "au_email", "label": "Email", "style": "Email", "placeholder": "name@example.com", "value": form_data.get("au_email") or ""},
        ])

    team_codes_selected = [c.strip() for c in (form_data.get("au_team") or "").split(",") if c.strip()]
    team_options = [{"title": name, "value": code} for code, name in TEAM_ROLE_OPTIONS]
    team_element = {"type": "Input.ChoiceSet", "id": f"au_team_{rev}", "label": "Team(s)", "style": "expanded", "isMultiSelect": True, "choices": team_options}
    # Real bug report: this was setting "initial_options" (a list of
    # {title, value} dicts) — that's Slack Block Kit's multi_static_select
    # convention, not a real Adaptive Cards Input.ChoiceSet property, so
    # Teams silently ignored it and the checkbox never showed as checked
    # on re-render at all (form_data itself carried the selection through
    # correctly the whole time — only the visual checkbox state was ever
    # wrong). Adaptive Cards' actual property is "value": a single string,
    # comma-separated when isMultiSelect is true.
    initial = [o for o in team_options if o["value"] in team_codes_selected]
    if initial:
        team_element["value"] = ",".join(o["value"] for o in initial)
    body.append(team_element)
    body.append({
        "type": "ActionSet", "spacing": "Small",
        "actions": [cards._execute_action("🔄 Show Assets & Vulnerabilities for selected Team(s)", {"action_id": "team_adduser_refresh"})],
    })

    if team_codes_selected:
        team_names = [TEAM_CODE_TO_NAME[c] for c in team_codes_selected if c in TEAM_CODE_TO_NAME]
        body.extend(_assets_vulns_picker_blocks(admin, team_names, form_data, rev))

    body.append({"type": "Input.Text", "id": "_rev", "value": str(rev), "isVisible": False})
    body.append({
        "type": "ActionSet", "spacing": "Medium",
        "actions": [cards._execute_action("✅ Add User", {"action_id": "team_adduser_submit"}, style="positive")],
    })
    return body


def _fetch_team_assets_vulns(admin, team_names):
    """Real assigned_team data for the selected team(s) — same source and
    same merge/dedupe-across-teams behavior as Slack's own
    users.views.SlackSlashCommandView._get_team_assets_vulns_combined,
    just called in-process (Django REST view, not an HTTP round-trip to
    our own API) matching how every other admin-data fetch in this module
    already works. Read-only — no API changes."""
    from users_details.views import ReportAssetsVulnsAPIView
    from .actions import _call_view_in_process

    assets_by_id, vulns_by_id = {}, {}
    for team_name in team_names:
        status_code, data = _call_view_in_process(
            ReportAssetsVulnsAPIView, admin, method="get", data={"role": team_name},
        )
        if status_code >= 300 or not isinstance(data, dict):
            continue
        for a in (data.get("assets") or []):
            host = a.get("host_name")
            if not host:
                continue
            a_vulns = a.get("vulnerabilities") or []
            if host not in assets_by_id:
                top_sev = a_vulns[0].get("severity") if a_vulns else "—"
                assets_by_id[host] = {"id": host, "label": host, "severity": top_sev}
            for v in a_vulns:
                pname = v.get("plugin_name") or "Unknown"
                vid = f"{host}||{pname}"
                if vid not in vulns_by_id:
                    vulns_by_id[vid] = {
                        "id": vid, "label": pname, "host": host,
                        "severity": v.get("severity") or "—",
                    }
    return list(assets_by_id.values()), list(vulns_by_id.values())




def _assets_vulns_picker_blocks(admin, team_names, form_data, rev):
    """Assets + Vulnerabilities checkboxes for add_user_form_body, scoped to
    the currently-selected team(s) — embedded directly in that one combined
    screen (see its own docstring for why) rather than a separate step.
    Select All/Clear All (real request, matching Slack's own Add User
    picker) work the same "re-render this same screen" way every other
    button here does: team_adduser_assets_all/_none and
    _vulns_all/_none set au_assets/au_vulns to every id (or to none)
    before the very next render, via _apply_select_all below — now always
    EVERY asset/vuln, not just the current page (see its own docstring).
    `rev` (same counter add_user_form_body computed for au_team) keeps
    these two ChoiceSets' ids fresh every render too — see
    add_user_form_body's own docstring for why that's needed.

    Real follow-up request: this used to just show the first 40 of each
    list with no way to see the rest. Paginated properly instead, same
    PAGE_SIZE=5 + Prev/Next convention as every other list in this bot —
    see _asset_vuln_pagination_row. The two lists page independently
    (au_assets_offset / au_vulns_offset), and — deliberately — these are
    NOT hidden Input.Text fields the way _rev is; they're carried purely
    through each Prev/Next click's own action data (see that function),
    so any OTHER click on this card (changing the team, Select All, the
    final Add User submit) naturally resets both back to page 1 instead
    of a stale offset accumulating forever across unrelated clicks.
    """
    body = [{"type": "TextBlock", "text": f"Assets & Vulnerabilities for {', '.join(team_names)}:", "size": "Small", "weight": "Bolder", "spacing": "Medium", "wrap": True}]

    assets, vulns = _fetch_team_assets_vulns(admin, team_names) if team_names else ([], [])
    sel_assets = [a.strip() for a in (form_data.get("au_assets") or "").split(",") if a.strip()]
    sel_vulns = [v.strip() for v in (form_data.get("au_vulns") or "").split(",") if v.strip()]

    def _int_offset(key):
        try:
            return max(0, int(form_data.get(key) or 0))
        except (TypeError, ValueError):
            return 0
    a_offset = _int_offset("au_assets_offset")
    v_offset = _int_offset("au_vulns_offset")

    if assets:
        a_total = len(assets)
        shown = assets[a_offset:a_offset + PAGE_SIZE]
        body.append({
            "type": "ActionSet", "spacing": "Small",
            "actions": [
                cards._execute_action(f"☑️ Select All Assets ({a_total})", {"action_id": "team_adduser_assets_all"}, style="positive"),
                cards._execute_action("☐ Clear Assets", {"action_id": "team_adduser_assets_none"}),
            ],
        })
        a_options = [{"title": f"{a['label']} [{a['severity']}]"[:75], "value": a["id"]} for a in shown]
        a_element = {"type": "Input.ChoiceSet", "id": f"au_assets_{rev}", "label": f"Assets ({a_total})", "style": "expanded", "isMultiSelect": True, "choices": a_options}
        # Real bug report — see add_user_form_body's team_element comment:
        # "initial_options" isn't a real Adaptive Cards property, use
        # "value" (comma-separated string) instead.
        a_initial = [o for o in a_options if o["value"] in sel_assets]
        if a_initial:
            a_element["value"] = ",".join(o["value"] for o in a_initial)
        body.append(a_element)
        body.extend(_asset_vuln_pagination_row(a_offset, a_total, "assets", v_offset))
    if vulns:
        v_total = len(vulns)
        shown = vulns[v_offset:v_offset + PAGE_SIZE]
        body.append({
            "type": "ActionSet", "spacing": "Small",
            "actions": [
                cards._execute_action(f"☑️ Select All Vulnerabilities ({v_total})", {"action_id": "team_adduser_vulns_all"}, style="positive"),
                cards._execute_action("☐ Clear Vulnerabilities", {"action_id": "team_adduser_vulns_none"}),
            ],
        })
        v_options = [{"title": f"{v['label']} ({v['host']}) [{v['severity']}]"[:75], "value": v["id"]} for v in shown]
        v_element = {"type": "Input.ChoiceSet", "id": f"au_vulns_{rev}", "label": f"Vulnerabilities ({v_total})", "style": "expanded", "isMultiSelect": True, "choices": v_options}
        # Real bug report — see add_user_form_body's team_element comment:
        # "initial_options" isn't a real Adaptive Cards property, use
        # "value" (comma-separated string) instead.
        v_initial = [o for o in v_options if o["value"] in sel_vulns]
        if v_initial:
            v_element["value"] = ",".join(o["value"] for o in v_initial)
        body.append(v_element)
        body.extend(_asset_vuln_pagination_row(v_offset, v_total, "vulns", a_offset))
    if not assets and not vulns:
        body.append({"type": "TextBlock", "text": "_No assets/vulnerabilities found for the selected team(s) yet — you can still add the user with team-level access._", "size": "Small", "isSubtle": True, "spacing": "Medium", "wrap": True})
    return body


def _asset_vuln_pagination_row(offset, total, which, other_offset):
    """Prev/Next for one of the two lists in _assets_vulns_picker_blocks.
    Both offsets are always sent explicitly on a click (this list's new
    one, plus the OTHER list's current one, unchanged) — action-data-
    driven rather than a hidden Input.Text, see that function's own
    docstring for why."""
    start = offset + 1 if total else 0
    end = min(offset + PAGE_SIZE, total)
    this_key = "au_assets_offset" if which == "assets" else "au_vulns_offset"
    other_key = "au_vulns_offset" if which == "assets" else "au_assets_offset"
    body = [{"type": "TextBlock", "text": f"Showing {start}-{end} of {total}", "size": "Small", "isSubtle": True, "spacing": "Small"}]
    actions = []
    if offset > 0:
        actions.append(cards._execute_action("‹ Prev", {
            "action_id": "team_adduser_refresh",
            this_key: max(0, offset - PAGE_SIZE),
            other_key: other_offset,
        }))
    if offset + PAGE_SIZE < total:
        actions.append(cards._execute_action("Next ›", {
            "action_id": "team_adduser_refresh",
            this_key: offset + PAGE_SIZE,
            other_key: other_offset,
        }))
    if actions:
        body.append({"type": "ActionSet", "spacing": "Small", "actions": actions})
    return body


def _apply_select_all(admin, form_data, which, select):
    """Handles team_adduser_assets_all/_none and _vulns_all/_none — returns
    a NEW form_data dict with au_assets or au_vulns overridden to either
    EVERY asset/vuln for the selected team(s) (select=True, not just the
    current page) or cleared (select=False), leaving every other field
    exactly as the click carried them in."""
    team_codes = [c.strip() for c in (form_data.get("au_team") or "").split(",") if c.strip()]
    team_names = [TEAM_CODE_TO_NAME[c] for c in team_codes if c in TEAM_CODE_TO_NAME]
    assets, vulns = _fetch_team_assets_vulns(admin, team_names) if team_names else ([], [])
    updated = dict(form_data)
    if which == "assets":
        updated["au_assets"] = ",".join(a["id"] for a in assets) if select else ""
    else:
        updated["au_vulns"] = ",".join(v["id"] for v in vulns) if select else ""
    return updated


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

    # Same optional field Slack's modal sends when the Assets/Vulnerabilities
    # picker was used — see _assets_vulns_picker_blocks. Also isMultiSelect
    # ChoiceSets, so comma-separated the same way au_team is.
    sel_assets = [a.strip() for a in (form_data.get("au_assets") or "").split(",") if a.strip()]
    sel_vulns = [v.strip() for v in (form_data.get("au_vulns") or "").split(",") if v.strip()]
    role_assignments = {"assets": sel_assets, "vulnerabilities": sel_vulns} if (sel_assets or sel_vulns) else None

    teams_label = ", ".join(team_names)
    post_data = {
        "admin_id": str(admin.id),
        "email": email,
        "first_name": first,
        "last_name": last,
        "user_type": user_type,
        "team_name": team_names[0],
        "Member_role": team_names,
    }
    if role_assignments:
        post_data["role_assignments"] = role_assignments
    status_code, data = _call_view_in_process(
        UserDetailCreateView, admin, method="post", request_format="json",
        data=post_data,
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
