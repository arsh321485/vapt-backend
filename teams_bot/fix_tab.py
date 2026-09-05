"""
Fix tab content — All Assets / All Vulns / Common Vulns.

Built as native, clickable Adaptive Card elements (rows with a real "View"
Action.Submit button, Prev/Next pagination, and a drill-down detail card)
rather than the flat PNG snapshot the first version used — a picture has no
clickable regions, so "View" never actually did anything. This mirrors
Slack's own real Block Kit behaviour for the same tabs (see
users.views.SlackSlashCommandView._format_asset_list/_format_asset_vulns
for All Assets, and _group_common_vulns_by_team for Common Vulns) — same
data sources, same drill-down shape, just Adaptive Card JSON instead of
Block Kit blocks. Home/Team stay as PNG images (cards.dashboard_image_card_body)
since those don't have per-row interaction to begin with.
"""
import logging

from . import cards

logger = logging.getLogger(__name__)

PAGE_SIZE = 5

_SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def _status_label(status):
    st = (status or "open").strip().lower()
    if st == "closed":
        return "🟢 Closed"
    if "progress" in st:
        return "🟠 In Progress"
    if "review" in st:
        return "🟣 Open/Review"
    return "🔴 Open"


def _sev_dots_text(counts):
    parts = [f"{_SEV_ICON[k]} {k.title()}: {counts.get(k, 0)}" for k in ("critical", "high", "medium", "low") if counts.get(k, 0)]
    return "   ".join(parts) if parts else "No open vulnerabilities"


# ─── Severity + status filter row (same pattern as register_tab.py's own
# Register tab filters — requested for the Fix tab's 3 list views too:
# All Assets, All Vulns, Common Vulns) ───────────────────────────────────

SEV_FILTERS = [("all", "All"), ("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")]
STATUS_FILTERS = [("all", "All"), ("open", "Open"), ("closed", "Closed"), ("in_progress", "In Progress")]


def _norm_sev(r):
    return (r.get("severity") or "").strip().lower()


def _norm_status(r):
    return (r.get("status") or "open").strip().lower()


def _match_sev(r, sev):
    return sev == "all" or _norm_sev(r) == sev


def _match_status(r, st):
    s = _norm_status(r)
    if st == "all":
        return True
    if st == "in_progress":
        return "progress" in s
    if st == "open":
        return s == "open" or s.startswith("open/")
    if st == "closed":
        return s == "closed"
    return s == st


def _status_counts(rows):
    return {
        "all": len(rows),
        "open": sum(1 for r in rows if _norm_status(r) == "open" or _norm_status(r).startswith("open/")),
        "closed": sum(1 for r in rows if _norm_status(r) == "closed"),
        "in_progress": sum(1 for r in rows if "progress" in _norm_status(r)),
    }


def _sev_filter_columnset(prefix, active_sev, active_st, extra_value=None):
    """`prefix` is this list's own action-id root — e.g. "fix_asset" ->
    clicking a severity pill fires action_id "fix_asset_sev". `extra_value`
    carries any context a click needs to preserve beyond sev/st/offset —
    e.g. Common Vulns' currently-selected `team`."""
    extra_value = extra_value or {}
    return cards.pill_columnset(
        SEV_FILTERS, active_sev,
        lambda k: {"action_id": f"{prefix}_sev", "sev": k, "st": active_st, "offset": 0, **extra_value},
    )


def _status_filter_columnset(prefix, active_sev, active_st, counts, extra_value=None):
    extra_value = extra_value or {}
    options = [(k, f"{label} {counts.get(k, 0)}") for k, label in STATUS_FILTERS]
    return cards.pill_columnset(
        options, active_st,
        lambda k: {"action_id": f"{prefix}_st", "sev": active_sev, "st": k, "offset": 0, **extra_value},
    )


def _row(title_text, subtitle_text, action_id, value):
    """One clickable list row — title/subtitle on the left, a real 'View'
    button on the right (matches Slack's section+accessory-button rows)."""
    return {
        "type": "ColumnSet",
        "spacing": "Medium",
        "separator": True,
        "columns": [
            {
                "type": "Column", "width": "stretch",
                "items": [
                    {"type": "TextBlock", "text": title_text, "weight": "Bolder", "size": "Small", "wrap": True},
                    {"type": "TextBlock", "text": subtitle_text, "size": "Small", "isSubtle": True, "wrap": True, "spacing": "None"},
                ],
            },
            {
                "type": "Column", "width": "auto", "verticalContentAlignment": "Center",
                "items": [{
                    "type": "ActionSet",
                    "actions": [cards._execute_action("View ›", {"action_id": action_id, **value})],
                }],
            },
        ],
    }


def _pagination_body(offset, total, action_id, extra_value=None):
    extra_value = extra_value or {}
    start = offset + 1 if total else 0
    end = min(offset + PAGE_SIZE, total)
    body = [{"type": "TextBlock", "text": f"Showing {start}-{end} of {total}", "size": "Small", "isSubtle": True, "spacing": "Medium"}]
    actions = []
    if offset > 0:
        actions.append(cards._execute_action("‹ Prev", {"action_id": action_id, "offset": max(0, offset - PAGE_SIZE), **extra_value}))
    if offset + PAGE_SIZE < total:
        actions.append(cards._execute_action("Next ›", {"action_id": action_id, "offset": offset + PAGE_SIZE, **extra_value}))
    if actions:
        body.append({"type": "ActionSet", "actions": actions})
    return body


def _back_action(title, action_id, value):
    return {"type": "ActionSet", "actions": [cards._execute_action(title, {"action_id": action_id, **value})]}


def script_download_url(team_id, team_name, plugin_id):
    """Signed-URL download link for one automation script — shared by
    user_register_tab.py's Scripts sub-tab and user_fix_tab.py's Auto Fix
    detail (both need it, and putting it here — the common base module
    both already import — avoids a circular import between them)."""
    import time
    from urllib.parse import quote
    from django.conf import settings
    from users.views import _dashboard_image_signer

    token = _dashboard_image_signer().sign(team_id)
    backend = getattr(settings, "VAPTFIX_BACKEND_URL", "https://vaptbackend.secureitlab.com")
    return (
        f"{backend}/api/admin/users/teams/script-download/?token={quote(token)}"
        f"&team={quote(team_name)}&plugin_id={plugin_id}&t={int(time.time())}"
    )


def cached_fetch(cache_key, ttl, fetch_fn):
    """
    Small shared helper (used by fix_tab/register_tab/automations_tab/
    reminder_tab) — every Action.Execute click BLOCKS the Teams client
    (buttons show disabled) until our invoke response comes back, so a
    user clicking through several tabs/pages/filters in quick succession
    keeps re-running the same in-process DRF calls (Mongo round trips)
    over and over within a few seconds of each other. This data only
    actually changes on distinct events well outside that window (a new
    report upload, a risk-criteria save, an automation script being
    added) — not from anything these read-only tab clicks themselves do —
    so a short cache is safe and directly shortens that visible "greyed
    out while waiting" window on every click after the first.
    """
    from django.core.cache import cache
    key = f"teamsbot_cache:{cache_key}"
    val = cache.get(key)
    if val is not None:
        return val
    val = fetch_fn()
    cache.set(key, val, timeout=ttl)
    return val


def _fetch_register_data(admin):
    """Full response (rows + report_id) — the Fix/Manual toggle needs
    report_id too (to get-or-create a fix record), not just the rows."""
    def _fetch():
        from adminregister.views import LatestSuperAdminVulnerabilityRegisterAPIView
        from .actions import _call_view_in_process
        status_code, data = _call_view_in_process(LatestSuperAdminVulnerabilityRegisterAPIView, admin, method="get")
        if status_code >= 300 or not isinstance(data, dict):
            raise ValueError(f"register fetch failed: {status_code}")
        return data
    return cached_fetch(f"register_data:{admin.id}", 20, _fetch)


def _fetch_register_rows(admin):
    return _fetch_register_data(admin).get("rows") or []


def _group_assets(rows):
    assets = {}
    order = []
    for r in rows:
        host = (r.get("asset") or "Unknown").strip() or "Unknown"
        if host not in assets:
            assets[host] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "statuses": set()}
            order.append(host)
        sev = (r.get("severity") or "").strip().lower()
        if sev in assets[host]:
            assets[host][sev] += 1
        assets[host]["statuses"].add((r.get("status") or "open").strip().lower())
    result = []
    for host in order:
        info = assets[host]
        total = info["critical"] + info["high"] + info["medium"] + info["low"]
        statuses = info["statuses"]
        status = "closed" if statuses == {"closed"} else ("in_progress" if any("progress" in s for s in statuses) else "open")
        result.append({"host": host, "total": total, "status": status, "counts": info})
    return result


# ─── All Assets ─────────────────────────────────────────────────────────

def assets_list_body(admin, sev="all", st="all", offset=0):
    rows = _fetch_register_rows(admin)
    sev_base = [r for r in rows if _match_sev(r, sev)]
    st_counts = _status_counts(sev_base)
    filtered_rows = [r for r in sev_base if _match_status(r, st)]
    assets = _group_assets(filtered_rows)
    total = len(assets)
    page = assets[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "💻 All Assets", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Every asset in your latest report. Tap View to see its vulnerabilities.", "size": "Small", "isSubtle": True, "wrap": True},
        _sev_filter_columnset("fix_asset", sev, st),
        _status_filter_columnset("fix_asset", sev, st, st_counts),
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No assets found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for a in page:
        subtitle = f"{a['total']} Vulns   ·   {_status_label(a['status'])}\n{_sev_dots_text(a['counts'])}"
        body.append(_row(f"🖥 {a['host']}", subtitle, "fix_asset_view", {"host": a["host"], "offset": offset}))
    body.extend(_pagination_body(offset, total, "fix_asset_pg", {"sev": sev, "st": st}))
    return body


def asset_detail_body(admin, host, back_offset=0):
    rows = _fetch_register_rows(admin)
    # Keep each row's index in the FULL (unfiltered) list, not its position
    # within this host's own subset — "View" on a row needs to hand back an
    # idx that vuln_facts / asset_vuln_detail_body can look up again from
    # that same full list on the next click.
    host_rows = [(i, r) for i, r in enumerate(rows) if (r.get("asset") or "Unknown").strip() == host]

    body = [_back_action("← Back to All Assets", "fix_asset_back", {"offset": back_offset})]
    body.append({"type": "TextBlock", "text": f"🖥 {host}", "weight": "Bolder", "size": "Medium", "spacing": "Medium", "wrap": True})
    body.append({"type": "TextBlock", "text": f"{len(host_rows)} vulnerabilities on this asset.", "size": "Small", "isSubtle": True})
    if not host_rows:
        body.append({"type": "TextBlock", "text": "No vulnerabilities found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for idx, r in host_rows[:20]:
        name = r.get("vul_name") or "Unnamed vulnerability"
        sev = (r.get("severity") or "medium").strip().lower()
        if sev not in _SEV_ICON:
            sev = "medium"
        status = r.get("status") or "open"
        subtitle = f"{_SEV_ICON[sev]} {sev.title()}   ·   {_status_label(status)}"
        body.append(_row(name, subtitle, "fix_asset_vuln_view", {"idx": idx, "host": host, "offset": back_offset}))
    if len(host_rows) > 20:
        body.append({"type": "TextBlock", "text": f"+ {len(host_rows) - 20} more not shown.", "size": "Small", "isSubtle": True, "spacing": "Small"})
    return body


# ─── All Vulns (flat list) ──────────────────────────────────────────────

def vulns_list_body(admin, sev="all", st="all", offset=0):
    rows = _fetch_register_rows(admin)
    # Keep the index into the FULL unfiltered list — "View" hands back an
    # idx the shared vuln-detail body resolves against that same full list
    # (same reasoning as asset_detail_body's own host_rows indices).
    sev_base = [(i, r) for i, r in enumerate(rows) if _match_sev(r, sev)]
    st_counts = _status_counts([r for _, r in sev_base])
    filtered = [(i, r) for i, r in sev_base if _match_status(r, st)]
    total = len(filtered)
    page = filtered[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "📋 All Vulnerabilities", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Every vulnerability in your latest report.", "size": "Small", "isSubtle": True, "wrap": True},
        _sev_filter_columnset("fix_vuln", sev, st),
        _status_filter_columnset("fix_vuln", sev, st, st_counts),
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No vulnerabilities found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for idx, r in page:
        name = r.get("vul_name") or "Unnamed vulnerability"
        rsev = (r.get("severity") or "medium").strip().lower()
        if rsev not in _SEV_ICON:
            rsev = "medium"
        host = r.get("asset") or "—"
        status = r.get("status") or "open"
        subtitle = f"{host}   ·   {_status_label(status)}"
        body.append(_row(f"{_SEV_ICON[rsev]} {name}", subtitle, "fix_vuln_view", {"idx": idx, "offset": offset}))
    body.extend(_pagination_body(offset, total, "fix_vuln_pg", {"sev": sev, "st": st}))
    return body


def _vuln_facts_body(r):
    sev = (r.get("severity") or "medium").strip().lower()
    if sev not in _SEV_ICON:
        sev = "medium"
    status = r.get("status") or "open"
    return [
        {"type": "TextBlock", "text": r.get("vul_name") or "Unnamed vulnerability", "weight": "Bolder", "size": "Medium", "wrap": True, "spacing": "Medium"},
        {
            "type": "FactSet",
            "facts": [
                {"title": "Asset", "value": str(r.get("asset") or "—")},
                {"title": "Severity", "value": f"{_SEV_ICON[sev]} {sev.title()}"},
                {"title": "Status", "value": _status_label(status)},
            ],
        },
    ]


# ─── Manual Fix / Automated Fix (matches Microsoft -Admin/vulndetail.html,
# real data instead of that mockup's hardcoded sample) ───────────────────
# Mirrors users.views.SlackSlashCommandView._allvuln_detail_blocks — same
# two real data sources, same read-only-for-admin behaviour (no run/mark-
# complete actions here, matching the website's admin-is-read-only rule).

def _fetch_automation_match(admin, r):
    from automation_scripts_api import views as auto_views
    from .actions import _call_view_in_process

    os_param = r.get("operating_system")
    plugin_id = r.get("plugin_id")
    if plugin_id not in (None, ""):
        try:
            pid = int(plugin_id)
        except (TypeError, ValueError):
            pid = None
        if pid is not None:
            status_code, data = _call_view_in_process(
                auto_views.admin_match_script, admin, method="get",
                url_kwargs={"plugin_id": pid},
                data={"os": os_param} if os_param else None,
            )
            if status_code < 300 and isinstance(data, dict):
                return data

    name = r.get("vul_name")
    if not name:
        return {"matched": False, "message": "No automated fix available for this vulnerability."}
    body = {"vulnerability_names": [name]}
    if os_param:
        body["os"] = os_param
    status_code, data = _call_view_in_process(
        auto_views.admin_match_scripts_by_name, admin, method="post", data=body, request_format="json",
    )
    if status_code < 300 and isinstance(data, dict):
        results = data.get("results") or []
        return results[0] if results else {"matched": False, "message": "No automated fix available for this vulnerability."}
    return {"matched": False, "message": "No automated fix available for this vulnerability."}


def _automation_fix_body(automation, admin=None):
    if not automation.get("matched"):
        return [{"type": "TextBlock", "text": "Automation script not ready for this vulnerability.", "wrap": True, "isSubtle": True, "spacing": "Medium"}]

    # Plan gate — automation_scripts_api.views' admin_match_script/
    # user_match_script (fetched in-process by _fetch_automation_match in
    # this file and user_fix_tab.py) already strips the actual script
    # content and adds premium_required/message when the plan doesn't
    # allow automation scripts (see _script_response there) — show that
    # lock notice explicitly here instead of silently rendering a
    # near-empty FactSet with none of the "What this does"/etc. sections.
    # Matches the same fix already applied to Slack.
    if automation.get("premium_required"):
        # Real bug report: this stopped at the text notice — Slack's
        # equivalent lock message (users.views._freemium_upgrade_prompt
        # blocks, and the plan-limit chat.postMessage in
        # SlackUploadReportView) always pairs the notice with an actual
        # "Upgrade to Premium" button (?source=slack on the pricing URL).
        # Teams had no way to act on the notice at all — add the same
        # button here, ?source=teams so pricing-page analytics can tell
        # the two apart.
        return [
            {
                "type": "TextBlock",
                "text": f"🔒 {automation.get('message') or 'Automation scripts are not available on your plan.'}",
                "wrap": True, "weight": "Bolder", "color": "attention", "spacing": "Medium",
            },
            {
                "type": "ActionSet",
                "spacing": "Small",
                "actions": [{
                    "type": "Action.OpenUrl",
                    "title": "⭐ Upgrade to Premium",
                    "url": cards.pricing_url(admin),
                    "style": "positive",
                }],
            },
        ]

    body = [{
        "type": "FactSet",
        "facts": [
            {"title": "Severity", "value": str(automation.get("severity") or "—")},
            {"title": "OS", "value": str(automation.get("os") or "—")},
            {"title": "Language", "value": str(automation.get("language") or "—")},
            {"title": "Automation Possible", "value": str(automation.get("automation_possible") or "—")},
        ],
    }]

    def add(label, key):
        val = automation.get(key)
        if val:
            body.append({"type": "TextBlock", "text": f"**{label}**", "wrap": True, "size": "Small", "spacing": "Medium"})
            body.append({"type": "TextBlock", "text": str(val)[:800], "wrap": True, "size": "Small"})

    add("What this does", "script_description")
    add("Recommended Approach", "recommended_approach")
    add("What can be automated", "what_can_be_automated")
    add("What must remain manual", "what_must_remain_manual")

    libs = automation.get("libraries") or []
    if libs:
        libs_str = ", ".join(str(x) for x in libs) if isinstance(libs, list) else str(libs)
        body.append({"type": "TextBlock", "text": "**Libraries needed**", "wrap": True, "size": "Small", "spacing": "Medium"})
        body.append({"type": "TextBlock", "text": libs_str, "wrap": True, "size": "Small", "fontType": "Monospace"})
    if automation.get("command_download_libraries"):
        body.append({"type": "TextBlock", "text": "**Install command**", "wrap": True, "size": "Small", "spacing": "Medium"})
        body.append({"type": "TextBlock", "text": str(automation["command_download_libraries"]), "wrap": True, "size": "Small", "fontType": "Monospace"})
    add("Before running", "considerations_before")

    body.append({
        "type": "TextBlock",
        "text": f"Script: `{automation.get('fix_script_name') or '—'}` — team members can download this in their team channel.",
        "wrap": True, "size": "Small", "isSubtle": True, "spacing": "Medium",
    })
    return body


def _get_or_create_fix_vuln_id(admin, r, report_id):
    fix_vuln_id = r.get("fix_vulnerability_id")
    if fix_vuln_id:
        return fix_vuln_id
    host_name = r.get("asset") or ""
    if not report_id or not host_name:
        return None
    from adminregister.views import FixVulnerabilityCreateAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        FixVulnerabilityCreateAPIView, admin, method="post",
        url_kwargs={"report_id": report_id, "host_name": host_name},
        data={
            "id": r.get("id", ""),
            "plugin_name": r.get("vul_name") or "",
            "risk_factor": r.get("severity") or "Medium",
            "port": r.get("port", ""),
        },
        # This endpoint only has a JSON parser configured — the shared
        # helper's multipart default got a hard 415 here (confirmed via a
        # real call), which is why Manual Fix always fell through to "no
        # steps to show" regardless of whether real steps existed.
        request_format="json",
    )
    if status_code >= 300 or not isinstance(data, dict):
        return None
    result = data.get("data") or {}
    return result.get("fix_vulnerability_id") or result.get("_id")


def _fetch_fix_steps(admin, fix_vuln_id):
    if not fix_vuln_id:
        return None
    from adminregister.views import FixVulnerabilityStepsAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        FixVulnerabilityStepsAPIView, admin, method="get", url_kwargs={"fix_vuln_id": fix_vuln_id},
    )
    if status_code >= 300 or not isinstance(data, dict):
        return None
    return data


def step_content_items(step, os_key, truncate=None):
    """
    One step's full content (Action, File Path, Where To Run, Command,
    Verification, Important) as a list of Adaptive Card TextBlocks — used
    by both the admin (read-only, one-at-a-time nav) and member
    (interactive, one-at-a-time + Mark Step Complete) Manual Fix views, so
    the two never drift out of sync.

    NOT "fontType": "Monospace" on the command text — a step whose
    "command" field is actually a plain-English instruction (no real shell
    command exists, e.g. "Run a security scan using an appropriate tool
    (e.g., Nessus)") rendered oversized in Teams' monospace font stack.

    Every field also goes through _escape_md_leading — confirmed via real
    testing that "Run a security scan..." STILL rendered as a giant
    heading even after removing Monospace: Teams' renderer treats a
    TextBlock's text as markdown, and this particular field's stored value
    starts with "#" (a genuine step instruction happened to be phrased
    that way in the source data) — read as a markdown H1, which overrides
    the "size": "Small" the JSON declares. Escaping a leading #/-/*/>/digit-dot
    (the characters markdown treats specially at the start of a line)
    makes it render as the plain text it's supposed to be, regardless of
    what's actually in the stored value.
    `truncate`: char limit per field (None = no limit — safe now that only
    ONE step renders at a time, unlike the old flat 15-steps-at-once view
    this replaced, which needed [:400] to stay a sane card size).
    """
    import re as _re

    def _cut(s):
        s = s[:truncate] if truncate else s
        # A plain r"...\\\2..." replacement string doesn't actually insert
        # a literal backslash here (confirmed — re.sub's own backslash
        # handling doesn't parse the way it looks), so every step below
        # uses a replacement FUNCTION instead, which unambiguously does.
        #
        # 1) Escape emphasis/code markers ANYWHERE in the text, not just
        # leading — confirmed the heading fix alone left some step text
        # still rendering bold: a stray "*"/"_"/backtick pair mid-sentence
        # reads as **bold**/`code` no matter where it sits. Doing this
        # FIRST (before the leading-char check below) so a leading "*"
        # isn't escaped twice by both passes.
        s = _re.sub(r"[*_`]", lambda m: "\\" + m.group(0), s)
        # 2) Escape a leading #, >, +, -, or digit+"." (heading /
        # blockquote / list-bullet triggers pass 1 doesn't touch — "*" is
        # excluded here since pass 1 already escaped every "*", leading or
        # not). Confirmed via real testing this leading-# case is what
        # turned "Run a security scan..." into a giant heading, overriding
        # the declared "size": "Small" entirely.
        s = _re.sub(
            r"^(\s*)([#>+-]|\d+\.)(\s)",
            lambda m: m.group(1) + "\\" + m.group(2) + m.group(3),
            s,
        )
        return s

    step_num = step.get("step_number")
    step_name = step.get("step_name") or f"Step {step_num}"
    status_v = step.get("status", "pending")
    done = status_v == "completed"
    badge = "✅ Done" if done else ("🔒 Locked" if step.get("is_locked") else "▶️ Pending")
    os_data = step.get(os_key) or {}
    action = (os_data.get("action") or "").strip()

    items = [{"type": "TextBlock", "text": f"{step_num}. {step_name} — {badge}", "weight": "Bolder", "size": "Medium", "wrap": True}]
    if action:
        items.append({"type": "TextBlock", "text": _cut(action), "wrap": True, "size": "Small"})
    file_path = (os_data.get("system_file_path") or "").strip()
    if file_path:
        items.append({"type": "TextBlock", "text": f"File Path: {file_path}", "wrap": True, "size": "Small", "fontType": "Monospace"})
    where_label = (os_data.get("where_to_run_label") or "").strip()
    if where_label:
        items.append({"type": "TextBlock", "text": f"Where To Run: {where_label}", "wrap": True, "size": "Small", "isSubtle": True})
    cmd_groups = os_data.get("commands_for_action")
    command_lines = []
    if isinstance(cmd_groups, list):
        for grp in cmd_groups:
            if isinstance(grp, dict):
                command_lines.extend(str(c) for c in (grp.get("commands") or []) if c)
    command_text = "\n".join(command_lines).strip() or (
        str(os_data.get("command_to_run") or "").strip()
        if not isinstance(os_data.get("commands_for_action"), list) else ""
    )
    if command_text:
        items.append({"type": "TextBlock", "text": _cut(command_text), "wrap": True, "size": "Small"})
    verification_check = (os_data.get("verification_check") or "").strip()
    if verification_check:
        items.append({"type": "TextBlock", "text": f"Verification: {_cut(verification_check)}", "wrap": True, "size": "Small", "isSubtle": True})
    important = (os_data.get("important_consideration") or "").strip()
    if important:
        items.append({"type": "TextBlock", "text": f"⚠️ Important: {_cut(important)}", "wrap": True, "size": "Small", "color": "attention"})
    return items, done


def _manual_fix_body(steps_data, host_os_hint, value_base, step_number=None):
    """One step at a time (view-only — no Mark Complete, admin can't act
    on fix progress, matching the website's own read-only rule), with
    Previous/Next Step navigation instead of the old flat 15-steps list."""
    if not steps_data or steps_data.get("detail"):
        return [{"type": "TextBlock", "text": "No fix has been started for this vulnerability yet — no steps to show.", "wrap": True, "isSubtle": True, "spacing": "Medium"}]

    steps = steps_data.get("steps") or []
    completed = steps_data.get("completed_steps", 0)
    total = steps_data.get("total_steps", 0)
    os_v = steps_data.get("operating_system") or host_os_hint or "—"
    os_key = "linux" if os_v and os_v.lower() in ("linux", "unix") else "windows"
    if not steps:
        return [{"type": "TextBlock", "text": "No steps found.", "isSubtle": True, "size": "Small", "spacing": "Medium"}]

    by_number = {s.get("step_number"): s for s in steps}
    if step_number is None or step_number not in by_number:
        current = next((s for s in steps if s.get("status") != "completed"), steps[-1])
        step_number = current.get("step_number")
    step = by_number[step_number]

    body = [{"type": "TextBlock", "text": f"📋 Step {step_number} of {total} (view only) — {completed}/{total} done · OS: {os_v}", "weight": "Bolder", "size": "Small", "wrap": True, "spacing": "Medium"}]
    items, _done = step_content_items(step, os_key)
    body.append({"type": "Container", "items": items, "spacing": "Medium", "separator": True})

    nav_actions = []
    if step_number > 1:
        nav_actions.append(cards._execute_action("◀ Previous Step", {"action_id": "fix_step_nav", "step": step_number - 1, **value_base}))
    if step_number < total:
        nav_actions.append(cards._execute_action("Next Step ▶", {"action_id": "fix_step_nav", "step": step_number + 1, **value_base}))
    if nav_actions:
        body.append({"type": "ActionSet", "spacing": "Medium", "actions": nav_actions})
    return body


def _fix_toggle_actionset(sub, value_base):
    def action(title, sub_val):
        return cards._execute_action(
            title, {"action_id": "fix_vuln_toggle", "sub": sub_val, **value_base},
            style="positive" if sub == sub_val else None,
        )
    return {"type": "ActionSet", "spacing": "Medium", "actions": [action("🛠 Manual", "manual"), action("🤖 Automation Fix", "automation")]}


def _vuln_detail_full_body(admin, idx, sub="manual", ctx="vulns", host=None, offset=0,
                            back_action_id=None, back_title=None, extra_value=None, step_number=None):
    """Shared by every entry point that drills into one vulnerability's own
    Manual/Automation Fix detail (flat All Vulns list, an asset's own vuln
    list, and Register's filtered list) — `ctx`/`host` decide where the
    Back button returns to for the two built-in cases; `back_action_id`/
    `back_title`/`extra_value` let a THIRD caller (Register — see
    teams_bot.register_tab) plug in its own Back target and extra state
    (its severity/status filters) without this module needing to know
    anything about Register's filter concept. Read-only for admins, same
    as the website/Slack."""
    data = _fetch_register_data(admin)
    rows = data.get("rows") or []
    extra_value = extra_value or {}

    if back_action_id:
        body = [_back_action(back_title or "← Back", back_action_id, {"offset": offset, **extra_value})]
    elif ctx == "asset":
        body = [_back_action(f"← Back to {host}", "fix_asset_vuln_back", {"host": host, "offset": offset})]
    else:
        body = [_back_action("← Back to All Vulns", "fix_vuln_back", {"offset": offset})]

    if idx is None or idx < 0 or idx >= len(rows):
        body.append({"type": "TextBlock", "text": "This vulnerability could not be found — the report may have changed. Go back and try again.", "wrap": True, "spacing": "Medium"})
        return body

    r = rows[idx]
    body.extend(_vuln_facts_body(r))

    value_base = {"idx": idx, "ctx": ctx, "offset": offset, **extra_value}
    if ctx == "asset":
        value_base["host"] = host
    body.append(_fix_toggle_actionset(sub, value_base))

    try:
        if sub == "automation":
            automation = _fetch_automation_match(admin, r)
            body.extend(_automation_fix_body(automation, admin=admin))
        else:
            fix_vuln_id = _get_or_create_fix_vuln_id(admin, r, data.get("report_id"))
            steps_data = _fetch_fix_steps(admin, fix_vuln_id) if fix_vuln_id else None
            body.extend(_manual_fix_body(steps_data, r.get("operating_system"), value_base, step_number=step_number))
    except Exception:
        logger.exception("[TeamsBot] fix content fetch failed (sub=%s)", sub)
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "isSubtle": True, "spacing": "Medium"})
    return body


def vuln_detail_body(admin, idx, back_offset=0, sub="manual", step_number=None):
    """Reached from the flat All Vulns list — Back returns there."""
    return _vuln_detail_full_body(admin, idx, sub=sub, ctx="vulns", offset=back_offset, step_number=step_number)


def asset_vuln_detail_body(admin, idx, host, back_offset=0, sub="manual", step_number=None):
    """Reached from an asset's own vulnerability list — Back returns to
    that asset's detail page, not the flat All Vulns list."""
    return _vuln_detail_full_body(admin, idx, sub=sub, ctx="asset", host=host, offset=back_offset, step_number=step_number)


# ─── Common Vulns (team-scoped) ─────────────────────────────────────────

def _fetch_common_vulns_grouped(admin):
    from adminmitigationstrategy.views import MitigationStrategyByTeamAPIView
    from users.views import SlackSlashCommandView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(MitigationStrategyByTeamAPIView, admin, method="get")
    if status_code >= 300 or not isinstance(data, dict):
        raise ValueError(f"mitigation strategy fetch failed: {status_code}")
    return SlackSlashCommandView()._group_common_vulns_by_team(data)


def _combined_common_vulns_team(grouped):
    """Real request: an "All Teams" view across Common Vulns, not just one
    team at a time — synthesizes a pseudo-team from the 4 real ones,
    tagging each vuln with its real team's display name (via "_team_name",
    read back by common_vulns_list_body's own row rendering) since which
    team a vuln belongs to is no longer implied by a single selection."""
    all_vulns = []
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for key, team in (grouped or {}).items():
        for v in team.get("vulns") or []:
            tagged = dict(v)
            tagged["_team_name"] = team.get("display_name") or dict(cards.COMMON_VULNS_TEAMS).get(key, key)
            all_vulns.append(tagged)
        sev = team.get("severity") or {}
        for k in totals:
            totals[k] += sev.get(k, 0)
    return {"display_name": "All Teams", "severity": totals, "vulns": all_vulns}


def common_vulns_list_body(admin, team_key="config", sev="all", st="all", offset=0, prefix="fix_common"):
    """`prefix` lets the user (member) side reuse this exact function with
    its own "ufix_common_*" action-id family instead of admin's "fix_common_*"
    — the member-side dispatcher (user_actions.py's _FIX_ACTION_IDS) only
    recognizes the "ufix_"-prefixed ones, so passing admin's default here
    for a member card would leave every pagination/filter click on it
    unrecognized."""
    grouped = _fetch_common_vulns_grouped(admin)
    if team_key == "all":
        team = _combined_common_vulns_team(grouped)
    else:
        team = grouped.get(team_key) or {"display_name": dict(cards.COMMON_VULNS_TEAMS).get(team_key, team_key), "severity": {}, "vulns": []}
    all_vulns = team.get("vulns") or []
    sev_summary = team.get("severity") or {}

    # Common-vuln rows don't carry a `status` field of their own (each is
    # an aggregate across N assets, not a single vuln instance) — the
    # status filter here is applied per-ASSET within a vuln instead: a
    # vuln "matches" a status filter if at least one of its affected
    # assets is in that state, same spirit as the severity filter still
    # matching on the vuln's own aggregate severity.
    def _vuln_matches_status(v, target_st):
        if target_st == "all":
            return True
        assets = v.get("assets") or []
        return any(_match_status(a, target_st) for a in assets)

    # Keep each vuln's index into the FULL (unfiltered) team vulns list —
    # common_vuln_detail_body indexes back into that same full list, same
    # reasoning as vulns_list_body's own idx handling above.
    sev_base = [(i, v) for i, v in enumerate(all_vulns) if _match_sev(v, sev)]
    st_counts = {
        "all": len(sev_base),
        "open": sum(1 for _, v in sev_base if _vuln_matches_status(v, "open")),
        "closed": sum(1 for _, v in sev_base if _vuln_matches_status(v, "closed")),
        "in_progress": sum(1 for _, v in sev_base if _vuln_matches_status(v, "in_progress")),
    }
    indexed_vulns = [(i, v) for i, v in sev_base if _vuln_matches_status(v, st)]
    total = len(indexed_vulns)
    page = indexed_vulns[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "🧩 Common Vulnerabilities", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Vulnerabilities appearing on 4+ assets, by team.", "size": "Small", "isSubtle": True, "wrap": True},
        {
            "type": "TextBlock",
            "text": (f"{team.get('display_name', team_key)}  ·  Total Vulns: {len(all_vulns)}\n"
                     f"🔴 Critical: {sev_summary.get('critical', 0)}   🟠 High: {sev_summary.get('high', 0)}   "
                     f"🟡 Medium: {sev_summary.get('medium', 0)}   🟢 Low: {sev_summary.get('low', 0)}"),
            "size": "Small", "weight": "Bolder", "wrap": True, "spacing": "Small",
        },
        _sev_filter_columnset(f"{prefix}_vuln", sev, st, extra_value={"team": team_key}),
        _status_filter_columnset(f"{prefix}_vuln", sev, st, st_counts, extra_value={"team": team_key}),
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No common vulnerabilities for this team. Nothing appears on 4+ assets yet.", "size": "Small", "isSubtle": True, "spacing": "Medium", "wrap": True})
        return body
    for idx, v in page:
        vsev = (v.get("severity") or "medium").strip().lower()
        if vsev not in _SEV_ICON:
            vsev = "medium"
        asset_count = v.get("asset_count") or len(v.get("assets") or [])
        subtitle = f"💻 {asset_count} assets   ·   {_SEV_ICON[vsev]} {vsev.title()}"
        # Real request: show which team a vuln is assigned to — mainly
        # matters in "All Teams" view (see _combined_common_vulns_team's
        # "_team_name" tag) where it's no longer implied by the current
        # single-team selection.
        if v.get("_team_name"):
            subtitle += f"   ·   Team: {v['_team_name']}"
        body.append(_row(v.get("name") or "Unnamed vulnerability", subtitle, f"{prefix}_vuln_view", {"team": team_key, "idx": idx, "offset": offset}))
    body.extend(_pagination_body(offset, total, f"{prefix}_vuln_pg", {"team": team_key, "sev": sev, "st": st}))
    return body


def _find_row_idx_for_asset(admin, vuln_name, host):
    """Common Vulns' own data source (MitigationStrategyByTeamAPIView, an
    aggregate across assets) is separate from the flat register rows
    _vuln_detail_full_body indexes into — this bridges the two by matching
    on (vuln name, host), the same identity a real vulnerability instance
    has in both places, so a common vuln's own per-asset "View" can reuse
    the exact same Manual/Automation Fix detail every other entry point
    already renders instead of duplicating it."""
    rows = _fetch_register_rows(admin)
    for i, r in enumerate(rows):
        if (r.get("vul_name") or "").strip() == (vuln_name or "").strip() and (r.get("asset") or "").strip() == (host or "").strip():
            return i
    return None


def common_vuln_detail_body(admin, team_key, idx, back_offset=0, asset_offset=0, prefix="fix_common"):
    grouped = _fetch_common_vulns_grouped(admin)
    if team_key == "all":
        team = _combined_common_vulns_team(grouped)
    else:
        team = grouped.get(team_key) or {"vulns": []}
    vulns = team.get("vulns") or []

    body = [_back_action("← Back to Common Vulns", f"{prefix}_vuln_back", {"team": team_key, "offset": back_offset})]
    if idx is None or idx < 0 or idx >= len(vulns):
        body.append({"type": "TextBlock", "text": "This vulnerability could not be found — the report may have changed. Go back and try again.", "wrap": True, "spacing": "Medium"})
        return body
    v = vulns[idx]
    sev = (v.get("severity") or "medium").strip().lower()
    if sev not in _SEV_ICON:
        sev = "medium"
    assets = v.get("assets") or []
    total = len(assets)
    page = assets[asset_offset:asset_offset + PAGE_SIZE]
    body.append({"type": "TextBlock", "text": v.get("name") or "Unnamed vulnerability", "weight": "Bolder", "size": "Medium", "wrap": True, "spacing": "Medium"})
    sev_line = f"{_SEV_ICON[sev]} {sev.title()}   ·   Affects {total} asset(s)"
    if v.get("_team_name"):
        sev_line += f"   ·   Team: {v['_team_name']}"
    body.append({"type": "TextBlock", "text": sev_line, "size": "Small", "weight": "Bolder", "spacing": "Small"})
    for a in page:
        host = a.get("host") or "—"
        subtitle = _status_label(a.get('status'))
        body.append(_row(
            f"🖥 {host}", subtitle, f"{prefix}_vuln_asset_view",
            {"team": team_key, "idx": idx, "host": host, "offset": asset_offset, "back_offset": back_offset},
        ))
    body.extend(_pagination_body(asset_offset, total, f"{prefix}_vuln_asset_pg", {"team": team_key, "idx": idx, "back_offset": back_offset}))
    return body


def common_vuln_asset_detail_body(admin, team_key, idx, host, asset_offset=0, back_offset=0, sub="manual", step_number=None, prefix="fix_common"):
    """One specific (vuln, asset) instance's own Manual/Automation Fix
    detail, reached from common_vuln_detail_body's per-asset "View" —
    resolves the matching flat register row (see _find_row_idx_for_asset)
    and reuses _vuln_detail_full_body verbatim so this never drifts out
    of sync with the identical detail every other entry point shows.

    Real gotcha: _vuln_detail_full_body's own value_base already owns
    "idx" (the row_idx, for its Fix/Automation toggle + step-nav to
    refetch the SAME row) and "offset" (this call's own `offset` param).
    extra_value gets merged on TOP of those, so reusing either name here
    for the common-vuln's own idx/asset-list-offset would silently
    clobber the ones _vuln_detail_full_body needs — kept under distinct
    "cv_idx"/"cv_offset" keys instead (read back by the *_vuln_asset_back
    / *_vuln_toggle / *_step_nav handlers in actions.py/user_actions.py)."""
    grouped = _fetch_common_vulns_grouped(admin)
    team = _combined_common_vulns_team(grouped) if team_key == "all" else (grouped.get(team_key) or {"vulns": []})
    vulns = team.get("vulns") or []
    vuln_name = vulns[idx].get("name") if (idx is not None and 0 <= idx < len(vulns)) else None

    row_idx = _find_row_idx_for_asset(admin, vuln_name, host)
    return _vuln_detail_full_body(
        admin, row_idx, sub=sub, ctx="common", step_number=step_number,
        back_action_id=f"{prefix}_vuln_asset_back",
        back_title=f"← Back to {vuln_name or 'vulnerability'}",
        extra_value={"team": team_key, "cv_idx": idx, "host": host, "cv_offset": asset_offset, "back_offset": back_offset},
    )


# ─── Top-level entry point ──────────────────────────────────────────────

def fix_tab_body(admin, active_sub="fix_sub_assets", offset=0, common_team="config", sev="all", st="all"):
    """Sub-nav row + that sub-tab's real (clickable) content."""
    body = [cards._fix_subnav_columnset(active_sub)]
    try:
        if active_sub == "fix_sub_vulns":
            body.extend(vulns_list_body(admin, sev=sev, st=st, offset=offset))
        elif active_sub == "fix_sub_common":
            body.append(cards._common_vulns_team_columnset(common_team))
            body.extend(common_vulns_list_body(admin, team_key=common_team, sev=sev, st=st, offset=offset))
        else:
            body.extend(assets_list_body(admin, sev=sev, st=st, offset=offset))
    except Exception:
        logger.exception(f"[TeamsBot] fix_tab_body failed for {active_sub}")
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "spacing": "Medium"})
    return body
