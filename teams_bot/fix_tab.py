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


def _row(title_text, subtitle_text, action_id, value, size="Small", extra_actions=None):
    """One clickable list row — title/subtitle on the left, a real 'View'
    button on the right (matches Slack's section+accessory-button rows).
    `size` bumps both lines up together (e.g. "Default") for callers that
    want a larger read — defaults to "Small" so every other caller's
    layout is unchanged. `extra_actions` (Hold/Unhold/Delete, etc.) render
    alongside "View" in the same ActionSet when a caller needs more than
    one action per row — action_id/value can be None to omit "View"
    entirely (a row with only Hold/Unhold/Delete, no drill-down)."""
    actions = list(extra_actions or [])
    if action_id:
        actions.insert(0, cards._execute_action("View ›", {"action_id": action_id, **value}))
    return {
        "type": "ColumnSet",
        "spacing": "Medium",
        "separator": True,
        "columns": [
            {
                "type": "Column", "width": "stretch",
                "items": [
                    {"type": "TextBlock", "text": title_text, "weight": "Bolder", "size": size, "wrap": True},
                    {"type": "TextBlock", "text": subtitle_text, "size": size, "isSubtle": True, "wrap": True, "spacing": "None"},
                ],
            },
            {
                "type": "Column", "width": "auto", "verticalContentAlignment": "Center",
                "items": [{"type": "ActionSet", "actions": actions}],
            },
        ],
    }


# ─── Classification filter (Assets/Web App/Firewall/Server) — same
# taxonomy as the website's Assets tab and Slack's own Hold/Unhold/Delete
# feature (upload_report.asset_classification). Added as a supplemental
# filter alongside the existing severity/status pills, not a replacement
# — both All Assets and All Vulnerabilities keep their register-sourced
# data; classification/hold status is looked up per host_name and joined
# in, same approach Slack's _fix_subtab_blocks uses. ──────────────────────

CLASS_FILTERS = [("all", "All"), ("other", "Assets"), ("web_app", "Web App"), ("firewall", "Firewall"), ("server", "Server")]
_CLASS_LABEL = {"web_app": "Web App", "firewall": "Firewall", "server": "Server", "other": "Asset"}


def _match_class(atype, cls):
    return cls == "all" or (atype or "other") == cls


def _class_counts(items, type_key="asset_type"):
    """{"all": N, "other": n, "web_app": n, ...} from a list of dicts (or
    (i, r, atype)/(idx, r, atype) tuples — see call sites) each carrying
    their own classification. Same counts-in-the-pill-label convention as
    _status_filter_columnset's own STATUS_FILTERS."""
    counts = {"all": len(items), "other": 0, "web_app": 0, "firewall": 0, "server": 0}
    for item in items:
        atype = item.get(type_key, "other") if isinstance(item, dict) else item[-1]
        counts[atype] = counts.get(atype, 0) + 1
    return counts


def _class_filter_columnset(prefix, active_cls, counts, extra_value=None):
    extra_value = extra_value or {}
    options = [(k, f"{label} {counts.get(k, 0)}") for k, label in CLASS_FILTERS]
    return cards.pill_columnset(
        options, active_cls,
        lambda k: {"action_id": f"{prefix}_cls", "cls": k, "offset": 0, **extra_value},
    )


def _confirm_body(title, warning, confirm_action_id, confirm_val, cancel_action_id, cancel_val):
    """Generic destructive-action confirm screen — same Confirm/Cancel
    convention as team_tab.py's own delete-user flow (see its
    `_confirm_body`), duplicated here rather than imported to avoid a
    circular import (team_tab already imports FROM this module)."""
    return [
        {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "spacing": "Medium", "color": "attention", "wrap": True},
        {"type": "TextBlock", "text": warning, "wrap": True, "size": "Small"},
        {
            "type": "ActionSet", "spacing": "Medium",
            "actions": [
                cards._execute_action("✅ Yes, delete", {"action_id": confirm_action_id, **confirm_val}, style="destructive"),
                cards._execute_action("← Cancel", {"action_id": cancel_action_id, **cancel_val}),
            ],
        },
    ]


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


def script_download_url_ai(team_id, team_name, card_id, script_type="fix"):
    """Signed-URL download link for an AI-generated automation_card's
    fix/verify script — same signing/backend convention as
    script_download_url above, routed to TeamsAIScriptDownloadView (which
    reads vulnerability_cards.automation_card by card_id) instead of the
    curated automation_scripts library by plugin_id."""
    import time
    from urllib.parse import quote
    from django.conf import settings
    from users.views import _dashboard_image_signer

    token = _dashboard_image_signer().sign(team_id)
    backend = getattr(settings, "VAPTFIX_BACKEND_URL", "https://vaptbackend.secureitlab.com")
    return (
        f"{backend}/api/admin/users/teams/ai-script-download/?token={quote(token)}"
        f"&team={quote(team_name)}&card_id={quote(card_id)}&type={quote(script_type)}&t={int(time.time())}"
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


def _fetch_rows(caller, as_member=False, team_name=None):
    """admin -> _fetch_register_rows; member -> the team-scoped
    UserLatestVulnerabilityRegisterAPIView rows (same shape, same fields —
    see user_fix_tab.py's own module docstring)."""
    if not as_member:
        return _fetch_register_rows(caller)

    def _fetch():
        from userregister.views import UserLatestVulnerabilityRegisterAPIView
        from .actions import _call_view_in_process
        status_code, data = _call_view_in_process(
            UserLatestVulnerabilityRegisterAPIView, caller, method="get", data={"team": team_name},
        )
        if status_code >= 300 or not isinstance(data, dict):
            raise ValueError(f"user register fetch failed: {status_code}")
        return data
    return cached_fetch(f"user_register_data:{caller.id}:{team_name}", 20, _fetch).get("rows") or []


def bust_asset_vuln_caches(caller, as_member=False, team_name=None):
    """
    Called right after a real Hold/Unhold/Delete mutation — cached_fetch's
    own TTL (20s) would otherwise show the pre-mutation state for up to
    20s after the click that just changed it, on the very same list the
    user is looking at. Every cache key this feature reads from, busted
    for this exact caller/scope.
    """
    from django.core.cache import cache
    suffix = "member" if as_member else "admin"
    keys = [
        f"asset_class:{caller.id}:{suffix}:{team_name or ''}",
        f"held_assets:{caller.id}:{suffix}:{team_name or ''}",
        f"held_vulns:{caller.id}:{suffix}:{team_name or ''}",
    ]
    keys.append(f"user_register_data:{caller.id}:{team_name}" if as_member else f"register_data:{caller.id}")
    # all_vulns_totals/all_vulns_grouped are keyed by report_id too — look
    # it up (itself cached, so this doesn't add a real round trip) so the
    # grouped "All Vulnerabilities" list/detail screens don't keep showing
    # pre-mutation Hold/Delete state for up to 20s like the others would.
    try:
        report_id = _fetch_asset_classification_data(caller, as_member=as_member, team_name=team_name)["report_id"]
    except Exception:
        report_id = None
    if report_id:
        keys.append(f"all_vulns_totals:{caller.id}:{suffix}:{report_id}:{team_name or ''}")
        keys.append(f"all_vulns_grouped:{caller.id}:{suffix}:{report_id}:{team_name or ''}")
    for k in keys:
        cache.delete(f"teamsbot_cache:{k}")


def _fetch_asset_classification_data(caller, as_member=False, team_name=None):
    """
    Classification data for the Assets tab — via AdminAssetsAPIView (admin)
    or UserAssetsAPIView (as_member=True, team-scoped), the SAME real
    endpoint the website's own All Assets tab calls. Same data source
    Slack's Hold/Unhold/Delete + classification feature already uses
    (users.views.SlackSlashCommandView._fetch_asset_classification_map).

    Real bug report: this used to keep only a single {host: asset_type}
    map and recompute its OWN pill counts locally (one category per
    host) — that disagreed with the website's own numbers for the exact
    same report, because a host with mixed-nature findings counts toward
    EVERY category it has a finding in there (see AdminAssetsAPIView's
    own `categories` list per asset and its `asset_type_totals`), not
    just one. Now carries `categories_map` (host -> list of categories,
    for filtering) and `asset_type_totals` (the website's own precomputed
    pill counts) straight through instead of re-deriving either locally,
    so Teams' numbers can never drift from the website's again.
    """
    def _fetch():
        from .actions import _call_view_in_process
        if as_member:
            from userasset.views import UserAssetsAPIView
            data_kwargs = {"team": team_name} if team_name else None
            status_code, data = _call_view_in_process(UserAssetsAPIView, caller, method="get", data=data_kwargs)
        else:
            from adminasset.views import AdminAssetsAPIView
            status_code, data = _call_view_in_process(AdminAssetsAPIView, caller, method="get")
        if status_code >= 300 or not isinstance(data, dict):
            return {"map": {}, "categories_map": {}, "asset_type_totals": {}, "report_id": None}
        cmap = {}
        categories_map = {}
        for a in (data.get("assets") or []):
            host = a.get("asset")
            if not host:
                continue
            cmap[host] = a.get("asset_type") or "other"
            categories_map[host] = a.get("categories") or [cmap[host]]
        return {
            "map": cmap,
            "categories_map": categories_map,
            "asset_type_totals": data.get("asset_type_totals") or {},
            "total_assets": data.get("total_assets", len(cmap)),
            "report_id": data.get("report_id"),
        }
    key = f"asset_class:{caller.id}:{'member' if as_member else 'admin'}:{team_name or ''}"
    return cached_fetch(key, 20, _fetch)


def _fetch_held_assets_map(caller, as_member=False, team_name=None):
    """{host_name: held-asset info dict} — via AdminHoldAssetsAPIView or
    UserHoldAssetsAPIView (as_member=True, team-scoped)."""
    def _fetch():
        from .actions import _call_view_in_process
        if as_member:
            from userasset.views import UserHoldAssetsAPIView
            data_kwargs = {"team": team_name} if team_name else None
            status_code, data = _call_view_in_process(UserHoldAssetsAPIView, caller, method="get", data=data_kwargs)
        else:
            from adminasset.views import AdminHoldAssetsAPIView
            status_code, data = _call_view_in_process(AdminHoldAssetsAPIView, caller, method="get")
        if status_code >= 300 or not isinstance(data, dict):
            return {}
        return {a.get("asset"): a for a in (data.get("assets") or []) if a.get("asset")}
    key = f"held_assets:{caller.id}:{'member' if as_member else 'admin'}:{team_name or ''}"
    return cached_fetch(key, 20, _fetch)


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

def assets_list_body(admin, sev="all", st="all", cls="all", offset=0, as_member=False, team_name=None,
                      view_prefix="fix_asset", subtitle=None):
    rows = _fetch_rows(admin, as_member=as_member, team_name=team_name)
    sev_base = [r for r in rows if _match_sev(r, sev)]
    st_counts = _status_counts(sev_base)
    filtered_rows = [r for r in sev_base if _match_status(r, st)]
    assets = _group_assets(filtered_rows)

    class_data = _fetch_asset_classification_data(admin, as_member=as_member, team_name=team_name)
    class_map, report_id = class_data["map"], class_data["report_id"]
    categories_map = class_data["categories_map"]
    held_map = _fetch_held_assets_map(admin, as_member=as_member, team_name=team_name)

    # Real bug report: pill counts here used to be recomputed locally
    # (one category per host) and disagreed with the website's own All
    # Assets tab for the exact same report — a mixed-nature host counts
    # toward EVERY category it has a finding in on the website (see
    # AdminAssetsAPIView's own `categories` list), not just one. Use the
    # website's own precomputed asset_type_totals directly instead of
    # re-deriving a different number, and filter by full `categories`
    # membership (not a single asset_type) so a click on "Web App" shows
    # the exact same assets the website's own Web App tab would.
    cls_counts = {"all": class_data["total_assets"], **class_data["asset_type_totals"]}

    # Real bug report: _group_assets only ever creates an entry for a host
    # that appears in the vulnerability register rows — a host with ZERO
    # findings never has a row there at all, so it silently never showed
    # up in this list, even though the pill above correctly says 15 (it
    # comes from class_data["total_assets"], the website's own real asset
    # count, not from this row-derived list). The website's own All Assets
    # tab shows every asset regardless of vuln count. Only backfill these
    # when sev/st are both "all" — the sev/st pills filter real findings,
    # and a zero-vuln host has none to match a specific severity/status
    # against, so it's correctly absent from a filtered view, same as the
    # website's own per-severity breakdowns.
    if sev == "all" and st == "all":
        present_hosts = {a["host"] for a in assets}
        for host in class_map:
            if host not in present_hosts:
                assets.append({
                    "host": host, "total": 0, "status": "closed",
                    "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                })

    for a in assets:
        a["asset_type"] = class_map.get(a["host"], "other")
        a["categories"] = categories_map.get(a["host"], [a["asset_type"]])
    assets = [a for a in assets if cls == "all" or cls in a["categories"]]

    total = len(assets)
    page = assets[offset:offset + PAGE_SIZE]
    common_val = {"sev": sev, "st": st, "cls": cls, "report_id": report_id}

    body = [
        {"type": "TextBlock", "text": "💻 All Assets", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": subtitle or "Every asset in your latest report. Tap View to see its vulnerabilities.", "size": "Small", "isSubtle": True, "wrap": True},
        _sev_filter_columnset(view_prefix, sev, st, {"cls": cls}),
        _status_filter_columnset(view_prefix, sev, st, st_counts, {"cls": cls}),
        _class_filter_columnset(view_prefix, cls, cls_counts, {"sev": sev, "st": st}),
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No assets found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return _append_held_assets_section(body, held_map, view_prefix, common_val, offset)
    for a in page:
        # Real request: host name, vuln count, status, and classification
        # used to be on separate lines — combine them into one row so
        # they're all visible at a glance, and bump the font size up a
        # step for readability.
        #
        # Real bug report: a mixed-nature host matches a specific
        # classification pill (e.g. "Server") whenever that category is
        # anywhere in its `categories` list, but this label only ever
        # showed the host's single PRIMARY asset_type — a host primarily
        # classified "Asset" with a secondary "Server" finding correctly
        # appeared under the Server pill, yet still displayed "Asset" on
        # its own row. When a specific pill is active, show that pill's
        # own label instead; only fall back to the host's primary type
        # under "All".
        #
        # Real bug report #2: even under "All", a host whose own base
        # asset_type is "other" but has a specific finding-level category
        # too (e.g. an OpenSSH finding classified "server" — see
        # classify_finding_type's own docstring for why a host's
        # categories can include more than its base type) always showed
        # "Other" here — technically its primary type, but misleading when
        # it's also genuinely counted under "Server". Prefer any specific
        # category over "other" when one exists.
        if cls != "all":
            row_label = _CLASS_LABEL.get(cls, "Asset")
        else:
            specific = next((c for c in a["categories"] if c != "other"), None)
            row_label = _CLASS_LABEL.get(specific or a['asset_type'], "Asset")
        title = f"🖥 {a['host']}   ·   {a['total']} Vulns   ·   {_status_label(a['status'])}   ·   {row_label}"
        val = {"host": a["host"], "offset": offset, **common_val}
        extra = [cards._execute_action(
            "⏸ Hold", {"action_id": f"{view_prefix}_hold", **val},
        )] if a["host"] not in held_map else []
        extra.append(cards._execute_action(
            "🗑 Delete", {"action_id": f"{view_prefix}_delete_confirm", **val}, style="destructive",
        ))
        body.append(_row(
            title, _sev_dots_text(a["counts"]), f"{view_prefix}_view", {"host": a["host"], "offset": offset},
            size="Default", extra_actions=extra,
        ))
    body.extend(_pagination_body(offset, total, f"{view_prefix}_pg", common_val))
    return _append_held_assets_section(body, held_map, view_prefix, common_val, offset)


def _append_held_assets_section(body, held_map, view_prefix, common_val, offset, limit=10):
    """Real request (mirrors Slack's own Hold/Unhold/Delete feature):
    a held asset is pulled out of the main list above (it has no open
    findings left to show there), so without this it would look like
    holding an asset just made it disappear with no way back."""
    if not held_map:
        return body
    body.append({"type": "TextBlock", "text": "🔒 Held Assets", "weight": "Bolder", "size": "Medium", "spacing": "Large"})
    for host, info in list(held_map.items())[:limit]:
        sc = info.get("severity_counts") or {}
        atype = info.get("asset_type") or "other"
        title = f"🖥 {host}   ·   {_CLASS_LABEL.get(atype, 'Asset')}"
        val = {"host": host, "offset": offset, **common_val}
        body.append(_row(
            title, _sev_dots_text(sc), None, None,
            extra_actions=[cards._execute_action("🔓 Unhold", {"action_id": f"{view_prefix}_unhold", **val})],
        ))
    if len(held_map) > limit:
        body.append({"type": "TextBlock", "text": f"+ {len(held_map) - limit} more held not shown.", "size": "Small", "isSubtle": True, "spacing": "Small"})
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

def _fetch_held_vulns_map(caller, as_member=False, team_name=None):
    """{(plugin_name, host_name): held-doc} — via VulnHoldListByReportAPIView
    (admin) or UserVulnHoldListByReportAPIView (as_member=True), report_id
    resolved from the SAME classification fetch (no extra round trip)."""
    def _fetch():
        from .actions import _call_view_in_process
        class_data = _fetch_asset_classification_data(caller, as_member=as_member, team_name=team_name)
        report_id = class_data["report_id"]
        if not report_id:
            return {}
        if as_member:
            from userasset.views import UserVulnHoldListByReportAPIView
            status_code, data = _call_view_in_process(
                UserVulnHoldListByReportAPIView, caller, method="get", url_kwargs={"report_id": report_id},
            )
        else:
            from adminasset.views import VulnHoldListByReportAPIView
            status_code, data = _call_view_in_process(
                VulnHoldListByReportAPIView, caller, method="get", url_kwargs={"report_id": report_id},
            )
        if status_code >= 300 or not isinstance(data, dict):
            return {}
        held = {}
        for v in (data.get("vulnerabilities") or []):
            for h in (v.get("hosts") or []):
                held[(v.get("plugin_name"), h.get("host_name"))] = {
                    "plugin_name": v.get("plugin_name"), "severity": v.get("severity"),
                    "host_name": h.get("host_name"), "asset_type": h.get("asset_type"),
                }
        return held
    key = f"held_vulns:{caller.id}:{'member' if as_member else 'admin'}:{team_name or ''}"
    return cached_fetch(key, 20, _fetch)


def _fetch_all_vulnerabilities_totals(caller, report_id, as_member=False, team_name=None):
    """
    asset_type_totals (+ total) straight from AllVulnerabilitiesAPIView/
    UserAllVulnerabilitiesAPIView — the SAME real endpoint the website's
    own All Vulnerabilities tab calls for its classification pill counts.
    Real bug report: this tab used to recompute its own pill counts from
    the flat register rows (one row per vuln+host pair) instead, which
    counts differently than the website's own grouped-by-plugin-name
    logic and disagreed with it for the exact same report.

    Real bug report #2: on the member side, this never passed `team_name`
    through to UserAllVulnerabilitiesAPIView at all (unlike
    _fetch_asset_classification_data's own member path, which does) —
    the API silently fell back to combining ALL of the member's teams
    instead of scoping to whichever one was actually selected, and since
    the cache key below also didn't include team_name, switching teams
    could keep showing the FIRST team's numbers even after that.
    """
    def _fetch():
        from .actions import _call_view_in_process
        if as_member:
            from userasset.views import UserAllVulnerabilitiesAPIView
            data_kwargs = {"team": team_name} if team_name else None
            status_code, data = _call_view_in_process(
                UserAllVulnerabilitiesAPIView, caller, method="get", url_kwargs={"report_id": report_id}, data=data_kwargs,
            )
        else:
            from adminasset.views import AllVulnerabilitiesAPIView
            status_code, data = _call_view_in_process(
                AllVulnerabilitiesAPIView, caller, method="get", url_kwargs={"report_id": report_id},
            )
        if status_code >= 300 or not isinstance(data, dict):
            return {"total": 0, "asset_type_totals": {}}
        return {"total": data.get("total", 0), "asset_type_totals": data.get("asset_type_totals") or {}}
    key = f"all_vulns_totals:{caller.id}:{'member' if as_member else 'admin'}:{report_id}:{team_name or ''}"
    return cached_fetch(key, 20, _fetch)


def _fetch_grouped_vulnerabilities(caller, report_id, as_member=False, team_name=None):
    """
    Full AllVulnerabilitiesAPIView/UserAllVulnerabilitiesAPIView response —
    one entry per DISTINCT vulnerability (grouped by plugin_name), each
    carrying its own `hosts` list (host_name/asset_type/status per
    affected asset) — everything a "N asset(s) affected" list row plus its
    own per-asset drill-down screen needs, no separate fetch per
    vulnerability required. Same endpoint _fetch_all_vulnerabilities_totals
    already calls for pill counts, kept separate since that one discards
    everything except the totals.
    """
    def _fetch():
        from .actions import _call_view_in_process
        if as_member:
            from userasset.views import UserAllVulnerabilitiesAPIView
            data_kwargs = {"team": team_name} if team_name else None
            status_code, data = _call_view_in_process(
                UserAllVulnerabilitiesAPIView, caller, method="get", url_kwargs={"report_id": report_id}, data=data_kwargs,
            )
        else:
            from adminasset.views import AllVulnerabilitiesAPIView
            status_code, data = _call_view_in_process(
                AllVulnerabilitiesAPIView, caller, method="get", url_kwargs={"report_id": report_id},
            )
        if status_code >= 300 or not isinstance(data, dict):
            return []
        return data.get("vulnerabilities") or []
    key = f"all_vulns_grouped:{caller.id}:{'member' if as_member else 'admin'}:{report_id}:{team_name or ''}"
    return cached_fetch(key, 20, _fetch)


def vulns_list_body(admin, sev="all", st="all", cls="all", offset=0, as_member=False, team_name=None,
                     view_prefix="fix_vuln", subtitle=None):
    rows = _fetch_rows(admin, as_member=as_member, team_name=team_name)
    # Keep the index into the FULL unfiltered list — "View" hands back an
    # idx the shared vuln-detail body resolves again from that same full
    # list (same reasoning as asset_detail_body's own host_rows indices).
    sev_base = [(i, r) for i, r in enumerate(rows) if _match_sev(r, sev)]
    st_counts = _status_counts([r for _, r in sev_base])
    filtered = [(i, r) for i, r in sev_base if _match_status(r, st)]

    class_data = _fetch_asset_classification_data(admin, as_member=as_member, team_name=team_name)
    class_map, categories_map, report_id = class_data["map"], class_data["categories_map"], class_data["report_id"]

    def _display_type(host):
        cats = categories_map.get(host) or []
        specific = next((c for c in cats if c != "other"), None)
        return specific or class_map.get(host, "other")

    # Real bug report: a host whose own base asset_type is "other" but has
    # a specific finding-level category too (e.g. an OpenSSH finding
    # classified "server") matches the Server pill correctly (that's what
    # `categories` is for), but this per-row label always showed the
    # host's base type regardless, so a host genuinely counted under
    # Server still always displayed "Asset". Prefer any specific category
    # over "other" here too.
    filtered = [
        (i, r, _display_type((r.get("asset") or "").strip()))
        for i, r in filtered
    ]
    # Real bug report: pill counts here used to be recomputed locally from
    # these flat register rows (one row per vuln+host pair — the same
    # vulnerability on 3 hosts counts 3 times) instead of the website's
    # own AllVulnerabilitiesAPIView numbers (one entry per DISTINCT
    # vulnerability) — disagreed with the website for the exact same
    # report. Pull the real totals straight from that same endpoint;
    # per-row filtering below still checks this row's own host against
    # its full `categories` list (not just its single primary asset_type)
    # so a click on a pill shows every row genuinely in that category.
    real_totals = _fetch_all_vulnerabilities_totals(admin, report_id, as_member=as_member, team_name=team_name) if report_id else {"total": 0, "asset_type_totals": {}}
    cls_counts = {"all": real_totals["total"], **real_totals["asset_type_totals"]}
    filtered = [
        (i, r, atype) for i, r, atype in filtered
        if cls == "all" or cls in categories_map.get((r.get("asset") or "").strip(), [atype])
    ]

    total = len(filtered)
    page = filtered[offset:offset + PAGE_SIZE]
    common_val = {"sev": sev, "st": st, "cls": cls, "report_id": report_id}
    held_map = _fetch_held_vulns_map(admin, as_member=as_member, team_name=team_name)

    body = [
        {"type": "TextBlock", "text": "📋 All Vulnerabilities", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": subtitle or "Every vulnerability in your latest report.", "size": "Small", "isSubtle": True, "wrap": True},
        _sev_filter_columnset(view_prefix, sev, st, {"cls": cls}),
        _status_filter_columnset(view_prefix, sev, st, st_counts, {"cls": cls}),
        _class_filter_columnset(view_prefix, cls, cls_counts, {"sev": sev, "st": st}),
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No vulnerabilities found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return _append_held_vulns_section(body, held_map, view_prefix, common_val, offset)
    for idx, r, atype in page:
        name = r.get("vul_name") or "Unnamed vulnerability"
        rsev = (r.get("severity") or "medium").strip().lower()
        if rsev not in _SEV_ICON:
            rsev = "medium"
        host = r.get("asset") or "—"
        status = r.get("status") or "open"
        subtitle = f"{host}   ·   {_status_label(status)}   ·   {_CLASS_LABEL.get(atype, 'Asset')}"
        val = {"host": host, "plugin_name": name, "offset": offset, **common_val}
        extra = [
            cards._execute_action("⏸ Hold", {"action_id": f"{view_prefix}_hold", **val}),
            cards._execute_action("🗑 Delete", {"action_id": f"{view_prefix}_delete_confirm", **val}, style="destructive"),
        ]
        body.append(_row(
            f"{_SEV_ICON[rsev]} {name}", subtitle, f"{view_prefix}_view", {"idx": idx, "offset": offset},
            extra_actions=extra,
        ))
    body.extend(_pagination_body(offset, total, f"{view_prefix}_pg", common_val))
    return _append_held_vulns_section(body, held_map, view_prefix, common_val, offset)


def _append_held_vulns_section(body, held_map, view_prefix, common_val, offset, limit=10):
    if not held_map:
        return body
    body.append({"type": "TextBlock", "text": "🔒 Held Vulnerabilities", "weight": "Bolder", "size": "Medium", "spacing": "Large"})
    for (plugin_name, host), info in list(held_map.items())[:limit]:
        rsev = (info.get("severity") or "medium").strip().lower()
        if rsev not in _SEV_ICON:
            rsev = "medium"
        atype = info.get("asset_type") or "other"
        title = f"{_SEV_ICON[rsev]} {plugin_name}"
        subtitle = f"{host}   ·   {_CLASS_LABEL.get(atype, 'Asset')}"
        val = {"host": host, "plugin_name": plugin_name, "offset": offset, **common_val}
        body.append(_row(
            title, subtitle, None, None,
            extra_actions=[cards._execute_action("🔓 Unhold", {"action_id": f"{view_prefix}_unhold", **val})],
        ))
    if len(held_map) > limit:
        body.append({"type": "TextBlock", "text": f"+ {len(held_map) - limit} more held not shown.", "size": "Small", "isSubtle": True, "spacing": "Small"})
    return body


# ─── All Vulns (grouped by finding — real request: show how many assets
# EACH distinct vulnerability affects, matching Slack's own grouped view
# (_format_grouped_vulns_list/_format_vuln_assets_detail), instead of the
# flat per-host list above (vulns_list_body) which never showed a
# per-finding asset count at all. ────────────────────────────────────────

def grouped_vulns_list_body(admin, cls="all", offset=0, as_member=False, team_name=None, view_prefix="fix_gvuln", subtitle=None):
    """One row per DISTINCT finding (grouped by plugin_name, via the same
    AllVulnerabilitiesAPIView/UserAllVulnerabilitiesAPIView the website's
    own All Vulnerabilities tab uses) — "N asset(s) affected", open/held
    breakdown, Hold All/Delete All, and a "View" into
    grouped_vuln_assets_detail_body for the per-asset list."""
    class_data = _fetch_asset_classification_data(admin, as_member=as_member, team_name=team_name)
    report_id = class_data["report_id"]
    vulns = _fetch_grouped_vulnerabilities(admin, report_id, as_member=as_member, team_name=team_name) if report_id else []
    real_totals = _fetch_all_vulnerabilities_totals(admin, report_id, as_member=as_member, team_name=team_name) if report_id else {"total": 0, "asset_type_totals": {}}
    cls_counts = {"all": real_totals["total"], **real_totals["asset_type_totals"]}

    def _matches_cls(v):
        return cls == "all" or (v.get("asset_type_counts") or {}).get(cls, 0) > 0

    filtered = [v for v in vulns if _matches_cls(v)]
    total = len(filtered)
    page = filtered[offset:offset + PAGE_SIZE]
    common_val = {"cls": cls, "report_id": report_id or ""}

    body = [
        {"type": "TextBlock", "text": "📋 All Vulnerabilities", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": subtitle or "Every distinct vulnerability in your latest report.", "size": "Small", "isSubtle": True, "wrap": True},
        _class_filter_columnset(view_prefix, cls, cls_counts),
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No vulnerabilities found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for v in page:
        name = v.get("plugin_name") or "Unnamed vulnerability"
        rsev = (v.get("severity") or "medium").strip().lower()
        if rsev not in _SEV_ICON:
            rsev = "medium"
        hosts = v.get("hosts") or []
        open_hosts = [h for h in hosts if (h.get("status") or "open") != "held"]
        held_count = len(hosts) - len(open_hosts)
        subtitle_txt = f"{len(hosts)} asset(s) affected   ·   {len(open_hosts)} open, {held_count} held"
        val = {"plugin_name": name, "offset": offset, **common_val}
        extra = []
        if open_hosts:
            extra.append(cards._execute_action("⏸ Hold All", {"action_id": f"{view_prefix}_hold_all", **val}))
            extra.append(cards._execute_action("🗑 Delete All", {"action_id": f"{view_prefix}_delete_all_confirm", **val}, style="destructive"))
        body.append(_row(
            f"{_SEV_ICON[rsev]} {name}", subtitle_txt, f"{view_prefix}_view", val,
            extra_actions=extra,
        ))
    body.extend(_pagination_body(offset, total, f"{view_prefix}_pg", common_val))
    return body


def grouped_vuln_assets_detail_body(admin, plugin_name, list_offset=0, cls="all", report_id=None, as_member=False, team_name=None, view_prefix="fix_gvuln"):
    """The "View" target for grouped_vulns_list_body — every asset one
    specific finding affects, each with its own Hold/Unhold/Delete.
    Mirrors Slack's _format_vuln_assets_detail (and its team-scoped
    _format_team_vuln_assets_detail mirror)."""
    vulns = _fetch_grouped_vulnerabilities(admin, report_id, as_member=as_member, team_name=team_name) if report_id else []
    v = next((x for x in vulns if (x.get("plugin_name") or "") == plugin_name), None)
    common_val = {"cls": cls, "report_id": report_id or ""}
    back_val = {"offset": list_offset, **common_val}
    body = [_back_action("← Back to All Vulnerabilities", f"{view_prefix}_back", back_val)]
    if not v:
        body.append({"type": "TextBlock", "text": f"❌ \"{plugin_name}\" could not be found — it may have just been deleted or fully held.", "wrap": True, "spacing": "Medium"})
        return body

    sev = (v.get("severity") or "Medium").strip() or "Medium"
    hosts = v.get("hosts") or []
    open_hosts = [h for h in hosts if (h.get("status") or "open") != "held"]
    held_hosts = [h for h in hosts if (h.get("status") or "open") == "held"]
    body.append({"type": "TextBlock", "text": f"🛡 {plugin_name}", "weight": "Bolder", "size": "Medium", "spacing": "Medium", "wrap": True})
    body.append({"type": "TextBlock", "text": f"{sev} severity   ·   {len(hosts)} asset(s) affected", "size": "Small", "isSubtle": True})

    # Real request: each asset row gets a View too, opening that asset's
    # own full vulnerability list (the same "fix_asset_view"/"ufix_asset_view"
    # target the All Assets tab's own row already uses) — same pattern as
    # Slack's _format_vuln_assets_detail.
    asset_view_action_id = "ufix_asset_view" if as_member else "fix_asset_view"
    asset_val_base = {"plugin_name": plugin_name, "list_offset": list_offset, **common_val}
    if not open_hosts:
        body.append({"type": "TextBlock", "text": "No open assets for this finding.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
    for h in open_hosts:
        host_name = h.get("host_name") or "Unknown"
        st = h.get("status") or "open"
        atype = h.get("asset_type") or "other"
        subtitle_txt = f"{_CLASS_LABEL.get(atype, 'Asset')}   ·   {_status_label(st)}"
        val = {"host": host_name, **asset_val_base}
        extra = [
            cards._execute_action("⏸ Hold", {"action_id": f"{view_prefix}_asset_hold", **val}),
            cards._execute_action("🗑 Delete", {"action_id": f"{view_prefix}_asset_delete_confirm", **val}, style="destructive"),
        ]
        body.append(_row(f"🖥 {host_name}", subtitle_txt, asset_view_action_id, {"host": host_name, "offset": 0}, extra_actions=extra))

    if held_hosts:
        body.append({"type": "TextBlock", "text": "🔒 Held", "weight": "Bolder", "size": "Medium", "spacing": "Large"})
        for h in held_hosts:
            host_name = h.get("host_name") or "Unknown"
            atype = h.get("asset_type") or "other"
            val = {"host": host_name, **asset_val_base}
            body.append(_row(
                f"🖥 {host_name}", _CLASS_LABEL.get(atype, "Asset"), asset_view_action_id, {"host": host_name, "offset": 0},
                extra_actions=[cards._execute_action("🔓 Unhold", {"action_id": f"{view_prefix}_asset_unhold", **val})],
            ))
    return body


def grouped_vuln_delete_all_confirm_body(plugin_name, val, view_prefix="fix_gvuln"):
    return _confirm_body(
        f"⚠️ Delete \"{plugin_name}\" from ALL affected assets?",
        "This removes this vulnerability from every open asset it currently affects. An admin can restore it from the website if needed.",
        f"{view_prefix}_delete_all_do", val,
        f"{view_prefix}_back", val,
    )


def grouped_vuln_asset_delete_confirm_body(plugin_name, host, val, view_prefix="fix_gvuln"):
    return _confirm_body(
        f"⚠️ Delete \"{plugin_name}\" on {host}?",
        "This removes this vulnerability from the Vulnerabilities list for this asset. An admin can restore it from the website if needed.",
        f"{view_prefix}_asset_delete_do", val,
        f"{view_prefix}_view", val,
    )


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


def card_severity(card):
    """
    Canonical severity for one vulnerability_cards document.

    Real bug report (round 2): the first fix here made vaptcode_analysis.
    severity (the Vulnerability Analyst agent's own assessment) win over
    automation_card.severity — that closed most mismatches, but a live
    report still showed a real one: "SSL Certificate Chain Contains RSA
    Keys..." on 192.168.0.2 was Low on Register, High here. Register's
    severity was NEVER an AI value at all — it's the raw Nessus
    risk_factor straight from vulnerabilities_by_host (see
    adminregister.views.LatestSuperAdminVulnerabilityRegisterAPIView), and
    vaptcode_analysis.severity is ALSO just an AI reassessment that can
    disagree with the real scan data, same as automation_card.severity
    could.

    true_severity — injected onto every card by
    upload_report.views.VulnerabilityCardListView /
    UserVulnerabilityCardListAPIView (via _true_severity_lookup, which
    reads that exact same raw vulnerabilities_by_host data) — is the only
    genuinely authoritative source and now wins outright. The two AI
    fields stay as fallbacks only for the rare case the raw lookup found
    nothing (e.g. a finding whose plugin_name no longer matches after a
    report re-scan).
    """
    return (
        card.get("true_severity")
        or (card.get("vaptcode_analysis") or {}).get("severity")
        or (card.get("automation_card") or {}).get("severity")
        or ""
    )


# ─── Manual Fix / Automated Fix (matches Microsoft -Admin/vulndetail.html,
# real data instead of that mockup's hardcoded sample) ───────────────────
# Mirrors users.views.SlackSlashCommandView._allvuln_detail_blocks — same
# vulnerability_cards.automation_card data source, same read-only-for-admin
# behaviour (no run/mark-complete actions here, matching the website's
# admin-is-read-only rule).

def _fetch_automation_cards_for_report(caller, report_id, as_member=False):
    """
    Every vulnerability_cards document for this report_id, via
    VulnerabilityCardListView (admin caller) — same source automations_tab.py
    already reads for the report-wide Full/Partial tab — or
    UserVulnerabilityCardListAPIView (as_member=True) when `caller` is a
    team member, not the admin.

    Real gotcha: VulnerabilityCardListView filters by
    admin_email == request.user's OWN email — calling it in-process AS a
    team member (a different email than the report's owning admin) would
    silently match zero cards every time, not raise an error, so this
    would have looked like "automation just never generated" for every
    single member-side Automation Fix click. UserVulnerabilityCardListAPIView
    resolves the member's own admin internally instead (same as every
    other user_* endpoint), so member callers must go through that one.
    Cached per-caller, same convention as _fetch_register_data above.
    """
    def _fetch():
        from .actions import _call_view_in_process
        if as_member:
            from upload_report.views import UserVulnerabilityCardListAPIView
            status_code, data = _call_view_in_process(
                UserVulnerabilityCardListAPIView, caller, data={"report_id": report_id}, method="get",
            )
        else:
            from upload_report.views import VulnerabilityCardListView
            status_code, data = _call_view_in_process(
                VulnerabilityCardListView, caller, data={"report_id": report_id}, method="get",
            )
        if status_code >= 300 or not isinstance(data, dict):
            return []
        return data.get("cards") or []
    return cached_fetch(f"automation_cards:{caller.id}:{'member' if as_member else 'admin'}", 20, _fetch)


def _fetch_automation_from_card(admin, r, report_id, as_member=False):
    """
    Automation Fix button's real data source — matches this exact
    (vulnerability, host) instance against the admin's own
    vulnerability_cards for this report and returns its AI-generated
    automation_card, reshaped into the same dict shape _automation_fix_body
    already expects (matched/premium_required/message/severity/os/
    language/automation_possible/script_description/... — the OLD curated-
    library response shape), so _automation_fix_body itself needs no
    changes.

    Real bug report: the Automation Fix button only ever checked the
    curated ~63-plugin automation_scripts library (the old
    _fetch_automation_match, matched by plugin_id) — any vulnerability
    outside that fixed set (the vast majority of a real report) always
    showed "Automation script not ready for this vulnerability" even when
    the AI Automation Engineer had already generated a real automation_card
    for it (confirmed live: SNMP plugin_id=41028 — in the curated library —
    showed full detail, HP LaserJet RCE — not in it — showed "not ready"
    even though its own automation_card existed). Reads from the same
    source automations_tab.py / the website Script tab now use.

    as_member=True (passed by user_fix_tab.py) — `admin` here is actually
    the calling TEAM MEMBER, not the admin; see
    _fetch_automation_cards_for_report's own docstring for why this can't
    just reuse the admin call path.
    """
    if not report_id:
        return {"matched": False, "message": "No automated fix available for this vulnerability."}
    host_name = (r.get("asset") or "").strip()
    vuln_name = (r.get("vul_name") or "").strip()
    if not vuln_name:
        return {"matched": False, "message": "No automated fix available for this vulnerability."}

    cards_list = _fetch_automation_cards_for_report(admin, report_id, as_member=as_member)
    card = None
    for c in cards_list:
        if (c.get("vulnerability_name") or "").strip().lower() != vuln_name.lower():
            continue
        if host_name and (c.get("host_name") or "").strip() != host_name:
            continue
        card = c
        break
    if not card:
        return {"matched": False, "message": "No automated fix available for this vulnerability."}
    return shape_automation_detail(card)


def shape_automation_detail(card):
    """
    Reshapes ONE vulnerability_cards document's automation_card into the
    dict shape _automation_fix_body expects (matched/premium_required/
    message/severity/os/language/automation_possible/script_description/
    ... — the OLD curated-library response shape) — shared by
    _fetch_automation_from_card (matches by vuln+host first) and
    automations_tab.py's own View-button detail drill-down (already has
    the exact card via card_id, no matching needed).
    """
    automation = card.get("automation_card") or {}
    if not automation or automation.get("automation_status") is None:
        if automation.get("premium_required"):
            return {
                "matched": True, "premium_required": True,
                "message": automation.get("message") or "Automation scripts are a Premium/Custom feature — upgrade your plan to generate one for this vulnerability.",
            }
        return {"matched": False, "message": "Automation analysis for this vulnerability is still being generated — check back shortly."}

    if automation.get("automation_status") == "not_possible":
        return {
            "matched": True,
            "automation_possible": "No",
            "severity": card_severity(card),
            "os": automation.get("os"),
            "reason_not_possible": automation.get("reason_not_possible"),
        }

    return {
        "matched": True,
        "premium_required": bool(automation.get("premium_required")),
        "message": automation.get("message"),
        "card_id": card.get("card_id"),
        "vulnerability": card.get("vulnerability_name") or automation.get("vulnerability"),
        "severity": card_severity(card),
        "os": automation.get("os"),
        "available_os": [automation.get("os")] if automation.get("os") else [],
        "language": automation.get("language"),
        "automation_possible": automation.get("automation_possible"),
        # Still reshaped for the list views (Automations tab, Register->
        # Scripts) that show a download count per row — the detail page's
        # own "Downloaded" field was removed per explicit request.
        "download_count": automation.get("download_count", 0),
        "script_name": automation.get("script_name"),
        "script_description": automation.get("script_description"),
        "recommended_approach": automation.get("recommended_approach"),
        "what_can_be_automated": automation.get("what_can_be_automated"),
        "what_must_remain_manual": automation.get("what_must_remain_manual"),
        "libraries": automation.get("libraries"),
        "command_download_libraries": automation.get("command_download_libraries"),
        "command_run_script": automation.get("command_run_script"),
        "considerations_before": automation.get("considerations_before"),
        "considerations_after": automation.get("considerations_after"),
        "tested_manually": automation.get("tested_manually"),
        "fix_script_name": automation.get("fix_script_filename") or automation.get("script_name") or "automation_fix",
        # Real gap: neither Slack nor Teams had any way to know a verify
        # script even existed for this card — both only ever offered a
        # "Download Fix Script" action, with no equivalent for
        # automation_card.verify_script (which the website already
        # surfaces as its own separate "Download Verify Script" button).
        # Only a bool, never the raw script content — same rule as
        # fix_script above, actual download stays behind the authenticated
        # /automation-scripts/ai/<card_id>/download/?type=verify endpoint.
        "has_verify_script": bool((automation.get("verify_script") or "").strip()),
        "verify_script_name": automation.get("verify_script_filename") or None,
    }


def _automation_fix_body(automation, admin=None):
    if not automation.get("matched"):
        return [{"type": "TextBlock", "text": "Automation script not ready for this vulnerability.", "wrap": True, "isSubtle": True, "spacing": "Medium"}]

    # Plan gate — _fetch_automation_from_card (in this file and
    # user_fix_tab.py) already strips the actual script content and adds
    # premium_required/message when the plan doesn't allow automation
    # scripts (mirroring VulnerabilityCardListView's own Freemium lock) —
    # show that lock notice explicitly here instead of silently rendering
    # a near-empty FactSet with none of the "What this does"/etc. sections.
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

    # AI-assessed as genuinely not automatable (automation_status ==
    # "not_possible") — say so plainly with the AI's own reason, rather
    # than falling into the generic FactSet below with every content
    # section empty (which used to read as "an automation exists but
    # nothing was said about it", not "this can't be automated").
    if automation.get("automation_possible") == "No":
        body = [
            {
                "type": "FactSet",
                "facts": [
                    {"title": "Severity", "value": str(automation.get("severity") or "—")},
                    {"title": "OS", "value": str(automation.get("os") or "—")},
                ],
            },
            {
                "type": "TextBlock",
                "text": "🚫 Automation is not possible for this vulnerability — manual remediation required.",
                "wrap": True, "weight": "Bolder", "spacing": "Medium",
            },
        ]
        reason = automation.get("reason_not_possible")
        if reason:
            body.append({"type": "TextBlock", "text": str(reason)[:800], "wrap": True, "size": "Small", "isSubtle": True})
        return body

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
    if automation.get("command_run_script"):
        body.append({"type": "TextBlock", "text": "**Run command**", "wrap": True, "size": "Small", "spacing": "Medium"})
        body.append({"type": "TextBlock", "text": str(automation["command_run_script"]), "wrap": True, "size": "Small", "fontType": "Monospace"})
    add("Before running", "considerations_before")
    add("After running", "considerations_after")

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
            automation = _fetch_automation_from_card(admin, r, data.get("report_id"))
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
    # Real bug report: `grouped` (from _group_common_vulns_by_team) already
    # has its OWN "all" key — the every-team aggregate, deduped by plugin
    # name across teams and tagged with the generic "All Teams" display
    # name. Not skipping it here meant every vuln got added TWICE: once
    # correctly under its real team (config/pm/ns/af), and again from the
    # "all" bucket itself, mislabeled "Team: All Teams" — exactly the
    # duplicate rows seen in the Common Vulnerabilities > All Teams list.
    all_vulns = []
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for key, team in (grouped or {}).items():
        if key == "all":
            continue
        for v in team.get("vulns") or []:
            tagged = dict(v)
            tagged["_team_name"] = team.get("display_name") or dict(cards.COMMON_VULNS_TEAMS).get(key, key)
            all_vulns.append(tagged)
        sev = team.get("severity") or {}
        for k in totals:
            totals[k] += sev.get(k, 0)
    return {"display_name": "All Teams", "severity": totals, "vulns": all_vulns}


def common_vulns_list_body(admin, team_key="all", sev="all", st="all", offset=0, prefix="fix_common"):
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

def fix_tab_body(admin, active_sub="fix_sub_assets", offset=0, common_team="all", sev="all", st="all", cls="all"):
    """Sub-nav row + that sub-tab's real (clickable) content.

    Real bug report: clicking the Common Vulns nav tab landed on
    'Configuration Management' by default (the OLD default before "All
    Teams" existed at all) instead of showing everything — defaults to
    "all" now, matching the newly-added All Teams option's own place at
    the front of COMMON_VULNS_TEAMS."""
    body = [cards._fix_subnav_columnset(active_sub)]
    try:
        if active_sub == "fix_sub_vulns":
            body.extend(grouped_vulns_list_body(admin, cls=cls, offset=offset))
        elif active_sub == "fix_sub_common":
            body.append(cards._common_vulns_team_columnset(common_team))
            body.extend(common_vulns_list_body(admin, team_key=common_team, sev=sev, st=st, offset=offset))
        else:
            body.extend(assets_list_body(admin, sev=sev, st=st, cls=cls, offset=offset))
    except Exception:
        logger.exception(f"[TeamsBot] fix_tab_body failed for {active_sub}")
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "spacing": "Medium"})
    return body


# ─── Hold/Unhold/Delete confirm screens (Assets + Vulns) ────────────────
# Delete goes through an explicit Confirm/Cancel step, same convention as
# team_tab.py's own destructive actions — Hold/Unhold are non-destructive
# (freely reversible from the same list) and fire immediately.

def asset_delete_confirm_body(host, val, view_prefix="fix_asset"):
    return _confirm_body(
        f"⚠️ Delete asset {host}?",
        "This removes the asset from the Assets/Vulnerabilities lists. An admin can restore it from the website if needed.",
        f"{view_prefix}_delete_do", val,
        f"{view_prefix}_back", val,
    )


def vuln_delete_confirm_body(plugin_name, host, val, view_prefix="fix_vuln"):
    return _confirm_body(
        f"⚠️ Delete \"{plugin_name}\" on {host}?",
        "This removes this vulnerability from the Vulnerabilities list for this asset. An admin can restore it from the website if needed.",
        f"{view_prefix}_delete_do", val,
        f"{view_prefix}_back", val,
    )
