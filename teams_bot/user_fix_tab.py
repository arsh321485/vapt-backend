"""
User-side Fix tab — All Assets / All Vulns / Common Vulns, team-scoped.
Mirrors teams_bot.fix_tab (admin side) closely — same row/pagination/
detail layout and the same field names (both admin's
LatestSuperAdminVulnerabilityRegisterAPIView and this one's
UserLatestVulnerabilityRegisterAPIView return the identical vul_name/
asset/severity/port/protocol/status shape) — reuses fix_tab's generic
rendering helpers directly (_row, _pagination_body, _automation_fix_body,
... — none of those take `admin`, just data) rather than duplicating
them. Manual Fix's own step display is NOT reused from admin's fix_tab
(that one is a flat, view-only list) — see _manual_fix_body_interactive.

UNLIKE the admin side (explicitly read-only, matching the website), a
member gets real actions here: Manual/Automation Fix toggle with actual
steps, and a "Mark Mitigated" button — this is the member's own workflow,
same as Slack's /startfix, /manualfix, /autofix, /mitigated.
"""
import logging

from . import cards
from . import fix_tab
from .fix_tab import (
    _row, _pagination_body, _back_action, _sev_dots_text, _status_label,
    _SEV_ICON, cached_fetch, _group_assets, PAGE_SIZE,
    _vuln_facts_body, _automation_fix_body,
    common_vulns_list_body, common_vuln_detail_body,
    _match_sev, _match_status, _status_counts,
    _sev_filter_columnset, _status_filter_columnset,
)
from . import cards as _cards_mod  # for COMMON_VULNS_TEAMS

logger = logging.getLogger(__name__)

UFIX_SUBTABS = [
    ("ufix_sub_assets", "🖥 All Assets"),
    ("ufix_sub_vulns",  "📋 All Vulns"),
    ("ufix_sub_common", "🧩 Common Vulns"),
]

# "Configuration Management" -> "config" (COMMON_VULNS_TEAMS is
# [(key, display_name), ...] — see cards.py).
_TEAM_NAME_TO_COMMON_KEY = {v: k for k, v in _cards_mod.COMMON_VULNS_TEAMS}


def _fix_subnav_columnset(active_sub):
    return cards.pill_columnset(UFIX_SUBTABS, active_sub, lambda action_id: {"action_id": action_id})


def _fetch_team_data(member_user, team_name):
    def _fetch():
        from userregister.views import UserLatestVulnerabilityRegisterAPIView
        from .actions import _call_view_in_process
        status_code, data = _call_view_in_process(
            UserLatestVulnerabilityRegisterAPIView, member_user, method="get", data={"team": team_name},
        )
        if status_code >= 300 or not isinstance(data, dict):
            raise ValueError(f"user register fetch failed: {status_code}")
        return data
    return cached_fetch(f"user_register_data:{member_user.id}:{team_name}", 20, _fetch)


def _fetch_team_rows(member_user, team_name):
    return _fetch_team_data(member_user, team_name).get("rows") or []


def assets_list_body(member_user, team_name, sev="all", st="all", offset=0):
    rows = _fetch_team_rows(member_user, team_name)
    sev_base = [r for r in rows if _match_sev(r, sev)]
    st_counts = _status_counts(sev_base)
    filtered_rows = [r for r in sev_base if _match_status(r, st)]
    assets = _group_assets(filtered_rows)
    total = len(assets)
    page = assets[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "💻 All Assets", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": f"Assets assigned to {team_name}. Tap View to see its vulnerabilities.", "size": "Small", "isSubtle": True, "wrap": True},
        _sev_filter_columnset("ufix_asset", sev, st),
        _status_filter_columnset("ufix_asset", sev, st, st_counts),
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No assets found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for a in page:
        subtitle = f"{a['total']} Vulns   ·   {_status_label(a['status'])}\n{_sev_dots_text(a['counts'])}"
        body.append(_row(f"🖥 {a['host']}", subtitle, "ufix_asset_view", {"host": a["host"], "offset": offset}))
    body.extend(_pagination_body(offset, total, "ufix_asset_pg", {"sev": sev, "st": st}))
    return body


def asset_detail_body(member_user, team_name, host, back_offset=0):
    rows = _fetch_team_rows(member_user, team_name)
    host_rows = [(i, r) for i, r in enumerate(rows) if (r.get("asset") or "Unknown").strip() == host]

    body = [_back_action("← Back to All Assets", "ufix_asset_back", {"offset": back_offset})]
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
        body.append(_row(name, subtitle, "ufix_asset_vuln_view", {"idx": idx, "host": host, "offset": back_offset}))
    if len(host_rows) > 20:
        body.append({"type": "TextBlock", "text": f"+ {len(host_rows) - 20} more not shown.", "size": "Small", "isSubtle": True, "spacing": "Small"})
    return body


def vulns_list_body(member_user, team_name, sev="all", st="all", offset=0):
    rows = _fetch_team_rows(member_user, team_name)
    sev_base = [(i, r) for i, r in enumerate(rows) if _match_sev(r, sev)]
    st_counts = _status_counts([r for _, r in sev_base])
    filtered = [(i, r) for i, r in sev_base if _match_status(r, st)]
    total = len(filtered)
    page = filtered[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "📋 All Vulnerabilities", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": f"Every vulnerability assigned to {team_name}.", "size": "Small", "isSubtle": True, "wrap": True},
        _sev_filter_columnset("ufix_vuln", sev, st),
        _status_filter_columnset("ufix_vuln", sev, st, st_counts),
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
        body.append(_row(f"{_SEV_ICON[rsev]} {name}", subtitle, "ufix_vuln_view", {"idx": idx, "offset": offset}))
    body.extend(_pagination_body(offset, total, "ufix_vuln_pg", {"sev": sev, "st": st}))
    return body


# ─── Manual Fix / Automation Fix (real, actionable — member side) ───────

def _get_or_create_fix_vuln_id(member_user, r, report_id):
    fix_vuln_id = r.get("fix_vulnerability_id")
    if fix_vuln_id:
        return fix_vuln_id
    host_name = r.get("asset") or ""
    if not report_id or not host_name:
        return None
    from userregister.views import UserFixVulnerabilityCreateAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        UserFixVulnerabilityCreateAPIView, member_user, method="post",
        url_kwargs={"report_id": report_id, "host_name": host_name},
        data={
            "id": r.get("id", ""),
            "plugin_name": r.get("vul_name") or "",
            "risk_factor": r.get("severity") or "Medium",
            "port": r.get("port", ""),
        },
        request_format="json",
    )
    if status_code >= 300 or not isinstance(data, dict):
        return None
    result = data.get("data") or {}
    return result.get("fix_vulnerability_id") or result.get("_id")


def _fetch_fix_steps(member_user, fix_vuln_id):
    if not fix_vuln_id:
        return None
    from userregister.views import UserFixVulnerabilityStepsAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        UserFixVulnerabilityStepsAPIView, member_user, method="get", url_kwargs={"fix_vuln_id": fix_vuln_id},
    )
    if status_code >= 300 or not isinstance(data, dict):
        return None
    return data


def _fetch_automation_match(member_user, r):
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
                auto_views.user_match_script, member_user, method="get",
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
        auto_views.user_match_scripts_by_name, member_user, method="post", data=body, request_format="json",
    )
    if status_code < 300 and isinstance(data, dict):
        results = data.get("results") or []
        return results[0] if results else {"matched": False, "message": "No automated fix available for this vulnerability."}
    return {"matched": False, "message": "No automated fix available for this vulnerability."}


def mark_mitigated(member_user, r, report_id):
    """Marks every step complete for this vuln's fix record — creates the
    record first if it doesn't exist yet (a member can mark something
    mitigated without ever opening Manual Fix first)."""
    fix_vuln_id = _get_or_create_fix_vuln_id(member_user, r, report_id)
    if not fix_vuln_id:
        return False, "Could not start a fix record for this vulnerability."
    from userregister.views import UserFixVulnerabilityStepsAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        UserFixVulnerabilityStepsAPIView, member_user, method="post", url_kwargs={"fix_vuln_id": fix_vuln_id},
        data={"step_number": 1, "complete_all": True}, request_format="json",
    )
    if status_code >= 300:
        return False, (data or {}).get("detail") or "Could not update fix status."
    return True, None


def submit_retest(member_user, r, report_id):
    """Submits a fixed vulnerability for admin retesting — matches Slack's
    /retest [vuln-id]. Requires every fix step already complete (via
    complete_step/mark_mitigated first); the backend itself enforces this
    and returns a clear error otherwise."""
    fix_vuln_id = _get_or_create_fix_vuln_id(member_user, r, report_id)
    if not fix_vuln_id:
        return False, "Could not start a fix record for this vulnerability."
    from userregister.views import UserSendVerificationAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        UserSendVerificationAPIView, member_user, method="post", url_kwargs={"fix_vuln_id": fix_vuln_id},
    )
    result_status = (data or {}).get("status")
    if status_code >= 300 or result_status not in ("open/review", "closed"):
        err = (data or {}).get("message") or (data or {}).get("detail") or (data or {}).get("error") or "Could not submit for retest."
        return False, f"{err} — mark every step complete first."
    return True, None


def complete_step(member_user, r, report_id, step_number):
    """Marks ONE specific step done (not the whole vuln) — matches Slack's
    /mitigated [vuln-id] [step-id]."""
    fix_vuln_id = _get_or_create_fix_vuln_id(member_user, r, report_id)
    if not fix_vuln_id:
        return False, "Could not start a fix record for this vulnerability."
    from userregister.views import UserFixVulnerabilityStepsAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        UserFixVulnerabilityStepsAPIView, member_user, method="post", url_kwargs={"fix_vuln_id": fix_vuln_id},
        data={"step_number": step_number}, request_format="json",
    )
    if status_code >= 300:
        return False, (data or {}).get("detail") or "Could not update this step."
    return True, None


def _all_steps_readonly_body(steps_data, host_os_hint, value_base, nav_action_id="ufix_step_nav", step_number=None):
    """One step at a time, view-only (no Mark Complete / Raise Support
    Request — nothing left to act on, the vuln is already CLOSED), with
    Previous/Next Step nav — same one-at-a-time UX as the still-open
    interactive view, just without the action buttons. `nav_action_id`
    lets different callers (a vuln opened from Fix/Register vs. the Fixed
    tab's own detail, which indexes a completely different list) each
    route Previous/Next through their own dispatch."""
    if not steps_data or steps_data.get("detail"):
        return [{"type": "TextBlock", "text": "No fix steps were recorded for this vulnerability.", "wrap": True, "isSubtle": True, "spacing": "Medium"}]

    steps = steps_data.get("steps") or []
    total = steps_data.get("total_steps", 0)
    os_v = steps_data.get("operating_system") or host_os_hint or "—"
    os_key = "linux" if os_v and os_v.lower() in ("linux", "unix") else "windows"
    if not steps:
        return [{"type": "TextBlock", "text": "No fix steps were recorded for this vulnerability.", "isSubtle": True, "size": "Small", "spacing": "Medium"}]

    by_number = {s.get("step_number"): s for s in steps}
    if step_number is None or step_number not in by_number:
        step_number = steps[0].get("step_number")
    step = by_number[step_number]

    body = [{"type": "TextBlock", "text": f"📋 Step {step_number} of {total} (completed) · OS: {os_v}", "weight": "Bolder", "size": "Small", "wrap": True, "spacing": "Medium"}]
    items, _done = fix_tab.step_content_items(step, os_key)
    body.append({"type": "Container", "items": items, "spacing": "Medium", "separator": True})

    nav_actions = []
    if step_number > 1:
        nav_actions.append(cards._execute_action("◀ Previous Step", {"action_id": nav_action_id, "step": step_number - 1, **value_base}))
    if step_number < total:
        nav_actions.append(cards._execute_action("Next Step ▶", {"action_id": nav_action_id, "step": step_number + 1, **value_base}))
    if nav_actions:
        body.append({"type": "ActionSet", "spacing": "Medium", "actions": nav_actions})
    return body


def _manual_fix_body_interactive(steps_data, host_os_hint, value_base, step_number=None):
    """One step at a time (not the admin side's flat view-only list) — a
    real 'Mark Step Complete' action per step, plus Previous/Next Step
    navigation, matching Slack's /manualfix + /mitigated [id] [step]."""
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

    body = [{"type": "TextBlock", "text": f"📋 Step {step_number} of {total}  ·  {completed}/{total} done  ·  OS: {os_v}", "weight": "Bolder", "size": "Small", "wrap": True, "spacing": "Medium"}]
    items, done = fix_tab.step_content_items(step, os_key)
    body.append({"type": "Container", "items": items, "spacing": "Medium", "separator": True})

    nav_actions = []
    if step_number > 1:
        nav_actions.append(cards._execute_action("◀ Previous Step", {"action_id": "ufix_step_nav", "step": step_number - 1, **value_base}))
    # Raise Support Request sits immediately to the LEFT of Mark Step
    # Complete, same row — tied to this exact step (not just a generic one
    # in the Support Status tab) so the admin sees precisely where the
    # member is stuck (see usup_step_form/submit_step_support_request).
    nav_actions.append(cards._execute_action("🎫 Raise Support Request", {"action_id": "usup_step_form", "step": step_number, **value_base}))
    if not done and not step.get("is_locked"):
        nav_actions.append(cards._execute_action("✅ Mark Step Complete", {"action_id": "ufix_step_complete", "step": step_number, **value_base}, style="positive"))
    if step_number < total:
        nav_actions.append(cards._execute_action("Next Step ▶", {"action_id": "ufix_step_nav", "step": step_number + 1, **value_base}))
    body.append({"type": "ActionSet", "spacing": "Medium", "actions": nav_actions})
    return body


def step_support_form_body(step_number, value_base):
    return [
        cards._section_title(f"🎫 Raise Support Request — Step {step_number}"),
        {"type": "Input.Text", "id": "usup_step_message", "label": "What do you need help with on this step?", "isMultiline": True},
        {
            "type": "ActionSet", "spacing": "Medium",
            "actions": [cards._execute_action("✅ Submit", {"action_id": "usup_step_submit", "step": step_number, **value_base}, style="positive")],
        },
    ]


def submit_step_support_request(member_user, r, report_id, step_number, message):
    message = (message or "").strip()
    if not message:
        return False, "Please describe what you need help with."
    fix_vuln_id = _get_or_create_fix_vuln_id(member_user, r, report_id)
    if not fix_vuln_id:
        return False, "Could not start a fix record for this vulnerability."
    from userregister.views import UserRaiseSupportRequestAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        UserRaiseSupportRequestAPIView, member_user, method="post",
        url_kwargs={"fix_vuln_id": fix_vuln_id},
        data={"step_number": step_number, "description": message}, request_format="json",
    )
    if status_code >= 300:
        return False, (data or {}).get("detail") or "Could not raise support request."
    return True, None


def _fix_toggle_actionset(sub, value_base):
    def action(title, sub_val):
        return cards._execute_action(
            title, {"action_id": "ufix_vuln_toggle", "sub": sub_val, **value_base},
            style="positive" if sub == sub_val else None,
        )
    return {"type": "ActionSet", "spacing": "Medium", "actions": [action("🛠 Manual Fix", "manual"), action("🤖 Automation Fix", "automation")]}


def _mark_mitigated_actionset(value_base):
    return {
        "type": "ActionSet", "spacing": "Medium",
        "actions": [cards._execute_action("✅ Mark Mitigated", {"action_id": "ufix_mark_mitigated", **value_base}, style="positive")],
    }


def _retest_actionset(value_base):
    return {
        "type": "ActionSet", "spacing": "Small",
        "actions": [cards._execute_action("🔁 Retest", {"action_id": "ufix_retest", **value_base})],
    }


def vuln_detail_body(member_user, team_id, team_name, idx, ctx="vulns", host=None, offset=0, sub="manual",
                      back_action_id=None, back_title=None, extra_value=None, step_number=None, admin=None):
    """Shared by every entry point that drills into one vulnerability's own
    detail (flat All Vulns list, an asset's own vuln list, Register's
    filtered list — ctx/host decide where Back goes for the two built-in
    cases; back_action_id/back_title/extra_value let a third caller plug
    in its own, same shape as admin fix_tab.py's _vuln_detail_full_body).
    Real Manual/Auto Fix toggle + steps + Mark Mitigated + Request
    Extension actions, unlike admin's read-only equivalent."""
    data = _fetch_team_data(member_user, team_name)
    rows = data.get("rows") or []
    report_id = data.get("report_id")
    extra_value = extra_value or {}

    if back_action_id:
        body = [_back_action(back_title or "← Back", back_action_id, {"offset": offset, **extra_value})]
    elif ctx == "asset":
        body = [_back_action(f"← Back to {host}", "ufix_asset_vuln_back", {"host": host, "offset": offset})]
    else:
        body = [_back_action("← Back to All Vulns", "ufix_vuln_back", {"offset": offset})]

    if idx is None or idx < 0 or idx >= len(rows):
        body.append({"type": "TextBlock", "text": "This vulnerability could not be found — the report may have refreshed. Go back and try again.", "wrap": True, "spacing": "Medium"})
        return body

    r = rows[idx]
    body.extend(_vuln_facts_body(r))

    value_base = {"idx": idx, "ctx": ctx, "offset": offset, **extra_value}
    if ctx == "asset":
        value_base["host"] = host

    # Already fixed — nothing left to CHOOSE (Manual vs Auto toggle, which
    # step to work on next) — but the steps themselves stay visible,
    # read-only, so a member can see exactly what was done. Retest stays
    # too (it's literally what reopens an already-closed vuln — see
    # submit_retest's docstring) since a false-positive close can happen.
    if (r.get("status") or "open").strip().lower() == "closed":
        body.append({"type": "TextBlock", "text": "✅ This vulnerability has been fixed and closed.", "weight": "Bolder", "size": "Small", "color": "good", "wrap": True, "spacing": "Medium"})
        try:
            fix_vuln_id = _get_or_create_fix_vuln_id(member_user, r, report_id)
            steps_data = _fetch_fix_steps(member_user, fix_vuln_id) if fix_vuln_id else None
            body.extend(_all_steps_readonly_body(steps_data, r.get("operating_system"), value_base, step_number=step_number))
        except Exception:
            logger.exception("[TeamsBot] user closed-vuln steps fetch failed")
        body.append(_retest_actionset(value_base))
        return body

    body.append(_fix_toggle_actionset(sub, value_base))

    try:
        if sub == "automation":
            automation = _fetch_automation_match(member_user, r)
            body.extend(_automation_fix_body(automation, admin=admin))
            plugin_id = automation.get("plugin_id") or r.get("plugin_id")
            # Don't offer a Download button the actual download endpoint
            # (user_download_script, called in-process by
            # TeamsScriptDownloadView) will just reject anyway — a visible
            # but broken button is worse than no button. Matches
            # _automation_fix_body's own content-hiding above.
            if automation.get("matched") and not automation.get("premium_required") and plugin_id and team_id:
                body.append({
                    "type": "ActionSet", "spacing": "Small",
                    "actions": [{"type": "Action.OpenUrl", "title": "📥 Download Script", "url": fix_tab.script_download_url(team_id, team_name, plugin_id)}],
                })
        else:
            fix_vuln_id = _get_or_create_fix_vuln_id(member_user, r, report_id)
            steps_data = _fetch_fix_steps(member_user, fix_vuln_id) if fix_vuln_id else None
            body.extend(_manual_fix_body_interactive(steps_data, r.get("operating_system"), value_base, step_number=step_number))
    except Exception:
        logger.exception("[TeamsBot] user fix content fetch failed (sub=%s)", sub)
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "isSubtle": True, "spacing": "Medium"})

    # Mark Mitigated only makes sense while actually working the manual
    # steps — Automation Fix is just a script preview/download, nothing to
    # mark done there. Retest only makes sense on an already-CLOSED vuln
    # (see submit_retest's docstring — it's literally what reopens one),
    # which takes the early-return branch above; not shown here at all.
    if sub != "automation":
        body.append(_mark_mitigated_actionset(value_base))
    return body


def submit_extension_request(member_user, r):
    from userdashboard.views import UserMitigationTimelineExtensionCreateAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        UserMitigationTimelineExtensionCreateAPIView, member_user, method="post",
        data={
            "severity": (r.get("severity") or "Medium").strip().title(),
            "asset": r.get("asset") or "",
            "vulnerability_name": r.get("vul_name") or "",
            "requested_extension_days": r.get("_requested_days") or 7,
            "reason": r.get("_reason") or "",
        },
        request_format="json",
    )
    if status_code >= 300 or not isinstance(data, dict) or not data.get("request_id"):
        return False, (data or {}).get("detail") or "Could not submit extension request."
    return True, None


def fix_tab_body(member_user, admin, team_name, sub_action_id="ufix_sub_assets", offset=0, sev="all", st="all"):
    """`admin` is only used for the Common Vulns sub-tab (admin-scoped
    data source, see _common_vulns_for_team) — every other sub-tab is
    genuinely member-scoped and ignores it."""
    body = [_fix_subnav_columnset(sub_action_id)]
    if sub_action_id == "ufix_sub_vulns":
        body.extend(vulns_list_body(member_user, team_name, sev=sev, st=st, offset=offset))
    elif sub_action_id == "ufix_sub_common":
        body.extend(_common_vulns_for_team(admin, team_name, sev=sev, st=st, offset=offset))
    else:
        body.extend(assets_list_body(member_user, team_name, sev=sev, st=st, offset=offset))
    return body


# ─── Common Vulns (locked to the member's own team, unlike admin's
# switchable-team view — reuses fix_tab.py's admin-authenticated data
# fetch verbatim: MitigationStrategyByTeamAPIView is admin-scoped data,
# there's no per-member variant, and there doesn't need to be — every
# member of a team sees the same "vulns on 4+ assets" data for that team.
# `admin` is threaded in from teams_bot.actions.handle_card_action's own
# already-resolved admin — see user_actions.py's call site).

def _common_vulns_for_team(admin, team_name, sev="all", st="all", offset=0):
    team_key = _TEAM_NAME_TO_COMMON_KEY.get(team_name, "config")
    # prefix="ufix_common" — real bug fixed alongside this: without it,
    # this reused admin's own "fix_common_*" action ids on a MEMBER's
    # card, which user_actions.py's _FIX_ACTION_IDS never recognized (only
    # the "ufix_"-prefixed family), so every pagination/View click on a
    # member's Common Vulns list silently fell through unrecognized.
    return common_vulns_list_body(admin, team_key=team_key, sev=sev, st=st, offset=offset, prefix="ufix_common")


def common_vuln_detail_for_team(admin, team_name, idx, back_offset=0, asset_offset=0):
    team_key = _TEAM_NAME_TO_COMMON_KEY.get(team_name, "config")
    return common_vuln_detail_body(admin, team_key, idx, back_offset=back_offset, asset_offset=asset_offset, prefix="ufix_common")


def _find_team_row_idx_for_asset(member_user, team_name, vuln_name, host):
    """Member-scoped counterpart of fix_tab._find_row_idx_for_asset —
    Common Vulns' own grouped data (shared, admin-authenticated) doesn't
    carry the same row identity user_fix_tab.vuln_detail_body indexes
    into (that one reads the MEMBER's own team-scoped rows), so a common
    vuln's per-asset "View" bridges the two by matching (vuln name, host),
    same as admin's version."""
    rows = _fetch_team_rows(member_user, team_name)
    for i, r in enumerate(rows):
        if (r.get("vul_name") or "").strip() == (vuln_name or "").strip() and (r.get("asset") or "").strip() == (host or "").strip():
            return i
    return None


def common_vuln_asset_detail_for_team(member_user, admin, team_id, team_name, idx, host, asset_offset=0, back_offset=0, sub="manual", step_number=None):
    """Member-side counterpart of fix_tab.common_vuln_asset_detail_body —
    same (vuln, asset) -> real Manual/Automation Fix + Mark Mitigated
    detail, just reusing THIS module's own interactive vuln_detail_body
    (member gets real actions, unlike admin's read-only equivalent) —
    see that function's own docstring for why "cv_idx"/"cv_offset" are
    used instead of "idx"/"offset" in extra_value."""
    from . import fix_tab as _admin_fix_tab
    team_key = _TEAM_NAME_TO_COMMON_KEY.get(team_name, "config")
    grouped = _admin_fix_tab._fetch_common_vulns_grouped(admin)
    team = grouped.get(team_key) or {"vulns": []}
    vulns = team.get("vulns") or []
    vuln_name = vulns[idx].get("name") if (idx is not None and 0 <= idx < len(vulns)) else None

    row_idx = _find_team_row_idx_for_asset(member_user, team_name, vuln_name, host)
    return vuln_detail_body(
        member_user, team_id, team_name, row_idx, ctx="common", host=host, sub=sub, step_number=step_number,
        back_action_id="ufix_common_vuln_asset_back",
        back_title=f"← Back to {vuln_name or 'vulnerability'}",
        extra_value={"team": team_key, "cv_idx": idx, "host": host, "cv_offset": asset_offset, "back_offset": back_offset},
    )
