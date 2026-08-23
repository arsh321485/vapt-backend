"""
Timeline Ext. tab — Extension Requests (pending team requests to extend a
mitigation deadline, with Approve/Reject right on the row) and History (an
Approve/Reject toggle over the full list, same toggle pattern as Fix's
Manual/Automation). Mirrors users.views.SlackSlashCommandView.
_format_extension_requests / _build_approve_list_blocks /
_build_reject_list_blocks / _cmd_approve / _cmd_reject.
"""
import logging

from . import cards
from . import fix_tab

logger = logging.getLogger(__name__)

PAGE_SIZE = 5

REQUEST_SUBTABS = [
    ("req_sub_extensions", "📋 Extension Requests"),
    ("req_sub_history", "🕘 History"),
]


def request_subnav_columnset(active_sub):
    return cards.pill_columnset(REQUEST_SUBTABS, active_sub, lambda k: {"action_id": k})


def _fetch_requests(admin):
    from admindashboard.views import AdminMitigationTimelineExtensionReportAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(AdminMitigationTimelineExtensionReportAPIView, admin, method="get")
    if status_code >= 300 or not isinstance(data, dict):
        raise ValueError(f"extension request fetch failed: {status_code}")
    return data.get("results") or []


def _row_subtitle(r):
    team = r.get("requested_by") or "Unknown"
    days = r.get("extension_days", 0)
    reason = r.get("reason") or "—"
    return f"Team: {team}   ·   +{days} days   ·   Reason: {reason}"


# ── Extension Requests (pending only, Approve/Reject inline) ────────────

def extensions_list_body(admin, offset=0):
    requests_ = [r for r in _fetch_requests(admin) if r.get("status", "review") == "review"]
    total = len(requests_)
    page = requests_[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "⏳ Timeline Extension Requests", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": f"Pending team requests to extend mitigation deadlines: {total}", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "✅ No pending extension requests — all caught up.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for r in page:
        rid = r.get("request_id") or ""
        name = r.get("vul_name") or "Unnamed vulnerability"
        body.append({
            "type": "ColumnSet", "spacing": "Medium", "separator": True,
            "columns": [
                {
                    "type": "Column", "width": "stretch",
                    "items": [
                        {"type": "TextBlock", "text": name, "weight": "Bolder", "size": "Small", "wrap": True},
                        {"type": "TextBlock", "text": _row_subtitle(r), "size": "Small", "isSubtle": True, "wrap": True, "spacing": "None"},
                    ],
                },
                {
                    "type": "Column", "width": "auto", "verticalContentAlignment": "Center",
                    "items": [{
                        "type": "ActionSet",
                        "actions": [
                            cards._execute_action("✅ Approve", {"action_id": "ext_approve_do", "request_id": rid, "offset": offset, "src": "ext"}, style="positive"),
                            cards._execute_action("❌ Reject", {"action_id": "ext_reject_start", "request_id": rid, "offset": offset, "src": "ext"}, style="destructive"),
                        ],
                    }],
                },
            ],
        })
    body.extend(fix_tab._pagination_body(offset, total, "ext_list_pg"))
    return body


# ── History (Approve/Reject toggle over the full list) ──────────────────

def _history_toggle_actionset(view):
    def action(title, v):
        return cards._execute_action(title, {"action_id": "hist_toggle", "view": v}, style="positive" if view == v else None)
    return {"type": "ActionSet", "spacing": "Medium", "actions": [action("✅ Approve", "approve"), action("❌ Reject", "reject")]}


def history_list_body(admin, view="approve", offset=0):
    all_requests = _fetch_requests(admin)
    if view == "reject":
        requests_ = [r for r in all_requests if r.get("status", "review") != "approved"]
    else:
        requests_ = [r for r in all_requests if r.get("status", "review") != "rejected"]
    total = len(requests_)
    page = requests_[offset:offset + PAGE_SIZE]

    title = "✅ Approve Timeline Extension" if view == "approve" else "❌ Reject Timeline Extension"
    body = [
        {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        _history_toggle_actionset(view),
        {"type": "TextBlock", "text": f"Total requests: {total}", "size": "Small", "isSubtle": True, "spacing": "Small"},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No timeline extension requests found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for r in page:
        rid = r.get("request_id") or ""
        name = r.get("vul_name") or "Unnamed vulnerability"
        st = r.get("status", "review")
        days = r.get("extension_days", 0)
        items = [
            {"type": "TextBlock", "text": name, "weight": "Bolder", "size": "Small", "wrap": True},
            {"type": "TextBlock", "text": f"+{days} days", "size": "Small", "isSubtle": True, "spacing": "None"},
        ]
        if view == "approve" and st == "approved":
            items.append({"type": "TextBlock", "text": "✅ Approved", "size": "Small", "color": "good", "weight": "Bolder"})
            body.append({"type": "Container", "items": items, "spacing": "Medium", "separator": True})
        elif view == "reject" and st == "rejected":
            items.append({"type": "TextBlock", "text": f"❌ Rejected — Reason: {r.get('reason') or '—'}", "size": "Small", "color": "attention", "weight": "Bolder", "wrap": True})
            body.append({"type": "Container", "items": items, "spacing": "Medium", "separator": True})
        else:
            btn_title = "✅ Approve Request" if view == "approve" else "❌ Reject Request"
            btn_action = "ext_approve_do" if view == "approve" else "ext_reject_start"
            body.append({
                "type": "ColumnSet", "spacing": "Medium", "separator": True,
                "columns": [
                    {"type": "Column", "width": "stretch", "items": items},
                    {
                        "type": "Column", "width": "auto", "verticalContentAlignment": "Center",
                        "items": [{"type": "ActionSet", "actions": [
                            cards._execute_action(btn_title, {"action_id": btn_action, "request_id": rid, "offset": offset, "src": "hist", "view": view},
                                                   style="positive" if view == "approve" else "destructive"),
                        ]}],
                    },
                ],
            })
    body.extend(fix_tab._pagination_body(offset, total, "hist_list_pg", {"view": view}))
    return body


def reject_reason_body(request_id, offset, src, view=None):
    val = {"request_id": request_id, "offset": offset, "src": src}
    if view:
        val["view"] = view
    return [
        {"type": "TextBlock", "text": "❌ Reject this extension request?", "weight": "Bolder", "size": "Medium", "spacing": "Medium", "color": "attention"},
        {"type": "Input.Text", "id": "reject_reason", "label": "Reason (optional)", "isMultiline": True, "placeholder": "Why is this being rejected?"},
        {
            "type": "ActionSet", "spacing": "Medium",
            "actions": [
                cards._execute_action("✅ Confirm Reject", {"action_id": "ext_reject_do", **val}, style="destructive"),
                cards._execute_action("← Cancel", {"action_id": "ext_reject_cancel", **val}),
            ],
        },
    ]


def do_approve(admin, request_id):
    from admindashboard.views import AdminMitigationTimelineExtensionStatusAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        AdminMitigationTimelineExtensionStatusAPIView, admin, method="patch", request_format="json",
        data={"status": "approved"}, url_kwargs={"request_id": request_id},
    )
    if status_code >= 300:
        err = (data or {}).get("detail") or f"status {status_code}"
        return False, f"Could not approve — {err}."
    return True, "Request approved."


def do_reject(admin, request_id, reason=""):
    from admindashboard.views import AdminMitigationTimelineExtensionStatusAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(
        AdminMitigationTimelineExtensionStatusAPIView, admin, method="patch", request_format="json",
        data={"status": "rejected", "admin_comment": reason}, url_kwargs={"request_id": request_id},
    )
    if status_code >= 300:
        err = (data or {}).get("detail") or f"status {status_code}"
        return False, f"Could not reject — {err}."
    return True, "Request rejected."


# ── Top-level entry point ────────────────────────────────────────────────

def timeline_tab_body(admin, active_sub="req_sub_extensions", view="approve", offset=0):
    body = [request_subnav_columnset(active_sub)]
    try:
        if active_sub == "req_sub_history":
            body.extend(history_list_body(admin, view=view, offset=offset))
        else:
            body.extend(extensions_list_body(admin, offset=offset))
    except Exception:
        logger.exception(f"[TeamsBot] timeline_tab_body failed for {active_sub}")
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "spacing": "Medium"})
    return body
