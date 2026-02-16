from django.contrib import admin
from django.conf import settings
from django.http import HttpResponse, HttpResponseForbidden
from django.urls import path
import pymongo

from .models import SupportRequestView, TicketView, VulnCardView
from users.models import User

SUPPORT_REQUEST_COLLECTION = "support_requests"
TICKETS_COLLECTION = "tickets"
FIX_VULN_COLLECTION = "fix_vulnerabilities"
FIX_VULN_CLOSED_COLLECTION = "fix_vulnerabilities_closed"
NESSUS_COLLECTION = "nessus_reports"


def get_mongo_db():
    try:
        mongo_uri = settings.DATABASES['default']['CLIENT']['host']
    except Exception:
        mongo_uri = getattr(settings, "MONGO_DB_URL", None)
    if not mongo_uri:
        return None
    try:
        client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        try:
            db = client.get_default_database()
            if db:
                return db
        except Exception:
            pass
        try:
            dbname = settings.DATABASES['default'].get('NAME')
            if dbname:
                return client[dbname]
        except Exception:
            pass
        return client["vaptfix"]
    except Exception:
        return None


def get_base_html(title, breadcrumbs, content, user_email):
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>{title} | Django site admin</title>
        <style>
            * {{ box-sizing: border-box; }}
            body {{
                font-family: "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                margin: 0; padding: 0; background: #f5f7fa; color: #333;
            }}
            #header {{
                background: linear-gradient(135deg, #417690 0%, #2c5364 100%);
                color: #fff; padding: 15px 40px; display: flex;
                justify-content: space-between; align-items: center;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            #header h1 {{ margin: 0; font-size: 20px; font-weight: 500; }}
            #header a {{ color: #fff; text-decoration: none; }}
            #user-tools {{ font-size: 13px; opacity: 0.9; }}
            #user-tools a {{ color: #fff; margin-left: 15px; text-decoration: underline; }}
            .breadcrumbs {{
                background: #79aec8; padding: 12px 40px; font-size: 13px;
                color: rgba(255,255,255,0.8);
            }}
            .breadcrumbs a {{ color: #fff; text-decoration: none; }}
            .breadcrumbs a:hover {{ text-decoration: underline; }}
            #content {{ padding: 25px 40px; max-width: 1400px; }}
            #content h1 {{ font-size: 24px; color: #2c3e50; margin: 0 0 25px 0; font-weight: 600; }}
            .summary-box {{ display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap; }}
            .summary-item {{
                background: #fff; padding: 20px 30px; border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center;
                min-width: 140px; border-left: 4px solid #417690;
            }}
            .summary-item.open {{ border-left-color: #e74c3c; }}
            .summary-item.closed {{ border-left-color: #27ae60; }}
            .summary-item .label {{
                font-size: 12px; color: #7f8c8d; margin-bottom: 8px;
                text-transform: uppercase; letter-spacing: 0.5px;
            }}
            .summary-item .value {{ font-size: 28px; font-weight: 700; color: #2c3e50; }}
            .table-container {{
                background: #fff; box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                border-radius: 8px; overflow: hidden; margin-bottom: 25px;
            }}
            table {{ width: 100%; border-collapse: collapse; }}
            thead th {{
                background: #34495e; color: #fff; padding: 14px 16px;
                text-align: left; font-weight: 600; font-size: 13px;
                text-transform: uppercase; letter-spacing: 0.5px;
                border-bottom: 2px solid #2c3e50;
            }}
            thead th.text-center {{ text-align: center; }}
            tbody td {{
                font-size: 14px; padding: 14px 16px;
                border-bottom: 1px solid #ecf0f1; vertical-align: middle;
            }}
            tbody td.text-center {{ text-align: center; }}
            tbody tr:hover {{ background: #f8f9fa; }}
            tbody tr:last-child td {{ border-bottom: none; }}
            .link {{ color: #3498db; text-decoration: none; font-weight: 500; }}
            .link:hover {{ color: #2980b9; text-decoration: underline; }}
            .btn {{
                display: inline-block; padding: 8px 16px; background: #3498db;
                color: #fff; text-decoration: none; border-radius: 4px;
                font-size: 12px; font-weight: 500; transition: background 0.2s;
            }}
            .btn:hover {{ background: #2980b9; }}
            .back-link {{ margin-bottom: 20px; font-size: 14px; }}
            .back-link a {{ color: #3498db; text-decoration: none; }}
            .back-link a:hover {{ text-decoration: underline; }}
            .badge {{
                display: inline-block; padding: 4px 10px; border-radius: 12px;
                font-size: 11px; font-weight: 600; text-transform: uppercase;
            }}
            .badge-open {{ background: #fdecea; color: #e74c3c; }}
            .badge-closed {{ background: #eafaf1; color: #27ae60; }}
            .text-primary {{ color: #3498db; font-weight: 600; }}
            .text-success {{ color: #27ae60; font-weight: 600; }}
            .text-warning {{ color: #f39c12; font-weight: 600; }}
            .text-danger {{ color: #e74c3c; font-weight: 600; }}
            .text-muted {{ color: #95a5a6; }}
            .empty-state {{
                padding: 40px 20px; text-align: center;
                color: #7f8c8d; background: #fafbfc;
            }}
        </style>
    </head>
    <body>
        <div id="header">
            <h1><a href="/admin/">Django Administration</a></h1>
            <div id="user-tools">Welcome, <strong>{user_email}</strong> <a href="/admin/logout/">Log out</a></div>
        </div>
        <div class="breadcrumbs">{breadcrumbs}</div>
        <div id="content">{content}</div>
    </body>
    </html>
    '''


def _format_datetime(dt):
    if dt:
        try:
            return dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            return str(dt)
    return "-"


def _get_admin_email_map():
    email_map = {}
    try:
        for user in User.objects.all():
            email_map[str(user.id)] = user.email
    except Exception:
        pass
    return email_map


def _get_admin_email_by_id(admin_id):
    try:
        user = User.objects.get(id=admin_id)
        return user.email
    except Exception:
        return None


def _is_super(request):
    return request.user.is_authenticated and getattr(request.user, 'is_superuser', False)


def _get_admin_reports(db, admin_id):
    """Get list of reports for an admin from nessus_reports collection."""
    reports = []
    if not db:
        return reports
    coll = db[NESSUS_COLLECTION]
    cursor = coll.find(
        {"admin_id": admin_id},
        {"report_id": 1, "original_filename": 1, "uploaded_at": 1}
    ).sort("uploaded_at", -1)
    for doc in cursor:
        reports.append({
            "report_id": doc.get("report_id", str(doc.get("_id", ""))),
            "filename": doc.get("original_filename", "Unknown"),
            "uploaded_at": _format_datetime(doc.get("uploaded_at")),
        })
    return reports


def _get_severity_class(severity):
    s = (severity or "").lower()
    if s in ("critical", "high"):
        return "text-danger"
    elif s == "medium":
        return "text-warning"
    elif s == "low":
        return "text-primary"
    return "text-muted"


# ══════════════════════════════════════════════════════
# SUPPORT REQUESTS
# ══════════════════════════════════════════════════════

def support_request_list_view(request):
    """Level 1: List all admins with support request counts."""
    if not _is_super(request):
        return HttpResponseForbidden("Access denied.")

    db = get_mongo_db()
    email_map = _get_admin_email_map()
    admins_data = []
    total_open = 0
    total_closed = 0

    if db:
        coll = db[SUPPORT_REQUEST_COLLECTION]
        for doc in coll.aggregate([
            {"$match": {"admin_id": {"$exists": True, "$ne": None}}},
            {"$group": {
                "_id": "$admin_id",
                "total": {"$sum": 1},
                "open_count": {"$sum": {"$cond": [{"$eq": ["$status", "open"]}, 1, 0]}},
                "closed_count": {"$sum": {"$cond": [{"$ne": ["$status", "open"]}, 1, 0]}},
                "latest": {"$max": "$requested_at"},
            }}
        ]):
            aid = doc["_id"]
            oc = doc.get("open_count", 0)
            cc = doc.get("closed_count", 0)
            total_open += oc
            total_closed += cc
            admins_data.append({
                "admin_id": aid,
                "admin_email": email_map.get(aid, aid),
                "total": doc.get("total", 0),
                "open_count": oc, "closed_count": cc,
                "latest": _format_datetime(doc.get("latest")),
            })

    rows = ""
    for d in admins_data:
        rows += f'''<tr>
            <td><a href="/admin/adminregister/supportrequestview/{d["admin_id"]}/reports/" class="link">{d["admin_email"]}</a></td>
            <td class="text-center">{d["total"]}</td>
            <td class="text-center text-danger">{d["open_count"]}</td>
            <td class="text-center text-success">{d["closed_count"]}</td>
            <td class="text-center">{d["latest"]}</td>
            <td class="text-center"><a href="/admin/adminregister/supportrequestview/{d["admin_id"]}/reports/" class="btn">View Reports</a></td>
        </tr>'''
    if not rows:
        rows = '<tr><td colspan="6" class="empty-state">No support requests found.</td></tr>'

    content = f'''
        <h1>Support Requests Overview</h1>
        <div class="summary-box">
            <div class="summary-item"><div class="label">Total Admins</div><div class="value">{len(admins_data)}</div></div>
            <div class="summary-item open"><div class="label">Open</div><div class="value" style="color:#e74c3c;">{total_open}</div></div>
            <div class="summary-item closed"><div class="label">Closed</div><div class="value" style="color:#27ae60;">{total_closed}</div></div>
        </div>
        <div class="table-container"><table><thead><tr>
            <th style="width:25%;">Admin Email</th>
            <th class="text-center" style="width:12%;">Total</th>
            <th class="text-center" style="width:12%;">Open</th>
            <th class="text-center" style="width:12%;">Closed</th>
            <th class="text-center" style="width:18%;">Latest</th>
            <th class="text-center" style="width:15%;">Action</th>
        </tr></thead><tbody>{rows}</tbody></table></div>
    '''
    breadcrumbs = '<a href="/admin/">Home</a> &rsaquo; Support Requests'
    return HttpResponse(get_base_html("Support Requests", breadcrumbs, content, request.user.email))


def support_request_reports_view(request, admin_id):
    """Level 2: List reports for a specific admin."""
    if not _is_super(request):
        return HttpResponseForbidden("Access denied.")

    db = get_mongo_db()
    admin_email = _get_admin_email_by_id(admin_id) or admin_id
    reports = _get_admin_reports(db, str(admin_id))

    # Get support request counts per report
    sr_counts = {}
    if db:
        coll = db[SUPPORT_REQUEST_COLLECTION]
        for doc in coll.aggregate([
            {"$match": {"admin_id": str(admin_id)}},
            {"$group": {"_id": "$report_id", "count": {"$sum": 1}}}
        ]):
            sr_counts[doc["_id"]] = doc.get("count", 0)

    rows = ""
    for r in reports:
        rid = r["report_id"]
        count = sr_counts.get(rid, 0)
        rows += f'''<tr>
            <td>{r["filename"]}</td>
            <td class="text-center">{rid}</td>
            <td class="text-center">{count}</td>
            <td class="text-center">{r["uploaded_at"]}</td>
            <td class="text-center"><a href="/admin/adminregister/supportrequestview/{admin_id}/report/{rid}/" class="btn">View Details</a></td>
        </tr>'''
    if not rows:
        rows = '<tr><td colspan="5" class="empty-state">No reports found for this admin.</td></tr>'

    content = f'''
        <div class="back-link"><a href="/admin/adminregister/supportrequestview/">&larr; Back to Support Requests</a></div>
        <h1>Support Requests &mdash; {admin_email}</h1>
        <div class="table-container"><table><thead><tr>
            <th style="width:25%;">Report File</th>
            <th class="text-center" style="width:20%;">Report ID</th>
            <th class="text-center" style="width:15%;">Support Requests</th>
            <th class="text-center" style="width:18%;">Uploaded</th>
            <th class="text-center" style="width:15%;">Action</th>
        </tr></thead><tbody>{rows}</tbody></table></div>
    '''
    breadcrumbs = f'<a href="/admin/">Home</a> &rsaquo; <a href="/admin/adminregister/supportrequestview/">Support Requests</a> &rsaquo; {admin_email}'
    return HttpResponse(get_base_html(f"Support Requests - {admin_email}", breadcrumbs, content, request.user.email))


def support_request_detail_view(request, admin_id, report_id):
    """Level 3: Show support requests for admin + report."""
    if not _is_super(request):
        return HttpResponseForbidden("Access denied.")

    db = get_mongo_db()
    admin_email = _get_admin_email_by_id(admin_id) or admin_id
    results = []

    if db:
        coll = db[SUPPORT_REQUEST_COLLECTION]
        for doc in coll.find({"admin_id": str(admin_id), "report_id": str(report_id)}).sort("requested_at", -1):
            results.append({
                "vul_name": doc.get("vul_name", "-"),
                "host_name": doc.get("host_name", "-"),
                "assigned_team": doc.get("assigned_team", "-"),
                "step_requested": doc.get("step_requested", "-"),
                "description": doc.get("description", "-"),
                "status": doc.get("status", "open"),
                "requested_at": _format_datetime(doc.get("requested_at")),
            })

    rows = ""
    for d in results:
        badge = f'<span class="badge badge-{d["status"]}">{d["status"]}</span>'
        desc = d["description"][:80] + "..." if len(d["description"]) > 80 else d["description"]
        rows += f'''<tr>
            <td>{d["vul_name"]}</td>
            <td>{d["host_name"]}</td>
            <td>{d["assigned_team"]}</td>
            <td class="text-center">{d["step_requested"]}</td>
            <td>{desc}</td>
            <td class="text-center">{badge}</td>
            <td class="text-center">{d["requested_at"]}</td>
        </tr>'''
    if not rows:
        rows = '<tr><td colspan="7" class="empty-state">No support requests for this report.</td></tr>'

    open_c = sum(1 for r in results if r["status"] == "open")
    closed_c = len(results) - open_c

    content = f'''
        <div class="back-link"><a href="/admin/adminregister/supportrequestview/{admin_id}/reports/">&larr; Back to Reports</a></div>
        <h1>Support Requests &mdash; {admin_email} &mdash; Report {report_id}</h1>
        <div class="summary-box">
            <div class="summary-item"><div class="label">Total</div><div class="value">{len(results)}</div></div>
            <div class="summary-item open"><div class="label">Open</div><div class="value" style="color:#e74c3c;">{open_c}</div></div>
            <div class="summary-item closed"><div class="label">Closed</div><div class="value" style="color:#27ae60;">{closed_c}</div></div>
        </div>
        <div class="table-container"><table><thead><tr>
            <th style="width:18%;">Vulnerability</th>
            <th style="width:12%;">Host</th>
            <th style="width:12%;">Assigned Team</th>
            <th class="text-center" style="width:8%;">Step</th>
            <th style="width:22%;">Description</th>
            <th class="text-center" style="width:10%;">Status</th>
            <th class="text-center" style="width:14%;">Requested At</th>
        </tr></thead><tbody>{rows}</tbody></table></div>
    '''
    breadcrumbs = f'<a href="/admin/">Home</a> &rsaquo; <a href="/admin/adminregister/supportrequestview/">Support Requests</a> &rsaquo; <a href="/admin/adminregister/supportrequestview/{admin_id}/reports/">{admin_email}</a> &rsaquo; Report'
    return HttpResponse(get_base_html(f"Support Requests - Report", breadcrumbs, content, request.user.email))


# ══════════════════════════════════════════════════════
# TICKETS
# ══════════════════════════════════════════════════════

def ticket_list_view(request):
    """Level 1: List all admins with ticket counts."""
    if not _is_super(request):
        return HttpResponseForbidden("Access denied.")

    db = get_mongo_db()
    email_map = _get_admin_email_map()
    admins_data = []
    total_open = 0
    total_closed = 0

    if db:
        coll = db[TICKETS_COLLECTION]
        for doc in coll.aggregate([
            {"$match": {"admin_id": {"$exists": True, "$ne": None}}},
            {"$group": {
                "_id": "$admin_id",
                "total": {"$sum": 1},
                "open_count": {"$sum": {"$cond": [{"$eq": ["$status", "open"]}, 1, 0]}},
                "closed_count": {"$sum": {"$cond": [{"$eq": ["$status", "closed"]}, 1, 0]}},
                "latest": {"$max": "$created_at"},
            }}
        ]):
            aid = doc["_id"]
            oc = doc.get("open_count", 0)
            cc = doc.get("closed_count", 0)
            total_open += oc
            total_closed += cc
            admins_data.append({
                "admin_id": aid,
                "admin_email": email_map.get(aid, aid),
                "total": doc.get("total", 0),
                "open_count": oc, "closed_count": cc,
                "latest": _format_datetime(doc.get("latest")),
            })

    rows = ""
    for d in admins_data:
        rows += f'''<tr>
            <td><a href="/admin/adminregister/ticketview/{d["admin_id"]}/reports/" class="link">{d["admin_email"]}</a></td>
            <td class="text-center">{d["total"]}</td>
            <td class="text-center text-danger">{d["open_count"]}</td>
            <td class="text-center text-success">{d["closed_count"]}</td>
            <td class="text-center">{d["latest"]}</td>
            <td class="text-center"><a href="/admin/adminregister/ticketview/{d["admin_id"]}/reports/" class="btn">View Reports</a></td>
        </tr>'''
    if not rows:
        rows = '<tr><td colspan="6" class="empty-state">No tickets found.</td></tr>'

    content = f'''
        <h1>Tickets Overview</h1>
        <div class="summary-box">
            <div class="summary-item"><div class="label">Total Admins</div><div class="value">{len(admins_data)}</div></div>
            <div class="summary-item open"><div class="label">Open</div><div class="value" style="color:#e74c3c;">{total_open}</div></div>
            <div class="summary-item closed"><div class="label">Closed</div><div class="value" style="color:#27ae60;">{total_closed}</div></div>
        </div>
        <div class="table-container"><table><thead><tr>
            <th style="width:25%;">Admin Email</th>
            <th class="text-center" style="width:12%;">Total</th>
            <th class="text-center" style="width:12%;">Open</th>
            <th class="text-center" style="width:12%;">Closed</th>
            <th class="text-center" style="width:18%;">Latest</th>
            <th class="text-center" style="width:15%;">Action</th>
        </tr></thead><tbody>{rows}</tbody></table></div>
    '''
    breadcrumbs = '<a href="/admin/">Home</a> &rsaquo; Tickets'
    return HttpResponse(get_base_html("Tickets", breadcrumbs, content, request.user.email))


def ticket_reports_view(request, admin_id):
    """Level 2: List reports for a specific admin."""
    if not _is_super(request):
        return HttpResponseForbidden("Access denied.")

    db = get_mongo_db()
    admin_email = _get_admin_email_by_id(admin_id) or admin_id
    reports = _get_admin_reports(db, str(admin_id))

    t_counts = {}
    if db:
        coll = db[TICKETS_COLLECTION]
        for doc in coll.aggregate([
            {"$match": {"admin_id": str(admin_id)}},
            {"$group": {"_id": "$report_id", "count": {"$sum": 1}}}
        ]):
            t_counts[doc["_id"]] = doc.get("count", 0)

    rows = ""
    for r in reports:
        rid = r["report_id"]
        count = t_counts.get(rid, 0)
        rows += f'''<tr>
            <td>{r["filename"]}</td>
            <td class="text-center">{rid}</td>
            <td class="text-center">{count}</td>
            <td class="text-center">{r["uploaded_at"]}</td>
            <td class="text-center"><a href="/admin/adminregister/ticketview/{admin_id}/report/{rid}/" class="btn">View Details</a></td>
        </tr>'''
    if not rows:
        rows = '<tr><td colspan="5" class="empty-state">No reports found for this admin.</td></tr>'

    content = f'''
        <div class="back-link"><a href="/admin/adminregister/ticketview/">&larr; Back to Tickets</a></div>
        <h1>Tickets &mdash; {admin_email}</h1>
        <div class="table-container"><table><thead><tr>
            <th style="width:25%;">Report File</th>
            <th class="text-center" style="width:20%;">Report ID</th>
            <th class="text-center" style="width:15%;">Tickets</th>
            <th class="text-center" style="width:18%;">Uploaded</th>
            <th class="text-center" style="width:15%;">Action</th>
        </tr></thead><tbody>{rows}</tbody></table></div>
    '''
    breadcrumbs = f'<a href="/admin/">Home</a> &rsaquo; <a href="/admin/adminregister/ticketview/">Tickets</a> &rsaquo; {admin_email}'
    return HttpResponse(get_base_html(f"Tickets - {admin_email}", breadcrumbs, content, request.user.email))


def ticket_detail_view(request, admin_id, report_id):
    """Level 3: Show tickets for admin + report."""
    if not _is_super(request):
        return HttpResponseForbidden("Access denied.")

    db = get_mongo_db()
    admin_email = _get_admin_email_by_id(admin_id) or admin_id
    results = []

    if db:
        coll = db[TICKETS_COLLECTION]
        for doc in coll.find({"admin_id": str(admin_id), "report_id": str(report_id)}).sort("created_at", -1):
            results.append({
                "plugin_name": doc.get("plugin_name", "-"),
                "host_name": doc.get("host_name", "-"),
                "category": doc.get("category", "-"),
                "subject": doc.get("subject", "-"),
                "description": doc.get("description", "-"),
                "status": doc.get("status", "open"),
                "created_at": _format_datetime(doc.get("created_at")),
                "closed_at": _format_datetime(doc.get("closed_at")),
            })

    rows = ""
    for d in results:
        badge = f'<span class="badge badge-{d["status"]}">{d["status"]}</span>'
        desc = d["description"][:60] + "..." if len(d["description"]) > 60 else d["description"]
        close_info = d["closed_at"] if d["status"] == "closed" else "-"
        rows += f'''<tr>
            <td>{d["plugin_name"]}</td>
            <td>{d["host_name"]}</td>
            <td>{d["category"]}</td>
            <td>{d["subject"]}</td>
            <td>{desc}</td>
            <td class="text-center">{badge}</td>
            <td class="text-center">{d["created_at"]}</td>
            <td class="text-center">{close_info}</td>
        </tr>'''
    if not rows:
        rows = '<tr><td colspan="8" class="empty-state">No tickets for this report.</td></tr>'

    open_c = sum(1 for r in results if r["status"] == "open")
    closed_c = sum(1 for r in results if r["status"] == "closed")

    content = f'''
        <div class="back-link"><a href="/admin/adminregister/ticketview/{admin_id}/reports/">&larr; Back to Reports</a></div>
        <h1>Tickets &mdash; {admin_email} &mdash; Report {report_id}</h1>
        <div class="summary-box">
            <div class="summary-item"><div class="label">Total</div><div class="value">{len(results)}</div></div>
            <div class="summary-item open"><div class="label">Open</div><div class="value" style="color:#e74c3c;">{open_c}</div></div>
            <div class="summary-item closed"><div class="label">Closed</div><div class="value" style="color:#27ae60;">{closed_c}</div></div>
        </div>
        <div class="table-container"><table><thead><tr>
            <th style="width:15%;">Vulnerability</th>
            <th style="width:10%;">Host</th>
            <th style="width:10%;">Category</th>
            <th style="width:12%;">Subject</th>
            <th style="width:18%;">Description</th>
            <th class="text-center" style="width:8%;">Status</th>
            <th class="text-center" style="width:12%;">Created</th>
            <th class="text-center" style="width:12%;">Closed At</th>
        </tr></thead><tbody>{rows}</tbody></table></div>
    '''
    breadcrumbs = f'<a href="/admin/">Home</a> &rsaquo; <a href="/admin/adminregister/ticketview/">Tickets</a> &rsaquo; <a href="/admin/adminregister/ticketview/{admin_id}/reports/">{admin_email}</a> &rsaquo; Report'
    return HttpResponse(get_base_html(f"Tickets - Report", breadcrumbs, content, request.user.email))


# ══════════════════════════════════════════════════════
# VULNERABILITY CARDS
# ══════════════════════════════════════════════════════

def vuln_card_list_view(request):
    """Level 1: List all admins with vuln card counts."""
    if not _is_super(request):
        return HttpResponseForbidden("Access denied.")

    db = get_mongo_db()
    email_map = _get_admin_email_map()
    admins_data = []
    grand_open = 0
    grand_closed = 0

    if db:
        open_map = {}
        for doc in db[FIX_VULN_COLLECTION].aggregate([
            {"$match": {"created_by": {"$exists": True, "$ne": None}}},
            {"$group": {"_id": "$created_by", "count": {"$sum": 1}}}
        ]):
            open_map[doc["_id"]] = doc.get("count", 0)

        closed_map = {}
        for doc in db[FIX_VULN_CLOSED_COLLECTION].aggregate([
            {"$match": {"created_by": {"$exists": True, "$ne": None}}},
            {"$group": {"_id": "$created_by", "count": {"$sum": 1}}}
        ]):
            closed_map[doc["_id"]] = doc.get("count", 0)

        for aid in set(open_map.keys()) | set(closed_map.keys()):
            oc = open_map.get(aid, 0)
            cc = closed_map.get(aid, 0)
            grand_open += oc
            grand_closed += cc
            admins_data.append({
                "admin_id": aid,
                "admin_email": email_map.get(aid, aid),
                "open_count": oc, "closed_count": cc,
                "total": oc + cc,
            })

    rows = ""
    for d in admins_data:
        rows += f'''<tr>
            <td><a href="/admin/adminregister/vulncardview/{d["admin_id"]}/reports/" class="link">{d["admin_email"]}</a></td>
            <td class="text-center">{d["total"]}</td>
            <td class="text-center text-danger">{d["open_count"]}</td>
            <td class="text-center text-success">{d["closed_count"]}</td>
            <td class="text-center"><a href="/admin/adminregister/vulncardview/{d["admin_id"]}/reports/" class="btn">View Reports</a></td>
        </tr>'''
    if not rows:
        rows = '<tr><td colspan="5" class="empty-state">No vulnerability cards found.</td></tr>'

    content = f'''
        <h1>Vulnerability Cards Overview</h1>
        <div class="summary-box">
            <div class="summary-item"><div class="label">Total Admins</div><div class="value">{len(admins_data)}</div></div>
            <div class="summary-item open"><div class="label">Open</div><div class="value" style="color:#e74c3c;">{grand_open}</div></div>
            <div class="summary-item closed"><div class="label">Closed</div><div class="value" style="color:#27ae60;">{grand_closed}</div></div>
        </div>
        <div class="table-container"><table><thead><tr>
            <th style="width:30%;">Admin Email</th>
            <th class="text-center" style="width:15%;">Total</th>
            <th class="text-center" style="width:15%;">Open</th>
            <th class="text-center" style="width:15%;">Closed</th>
            <th class="text-center" style="width:15%;">Action</th>
        </tr></thead><tbody>{rows}</tbody></table></div>
    '''
    breadcrumbs = '<a href="/admin/">Home</a> &rsaquo; Vulnerability Cards'
    return HttpResponse(get_base_html("Vulnerability Cards", breadcrumbs, content, request.user.email))


def vuln_card_reports_view(request, admin_id):
    """Level 2: List reports for a specific admin."""
    if not _is_super(request):
        return HttpResponseForbidden("Access denied.")

    db = get_mongo_db()
    admin_email = _get_admin_email_by_id(admin_id) or admin_id
    reports = _get_admin_reports(db, str(admin_id))

    open_counts = {}
    closed_counts = {}
    if db:
        for doc in db[FIX_VULN_COLLECTION].aggregate([
            {"$match": {"created_by": str(admin_id)}},
            {"$group": {"_id": "$report_id", "count": {"$sum": 1}}}
        ]):
            open_counts[doc["_id"]] = doc.get("count", 0)

        for doc in db[FIX_VULN_CLOSED_COLLECTION].aggregate([
            {"$match": {"created_by": str(admin_id)}},
            {"$group": {"_id": "$report_id", "count": {"$sum": 1}}}
        ]):
            closed_counts[doc["_id"]] = doc.get("count", 0)

    rows = ""
    for r in reports:
        rid = r["report_id"]
        oc = open_counts.get(rid, 0)
        cc = closed_counts.get(rid, 0)
        rows += f'''<tr>
            <td>{r["filename"]}</td>
            <td class="text-center">{rid}</td>
            <td class="text-center text-danger">{oc}</td>
            <td class="text-center text-success">{cc}</td>
            <td class="text-center">{r["uploaded_at"]}</td>
            <td class="text-center"><a href="/admin/adminregister/vulncardview/{admin_id}/report/{rid}/" class="btn">View Details</a></td>
        </tr>'''
    if not rows:
        rows = '<tr><td colspan="6" class="empty-state">No reports found for this admin.</td></tr>'

    content = f'''
        <div class="back-link"><a href="/admin/adminregister/vulncardview/">&larr; Back to Vulnerability Cards</a></div>
        <h1>Vulnerability Cards &mdash; {admin_email}</h1>
        <div class="table-container"><table><thead><tr>
            <th style="width:22%;">Report File</th>
            <th class="text-center" style="width:18%;">Report ID</th>
            <th class="text-center" style="width:12%;">Open</th>
            <th class="text-center" style="width:12%;">Closed</th>
            <th class="text-center" style="width:16%;">Uploaded</th>
            <th class="text-center" style="width:14%;">Action</th>
        </tr></thead><tbody>{rows}</tbody></table></div>
    '''
    breadcrumbs = f'<a href="/admin/">Home</a> &rsaquo; <a href="/admin/adminregister/vulncardview/">Vulnerability Cards</a> &rsaquo; {admin_email}'
    return HttpResponse(get_base_html(f"Vulnerability Cards - {admin_email}", breadcrumbs, content, request.user.email))


def vuln_card_detail_view(request, admin_id, report_id):
    """Level 3: Show vuln cards for admin + report (open + closed)."""
    if not _is_super(request):
        return HttpResponseForbidden("Access denied.")

    db = get_mongo_db()
    admin_email = _get_admin_email_by_id(admin_id) or admin_id
    open_results = []
    closed_results = []

    if db:
        for doc in db[FIX_VULN_COLLECTION].find(
            {"created_by": str(admin_id), "report_id": str(report_id)}
        ).sort("created_at", -1):
            open_results.append({
                "plugin_name": doc.get("plugin_name", "-"),
                "host_name": doc.get("host_name", "-"),
                "risk_factor": doc.get("risk_factor", "-"),
                "port": doc.get("port", "-"),
                "assigned_team": doc.get("assigned_team", "-"),
                "vulnerability_type": doc.get("vulnerability_type", "-"),
                "created_at": _format_datetime(doc.get("created_at")),
            })

        for doc in db[FIX_VULN_CLOSED_COLLECTION].find(
            {"created_by": str(admin_id), "report_id": str(report_id)}
        ).sort("closed_at", -1):
            closed_results.append({
                "plugin_name": doc.get("plugin_name", "-"),
                "host_name": doc.get("host_name", "-"),
                "risk_factor": doc.get("risk_factor", "-"),
                "port": doc.get("port", "-"),
                "assigned_team": doc.get("assigned_team", "-"),
                "vulnerability_type": doc.get("vulnerability_type", "-"),
                "created_at": _format_datetime(doc.get("created_at")),
                "closed_at": _format_datetime(doc.get("closed_at")),
            })

    open_rows = ""
    for d in open_results:
        sc = _get_severity_class(d["risk_factor"])
        open_rows += f'''<tr>
            <td>{d["plugin_name"]}</td><td>{d["host_name"]}</td>
            <td class="text-center {sc}">{d["risk_factor"]}</td>
            <td class="text-center">{d["port"]}</td><td>{d["assigned_team"]}</td>
            <td>{d["vulnerability_type"]}</td><td class="text-center">{d["created_at"]}</td>
        </tr>'''
    if not open_rows:
        open_rows = '<tr><td colspan="7" class="empty-state">No open vulnerability cards.</td></tr>'

    closed_rows = ""
    for d in closed_results:
        sc = _get_severity_class(d["risk_factor"])
        closed_rows += f'''<tr>
            <td>{d["plugin_name"]}</td><td>{d["host_name"]}</td>
            <td class="text-center {sc}">{d["risk_factor"]}</td>
            <td class="text-center">{d["port"]}</td><td>{d["assigned_team"]}</td>
            <td>{d["vulnerability_type"]}</td><td class="text-center">{d["created_at"]}</td>
            <td class="text-center">{d["closed_at"]}</td>
        </tr>'''
    if not closed_rows:
        closed_rows = '<tr><td colspan="8" class="empty-state">No closed vulnerability cards.</td></tr>'

    content = f'''
        <div class="back-link"><a href="/admin/adminregister/vulncardview/{admin_id}/reports/">&larr; Back to Reports</a></div>
        <h1>Vulnerability Cards &mdash; {admin_email} &mdash; Report {report_id}</h1>
        <div class="summary-box">
            <div class="summary-item"><div class="label">Total</div><div class="value">{len(open_results) + len(closed_results)}</div></div>
            <div class="summary-item open"><div class="label">Open</div><div class="value" style="color:#e74c3c;">{len(open_results)}</div></div>
            <div class="summary-item closed"><div class="label">Closed</div><div class="value" style="color:#27ae60;">{len(closed_results)}</div></div>
        </div>

        <div style="margin-bottom:30px;">
            <h2 style="font-size:18px; color:#e74c3c; margin:0 0 15px 0; padding-bottom:10px; border-bottom:2px solid #e74c3c;">Open Vulnerabilities ({len(open_results)})</h2>
            <div class="table-container"><table><thead><tr>
                <th style="width:22%;">Vulnerability</th><th style="width:13%;">Host</th>
                <th class="text-center" style="width:10%;">Severity</th>
                <th class="text-center" style="width:8%;">Port</th>
                <th style="width:14%;">Assigned Team</th><th style="width:14%;">Type</th>
                <th class="text-center" style="width:12%;">Created</th>
            </tr></thead><tbody>{open_rows}</tbody></table></div>
        </div>

        <div style="margin-bottom:30px;">
            <h2 style="font-size:18px; color:#27ae60; margin:0 0 15px 0; padding-bottom:10px; border-bottom:2px solid #27ae60;">Closed Vulnerabilities ({len(closed_results)})</h2>
            <div class="table-container"><table><thead><tr>
                <th style="width:20%;">Vulnerability</th><th style="width:12%;">Host</th>
                <th class="text-center" style="width:9%;">Severity</th>
                <th class="text-center" style="width:7%;">Port</th>
                <th style="width:12%;">Assigned Team</th><th style="width:12%;">Type</th>
                <th class="text-center" style="width:11%;">Created</th>
                <th class="text-center" style="width:11%;">Closed</th>
            </tr></thead><tbody>{closed_rows}</tbody></table></div>
        </div>
    '''
    breadcrumbs = f'<a href="/admin/">Home</a> &rsaquo; <a href="/admin/adminregister/vulncardview/">Vulnerability Cards</a> &rsaquo; <a href="/admin/adminregister/vulncardview/{admin_id}/reports/">{admin_email}</a> &rsaquo; Report'
    return HttpResponse(get_base_html(f"Vulnerability Cards - Report", breadcrumbs, content, request.user.email))


# ══════════════════════════════════════════════════════
# ADMIN REGISTRATIONS
# ══════════════════════════════════════════════════════

@admin.register(SupportRequestView)
class SupportRequestViewAdmin(admin.ModelAdmin):
    def get_urls(self):
        urls = super().get_urls()
        return [
            path('<str:admin_id>/reports/', self.admin_site.admin_view(support_request_reports_view), name='sr_reports'),
            path('<str:admin_id>/report/<str:report_id>/', self.admin_site.admin_view(support_request_detail_view), name='sr_detail'),
        ] + urls

    def changelist_view(self, request, extra_context=None):
        return support_request_list_view(request)

    def has_module_permission(self, request):
        return _is_super(request)
    def has_view_permission(self, request, obj=None):
        return _is_super(request)
    def has_add_permission(self, request):
        return False
    def has_change_permission(self, request, obj=None):
        return False
    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(TicketView)
class TicketViewAdmin(admin.ModelAdmin):
    def get_urls(self):
        urls = super().get_urls()
        return [
            path('<str:admin_id>/reports/', self.admin_site.admin_view(ticket_reports_view), name='ticket_reports'),
            path('<str:admin_id>/report/<str:report_id>/', self.admin_site.admin_view(ticket_detail_view), name='ticket_detail'),
        ] + urls

    def changelist_view(self, request, extra_context=None):
        return ticket_list_view(request)

    def has_module_permission(self, request):
        return _is_super(request)
    def has_view_permission(self, request, obj=None):
        return _is_super(request)
    def has_add_permission(self, request):
        return False
    def has_change_permission(self, request, obj=None):
        return False
    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(VulnCardView)
class VulnCardViewAdmin(admin.ModelAdmin):
    def get_urls(self):
        urls = super().get_urls()
        return [
            path('<str:admin_id>/reports/', self.admin_site.admin_view(vuln_card_reports_view), name='vc_reports'),
            path('<str:admin_id>/report/<str:report_id>/', self.admin_site.admin_view(vuln_card_detail_view), name='vc_detail'),
        ] + urls

    def changelist_view(self, request, extra_context=None):
        return vuln_card_list_view(request)

    def has_module_permission(self, request):
        return _is_super(request)
    def has_view_permission(self, request, obj=None):
        return _is_super(request)
    def has_add_permission(self, request):
        return False
    def has_change_permission(self, request, obj=None):
        return False
    def has_delete_permission(self, request, obj=None):
        return False
