from django.contrib import admin
from django.conf import settings
from django.http import HttpResponse, HttpResponseForbidden
from django.urls import path
import pymongo

from .models import AdminAssetsView

NESSUS_COLLECTION = "nessus_reports"
HOLD_COLLECTION = "hold_assets"


def get_mongo_db():
    """Get MongoDB database connection."""
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
    """Generate base HTML template with improved styling."""
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>{title} | Django site admin</title>
        <style>
            * {{ box-sizing: border-box; }}
            body {{
                font-family: "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                margin: 0;
                padding: 0;
                background: #f5f7fa;
                color: #333;
            }}
            #header {{
                background: linear-gradient(135deg, #417690 0%, #2c5364 100%);
                color: #fff;
                padding: 15px 40px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            #header h1 {{ margin: 0; font-size: 20px; font-weight: 500; }}
            #header a {{ color: #fff; text-decoration: none; }}
            #user-tools {{ font-size: 13px; opacity: 0.9; }}
            #user-tools a {{ color: #fff; margin-left: 15px; text-decoration: underline; }}
            .breadcrumbs {{
                background: #79aec8;
                padding: 12px 40px;
                font-size: 13px;
                color: rgba(255,255,255,0.8);
            }}
            .breadcrumbs a {{ color: #fff; text-decoration: none; }}
            .breadcrumbs a:hover {{ text-decoration: underline; }}
            #content {{ padding: 25px 40px; max-width: 1400px; }}
            #content h1 {{
                font-size: 24px;
                color: #2c3e50;
                margin: 0 0 25px 0;
                font-weight: 600;
            }}

            /* Summary Cards */
            .summary-box {{
                display: flex;
                gap: 15px;
                margin-bottom: 25px;
                flex-wrap: wrap;
            }}
            .summary-item {{
                background: #fff;
                padding: 20px 30px;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                text-align: center;
                min-width: 140px;
                border-left: 4px solid #417690;
            }}
            .summary-item.active {{ border-left-color: #417690; }}
            .summary-item.hold {{ border-left-color: #ff9800; }}
            .summary-item .label {{
                font-size: 12px;
                color: #7f8c8d;
                margin-bottom: 8px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            .summary-item .value {{
                font-size: 28px;
                font-weight: 700;
                color: #2c3e50;
            }}

            /* Tables */
            .table-container {{
                background: #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                border-radius: 8px;
                overflow: hidden;
                margin-bottom: 25px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            thead th {{
                background: #34495e;
                color: #fff;
                padding: 14px 16px;
                text-align: left;
                font-weight: 600;
                font-size: 13px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                border-bottom: 2px solid #2c3e50;
            }}
            thead th.text-center {{ text-align: center; }}
            thead th.text-right {{ text-align: right; }}
            tbody td {{
                font-size: 14px;
                padding: 14px 16px;
                border-bottom: 1px solid #ecf0f1;
                vertical-align: middle;
            }}
            tbody td.text-center {{ text-align: center; }}
            tbody td.text-right {{ text-align: right; }}
            tbody tr:hover {{ background: #f8f9fa; }}
            tbody tr:last-child td {{ border-bottom: none; }}

            /* Links & Buttons */
            .link {{ color: #3498db; text-decoration: none; font-weight: 500; }}
            .link:hover {{ color: #2980b9; text-decoration: underline; }}
            .btn {{
                display: inline-block;
                padding: 8px 16px;
                background: #3498db;
                color: #fff;
                text-decoration: none;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 500;
                transition: background 0.2s;
            }}
            .btn:hover {{ background: #2980b9; }}

            /* Back Link */
            .back-link {{
                margin-bottom: 20px;
                font-size: 14px;
            }}
            .back-link a {{
                color: #3498db;
                text-decoration: none;
                display: inline-flex;
                align-items: center;
            }}
            .back-link a:hover {{ text-decoration: underline; }}

            /* Sections */
            .section {{ margin-bottom: 30px; }}
            .section h2 {{
                font-size: 18px;
                color: #2c3e50;
                margin: 0 0 15px 0;
                padding-bottom: 10px;
                border-bottom: 2px solid #ecf0f1;
                font-weight: 600;
            }}
            .section h2.hold {{ color: #e67e22; border-bottom-color: #f39c12; }}

            /* Status Colors */
            .text-primary {{ color: #3498db; font-weight: 600; }}
            .text-success {{ color: #27ae60; font-weight: 600; }}
            .text-warning {{ color: #f39c12; font-weight: 600; }}
            .text-danger {{ color: #e74c3c; font-weight: 600; }}
            .text-muted {{ color: #95a5a6; }}

            /* Empty State */
            .empty-state {{
                padding: 40px 20px;
                text-align: center;
                color: #7f8c8d;
                background: #fafbfc;
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


def admin_list_view(request):
    """Main view: List all admins with summary."""
    if not request.user.is_authenticated or not getattr(request.user, 'is_superuser', False):
        return HttpResponseForbidden("Access denied. Super Admin only.")

    db = get_mongo_db()
    admins_data = []

    if db:
        coll = db[NESSUS_COLLECTION]
        held_coll = db[HOLD_COLLECTION]

        pipeline = [
            {"$match": {"admin_email": {"$exists": True, "$ne": None}}},
            {"$sort": {"uploaded_at": -1}},
            {"$group": {
                "_id": "$admin_email",
                "admin_id": {"$first": "$admin_id"},
                "total_reports": {"$sum": 1},
                "latest_upload": {"$first": "$uploaded_at"},
            }}
        ]

        for admin_data in coll.aggregate(pipeline):
            admin_email = admin_data["_id"]
            admin_id = admin_data.get("admin_id")

            report_ids = [r["report_id"] for r in coll.find(
                {"$or": [{"admin_id": admin_id}, {"admin_email": admin_email}]},
                {"report_id": 1}
            )]

            total_active = 0
            for rid in report_ids:
                doc = coll.find_one({"report_id": rid}, {"vulnerabilities_by_host": 1})
                if doc:
                    total_active += len(doc.get("vulnerabilities_by_host", []))

            held_count = held_coll.count_documents({"report_id": {"$in": report_ids}}) if report_ids else 0

            latest_upload = admin_data.get("latest_upload")
            latest_upload_str = latest_upload.strftime("%Y-%m-%d %H:%M") if latest_upload else "-"

            admins_data.append({
                "admin_email": admin_email,
                "total_reports": admin_data.get("total_reports", 0),
                "total_active": total_active,
                "held_count": held_count,
                "latest_upload": latest_upload_str,
            })

    rows = ""
    for i, d in enumerate(admins_data):
        rows += f'''
        <tr>
            <td><a href="/admin/adminasset/adminassetsview/{d["admin_email"].replace("@", "%40")}/reports/" class="link">{d["admin_email"]}</a></td>
            <td class="text-center">{d["total_reports"]}</td>
            <td class="text-center text-primary">{d["total_active"]}</td>
            <td class="text-center {'text-warning' if d["held_count"] > 0 else 'text-muted'}">{d["held_count"]}</td>
            <td class="text-center">{d["latest_upload"]}</td>
            <td class="text-center"><a href="/admin/adminasset/adminassetsview/{d["admin_email"].replace("@", "%40")}/reports/" class="btn">View Reports</a></td>
        </tr>
        '''

    if not rows:
        rows = '<tr><td colspan="6" class="empty-state">No admin data found. Upload reports to see data here.</td></tr>'

    content = f'''
        <h1>Admin Assets Overview</h1>
        <div class="summary-box">
            <div class="summary-item">
                <div class="label">Total Admins</div>
                <div class="value">{len(admins_data)}</div>
            </div>
            <div class="summary-item active">
                <div class="label">Active Assets</div>
                <div class="value" style="color:#3498db;">{sum(d["total_active"] for d in admins_data)}</div>
            </div>
            <div class="summary-item hold">
                <div class="label">On Hold</div>
                <div class="value" style="color:#f39c12;">{sum(d["held_count"] for d in admins_data)}</div>
            </div>
        </div>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th style="width: 28%;">Admin Email</th>
                        <th class="text-center" style="width: 12%;">Reports</th>
                        <th class="text-center" style="width: 15%;">Active Assets</th>
                        <th class="text-center" style="width: 15%;">On Hold</th>
                        <th class="text-center" style="width: 15%;">Latest Upload</th>
                        <th class="text-center" style="width: 15%;">Action</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    '''

    breadcrumbs = '<a href="/admin/">Home</a> &rsaquo; Admin Assets'
    return HttpResponse(get_base_html("Admin Assets", breadcrumbs, content, request.user.email))


def admin_reports_view(request, admin_email):
    """View all reports for a specific admin."""
    if not request.user.is_authenticated or not getattr(request.user, 'is_superuser', False):
        return HttpResponseForbidden("Access denied.")

    admin_email = admin_email.replace("%40", "@")
    db = get_mongo_db()
    reports = []

    if db:
        coll = db[NESSUS_COLLECTION]
        held_coll = db[HOLD_COLLECTION]

        for doc in coll.find({"admin_email": admin_email}).sort("uploaded_at", -1):
            report_id = doc.get("report_id")
            active = len(doc.get("vulnerabilities_by_host", []))
            held = held_coll.count_documents({"report_id": report_id})
            uploaded = doc.get("uploaded_at")
            uploaded_str = uploaded.strftime("%Y-%m-%d %H:%M") if uploaded else "-"

            reports.append({
                "report_id": report_id,
                "filename": doc.get("original_filename", "-"),
                "member_type": doc.get("member_type", "-").title(),
                "active": active,
                "held": held,
                "uploaded_at": uploaded_str,
            })

    rows = ""
    for i, r in enumerate(reports):
        short_id = r["report_id"][:24] + "..." if len(r["report_id"]) > 24 else r["report_id"]
        rows += f'''
        <tr>
            <td><a href="/admin/adminasset/adminassetsview/{admin_email.replace("@", "%40")}/report/{r["report_id"]}/" class="link" title="{r["report_id"]}">{short_id}</a></td>
            <td>{r["filename"]}</td>
            <td class="text-center">{r["member_type"]}</td>
            <td class="text-center text-primary">{r["active"]}</td>
            <td class="text-center {'text-warning' if r["held"] > 0 else 'text-muted'}">{r["held"]}</td>
            <td class="text-center">{r["uploaded_at"]}</td>
            <td class="text-center"><a href="/admin/adminasset/adminassetsview/{admin_email.replace("@", "%40")}/report/{r["report_id"]}/" class="btn">View Assets</a></td>
        </tr>
        '''

    if not rows:
        rows = '<tr><td colspan="7" class="empty-state">No reports found for this admin.</td></tr>'

    content = f'''
        <div class="back-link"><a href="/admin/adminasset/adminassetsview/">&larr; Back to All Admins</a></div>
        <h1>Reports for {admin_email}</h1>
        <div class="summary-box">
            <div class="summary-item">
                <div class="label">Total Reports</div>
                <div class="value">{len(reports)}</div>
            </div>
            <div class="summary-item active">
                <div class="label">Active Assets</div>
                <div class="value" style="color:#3498db;">{sum(r["active"] for r in reports)}</div>
            </div>
            <div class="summary-item hold">
                <div class="label">On Hold</div>
                <div class="value" style="color:#f39c12;">{sum(r["held"] for r in reports)}</div>
            </div>
        </div>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th style="width: 20%;">Report ID</th>
                        <th style="width: 22%;">Filename</th>
                        <th class="text-center" style="width: 12%;">Type</th>
                        <th class="text-center" style="width: 12%;">Active</th>
                        <th class="text-center" style="width: 12%;">On Hold</th>
                        <th class="text-center" style="width: 12%;">Uploaded</th>
                        <th class="text-center" style="width: 10%;">Action</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    '''

    breadcrumbs = f'<a href="/admin/">Home</a> &rsaquo; <a href="/admin/adminasset/adminassetsview/">Admin Assets</a> &rsaquo; {admin_email}'
    return HttpResponse(get_base_html(f"Reports - {admin_email}", breadcrumbs, content, request.user.email))


def report_assets_view(request, admin_email, report_id):
    """View assets for a specific report."""
    if not request.user.is_authenticated or not getattr(request.user, 'is_superuser', False):
        return HttpResponseForbidden("Access denied.")

    admin_email = admin_email.replace("%40", "@")
    db = get_mongo_db()

    active_assets = []
    held_assets = []

    if db:
        coll = db[NESSUS_COLLECTION]
        held_coll = db[HOLD_COLLECTION]

        doc = coll.find_one({"report_id": report_id})
        if doc:
            for h in doc.get("vulnerabilities_by_host", []):
                host_name = h.get("host_name") or h.get("host") or "-"
                vulns = h.get("vulnerabilities", [])
                severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for v in vulns:
                    risk = (v.get("risk_factor") or "").lower()
                    if risk.startswith("crit"): severity["critical"] += 1
                    elif risk.startswith("high"): severity["high"] += 1
                    elif risk.startswith("med"): severity["medium"] += 1
                    elif risk.startswith("low"): severity["low"] += 1
                active_assets.append({"host": host_name, "vulns": len(vulns), "severity": severity})

        for h in held_coll.find({"report_id": report_id}):
            host_entry = h.get("host_entry", {})
            vulns = host_entry.get("vulnerabilities", [])
            held_assets.append({
                "host": h.get("host_name", "-"),
                "vulns": len(vulns),
                "held_at": h.get("held_at").strftime("%Y-%m-%d %H:%M") if h.get("held_at") else "-",
                "held_by": h.get("held_by", "-"),
            })

    # Active assets table
    active_rows = ""
    for a in active_assets:
        active_rows += f'''
        <tr>
            <td>{a["host"]}</td>
            <td class="text-center">{a["vulns"]}</td>
            <td class="text-center text-danger">{a["severity"]["critical"]}</td>
            <td class="text-center text-warning">{a["severity"]["high"]}</td>
            <td class="text-center" style="color:#f1c40f;">{a["severity"]["medium"]}</td>
            <td class="text-center text-success">{a["severity"]["low"]}</td>
        </tr>'''
    if not active_rows:
        active_rows = '<tr><td colspan="6" class="empty-state">No active assets in this report</td></tr>'

    # Held assets table
    held_rows = ""
    for h in held_assets:
        held_rows += f'''
        <tr>
            <td>{h["host"]}</td>
            <td class="text-center">{h["vulns"]}</td>
            <td class="text-center">{h["held_at"]}</td>
            <td>{h["held_by"]}</td>
        </tr>'''
    if not held_rows:
        held_rows = '<tr><td colspan="4" class="empty-state">No assets on hold</td></tr>'

    short_report_id = report_id[:30] + "..." if len(report_id) > 30 else report_id

    content = f'''
        <div class="back-link"><a href="/admin/adminasset/adminassetsview/{admin_email.replace("@", "%40")}/reports/">&larr; Back to Reports</a></div>
        <h1>Report: {short_report_id}</h1>
        <div class="summary-box">
            <div class="summary-item active">
                <div class="label">Active Assets</div>
                <div class="value" style="color:#3498db;">{len(active_assets)}</div>
            </div>
            <div class="summary-item hold">
                <div class="label">On Hold</div>
                <div class="value" style="color:#f39c12;">{len(held_assets)}</div>
            </div>
        </div>

        <div class="section">
            <h2>Active Assets ({len(active_assets)})</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 30%;">Host / Asset</th>
                            <th class="text-center" style="width: 14%;">Vulnerabilities</th>
                            <th class="text-center" style="width: 14%;">Critical</th>
                            <th class="text-center" style="width: 14%;">High</th>
                            <th class="text-center" style="width: 14%;">Medium</th>
                            <th class="text-center" style="width: 14%;">Low</th>
                        </tr>
                    </thead>
                    <tbody>{active_rows}</tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <h2 class="hold">Assets On Hold ({len(held_assets)})</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 35%;">Host / Asset</th>
                            <th class="text-center" style="width: 15%;">Vulnerabilities</th>
                            <th class="text-center" style="width: 25%;">Held At</th>
                            <th style="width: 25%;">Held By</th>
                        </tr>
                    </thead>
                    <tbody>{held_rows}</tbody>
                </table>
            </div>
        </div>
    '''

    breadcrumbs = f'<a href="/admin/">Home</a> &rsaquo; <a href="/admin/adminasset/adminassetsview/">Admin Assets</a> &rsaquo; <a href="/admin/adminasset/adminassetsview/{admin_email.replace("@", "%40")}/reports/">{admin_email}</a> &rsaquo; Report'
    return HttpResponse(get_base_html("Report Assets", breadcrumbs, content, request.user.email))


@admin.register(AdminAssetsView)
class AdminAssetsViewAdmin(admin.ModelAdmin):
    """Admin panel for Admin Assets with drill-down views."""

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('<str:admin_email>/reports/', self.admin_site.admin_view(admin_reports_view), name='admin_reports'),
            path('<str:admin_email>/report/<str:report_id>/', self.admin_site.admin_view(report_assets_view), name='report_assets'),
        ]
        return custom_urls + urls

    def changelist_view(self, request, extra_context=None):
        return admin_list_view(request)

    def has_module_permission(self, request):
        return request.user.is_authenticated and getattr(request.user, 'is_superuser', False)

    def has_view_permission(self, request, obj=None):
        return request.user.is_authenticated and getattr(request.user, 'is_superuser', False)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
