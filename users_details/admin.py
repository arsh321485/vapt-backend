from django.contrib import admin
from django.http import HttpResponse, HttpResponseForbidden
from django.urls import path

from .models import UserDetail
from users.models import User


def _is_super(request):
    return request.user.is_authenticated and getattr(request.user, 'is_superuser', False)


def _format_datetime(dt):
    if dt:
        try:
            return dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            return str(dt)
    return "-"


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
                font-size: 11px; font-weight: 600;
            }}
            .text-primary {{ color: #3498db; font-weight: 600; }}
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


def team_list_view(request):
    """Level 1: List all admins with their team member counts."""
    if not _is_super(request):
        return HttpResponseForbidden("Access denied.")

    admins_data = []
    total_members = 0

    try:
        # Get all admins that have team members
        admin_ids = UserDetail.objects.values_list('admin_id', flat=True).distinct()
        for admin_id in admin_ids:
            try:
                admin_user = User.objects.get(id=admin_id)
                admin_email = admin_user.email
            except User.DoesNotExist:
                admin_email = str(admin_id)

            count = UserDetail.objects.filter(admin_id=admin_id).count()
            total_members += count

            admins_data.append({
                "admin_id": str(admin_id),
                "admin_email": admin_email,
                "member_count": count,
            })
    except Exception:
        pass

    rows = ""
    for d in admins_data:
        rows += f'''<tr>
            <td><a href="/admin/users_details/userdetail/{d["admin_id"]}/members/" class="link">{d["admin_email"]}</a></td>
            <td class="text-center">{d["member_count"]}</td>
            <td class="text-center"><a href="/admin/users_details/userdetail/{d["admin_id"]}/members/" class="btn">View Members</a></td>
        </tr>'''
    if not rows:
        rows = '<tr><td colspan="3" class="empty-state">No team members found.</td></tr>'

    content = f'''
        <h1>Team Overview</h1>
        <div class="summary-box">
            <div class="summary-item"><div class="label">Total Admins</div><div class="value">{len(admins_data)}</div></div>
            <div class="summary-item"><div class="label">Total Members</div><div class="value">{total_members}</div></div>
        </div>
        <div class="table-container"><table><thead><tr>
            <th style="width:40%;">Admin Email</th>
            <th class="text-center" style="width:25%;">Team Members</th>
            <th class="text-center" style="width:25%;">Action</th>
        </tr></thead><tbody>{rows}</tbody></table></div>
    '''
    breadcrumbs = '<a href="/admin/">Home</a> &rsaquo; Teams'
    return HttpResponse(get_base_html("Teams", breadcrumbs, content, request.user.email))


def team_members_view(request, admin_id):
    """Level 2: Show team members for a specific admin."""
    if not _is_super(request):
        return HttpResponseForbidden("Access denied.")

    try:
        admin_user = User.objects.get(id=admin_id)
        admin_email = admin_user.email
    except User.DoesNotExist:
        admin_email = str(admin_id)

    members = []
    try:
        for ud in UserDetail.objects.filter(admin_id=admin_id).order_by('-created_at'):
            roles = ud.Member_role
            if isinstance(roles, list):
                roles = ", ".join(roles)
            members.append({
                "first_name": ud.first_name,
                "last_name": ud.last_name,
                "email": ud.email,
                "user_type": ud.user_type,
                "roles": roles or "-",
                "created_at": _format_datetime(ud.created_at),
            })
    except Exception:
        pass

    rows = ""
    for d in members:
        rows += f'''<tr>
            <td>{d["first_name"]}</td>
            <td>{d["last_name"]}</td>
            <td>{d["email"]}</td>
            <td class="text-center">{d["user_type"]}</td>
            <td>{d["roles"]}</td>
            <td class="text-center">{d["created_at"]}</td>
        </tr>'''
    if not rows:
        rows = '<tr><td colspan="6" class="empty-state">No team members found for this admin.</td></tr>'

    content = f'''
        <div class="back-link"><a href="/admin/users_details/userdetail/">&larr; Back to Teams</a></div>
        <h1>Team &mdash; {admin_email}</h1>
        <div class="summary-box">
            <div class="summary-item"><div class="label">Total Members</div><div class="value">{len(members)}</div></div>
        </div>
        <div class="table-container"><table><thead><tr>
            <th style="width:14%;">First Name</th>
            <th style="width:14%;">Last Name</th>
            <th style="width:22%;">Email</th>
            <th class="text-center" style="width:12%;">User Type</th>
            <th style="width:22%;">Roles</th>
            <th class="text-center" style="width:14%;">Created</th>
        </tr></thead><tbody>{rows}</tbody></table></div>
    '''
    breadcrumbs = f'<a href="/admin/">Home</a> &rsaquo; <a href="/admin/users_details/userdetail/">Teams</a> &rsaquo; {admin_email}'
    return HttpResponse(get_base_html(f"Team - {admin_email}", breadcrumbs, content, request.user.email))


@admin.register(UserDetail)
class UserDetailAdmin(admin.ModelAdmin):

    def get_urls(self):
        urls = super().get_urls()
        return [
            path('<str:admin_id>/members/', self.admin_site.admin_view(team_members_view), name='team_members'),
        ] + urls

    def changelist_view(self, request, extra_context=None):
        return team_list_view(request)

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
