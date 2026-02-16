from django.contrib import admin
from django import forms
from django.conf import settings
from django.contrib import messages
from .models import UploadReport
from users.models import User
from scope.models import Scope
import hashlib
import os
import datetime
import pymongo


def check_admin_has_locked_scope(admin_id):
    """Check if admin has at least one locked scope using Django ORM."""
    try:
        return Scope.objects.filter(admin_id=admin_id, is_locked=True).exists()
    except Exception:
        return False


class UploadReportAdminForm(forms.ModelForm):
    """Custom form for Upload Report with Admin dropdown."""

    admin_select = forms.ChoiceField(
        choices=[],
        required=True,
        label="Select Admin",
    )

    class Meta:
        model = UploadReport
        fields = ['file']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Build choices list for admin dropdown (show only email)
        choices = [('', '--- Select Admin ---')]
        try:
            for user in User.objects.all():
                if user.is_staff:
                    choices.append((str(user.id), user.email))
        except Exception:
            pass

        self.fields['admin_select'].choices = choices

        if self.instance and self.instance.pk and self.instance.admin:
            self.fields['admin_select'].initial = str(self.instance.admin.id)

    def clean_admin_select(self):
        admin_id = self.cleaned_data.get('admin_select')
        if not admin_id:
            raise forms.ValidationError("Please select an admin.")
        try:
            admin_user = User.objects.get(id=admin_id)
        except User.DoesNotExist:
            raise forms.ValidationError("Selected admin does not exist.")

        # Check if the admin has at least one locked scope using direct MongoDB query
        has_locked_scope = check_admin_has_locked_scope(admin_id)

        if not has_locked_scope:
            raise forms.ValidationError(
                f"Cannot upload report: Admin '{admin_user.email}' does not have any locked scope. "
                "Please lock the admin's scope first before uploading reports."
            )

        return admin_user


@admin.register(UploadReport)
class UploadReportAdmin(admin.ModelAdmin):
    form = UploadReportAdminForm

    list_display = ('_id', 'file', 'get_admin_id', 'get_admin_email', 'uploaded_at')
    search_fields = ('file',)
    list_filter = ('uploaded_at',)
    readonly_fields = ()
    exclude = ('file_hash', 'location', 'admin', 'uploaded_at', 'created_at', 'updated_at', 'parsed_count', 'member_type', 'status')

    def get_admin_id(self, obj):
        return getattr(obj.admin, "id", None)
    get_admin_id.short_description = "Admin ID"

    def get_admin_email(self, obj):
        return getattr(obj.admin, "email", None)
    get_admin_email.short_description = "Admin Email"

    def _generate_file_hash(self, uploaded_file):
        """Generate SHA256 hash for the uploaded file."""
        hasher = hashlib.sha256()
        for chunk in uploaded_file.chunks():
            hasher.update(chunk)
        uploaded_file.seek(0)
        return hasher.hexdigest()

    def _get_mongo_uri(self):
        """Get MongoDB URI from Django settings."""
        try:
            return settings.DATABASES['default']['CLIENT']['host']
        except Exception:
            return getattr(settings, "MONGO_DB_URL", None)

    def _get_mongo_db(self, client):
        """Get MongoDB database instance."""
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

    def _prepare_hosts_for_storage(self, hosts):
        """Prepare hosts data for MongoDB storage."""
        prepared_hosts = []
        for host in hosts:
            prepared_vulns = []
            for vuln in host.get("vulnerabilities", []):
                vuln_copy = vuln.copy()
                if "risk_factor" in vuln_copy and vuln_copy["risk_factor"]:
                    risk = str(vuln_copy["risk_factor"]).strip()
                    vuln_copy["risk_factor"] = risk.title() if risk else ""
                prepared_vulns.append(vuln_copy)
            prepared_hosts.append({
                "host_name": host.get("host_name"),
                "host_information": host.get("host_information", {}),
                "vulnerabilities": prepared_vulns
            })
        return prepared_hosts

    def _store_in_mongodb(self, parsed_data, report_id, admin_email, original_filename, member_type):
        """Store parsed report data in MongoDB."""
        mongo_uri = self._get_mongo_uri()
        if not mongo_uri:
            return False

        try:
            with pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000) as client:
                db = self._get_mongo_db(client)

                # Resolve admin_id from admin_email
                admin_id = None
                if admin_email:
                    try:
                        admin_user = User.objects.filter(email=admin_email).first()
                        if admin_user:
                            admin_id = str(admin_user.id)
                    except Exception:
                        pass

                document = {
                    "report_id": report_id,
                    "original_filename": original_filename,
                    "location_id": "",
                    "location_name": "",
                    "admin_id": admin_id,
                    "admin_email": admin_email,
                    "member_type": member_type,
                    "uploaded_at": datetime.datetime.utcnow(),
                    "report_type": parsed_data.get("type", "unknown"),
                }

                if parsed_data.get("type") in ("nessus_html", "nessus"):
                    hosts_payload = self._prepare_hosts_for_storage(
                        parsed_data.get("vulnerabilities_by_host", [])
                    )
                    document.update({
                        "scan_info": parsed_data.get("scan_info", {}),
                        "total_hosts": parsed_data.get("total_hosts", 0),
                        "total_vulnerabilities": parsed_data.get("total_vulnerabilities", 0),
                        "vulnerabilities_by_host": hosts_payload
                    })
                    db["nessus_reports"].insert_one(document)
                else:
                    document["parsed_data"] = parsed_data
                    db["parsed_reports"].insert_one(document)

                return True
        except Exception as e:
            print(f"MongoDB storage error: {e}")
            return False

    def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
        extra_context = extra_context or {}
        extra_context['show_save_and_add_another'] = False
        extra_context['show_save_and_continue'] = False
        return super().changeform_view(request, object_id, form_url, extra_context)

    def save_model(self, request, obj, form, change):
        """Save model and parse/store file data in MongoDB."""
        admin_user = form.cleaned_data.get('admin_select')
        obj.admin = admin_user

        uploaded_file = form.cleaned_data.get('file')
        is_new_file = uploaded_file and hasattr(uploaded_file, 'chunks')

        if is_new_file:
            # Generate file hash
            obj.file_hash = self._generate_file_hash(uploaded_file)

            # Save file under admin's folder
            admin_id = str(admin_user.id)
            new_filename = f"reports/{admin_id}/{uploaded_file.name}"
            file_dir = os.path.join(settings.MEDIA_ROOT, f"reports/{admin_id}")
            os.makedirs(file_dir, exist_ok=True)

            # Save the file manually
            file_path = os.path.join(settings.MEDIA_ROOT, new_filename)
            with open(file_path, 'wb+') as dest:
                for chunk in uploaded_file.chunks():
                    dest.write(chunk)

            obj.file.name = new_filename

        # Save the model first
        obj.save()

        # Parse and store data in MongoDB for new files
        if is_new_file:
            try:
                from .parsers import dispatch_parse

                file_path = os.path.join(settings.MEDIA_ROOT, obj.file.name)
                parsed_data = dispatch_parse(file_path, uploaded_file.name)

                if parsed_data and "error" not in parsed_data:
                    # Calculate parsed count
                    parsed_count = 1
                    if parsed_data.get("type") in ("nessus", "nessus_html"):
                        parsed_count = parsed_data.get("total_vulnerabilities", 1) or 1
                    elif "rows" in parsed_data:
                        parsed_count = parsed_data.get("rows", 1)

                    # Update parsed count and status
                    obj.parsed_count = parsed_count
                    obj.status = "Successfully Processed"
                    obj.save()

                    # Store in MongoDB
                    mongodb_stored = self._store_in_mongodb(
                        parsed_data=parsed_data,
                        report_id=str(obj._id),
                        admin_email=admin_user.email,
                        original_filename=uploaded_file.name,
                        member_type=obj.member_type or "external"
                    )

                    if mongodb_stored:
                        messages.success(request, f"File parsed and stored in database. Found {parsed_count} vulnerabilities.")
                    else:
                        messages.warning(request, "File saved but MongoDB storage failed.")
                else:
                    error_msg = parsed_data.get("error", "Unknown parsing error")
                    obj.status = "Parse Error"
                    obj.save()
                    messages.error(request, f"File parsing failed: {error_msg}")

            except ImportError:
                messages.error(request, "Parser module not found. File saved but not parsed.")
            except Exception as e:
                messages.error(request, f"Error parsing file: {str(e)}")

    # Restrict all permissions to Super Admin only
    def has_module_permission(self, request):
        if not request.user.is_authenticated:
            return False
        return getattr(request.user, 'is_superuser', False)

    def has_view_permission(self, request, obj=None):
        if not request.user.is_authenticated:
            return False
        return getattr(request.user, 'is_superuser', False)

    def has_add_permission(self, request):
        if not request.user.is_authenticated:
            return False
        return getattr(request.user, 'is_superuser', False)

    def has_change_permission(self, request, obj=None):
        if not request.user.is_authenticated:
            return False
        return getattr(request.user, 'is_superuser', False)

    def has_delete_permission(self, request, obj=None):
        if not request.user.is_authenticated:
            return False
        return getattr(request.user, 'is_superuser', False)
