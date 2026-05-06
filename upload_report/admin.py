from django.contrib import admin
from django import forms
from django.conf import settings
from django.contrib import messages
from .models import UploadReport
from users.models import User
import hashlib
import os
import datetime
import threading
import logging
import time
import pymongo
from django.db import transaction
from django.db.utils import DatabaseError

logger = logging.getLogger(__name__)
def check_admin_scoping_complete(admin_user):
    """Check if admin has completed both scoping forms (ProjectDetail + TestingMethodology)."""
    try:
        from scoping.models import ProjectDetail, TestingMethodology
        has_project = ProjectDetail.objects.filter(admin=admin_user).exists()
        has_methodology = TestingMethodology.objects.filter(admin=admin_user).exists()
        return has_project and has_methodology
    except Exception as e:
        logger.error(f"[ScopingCheck] Failed: {e}")
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
        # NOTE: djongo has a bug with boolean filters (is_staff=True generates broken SQL)
        # So we use direct pymongo query instead of Django ORM
        choices = [('', '--- Select Admin ---')]
        try:
            from django.conf import settings
            import pymongo as _pymongo
            mongo_uri = settings.DATABASES['default']['CLIENT']['host']
            with _pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000) as _client:
                try:
                    _db = _client.get_default_database()
                except Exception:
                    _db = _client[settings.DATABASES['default'].get('NAME', 'vaptfix')]
                admin_docs = list(_db["users_user"].find(
                    {"is_staff": True, "is_active": True, "is_superuser": {"$ne": True}},
                    {"id": 1, "email": 1, "_id": 0}
                ))
            choices += [(str(doc["id"]), doc["email"]) for doc in admin_docs if doc.get("email")]
            logger.info(f"[UploadReportAdminForm] Loaded {len(admin_docs)} admins")
        except Exception as e:
            logger.error(f"[UploadReportAdminForm] Failed to load admin list: {e}")

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

        # Check if admin has completed scoping forms
        scoping_complete = check_admin_scoping_complete(admin_user)

        if not scoping_complete:
            raise forms.ValidationError(
                f"Cannot upload report: Admin '{admin_user.email}' has not completed the scoping form "
                "(Project Details + Testing Methodology). Please ask the admin to complete the scoping form first."
            )

        return admin_user


@admin.register(UploadReport)
class UploadReportAdmin(admin.ModelAdmin):
    form = UploadReportAdminForm

    list_display = ('_id', 'file', 'status', 'parsed_count', 'get_admin_id', 'get_admin_email', 'uploaded_at')
    search_fields = ('file',)
    list_filter = ('uploaded_at',)
    readonly_fields = ()
    exclude = ('file_hash', 'location', 'admin', 'uploaded_at', 'created_at', 'updated_at', 'parsed_count', 'member_type', 'status')

    class Media:
        js = ("upload_report/admin_upload_timing.js",)

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

    def _seconds_to_text(self, seconds):
        sec = max(0, int(round(seconds or 0)))
        mins, rem = divmod(sec, 60)
        if mins > 0:
            return f"{mins} min {rem} sec"
        return f"{rem} sec"

    def _estimate_upload_seconds(self, file_size_bytes, filename):
        ext = os.path.splitext(filename or "")[1].lower()
        size_mb = (file_size_bytes or 0) / (1024 * 1024)
        if ext in (".nessus", ".xml", ".html", ".htm"):
            estimate = 20 + (size_mb * 4.0)
        elif ext in (".xlsx", ".xls", ".csv"):
            estimate = 8 + (size_mb * 1.5)
        else:
            estimate = 6 + (size_mb * 1.0)
        return int(max(8, min(estimate, 3600)))

    def _estimate_agent_seconds(self, parsed_count, parsed_type):
        if parsed_type not in ("nessus", "nessus_html"):
            return 0
        vuln_count = int(parsed_count or 0)
        # Base startup + per-card average generation latency.
        return int(max(45, min(45 + (vuln_count * 2), 7200)))

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
        except Exception as e:
            logger.warning("Suppressed error: %s", e)
        try:
            dbname = settings.DATABASES['default'].get('NAME')
            if dbname:
                return client[dbname]
        except Exception as e:
            logger.warning("Suppressed error: %s", e)
        return client["vaptfix"]

    def _prepare_hosts_for_storage(self, hosts):
        """Prepare hosts data for MongoDB storage."""
        prepared_hosts = []
        for host in hosts:
            # Group by plugin_name — collect all plugin_outputs as an array
            grouped = {}  # plugin_name -> vuln_dict
            for vuln in host.get("vulnerabilities", []):
                plugin_name = (vuln.get("plugin_name") or "").strip()
                if not plugin_name:
                    continue

                po_entry = {
                    "port": vuln.get("port") or "",
                    "plugin_output": vuln.get("plugin_output") or "",
                    "plugin_output_url": vuln.get("plugin_output_url") or "",
                }

                if plugin_name not in grouped:
                    vuln_copy = vuln.copy()
                    if "risk_factor" in vuln_copy and vuln_copy["risk_factor"]:
                        risk = str(vuln_copy["risk_factor"]).strip()
                        vuln_copy["risk_factor"] = risk.title() if risk else ""
                    # Replace single plugin_output with plugin_outputs array
                    vuln_copy.pop("plugin_output", None)
                    vuln_copy.pop("plugin_output_url", None)
                    vuln_copy.pop("port", None)
                    vuln_copy["plugin_outputs"] = [po_entry]
                    grouped[plugin_name] = vuln_copy
                else:
                    grouped[plugin_name]["plugin_outputs"].append(po_entry)

            prepared_hosts.append({
                "host_name": host.get("host_name"),
                "host_information": host.get("host_information", {}),
                "vulnerabilities": list(grouped.values())
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
                    except Exception as e:
                        logger.warning("Suppressed error: %s", e)

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

    def _parse_and_store_report_bg(self, report_pk, admin_email, admin_id, original_filename, upload_estimate_seconds):
        """Parse report in background to avoid admin request hangs."""
        started = time.perf_counter()
        print(f"[AdminUploadBG] Worker started for report_pk={report_pk}", flush=True)
        try:
            from .parsers import dispatch_parse
            from .models import UploadReport as _UploadReport

            report_obj = None
            # Small retry window in case thread runs before DB visibility is stable.
            for _ in range(10):
                report_obj = _UploadReport.objects.filter(pk=report_pk).first()
                if report_obj:
                    break
                time.sleep(0.5)
            if not report_obj:
                logger.error(f"[AdminUploadBG] Report not found for report_pk={report_pk}")
                print(f"[AdminUploadBG] Report not found for report_pk={report_pk}", flush=True)
                return

            report_obj.status = "Processing"
            report_obj.save()

            report_id = str(report_obj._id)
            file_path = os.path.join(settings.MEDIA_ROOT, report_obj.file.name)
            parsed_data = dispatch_parse(file_path, original_filename)
            if not parsed_data or "error" in parsed_data:
                error_msg = (parsed_data or {}).get("error", "Unknown parsing error")
                report_obj.status = "Parse Error"
                report_obj.save()
                logger.error(f"[AdminUploadBG] Parse failed report_id={report_id}: {error_msg}")
                print(f"[AdminUploadBG] Parse failed report_id={report_id}: {error_msg}", flush=True)
                return

            parsed_count = 1
            if parsed_data.get("type") in ("nessus", "nessus_html"):
                parsed_count = parsed_data.get("total_vulnerabilities", 1) or 1
            elif "rows" in parsed_data:
                parsed_count = parsed_data.get("rows", 1)

            report_obj.parsed_count = parsed_count
            report_obj.status = "Successfully Processed"
            report_obj.save()
            print(
                f"[AdminUploadBG] Parsed report_id={report_id} type={parsed_data.get('type')} parsed_count={parsed_count}",
                flush=True
            )

            mongodb_stored = self._store_in_mongodb(
                parsed_data=parsed_data,
                report_id=str(report_obj._id),
                admin_email=admin_email,
                original_filename=original_filename,
                member_type=report_obj.member_type or "external",
            )
            if not mongodb_stored:
                report_obj.status = "MongoDB Storage Failed"
                report_obj.save()
                logger.warning(f"[AdminUploadBG] MongoDB store failed report_id={report_id}")
                print(f"[AdminUploadBG] MongoDB store failed report_id={report_id}", flush=True)
                return

            upload_actual_seconds = time.perf_counter() - started
            if parsed_data.get("type") in ("nessus", "nessus_html"):
                try:
                    mongo_uri = self._get_mongo_uri()
                    with pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000) as _client:
                        _db = self._get_mongo_db(_client)
                        _db["nessus_reports"].update_one(
                            {"report_id": str(report_obj._id)},
                            {"$set": {"upload_processing_seconds": int(round(upload_actual_seconds))}}
                        )
                except Exception as _upe:
                    logger.warning(f"[AdminUploadBG] Could not store upload_processing_seconds: {_upe}")

            # Auto-generate vulnerability cards in background (only for nessus reports)
            if parsed_data.get("type") in ("nessus", "nessus_html"):
                from .views import _auto_generate_cards_bg
                t = threading.Thread(
                    target=_auto_generate_cards_bg,
                    args=(str(report_obj._id), admin_email, admin_id),
                    daemon=True
                )
                t.start()
                logger.info(f"[AdminUploadBG] Auto card generation started report_id={report_id}")
                print(f"[AdminUploadBG] Auto card generation started report_id={report_id}", flush=True)

            logger.info(
                "[AdminUploadBG] Completed report_id=%s parsed_count=%s upload_actual=%ss estimated=%ss",
                report_id, parsed_count, int(round(upload_actual_seconds)), upload_estimate_seconds
            )
            print(
                f"[AdminUploadBG] Completed report_id={report_id} parsed_count={parsed_count} "
                f"upload_actual={int(round(upload_actual_seconds))}s",
                flush=True
            )
        except Exception as e:
            logger.error(f"[AdminUploadBG] Unexpected error report_pk={report_pk}: {e}", exc_info=True)
            print(f"[AdminUploadBG] Unexpected error report_pk={report_pk}: {e}", flush=True)

    def save_model(self, request, obj, form, change):
        """Save model and parse/store file data in MongoDB."""
        op_started = time.perf_counter()
        admin_user = form.cleaned_data.get('admin_select')
        obj.admin = admin_user

        uploaded_file = form.cleaned_data.get('file')
        is_new_file = uploaded_file and hasattr(uploaded_file, 'chunks')
        upload_estimate_seconds = 0
        if is_new_file:
            upload_estimate_seconds = self._estimate_upload_seconds(
                getattr(uploaded_file, "size", 0),
                uploaded_file.name
            )

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
            ext = os.path.splitext((uploaded_file.name or ""))[1].lower()
            file_size = int(getattr(uploaded_file, "size", 0) or 0)
            # For large HTML uploads, offload parse/store to background to prevent admin hangs.
            if ext in (".html", ".htm") and file_size >= 20 * 1024 * 1024:
                obj.status = "Queued for Processing"
                obj.save()
                print(
                    f"[AdminUploadBG] Queued large HTML report pk={obj.pk} file_size={file_size}",
                    flush=True
                )
                def _launch_bg_worker():
                    try:
                        t = threading.Thread(
                            target=self._parse_and_store_report_bg,
                            args=(
                                obj.pk,
                                admin_user.email,
                                str(admin_user.id),
                                uploaded_file.name,
                                upload_estimate_seconds,
                            ),
                            daemon=True
                        )
                        t.start()
                        print(f"[AdminUploadBG] Worker thread launched for pk={obj.pk}", flush=True)
                    except Exception as launch_exc:
                        logger.error(f"[AdminUploadBG] Failed to launch worker for pk={obj.pk}: {launch_exc}", exc_info=True)
                        print(f"[AdminUploadBG] Failed to launch worker for pk={obj.pk}: {launch_exc}", flush=True)

                transaction.on_commit(_launch_bg_worker)
                messages.info(
                    request,
                    (
                        "Large HTML report queued for background processing. "
                        "You can safely leave this page and check the report status later."
                    )
                )
                return
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
                        upload_actual_seconds = time.perf_counter() - op_started

                        # Store actual upload processing time for UploadStatusView ETA
                        if parsed_data.get("type") in ("nessus", "nessus_html"):
                            try:
                                mongo_uri = self._get_mongo_uri()
                                with pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000) as _client:
                                    _db = self._get_mongo_db(_client)
                                    _db["nessus_reports"].update_one(
                                        {"report_id": str(obj._id)},
                                        {"$set": {"upload_processing_seconds": int(round(upload_actual_seconds))}}
                                    )
                            except Exception as _upe:
                                logger.warning(f"[AdminUploadTiming] Could not store upload_processing_seconds: {_upe}")

                        agent_eta_seconds = self._estimate_agent_seconds(parsed_count, parsed_data.get("type"))
                        total_eta_seconds = upload_estimate_seconds + agent_eta_seconds
                        messages.success(
                            request,
                            (
                                f"File parsed and stored in database. Found {parsed_count} vulnerabilities. "
                                f"Upload processing time: {self._seconds_to_text(upload_actual_seconds)}. "
                                f"Estimated upload time: {self._seconds_to_text(upload_estimate_seconds)}."
                            )
                        )

                        # Auto-generate vulnerability cards in background (only for nessus reports, only on new upload)
                        if parsed_data.get("type") in ("nessus", "nessus_html") and not change:
                            from .views import _auto_generate_cards_bg
                            report_id = str(obj._id)
                            t = threading.Thread(
                                target=_auto_generate_cards_bg,
                                args=(report_id, admin_user.email, str(admin_user.id)),
                                daemon=True
                            )
                            t.start()
                            logger.info(f"[AutoGenCards] Background thread started from admin panel for report_id={report_id}")
                            print(f"[AutoGenCards] Background thread started from admin panel for report_id={report_id}", flush=True)
                            messages.info(
                                request,
                                (
                                    "Vulnerability cards are being generated in background. "
                                    f"Estimated agent creation time: {self._seconds_to_text(agent_eta_seconds)}. "
                                    f"Estimated total (upload + agent): {self._seconds_to_text(total_eta_seconds)}."
                                )
                            )
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

    def log_addition(self, request, object, message):
        try:
            return super().log_addition(request, object, message)
        except DatabaseError as e:
            logger.warning("[UploadReportAdmin] Admin log write failed (djongo counter issue): %s", e)

    def log_change(self, request, object, message):
        try:
            return super().log_change(request, object, message)
        except DatabaseError as e:
            logger.warning("[UploadReportAdmin] Admin log write failed (djongo counter issue): %s", e)

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
