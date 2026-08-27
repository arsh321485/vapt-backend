from django.contrib import admin
from django import forms
from django.conf import settings
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.template.response import TemplateResponse
from .models import UploadReport, MagicPinUpload, FixVulnVerification, SupportRequestReview
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
                    {
                        "is_active": True,
                        "is_superuser": {"$ne": True},
                        "$or": [
                            {"is_staff": True},
                            {"login_provider": {"$in": ["slack", "microsoft_teams"]}},
                        ],
                    },
                    {"id": 1, "_id": 1, "email": 1}
                ))
            # Some records may store identifier as `_id` in Mongo, so support both.
            for doc in admin_docs:
                admin_id = doc.get("id") or doc.get("_id")
                admin_email = doc.get("email")
                if admin_id and admin_email:
                    choices.append((str(admin_id), admin_email))
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

        return admin_user


class MagicPinUploadForm(forms.ModelForm):
    """
    No admin dropdown at all — explicit request: a magic-pin upload should
    never be attached to (or ask for) any existing admin's account.
    MagicPinUploadAdmin.save_model always attributes the report to the
    Super Admin doing the upload.
    """

    class Meta:
        model = UploadReport
        fields = ['file']


@admin.register(UploadReport)
class UploadReportAdmin(admin.ModelAdmin):
    form = UploadReportAdminForm

    list_display = ('_id', 'file', 'status', 'parsed_count', 'get_admin_id', 'get_admin_email', 'get_cards_status', 'uploaded_at')
    search_fields = ('file',)
    list_filter = ('uploaded_at',)
    readonly_fields = ()
    exclude = ('file_hash', 'location', 'admin', 'uploaded_at', 'created_at', 'updated_at', 'parsed_count', 'member_type', 'status')
    actions = ['generate_claim_link']

    def generate_claim_link(self, request, queryset):
        """
        Select one or more reports you (Super Admin) own here and run this
        action — produces a single 15-minute magic link that hands all of
        them off to whoever completes VaptFix signup through it. Stopgap
        until the website gets its own "Generate claim link" button —
        see users/invite_utils.py for how the link itself works.
        """
        if not request.user.is_superuser:
            self.message_user(request, "Only Super Admin can generate a claim invite.", level=messages.ERROR)
            return

        # Don't trust the `queryset` Django admin hands us here — it's built
        # via `.filter(pk__in=<checkbox strings>)`, and djongo's
        # ObjectIdField doesn't coerce plain strings in an __in lookup, so
        # it silently comes back empty every time. Re-derive the selection
        # straight from the raw checkbox POST values and look each one up
        # explicitly instead.
        from django.contrib.admin import helpers as _admin_helpers
        from bson import ObjectId as _ObjectId
        from bson.errors import InvalidId as _InvalidId
        selected_ids = request.POST.getlist(_admin_helpers.ACTION_CHECKBOX_NAME)
        selected = []
        for sid in selected_ids:
            try:
                selected.append(UploadReport.objects.get(_id=_ObjectId(sid)))
            except (UploadReport.DoesNotExist, _InvalidId):
                pass

        # Compare raw admin_id (not r.admin.id) — djongo doesn't reliably
        # resolve the FK relation on these instances either.
        owned = [r for r in selected if str(getattr(r, "admin_id", "")) == str(request.user.id)]
        not_owned = len(selected) - len(owned)
        if not owned:
            self.message_user(
                request,
                "None of the selected report(s) are owned by your account — "
                "a claim link can only hand off reports you uploaded yourself.",
                level=messages.ERROR,
            )
            return

        from users.invite_utils import create_invite, INVITE_TTL_SECONDS

        report_ids = [str(r._id) for r in owned]
        token = create_invite(report_ids, request.user.id)
        frontend_base = getattr(settings, "FRONTEND_URL", "https://vaptfix.ai").rstrip("/")
        invite_url = f"{frontend_base}/signup?invite={token}"

        msg = (
            f"Claim link (expires in {INVITE_TTL_SECONDS // 60} minutes) for "
            f"{len(owned)} report(s): {invite_url}"
        )
        if not_owned:
            msg += f"  ({not_owned} selected report(s) skipped — not owned by you.)"
        self.message_user(request, msg, level=messages.SUCCESS)
    generate_claim_link.short_description = "Generate claim link (magic link) for selected report(s)"

    class Media:
        js = ("upload_report/admin_upload_timing.js",)

    def get_admin_id(self, obj):
        return getattr(obj.admin, "id", None)
    get_admin_id.short_description = "Admin ID"

    def get_admin_email(self, obj):
        return getattr(obj.admin, "email", None)
    get_admin_email.short_description = "Admin Email"

    def get_cards_status(self, obj):
        """
        Surfaces vulnerability-card generation state that was previously
        invisible — a report could silently finish 0/N cards (e.g. a
        transient GPT-4o/Mongo failure) and the admin had no way to see it
        without querying MongoDB directly. Run
        `python manage.py retry_incomplete_card_generation` to fix any
        "Incomplete" rows shown here.
        """
        try:
            from vaptfix.mongo_client import MongoContext
            with MongoContext() as db:
                doc = db["nessus_reports"].find_one(
                    {"report_id": str(obj._id)},
                    {"cards_expected_count": 1, "cards_generated_count": 1, "cards_generation_complete": 1},
                )
        except Exception:
            return "—"

        if not doc:
            return "—"
        expected = int(doc.get("cards_expected_count") or 0)
        generated = int(doc.get("cards_generated_count") or 0)
        if expected == 0:
            return "—"
        if generated >= expected:
            return f"✅ {generated}/{expected}"
        return f"⚠️ Incomplete {generated}/{expected}"
    get_cards_status.short_description = "Cards"

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
                admin_user = None
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

                if parsed_data.get("type") in ("nessus_html", "nessus", "aws", "custom"):
                    # Plan gate — Freemium gets at most max_internal_ips
                    # hosts / max_vulnerabilities findings (billing/plans.py).
                    # Real bug confirmed: this admin-panel upload path never
                    # applied this at all (only the website's DRF upload
                    # endpoint — upload_report/views.py's post() — did), so
                    # a Freemium admin uploaded here saw ALL 42 hosts
                    # instead of 5. Excess hosts are retained as
                    # locked_hosts (not discarded), matching the website's
                    # own behavior, so they still unlock automatically on
                    # upgrade (billing/stripe_service.py).
                    locked_hosts = []
                    if admin_user:
                        from billing.enforcement import select_freemium_active_hosts
                        active_hosts, locked_hosts = select_freemium_active_hosts(
                            parsed_data.get("vulnerabilities_by_host") or [], admin_user
                        )
                        if locked_hosts:
                            parsed_data = dict(parsed_data)
                            parsed_data["vulnerabilities_by_host"] = active_hosts
                            parsed_data["total_hosts"] = len(active_hosts)
                            parsed_data["total_vulnerabilities"] = sum(
                                len(h.get("vulnerabilities") or []) for h in active_hosts
                            )

                    hosts_payload = self._prepare_hosts_for_storage(
                        parsed_data.get("vulnerabilities_by_host", [])
                    )
                    document.update({
                        "scan_info": parsed_data.get("scan_info", {}),
                        "total_hosts": parsed_data.get("total_hosts", 0),
                        "total_vulnerabilities": parsed_data.get("total_vulnerabilities", 0),
                        "vulnerabilities_by_host": hosts_payload
                    })
                    if locked_hosts:
                        document["locked_hosts"] = self._prepare_hosts_for_storage(locked_hosts)
                        document["freemium_trimmed"] = True
                    db["nessus_reports"].insert_one(document)
                else:
                    document["parsed_data"] = parsed_data
                    db["parsed_reports"].insert_one(document)

                return True
        except Exception as e:
            print(f"MongoDB storage error: {e}")
            return False

    def _validate_custom_if_needed(self, parsed_data, filename):
        """
        Anything that isn't a recognized Nessus/AWS export (pdf/csv/excel/
        html/docx/doc) needs the same GPT-4o-mini validate+extract step the
        DRF upload API (upload_report/views.py post()) already runs before
        it's allowed near storage or card generation — this admin panel
        form is a completely separate upload path with its own
        dispatch_parse() call, and previously skipped this step entirely,
        so a PDF/DOCX pentest report uploaded here just landed in the
        generic `parsed_reports` collection as raw text (no
        vulnerabilities_by_host, no mitigation cards, nothing usable).

        Returns (parsed_data, error) — error is None on success (or when
        no validation was needed, e.g. a native Nessus/AWS file), else a
        user-facing rejection reason and parsed_data should be discarded.
        """
        if parsed_data.get("type") not in ("pdf", "csv", "excel", "html", "docx", "doc"):
            return parsed_data, None
        from .custom_report_ai import validate_and_extract_custom_report
        validation_result = validate_and_extract_custom_report(parsed_data, filename)
        if not validation_result.get("valid"):
            return parsed_data, (
                validation_result.get("reason")
                or "This file does not appear to contain vulnerability scan data."
            )
        return validation_result, None

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

            parsed_data, custom_error = self._validate_custom_if_needed(parsed_data, original_filename)
            if custom_error:
                report_obj.status = "Parse Error"
                report_obj.save()
                logger.error(f"[AdminUploadBG] Custom validation failed report_id={report_id}: {custom_error}")
                print(f"[AdminUploadBG] Custom validation failed report_id={report_id}: {custom_error}", flush=True)
                return

            parsed_count = 1
            if parsed_data.get("type") in ("nessus", "nessus_html", "aws", "custom"):
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

            # Auto-generate vulnerability cards in background (Nessus, AWS, and
            # validated custom reports — matches the condition in views.py's
            # UploadReportView so admin-panel uploads don't silently skip
            # card generation for anything but native Nessus files).
            if parsed_data.get("type") in ("nessus", "nessus_html", "aws", "custom"):
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
                    parsed_data, custom_error = self._validate_custom_if_needed(parsed_data, uploaded_file.name)
                    if custom_error:
                        parsed_data = {"error": custom_error}

                if parsed_data and "error" not in parsed_data:
                    # Calculate parsed count
                    parsed_count = 1
                    if parsed_data.get("type") in ("nessus", "nessus_html", "aws", "custom"):
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

                        # Same Slack onboarding hook as the DRF upload API
                        # (upload_report/views.py) — this admin panel form is
                        # a completely separate upload path with its own
                        # parsing/storage, so it needs its own copy of this
                        # call or a Super Admin uploading from here (rather
                        # than the API) would leave the admin stuck on the
                        # Slack "welcome" message forever despite the report
                        # having actually landed.
                        try:
                            from users.views import notify_admin_report_uploaded
                            threading.Thread(
                                target=notify_admin_report_uploaded, args=(admin_user,), daemon=True,
                            ).start()
                        except Exception:
                            logger.exception("Failed to trigger Slack onboarding notification after admin-panel upload")

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

                        # Auto-generate vulnerability cards in background (Nessus, AWS, and
                        # validated custom reports — see matching fix in _parse_and_store_report_bg
                        # above; only on new upload)
                        if parsed_data.get("type") in ("nessus", "nessus_html", "aws", "custom") and not change:
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


# ---------------------------------------------------------------------------
# Magic Pin Upload (Superadmin only) — dedicated tab, explicit request
# ---------------------------------------------------------------------------

@admin.register(MagicPinUpload)
class MagicPinUploadAdmin(UploadReportAdmin):
    """
    A dedicated Super Admin sidebar tab for magic-pin uploads, kept
    separate from the general 'Upload reports' list. Reuses every bit of
    UploadReportAdmin's pipeline (form, save_model, GPT extraction for
    custom files, card generation) unchanged via the MagicPinUpload proxy
    model — only the entry point differs: the tab jumps straight to the
    Add form instead of showing a list (there's nothing meaningfully
    different to list here — a report uploaded via this tab is the exact
    same row, and still shows up in 'Upload reports' too, since it's the
    same underlying table).

    No pricing/plan-gate call exists anywhere in this pipeline (confirmed
    in UploadReportAdmin.save_model) — uploads from here, same as the
    general admin panel, were never subject to Freemium limits in the
    first place.

    There is no "Select Admin" field at all (see MagicPinUploadForm) —
    explicit request: a magic-pin upload should never be attached to any
    existing admin's account. Every report uploaded from this tab is
    attributed to the Super Admin doing the upload.
    """
    form = MagicPinUploadForm
    actions = None  # "Generate claim link" bulk action lives on the main Upload reports tab only

    def save_model(self, request, obj, form, change):
        form.cleaned_data['admin_select'] = request.user
        super().save_model(request, obj, form, change)

    def changelist_view(self, request, extra_context=None):
        if not (request.user.is_authenticated and request.user.is_superuser):
            from django.contrib.auth.views import redirect_to_login
            return redirect_to_login(request.get_full_path())
        return HttpResponseRedirect(
            reverse("admin:upload_report_magicpinupload_add")
        )


# ---------------------------------------------------------------------------
# Pending Verification Admin (Superadmin only)
# ---------------------------------------------------------------------------

@admin.register(FixVulnVerification)
class FixVulnVerificationAdmin(admin.ModelAdmin):
    """
    Custom admin panel for superadmin to review and approve
    fix vulnerability verifications (status = "open/review").
    """

    def has_module_permission(self, request):
        return request.user.is_authenticated and request.user.is_superuser

    def has_view_permission(self, request, obj=None):
        return request.user.is_authenticated and request.user.is_superuser

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def get_queryset(self, request):
        return FixVulnVerification.objects.none()

    def _get_pending(self):
        from vaptfix.mongo_client import get_shared_client, get_shared_db
        client = get_shared_client()
        db = get_shared_db(client)
        docs = list(db["fix_vulnerabilities"].find({"status": "open/review"}).sort("verification_sent_at", -1))
        result = []
        for doc in docs:
            fix_vuln_id = str(doc["_id"])
            sent    = doc.get("verification_sent_at")
            created = doc.get("created_at")

            # Find who completed the steps (last updated_by in steps collection)
            completed_by_id = doc.get("created_by", "")
            last_step = db["fix_vulnerability_steps"].find_one(
                {"fix_vulnerability_id": fix_vuln_id, "status": "completed"},
                sort=[("updated_at", -1)],
            )
            if last_step and last_step.get("updated_by"):
                completed_by_id = last_step["updated_by"]

            # Resolve user email from users_user collection
            completed_by_email = ""
            if completed_by_id:
                try:
                    from bson import ObjectId as _OId
                    u = db["users_user"].find_one(
                        {"$or": [{"id": completed_by_id}, {"_id": _OId(completed_by_id)}]},
                        {"email": 1}
                    )
                    completed_by_email = (u or {}).get("email", completed_by_id)
                except Exception:
                    completed_by_email = completed_by_id

            result.append({
                "fix_id": fix_vuln_id,
                "vulnerability_name": doc.get("plugin_name", ""),
                "asset": doc.get("host_name", ""),
                "severity": doc.get("risk_factor", ""),
                "port": doc.get("port", ""),
                "assigned_team": doc.get("assigned_team", ""),
                "admin_id": doc.get("admin_id", ""),
                "completed_by": completed_by_email,
                "verification_sent_at": sent.strftime("%Y-%m-%d %H:%M UTC") if sent else "-",
                "created_at": created.strftime("%Y-%m-%d") if created else "-",
            })
        return result

    def changelist_view(self, request, extra_context=None):
        if not (request.user.is_authenticated and request.user.is_superuser):
            from django.contrib.auth.views import redirect_to_login
            return redirect_to_login(request.get_full_path())

        # Handle approve POST
        if request.method == "POST":
            fix_vuln_id = request.POST.get("fix_vuln_id", "").strip()
            if fix_vuln_id:
                try:
                    from bson import ObjectId
                    from vaptfix.mongo_client import get_shared_client, get_shared_db
                    import datetime as _dt
                    client = get_shared_client()
                    db = get_shared_db(client)
                    fix_coll    = db["fix_vulnerabilities"]
                    closed_coll = db["fix_vulnerabilities_closed"]

                    fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
                    if fix_doc and fix_doc.get("status") == "open/review":
                        now = _dt.datetime.utcnow()
                        superadmin_id = str(request.user.id)

                        closed_doc = fix_doc.copy()
                        closed_doc["fix_vulnerability_id"] = str(fix_doc["_id"])
                        closed_doc.pop("_id", None)
                        closed_doc.update({
                            "status": "closed",
                            "closed_at": now,
                            "closed_by": superadmin_id,
                            "approved_by_superadmin": superadmin_id,
                            "approved_at": now,
                        })
                        closed_coll.insert_one(closed_doc)
                        fix_coll.delete_one({"_id": ObjectId(fix_vuln_id)})

                        db["tickets"].update_many(
                            {"fix_vulnerability_id": fix_vuln_id, "status": "open"},
                            {"$set": {
                                "status": "closed",
                                "closed_at": now,
                                "close_comment": "Auto-closed: approved by superadmin",
                            }},
                        )
                        # Also close the actual support_requests documents —
                        # the collection /support status and the Support tab
                        # read, distinct from "tickets" above; without this
                        # a resolved vuln's support request stayed "open"
                        # forever from the admin/team's point of view.
                        db["support_requests"].update_many(
                            {"vulnerability_id": fix_vuln_id, "status": "open"},
                            {"$set": {
                                "status": "closed",
                                "closed_at": now,
                                "closed_by": superadmin_id,
                                "close_comment": "Auto-closed: approved by superadmin",
                            }},
                        )

                        try:
                            from notifications.utils import create_notification
                            _vuln = fix_doc.get("plugin_name", "")
                            _asset = fix_doc.get("host_name", "")
                            _team = fix_doc.get("assigned_team", "")
                            _admin_id = fix_doc.get("admin_id", "") or fix_doc.get("created_by", "")
                            _closed_by_name = fix_doc.get("closed_by_name", "")
                            _title = f"Vulnerability Verified & Closed: {_vuln[:80]}"
                            _msg = (
                                f"{_vuln} on {_asset}"
                                + (f" (fixed by {_closed_by_name})" if _closed_by_name else "")
                                + f" has been verified and closed by superadmin ({request.user.email}). Team: {_team}."
                            )
                            _meta = {
                                "vulnerability_name": _vuln, "asset": _asset,
                                "fix_vulnerability_id": fix_vuln_id, "assigned_team": _team,
                                "closed_by_name": _closed_by_name, "approved_by_name": request.user.email,
                            }
                            if _admin_id:
                                create_notification(_admin_id, 'admin', 'vuln_closed', _title, _msg, _meta)
                                create_notification(_admin_id, 'user', 'vuln_closed', _title, _msg, _meta)
                        except Exception:
                            pass

                        messages.success(request, f"✅ '{fix_doc.get('plugin_name')}' on {fix_doc.get('host_name')} approved and closed.")
                    else:
                        messages.warning(request, "Vulnerability not found or not in open/review status.")
                except Exception as exc:
                    messages.error(request, f"Error approving: {exc}")

            return HttpResponseRedirect(
                reverse("admin:upload_report_fixvulnverification_changelist")
            )

        # GET — show pending list
        pending = self._get_pending()
        context = {
            **self.admin_site.each_context(request),
            "title": "Pending Verifications",
            "opts": self.model._meta,
            "pending_verifications": pending,
            "cl": type("FakeCL", (), {"opts": self.model._meta})(),
        }
        return TemplateResponse(
            request,
            "admin/upload_report/fixvulnverification/change_list.html",
            context,
        )


@admin.register(SupportRequestReview)
class SupportRequestReviewAdmin(admin.ModelAdmin):
    """
    Custom admin panel for superadmin to view open support requests and
    close them directly — independent of the linked vulnerability's own
    status. Until now a support request only ever closed as a side effect
    of its vulnerability being verified/closed; this lets superadmin
    resolve a ticket on its own, earlier if needed.
    """

    def has_module_permission(self, request):
        return request.user.is_authenticated and request.user.is_superuser

    def has_view_permission(self, request, obj=None):
        return request.user.is_authenticated and request.user.is_superuser

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def get_queryset(self, request):
        return SupportRequestReview.objects.none()

    def _get_open_requests(self):
        from vaptfix.mongo_client import get_shared_client, get_shared_db
        client = get_shared_client()
        db = get_shared_db(client)
        docs = list(db["support_requests"].find({"status": "open"}).sort("requested_at", -1))
        result = []
        for doc in docs:
            requested_at = doc.get("requested_at")
            result.append({
                "request_id":     str(doc["_id"]),
                "vul_name":       doc.get("vul_name") or "General",
                "host_name":      doc.get("host_name") or "-",
                "assigned_team":  doc.get("assigned_team", ""),
                "requested_by":   doc.get("requested_by", ""),
                "description":    doc.get("description", ""),
                "requested_at":   requested_at.strftime("%Y-%m-%d %H:%M UTC") if requested_at else "-",
            })
        return result

    def changelist_view(self, request, extra_context=None):
        if not (request.user.is_authenticated and request.user.is_superuser):
            from django.contrib.auth.views import redirect_to_login
            return redirect_to_login(request.get_full_path())

        if request.method == "POST":
            request_id = request.POST.get("request_id", "").strip()
            if request_id:
                try:
                    from bson import ObjectId
                    from vaptfix.mongo_client import get_shared_client, get_shared_db
                    import datetime as _dt
                    client = get_shared_client()
                    db = get_shared_db(client)
                    support_coll = db["support_requests"]

                    doc = support_coll.find_one({"_id": ObjectId(request_id)})
                    if doc and doc.get("status") == "open":
                        now = _dt.datetime.utcnow()
                        superadmin_id = str(request.user.id)
                        support_coll.update_one(
                            {"_id": ObjectId(request_id)},
                            {"$set": {
                                "status": "closed",
                                "closed_at": now,
                                "closed_by": superadmin_id,
                                "close_comment": "Manually closed by superadmin",
                            }},
                        )

                        try:
                            from notifications.utils import create_notification
                            _admin_id = doc.get("admin_id", "")
                            _vuln_label = doc.get("vul_name") or "your support request"
                            _requested_by = doc.get("requested_by", "")
                            _title = f"Support Request Closed: {_vuln_label[:80]}"
                            _msg = f"Your support request for '{_vuln_label}' has been closed by superadmin."
                            _meta = {
                                "support_request_id": request_id,
                                "vul_name": doc.get("vul_name", ""),
                                "host_name": doc.get("host_name", ""),
                            }
                            if _admin_id:
                                create_notification(_admin_id, 'admin', 'support_request_closed', _title, _msg, _meta)
                                if _requested_by and "@" in _requested_by:
                                    create_notification(
                                        _admin_id, 'user', 'support_request_closed', _title, _msg, _meta,
                                        recipient_email=_requested_by,
                                    )
                        except Exception:
                            pass

                        messages.success(request, f"✅ Support request for '{doc.get('vul_name') or 'General'}' closed.")
                    else:
                        messages.warning(request, "Support request not found or already closed.")
                except Exception as exc:
                    messages.error(request, f"Error closing support request: {exc}")

            return HttpResponseRedirect(
                reverse("admin:upload_report_supportrequestreview_changelist")
            )

        open_requests = self._get_open_requests()
        context = {
            **self.admin_site.each_context(request),
            "title": "Support Requests",
            "opts": self.model._meta,
            "open_requests": open_requests,
            "cl": type("FakeCL", (), {"opts": self.model._meta})(),
        }
        return TemplateResponse(
            request,
            "admin/upload_report/supportrequestreview/change_list.html",
            context,
        )
