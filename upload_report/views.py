import os
import uuid
import json
import datetime
import time
import threading
import logging
from typing import Optional, Dict, Any, List
import hashlib

logger = logging.getLogger(__name__)
from bson import ObjectId
from bson.errors import InvalidId

from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

import pymongo
from pymongo import MongoClient

from location.models import Location
from users.models import User
from .models import UploadReport
from .serializers import UploadReportSerializer
from django.http import FileResponse, Http404, HttpResponseForbidden
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth.decorators import login_required

# Serve uploaded report files (uses Django session auth for admin access)
@login_required(login_url='/admin/login/')
def serve_report_file(request, path):
    base = os.path.realpath(settings.MEDIA_ROOT)
    file_path = os.path.realpath(os.path.join(settings.MEDIA_ROOT, path))

    if not file_path.startswith(base + os.sep) and file_path != base:
        raise Http404("File not found")

    if not os.path.exists(file_path):
        raise Http404("File not found")

    # Determine content type based on file extension
    ext = os.path.splitext(path)[1].lower()
    content_types = {
        '.html': 'text/html',
        '.htm': 'text/html',
        '.pdf': 'application/pdf',
        '.csv': 'text/csv',
        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.xls': 'application/vnd.ms-excel',
        '.xml': 'application/xml',
    }
    content_type = content_types.get(ext, 'application/octet-stream')

    return FileResponse(
        open(file_path, "rb"),
        content_type=content_type
    )


# Multiple upload report view

class UploadReportView(APIView):
    """API endpoint for uploading and parsing vulnerability reports."""
    
    permission_classes = [IsAuthenticated]

    ALLOWED_EXTENSIONS = {
        '.pdf', '.csv', '.xlsx', '.xls', '.xml', '.nessus',
        '.html', '.htm', '.bmp', '.tiff'
    }

    def _seconds_to_text(self, seconds: float) -> str:
        seconds_int = max(0, int(round(seconds)))
        mins, secs = divmod(seconds_int, 60)
        if mins > 0:
            return f"{mins} min {secs} sec"
        return f"{secs} sec"

    def _estimate_processing_seconds(self, file_size_bytes: int, ext: str, member_type: str) -> int:
        size_mb = (file_size_bytes or 0) / (1024 * 1024)

        if ext in (".nessus", ".xml", ".html", ".htm"):
            estimate = 20 + (size_mb * 4.0)
        elif ext in (".xlsx", ".xls", ".csv"):
            estimate = 8 + (size_mb * 1.5)
        else:
            estimate = 6 + (size_mb * 1.0)

        if member_type == "both":
            estimate *= 1.35

        return int(max(8, min(estimate, 3600)))

    def _save_file_and_hash(self, uploaded_file, file_path: str):
        hasher = hashlib.sha256()
        bytes_written = 0
        with open(file_path, "wb+") as dest:
            for chunk in uploaded_file.chunks():
                hasher.update(chunk)
                dest.write(chunk)
                bytes_written += len(chunk)
        return hasher.hexdigest(), bytes_written
    
    def _generate_file_hash(self, uploaded_file):
        hasher = hashlib.sha256()
        for chunk in uploaded_file.chunks():
            hasher.update(chunk)
        return hasher.hexdigest()

    def _get_mongo_uri(self) -> Optional[str]:
        """Get MongoDB URI from Django settings."""
        try:
            return settings.DATABASES['default']['CLIENT']['host']
        except Exception:
            return getattr(settings, "MONGO_DB_URL", None)

    def _get_mongo_db(self, client: pymongo.MongoClient):
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

    def _prepare_hosts_for_storage(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Prepare hosts data for MongoDB storage.
        NOW KEEPS risk_factor field - this was the bug!
        """
        prepared_hosts: List[Dict[str, Any]] = []
        
        for host in hosts:
            prepared_vulns: List[Dict[str, Any]] = []
            
            for vuln in host.get("vulnerabilities", []):
                # Keep ALL fields including risk_factor
                vuln_copy = vuln.copy()
                
                # Normalize risk_factor to title case if present
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

    def _store_in_mongodb(self, 
                         parsed_data: Dict[str, Any],
                         report_id: str,
                         location_id: str,
                         location_name: str,
                         admin_email: str,
                         original_filename: str,
                         member_type: str) -> bool:
        """
        Store parsed report data in MongoDB.
        
        For Nessus reports, stores with vulnerabilities_by_host structure.
        For other reports, stores the parsed data as-is.
        """
        try:
            client, db = _get_mongo_client_and_db()

            # Base document structure
            # Fetch admin_id from admin_email for ownership validation
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
                "location_id": location_id,
                "location_name": location_name,
                "admin_id": admin_id,  # Store admin_id for ownership validation
                "admin_email": admin_email,
                "member_type": member_type,
                "uploaded_at": datetime.datetime.utcnow(),
                "report_type": parsed_data.get("type", "unknown"),
            }

            # For Nessus reports, use structured format
            if parsed_data.get("type") in ("nessus_html", "nessus"):
                # FIXED: Now using _prepare_hosts_for_storage which KEEPS risk_factor
                hosts_payload = self._prepare_hosts_for_storage(
                    parsed_data.get("vulnerabilities_by_host", [])
                )

                document.update({
                    "scan_info": parsed_data.get("scan_info", {}),
                    "total_hosts": parsed_data.get("total_hosts", 0),
                    "total_vulnerabilities": parsed_data.get("total_vulnerabilities", 0),
                    "vulnerabilities_by_host": hosts_payload
                })

                # Insert into nessus_reports collection
                db["nessus_reports"].insert_one(document)
            else:
                # For other report types, store in generic collection
                document["parsed_data"] = parsed_data
                db["parsed_reports"].insert_one(document)

            print(f"Successfully stored report {report_id} in MongoDB with risk_factor data")
            return True

        except Exception as e:
            print(f"MongoDB storage error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _create_preview(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a lightweight preview of parsed data for API response.
        Limits data size to keep response manageable.
        """
        report_type = parsed_data.get("type")
        
        # Nessus reports (HTML or XML)
        if report_type in ("nessus_html", "nessus"):
            preview = {
                "type": report_type,
                "scan_info": parsed_data.get("scan_info", {}),
                "total_hosts": parsed_data.get("total_hosts", 0),
                "total_vulnerabilities": parsed_data.get("total_vulnerabilities", 0),
                "hosts_preview": []
            }
            
            # Include first 20 hosts with limited vulnerabilities
            hosts = parsed_data.get("vulnerabilities_by_host", [])
            for host in hosts[:20]:
                allowed_risks = {"critical", "high", "medium", "low"}
                filtered_vulns = [
                    v for v in host.get("vulnerabilities", [])
                    if not v.get("risk_factor") or v.get("risk_factor", "").strip().lower() in allowed_risks
                ]
                host_preview = {
                    "host_name": host.get("host_name"),
                    "host_information": host.get("host_information", {}),
                    "vulnerability_count": len(filtered_vulns),
                    "vulnerabilities": []
                }
                
                # Add first 20 vulnerabilities per host (with limited fields)
                for vuln in filtered_vulns[:20]:
                    risk = (vuln.get("risk_factor") or "").strip()
                    risk_normalized = risk.title() if risk else ""
                    desc_points = vuln.get("description_points") or []
                    if desc_points:
                        description_preview = " | ".join(desc_points)[:500]
                    else:
                        description_preview = (vuln.get("description") or "")[:500]
                    
                    vuln_preview = {
                        "plugin_id": vuln.get("plugin_id"),
                        "plugin_name": vuln.get("plugin_name"),
                        "risk_factor": risk_normalized,  # INCLUDED in preview
                        "cvss_v3_base_score": vuln.get("cvss_v3_base_score"),
                        "description": description_preview,
                    }
                    host_preview["vulnerabilities"].append(vuln_preview)
                
                preview["hosts_preview"].append(host_preview)
            
            return preview
        
        # PDF files
        if report_type == "pdf":
            return {
                "type": "pdf",
                "pages": parsed_data.get("pages", 0),
                "text_preview": parsed_data.get("text_preview", "")[:2000]
            }
        
        # CSV/Excel files
        if report_type in ("csv", "excel"):
            return {
                "type": "report_type",
                "columns": parsed_data.get("columns", []),
                "rows": parsed_data.get("rows", 0),
                "sample_data": parsed_data.get("preview", [])[:10]
            }
        
        # HTML files
        if report_type == "html":
            return {
                "type": "html",
                "title": parsed_data.get("title", ""),
                "headings_count": len(parsed_data.get("headings", [])),
                "links_count": len(parsed_data.get("links", [])),
                "text_preview": parsed_data.get("text_preview", "")[:1000]
            }
        
        # Default fallback
        return {"type": report_type}
    
    def _resolve_location(self, location_value, user) -> Location:
        """
        Accept ONLY one Location ID.
        No 'all', no list, no comma-separated values.
        """

        if not location_value:
            raise ValueError("Location is required")

        # ❌ block list / array
        if isinstance(location_value, (list, tuple)):
            raise ValueError("Only one location can be selected at a time")

        location_str = str(location_value).strip()

        # ❌ block comma-separated ids
        if "," in location_str:
            raise ValueError("Only one location can be selected at a time")

        try:
            location_id = ObjectId(location_str)
        except Exception:
            raise ValueError("Invalid location ID format")

        try:
            return Location.objects.get(pk=location_id)
        except Location.DoesNotExist:
            raise ValueError("Location not found")


    # Single file upload 
    # def post(self, request):
    #     """
    #     Handle POST request to upload and parse vulnerability report.
        
    #     Expected form data:
    #     - file: The uploaded file
    #     - location: Location ID (can be "all", single ID, or comma-separated IDs)
    #     - member_type: Type of member (external/internal)
    #     - report_type: Optional report type hint (excel, csv, nessus, etc.)
    #     """
    #     # Import parser module
    #     try:
    #         from .parsers import dispatch_parse
    #     except ImportError:
    #         return Response({
    #             "error": "File parser module not found. Ensure file_parsers.py exists."
    #         }, status=500)
        
    #     file_path = None

    #     try:
    #         # Extract request data
    #         location_raw = request.data.get("location")
    #         member_type = request.data.get("member_type", "external")
    #         uploaded_file = request.FILES.get("file")

    #         # Validation
    #         if not location_raw:
    #             return Response({"error": "Location is required"}, status=400)
    #         try:
    #             location_objects = self._resolve_locations(location_raw, request.user)
    #         except ValueError as exc:
    #             return Response({"error": str(exc)}, status=400)

    #         if not location_objects:
    #             return Response({"error": "No valid locations were provided"}, status=400)

    #         if not uploaded_file:
    #             return Response({"error": "File is required"}, status=400)

    #         # Check file extension
    #         ext = os.path.splitext(uploaded_file.name)[1].lower()
    #         if ext not in self.ALLOWED_EXTENSIONS:
    #             return Response({
    #                 "error": f"Unsupported file type: {ext}. Allowed: {', '.join(self.ALLOWED_EXTENSIONS)}"
    #             }, status=400)

    #         # Save uploaded file to MEDIA_ROOT/reports/
    #         unique_filename = f"{uuid.uuid4().hex}_{uploaded_file.name}"
    #         relative_filename = os.path.join("reports", unique_filename).replace("\\", "/")
    #         file_path = os.path.join(settings.MEDIA_ROOT, relative_filename)
    #         os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
    #         with open(file_path, "wb+") as dest:
    #             for chunk in uploaded_file.chunks():
    #                 dest.write(chunk)

    #         # Parse the file
    #         parsed_data = dispatch_parse(file_path, uploaded_file.name)
            
    #         # Check for parsing errors
    #         if not isinstance(parsed_data, dict):
    #             if file_path and os.path.exists(file_path):
    #                 os.remove(file_path)
    #             return Response({
    #                 "error": "Failed to parse the uploaded file"
    #             }, status=400)
            
    #         if "error" in parsed_data:
    #             if file_path and os.path.exists(file_path):
    #                 os.remove(file_path)
    #             return Response({
    #                 "error": parsed_data["error"]
    #             }, status=400)

    #         # Calculate parsed count for status tracking
    #         parsed_count = 1
    #         if parsed_data.get("type") in ("nessus", "nessus_html"):
    #             parsed_count = parsed_data.get("total_vulnerabilities", 1) or 1
    #         elif "rows" in parsed_data:
    #             parsed_count = parsed_data.get("rows", 1)

    #         # Process each location
    #         upload_results = []
    #         errors = []
    #         for location_obj in location_objects:
    #             location_name = getattr(location_obj, "location_name", "")
    #             try:
    #                 upload_report = UploadReport.objects.create(
    #                     file=relative_filename,
    #                     location=location_obj,
    #                     admin=request.user,
    #                     member_type=member_type,
    #                     status="processed",
    #                     parsed_count=parsed_count,
    #                 )

    #                 report_id = str(getattr(upload_report, "_id", upload_report.pk))

    #                 mongodb_stored = self._store_in_mongodb(
    #                     parsed_data=parsed_data,
    #                     report_id=report_id,
    #                     location_id=str(location_obj.pk),
    #                     location_name=location_name,
    #                     admin_email=getattr(request.user, "email", ""),
    #                     original_filename=uploaded_file.name,
    #                     member_type=member_type
    #                 )

    #                 serializer = UploadReportSerializer(upload_report)
    #                 report_payload = json.loads(json.dumps(serializer.data, default=str))
    #                 upload_results.append({
    #                     "location": {
    #                         "id": str(location_obj.pk),
    #                         "name": location_name,
    #                     },
    #                     "upload_report": report_payload,
    #                     "mongodb_stored": mongodb_stored,
    #                 })
    #             except Exception as loop_exc:
    #                 errors.append({
    #                     "location": {
    #                         "id": str(location_obj.pk),
    #                         "name": location_name,
    #                     },
    #                     "error": str(loop_exc)
    #                 })

    #         # Create preview for API response
    #         preview = self._create_preview(parsed_data)

    #         if errors and not upload_results:
    #             return Response({
    #                 "error": "Upload failed for all locations",
    #                 "details": errors
    #             }, status=500)

    #         if len(upload_results) == 1:
    #             single = upload_results[0]
    #             response_payload = {
    #                 "success": True,
    #                 "message": "File uploaded and parsed successfully",
    #                 "upload_report": single["upload_report"],
    #                 "location": single["location"],
    #                 "parsed_count": parsed_count,
    #                 "mongodb_stored": single["mongodb_stored"],
    #                 "report_type": parsed_data.get("type"),
    #                 "structured_data_preview": preview
    #             }
    #         else:
    #             response_payload = {
    #                 "success": True,
    #                 "message": "File uploaded and parsed successfully",
    #                 "results": upload_results,
    #                 "parsed_count": parsed_count,
    #                 "report_type": parsed_data.get("type"),
    #                 "structured_data_preview": preview,
    #                 "errors": errors
    #             }
            
    #         return Response(response_payload, status=201)

    #     except Exception as exc:
    #         print(f"Upload error: {exc}")
    #         import traceback
    #         traceback.print_exc()
            
    #         # Cleanup on error
    #         if file_path and os.path.exists(file_path):
    #             try:
    #                 os.remove(file_path)
    #             except Exception:
    #                 pass
            
    #         return Response({
    #             "error": f"Upload failed: {str(exc)}"
    #         }, status=500)
    
    #Multiple file upload
    def post(self, request):
        api_start = time.perf_counter()
        try:
            from .parsers import dispatch_parse

            # Determine target admin for upload
            admin_id = request.data.get("admin_id")

            if admin_id:
                # Only Super Admin can upload on behalf of another admin
                if not request.user.is_superuser:
                    return Response(
                        {"error": "Only Super Admin can upload reports for other admins."},
                        status=403
                    )

                # Validate and fetch the target admin
                try:
                    target_admin = User.objects.get(id=admin_id)
                except User.DoesNotExist:
                    return Response(
                        {"error": "Admin not found with the provided admin_id."},
                        status=404
                    )
            else:
                # Regular flow: use the requesting user as target admin
                target_admin = request.user

            # Check if target admin has completed scoping forms
            try:
                from scoping.models import ProjectDetail, TestingMethodology
                has_project = ProjectDetail.objects.filter(admin=target_admin).exists()
                has_methodology = TestingMethodology.objects.filter(admin=target_admin).exists()
                scoping_complete = has_project and has_methodology
            except Exception:
                scoping_complete = False

            if not scoping_complete:
                return Response(
                    {"error": "Admin has not completed the scoping form (Project Details + Testing Methodology). "
                              "File upload is not allowed until scoping is complete."},
                    status=403
                )

            member_type = request.data.get("member_type", "external")

            if member_type not in {"external", "internal", "both"}:
                return Response(
                    {"error": "member_type must be external, internal or both"},
                    status=400
                )

            # ✅ MULTIPLE FILES
            uploaded_files = request.FILES.getlist("file")

            if not uploaded_files:
                return Response({"error": "At least one file is required"}, status=400)

            upload_results = []
            errors = []

            for uploaded_file in uploaded_files:
                file_path = None
                file_start = time.perf_counter()
                file_size_bytes = int(getattr(uploaded_file, "size", 0) or 0)
                ext = os.path.splitext(uploaded_file.name)[1].lower()
                estimated_seconds = self._estimate_processing_seconds(file_size_bytes, ext, member_type)
                timings_ms = {
                    "save_and_hash_ms": 0,
                    "duplicate_check_ms": 0,
                    "parse_ms": 0,
                    "mongo_ms": 0,
                    "response_build_ms": 0,
                    "total_ms": 0,
                }

                try:
                    # 🔹 Extension check
                    if ext not in self.ALLOWED_EXTENSIONS:
                        errors.append({
                            "file": uploaded_file.name,
                            "error": "Unsupported file type"
                        })
                        continue

                    # 🔹 Save file + hash in single pass (faster than two reads)
                    target_admin_id = str(target_admin.id)
                    safe_filename = os.path.basename(uploaded_file.name)
                    relative_filename = f"reports/{target_admin_id}/{safe_filename}"
                    file_path = os.path.join(settings.MEDIA_ROOT, relative_filename)
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)

                    save_hash_start = time.perf_counter()
                    file_hash, bytes_written = self._save_file_and_hash(uploaded_file, file_path)
                    timings_ms["save_and_hash_ms"] = int((time.perf_counter() - save_hash_start) * 1000)

                    dup_start = time.perf_counter()
                    if UploadReport.objects.filter(
                        admin=target_admin,
                        file_hash=file_hash
                    ).exists():
                        if file_path and os.path.exists(file_path):
                            os.remove(file_path)
                        timings_ms["duplicate_check_ms"] = int((time.perf_counter() - dup_start) * 1000)
                        errors.append({
                            "file": uploaded_file.name,
                            "error": "Duplicate file detected. This file was already uploaded."
                        })
                        continue
                    timings_ms["duplicate_check_ms"] = int((time.perf_counter() - dup_start) * 1000)

                    # 🔹 Parse file (your existing parser)
                    parse_start = time.perf_counter()
                    parsed_data = dispatch_parse(file_path, uploaded_file.name)
                    timings_ms["parse_ms"] = int((time.perf_counter() - parse_start) * 1000)

                    if "error" in parsed_data:
                        raise Exception(parsed_data["error"])

                    # 🔹 Parsed count
                    parsed_count = 1
                    if parsed_data.get("type") in ("nessus", "nessus_html"):
                        parsed_count = parsed_data.get("total_vulnerabilities", 1) or 1
                    elif "rows" in parsed_data:
                        parsed_count = parsed_data.get("rows", 1)

                    member_types_to_create = (
                        ["external", "internal"]
                        if member_type == "both"
                        else [member_type]
                    )

                    for mt in member_types_to_create:
                        mongo_start = time.perf_counter()
                        upload_report = UploadReport.objects.create(
                            file=relative_filename,
                            file_hash=file_hash,
                            location=None,
                            admin=target_admin,
                            member_type=mt,
                            status="Sucessfully Processed",
                            parsed_count=parsed_count,
                        )

                        report_id = str(upload_report._id)

                        mongodb_stored = self._store_in_mongodb(
                            parsed_data=parsed_data,
                            report_id=report_id,
                            location_id="",
                            location_name="",
                            admin_email=target_admin.email,
                            original_filename=uploaded_file.name,
                            member_type=mt
                        )

                        # Store actual upload processing time for UploadStatusView ETA
                        if mongodb_stored and parsed_data.get("type") in ("nessus", "nessus_html"):
                            upload_processing_seconds = int(round(time.perf_counter() - file_start))
                            try:
                                from vaptfix.mongo_client import get_shared_client, get_shared_db
                                _mc = get_shared_client()
                                _db = get_shared_db(_mc)
                                _db["nessus_reports"].update_one(
                                    {"report_id": report_id},
                                    {"$set": {"upload_processing_seconds": upload_processing_seconds}}
                                )
                            except Exception as _upe:
                                logger.warning(f"[UploadTiming] Could not store upload_processing_seconds: {_upe}")

                        # Auto-generate vulnerability cards in background (only for nessus reports)
                        print(f"[AutoGenCards] mongodb_stored={mongodb_stored}, report_type={parsed_data.get('type')}", flush=True)
                        if mongodb_stored and parsed_data.get("type") in ("nessus", "nessus_html"):
                            t = threading.Thread(
                                target=_auto_generate_cards_bg,
                                args=(report_id, target_admin.email, str(target_admin.id)),
                                daemon=True
                            )
                            t.start()
                            logger.info(f"[AutoGenCards] Background thread started for report_id={report_id}")
                            print(f"[AutoGenCards] Background thread started for report_id={report_id}", flush=True)
                        else:
                            print(f"[AutoGenCards] Thread NOT started — condition failed", flush=True)

                        file_url = request.build_absolute_uri(
                            settings.MEDIA_URL + relative_filename
                        )
                        timings_ms["mongo_ms"] += int((time.perf_counter() - mongo_start) * 1000)

                        response_start = time.perf_counter()
                        upload_results.append({
                            "report_id": report_id,
                            "file_name": uploaded_file.name,
                            "file_size_bytes": file_size_bytes or bytes_written,
                            "file_url": file_url,
                            "admin_id": str(target_admin.id),
                            "admin_email": target_admin.email,
                            "member_type": mt,
                            "status": upload_report.status,
                            "parsed_count": parsed_count,
                            "mongodb_stored": mongodb_stored,
                            "report_type": parsed_data.get("type"),
                            "structured_data_preview": self._create_preview(parsed_data),
                            "estimated_time_seconds": estimated_seconds,
                            "estimated_time_text": self._seconds_to_text(estimated_seconds),
                        })
                        timings_ms["response_build_ms"] += int((time.perf_counter() - response_start) * 1000)

                    file_total_seconds = time.perf_counter() - file_start
                    timings_ms["total_ms"] = int(file_total_seconds * 1000)

                    # Apply same file-level timing to all result rows created for this source file.
                    for result in reversed(upload_results):
                        if result.get("file_name") != uploaded_file.name:
                            break
                        result["actual_time_seconds"] = round(file_total_seconds, 2)
                        result["actual_time_text"] = self._seconds_to_text(file_total_seconds)
                        result["timings_ms"] = timings_ms

                except Exception as file_exc:
                    if file_path and os.path.exists(file_path):
                        os.remove(file_path)

                    errors.append({
                        "file": uploaded_file.name,
                        "error": str(file_exc)
                    })

            return Response({
                "success": True,
                "message": "Files Uploaded Successfully",
                "count": len(upload_results),
                "results": upload_results,
                "errors": errors,
                "total_processing_time_seconds": round(time.perf_counter() - api_start, 2),
                "total_processing_time_text": self._seconds_to_text(time.perf_counter() - api_start),
            }, status=201)

        except Exception as exc:
            return Response(
                {"error": "Upload failed", "detail": str(exc)},
                status=500
            )
      
        

class UploadReportLocationAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        try:
            try:
                obj_id = ObjectId(report_id)
            except Exception:
                return Response({"error": "Invalid report_id"}, status=400)

            report = (
                UploadReport.objects
                .filter(_id=obj_id, admin=request.user)
                .select_related("location")
                .first()
            )

            if not report or not report.location:
                return Response({"error": "Report or location not found"}, status=404)

            # ✅ selected location details
            selected_location = {
                "id": str(report.location._id),
                "name": report.location.location_name
            }

            qs = (
                UploadReport.objects
                .filter(admin=request.user)
                .select_related("location")
                .order_by("-uploaded_at")
            )

            locations_map = {}

            for r in qs:
                loc = r.location
                if not loc:
                    continue

                loc_id = str(loc._id)
                if loc_id not in locations_map:
                    locations_map[loc_id] = {
                        "id": loc_id,
                        "name": loc.location_name
                    }

            return Response({
                "success": True,
                "count": len(locations_map),
                "locations": list(locations_map.values()),
                "selected_location": selected_location
            }, status=200)

        except Exception as exc:
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=500
            )
            
            
            
# Upload Report BY ID
class UploadReportDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        # 🔹 Validate ObjectId
        try:
            obj_id = ObjectId(report_id)
        except (InvalidId, TypeError):
            return Response(
                {"error": "Invalid upload_report_id"},
                status=400
            )

        # 🔹 Fetch report ONLY for logged-in admin
        report = (
            UploadReport.objects
            .filter(_id=obj_id, admin=request.user)
            .select_related("location", "admin")
            .first()
        )

        if not report:
            return Response(
                {"error": "Upload report not found"},
                status=404
            )

        serializer = UploadReportSerializer(
            report,
            context={"request": request}
            )

        return Response(
            {
                "success": True,
                "message": "Upload report retrieved successfully",
                "upload_report": serializer.data
            },
            status=200
        )


#Upload report get all by admin
class UploadReportListByAdminAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # 🔹 Fetch all reports for logged-in admin
        reports = (
            UploadReport.objects
            .filter(admin=request.user)
            .select_related("location", "admin")
            .order_by("-uploaded_at")
        )

        serializer = UploadReportSerializer(
            reports,
            many=True,
            context={"request": request}
        )

        return Response(
            {
                "success": True,
                "count": reports.count(),
                "upload_reports": serializer.data
            },
            status=200
        )
        
# DELETE UPLOAD REPORT BY ID
class UploadReportDeleteAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, report_id):
        # 🔹 Validate ObjectId
        try:
            obj_id = ObjectId(report_id)
        except (InvalidId, TypeError):
            return Response(
                {"success": False, "message": "Invalid upload_report_id"},
                status=400
            )

        # 🔹 Fetch report only for logged-in admin
        report = (
            UploadReport.objects
            .filter(_id=obj_id, admin=request.user)
            .first()
        )

        if not report:
            return Response(
                {
                    "success": False,
                    "message": "Upload report not found or access denied"
                },
                status=404
            )

        # 🔹 Delete file from disk (if exists)
        if report.file:
            try:
                file_path = report.file.path
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as e:
                logger.warning("Failed to remove report file from disk: %s", e)

        # 🔹 OPTIONAL: delete MongoDB data
        try:
            _, db = _get_mongo_client_and_db()
            db["nessus_reports"].delete_one(
                {"report_id": str(report._id)}
            )
        except Exception as e:
            logger.warning("Mongo cleanup failed during report delete: %s", e)

        # 🔹 Delete DB record
        report.delete()

        return Response(
            {
                "success": True,
                "message": "Upload report deleted successfully",
                "deleted_report_id": report_id
            },
            status=200
        )


# ---------------------------------------------------------------------------
# Vulnerability Card generation and retrieval views
# ---------------------------------------------------------------------------

VULN_CARD_COLLECTION = "vulnerability_cards"
NESSUS_COLLECTION = "nessus_reports"

# Track running card generation jobs to prevent duplicate threads
_running_card_jobs: set = set()
_running_card_jobs_lock = threading.Lock()


def _auto_generate_cards_bg(report_id: str, admin_email: str, admin_id: str):
    """
    Background thread: auto-generate vulnerability cards after file upload.
    Runs the same logic as GenerateVulnerabilityCardView (Mode B).
    """
    import time
    import uuid as _uuid
    from .mitigation_tool import MitigationGenerationTool, _parse_troubleshooting_guide, _detect_os

    # Prevent duplicate threads for the same report_id
    with _running_card_jobs_lock:
        if report_id in _running_card_jobs:
            print(f"[AutoGenCards] Skipping duplicate thread for report_id={report_id}", flush=True)
            return
        _running_card_jobs.add(report_id)

    print(f"[AutoGenCards] Starting background card generation for report_id={report_id}", flush=True)

    # Small delay to ensure MongoDB document is fully committed
    time.sleep(2)

    client = None
    try:
        client, db = _get_mongo_client_and_db()
        print(f"[AutoGenCards] MongoDB connected for report_id={report_id}", flush=True)

        # MongoDB-level distributed lock (works across processes unlike in-memory lock)
        existing_lock = db["card_gen_locks"].find_one_and_update(
            {"report_id": report_id},
            {"$setOnInsert": {"report_id": report_id, "locked_at": datetime.datetime.utcnow()}},
            upsert=True,
        )
        if existing_lock is not None:
            # Lock already existed — another process/thread is handling this
            print(f"[AutoGenCards] Lock already held by another process for report_id={report_id}, skipping", flush=True)
            return

        # Store agent start time so UploadStatusView can compute accurate elapsed
        db[NESSUS_COLLECTION].update_one(
            {"report_id": report_id},
            {"$set": {"cards_generation_started_at": datetime.datetime.utcnow()}}
        )

        # Fetch nessus report from MongoDB
        nessus_doc = db[NESSUS_COLLECTION].find_one({"report_id": report_id})
        if not nessus_doc:
            logger.warning(f"[AutoGenCards] Nessus report not found: {report_id}")
            print(f"[AutoGenCards] ERROR: Nessus report not found in MongoDB for report_id={report_id}", flush=True)
            return

        # Build vulnerabilities list — one card per (host, plugin_name) combination
        # nessus_reports now stores plugin_outputs as array; use first entry for AI context
        vulns_to_process = []
        for host in nessus_doc.get("vulnerabilities_by_host", []):
            host_name = (host.get("host_name") or "").strip()
            # Extract OS from host_information (used for OS-specific mitigation steps)
            host_info = host.get("host_information") or {}
            operating_system = (
                host_info.get("operating-system")
                or host_info.get("os")
                or ""
            ).strip()

            for vuln in host.get("vulnerabilities", []):
                vuln_plugin_name = vuln.get("plugin_name", "").strip()
                if not vuln_plugin_name:
                    continue
                vuln_description = (
                    vuln.get("description", "")
                    or " ".join(vuln.get("description_points", []))
                ).strip()
                if not vuln_description:
                    continue

                # Get first plugin_output for AI context (new format: plugin_outputs array)
                plugin_outputs = vuln.get("plugin_outputs")
                if plugin_outputs and isinstance(plugin_outputs, list) and plugin_outputs:
                    first_po = plugin_outputs[0]
                    first_plugin_output = first_po.get("plugin_output", "") or ""
                    first_plugin_output_url = first_po.get("plugin_output_url")
                else:
                    # Fallback: old single-field format
                    first_plugin_output = vuln.get("plugin_output", "") or ""
                    first_plugin_output_url = vuln.get("plugin_output_url")

                vulns_to_process.append({
                    "plugin_name": vuln_plugin_name,
                    "description": vuln_description,
                    "host_name": host_name,
                    "operating_system": operating_system,
                    "os_category": _detect_os(operating_system),
                    "plugin_output": first_plugin_output,
                    "plugin_output_url": first_plugin_output_url,
                })

        if not vulns_to_process:
            logger.info(f"[AutoGenCards] No vulnerabilities to process for report_id={report_id}")
            return

        print(f"[AutoGenCards] {len(vulns_to_process)} total vulnerabilities to process for report_id={report_id}", flush=True)

        # Ensure indexes — unique per (report_id, vulnerability_name, host_name)
        db[VULN_CARD_COLLECTION].create_index("card_id", unique=True)
        db[VULN_CARD_COLLECTION].create_index("report_id")
        db[VULN_CARD_COLLECTION].create_index("admin_email")
        # Drop old (report_id, vulnerability_name) unique index if it exists
        try:
            db[VULN_CARD_COLLECTION].drop_index("report_id_1_vulnerability_name_1")
        except Exception as e:
            logger.warning("Suppressed error: %s", e)
        # Drop old compound index variants to avoid conflicts
        try:
            db[VULN_CARD_COLLECTION].drop_index("report_id_1_vulnerability_name_1_host_name_1")
        except Exception as e:
            logger.warning("Suppressed error: %s", e)
        db[VULN_CARD_COLLECTION].create_index(
            [("report_id", 1), ("vulnerability_name", 1), ("host_name", 1)],
            unique=True,
        )
        db[VULN_CARD_COLLECTION].create_index("created_at")

        tool = MitigationGenerationTool()
        generated = 0
        cached = 0
        errors = 0

        for vuln in vulns_to_process:
            vuln_plugin_name = vuln["plugin_name"]
            vuln_host_name   = vuln.get("host_name", "") or ""
            vuln_os_category = vuln.get("os_category", "windows")

            # ── Step 1: Skip if card already exists for this exact (report_id, plugin_name, host_name) ──
            already_exists = db[VULN_CARD_COLLECTION].find_one({
                "report_id":          report_id,
                "vulnerability_name": vuln_plugin_name,
                "host_name":          vuln_host_name,
            })
            if already_exists:
                print(f"[AutoGenCards] Already exists, skipping: '{vuln_plugin_name}' on '{vuln_host_name}'", flush=True)
                cached += 1
                continue

            # ── Step 2: Check if any card for this plugin_name + OS category exists in DB ──
            cached_card = db[VULN_CARD_COLLECTION].find_one(
                {"vulnerability_name": vuln_plugin_name, "os_category": vuln_os_category},
                sort=[("created_at", -1)],
            )

            if cached_card:
                # Reuse mitigation data from existing card — no GPT call needed
                print(f"[AutoGenCards] Cache hit for '{vuln_plugin_name}' ({vuln_os_category}), copying from existing card", flush=True)
                document = {
                    "card_id":            str(_uuid.uuid4()),
                    "report_id":          report_id,
                    "admin_email":        admin_email,
                    "admin_id":           admin_id,
                    "vulnerability_name": vuln_plugin_name,
                    "host_name":          vuln_host_name,
                    "os_category":        vuln_os_category,
                    "description":        vuln["description"],
                    "mitigation_table":   cached_card.get("mitigation_table", []),
                    "resource_id":        vuln_host_name or cached_card.get("resource_id"),
                    "region":             cached_card.get("region"),
                    "affected_packages":  cached_card.get("affected_packages"),
                    "vendor_advisory":    cached_card.get("vendor_advisory"),
                    "reference_url":      cached_card.get("reference_url"),
                    "vulnerability_type": cached_card.get("vulnerability_type"),
                    "affected_port_ranges": cached_card.get("affected_port_ranges"),
                    "assigned_team":      cached_card.get("assigned_team"),
                    "vendor_fix_available": cached_card.get("vendor_fix_available"),
                    "steps_to_fix_count": cached_card.get("steps_to_fix_count"),
                    "steps_to_fix_description": cached_card.get("steps_to_fix_description"),
                    "deadline":           cached_card.get("deadline"),
                    "artifacts_tools":    cached_card.get("artifacts_tools"),
                    "post_mitigation_troubleshooting_guide": cached_card.get("post_mitigation_troubleshooting_guide", []),
                    "generated_at":       cached_card.get("generated_at"),
                    "created_at":         datetime.datetime.utcnow(),
                    "cached_from_card_id": str(cached_card.get("card_id", "")),
                }
            else:
                # ── Step 3: No cache — call GPT-4o to generate new card ──
                print(f"[AutoGenCards] No cache for '{vuln_plugin_name}', calling GPT-4o", flush=True)
                result = tool._run(
                    plugin_name=vuln_plugin_name,
                    description=vuln["description"],
                    plugin_output=vuln.get("plugin_output", "") or "",
                    report_id=report_id,
                    host_name=vuln_host_name,
                    operating_system=vuln.get("operating_system", "") or "",
                )

                if not result["success"]:
                    logger.warning(f"[AutoGenCards] Failed for '{vuln_plugin_name}': {result.get('error')}")
                    errors += 1
                    continue

                vc = result.get("vulnerability_card", {})
                mitigation_table_arr = result.get("mitigation_table", [])
                troubleshooting_steps = _parse_troubleshooting_guide(
                    vc.get("post_mitigation_troubleshooting_guide", "") or ""
                )

                document = {
                    "card_id":            str(_uuid.uuid4()),
                    "report_id":          report_id,
                    "admin_email":        admin_email,
                    "admin_id":           admin_id,
                    "vulnerability_name": vuln_plugin_name,
                    "host_name":          vuln_host_name,
                    "os_category":        vuln_os_category,
                    "description":        vuln["description"],
                    "mitigation_table":   mitigation_table_arr,
                    "resource_id":        vc.get("resource_id"),
                    "region":             vc.get("region"),
                    "affected_packages":  vc.get("affected_packages"),
                    "vendor_advisory":    vc.get("vendor_advisory"),
                    "reference_url":      vc.get("reference_url"),
                    "vulnerability_type": vc.get("vulnerability_type"),
                    "affected_port_ranges": vc.get("affected_port_ranges"),
                    "assigned_team":      vc.get("assigned_team"),
                    "vendor_fix_available": vc.get("vendor_fix_available"),
                    "steps_to_fix_count": vc.get("steps_to_fix_count"),
                    "steps_to_fix_description": vc.get("steps_to_fix_description"),
                    "deadline":           vc.get("deadline"),
                    "artifacts_tools":    vc.get("artifacts_tools"),
                    "post_mitigation_troubleshooting_guide": troubleshooting_steps,
                    "generated_at":       result.get("generated_at"),
                    "created_at":         datetime.datetime.utcnow(),
                }

            try:
                db[VULN_CARD_COLLECTION].update_one(
                    {
                        "report_id":          report_id,
                        "vulnerability_name": vuln_plugin_name,
                        "host_name":          vuln_host_name,
                    },
                    {"$set": document},
                    upsert=True,
                )
                if cached_card:
                    cached += 1
                else:
                    generated += 1
            except Exception as insert_err:
                print(f"[AutoGenCards] Insert error for '{vuln_plugin_name}' on host '{vuln_host_name}': {insert_err}", flush=True)
                errors += 1

        # Verify actual count in MongoDB
        actual_count = db[VULN_CARD_COLLECTION].count_documents({"report_id": report_id})
        logger.info(
            f"[AutoGenCards] Done for report_id={report_id} — "
            f"generated={generated}, cached={cached}, errors={errors}, actual_in_db={actual_count}"
        )
        print(f"[AutoGenCards] Done for report_id={report_id} — generated={generated}, cached={cached}, errors={errors}, actual_in_db={actual_count}", flush=True)

        # Mark generation as complete in nessus_reports so UploadStatusView knows
        db[NESSUS_COLLECTION].update_one(
            {"report_id": report_id},
            {"$set": {"cards_generation_complete": True, "cards_generated_count": actual_count}}
        )

    except Exception as e:
        logger.error(f"[AutoGenCards] Background generation failed for report_id={report_id}: {str(e)}", exc_info=True)
        print(f"[AutoGenCards] EXCEPTION for report_id={report_id}: {str(e)}", flush=True)
    finally:
        try:
            _, _db = _get_mongo_client_and_db()
            _db["card_gen_locks"].delete_one({"report_id": report_id})
        except Exception as e:
            logger.warning("Suppressed error: %s", e)
        with _running_card_jobs_lock:
            _running_card_jobs.discard(report_id)


from vaptfix.mongo_client import get_shared_client, get_shared_db


def _get_mongo_client_and_db():
    """Return (client, db) using the shared MongoDB connection pool."""
    client = get_shared_client()
    return client, get_shared_db(client)


class GenerateVulnerabilityCardView(APIView):
    """
    POST /api/admin/upload_report/vulnerability-cards/generate/

    Mode A — single vulnerability (provide plugin_name + description in body):
    {
        "report_id": "<string>",
        "plugin_name": "<string>",
        "description": "<string>",
        "cve_id": "<string>",        # optional
        "risk_factor": "<string>",   # optional
        "host_name": "<string>",     # optional
        "cvss_score": "<string>",    # optional
        "force_regenerate": false    # optional
    }

    Mode B — bulk from nessus_reports (provide only report_id):
    {
        "report_id": "<string>",
        "force_regenerate": false    # optional
    }
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        from .mitigation_tool import MitigationGenerationTool, _detect_os

        report_id = request.data.get("report_id", "").strip()
        if not report_id:
            return Response({"error": "report_id is required"}, status=400)

        force_regenerate = bool(request.data.get("force_regenerate", False))
        plugin_name = request.data.get("plugin_name", "").strip()
        description = request.data.get("description", "").strip()

        # Determine mode
        mode_a = bool(plugin_name and description)

        try:
            client, db = _get_mongo_client_and_db()
        except RuntimeError as exc:
            return Response({"error": str(exc)}, status=500)

        try:
            if mode_a:
                # Mode A: single vulnerability from request body
                vulns_to_process = [{
                    "plugin_name": plugin_name,
                    "description": description,
                    "plugin_output": request.data.get("plugin_output", ""),
                    "host_name": request.data.get("host_name", ""),
                    "risk_factor": request.data.get("risk_factor", ""),
                }]
            else:
                # Mode B: fetch all vulnerabilities from nessus_reports
                nessus_doc = db[NESSUS_COLLECTION].find_one({"report_id": report_id})
                if not nessus_doc:
                    return Response(
                        {"error": "Nessus report not found for the given report_id"},
                        status=404,
                    )

                # Ownership check
                doc_admin_email = nessus_doc.get("admin_email", "")
                if (
                    doc_admin_email != getattr(request.user, "email", "")
                    and not request.user.is_superuser
                ):
                    return Response(
                        {"error": "Access denied: report belongs to a different admin"},
                        status=403,
                    )

                # Flatten all vulnerabilities across all hosts
                vulns_to_process = []
                for host in nessus_doc.get("vulnerabilities_by_host", []):
                    host_name = host.get("host_name", "")
                    host_info = host.get("host_information") or {}
                    host_os = (
                        host_info.get("operating-system")
                        or host_info.get("os")
                        or ""
                    ).strip()
                    for vuln in host.get("vulnerabilities", []):
                        vuln_plugin_name = vuln.get("plugin_name", "").strip()
                        vuln_description = (
                            vuln.get("description", "")
                            or " ".join(vuln.get("description_points", []))
                        ).strip()
                        if not vuln_plugin_name or not vuln_description:
                            continue
                        vulns_to_process.append({
                            "plugin_name": vuln_plugin_name,
                            "description": vuln_description,
                            "plugin_output": vuln.get("plugin_output", ""),
                            "host_name": host_name,
                            "operating_system": host_os,
                            "os_category": _detect_os(host_os),
                            "risk_factor": vuln.get("risk_factor", ""),
                        })

            if not vulns_to_process:
                return Response(
                    {"error": "No vulnerabilities with plugin_name and description found"},
                    status=400,
                )

            # Ensure indexes exist
            db[VULN_CARD_COLLECTION].create_index("card_id", unique=True)
            db[VULN_CARD_COLLECTION].create_index("report_id")
            db[VULN_CARD_COLLECTION].create_index("admin_email")
            db[VULN_CARD_COLLECTION].create_index(
                [("report_id", 1), ("vulnerability_name", 1)]
            )
            db[VULN_CARD_COLLECTION].create_index("created_at")

            tool = MitigationGenerationTool()
            cards_generated = []
            skipped_count = 0
            errors = []

            for vuln in vulns_to_process:
                vuln_plugin_name = vuln["plugin_name"]

                # Deduplication check
                if not force_regenerate:
                    existing = db[VULN_CARD_COLLECTION].find_one({
                        "report_id": report_id,
                        "vulnerability_name": vuln_plugin_name,
                    })
                    if existing:
                        skipped_count += 1
                        continue

                result = tool._run(
                    plugin_name=vuln_plugin_name,
                    description=vuln["description"],
                    plugin_output=vuln.get("plugin_output", ""),
                    report_id=report_id,
                    host_name=vuln.get("host_name", "") or "",
                    operating_system=vuln.get("operating_system", "") or "",
                )

                if not result["success"]:
                    errors.append({
                        "vulnerability_name": vuln_plugin_name,
                        "error": result.get("error", "Unknown error"),
                    })
                    continue

                import uuid as _uuid
                card_id = str(_uuid.uuid4())
                now = datetime.datetime.utcnow()
                vc = result.get("vulnerability_card", {})

                # mitigation_table is a list from the parser
                mitigation_table_arr = result.get("mitigation_table", [])

                # Fix: if AI returns null for resource_id, fall back to host_name from scan data
                resource_id = vc.get("resource_id") or vuln.get("host_name", "") or None

                # Parse post_mitigation_troubleshooting_guide into structured steps
                from .mitigation_tool import _parse_troubleshooting_guide
                troubleshooting_steps = _parse_troubleshooting_guide(
                    vc.get("post_mitigation_troubleshooting_guide", "") or ""
                )

                document = {
                    "card_id": card_id,
                    "report_id": report_id,
                    "admin_email": getattr(request.user, "email", ""),
                    "admin_id": str(request.user.id),
                    "vulnerability_name": vuln_plugin_name,
                    "os_category": vuln.get("os_category", "windows"),
                    "description": vuln["description"],
                    "plugin_output": vuln.get("plugin_output", "") or None,
                    "mitigation_table": mitigation_table_arr,
                    # Vulnerability Card fields from AI
                    "resource_id": resource_id,
                    "region": vc.get("region"),
                    "affected_packages": vc.get("affected_packages"),
                    "vendor_advisory": vc.get("vendor_advisory"),
                    "reference_url": vc.get("reference_url"),
                    "vulnerability_type": vc.get("vulnerability_type"),
                    "affected_port_ranges": vc.get("affected_port_ranges"),
                    "file_path": vc.get("file_path"),
                    "assigned_team": vc.get("assigned_team"),
                    "vendor_fix_available": vc.get("vendor_fix_available"),
                    "steps_to_fix_count": vc.get("steps_to_fix_count"),
                    "steps_to_fix_description": vc.get("steps_to_fix_description"),
                    "deadline": vc.get("deadline"),
                    "artifacts_tools": vc.get("artifacts_tools"),
                    "post_mitigation_troubleshooting_guide": troubleshooting_steps,
                    "generated_at": result.get("generated_at"),
                    "created_at": now,
                }

                db[VULN_CARD_COLLECTION].insert_one(document)

                cards_generated.append({
                    "card_id": card_id,
                    "report_id": report_id,
                    "vulnerability_name": vuln_plugin_name,
                    "description": vuln["description"],
                    "plugin_output": vuln.get("plugin_output", "") or None,
                    # Vulnerability Card fields from AI
                    "resource_id": resource_id,
                    "region": vc.get("region"),
                    "affected_packages": vc.get("affected_packages"),
                    "vendor_advisory": vc.get("vendor_advisory"),
                    "reference_url": vc.get("reference_url"),
                    "vulnerability_type": vc.get("vulnerability_type"),
                    "affected_port_ranges": vc.get("affected_port_ranges"),
                    "file_path": vc.get("file_path"),
                    "assigned_team": vc.get("assigned_team"),
                    "vendor_fix_available": vc.get("vendor_fix_available"),
                    "steps_to_fix_count": vc.get("steps_to_fix_count"),
                    "steps_to_fix_description": vc.get("steps_to_fix_description"),
                    "deadline": vc.get("deadline"),
                    "artifacts_tools": vc.get("artifacts_tools"),
                    "post_mitigation_troubleshooting_guide": troubleshooting_steps,
                    "mitigation_table": mitigation_table_arr,
                    "generated_at": result.get("generated_at"),
                })

            return Response(
                {
                    "success": True,
                    "message": "Vulnerability cards generated successfully",
                    "count": len(cards_generated),
                    "skipped_count": skipped_count,
                    "cards": cards_generated,
                    "errors": errors,
                },
                status=201,
            )

        except Exception as exc:
            import traceback
            traceback.print_exc()
            return Response(
                {"error": "Generation failed", "detail": str(exc)},
                status=500,
            )


class VulnerabilityCardListView(APIView):
    """
    GET /api/admin/upload_report/vulnerability-cards/?report_id=<id>

    Returns summary of all vulnerability cards for the given report.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        report_id = request.query_params.get("report_id", "").strip()
        if not report_id:
            return Response({"error": "report_id query parameter is required"}, status=400)

        try:
            client, db = _get_mongo_client_and_db()
        except RuntimeError as exc:
            return Response({"error": str(exc)}, status=500)

        try:
            query = {
                "report_id": report_id,
                "admin_email": getattr(request.user, "email", ""),
            }
            if request.user.is_superuser:
                query = {"report_id": report_id}

            cursor = db[VULN_CARD_COLLECTION].find(
                query,
                {
                    # Exclude heavy fields from list view
                    "mitigation_table": 0,
                    "contextual_analysis": 0,
                    "raw_ai_response": 0,
                    "_id": 0,
                },
            ).sort("created_at", -1)

            cards = list(cursor)
            for card in cards:
                # Ensure datetime objects are serializable
                if "created_at" in card and isinstance(card["created_at"], datetime.datetime):
                    card["created_at"] = card["created_at"].isoformat()

            return Response(
                {
                    "success": True,
                    "count": len(cards),
                    "report_id": report_id,
                    "cards": cards,
                },
                status=200,
            )

        except Exception as exc:
            return Response(
                {"error": "Failed to retrieve cards", "detail": str(exc)},
                status=500,
            )


class VulnerabilityCardDetailView(APIView):
    """
    GET /api/admin/upload_report/vulnerability-cards/<card_id>/

    Returns the full vulnerability card including mitigation_table and
    contextual_analysis.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, card_id):
        try:
            client, db = _get_mongo_client_and_db()
        except RuntimeError as exc:
            return Response({"error": str(exc)}, status=500)

        try:
            query = {"card_id": card_id}
            if not request.user.is_superuser:
                query["admin_email"] = getattr(request.user, "email", "")

            card = db[VULN_CARD_COLLECTION].find_one(query, {"_id": 0})
            if not card:
                return Response(
                    {"error": "Vulnerability card not found or access denied"},
                    status=404,
                )

            if "created_at" in card and isinstance(card["created_at"], datetime.datetime):
                card["created_at"] = card["created_at"].isoformat()

            return Response(
                {
                    "success": True,
                    "card": card,
                },
                status=200,
            )

        except Exception as exc:
            return Response(
                {"error": "Failed to retrieve card", "detail": str(exc)},
                status=500,
            )