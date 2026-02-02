import os
import uuid
import json
import datetime
from typing import Optional, Dict, Any, List
import hashlib

from bson import ObjectId
from bson.errors import InvalidId

from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

import pymongo

from location.models import Location
from scope.models import Scope
from users.models import User
from .models import UploadReport
from .serializers import UploadReportSerializer
from django.http import FileResponse, Http404, HttpResponseForbidden
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth.decorators import login_required

# Serve uploaded report files (uses Django session auth for admin access)
@login_required(login_url='/admin/login/')
def serve_report_file(request, path):
    file_path = os.path.join(settings.MEDIA_ROOT, path)

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
        except Exception:
            pass
        
        try:
            dbname = settings.DATABASES['default'].get('NAME')
            if dbname:
                return client[dbname]
        except Exception:
            pass
        
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
        mongo_uri = self._get_mongo_uri()
        if not mongo_uri:
            print("Warning: No MongoDB URI configured")
            return False
        
        try:
            with pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000) as client:
                db = self._get_mongo_db(client)
                
                # Base document structure
                document = {
                    "report_id": report_id,
                    "original_filename": original_filename,
                    "location_id": location_id,
                    "location_name": location_name,
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
                    
                    # Create indexes for efficient querying
                    db["nessus_reports"].create_index("report_id", unique=True)
                    db["nessus_reports"].create_index("location_id")
                    db["nessus_reports"].create_index("uploaded_at")
                    db["nessus_reports"].create_index([("vulnerabilities_by_host.host_name", 1)])
                    # IMPORTANT: Index on risk_factor for filtering
                    db["nessus_reports"].create_index([
                        ("vulnerabilities_by_host.vulnerabilities.risk_factor", 1)
                    ])
                    db["nessus_reports"].create_index([
                        ("vulnerabilities_by_host.vulnerabilities.plugin_id", 1)
                    ])
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

            # Check if target admin's scope is locked
            # If scope is locked, only Super Admin can upload reports
            admin_has_locked_scope = Scope.objects.filter(
                admin=target_admin,
                is_locked=True
            ).exists()

            if admin_has_locked_scope and not request.user.is_superuser:
                return Response(
                    {"error": "Scope is locked. Only Super Admin can upload reports."},
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

                try:
                    # 🔹 Extension check
                    ext = os.path.splitext(uploaded_file.name)[1].lower()
                    if ext not in self.ALLOWED_EXTENSIONS:
                        errors.append({
                            "file": uploaded_file.name,
                            "error": "Unsupported file type"
                        })
                        continue

                    # 🔹 FILE HASH (duplicate check)
                    file_hash = self._generate_file_hash(uploaded_file)

                    if UploadReport.objects.filter(
                        admin=target_admin,
                        file_hash=file_hash
                    ).exists():
                        errors.append({
                            "file": uploaded_file.name,
                            "error": "Duplicate file detected. This file was already uploaded."
                        })
                        continue

                    # 🔹 Save file
                    # Save under target admin folder to avoid overwrite
                    target_admin_id = str(target_admin.id)

                    relative_filename = f"reports/{target_admin_id}/{uploaded_file.name}"
                    file_path = os.path.join(settings.MEDIA_ROOT, relative_filename)

                    os.makedirs(os.path.dirname(file_path), exist_ok=True)

                    with open(file_path, "wb+") as dest:
                        for chunk in uploaded_file.chunks():
                            dest.write(chunk)

                    # 🔹 Parse file (your existing parser)
                    parsed_data = dispatch_parse(file_path, uploaded_file.name)

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

                        file_url = request.build_absolute_uri(
                            settings.MEDIA_URL + relative_filename
                        )

                        upload_results.append({
                            "report_id": report_id,
                            "file_name": uploaded_file.name,
                            "file_url": file_url,
                            "admin_id": str(target_admin.id),
                            "admin_email": target_admin.email,
                            "member_type": mt,
                            "status": upload_report.status,
                            "parsed_count": parsed_count,
                            "mongodb_stored": mongodb_stored,
                            "report_type": parsed_data.get("type"),
                            "structured_data_preview": self._create_preview(parsed_data)
                        })

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
                "errors": errors
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
            except Exception:
                pass  # do not fail delete if file missing

        # 🔹 OPTIONAL: delete MongoDB data
        try:
            from pymongo import MongoClient
            mongo_uri = settings.DATABASES["default"]["CLIENT"]["host"]

            with MongoClient(mongo_uri) as client:
                db = client.get_default_database()
                db["nessus_reports"].delete_one(
                    {"report_id": str(report._id)}
                )
        except Exception:
            pass  # Mongo cleanup should not block API

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