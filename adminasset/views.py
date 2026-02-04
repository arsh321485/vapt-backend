from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.conf import settings
from urllib.parse import urlparse,unquote
from datetime import datetime
from django.utils.timezone import is_naive, make_aware
from django.utils import timezone
import pymongo
import re

from .serializers import AdminAssetSerializer,AssetHostVulnSerializer,HoldAssetSerializer,HoldAssetListSerializer
# Import User for organisation_name lookup
try:
    from users.models import User
except Exception:
    User = None

NESSUS_COLLECTION = "nessus_reports"
HOLD_COLLECTION = "hold_assets"
FIX_VULN_COLLECTION = "fix_vulnerabilities"

# ---------------------- Mongo Context ----------------------
class MongoContext:
    def __init__(self):
        self.uri = getattr(settings, "MONGO_DB_URL", None)
        if not self.uri:
            self.uri = settings.DATABASES.get("default", {}).get("CLIENT", {}).get("host")
        self.client = None

    def __enter__(self):
        if not self.uri:
            raise RuntimeError("MongoDB URI not configured.")

        self.client = pymongo.MongoClient(self.uri, serverSelectionTimeoutMS=5000)

        parsed = urlparse(self.uri)
        dbname = parsed.path.replace("/", "") or "vaptfix"

        return self.client[dbname]

    def __exit__(self, exc_type, exc, tb):
        if self.client:
            self.client.close()


# ---------------------- Helper ----------------------
def validate_report_ownership(db, report_id, user):
    """
    Validate that the requesting user owns the report.

    Args:
        db: MongoDB database instance
        report_id: The report ID to validate
        user: The requesting user

    Returns:
        tuple: (is_valid, doc, error_response)
            - is_valid: Boolean indicating if user has access
            - doc: The report document if found, None otherwise
            - error_response: Response object if validation fails, None otherwise
    """
    coll = db[NESSUS_COLLECTION]
    doc = coll.find_one({"report_id": str(report_id)})

    if not doc:
        return False, None, Response(
            {"detail": "Report not found"},
            status=status.HTTP_404_NOT_FOUND
        )

    # Super admin can access all reports
    if getattr(user, 'is_superuser', False):
        return True, doc, None

    # Check ownership by admin_id
    report_admin_id = doc.get("admin_id")
    user_id = str(user.id)

    if report_admin_id and report_admin_id != user_id:
        return False, None, Response(
            {"detail": "Access denied. You can only view assets from your own reports."},
            status=status.HTTP_403_FORBIDDEN
        )

    # Fallback: check by admin_email if admin_id not present (for older reports)
    if not report_admin_id:
        report_admin_email = doc.get("admin_email")
        user_email = getattr(user, 'email', None)
        if report_admin_email and user_email and report_admin_email != user_email:
            return False, None, Response(
                {"detail": "Access denied. You can only view assets from your own reports."},
                status=status.HTTP_403_FORBIDDEN
            )

    return True, doc, None


def _iso(v):
    if not v:
        return None
    if isinstance(v, datetime):
        if is_naive(v):
            v = make_aware(v)
        return v.isoformat()
    return str(v)

def _join_description(vuln):
    pts = vuln.get("description_points") or []
    if isinstance(pts, (list, tuple)) and pts:
        return " ".join([str(p).strip() for p in pts if p is not None and str(p).strip()])
    return (vuln.get("description") or vuln.get("synopsis") or "").strip()


def compute_total_assets_for_report(db, report_id):
    coll = db[NESSUS_COLLECTION]
    doc = coll.find_one(
        {"report_id": str(report_id)},
        {"vulnerabilities_by_host": 1}
    )
    if not doc:
        return 0
    return len(doc.get("vulnerabilities_by_host", []))



# ---------------------- GET ALL ASSETS API ----------------------
class ReportAssetsAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, report_id):
        try:
            # 🔍 search query (asset / host_name only)
            search_q = (request.query_params.get("q") or "").strip().lower()

            with MongoContext() as db:
                # Validate ownership - admin can only see their own reports
                is_valid, doc, error_response = validate_report_ownership(
                    db, report_id, request.user
                )
                if not is_valid:
                    return error_response

                uploaded_at = doc.get("uploaded_at")
                member_type = doc.get("member_type")

                assets = {}

                for host in doc.get("vulnerabilities_by_host", []):
                    host_name = (host.get("host_name") or "").strip()
                    if not host_name:
                        continue

                    # ✅ APPLY SEARCH FILTER (asset only)
                    if search_q and search_q not in host_name.lower():
                        continue

                    if host_name not in assets:
                        assets[host_name] = {
                            "asset": host_name,
                            "first_seen": uploaded_at,
                            "last_seen": uploaded_at,
                            "member_type": member_type,
                            "total_vulnerabilities": 0,
                            "severity_counts": {
                                "critical": 0,
                                "high": 0,
                                "medium": 0,
                                "low": 0
                            },
                            "host_information": host.get("host_information") or {}
                        }

                    entry = assets[host_name]

                    for v in host.get("vulnerabilities", []):
                        entry["total_vulnerabilities"] += 1
                        risk = (v.get("risk_factor") or v.get("severity") or "").lower()

                        if risk.startswith("crit"):
                            entry["severity_counts"]["critical"] += 1
                        elif risk.startswith("high"):
                            entry["severity_counts"]["high"] += 1
                        elif risk.startswith("med"):
                            entry["severity_counts"]["medium"] += 1
                        elif risk.startswith("low"):
                            entry["severity_counts"]["low"] += 1

                final = []
                for a in assets.values():
                    final.append({
                        "asset": a["asset"],
                        "member_type": a["member_type"],
                        "first_seen": _iso(a["first_seen"]),
                        "last_seen": _iso(a["last_seen"]),
                        "total_vulnerabilities": a["total_vulnerabilities"],
                        "severity_counts": a["severity_counts"],
                        "host_information": a["host_information"],
                    })

                serializer = AdminAssetSerializer(final, many=True)

                return Response({
                    "report_id": report_id,
                    "member_type": member_type,
                    "total_assets": len(final),
                    "assets": serializer.data
                }, status=200)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": str(exc)}, status=500)

 
# ----------------  ASSET DELETE ----------------    
class AssetDeleteAPIView(APIView):
    """
    DELETE /api/adminasset/report/<report_id>/assets/<host_name>/
    Removes the host (vulnerabilities_by_host entry with matching host_name) from the report.
    """
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, report_id, host_name):
        # host_name may be URL-encoded path; unquote it
        host_name = unquote(host_name)
        try:
            with MongoContext() as db:
                # Validate ownership - admin can only delete assets from their own reports
                is_valid, doc, error_response = validate_report_ownership(
                    db, report_id, request.user
                )
                if not is_valid:
                    return error_response

                coll = db[NESSUS_COLLECTION]

                # Use $pull to remove host entry by host_name OR host (handle both keys safely)
                res = coll.update_one(
                    {"report_id": str(report_id)},
                    {"$pull": {"vulnerabilities_by_host": {"$or": [{"host_name": host_name}, {"host": host_name}]}}}
                )

                # For safety, check if host still exists
                remaining = coll.find_one({"report_id": str(report_id), "$or": [{"vulnerabilities_by_host.host_name": host_name}, {"vulnerabilities_by_host.host": host_name}]}, {"_id": 1})
                if remaining:
                    return Response({"detail": "delete attempted but host still present; check host_name formatting"}, status=500)

                if res.matched_count == 0:
                    return Response({"detail": "Report not found"}, status=status.HTTP_404_NOT_FOUND)
                if res.modified_count == 0:
                    return Response({"detail": "Asset not found in report"}, status=status.HTTP_404_NOT_FOUND)

                return Response({"detail": "Asset removed from report"}, status=status.HTTP_200_OK)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": "Delete failed", "error": str(exc)}, status=500)
        
        
        
# ----------------  ASSET vulnerabilities ----------------   

class AssetVulnerabilitiesByHostAPIView(APIView):
    """
    GET /api/admin/adminasset/report/<report_id>/asset/<path:host_name>/vulnerabilities/
    Returns vulnerabilities for one specific host_name in the report.
    Fields mapped:
      - asset -> host_name
      - exposure -> member_type (from report)
      - owner -> organisation_name (or user.organisation_name fallback)
      - severity -> risk_factor
      - vul_name -> plugin_name
      - vendor_fix_available -> "Yes" (default)
      - cvss_score -> cvss_v3_base_score
      - description -> description_points (joined)
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, report_id, host_name):
        host_name = unquote(host_name)
        try:
            with MongoContext() as db:
                # Validate ownership - admin can only view vulnerabilities from their own reports
                is_valid, doc, error_response = validate_report_ownership(
                    db, report_id, request.user
                )
                if not is_valid:
                    return error_response

                # context fields
                member_type = doc.get("member_type") or ""
                scan_info = doc.get("scan_info") or {}
                organisation_name = (
                    scan_info.get("organisation_name")
                    or scan_info.get("organization")
                    or scan_info.get("organisation")
                    or ""
                )
                # fallback to user table if admin_email present and no organisation_name
                admin_email = doc.get("admin_email") or ""
                if not organisation_name and User is not None and admin_email:
                    user = User.objects.filter(email=admin_email).first()
                    if user:
                        organisation_name = getattr(user, "organisation_name", "") or ""

                # find host entry
                host_entry = None
                for h in (doc.get("vulnerabilities_by_host") or []):
                    hn = (h.get("host_name") or h.get("host") or "").strip()
                    if hn == host_name:
                        host_entry = h
                        break

                if not host_entry:
                    return Response({"detail": "Asset not found in report"}, status=status.HTTP_404_NOT_FOUND)

                out = []
                for v in (host_entry.get("vulnerabilities") or []):
                    item = {
                        "asset": host_name,
                        "exposure": member_type,
                        "owner": organisation_name,
                        "severity": (v.get("risk_factor") or v.get("severity") or "").title(),
                        "vul_name": v.get("plugin_name") or v.get("pluginname") or v.get("name") or "",
                        "vendor_fix_available": "Yes",
                        "cvss_score": str(v.get("cvss_v3_base_score") or v.get("cvss") or v.get("cvss_score") or ""),
                        "description": _join_description(v),
                    }
                    out.append(item)

                serializer = AssetHostVulnSerializer(out, many=True)
                return Response({
                    "report_id": str(report_id),
                    "asset": host_name,
                    "count": len(out),
                    "vulnerabilities": serializer.data
                }, status=200)

        except pymongo.errors.ServerSelectionTimeoutError as e:
            return Response({"detail": "cannot connect to MongoDB", "error": str(e)}, status=500)
        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": "unexpected error", "error": str(exc)}, status=500)        
  
# ----------------  ASSET HOLD ----------------        
class AssetHoldAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, report_id, host_name):
        host_name = unquote(host_name)

        try:
            with MongoContext() as db:
                # Validate ownership - admin can only hold assets from their own reports
                is_valid, doc, error_response = validate_report_ownership(
                    db, report_id, request.user
                )
                if not is_valid:
                    return error_response

                coll = db[NESSUS_COLLECTION]
                held_coll = db[HOLD_COLLECTION]

                member_type = doc.get("member_type")

                found = None
                for h in doc.get("vulnerabilities_by_host", []):
                    hn = (h.get("host_name") or h.get("host") or "").strip()
                    if hn == host_name:
                        found = h
                        break

                if not found:
                    return Response(
                        {"detail": "Asset not found in report"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                # Remove asset from report
                coll.update_one(
                    {"report_id": str(report_id)},
                    {
                        "$pull": {
                            "vulnerabilities_by_host": {
                                "$or": [
                                    {"host_name": host_name},
                                    {"host": host_name}
                                ]
                            }
                        }
                    }
                )

                # Store into hold collection
                held_coll.insert_one({
                    "report_id": str(report_id),
                    "host_name": host_name,
                    "member_type": member_type,
                    "host_entry": found,
                    "held_at": timezone.now(),
                    "held_by": getattr(request.user, "email", None)
                               or getattr(request.user, "username", None),
                })

                # Prepare asset data for response
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for v in found.get("vulnerabilities", []):
                    risk = (v.get("risk_factor") or "").lower()
                    if risk.startswith("crit"):
                        severity_counts["critical"] += 1
                    elif risk.startswith("high"):
                        severity_counts["high"] += 1
                    elif risk.startswith("med"):
                        severity_counts["medium"] += 1
                    elif risk.startswith("low"):
                        severity_counts["low"] += 1

                asset_data = {
                    "asset": host_name,
                    "member_type": member_type,
                    "total_vulnerabilities": len(found.get("vulnerabilities", [])),
                    "severity_counts": severity_counts,
                    "host_information": found.get("host_information") or {}
                }

                total_assets = compute_total_assets_for_report(db, report_id)

                return Response(
                    {
                        "detail": "Asset hold (removed from report)",
                        "total_assets": total_assets,
                        "asset": asset_data
                    },
                    status=status.HTTP_200_OK
                )

        except Exception as exc:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "Hold failed", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ----------------  ASSET UNHOLD ----------------
class AssetUnholdAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, report_id, host_name):
        host_name = unquote(host_name)

        try:
            with MongoContext() as db:
                # Validate ownership - admin can only unhold assets from their own reports
                is_valid, doc, error_response = validate_report_ownership(
                    db, report_id, request.user
                )
                if not is_valid:
                    return error_response

                coll = db[NESSUS_COLLECTION]
                held_coll = db[HOLD_COLLECTION]

                # 1️⃣ Find held asset
                held = held_coll.find_one({
                    "report_id": str(report_id),
                    "host_name": host_name
                })

                if not held:
                    return Response(
                        {"detail": "No hold asset found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                host_entry = held.get("host_entry")
                member_type = held.get("member_type")
                
                if not host_entry:
                    return Response(
                        {"detail": "Hold asset missing host_entry"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

                # 2️⃣ Restore asset to report
                res = coll.update_one(
                    {"report_id": str(report_id)},
                    {"$push": {"vulnerabilities_by_host": host_entry}}
                )

                if res.matched_count == 0:
                    return Response(
                        {"detail": "Report not found when restoring"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                # 3️⃣ Remove from hold_assets
                held_coll.delete_one({"_id": held["_id"]})

                # 4️⃣ Recompute total assets
                total_assets = compute_total_assets_for_report(db, report_id)

                # 5️⃣ Prepare asset response (summary)
                asset_response = {
                    "asset": host_name,
                    "member_type": member_type,
                    "total_vulnerabilities": len(host_entry.get("vulnerabilities", [])),
                    "host_information": host_entry.get("host_information", {}),
                    "severity_counts": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                    }
                }

                for v in host_entry.get("vulnerabilities", []):
                    sev = (v.get("risk_factor") or v.get("severity") or "").lower()
                    if sev.startswith("crit"):
                        asset_response["severity_counts"]["critical"] += 1
                    elif sev.startswith("high"):
                        asset_response["severity_counts"]["high"] += 1
                    elif sev.startswith("med"):
                        asset_response["severity_counts"]["medium"] += 1
                    elif sev.startswith("low"):
                        asset_response["severity_counts"]["low"] += 1

                # 6️⃣ Final response
                return Response(
                    {
                        "detail": "Asset unhold (restored to report)",
                        "total_assets": total_assets,
                        "asset": asset_response
                    },
                    status=status.HTTP_200_OK
                )

        except pymongo.errors.ServerSelectionTimeoutError as e:
            return Response(
                {"detail": "Cannot connect to MongoDB", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as exc:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "Unhold failed", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# ----------------HOLD  ASSET LIST ----------------
class HoldAssetsByReportAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                # Validate ownership - admin can only view held assets from their own reports
                is_valid, report_doc, error_response = validate_report_ownership(
                    db, report_id, request.user
                )
                if not is_valid:
                    return error_response

                held_coll = db[HOLD_COLLECTION]

                fallback_member_type = report_doc.get("member_type") if report_doc else None

                cursor = held_coll.find({"report_id": str(report_id)})
                results = []

                for doc in cursor:
                    host_entry = doc.get("host_entry") or {}
                    vulns = host_entry.get("vulnerabilities", [])

                    severity_counts = {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0
                    }

                    for v in vulns:
                        risk = (v.get("risk_factor") or "").lower()
                        if risk.startswith("crit"):
                            severity_counts["critical"] += 1
                        elif risk.startswith("high"):
                            severity_counts["high"] += 1
                        elif risk.startswith("med"):
                            severity_counts["medium"] += 1
                        elif risk.startswith("low"):
                            severity_counts["low"] += 1

                    results.append({
                        "asset": doc.get("host_name"),
                        # ✅ fallback logic
                        "member_type": doc.get("member_type") or fallback_member_type,
                        "total_vulnerabilities": len(vulns),
                        "severity_counts": severity_counts,
                        "host_information": host_entry.get("host_information") or {},
                        "held_at": doc.get("held_at"),
                        "held_by": doc.get("held_by"),
                    })

                return Response(
                    {
                        "report_id": str(report_id),
                        "count": len(results),
                        "assets": results
                    },
                    status=status.HTTP_200_OK
                )

        except Exception as exc:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "Failed to fetch held assets", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# ----------------RAISE SUPPORT REQUEST BY HOST ----------------

class SupportRequestByHostAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, host_name):
        admin_id = str(request.user.id)

        with MongoContext() as db:
            support_coll = db["support_requests"]

            cursor = support_coll.find(
                {
                    "host_name": host_name,
                    "admin_id": admin_id
                }
            ).sort("requested_at", -1)

            results = []
            for doc in cursor:
                results.append({
                    "_id": str(doc.get("_id")),
                    "report_id": doc.get("report_id"),
                    "vulnerability_id": doc.get("vulnerability_id"),
                    "vul_name": doc.get("vul_name"),
                    "host_name": doc.get("host_name"),
                    "assigned_team": doc.get("assigned_team"),
                    "step_requested": doc.get("step_requested"),
                    "description": doc.get("description"),
                    "status": doc.get("status"),
                    "requested_at": doc.get("requested_at"),
                })

            return Response(
                {
                    "host_name": host_name,
                    "count": len(results),
                    "results": results
                },
                status=status.HTTP_200_OK
            )



class ClosedFixVulnerabilitiesByHostAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, host_name):
        admin_id = str(request.user.id)

        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]

            # ✅ ONLY CLOSED FIX VULNERABILITIES
            cursor = fix_coll.find(
                {
                    "host_name": host_name,
                    "created_by": admin_id,
                    "status": "close"   # 🔑 main condition
                }
            ).sort("created_at", -1)

            results = []
            for doc in cursor:
                results.append({
                    "fix_vulnerability_id": str(doc.get("_id")),
                    "report_id": doc.get("report_id"),
                    "host_name": doc.get("host_name"),
                    "plugin_name": doc.get("plugin_name"),
                    "risk_factor": doc.get("risk_factor"),

                    "description_points": doc.get("description_points"),
                    "vendor_fix_available": doc.get("vendor_fix_available"),

                    "assigned_team": doc.get("assigned_team"),
                    "assigned_team_members": doc.get("assigned_team_members", []),

                    "mitigation_steps": doc.get("mitigation_steps", []),

                    "status": doc.get("status"),  # always "close"
                    "created_at": doc.get("created_at"),
                    "created_by": doc.get("created_by"),
                })

            return Response(
                {
                    "host_name": host_name,
                    "status": "close",
                    "count": len(results),
                    "results": results
                },
                status=status.HTTP_200_OK
            )


# ---------------------- Helper for Latest Report ----------------------
def _load_latest_report_for_admin(db, admin_email, admin_id=None):
    """
    Load the most recently uploaded report for a specific admin.
    Tries admin_id first (more reliable), falls back to admin_email.
    """
    coll = db[NESSUS_COLLECTION]

    # Try by admin_id first (for newer reports)
    if admin_id:
        doc = coll.find_one(
            {"admin_id": str(admin_id)},
            sort=[("uploaded_at", -1)]
        )
        if doc:
            return doc

    # Fallback to admin_email (for older reports)
    return coll.find_one(
        {"admin_email": admin_email},
        sort=[("uploaded_at", -1)]
    )


# ---------------------- ADMIN-LEVEL ASSETS API ----------------------
class AdminAssetsAPIView(APIView):
    """
    GET /api/adminasset/assets/
    Returns all assets from the most recently uploaded report for the logged-in admin.
    This endpoint automatically refreshes when a new report is uploaded.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            search_q = (request.query_params.get("q") or "").strip().lower()
            admin_email = request.user.email
            admin_id = str(request.user.id)

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email, admin_id)

                if not doc:
                    return Response({
                        "report_id": None,
                        "member_type": None,
                        "total_assets": 0,
                        "assets": [],
                        "message": "No reports found for this admin"
                    }, status=status.HTTP_200_OK)

                report_id = doc.get("report_id") or str(doc.get("_id", ""))
                uploaded_at = doc.get("uploaded_at")
                member_type = doc.get("member_type")

                assets = {}

                for host in doc.get("vulnerabilities_by_host", []):
                    host_name = (host.get("host_name") or "").strip()
                    if not host_name:
                        continue

                    # Apply search filter
                    if search_q and search_q not in host_name.lower():
                        continue

                    if host_name not in assets:
                        assets[host_name] = {
                            "asset": host_name,
                            "first_seen": uploaded_at,
                            "last_seen": uploaded_at,
                            "member_type": member_type,
                            "total_vulnerabilities": 0,
                            "severity_counts": {
                                "critical": 0,
                                "high": 0,
                                "medium": 0,
                                "low": 0
                            },
                            "host_information": host.get("host_information") or {}
                        }

                    entry = assets[host_name]

                    for v in host.get("vulnerabilities", []):
                        entry["total_vulnerabilities"] += 1
                        risk = (v.get("risk_factor") or v.get("severity") or "").lower()

                        if risk.startswith("crit"):
                            entry["severity_counts"]["critical"] += 1
                        elif risk.startswith("high"):
                            entry["severity_counts"]["high"] += 1
                        elif risk.startswith("med"):
                            entry["severity_counts"]["medium"] += 1
                        elif risk.startswith("low"):
                            entry["severity_counts"]["low"] += 1

                final = []
                for a in assets.values():
                    final.append({
                        "asset": a["asset"],
                        "member_type": a["member_type"],
                        "first_seen": _iso(a["first_seen"]),
                        "last_seen": _iso(a["last_seen"]),
                        "total_vulnerabilities": a["total_vulnerabilities"],
                        "severity_counts": a["severity_counts"],
                        "host_information": a["host_information"],
                    })

                serializer = AdminAssetSerializer(final, many=True)

                return Response({
                    "report_id": report_id,
                    "member_type": member_type,
                    "total_assets": len(final),
                    "assets": serializer.data
                }, status=status.HTTP_200_OK)

        except Exception as exc:
            import traceback
            traceback.print_exc()
            return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminAssetVulnerabilitiesAPIView(APIView):
    """
    GET /api/adminasset/assets/<host_name>/vulnerabilities/
    Returns vulnerabilities for a specific asset from the most recently uploaded report.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, host_name):
        host_name = unquote(host_name)
        try:
            admin_email = request.user.email
            admin_id = str(request.user.id)

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email, admin_id)

                if not doc:
                    return Response(
                        {"detail": "No reports found for this admin"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                report_id = doc.get("report_id") or str(doc.get("_id", ""))
                member_type = doc.get("member_type") or ""
                scan_info = doc.get("scan_info") or {}
                organisation_name = (
                    scan_info.get("organisation_name")
                    or scan_info.get("organization")
                    or scan_info.get("organisation")
                    or ""
                )

                # Fallback to user table if no organisation_name
                if not organisation_name and User is not None:
                    organisation_name = getattr(request.user, "organisation_name", "") or ""

                # Find host entry
                host_entry = None
                for h in (doc.get("vulnerabilities_by_host") or []):
                    hn = (h.get("host_name") or h.get("host") or "").strip()
                    if hn == host_name:
                        host_entry = h
                        break

                if not host_entry:
                    return Response(
                        {"detail": "Asset not found in report"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                out = []
                for v in (host_entry.get("vulnerabilities") or []):
                    item = {
                        "asset": host_name,
                        "exposure": member_type,
                        "owner": organisation_name,
                        "severity": (v.get("risk_factor") or v.get("severity") or "").title(),
                        "vul_name": v.get("plugin_name") or v.get("pluginname") or v.get("name") or "",
                        "vendor_fix_available": "Yes",
                        "cvss_score": str(v.get("cvss_v3_base_score") or v.get("cvss") or v.get("cvss_score") or ""),
                        "description": _join_description(v),
                    }
                    out.append(item)

                serializer = AssetHostVulnSerializer(out, many=True)
                return Response({
                    "report_id": report_id,
                    "asset": host_name,
                    "count": len(out),
                    "vulnerabilities": serializer.data
                }, status=status.HTTP_200_OK)

        except pymongo.errors.ServerSelectionTimeoutError as e:
            return Response(
                {"detail": "Cannot connect to MongoDB", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as exc:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "Unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminHoldAssetsAPIView(APIView):
    """
    GET /api/adminasset/assets/hold-list/
    Returns all held assets from the most recently uploaded report for the logged-in admin.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            admin_email = request.user.email
            admin_id = str(request.user.id)

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email, admin_id)

                if not doc:
                    return Response({
                        "report_id": None,
                        "count": 0,
                        "assets": [],
                        "message": "No reports found for this admin"
                    }, status=status.HTTP_200_OK)

                report_id = doc.get("report_id") or str(doc.get("_id", ""))
                fallback_member_type = doc.get("member_type")

                held_coll = db[HOLD_COLLECTION]
                cursor = held_coll.find({"report_id": str(report_id)})
                results = []

                for held_doc in cursor:
                    host_entry = held_doc.get("host_entry") or {}
                    vulns = host_entry.get("vulnerabilities", [])

                    severity_counts = {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0
                    }

                    for v in vulns:
                        risk = (v.get("risk_factor") or "").lower()
                        if risk.startswith("crit"):
                            severity_counts["critical"] += 1
                        elif risk.startswith("high"):
                            severity_counts["high"] += 1
                        elif risk.startswith("med"):
                            severity_counts["medium"] += 1
                        elif risk.startswith("low"):
                            severity_counts["low"] += 1

                    results.append({
                        "asset": held_doc.get("host_name"),
                        "member_type": held_doc.get("member_type") or fallback_member_type,
                        "total_vulnerabilities": len(vulns),
                        "severity_counts": severity_counts,
                        "host_information": host_entry.get("host_information") or {},
                        "held_at": held_doc.get("held_at"),
                        "held_by": held_doc.get("held_by"),
                    })

                return Response({
                    "report_id": report_id,
                    "count": len(results),
                    "assets": results
                }, status=status.HTTP_200_OK)

        except Exception as exc:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "Failed to fetch held assets", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
