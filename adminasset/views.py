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

from .serializers import AdminAssetSerializer,AssetSearchSerializer,AssetHostVulnSerializer,HoldAssetSerializer
# Import User for organisation_name lookup
try:
    from users.models import User
except Exception:
    User = None

NESSUS_COLLECTION = "nessus_reports"
HOLD_COLLECTION = "hold_assets"


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
    """
    Return number of distinct host_name entries for a given report_id.
    `db` is the pymongo database object returned by MongoContext().
    """
    coll = db[NESSUS_COLLECTION]
    doc = coll.find_one({"report_id": str(report_id)}, {"vulnerabilities_by_host": 1})
    if not doc:
        return 0

    hosts = set()
    for h in (doc.get("vulnerabilities_by_host") or []):
        hn = (h.get("host_name") or h.get("host") or "").strip()
        if hn:
            hosts.add(hn)
    return len(hosts)



# ---------------------- GET ALL ASSETS API ----------------------
class ReportAssetsAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]
                doc = coll.find_one({"report_id": str(report_id)})

                if not doc:
                    return Response({"detail": "report not found"}, status=404)

                uploaded_at = doc.get("uploaded_at")

                # ---------- ASSET AGGREGATION ----------
                assets = {}

                for host in doc.get("vulnerabilities_by_host", []):
                    host_name = host.get("host_name") or ""
                    if not host_name:
                        continue

                    if host_name not in assets:
                        assets[host_name] = {
                            "asset": host_name,
                            "first_seen": uploaded_at,
                            "last_seen": uploaded_at,
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

                    # Count vulnerabilities by severity
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

                # ---------- FINAL OUTPUT ----------
                final = []
                for a in assets.values():
                    final.append({
                        "asset": a["asset"],
                        "first_seen": _iso(a["first_seen"]),
                        "last_seen": _iso(a["last_seen"]),
                        "total_vulnerabilities": a["total_vulnerabilities"],
                        "severity_counts": a["severity_counts"],
                        "host_information": a["host_information"],
                    })

                serializer = AdminAssetSerializer(final, many=True)

                return Response({
                    "report_id": report_id,
                    "total_assets": len(final),
                    "assets": serializer.data
                }, status=200)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": str(exc)}, status=500)
     
# ----------------  ASSET SEARCH ----------------
class AssetSearchAPIView(APIView):
    """
    Search only host_name values across all reports.
    GET /api/adminasset/assets/search/?q=
    Returns: [{ "asset": "192.168.0.2" }, ...]
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        q = (request.query_params.get("q") or "").strip()

        try:
            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]

                q_regex = re.compile(re.escape(q), re.IGNORECASE) if q else None

                results = set()   # ensure only unique host names

                cursor = coll.find({}, {"vulnerabilities_by_host": 1})

                for doc in cursor:
                    for host in doc.get("vulnerabilities_by_host", []):
                        host_name = host.get("host_name") or host.get("host") or ""
                        if not host_name:
                            continue

                        # if query provided, filter by substring match
                        if q_regex and not q_regex.search(host_name):
                            continue

                        results.add(host_name)

                final = [{"asset": h} for h in sorted(results)]

                serializer = AssetSearchSerializer(final, many=True)
                return Response({"count": len(final), "results": serializer.data}, status=200)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": "search failed", "error": str(exc)}, status=500)
        
        
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
                coll = db[NESSUS_COLLECTION]

                # ensure report exists
                doc = coll.find_one({"report_id": str(report_id)}, {"vulnerabilities_by_host": 1})
                if not doc:
                    return Response({"detail": "Report not found"}, status=status.HTTP_404_NOT_FOUND)

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
                coll = db[NESSUS_COLLECTION]
                doc = coll.find_one({"report_id": str(report_id)})
                if not doc:
                    return Response({"detail": "report not found"}, status=status.HTTP_404_NOT_FOUND)

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
        

class AssetHoldAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, report_id, host_name):
        host_name = unquote(host_name)
        try:
            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]
                held_coll = db[HOLD_COLLECTION]

                # load report -> find host entry
                doc = coll.find_one({"report_id": str(report_id)}, {"vulnerabilities_by_host": 1})
                if not doc:
                    return Response({"detail": "Report not found"}, status=status.HTTP_404_NOT_FOUND)

                found = None
                for h in doc.get("vulnerabilities_by_host", []):
                    hn = (h.get("host_name") or h.get("host") or "").strip()
                    if hn == host_name:
                        found = h
                        break

                if not found:
                    return Response({"detail": "Asset not found in report"}, status=status.HTTP_404_NOT_FOUND)

                # remove host from report
                res = coll.update_one(
                    {"report_id": str(report_id)},
                    {"$pull": {"vulnerabilities_by_host": {"$or": [{"host_name": host_name}, {"host": host_name}]}}}
                )
                if res.modified_count == 0:
                    return Response({"detail": "Failed to remove asset from report (maybe already removed)"},
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                # store into held_assets with metadata
                held_doc = {
                    "report_id": str(report_id),
                    "host_name": host_name,
                    "host_entry": found,
                    "held_at": timezone.now(),
                    "held_by": getattr(request.user, "email", None) or getattr(request.user, "username", None) or None,
                }
                held_coll.insert_one(held_doc)

                # recompute total assets after removal
                total_assets = compute_total_assets_for_report(db, report_id)
                return Response({"detail": "Asset hold (removed from report)", "total_assets": total_assets},
                status=status.HTTP_200_OK)
        except pymongo.errors.ServerSelectionTimeoutError as e:
            return Response({"detail": "Cannot connect to MongoDB", "error": str(e)}, status=500)
        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": "Hold failed", "error": str(exc)}, status=500)


class AssetUnholdAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, report_id, host_name):
        host_name = unquote(host_name)
        try:
            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]
                held_coll = db[HOLD_COLLECTION]

                # find held entry
                held = held_coll.find_one({"report_id": str(report_id), "host_name": host_name})
                if not held:
                    return Response({"detail": "No hold asset found"}, status=status.HTTP_404_NOT_FOUND)

                host_entry = held.get("host_entry")
                if not host_entry:
                    return Response({"detail": "Hold asset missing host_entry"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                # restore to report
                res = coll.update_one(
                    {"report_id": str(report_id)},
                    {"$push": {"vulnerabilities_by_host": host_entry}}
                )
                if res.matched_count == 0:
                    return Response({"detail": "Report not found when restoring"}, status=status.HTTP_404_NOT_FOUND)

                # remove held entry
                held_coll.delete_one({"_id": held["_id"]})

                # recompute total assets after restore
                total_assets = compute_total_assets_for_report(db, report_id)
                return Response({"detail": "Asset unhold (restored to report)", "total_assets": total_assets},
                                status=status.HTTP_200_OK)

        except pymongo.errors.ServerSelectionTimeoutError as e:
            return Response({"detail": "Cannot connect to MongoDB", "error": str(e)}, status=500)
        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": "Unhold failed", "error": str(exc)}, status=500)
